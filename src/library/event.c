/*
 * event.c - Functions to access event attributes
 * Copyright (c) 2016,2018-20,2023 Red Hat Inc.
 * All Rights Reserved.
 *
 * This software may be freely redistributed and/or modified under the
 * terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; see the file COPYING. If not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor
 * Boston, MA 02110-1335, USA.
 *
 * Authors:
 *   Steve Grubb <sgrubb@redhat.com>
 *   Radovan Sroka <rsroka@redhat.com>
 */

#include "config.h"
#include <string.h>
#include <limits.h>
#include <sys/fanotify.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <time.h>
#include <errno.h>

#include "event.h"
#include "database.h"
#include "file.h"
#include "lru.h"
#include "message.h"
#include "policy.h"
#include "rules.h"
#include "process.h"

#define ALL_EVENTS (FAN_ALL_EVENTS|FAN_OPEN_PERM|FAN_ACCESS_PERM| \
	FAN_OPEN_EXEC_PERM)

static Queue *subj_cache = NULL;
static Queue *obj_cache = NULL;
static bool obj_cache_warned = false;
static unsigned int early_subj_cache_evictions = 0;

atomic_bool needs_flush = false;

/*
 * subject_evict_warn - warn when a subject is evicted before fully built
 * @s: subject array to be evicted
 *
 * Rapid PID reuse can force a partially collected subject out of the
 * cache if the cache is too small. When this happens the dynamic linker
 * (ld.so) rule may deny access because when the evicted process re-appears
 * in the future, the loader (ld.so) appears as a standalone execution and
 * matches the ld_so pattern. Warn the administrator so they can consider
 * raising subj_cache_size to reduce the chances of this happening.
 */
static void subject_evict_warn(s_array *s)
{
	int warn = 0;
	if (s && s->info && s->info->state < STATE_FULL) {
		/*
		 * Normal interpreter re-exec replaces the process image
		 * before all paths are gathered. If the re-exec ends in
		 * a script (with or without #!) we know it is benign.
		 * Suppress the suggestion to grow the cache.
		 */
		if (!((s->info->state == STATE_REOPEN) &&
		      (s->info->elf_info & (HAS_SHEBANG|TEXT_SCRIPT))) ) {
			warn = 1;
			early_subj_cache_evictions++;
		}
	}

	if (early_subj_cache_evictions > 5)
		return;

	if (warn) {
		msg(LOG_WARNING,
		    "pid %d in state %d (%s) is being evicted from the "
		    "subject cache before pattern detection completes: "
		    "increase subj_cache_size",
		    s->info->pid, s->info->state, s->info->path1);
	}
}

/*
 * obj_evict_warn - check object cache eviction ratios
 *
 * Opportunistically check eviction ratios during evictions and warn the
 * administrator when thresholds indicate the object cache is too small.
 * Checks occur no more than once every 16 evictions and only one runtime
 * warning is emitted.
 *
 * It uses 2 ratios to decide if we need to issue a warning:
 *
 * E_over_M = evictions / misses
 *   - Measures how often a miss requires throwing out an existing object.
 *   - High values mean the cache is not just missing, but actively churning,
 *     which points to either capacity pressure or poor distribution.
 *
 * E_over_Q = evictions / total lookups
 *   - Measures the overall fraction of requests that cause an eviction.
 *   - This gives a user-facing view of churn: how much of the workload is
 *     paying the eviction penalty out of all operations.
 *
 * Together, these ratios let us distinguish "expected misses" from
 * "pathological evictions" and trigger a resize warning only when the cache
 * is turning over too aggressively for its occupancy level.
 */
static void obj_evict_warn(void *unused)
{
	unsigned long evicts, miss, hit, lookups, e_over_m, e_over_q;
	unsigned int occ, thr_m = 0, thr_q = 0;

	if (obj_cache_warned)
		return;

	if (obj_cache->evictions & 0xF)
		return;

	evicts = obj_cache->evictions + 1;
	miss = obj_cache->misses + 1;
	hit = obj_cache->hits;
	lookups = hit + miss;
	occ = (obj_cache->count * 100) / obj_cache->total;
	e_over_m = (evicts * 100) / miss;
	e_over_q = (evicts * 100) / (lookups ? lookups : 1);

	if (occ >= 85) {
		// Near-full tables churn; above these levels growth is
		// usually cheaper than misses.
		thr_m = 80;
		thr_q = 35;
	} else if (occ >= 75) {
		// Some churn is expected; beyond this you’re throwing away
		// too much reuse.
		thr_m = 55;
		thr_q = 20;
	} else if (occ >= 60) {
		// At this level evictions should be infrequent; higher means
		// collisions/skew or underprovisioning.
		thr_m = 35;
		thr_q = 12;
	} else
		return;

	if (e_over_m > thr_m || e_over_q > thr_q) {
		msg(LOG_WARNING,
		    "object cache eviction ratios high (occupancy: %u%%, "
		    "evict/miss=%lu%%, evict/lookups=%lu%%): "
		    "increase obj_cache_size",
		    occ, e_over_m, e_over_q);
		obj_cache_warned = true;
	}
}

// Return 0 on success and 1 on error
int init_event_system(const conf_t *config)
{
	/*
	 * Attach subject_evict_warn so we can see when fast PID turnover
	 * drops a subject before classification completes.  Without all the
	 * paths collected ld.so can report spurious access denials.  A larger
	 * subj_cache_size lengthens the window and avoids this condition.
	 */
	subj_cache=init_lru(config->subj_cache_size,
				(void (*)(void *))subject_clear, "Subject",
				(void (*)(void *))subject_evict_warn);
	if (!subj_cache)
		return 1;

	obj_cache = init_lru(config->obj_cache_size,
				(void (*)(void *))object_clear, "Object",
				obj_evict_warn);
	if (!obj_cache) {
		destroy_lru(subj_cache);
		subj_cache = NULL;
		return 1;
	}

	return 0;
}

static int flush_cache(void)
{
	if (obj_cache->count == 0)
		return 0;

	const unsigned int size = obj_cache->total;

	msg(LOG_DEBUG, "Flushing object cache");
	obj_cache->evict_cb = NULL;
	destroy_lru(obj_cache);

	obj_cache = init_lru(size,
				(void (*)(void *))object_clear, "Object",
				obj_evict_warn);
	if (!obj_cache)
		return 1;

	msg(LOG_DEBUG, "Flushed");

	return 0;
}

void destroy_event_system(void)
{
	/* We're intentionally clearing the caches; disable warnings */
	if (subj_cache)
		subj_cache->evict_cb = NULL;
	if (early_subj_cache_evictions)
		msg(LOG_WARNING,
		   "Processes are being evicted from the subject cache before "
		   "pattern detection completes: increase subj_cache_size "
		   "(total early evictions: %u)", early_subj_cache_evictions);
	if (obj_cache)
		obj_cache->evict_cb = NULL;
	if (obj_cache_warned)
		msg(LOG_WARNING,
		  "object cache eviction ratios high: increase obj_cache_size");
	destroy_lru(subj_cache);
	destroy_lru(obj_cache);
}

static inline void reset_subject_attributes(s_array *s)
{
	subject_reset(s, EXE);
	subject_reset(s, COMM);
	subject_reset(s, EXE_TYPE);
	subject_reset(s, SUBJ_TRUST);
}

// Return 0 on success and 1 on error
int new_event(const struct fanotify_event_metadata *m, event_t *e)
{
	subject_attr_t subj;
	QNode *q_node;
	unsigned int key, rc, evict = 1, skip_path = 0;
	s_array *s;
	o_array *o;
	struct proc_info *pinfo;
	struct file_info *finfo;

	if (needs_flush) {
		flush_cache();
		needs_flush = false;
	}

	// Transfer things from fanotify structs to ours
	e->pid = m->pid;
	e->fd = m->fd;
	e->type = m->mask & ALL_EVENTS;
	e->num = 0;

	key = compute_subject_key(subj_cache, m->pid);
	q_node = check_lru_cache(subj_cache, key);
	s = (s_array *)q_node->item;

	// get proc fingerprint
	pinfo = stat_proc_entry(m->pid);
	if (pinfo == NULL)
		return 1;

	// Check the subject to see if its what its supposed to be
	if (s) {
		rc = compare_proc_infos(pinfo, s->info);

		// EXEC_PERM causes 2 events for every execute. First is an
		// execute request. This is followed by an open request of
		// the same file. So, if we are collecting and perm is open,
		// that means this is the second step, open. We also need
		// be sure we are the same process. We skip collecting path
		// because it was collected on perm = execute.
		if ((s->info->state == STATE_COLLECTING) &&
			(e->type & FAN_OPEN_PERM) && !rc) {
			// special branch after ld_so exec
			// next opens will go fall trough
			if (s->info->path1 &&
				(strcmp(s->info->path1, SYSTEM_LD_SO) == 0))
				s->info->state = STATE_DEFAULT_REOPEN;
			else {
				skip_path = 1;
				s->info->state = STATE_REOPEN;
			}
		}

		// If not same proc or we detect execution, evict
		evict = rc || e->type & FAN_OPEN_EXEC_PERM;

		// We need to reset everything now that execve has finished
		if (s->info->state == STATE_STATIC_PARTIAL && !rc) {
			// If the static app itself launches an app right
			// away, go back to collecting.
			if (e->type & FAN_OPEN_EXEC_PERM)
				s->info->state = STATE_COLLECTING;
			else {
				s->info->state = STATE_STATIC;
				skip_path = 1;
			}
			evict = 0;
			reset_subject_attributes(s);
		}
		// Static has to sequence through a state machine to get to
		// the point where we can do a full subject reset. Still
		// in execve at this point.
		if ((s->info->state == STATE_STATIC_REOPEN) &&
					(e->type & FAN_OPEN_PERM) && !rc) {
			s->info->state = STATE_STATIC_PARTIAL;
			evict = 0;
			skip_path = 1;
		}


		// If we've seen the reopen and its an execute and process
		// has an interpreter and we're the same process, don't evict
		// and don't collect the path since reopen interp will. The
		// !skip_path is to prevent the STATE_REOPEN change above from
		// falling into this.
		if ((s->info->state == STATE_REOPEN) && !skip_path &&
				(e->type & FAN_OPEN_EXEC_PERM) &&
				(s->info->elf_info & HAS_INTERP) && !rc) {
			s->info->state = STATE_DEFAULT_REOPEN;
			evict = 0;
			skip_path = 1;
		}

		// this is how STATE_REOPEN and
		// STATE_DEFAULT_REOPEN differs
		// in STATE_REOPEN path is always skipped
		if ((s->info->state == STATE_REOPEN) && !skip_path &&
				(e->type & FAN_OPEN_PERM) && !rc) {
			skip_path = 1;
		}

		if (evict) {
			lru_evict(subj_cache, key);
			q_node = check_lru_cache(subj_cache, key);
			s = (s_array *)q_node->item;
		} else if (s->cnt == 0)
			msg(LOG_DEBUG, "cached subject has cnt of 0");
	}

	if (evict) {
		// If empty, setup the subject with what we currently have
		e->s = malloc(sizeof(s_array));
		subject_create(e->s);
		subj.type = PID;
		subj.pid = e->pid;
		subject_add(e->s, &subj);

		// give custody of the list to the cache
		q_node->item = e->s;
		((s_array *)q_node->item)->info = pinfo;

		// If this is the first time we've seen this process
		// and its doing a file open, its likely to be a running
		// process. That means we should not do pattern detection.
		if (!s && (e->type & FAN_OPEN_PERM))
			pinfo->state = STATE_NORMAL;
	} else	{ // Use the one from the cache
		e->s = s;
		clear_proc_info(pinfo);
		free(pinfo);
	}

	// Init the object
	// get file fingerprint
	rc = 1;
	finfo = stat_file_entry(m->fd);
	if (finfo == NULL) {
		/* On stat_file_entry failure, evict the subject to avoid
		 * leaving an incomplete subject cached, which could
		 * confuse later lookups and pattern matching. */
		if (evict) {
			lru_evict(subj_cache, key);
			e->s = NULL;
		}
		return 1;
	}

	// Just using inodes don't give a good key. It needs
	// conditioning to use more slots in the cache.
	unsigned long magic = finfo->inode + finfo->time.tv_nsec + finfo->size;
	key = compute_object_key(obj_cache, magic);
	q_node = check_lru_cache(obj_cache, key);
	o = (o_array *)q_node->item;

	if (o) {
		rc = compare_file_infos(finfo, o->info);
		if (rc) {
			lru_evict(obj_cache, key);
			q_node = check_lru_cache(obj_cache, key);
			o = (o_array *)q_node->item;
		}
	}

	if (rc) {
		// If empty, setup the object with what we currently have
		e->o = malloc(sizeof(o_array));
		object_create(e->o);

		// give custody of the list to the cache
		q_node->item = e->o;
		((o_array *)q_node->item)->info = finfo;
	} else { // Use the one from the cache
		e->o = o;
		free(finfo);
	}

	// Setup pattern info
	pinfo = e->s->info;
	if (pinfo && !skip_path && pinfo->state < STATE_FULL) {
		object_attr_t *on = get_obj_attr(e, PATH);
		if (on) {
			const char *file = on->o;
			if (pinfo->path1 == NULL) {
				// In this step, we gather info on what is
				// being asked permission to execute.
				pinfo->path1 = strdup(file);
				pinfo->elf_info = gather_elf(e->fd,
							e->o->info->size);
			//	pinfo->state = STATE_COLLECTING;Just for clarity
			} else if (pinfo->path2 == NULL) {
				pinfo->path2 = strdup(file);
				pinfo->state = STATE_PARTIAL;
			} else {
				// This third look is needed because the first
				// two are still the old process as far as
				// procfs is concerned. Reset things that could
				// change based on the new process name.
				pinfo->state = STATE_FULL;
				reset_subject_attributes(s);
			}
		}
	}
	return 0;
}

/*
 * fetch_proc_status - populate subject cache entries using /proc status
 * @e: event whose subject cache should be filled
 * @t: subject attribute type requested by the caller
 *
 * The function gathers all configured fields from /proc/<pid>/status for the
 * process associated with @e.  Each successfully read attribute is added to
 * the subject cache so subsequent lookups do not need to touch procfs
 * again.
 *
 * Return: pointer to the requested attribute on success, NULL otherwise.
 */
subject_attr_t *fetch_proc_status(event_t *e, subject_type_t t)
{
	unsigned int mask = rules_get_proc_status_mask();
	mask |= policy_get_syslog_proc_status_mask();
	struct proc_status_info info = {
		.ppid = -1,
		.uid = NULL,
		.groups = NULL,
		.comm = NULL
	};

	if (read_proc_status(e->pid, mask, &info) != 0)
		return NULL;

	// Cache everything - sets and comm are malloc'ed. Transfer ownership.
	// Not checking return of subject_add. Caller needs to check for NULL.
	if (mask & PROC_STAT_PPID) {
		subject_attr_t sub;
		sub.type = PPID;
		sub.pid = info.ppid;
		subject_add(e->s, &sub);
	}
	if (mask & PROC_STAT_UID) {
		subject_attr_t sub;
		sub.type = UID;
		sub.set = info.uid;
		subject_add(e->s, &sub);
	}
	if (mask & PROC_STAT_GID) {
	    subject_attr_t sub;
	    sub.type = GID;
	    sub.set = info.groups;
	    subject_add(e->s, &sub);
	}
	if (mask & PROC_STAT_COMM) {
		subject_attr_t sub;
		sub.type = COMM;
		sub.str = info.comm;
		subject_add(e->s, &sub);
	}

	//return the subject entry
	return subject_access(e->s, t);
}

/*
 * get_subj_attr - return a subject attribute, creating it on demand
 * @e: event describing the subject whose attribute is needed
 * @t: subject attribute identifier
 *
 * The function first looks for @t in the subject cache.  When missing, it
 * performs the necessary lookup and stores the result for reuse.  Some
 * attributes are retrieved directly, while UID/GID and credential data
 * are collected in bulk via fetch_proc_status().
 *
 * Return: pointer to the requested attribute, or NULL if acquisition fails.
 */
subject_attr_t *get_subj_attr(event_t *e, subject_type_t t)
{
	subject_attr_t subj;
	subject_attr_t *sn;
	s_array *s = e->s;

	sn = subject_access(s, t);
	if (sn)
		return sn;

	// The desired attribute is not on the list, look it up and cache it
	subj.type = t;
	subj.str = NULL;
	switch (t) {
		case AUID:
			subj.uval = get_program_auid_from_pid(e->pid);
			break;
		case PPID:
		case UID:
		case GID:
		case COMM:
			/*
			 * UID/GID credentials may differ between the real,
			 * effective, saved, and filesystem slots.  Cache all
			 * but saved so the rule engine can evaluate all
			 * possible identities during matching.
			 */
			return fetch_proc_status(e, t);
			break;
		case SESSIONID:
			subj.uval = (unsigned int)
					get_program_sessionid_from_pid(e->pid);
			break;
		case PID:
			subj.pid = e->pid;
			break;
		// If these 2 ever get separated, update subject_add
		// and subject_access in subject.c
		case EXE:
		case EXE_DIR: {
			char buf[PATH_MAX+1], *ptr;

			errno = 0;
			ptr = get_program_from_pid(e->pid, sizeof(buf), buf);
			if (errno == ENOENT) {
				/* kworkers have no exe entry, use comm */
				sn = subject_access(s, COMM);
				if (!sn)
					sn = fetch_proc_status(e, COMM);
				if (sn)
					subj.str = strdup(sn->str);
				else
					subj.str = strdup("?");
			} else if (ptr)
				subj.str = strdup(buf);
			else
				subj.str = strdup("?");
		}
		break;
		case EXE_TYPE: {
			char buf[128], *ptr;
			ptr = get_type_from_pid(e->pid, sizeof(buf), buf);
			if (ptr)
				subj.str = strdup(buf);
			else
				subj.str = strdup("?");
			}
			break;
		case SUBJ_TRUST: {
			subject_attr_t *exe = get_subj_attr(e, EXE);

			subj.uval = 0;
			if (exe) {
				if (exe->str) {
					int res = check_trust_database(exe->str,
								       NULL, 0);

					// ignore -1
					if (res == 1)
						subj.uval = 1;
					else
						subj.uval = 0;
				}
			}
			}
			break;
		default:
			return NULL;
	}

	if (subject_add(e->s, &subj) == 0) {
		sn = subject_access(e->s, t);
		return sn;
	}

	// free .str only when it was really used
	// otherwise invalid free is possible
	if (t >= COMM)
		free(subj.str);
	return NULL;
}


/*
 * This function will search the list for a nv pair of the right type.
 * If not found, it will create the type and return it.
 */
object_attr_t *get_obj_attr(event_t *e, object_type_t t)
{
	char buf[PATH_MAX+1], *ptr;
	object_attr_t obj;
	object_attr_t *on;
	o_array *o = e->o;

	on = object_access(o, t);
	if (on)
		return on;

	// One not on the list, look it up and make one
	obj.type = t;
	obj.o = NULL;
	obj.val = 0;
	switch (t) {
		case PATH:
		case ODIR:
			// Try to avoid looking up the path if we have it
			on = object_find_file(o);
			if (on)
				obj.o = strdup(on->o);
			else {
				ptr = get_file_from_fd(e->fd, e->pid,
							sizeof(buf), buf);
				if (ptr)
					obj.o = strdup(buf);
				else
					obj.o = strdup("?");
			}
			break;
		case DEVICE:
			ptr = get_device_from_stat(o->info->device,
					sizeof(buf), buf);
			if (ptr)
				obj.o = strdup(buf);
			else
				obj.o = strdup("?");
			break;
		case FTYPE: {
			object_attr_t *path =  get_obj_attr(e, PATH);
			ptr = get_file_type_from_fd(e->fd, o->info,
							path ? path->o : "?",
							sizeof(buf), buf);
			if (ptr)
				obj.o = strdup(buf);
			else
				obj.o = strdup("?");
			}
			break;
		case FILE_HASH: {
			file_hash_alg_t alg = FILE_HASH_ALG_SHA256;

			if (o->info) {
				if (o->info->digest_alg != FILE_HASH_ALG_NONE)
					alg = o->info->digest_alg;

				if (o->info->digest[0]) {
					obj.o = strdup(o->info->digest);
					break;
				}

				obj.o = get_hash_from_fd2(e->fd,
							  o->info->size, alg);
				if (obj.o) {
					file_info_cache_digest(o->info, alg);
					strncpy(o->info->digest, obj.o,
						FILE_DIGEST_STRING_MAX-1);
					o->info->digest[FILE_DIGEST_STRING_MAX-1] = 0;
				} else
					file_info_reset_digest(o->info);
			}
		}
		break;
		case OBJ_TRUST: {
			object_attr_t *path =  get_obj_attr(e, PATH);

			if (path && path->o) {
				int res = check_trust_database(path->o,
							       o->info, e->fd);

				// ignore -1
				if (res == 1)
					obj.val = 1;
				else
					obj.val = 0;
			}
			}
			break;
		case FMODE:
		default:
			obj.o = NULL;
			return NULL;
	}

	if (object_add(e->o, &obj) == 0) {
		on = object_access(e->o, t);
		return on;
	}

	free(obj.o);
	return NULL;
}

static void print_queue_stats(FILE *f, const Queue *q)
{
	fprintf(f, "%s cache size: %u\n", q->name, q->total);
	fprintf(f, "%s slots in use: %u (%u%%)\n", q->name, q->count,
				q->total ? (100*q->count)/q->total : 0);
	fprintf(f, "%s hits: %lu\n", q->name, q->hits);
	fprintf(f, "%s misses: %lu\n", q->name, q->misses);
	fprintf(f, "%s evictions: %lu (%lu%%)\n", q->name, q->evictions,
				q->hits ? (100*q->evictions)/q->hits : 0);
}

void run_usage_report(const conf_t *config, FILE *f)
{
	time_t t;
	QNode *q_node;

	if (f == NULL)
		return;

	if (config->detailed_report) {
		t = time(NULL);
		fprintf(f,
			"File access attempts from oldest to newest as of %s\n",
			ctime(&t));
		fprintf(f, "\tFILE\t\t\t\t\t\t    ATTEMPTS\n");
		fprintf(f,
"---------------------------------------------------------------------------\n"
			);
		if (obj_cache->count == 0) {
			fprintf(f, "(none)\n");
			return;
		}

		q_node = obj_cache->end;

		while (q_node) {
			unsigned int len;
			const char *file;
			o_array *o = (o_array *)q_node->item;
			object_attr_t *on = object_find_file(o);
			if (on == NULL)
				goto next_obj;
			file = on->o;
			if (file == NULL)
				goto next_obj;

			len = strlen(file);
			if (len > 62)
				fprintf(f, "%s\t%lu\n", file, q_node->uses);
			else
				fprintf(f, "%-62s\t%lu\n", file, q_node->uses);
		next_obj:
			q_node = q_node->prev;
		}

		fprintf(f, "\n---\n\n");
	}
	print_queue_stats(f, obj_cache);
	fprintf(f, "\n\n");

	if (config->detailed_report) {
		fprintf(f,
		   "Active processes oldest to most recently active as of %s\n",
		   ctime(&t));
		fprintf(f, "\tEXE\tCOMM\t\t\t\t\t    ATTEMPTS\n");
		fprintf(f,
"---------------------------------------------------------------------------\n"
			);
		if (subj_cache->count == 0) {
			fprintf(f, "(none)\n");
			return;
		}

		q_node = subj_cache->end;

		while (q_node) {
			unsigned int len;
			char *exe, *comm, *text;
			subject_attr_t *se, *sc;
			s_array *s = (s_array *)q_node->item;
			se = subject_find_exe(s);
			if (se == NULL)
				goto next_subj;
			exe = se->str;
			if (exe == NULL)
				goto next_subj;

			sc = subject_find_comm(s);
			if (sc == NULL)
				comm = "?";
			else
				comm = sc->str ? sc->str : "?";

			if (asprintf(&text, "%s (%s)", exe, comm) < 0) {
				fprintf(f, "?\n");
				goto next_subj;
			}

			len = strlen(text);
			if (len > 62)
				fprintf(f, "%s\t%lu\n", text, q_node->uses);
			else
				fprintf(f,"%-62s\t%lu\n", text, q_node->uses);
			free(text);
		next_subj:
			q_node = q_node->prev;
		}
		fprintf(f, "\n---\n\n");
	}
	print_queue_stats(f, subj_cache);
	fprintf(f, "\n");
}

void do_cache_reports(FILE *f)
{
	print_queue_stats(f, subj_cache);
	fprintf(f, "Early subject cache evictions: %u\n",
		early_subj_cache_evictions);
	print_queue_stats(f, obj_cache);
}

