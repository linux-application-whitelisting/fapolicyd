/*
 * event.c - Functions to access event attributes
 * Copyright (c) 2016 Red Hat Inc., Durham, North Carolina.
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
 * Free Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * Authors:
 *   Steve Grubb <sgrubb@redhat.com>
 */

#include "config.h"
#include <string.h>
#include <limits.h>
#include <sys/fanotify.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include "event.h"
#include "file.h"
#include "lru.h"
#include "message.h"

static Queue *subj_cache = NULL;
static Queue *obj_cache = NULL;
extern int details;

// Return 0 on success and 1 on error
int init_event_system(void)
{
	subj_cache = init_lru(1024, subject_clear, "Subject");
	if (!subj_cache)
		return 1;

	obj_cache = init_lru(4096, object_clear, "Object");
	if (!obj_cache)
		return 1;

	return 0;
}

void destroy_event_system(void)
{
	destroy_lru(subj_cache);
	destroy_lru(obj_cache);
}

// Return 0 on success and 1 on error
int new_event(const struct fanotify_event_metadata *m, event_t *e)
{
	subject_attr_t subj;
	QNode *q_node;
	unsigned int key, rc = 1;
	s_array *s;
	o_array *o;
	struct proc_info *pinfo;
	struct file_info *finfo;

	// Transfer things from fanotify structs to ours
	e->pid = m->pid;
	e->fd = m->fd;
	e->type = m->mask & FAN_ALL_EVENTS;

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
		if (rc) {
			lru_evict(subj_cache, key);
			q_node = check_lru_cache(subj_cache, key);
			s = (s_array *)q_node->item;
		} else if (s->cnt == 0)
			msg(LOG_DEBUG, "cached subject has cnt of 0");
	}

	if (rc) {
		// If empty, setup the subject with what we currently have
		e->s = malloc(sizeof(s_array));
		subject_create(e->s);
		subj.type = PID;
		subj.val = e->pid;
		subject_add(e->s, &subj);

		// give custody of the list to the cache
		q_node->item = e->s;
		((s_array *)q_node->item)->info = pinfo;
	} else	{ // Use the one from the cache
		e->s = s;
		clear_proc_info(pinfo);
		free(pinfo);
	}

	// Init the object
	// get file fingerprint
	rc = 1;
	finfo = stat_file_entry(m->fd);
	if (finfo == NULL)
		return 1;

	// Just using inodes don't give a good key. It needs 
	// conditioning to use more slots in the cache.
	unsigned int magic = finfo->inode + finfo->time.tv_sec + finfo->blocks;
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
		e->o = malloc(sizeof(s_array));
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
	if (pinfo && pinfo->state < STATE_FULL) {
		object_attr_t *on = get_obj_attr(e, PATH);
		if (on) {
			const char *file = on->o;
			if (pinfo->path1 == NULL) {
				pinfo->path1 = strdup(file);
			} else if (pinfo->path2 == NULL) {
				pinfo->path2 = strdup(file);
				pinfo->state = STATE_PARTIAL;
			} else if (pinfo->path3 == NULL) {
				pinfo->path3 = strdup(file);
				pinfo->state = STATE_FULL;
				subject_reset(e->s, EXE);
			}
		}
	}
	return 0;
}

/*
 * This function will search the list for a nv pair of the right type.
 * If not found, it will create the type and return it.
 */
subject_attr_t *get_subj_attr(event_t *e, subject_type_t t)
{
	subject_attr_t subj;
	subject_attr_t *sn;
	s_array *s = e->s;

	sn = subject_access(s, t);
	if (sn)
		return sn;

	// One not on the list, look it up and make one
	subj.type = t;
	switch (t) {
		case AUID:
			subj.val = get_program_auid_from_pid(e->pid);
			break;
		case UID:
			subj.val = get_program_uid_from_pid(e->pid);
			break;
		case SESSIONID:
			subj.val = get_program_sessionid_from_pid(e->pid);
			break;
		case PID:
			subj.val = e->pid;
			break;
		case COMM: {
			char buf[21], *ptr;
			ptr = get_comm_from_pid(e->pid,	sizeof(buf), buf);
			if (ptr)
				subj.str = strdup(buf);
			else
				subj.str = strdup("?");
			}
			break;
		case EXE:
		case EXE_DIR: {
			char buf[PATH_MAX+1], *ptr;
			ptr = get_program_from_pid(e->pid,
						sizeof(buf), buf);
			if (ptr)
				subj.str = strdup(buf);
			else
				subj.str = strdup("?");
			}
			break;
		case EXE_TYPE: {
			char buf[PATH_MAX+1], *ptr;
			ptr = get_type_from_pid(e->pid, sizeof(buf), buf);
			if (ptr)
				subj.str = strdup(buf);
			else
				subj.str = strdup("?");
			}
			break;
		case EXE_DEVICE:
			// FIXME: write real code for this
			subj.str = strdup("?");
			break;
		default:
			return NULL;
	};

	if (subject_add(e->s, &subj) == 0) {
		sn = subject_access(e->s, t);
		return sn;
	}

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
	obj.len = 0;
	obj.type = t;
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
		case FTYPE:
			ptr = get_file_type_from_fd(e->fd, sizeof(buf), buf);
			if (ptr)
				obj.o = strdup(buf);
			else
				obj.o = strdup("?");
			break;
		case SHA256HASH:
			obj.o = get_hash_from_fd(e->fd);
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

	return NULL;
}

static void print_queue_stats(FILE *f, const Queue *q)
{
	fprintf(f, "%s queue size: %u\n", q->name, q->total);
	fprintf(f, "%s slots in use: %u\n", q->name, q->count);
	fprintf(f, "%s hits: %lu\n", q->name, q->hits);
	fprintf(f, "%s misses: %lu\n", q->name, q->misses);
	fprintf(f, "%s evictions: %lu\n", q->name, q->evictions);
}

void run_usage_report(FILE *f)
{
	time_t t;
	QNode *q_node;

	if (f == NULL)
		return;

	if (details) {
		t = time(NULL);
		fprintf(f, "File access attempts from oldest to newest as of %s\n", ctime(&t));
		fprintf(f, "\tFILE\t\t\t\t\t\t    ATTEMPTS\n");
		fprintf(f, "---------------------------------------------------------------------------\n");
		if (obj_cache->count == 0) {
			fprintf(f, "(none)\n");
			fclose(f);
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

	if (details) {
		fprintf(f, "Active processes oldest to most recently active as of %s\n", ctime(&t));
		fprintf(f, "\tEXE\tCOMM\t\t\t\t\t    ATTEMPTS\n");
		fprintf(f, "---------------------------------------------------------------------------\n");
		if (subj_cache->count == 0) {
			fprintf(f, "(none)\n");
			fclose(f);
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

			asprintf(&text, "%s (%s)", exe, comm);
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

