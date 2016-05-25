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

#define REPORT "/var/log/fapolicyd-access.log"

static Queue *subj_cache = NULL;
static Queue *obj_cache = NULL;

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

void new_event(const struct fanotify_event_metadata *m, event_t *e)
{
	subject_attr_t subj;
	QNode *q_node;
	unsigned int key, rc = 1;
	slist *s;
	olist *o;
	struct proc_info *pinfo;
	struct file_info *finfo;

	// Transfer things from fanotify structs to ours
	e->pid = m->pid;
	e->fd = m->fd;
	e->type = m->mask & FAN_ALL_EVENTS;

	key = compute_subject_key(subj_cache, m->pid);
	q_node = check_lru_cache(subj_cache, key);
	s = (slist *)q_node->item;

	// get proc fingerprint
	pinfo = stat_proc_entry(m->pid);

	// Check the subject to see if its what its supposed to be
	if (s) {
		rc = compare_proc_infos(pinfo, s->info);
		if (rc) {
			lru_evict(subj_cache, key);
			q_node = check_lru_cache(subj_cache, key);
			s = (slist *)q_node->item;
		} else if (s->cnt == 0)
			msg(LOG_DEBUG, "cached subject has cnt of 0");
	}

	if (rc) {
		// If empty, setup the subject with what we currently have
		e->s = malloc(sizeof(slist));
		subject_create(e->s);
		subj.type = PID;
		subj.val = e->pid;
		subject_append(e->s, &subj);

		// give custody of the list to the cache
		q_node->item = e->s;
		((slist *)q_node->item)->info = pinfo;
	} else	{ // Use the one from the cache
		e->s = s;
		free(pinfo);
	}

	// Init the object
	// get file fingerprint
	rc = 1;
	finfo = stat_file_entry(m->fd);

	// Just using inodes don't give a good key. It needs 
	// conditioning to use more slots in the cache.
	unsigned int magic = finfo->inode + finfo->time.tv_sec + finfo->blocks;
	key = compute_object_key(obj_cache, magic);
//msg(LOG_DEBUG, "ino:%u key:%u info addr:%p", magic, key, finfo);
	q_node = check_lru_cache(obj_cache, key);
	o = (olist *)q_node->item;

	if (o) {
		rc = compare_file_infos(finfo, o->info);
		if (rc) {
//msg(LOG_DEBUG, "EVICTING cached object, info addr:%p", o->info);
			lru_evict(obj_cache, key);
			q_node = check_lru_cache(obj_cache, key);
			o = (olist *)q_node->item;
		} else if (o->cnt == 0)
			msg(LOG_DEBUG, "cached object has cnt of 0");
	}

	if (rc) {
		// If empty, setup the subject with what we currently have
		e->o = malloc(sizeof(olist));
		object_create(e->o);

		// give custody of the list to the cache
		q_node->item = e->o;
		((olist *)q_node->item)->info = finfo;
	} else { // Use the one from the cache
		e->o = o;
		free(finfo);
	}
}

/*
 * This function will search the list for a nv pair of the right type.
 * If not found, it will create the type and return it.
 */
subject_attr_t *get_subj_attr(event_t *e, subject_type_t t)
{
	subject_attr_t subj;
	snode *sn;
	slist *s = e->s;

	subject_first(s);
	sn = subject_get_cur(s);
	while (sn) {
		if (sn->s.type == t)
			return &(sn->s);
		sn = subject_next(s);
	}

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
			char buf[20], *ptr;
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
		default:
			return NULL;
	};

	if (subject_append(e->s, &subj) == 0) {
		sn = subject_get_cur(e->s);
		return &(sn->s);
	}

	return NULL;
}

object_attr_t *get_obj_attr(event_t *e, object_type_t t)
{
	char buf[PATH_MAX+1], *ptr;
	object_attr_t obj;
	onode *on = object_find_type(e->o, t);
	if (on)
		return &(on->o);

	// One not on the list, look it up and make one
	obj.type = t;
	switch (t) {
		case PATH:
		case ODIR:
			// Try to avoid looking up the path if we have it
			on = object_find_file(e->o);
			if (on)
				obj.o = strdup(on->o.o);
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
			ptr = get_device_from_fd(e->fd, 
					((olist *)e->o)->info->device,
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

	if (object_append(e->o, &obj) == 0) {
		on = object_get_cur(e->o);
		return &(on->o);
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

void run_usage_report(void)
{
	time_t t;
	QNode *q_node;
	FILE *f = fopen(REPORT, "w");
	if (f == NULL) {
		msg(LOG_INFO, "Cannot create usage report");
		return;
	}
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
		int len;
		const char *file;
		olist *o = (olist *)q_node->item;
		onode *on = object_find_file(o);
		if (on == NULL)
			goto next;
		file = on->o.o;
		if (file == NULL)
			goto next;

		len = strlen(file);
		if (len > 62)
			fprintf(f, "%s\t%lu\n", file, q_node->uses);
		else
			fprintf(f, "%-62s\t%lu\n", file, q_node->uses);
		next:
		q_node = q_node->prev;
	}

	fprintf(f, "\n---\n\n");
	print_queue_stats(f, obj_cache);
	fprintf(f, "\n");
	print_queue_stats(f, subj_cache);
	fclose(f);
}

