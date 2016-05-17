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
#include "event.h"
#include "process.h"
#include "file.h"

void new_event(const struct fanotify_event_metadata *m, event_t *e)
{
	subject_attr_t subj;

	// Transfer things from fanotify structs to ours
	e->pid = m->pid;
	e->fd = m->fd;
	e->type = m->mask & FAN_ALL_EVENTS;

	// Setup the subject with what we currently have
	subject_create(&(e->s));
	subj.type = PID;
	subj.val = e->pid;
	subject_append(&(e->s), &subj);

	// Init the object
	object_create(&(e->o));
}

void clear_event(event_t *e)
{
	subject_clear(&(e->s));
	object_clear(&(e->o));
}

/*
 * This function will search the list for a nv pair of the right type.
 * If not found, it will create the type and return it.
 */
subject_attr_t *get_subj_attr(event_t *e, subject_type_t t)
{
	subject_attr_t subj;
	snode *sn;
	slist *s = &(e->s);

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

	if (subject_append(&(e->s), &subj) == 0) {
		sn = subject_get_cur(&(e->s));
		return &(sn->s);
	}

	return NULL;
}

object_attr_t *get_obj_attr(event_t *e, object_type_t t)
{
	char buf[PATH_MAX+1], *ptr;
	object_attr_t obj;
	onode *on = object_find_type(&(e->o), t);
	if (on)
		return &(on->o);

	// One not on the list, look it up and make one
	obj.type = t;
	switch (t) {
		case PATH:
		case ODIR:
			// Try to avoid looking up the path if we have it
			on = object_find_file(&(e->o));
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
			ptr = get_device_from_fd(e->fd, sizeof(buf), buf);
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

	if (object_append(&(e->o), &obj) == 0) {
		on = object_get_cur(&(e->o));
		return &(on->o);
	}

	return NULL;
}

