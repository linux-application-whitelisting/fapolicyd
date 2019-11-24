/*
 * event.h - Header file for event.c
 * Copyright (c) 2016,2018-19 Red Hat Inc.
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

#ifndef EVENT_HEADER
#define EVENT_HEADER

#include <stdio.h>
#include <sys/types.h>
#include <sys/fanotify.h>
#include "subject.h"
#include "object.h"
#include "conf.h"

#ifndef FAN_OPEN_EXEC	// If kernel doesn't know these, set to 0 to disable
#define FAN_OPEN_EXEC		0
#define FAN_OPEN_EXEC_PERM	0
#endif

typedef struct ev {
	pid_t pid;
	int fd;
	int type;
	s_array *s;
	o_array *o;
} event_t;

int init_event_system(conf_t *config);
int flush_cache(conf_t *config);
void destroy_event_system(void);
int new_event(const struct fanotify_event_metadata *m, event_t *e);
subject_attr_t *get_subj_attr(event_t *e, subject_type_t t);
object_attr_t *get_obj_attr(event_t *e, object_type_t t);
void run_usage_report(conf_t *config, FILE *f);

#endif
