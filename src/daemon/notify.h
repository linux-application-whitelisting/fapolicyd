/*
 * notify.h - Header file for notify.c
 * Copyright (c) 2016,2018 Red Hat Inc.
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
 */

#ifndef NOTIFY_HEADER
#define NOTIFY_HEADER

#include "conf.h"
#include <stdio.h>
#include <sys/fanotify.h>
#include "mounts.h"

int init_fanotify(const conf_t *config, mlist *m);
void fanotify_update(mlist *m);
void unmark_fanotify(mlist *m);
void shutdown_fanotify(mlist *m);
void fanotify_queue_report(FILE *f);
void fanotify_queue_report_reset(FILE *f, int reset);
void fanotify_defer_config_report(FILE *f);
void fanotify_defer_fallback_report(FILE *f);
void fanotify_defer_age_report(FILE *f);
void fanotify_defer_health_report(FILE *f);
void fanotify_metrics_report_reset(FILE *f, int reset);
void handle_events(void);
int handle_kernel_event(const struct fanotify_event_metadata *metadata);
unsigned long getKernelQueueOverflow(void);
void nudge_queue(void);

#endif
