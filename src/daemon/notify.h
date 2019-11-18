/*
 * notify.h - Header file for notify.c
 * Copyright (c) 2016,2018 Red Hat Inc., Durham, North Carolina.
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

#include <stdio.h>
#include "daemon-config.h"
#include "mounts.h"

int init_fanotify(const conf_t *config, mlist *m);
void fanotify_update(mlist *m);
void shutdown_fanotify(mlist *m);
void decision_report(FILE *f);
void handle_events(void);

#endif
