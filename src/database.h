/*
 * database.h - Header file for trust database
 * Copyright (c) 2018-19 Red Hat Inc.
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

#ifndef DATABASE_HEADER
#define DATABASE_HEADER

#include "daemon-config.h"

void lock_update_thread(void);
void unlock_update_thread(void);

int preconstruct_fifo(struct daemon_conf *config);
int init_database(struct daemon_conf *config);
int check_trust_database(const char *path);
void close_database(void);

#endif
