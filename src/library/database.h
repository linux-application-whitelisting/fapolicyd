/*
 * database.h - Header file for trust database
 * Copyright (c) 2018-22 Red Hat Inc.
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

#include <lmdb.h>
#include "conf.h"
#include "file.h"

typedef struct {
	MDB_val path;
	MDB_val data;
} walkdb_entry_t;

void lock_update_thread(void);
void unlock_update_thread(void);
void set_integrity_mode(integrity_t mode);

const char *lookup_tsource(unsigned int tsource);
int preconstruct_fifo(const conf_t *config);
int init_database(conf_t *config);
int check_trust_database(const char *path, struct file_info *info, int fd);
void set_reload_trust_database(void);
void close_database(void);
void database_report(FILE *f);
int unlink_db(void);
void unlink_fifo(void);

void lock_rule(void);
void unlock_rule(void);

// Database verification functions
int walk_database_start(conf_t *config);
walkdb_entry_t *walk_database_get_entry(void);
int walk_database_next(void);
void walk_database_finish(void);

#define RELOAD_TRUSTDB_COMMAND '1'
#define FLUSH_CACHE_COMMAND '2'
#define RELOAD_RULES_COMMAND '3'

#endif
