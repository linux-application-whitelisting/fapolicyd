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

#include <stdio.h>
#include <time.h>
#include <lmdb.h>
#include "conf.h"
#include "file.h"
#include "gcc-attributes.h"

typedef struct {
	MDB_val path;
	MDB_val data;
} walkdb_entry_t;

#define TRUST_DB_METADATA_NAME "trust.meta"
#define TRUST_DB_METADATA_KEY "current"

typedef struct {
	unsigned long generation;
	long entries;
	time_t publish_time;
	unsigned long lmdb_generation;
	time_t lmdb_publish_time;
	unsigned int retired_count;
	unsigned long oldest_retired_age;
	unsigned long max_reclaim_delay;
} database_generation_report_t;

void lock_update_thread(void);
void unlock_update_thread(void);

const char *lookup_tsource(unsigned int tsource) __attribute_const__;
int preconstruct_fifo(const conf_t *config) __nonnull ((1));
int init_database(conf_t *config) __nonnull ((1));
int do_memfd_update(int memfd, long *entries) __nonnull ((2));
int check_trust_database(const char *path, struct file_info *info, int fd)
	__nonnull ((1));
void set_reload_trust_database(void);
void close_database(void);
void database_config_report(FILE *f);
void database_utilization_report(FILE *f, const conf_t *config);
void database_report(FILE *f);
void database_metrics_report_reset(FILE *f, int reset);
int database_generation_snapshot(database_generation_report_t *report)
	__nonnull ((1));
int unlink_db(void) __wur;
void unlink_fifo(void);
unsigned get_default_db_max_size(void);
void lock_rule(void);
void unlock_rule(void);

// Database verification functions
int walk_database_start(conf_t *config) __nonnull ((1));
walkdb_entry_t *walk_database_get_entry(void);
int walk_database_next(void);
void walk_database_finish(void);

// Functions for unit test use
typedef database_generation_report_t database_generation_test_report_t;

int database_set_location(const char *dir, const char *name);
int database_open_for_tests(conf_t *config) __nonnull ((1));
void database_close_for_tests(void);
int database_publish_memfd_for_tests(int memfd, conf_t *config)
	__nonnull ((2));
int database_publish_startup_memfd_for_tests(int memfd, conf_t *config)
	__nonnull ((2));
int database_drop_candidate_after_import_for_tests(int memfd);
int database_reload_for_tests(conf_t *config) __nonnull ((1));
int database_compact_memfd_for_tests(int memfd, conf_t *config)
	__nonnull ((2));
void *database_generation_hold_for_tests(void);
void database_generation_release_for_tests(void *cookie);
void database_reclaim_generations_for_tests(void);
int database_generation_report_for_tests(
	database_generation_test_report_t *report) __nonnull ((1));
unsigned int database_autosize_target_mb_for_tests(unsigned long active_pages,
	unsigned long env_allocated_pages, unsigned long map_pages,
	unsigned long page_size);

#define RELOAD_TRUSTDB_COMMAND '1'
#define FLUSH_CACHE_COMMAND '2'
#define RELOAD_RULES_COMMAND '3'
#define COMPACT_TRUSTDB_COMMAND '4'

#endif
