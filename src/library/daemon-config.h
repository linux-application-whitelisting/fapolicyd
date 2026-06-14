/* daemon-config.h --
 * Copyright 2018-20 Red Hat Inc.
 * All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Authors:
 *   Steve Grubb <sgrubb@redhat.com>
 *   Radovan Sroka <rsroka@redhat.com>
 *
 */

#ifndef DAEMON_CONFIG_H
#define DAEMON_CONFIG_H

#include "conf.h"

/*
 * Keep this cap in sync with fixed-size per-worker arrays such as decision
 * timing and attribute-lookup metrics. The value is intentionally tied to the
 * largest CPU count this implementation is prepared to use, not to arbitrary
 * configuration input.
 */
#define DAEMON_CONFIG_DECISION_THREADS_MAX 32
/*
 * Reserve LMDB reader slots for non-decision activity such as status walks,
 * trust database reload inspection, compaction validation, and administrative
 * checks. Eight gives those maintenance paths headroom without keeping the
 * LMDB reader table much larger than the worker cap.
 */
#define DAEMON_CONFIG_LMDB_MAINTENANCE_READERS 8
/* Largest LMDB reader table this config layer will request. */
#define DAEMON_CONFIG_LMDB_MAX_READERS \
	(DAEMON_CONFIG_DECISION_THREADS_MAX + \
	 DAEMON_CONFIG_LMDB_MAINTENANCE_READERS)
/*
 * Startup raises RLIMIT_NOFILE to at least this value when possible. The value
 * preserves the existing daemon behavior and lets default q_size plus future
 * worker queues fit under the service limit without requiring immediate
 * systemd LimitNOFILE changes.
 */
#define DAEMON_CONFIG_MIN_NOFILE 16384

int load_daemon_config(conf_t *config);
int validate_daemon_config(const conf_t *config);
void free_daemon_config(conf_t *config);
unsigned int daemon_config_lmdb_reader_limit(const conf_t *config);
const char *lookup_integrity(unsigned value);
const char *lookup_reset_strategy(unsigned value);
const char *lookup_timing_collection(unsigned value);

#endif
