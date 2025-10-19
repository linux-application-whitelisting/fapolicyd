/* globals.h - Constant paths used throughout fapolicyd
 * Copyright 2022 Red Hat Inc.
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
 *
 */

#ifndef GLOBALS_H
#define GLOBALS_H

#define CONFIG_FILE     "/etc/fapolicyd/fapolicyd.conf"
#define OLD_RULES_FILE  "/etc/fapolicyd/fapolicyd.rules"
#define RULES_FILE      "/etc/fapolicyd/compiled.rules"
#define LANGUAGE_RULES_FILE  "/etc/fapolicyd/rules.d/10-languages.rules"
#define MOUNTS_FILE     "/proc/mounts"
#define TRUST_DIR_PATH  "/etc/fapolicyd/trust.d/"
#define TRUST_FILE_PATH "/etc/fapolicyd/fapolicyd.trust"
#define DB_DIR          "/var/lib/fapolicyd"
#define DB_NAME         "trust.db"
#define REPORT          "/var/log/fapolicyd-access.log"
#define RUN_DIR         "/run/fapolicyd/"
#define STAT_REPORT     "/run/fapolicyd/fapolicyd.state"
#define fifo_path       "/run/fapolicyd/fapolicyd.fifo"
#define pidfile         "/run/fapolicyd.pid"

#define OLD_FILTER_FILE "/etc/fapolicyd/rpm-filter.conf"
#define FILTER_FILE     "/etc/fapolicyd/fapolicyd-filter.conf"

#endif
