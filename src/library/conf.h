/* conf.h configuration structure
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
 *   Radovan Sroka <rsroka@redhat.com>
 *
 */

#ifndef CONF_H
#define CONF_H

#include <pwd.h>

typedef enum { IN_NONE, IN_SIZE, IN_IMA, IN_SHA256 } integrity_t;

typedef struct conf
{
	unsigned int permissive;
	unsigned int nice_val;
	unsigned int q_size;
	uid_t uid;
	gid_t gid;
	unsigned int do_stat_report;
	unsigned int detailed_report;
	unsigned int db_max_size;
	unsigned int subj_cache_size;
	unsigned int obj_cache_size;
	const char *watch_fs;
	const char *trust;
	integrity_t integrity;
	const char *syslog_format;
	unsigned int rpm_sha256_only;
} conf_t;

#endif
