/*
 * subject-attr.c - functions to abstract subject attributes
 * Copyright (c) 2016,2019,2022 Red Hat Inc.
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

#include "config.h"
#include <stddef.h>	// For NULL
#include <string.h>
#include "subject-attr.h"

/*
 * Table1 is used for looking up rule fields written in the old format.
 * Do not add anything new here.
 */
static const nv_t table1[] = {
{	ALL_SUBJ,   "all"	},
{	AUID,       "auid"	},
{	UID,        "uid"	},
{	SESSIONID,  "sessionid"	},
{	PID,        "pid"	},
{	PATTERN,    "pattern"	},
{	COMM,       "comm"	},
{	EXE,        "exe"	},
{	EXE_DIR,    "exe_dir"	},
{	EXE_TYPE,   "exe_type"	},
};
#define MAX_SUBJECTS1 (sizeof(table1)/sizeof(table1[0]))

/*
 * Table2 is used for looking up rule fields written in the new format
 */
static const nv_t table2[] = {
{	ALL_SUBJ,   "all"	},
{	AUID,       "auid"	},
{	UID,        "uid"	},
{	SESSIONID,  "sessionid"	},
{	PID,        "pid"	},
{	PPID,       "ppid"	},
{	PATTERN,    "pattern"	},
{	SUBJ_TRUST, "trust"	},
{	GID,        "gid"       },
{	COMM,       "comm"	},
{	EXE,        "exe"	},
{	EXE_DIR,    "dir"	},
{	EXE_TYPE,   "ftype"	},
};
#define MAX_SUBJECTS2 (sizeof(table2)/sizeof(table2[0]))


int subj_name_to_val(const char *name, rformat_t format)
{
	unsigned int i = 0;
	if (format == RULE_FMT_ORIG) {
		while (i < MAX_SUBJECTS1) {
			if (strcmp(name, table1[i].name) == 0)
				return table1[i].value;
			i++;
		}
	} else {
		while (i < MAX_SUBJECTS2) {
			if (strcmp(name, table2[i].name) == 0)
				return table2[i].value;
			i++;
		}
	}
	return -1;
}

const char *subj_val_to_name(unsigned int v, rformat_t format)
{
	if (v > SUBJ_END)
		return NULL;

	unsigned int index = v - SUBJ_START;
	if (format == RULE_FMT_ORIG) {
		if (index < MAX_SUBJECTS1)
			return table1[index].name;
	} else {
		if (index < MAX_SUBJECTS2)
			return table2[index].name;
	}

	return NULL;
}
