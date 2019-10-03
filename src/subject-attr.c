/*
 * rules.c - functions to abstract subject attributes
 * Copyright (c) 2016 Red Hat Inc., Durham, North Carolina.
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

static const nv_t table[] = {
{	ALL_SUBJ,   "all"	},
{	AUID,       "auid"	},
{	UID,        "uid"	},
{	SESSIONID,  "sessionid"	},
{	PID,        "pid"	},
{	PATTERN,    "pattern"	},
/*{	SUBJ_TRUST, "subj_trust" },*/
{	COMM,       "comm"	},
{	EXE,        "exe"	},
{	EXE_DIR,    "exe_dir"	},
{	EXE_TYPE,   "exe_type"	},
{	EXE_DEVICE, "exe_device" },
};

#define MAX_SUBJECTS (sizeof(table)/sizeof(table[0]))

int subj_name_to_val(const char *name)
{
	unsigned int i = 0;
	while (i < MAX_SUBJECTS) {
		if (strcmp(name, table[i].name) == 0)
			return table[i].value;
		i++;
	}
	return -1;
}

const char *subj_val_to_name(unsigned int v)
{
	if (v < MAX_SUBJECTS)
		return table[v].name;

	return NULL;
}
