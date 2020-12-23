/*
 * subject-attr.h - Header file for subject-attr.c
 * Copyright (c) 2016,2019-20 Red Hat Inc.
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

#ifndef SUBJECT_ATTR_HEADER
#define SUBJECT_ATTR_HEADER

#include <sys/types.h>
#include "nv.h"
#include "fapolicyd-defs.h"
#include "attr-sets.h"

// Top is numbers, bottom is strings
typedef enum { ALL_SUBJ = SUBJ_START, AUID, UID, SESSIONID, PID,
       PATTERN, SUBJ_TRUST, GID, COMM, EXE, EXE_DIR, EXE_TYPE,
       EXE_DEVICE } subject_type_t;

#define SUBJ_END EXE_DEVICE

typedef struct s {
	subject_type_t type;
	union {
		int val;
		char *str;
		size_t gr_index;
		attr_sets_entry_t * set;
	};
} subject_attr_t;

int subj_name_to_val(const char *name, rformat_t format);
const char * subj_val_to_name(unsigned v, rformat_t format);

#endif
