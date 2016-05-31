/*
 * subject-attr.h - Header file for subject-attr.c
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
 * Free Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * Authors:
 *   Steve Grubb <sgrubb@redhat.com>
 */

#ifndef SUBJECT_ATTR_HEADER
#define SUBJECT_ATTR_HEADER

#include <sys/types.h>
#include "nv.h"

// Top is numbers, bottom is strings
typedef enum { ALL_SUBJ = SUBJ_START, AUID, UID, SESSIONID, PID, 
	COMM, EXE, EXE_DIR, EXE_TYPE, EXE_DEVICE } subject_type_t;

#define SUBJ_END EXE_DEVICE

typedef struct s {
	subject_type_t type;
	union {
		int val;
		char *str;
	};
} subject_attr_t;

int subj_name_to_val(const char *name);
const char *subj_val_to_name(unsigned int v);

#endif

