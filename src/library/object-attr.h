/*
 * object-attr.h - Header file for object-attr.c
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
 *  Steve Grubb <sgrubb@redhat.com>
 *  Radovan Sroka <rsroka@redhat.com>
 */

#ifndef OBJECT_ATTR_HEADER
#define OBJECT_ATTR_HEADER

#include <sys/types.h>
#include "nv.h"

#include "attr-sets.h"

typedef enum { ALL_OBJ = OBJ_START, PATH, ODIR, DEVICE, FTYPE,
		OBJ_TRUST, SHA256HASH, FMODE } object_type_t;

#define OBJ_END FMODE
#define OBJ_COUNT (OBJ_END - OBJ_START + 1)

typedef struct o {
	object_type_t type;
	int val;	// holds trust value
	char *o;	// Everything is a string

	union {
		size_t gr_index;
		attr_sets_entry_t * set;
	};
} object_attr_t;

int obj_name_to_val(const char *name);
const char *obj_val_to_name(unsigned int v);

#endif
