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
 * Free Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * Authors:
 *  Steve Grubb <sgrubb@redhat.com>
 */

#ifndef OBJECT_ATTR_HEADER
#define OBJECT_ATTR_HEADER

#include <sys/types.h>
#include "nv.h"

typedef enum { ALL_OBJ = OBJ_START, PATH, ODIR, DEVICE, FTYPE,
		SHA256HASH, FMODE } object_type_t;

#define OBJ_END FMODE

typedef struct o {
	object_type_t type;
	size_t len;	// String length of 'o' used by rules not events
	char *o;	// Everything is a string
} object_attr_t;

int obj_name_to_val(const char *name);
const char *obj_val_to_name(unsigned int v);

#endif
