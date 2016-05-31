/*
* object.h - Header file for object.c
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

#ifndef OBJECT_HEADER
#define OBJECT_HEADER

#include "object-attr.h"

/* This is the linked list head. Only data elements that are 1 per
 * event goes here. */
typedef struct {
  object_attr_t **obj;	// Object array
  unsigned int cnt;	// How many items in this list
  struct file_info *info; // unique file fingerprint
} o_array;

void object_create(o_array *a);
object_attr_t *object_access(o_array *a, object_type_t t);
int object_add(o_array *a, object_attr_t *obj);
object_attr_t *object_find_file(o_array *a);
void object_clear(o_array *a);
static inline int type_is_obj(int type) {if (type >= OBJ_START) return 1; else return 0;}

#endif

