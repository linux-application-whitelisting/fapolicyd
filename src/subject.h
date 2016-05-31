/*
* subject.h - Header file for subject.c
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

#ifndef SUBJECT_HEADER
#define SUBJECT_HEADER

#include "subject-attr.h"
#include "process.h"

/* This is the attribute array. Only data elements that are 1 per
 * event goes here. */
typedef struct {
  subject_attr_t **subj;	// Subject array
  unsigned int cnt;		// How many items in this list
  struct proc_info *info;	// unique proc fingerprint
} s_array;

void subject_create(s_array *a);
subject_attr_t *subject_access(s_array *a, subject_type_t t);
int subject_add(s_array *a, subject_attr_t *subj);
void subject_clear(s_array* a);
static inline int type_is_subj(int type) {if (type < OBJ_START) return 1; else return 0;}

#endif

