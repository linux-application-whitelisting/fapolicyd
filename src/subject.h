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

/* This is the node of the linked list. message & item are the only elements
 * at this time. Any data elements that are per item goes here. */
typedef struct _snode{
  subject_attr_t s;
  struct _snode *next;	// Next node pointer
} snode;

/* This is the linked list head. Only data elements that are 1 per
 * event goes here. */
typedef struct {
  snode *head;		// List head
  snode *cur;		// Pointer to current node
  unsigned int cnt;	// How many items in this list
  struct proc_info *info;	// unique proc fingerprint
} slist;

void subject_create(slist *l);
void subject_first(slist *l);
void subject_last(slist *l);
snode *subject_next(slist *l);
static inline snode *subject_get_cur(const slist *l) { return l->cur; }
int subject_append(slist *l, subject_attr_t *subj);
void subject_clear(slist* l);
static inline int type_is_subj(int type) {if (type < OBJ_START) return 1; else return 0;}

#endif

