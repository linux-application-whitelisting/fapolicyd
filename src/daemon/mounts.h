/*
 * mounts.h - Header file for mounts.c
 * Copyright (c) 2019 Red Hat Inc.
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

#ifndef MOUNTS_HEADER
#define MOUNTS_HEADER

typedef enum { NO_CHANGE, ADD, DELETE } change_t;

typedef struct _mnode{
	const char *path;
	change_t status;
	struct _mnode *next;  // Next node pointer
} mnode;

typedef struct {
	mnode *head;          // List head
	mnode *cur;           // Pointer to current node
	unsigned int cnt;     // How many items in this list
} mlist;

void mlist_create(mlist *m);
const char *mlist_first(mlist *m);
const char *mlist_next(mlist *m);
void mlist_mark_all_deleted(mlist *l);
int mlist_find(mlist *m, const char *p);
int mlist_append(mlist *m, const char *p);
void mlist_clear(mlist *m);
void mlist_delete_cur(mlist *m);

#endif
