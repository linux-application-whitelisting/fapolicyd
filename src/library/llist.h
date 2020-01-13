/*
 * temporary_db.h - Header file for linked list
 * Copyright (c) 2018 Red Hat Inc., Durham, North Carolina.
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
 *   Radovan Sroka <rsroka@redhat.com>
 */

#ifndef LLIST_H
#define LLIST_H

typedef struct item {
    const void * index;
    const void * data;
    struct item * next;
} list_item_t;

typedef struct list_header {
    long count;
    struct item* first;
    struct item* last;
} list_t;

void list_init(list_t * list);
list_item_t* list_get_first(list_t * list);
int list_append(list_t * list, const char * index, const char * data);
void list_empty(list_t * list);

#endif
