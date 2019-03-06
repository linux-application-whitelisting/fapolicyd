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

#ifndef TEMPORARY_DB
#define TEMPORARY_DB

#include "daemon-config.h"

typedef struct db_item {
    const char* index;
    const char* data;
    struct db_item* next;
} db_item_t;

typedef struct db_list_header {
    long count;
    struct db_item* first;
    struct db_item* last;
} db_list_t;

void init_db_list(void);
db_item_t* get_first_from_db_list(void);
int append_db_list(const char * index, const char * data);
void empty_db_list(void);

#endif
