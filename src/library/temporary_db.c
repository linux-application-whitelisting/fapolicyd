/*
 * temporary_db.c - Linked list as a temporary memory storage
 * for rpm databse data
 * Copyright (c) 2016,2018 Red Hat Inc., Durham, North Carolina.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "message.h"
#include "temporary_db.h"

static db_list_t list_header;

void init_db_list() {
    list_header.count = 0;
    list_header.first = NULL;
    list_header.last = NULL;
}

db_item_t* get_first_from_db_list(void) {
    return list_header.first;
}

int append_db_list(const char * index, const char * data) {
    db_item_t* item;

    if ((item = (db_item_t*)malloc(sizeof(db_item_t))) == NULL) {
        msg(LOG_ERR, "Malloc failed");
        return 1;
    }

    item->index = index;
    item->data = data;
    item->next = NULL;

    if (list_header.first == NULL) {
        list_header.first = item;
        list_header.last = item;
    } else {
        db_item_t* tmp = list_header.last;
        list_header.last = item;
        tmp->next = item;
    }

    list_header.count++;
    return 0;
}

static void destroy_db_item(db_item_t** item) {
    free((void*)(*item)->index);
    free((void*)(*item)->data);
    free((*item));
    *item = NULL;
}

void empty_db_list(void) {
    if (list_header.first == NULL) {
        return;
    } else {
        db_item_t* actual = list_header.first;
        db_item_t* next = NULL;
        for (; actual != NULL ; actual = next) {
            next = actual->next;
            destroy_db_item(&actual);
        }

        list_header.first = NULL;
        list_header.last = NULL;
        list_header.count = 0;
    }
}
