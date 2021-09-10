/*
 * llist.c - Linked list as a temporary memory storage
 * for trust database data
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
 *   Zoltan Fridrich <zfridric@redhat.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "message.h"
#include "llist.h"


void list_init(list_t *list)
{
	list->count = 0;
	list->first = NULL;
	list->last = NULL;
}


list_item_t *list_get_first(const list_t *list)
{
	return list->first;
}


int list_append(list_t *list, const char *index, const char *data)
{
	list_item_t *item = malloc(sizeof(list_item_t));
	if (!item) {
		msg(LOG_ERR, "Malloc failed");
		return 1;
	}

	item->index = index;
	item->data = data;
	item->next = NULL;

	if (list->first) {
		list->last->next = item;
		list->last = item;
	} else {
		list->first = item;
		list->last = item;
	}

	++list->count;
	return 0;
}


void list_destroy_item(list_item_t **item)
{
	free((void *)(*item)->index);
	free((void *)(*item)->data);
	free((*item));
	*item = NULL;
}


void list_empty(list_t *list)
{
	if (!list->first)
		return;
		
	list_item_t *actual = list->first;
	list_item_t *next = NULL;
	for (; actual; actual = next) {
		next = actual->next;
		list_destroy_item(&actual);
	}
	list_init(list);
}


// Return 1 if the list contains the string, 0 otherwise
int list_contains(list_t *list, const char *str)
{
	for (list_item_t *lptr = list->first; lptr; lptr = lptr->next) {
		if (!strcmp(str, lptr->index))
			return 1;
	}
	return 0;
}

// Return 1 if an item was removed, 0 otherwise
int list_remove(list_t *list, const char *str)
{
	list_item_t *lptr, *prev = NULL;
	for (lptr = list->first; lptr; lptr = lptr->next) {
		if (!strcmp(str, lptr->index)) {
			if (prev)
				prev->next = lptr->next;
			else
				list->first = lptr->next;
			if (!lptr->next)
				list->last = prev;
			--list->count;
			list_destroy_item(&lptr);
			return 1;
		}
		prev = lptr;
	}
	return 0;
}

void list_merge(list_t *dest, list_t *src)
{
	if (!dest->last) {
		*dest = *src;
	} else {
		dest->last->next = src->first;
		dest->count += src->count;
	}
	list_init(src);
}
