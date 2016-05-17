/*
* object.c - Minimal linked list set of object attributes
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

#include "config.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "policy.h"
#include "object.h"

void object_create(olist *l)
{
	l->head = NULL;
	l->cur = NULL;
	l->cnt = 0;
}

void object_first(olist *l)
{
	l->cur = l->head;
}

void object_last(olist *l)
{
        register onode* window;
	
	if (l->head == NULL) {
		l->cur = NULL;
		return;
	}

        window = l->head;
	while (window->next)
		window = window->next;
	l->cur = window;
}

onode *object_next(olist *l)
{
	if (l->cur == NULL)
		return NULL;
	l->cur = l->cur->next;
	return l->cur;
}

int object_append(olist *l, object_attr_t *obj)
{
	onode* newnode;

	if (obj) { // parse up the rule
		newnode = malloc(sizeof(onode));
		newnode->o.type = obj->type;
		newnode->o.len = obj->len;
		newnode->o.o = obj->o;
	} else
		return 1;

	newnode->next = NULL;
	object_last(l);

	// if we are at top, fix this up
	if (l->head == NULL)
		l->head = newnode;
	else {	// Otherwise add pointer to newnode
		object_last(l);
		l->cur->next = newnode;
	}

	// make newnode current
	l->cur = newnode;
	l->cnt++;
	return 0;
}

onode *object_find_type(olist *l, object_type_t t)
{
	l->cur = l->head;

	while (l->cur) {
		if (l->cur->o.type == t)
			return l->cur;
		l->cur = l->cur->next;
	}
	return NULL;
}

onode *object_find_file(olist *l)
{
	l->cur = l->head;

	while (l->cur) {
		if (l->cur->o.type >= PATH && l->cur->o.type <= ODIR)
			return l->cur;
		l->cur = l->cur->next;
	}
	return NULL;
}


void object_clear(olist* l)
{
	onode* nextnode;
	register onode* current;

	current = l->head;
	while (current) {
		free(current->o.o);
		nextnode=current->next;
		free(current);
		current=nextnode;
	}
	l->head = NULL;
	l->cur = NULL;
	l->cnt = 0;
}

