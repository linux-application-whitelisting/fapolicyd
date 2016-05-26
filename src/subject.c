/*
* subject.c - Minimal linked list set of subject attributes
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
#include "subject.h"

void subject_create(slist *l)
{
	l->head = NULL;
	l->cur = NULL;
	l->cnt = 0;
	l->info = NULL;
}

void subject_last(slist *l)
{
        register snode* window;
	
	if (l->head == NULL) {
		l->cur = NULL;
		return;
	}

        window = l->head;
	while (window->next)
		window = window->next;

	l->cur = window;
}

snode *subject_next(slist *l)
{
	if (l->cur == NULL)
		return NULL;
	l->cur = l->cur->next;

	return l->cur;
}

int subject_append(slist *l, subject_attr_t *subj)
{
	snode* newnode;

	if (subj) { // parse up the rule
		newnode = malloc(sizeof(snode));
		newnode->s.type = subj->type;
		if (subj->type >= COMM)
			newnode->s.str = subj->str;
		else
			newnode->s.val = subj->val;
	} else 
		return 1;

	newnode->next = NULL;
	subject_last(l);

	// if we are at top, fix this up
	if (l->head == NULL)
		l->head = newnode;
	else {	// Otherwise add pointer to newnode
		subject_last(l);
		l->cur->next = newnode;
	}

	// make newnode current
	l->cur = newnode;
	l->cnt++;
	return 0;
}

void subject_clear(slist* l)
{
	snode* nextnode;
	register snode* current;

	if (l == NULL)
		return;

	current = l->head;
	while (current) {
		if (current->s.type >= COMM)
			free(current->s.str);
		nextnode=current->next;
		free(current);
		current=nextnode;
	}
	free(l->info);
	l->head = NULL;
	l->cur = NULL;
	l->cnt = 0;
}

