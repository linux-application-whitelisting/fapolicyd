/*
 * mounts.c - Minimal linked list set of mount points
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

#include "config.h"
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <errno.h>
#include <sys/stat.h>
#include "mounts.h"
#include "message.h"

void mlist_create(mlist *m)
{
        m->head = NULL;
        m->cur = NULL;
        m->cnt = 0;
}

static void mlist_last(mlist *m)
{
	register mnode* window;

	if (m->head == NULL)
		return;

	window = m->head;
	while (window->next)
		window = window->next;

	m->cur = window;
}

// Returns 0 on success and 1 on error
int mlist_append(mlist *m, const char *p)
{
        mnode* newnode;

	if (p) {
		newnode = malloc(sizeof(mnode));
		if (newnode == NULL)
			return 1;
		newnode->path = strdup(p);
		newnode->status = ADD;
	} else
		return 1;

	newnode->next = NULL;
	mlist_last(m);

	// if we are at top, fix this up
	if (m->head == NULL)
		m->head = newnode;
	else    // Otherwise add pointer to newnode
		m->cur->next = newnode;

	// make newnode current
	m->cur = newnode;
	m->cnt++;

	return 0;
}

const char *mlist_first(mlist *m)
{
	m->cur = m->head;

	if (m->cur == NULL)
		return NULL;
	return m->cur->path;
}

const char *mlist_next(mlist *m)
{
	if (m->cur == NULL)
		return NULL;

	m->cur = m->cur->next;
	if (m->cur == NULL)
		return NULL;
	return m->cur->path;
}

void mlist_mark_all_deleted(mlist *m)
{
	register mnode *n = m->head;
	while (n) {
		n->status = DELETE;
		n = n->next;
	}
}

int mlist_find(mlist *m, const char *p)
{
	register mnode *n = m->head;
	while (n) {
		if (strcmp(p, n->path) == 0) {
			m->cur = n;
			return 1;
		}
		n = n->next;
	}
	return 0;
}

void mlist_clear(mlist *m)
{
	mnode* nextnode;
	register mnode* current;

	current = m->head;
	while (current) {
		nextnode=current->next;
		free((void *)current->path);
		free((void *)current);
		current=nextnode;
	}
	m->head = NULL;
	m->cur = NULL;
	m->cnt = 0;
}

void mlist_delete_cur(mlist *m)
{
	register mnode* current;

	current = m->cur;
	if (m->head == m->cur)
	{
		m->cur  = m->cur->next;
		m->head = m->cur;
	}
	else
	{
		register mnode* previous;

		previous = m->head;
		while (previous) {
			if (previous->next == current)
			{
				previous->next = current->next;
				m->cur         = current->next;
				break;
			}
			previous = previous->next;
		}
	}
	if (current)
	{
		free((void *)current->path);
		free((void *)current);
		m->cnt--;
	}
}

