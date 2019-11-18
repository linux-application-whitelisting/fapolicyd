/*
* rules.h - Header file for rules.c
* Copyright (c) 2016-17,2019 Red Hat Inc., Durham, North Carolina.
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

#ifndef RULES_HEADER
#define RULES_HEADER

#include "policy.h"
#include "subject-attr.h"
#include "object-attr.h"
#include "event.h"

#define MAX_FIELDS 8

/* This is one node of the linked list. Any data elements that are per
 * rule goes here. */
typedef struct _lnode{
  decision_t d;
  access_t a;
  unsigned int num;
  rformat_t format;
  unsigned int s_count;
  unsigned int o_count;
  subject_attr_t s[MAX_FIELDS];
  object_attr_t o[MAX_FIELDS];
  struct _lnode *next;	// Next node pointer
} lnode;

/* This is the linked list head. Only data elements that are 1 per
 * event goes here. */
typedef struct {
  lnode *head;		// List head
  lnode *cur;		// Pointer to current node
  unsigned int cnt;	// How many items in this list
} llist;

void rules_create(llist *l);
void rules_first(llist *l);
lnode *rules_next(llist *l);
static inline lnode *rules_get_cur(const llist *l) { return l->cur; }
int rules_append(llist *l, char *buf, unsigned int lineno);
decision_t rule_evaluate(lnode *r, event_t *e);
void rules_unsupport_audit(llist *l);
void rules_clear(llist* l);

#endif
