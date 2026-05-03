/*
* rules.h - Header file for rules.c
* Copyright (c) 2016-17,2019 Red Hat Inc.
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

#include <stdatomic.h>
#include <stdio.h>

#include "policy.h"
#include "subject-attr.h"
#include "object-attr.h"
#include "event.h"
#include "gcc-attributes.h"

#define MAX_FIELDS 11	// Subject side can have up to 11 attributes.
			// Object side can have up to 6. 11 covers both.

/* This is one node of the linked list. Any data elements that are per
 * rule goes here. */
typedef struct _lnode{
  decision_t d;
  access_t a;
  unsigned int num;
  atomic_ulong hits;
  char *text;
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
  lnode *cur;		// Mutable build/compat traversal state
  unsigned int cnt;	// How many items in this list
  attr_sets_t *sets;	// Registry that owns rule attribute sets
  unsigned int proc_status_mask; // /proc status fields needed by rules
} llist;

int rules_create(llist *l);
/*
 * rules_first/rules_next/rules_get_cur use llist.cur and are retained for
 * mutable construction-time traversal. Decision reads use local node cursors.
 */
void rules_first(llist *l);
lnode *rules_next(llist *l);
static inline lnode *rules_get_cur(const llist *l) { return l->cur; }

/* rules_first_node - get first rule for a local read cursor.
 * @l: rule list to read.
 * Return: first rule node, or NULL if the list is empty.
 */
static inline lnode *rules_first_node(const llist *l) { return l->head; }

/* rules_next_node - advance a local read cursor.
 * @n: current rule node, or NULL.
 * Return: next rule node, or NULL at the end of the list.
 */
static inline lnode *rules_next_node(const lnode *n)
{
	return n ? n->next : NULL;
}

int rules_append(llist *l, char *buf, unsigned int lineno) __wur;
__attribute__((hot)) decision_t rule_evaluate(lnode *r, event_t *e);
void rules_record_hit(lnode *r);
void rules_hits_report(FILE *f, const llist *l);
void rules_unsupport_audit(const llist *l);
void rules_clear(llist* l);
unsigned int rules_get_proc_status_mask(const llist *l);

#endif
