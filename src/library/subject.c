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
* Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor
* Boston, MA 02110-1335, USA.
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
#include "message.h"

//#define DEBUG

void subject_create(s_array *a)
{
	int i;

	a->subj = malloc(sizeof(subject_attr_t *) * SUBJ_COUNT);
	for (i = 0; i < SUBJ_COUNT; i++)
		a->subj[i] = NULL;
	a->cnt = 0;
	a->info = NULL;
}

#ifdef DEBUG
static void sanity_check_array(const s_array *a, const char *id)
{
	int i;
	unsigned int num = 0;
	if (a == NULL) {
		msg(LOG_DEBUG, "%s - array is NULL", id);
		abort();
	}
	for (i = 0; i < SUBJ_COUNT; i++)
		if (a->subj[i])
			num++;
	if (num != a->cnt) {
		msg(LOG_DEBUG, "%s - array corruption %u!=%u", id, num, a->cnt);
		abort();
	}
}
#else
#define sanity_check_array(a, b) do {} while(0)
#endif

subject_attr_t *subject_access(const s_array *a, subject_type_t t)
{
	sanity_check_array(a, "subject_access");
	// These store the same info, see get_subj_attr in event.c
	if (t == EXE_DIR)
		t = EXE;
	if (t >= SUBJ_START && t <= SUBJ_END)
		return a->subj[t - SUBJ_START];
	else
		return NULL;
}

// Returns 1 on failure and 0 on success
int subject_add(s_array *a, const subject_attr_t *subj)
{
	subject_attr_t* newnode;
	subject_type_t t;

	sanity_check_array(a, "subject_add 1");
	if (subj) {
		t = subj->type;
		// These store the same info, see get_subj_attr in event.c
		if (t == EXE_DIR)
			t = EXE;
		if (t >= SUBJ_START && t <= SUBJ_END) {
			newnode = malloc(sizeof(subject_attr_t));
			if (newnode == NULL)
				return 1;
			newnode->type = t;
			if (subj->type >= COMM)
				newnode->str = subj->str;
			else if (subj->type == GID)
				newnode->set = subj->set;
			else
				newnode->val = subj->val;
		} else
			return 1;
	} else
		return 1;

	a->subj[t - SUBJ_START] = newnode;
	a->cnt++;
	sanity_check_array(a, "subject_add 2");

	return 0;
}

subject_attr_t *subject_find_exe(const s_array *a)
{
	sanity_check_array(a, "subject_find_exe");
        if (a->subj[EXE - SUBJ_START])
                return a->subj[EXE - SUBJ_START];

	return NULL;
}

subject_attr_t *subject_find_comm(const s_array *a)
{
	sanity_check_array(a, "subject_find_comm");
        if (a->subj[COMM - SUBJ_START])
                return a->subj[COMM - SUBJ_START];

	return NULL;
}

void subject_clear(s_array* a)
{
	int i;
	subject_attr_t *current;

	if (a == NULL)
		return;

	sanity_check_array(a, "subject_clear");
	for (i = 0; i < SUBJ_COUNT; i++) {
		current = a->subj[i];
		if (current == NULL)
			continue;
		if (current->type == GID) {
			destroy_attr_set(current->set);
			free(current->set);
		} else if (current->type >= COMM)
			free(current->str);
		free(current);
		a->subj[i] = NULL;
	}
	clear_proc_info(a->info);
	free(a->info);
	a->info = NULL;
	free(a->subj);
	a->subj = NULL;
	a->cnt = 0;
}

void subject_reset(s_array *a, subject_type_t t)
{
	if (a == NULL)
		return;

	sanity_check_array(a, "subject_reset1");
	if (t >= SUBJ_START && t <= SUBJ_END) {
		subject_attr_t *current = a->subj[t - SUBJ_START];
		if (current == NULL)
			return;
		if (current->type == GID) {
			destroy_attr_set(current->set);
			free(current->set);
		} else if (current->type >= COMM)
			free(current->str);
		free(current);
		a->subj[t - SUBJ_START] = NULL;
		a->cnt--;
		sanity_check_array(a, "subject_reset2");
	}
}

