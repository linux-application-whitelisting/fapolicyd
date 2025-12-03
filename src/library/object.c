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
#include "object.h"
#include "message.h"

//#define DEBUG

void object_create(o_array *a)
{
	int i;

	a->obj = malloc(sizeof(object_attr_t *) * OBJ_COUNT);
	for (i = 0; i < OBJ_COUNT; i++)
		a->obj[i] = NULL;
	a->cnt = 0;
	a->info = NULL;
}

#ifdef DEBUG
static void sanity_check_array(const o_array *a, const char *id)
{
	int i;
	unsigned int num = 0;
	for (i = 0; i < OBJ_COUNT; i++)
		if (a->obj[i])
			num++;
	if (num != a->cnt) {
		msg(LOG_DEBUG, "%s - array corruption %u!=%u", id, num, a->cnt);
		abort();
	}
}
#else
#define sanity_check_array(a, b) do {} while(0)
#endif

object_attr_t *object_access(const o_array *a, object_type_t t)
{
	sanity_check_array(a, "object_access");
	if (t >= OBJ_START && t <= OBJ_END)
		return a->obj[t - OBJ_START];
	else
		return NULL;
}

// Returns 1 on failure and 0 on success
int object_add(o_array *a, const object_attr_t *obj)
{
	object_attr_t *newnode;

	sanity_check_array(a, "object_add 1");
	if (obj) {
		if (obj->type >= OBJ_START && obj->type <= OBJ_END) {
			newnode = malloc(sizeof(object_attr_t));
			if (newnode == NULL)
				return 1;
			newnode->type = obj->type;
			newnode->o = obj->o;
			newnode->val = obj->val;
		} else
			return 1;
	} else
		return 1;

	if (a->obj[obj->type - OBJ_START]) {
		free(a->obj[obj->type - OBJ_START]->o);
		free(a->obj[obj->type - OBJ_START]);
	} else {
		a->cnt++;
	}

	a->obj[obj->type - OBJ_START] = newnode;

	return 0;
}

object_attr_t *object_find_file(const o_array *a)
{
	sanity_check_array(a, "object_find_file");
	if (a->obj[PATH - OBJ_START])
		return a->obj[PATH - OBJ_START];
	else
		return a->obj[ODIR - OBJ_START];
}


void object_clear(o_array *a)
{
	int i;
	object_attr_t *current;

	if (a == NULL)
		return;

	for (i = 0; i < OBJ_COUNT; i++) {
		current = a->obj[i];
		if (current == NULL)
			continue;
		free(current->o);
		free(current);
	}
	free(a->info);
	free(a->obj);
	a->cnt = 0;
}
