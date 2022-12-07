/*
 * attr-sets.c - Attribute sets dynamic data structure
 *
 * Copyright (c) 2020 Red Hat Inc.
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
 *    Radovan Sroka <rsroka@redhat.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "attr-sets.h"
#include "message.h"

#define RESIZE_BY 2
#define DEFAULT_CAPACITY 100

attr_sets_t sets;

/*
 * this is a compare callback for avl string tree
 *
 * avl tree compare expect:
 * 0 when equals
 * <0 when a < b
 * >0 when a > b
 */
static int strcmp_cb(void * a, void * b)
{
	return strcmp(((avl_str_data_t *)a)->str, ((avl_str_data_t *)b)->str);
}

/*
 * this is a compare callback for avl int tree
 *
 * avl tree compare expect:
 * 0 when equals
 * <0 when a < b
 * >0 when a > b
 */
static int intcmp_cb(void * a, void * b)
{
	return ((avl_int_data_t *)a)->num - ((avl_int_data_t *)b)->num;
}

/*
 * this is a traverse callback for avl string tree
 * it provides directory test
 * e.g a->str = "/usr/bin/" a->len = 9
 *     b->str = "/usr/bin/ls"
 * strncmp return 0 with output above that means match
 *
 * avl tree traverse calls callback on each node and
 * it sums all return values and it returns the sum
 * so when I return 1 it just sums how many strncmp
 * returned match
 * with -1 I can break the recursion with first match
 */
static int strncmp_cb(void * a, void * b)
{
	return strncmp( ((avl_str_data_t *)a)->str,
			((avl_str_data_t *)b)->str,
			((avl_str_data_t *)a)->len)
		? 0 : -1;
}


int init_attr_sets(void)
{
	sets.resize_factor = RESIZE_BY;

	// first is reserved
	// we are using 0th index as failure return value
	sets.size = 1;
	sets.capacity = DEFAULT_CAPACITY;

	sets.array = malloc(sizeof(attr_sets_entry_t) * sets.capacity);
	if (!sets.array)
		return 1;

	memset(sets.array, 0, sets.capacity * sizeof(attr_sets_entry_t));
	return 0;
}

static int resize_attr_sets(void)
{
	size_t new_capacity = sets.capacity * sets.resize_factor;
	attr_sets_entry_t * tmp = realloc(sets.array,
					    sizeof(attr_sets_entry_t) * new_capacity);
	if (!tmp)
		return 1;

	sets.capacity = new_capacity;
	sets.array = tmp;

	return 0;
}

attr_sets_entry_t * get_attr_set(const size_t index)
{
	if (index == 0)
		return NULL;
	if (index > sets.size)
		return NULL;

	return &(sets.array[index]);
}

size_t search_attr_set_by_name(const char * name)
{
	// ignore 0th index
	for (size_t i = 1 ; i < sets.size ; i++) {
		const char * nname = sets.array[i].name;
		if (nname) {
			if (strcmp(nname, name) == 0)
				return i;
		}
	}
	return 0;
}

int add_attr_set(const char * name, const int type, size_t * index)
{
	if (sets.size == sets.capacity)
		if (resize_attr_sets())
			return 1;

	// getting last free known entry
	attr_sets_entry_t * entry = get_attr_set(sets.size);
	if (!entry)
		return 1;

	// copy string or set NULL for sure
	entry->name = name ? strdup(name) : NULL;
	entry->type = type;

	if (type == STRING)
		avl_init(&entry->tree, strcmp_cb);
	else if (type == INT)
		avl_init(&entry->tree, intcmp_cb);
	else {
	  // TODO error
	  (void)index;
	}

	*index = sets.size;
	sets.size++;

	return 0;
}

attr_sets_entry_t *init_standalone_set(const int type)
{
	attr_sets_entry_t *s = malloc(sizeof(attr_sets_entry_t));
	if (s) {
		s->name = NULL;
		s->type = type;
		if (type == STRING)
			avl_init(&s->tree, strcmp_cb);
		else
			avl_init(&s->tree, intcmp_cb);
	}
	return s;
}

int append_int_attr_set(attr_sets_entry_t * set, const int num)
{
	if (!set) return 1;

	if (set->type != INT) {
		// trying to insert wrong type?
		return 1;
	}

	avl_int_data_t * data = malloc(sizeof(avl_int_data_t));
	if (!data)
		return 1;

	data->num = num;

	avl_t * ret = avl_insert(&set->tree, (avl_t *)data);
	if (ret != (avl_t *)data) {
		// Already present in avl tree
		free(data);
		return 1;
	}

	return 0;
}

int append_str_attr_set(attr_sets_entry_t * set, const char * str)
{
	if (!set) return 1;

	if (set->type != STRING) {
		// trying to insert wrong type?
		return 1;
	}

	avl_str_data_t * data = malloc(sizeof(avl_str_data_t));
	if (!data)
		return 1;

	data->str = strdup(str);
	if (!data->str) {
		free(data);
		return 1;
	}

	data->len = strlen(str);

	avl_t * ret = avl_insert(&set->tree, (avl_t *)data);
	if (ret != (avl_t *)data) {
		// Already present in avl tree
		free((void *)data->str);
		free(data);
		return 1;
	}

	return 0;
}

int check_int_attr_set(attr_sets_entry_t * set, const int num)
{
	avl_int_data_t data;

	data.num = num;

	// we are doing following checks on upper level

	//if (!set) return 1;

	//if (set->type != INT)
	//  return -1;

	// ---------------------------------------------

	// valid pointer to data if found
	// NULL -> 0 if not
	return avl_search(&set->tree, (avl_t*)(&data)) ? 1 : 0;
}


int check_str_attr_set(attr_sets_entry_t * set, const char * str)
{
	avl_str_data_t data;

	data.str = str;

	// we are doing following checks on upper level

	//if (!set) return 1;

	//if (set->type != STRING)
	//  return -1;

	// --------------------------------------------

	// valid pointer to data if found
	// NULL -> 0 if not
	return avl_search(&set->tree, (avl_t*)(&data)) ? 1 : 0;
}

int check_pstr_attr_set(attr_sets_entry_t * set, const char * str)
{
	avl_str_data_t data;

	data.str = str;


	// we are doing following checks on upper level

	// if (!set) return 1;

	// if (set->type != STRING)
	//  return -1;

	// --------------------------------------------

	// -1 means broken recursion -> found
	// 0 means not found
	int ret = avl_traverse(&set->tree, strncmp_cb, (void*)&data);

	// want to be consistent
	if (ret == -1)
		return 1;

	return 0;
}

static int print_str(void * entry, void *data)
{
	(void) data;
	const char * str = ((avl_str_data_t *) entry)->str;
	msg(LOG_DEBUG, "%s", str);
	return 0;
}

static int print_int(void * entry, void *data)
{
	(void) data;
	const int num = ((avl_int_data_t *) entry)->num;
	msg(LOG_DEBUG, "%d", num);
	return 0;
}

void print_attr_set(attr_sets_entry_t * set)
{
	if (!set) return;

	msg(LOG_DEBUG, "Set: %s", set->name);

	if (set->type == STRING)
		avl_traverse(&set->tree, print_str, NULL);
	if (set->type == INT)
		avl_traverse(&set->tree, print_int, NULL);

	msg(LOG_DEBUG, "--------------");
}

void print_attr_sets(void)
{
	for (size_t i = 1 ; i < sets.size ; i++) {
		print_attr_set(&sets.array[i]);
	}
}

void destroy_attr_set(attr_sets_entry_t * set)
{
	if (!set) return;
	free(set->name);

	// free tree
	avl_t *cur;

	while ((cur = set->tree.root) != NULL) {

		void *tmp =(void *)avl_remove(&set->tree, cur);
		if ((avl_t *)tmp != cur)
			msg(LOG_DEBUG, "attr_set_entry: removal of invalid node");
		if (set->type == STRING) {
			free((void *)((avl_str_data_t *)tmp)->str);
		}
		free(tmp);
	}
}

void destroy_attr_sets(void)
{
	for (size_t i = 0 ; i < sets.size ; i++) {
		destroy_attr_set(&sets.array[i]);
	}
	free(sets.array);
}
