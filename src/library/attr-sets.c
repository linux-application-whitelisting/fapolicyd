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

/*
 * Overview
 * --------
 *
 * Attribute sets are AVL-backed collections used by rule parsing and process
 * status caching.  Each attr_sets_entry_t is individually allocated and all
 * callers keep direct entry pointers.  A registry, attr_sets_t, owns a growing
 * array of those pointers so named policy sets can be found while parsing.
 *
 * Registry growth only reallocates the pointer array.  It never moves the set
 * entries themselves, so rule attributes can store attr_sets_entry_t pointers
 * immediately without a second index-to-pointer regeneration pass after rule
 * parsing.
 *
 * Named policy sets and temporary UID/GID sets use the same attr_set_create()
 * and attr_set_destroy() API.  The difference is only ownership: registry sets
 * are released by attr_sets_destroy(), while standalone process-cache sets are
 * released directly by attr_set_destroy().
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "attr-sets.h"
#include "message.h"

#define RESIZE_BY 2
#define DEFAULT_CAPACITY 100

struct attr_sets {
	size_t capacity;
	size_t size;
	size_t resize_factor;
	attr_sets_entry_t **array;
};

/*
 * strcmp_cb - Compare two string AVL nodes.
 * @a: first avl_str_data_t node
 * @b: second avl_str_data_t node
 *
 * Returns: 0 when equal, negative when @a sorts before @b, and positive when
 * @a sorts after @b.
 */
static int strcmp_cb(void *a, void *b)
{
	return strcmp(((avl_str_data_t *)a)->str, ((avl_str_data_t *)b)->str);
}

/*
 * intcmp_cb - Compare two signed integer AVL nodes.
 * @a: first avl_int_data_t node
 * @b: second avl_int_data_t node
 *
 * Returns: 0 when equal, -1 when @a is less than @b, and 1 when @a is greater
 * than @b.
 */
static int intcmp_cb(void *a, void *b)
{
	int64_t va = ((avl_int_data_t *)a)->num;
	int64_t vb = ((avl_int_data_t *)b)->num;

	if (va > vb)
		return 1;
	if (va < vb)
		return -1;
	return 0;
}

/*
 * unsigned_cmp_cb - Compare two unsigned integer AVL nodes.
 * @a: first avl_int_data_t node
 * @b: second avl_int_data_t node
 *
 * Returns: 0 when equal, -1 when @a is less than @b, and 1 when @a is greater
 * than @b.
 */
static int unsigned_cmp_cb(void *a, void *b)
{
	uint64_t va = (uint64_t)((avl_int_data_t *)a)->num;
	uint64_t vb = (uint64_t)((avl_int_data_t *)b)->num;

	if (va > vb)
		return 1;
	if (va < vb)
		return -1;
	return 0;
}

/*
 * strncmp_cb - Check if a set string is a prefix of a lookup string.
 * @a: avl_str_data_t node from a set
 * @b: avl_str_data_t lookup value
 *
 * Returns: -1 when the prefix matches so traversal stops, or 0 when it does
 * not match.
 */
static int strncmp_cb(void *a, void *b)
{
	return strncmp(((avl_str_data_t *)a)->str,
		       ((avl_str_data_t *)b)->str,
		       ((avl_str_data_t *)a)->len) ? 0 : -1;
}

/*
 * attr_set_init_tree - Initialize the AVL tree for one set type.
 * @set: set entry to initialize
 * @type: STRING, SIGNED, or UNSIGNED
 *
 * Returns: 0 on success and 1 when @type is not supported.
 */
static int attr_set_init_tree(attr_sets_entry_t *set, int type)
{
	if (type == STRING)
		avl_init(&set->tree, strcmp_cb);
	else if (type == SIGNED)
		avl_init(&set->tree, intcmp_cb);
	else if (type == UNSIGNED)
		avl_init(&set->tree, unsigned_cmp_cb);
	else
		return 1;

	return 0;
}

/*
 * attr_sets_resize - Grow a registry pointer array.
 * @sets: registry to grow
 *
 * Returns: 0 on success and 1 on allocation failure.
 */
static int attr_sets_resize(attr_sets_t *sets)
{
	size_t new_capacity = sets->capacity * sets->resize_factor;
	attr_sets_entry_t **tmp = realloc(sets->array,
				sizeof(attr_sets_entry_t *) * new_capacity);

	if (!tmp)
		return 1;

	sets->capacity = new_capacity;
	sets->array = tmp;

	return 0;
}

/*
 * attr_sets_create - Allocate an empty attribute set registry.
 *
 * Returns: pointer to a new registry or NULL on allocation failure.
 */
attr_sets_t *attr_sets_create(void)
{
	attr_sets_t *sets = malloc(sizeof(attr_sets_t));

	if (!sets)
		return NULL;

	sets->resize_factor = RESIZE_BY;
	sets->size = 0;
	sets->capacity = DEFAULT_CAPACITY;
	sets->array = calloc(sets->capacity, sizeof(attr_sets_entry_t *));
	if (!sets->array) {
		free(sets);
		return NULL;
	}

	return sets;
}

/*
 * attr_sets_add - Add an existing set entry to a registry.
 * @sets: registry that takes ownership of @set
 * @set: set entry to append
 *
 * Returns: 0 on success and 1 on invalid input or allocation failure.
 */
int attr_sets_add(attr_sets_t *sets, attr_sets_entry_t *set)
{
	if (!sets || !set)
		return 1;

	if (sets->size == sets->capacity)
		if (attr_sets_resize(sets))
			return 1;

	sets->array[sets->size] = set;
	sets->size++;

	return 0;
}

/*
 * attr_sets_find - Find a named set in a registry.
 * @sets: registry to search
 * @name: set name without the leading percent character
 *
 * Returns: matching set entry, or NULL when no matching name exists.
 */
attr_sets_entry_t *attr_sets_find(const attr_sets_t *sets, const char *name)
{
	if (!sets || !name)
		return NULL;

	for (size_t i = 0 ; i < sets->size ; i++) {
		attr_sets_entry_t *set = sets->array[i];

		if (set && set->name && strcmp(set->name, name) == 0)
			return set;
	}

	return NULL;
}

/*
 * attr_sets_destroy - Free a registry and every set it owns.
 * @sets: registry to destroy
 */
void attr_sets_destroy(attr_sets_t *sets)
{
	if (!sets)
		return;

	for (size_t i = 0 ; i < sets->size ; i++)
		attr_set_destroy(sets->array[i]);

	free(sets->array);
	free(sets);
}

/*
 * attr_set_create - Allocate one attribute set entry.
 * @name: optional set name, copied when provided
 * @type: STRING, SIGNED, or UNSIGNED
 *
 * Returns: pointer to a new set entry or NULL on allocation failure or invalid
 * @type.
 */
attr_sets_entry_t *attr_set_create(const char *name, const int type)
{
	attr_sets_entry_t *set = malloc(sizeof(attr_sets_entry_t));

	if (!set)
		return NULL;

	memset(set, 0, sizeof(attr_sets_entry_t));
	set->type = type;

	if (attr_set_init_tree(set, type)) {
		free(set);
		return NULL;
	}

	if (name) {
		set->name = strdup(name);
		if (!set->name) {
			free(set);
			return NULL;
		}
	}

	return set;
}

/*
 * attr_set_append_int - Add an integer value to a set.
 * @set: target SIGNED or UNSIGNED set
 * @num: value to insert
 *
 * Returns: 0 on success and 1 on invalid input, duplicate value, or allocation
 * failure.
 */
int attr_set_append_int(attr_sets_entry_t *set, const int64_t num)
{
	avl_int_data_t *data;
	avl_t *ret;

	if (!set)
		return 1;

	if (set->type != SIGNED && set->type != UNSIGNED)
		return 1;

	if (set->type == UNSIGNED && num < 0)
		return 1;

	data = malloc(sizeof(avl_int_data_t));
	if (!data)
		return 1;

	data->num = num;

	ret = avl_insert(&set->tree, (avl_t *)data);
	if (ret != (avl_t *)data) {
		free(data);
		return 1;
	}

	return 0;
}

/*
 * attr_set_append_str - Add a string value to a set.
 * @set: target STRING set
 * @str: value to copy and insert
 *
 * Returns: 0 on success and 1 on invalid input, duplicate value, or allocation
 * failure.
 */
int attr_set_append_str(attr_sets_entry_t *set, const char *str)
{
	avl_str_data_t *data;
	avl_t *ret;

	if (!set || !str)
		return 1;

	if (set->type != STRING)
		return 1;

	data = malloc(sizeof(avl_str_data_t));
	if (!data)
		return 1;

	data->str = strdup(str);
	if (!data->str) {
		free(data);
		return 1;
	}

	data->len = strlen(str);

	ret = avl_insert(&set->tree, (avl_t *)data);
	if (ret != (avl_t *)data) {
		free((void *)data->str);
		free(data);
		return 1;
	}

	return 0;
}

/*
 * attr_set_empty - Determine if a set has no members.
 * @set: set to check
 *
 * Returns: true when @set is NULL or has no entries, false otherwise.
 */
bool attr_set_empty(attr_sets_entry_t *set)
{
	if (!set)
		return true;

	return set->tree.root == NULL;
}

/*
 * attr_set_check_int - Check if an integer set contains a value.
 * @set: SIGNED or UNSIGNED set to search
 * @num: value to search for
 *
 * Returns: 1 when found and 0 when not found or input is invalid.
 */
int attr_set_check_int(attr_sets_entry_t *set, const int64_t num)
{
	avl_int_data_t data;

	if (!set || (set->type != SIGNED && set->type != UNSIGNED))
		return 0;

	if (set->type == UNSIGNED && num < 0)
		return 0;

	data.num = num;

	return avl_search(&set->tree, (avl_t *)(&data)) ? 1 : 0;
}

/*
 * attr_set_check_str - Check if a string set contains a value.
 * @set: STRING set to search
 * @str: value to search for
 *
 * Returns: 1 when found and 0 when not found or input is invalid.
 */
int attr_set_check_str(attr_sets_entry_t *set, const char *str)
{
	avl_str_data_t data;

	if (!set || set->type != STRING || !str)
		return 0;

	data.str = str;

	return avl_search(&set->tree, (avl_t *)(&data)) ? 1 : 0;
}

/*
 * attr_set_check_pstr - Check if any set entry prefixes a string.
 * @set: STRING set containing possible prefixes
 * @str: value to test against the set
 *
 * Returns: 1 when a prefix matches and 0 when no prefix matches or input is
 * invalid.
 */
int attr_set_check_pstr(attr_sets_entry_t *set, const char *str)
{
	avl_str_data_t data;
	int ret;

	if (!set || set->type != STRING || !str)
		return 0;

	data.str = str;

	ret = avl_traverse(&set->tree, strncmp_cb, (void *)&data);
	if (ret == -1)
		return 1;

	return 0;
}

/*
 * print_str - Print one string set entry.
 * @entry: avl_str_data_t entry to print
 * @data: unused traversal callback data
 *
 * Returns: 0 to continue traversal.
 */
static int print_str(void *entry, void *data)
{
	(void)data;
	const char *str = ((avl_str_data_t *)entry)->str;

	msg(LOG_DEBUG, "%s", str);
	return 0;
}

/*
 * print_signed - Print one signed integer set entry.
 * @entry: avl_int_data_t entry to print
 * @data: unused traversal callback data
 *
 * Returns: 0 to continue traversal.
 */
static int print_signed(void *entry, void *data)
{
	(void)data;
	int64_t num = ((avl_int_data_t *)entry)->num;

	msg(LOG_DEBUG, "%lld", (long long)num);
	return 0;
}

/*
 * print_unsigned - Print one unsigned integer set entry.
 * @entry: avl_int_data_t entry to print
 * @data: unused traversal callback data
 *
 * Returns: 0 to continue traversal.
 */
static int print_unsigned(void *entry, void *data)
{
	(void)data;
	uint64_t num = (uint64_t)((avl_int_data_t *)entry)->num;

	msg(LOG_DEBUG, "%llu", (unsigned long long)num);
	return 0;
}

/*
 * attr_set_print - Print one set for debugging.
 * @set: set to print
 */
void attr_set_print(attr_sets_entry_t *set)
{
	if (!set)
		return;

	msg(LOG_DEBUG, "Set: %s", set->name ? set->name : "(anonymous)");

	if (set->type == STRING)
		avl_traverse(&set->tree, print_str, NULL);
	else if (set->type == SIGNED)
		avl_traverse(&set->tree, print_signed, NULL);
	else if (set->type == UNSIGNED)
		avl_traverse(&set->tree, print_unsigned, NULL);

	msg(LOG_DEBUG, "--------------");
}

/*
 * attr_sets_print - Print all registry-owned sets for debugging.
 * @sets: registry to print
 */
void attr_sets_print(const attr_sets_t *sets)
{
	if (!sets)
		return;

	for (size_t i = 0 ; i < sets->size ; i++)
		attr_set_print(sets->array[i]);
}

/*
 * attr_set_destroy - Free one set entry and all member values.
 * @set: set entry to destroy
 */
void attr_set_destroy(attr_sets_entry_t *set)
{
	avl_t *cur;

	if (!set)
		return;

	free(set->name);

	while ((cur = set->tree.root) != NULL) {
		void *tmp = (void *)avl_remove(&set->tree, cur);

		if ((avl_t *)tmp != cur)
			msg(LOG_DEBUG, "attr_set_entry: removal of invalid node");
		if (set->type == STRING)
			free((void *)((avl_str_data_t *)tmp)->str);
		free(tmp);
	}

	free(set);
}
