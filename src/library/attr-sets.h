/*
 * attr-sets.h - Header file for attribute sets
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
 *   Radovan Sroka <rsroka@redhat.com>
 */

#ifndef ATTR_SETS_H
#define ATTR_SETS_H

#include "stddef.h"
#include <stdint.h>
#include <stdbool.h>

#include "avl.h"

typedef struct _avl_str_data {
	avl_t avl;
	size_t len;
	const char * str;
} avl_str_data_t;

typedef struct _avl_int_data {
	avl_t avl;
	int64_t num;
} avl_int_data_t;


typedef struct attr_sets_entry {
	// optional
	char * name;
	// STRING, SIGNED, or UNSIGNED from DATA_TYPES
	int type;
	avl_tree_t tree;
} attr_sets_entry_t;

typedef struct attr_sets attr_sets_t;

typedef enum _types {
		STRING = 1,
		SIGNED,
		UNSIGNED,
} DATA_TYPES;


attr_sets_t *attr_sets_create(void);
void attr_sets_destroy(attr_sets_t *sets);
int attr_sets_add(attr_sets_t *sets, attr_sets_entry_t *set);
attr_sets_entry_t *attr_sets_find(const attr_sets_t *sets, const char *name);

attr_sets_entry_t *attr_set_create(const char *name, const int type);
void attr_set_destroy(attr_sets_entry_t *set);

int attr_set_append_int(attr_sets_entry_t *set, const int64_t num);
int attr_set_append_str(attr_sets_entry_t *set, const char *str);

int attr_set_check_int(attr_sets_entry_t *set, const int64_t num);
int attr_set_check_str(attr_sets_entry_t *set, const char *str);
int attr_set_check_pstr(attr_sets_entry_t *set, const char *str);

bool attr_set_empty(attr_sets_entry_t *set);

void attr_sets_print(const attr_sets_t *sets);
void attr_set_print(attr_sets_entry_t *set);

#endif // ATTR_SETS_H
