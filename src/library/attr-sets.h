/*
 * attr-sets.h - Header file for attribute sets
 * Copyright (c) 2020 Red Hat Inc., Durham, North Carolina.
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

#include "avl.h"

typedef struct _avl_str_data {
	avl avl;
	size_t len;
	const char * str;
} avl_str_data_t;

typedef struct _avl_int_data {
	avl avl;
	int num;
} avl_int_data_t;


typedef struct attr_sets_entry {
	// optional
	char * name;
	// STRING, INT from DATA_TYPES
	int type;
	avl_tree tree;
} attr_sets_entry_t;

// variable size array
typedef struct attr_sets {
	// allocated size
	size_t capacity;
	size_t size;
	size_t resize_factor;
	attr_sets_entry_t * array;
} attr_sets_t;

typedef enum _types {
		STRING = 1,
		INT,
} DATA_TYPES;


int init_attr_sets(void);
attr_sets_entry_t * get_attr_set(const size_t index);
int add_attr_set(const char * name, const int type, size_t * index);
void destroy_attr_set(attr_sets_entry_t *set);
void destroy_attr_sets(void);
size_t search_attr_set_by_name(const char * name);
attr_sets_entry_t *init_standalone_set(const int type);

int append_int_attr_set(attr_sets_entry_t * set, const int num);
int append_str_attr_set(attr_sets_entry_t * set, const char * str);

int check_int_attr_set(attr_sets_entry_t * set, const int num);
int check_str_attr_set(attr_sets_entry_t * set, const char * str);
int check_pstr_attr_set(attr_sets_entry_t * set, const char * str);

void print_attr_sets(void);
void print_attr_set(attr_sets_entry_t * set);

#endif // ATTR_SETS_H
