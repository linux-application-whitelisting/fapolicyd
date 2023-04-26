/*
* filter.h - Header for a filter implementation
* Copyright (c) 2023 Red Hat Inc., Durham, North Carolina.
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

#ifndef FILTER_H_
#define FILTER_H_

#include <stdlib.h>
#include <stddef.h>

#include "llist.h"

typedef enum filter_type
{
	NONE,
	ADD,
	SUB,
	COMMENT,
	BAD,
} filter_type_t;

typedef struct _filter
{
	filter_type_t type;
	char * path;
	size_t len;
	int processed;
	int matched;
	list_t list;
} filter_t;


typedef struct _stack_item
{
	int level;
	int offset;
	filter_t *filter;
} stack_item_t;


int filter_init(void);
void filter_destroy(void);
int filter_check(const char *_path);
int filter_load_file(void);


#endif // FILTER_H_
