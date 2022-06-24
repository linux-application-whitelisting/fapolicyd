/*
* stack.h - header for generic stack implementation
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


#ifndef STACK_H_
#define STACK_H_

#include "llist.h"

typedef list_t stack_t;

void stack_init(stack_t *_stack);
void stack_destroy(stack_t *_stack);
void stack_push(stack_t *_stack, void *_data);
void stack_pop(stack_t *_stack);
int stack_is_empty(stack_t *_stack);
const void *stack_top(stack_t *_stack);


#endif // STACK_H_
