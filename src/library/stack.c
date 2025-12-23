/*
* stack.c - generic stack impementation
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

#include "stack.h"
#include <stddef.h>

// init of the stack struct
void stack_init(stack_t *_stack)
{
	if (_stack == NULL)
		return;

	list_init(_stack);
}

// free all the resources from the stack
void stack_destroy(stack_t *_stack)
{
	if (_stack == NULL)
		return;

	list_empty(_stack);
}

// push to the top of the stack
void stack_push(stack_t *_stack, void *_data)
{
	if (_stack == NULL)
		return;

	list_prepend(_stack, NULL, (void *)_data);
}

// pop the the top without returning what was on the top
void stack_pop(stack_t *_stack)
{
	if (_stack == NULL)
		return;

	list_item_t *first = _stack->first;
	_stack->first = first->next;
	first->data = NULL;
	list_destroy_item(&first);
	_stack->count--;

	return;
}

// function returns 1 if stack is emtpy 0 if it's not
int stack_is_empty(const stack_t *_stack)
{
	if (_stack == NULL)
		return -1;

	if (_stack->count == 0)
		return 1;

	return 0;
}

// return top of the stack without popping
const void *stack_top(const stack_t *_stack)
{
	if (_stack == NULL)
		return NULL;

	return _stack->first ? _stack->first->data : NULL;
}
