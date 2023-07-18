/*
* filter.c - filter for a trust source
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

#include "filter.h"

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <fnmatch.h>

#include "llist.h"
#include "stack.h"
#include "message.h"
#include "string-util.h"

#define OLD_FILTER_FILE "/etc/fapolicyd/rpm-filter.conf"
#define FILTER_FILE "/etc/fapolicyd/fapolicyd-filter.conf"

filter_t *global_filter = NULL;

static filter_t *filter_create_obj(void);
static void filter_destroy_obj(filter_t *_filter);

// init fuction of this module
int filter_init(void)
{
	global_filter = filter_create_obj();
	if (global_filter == NULL)
		return 1;

	return 0;
}

// destroy funtion of this module
void filter_destroy(void)
{
	filter_destroy_obj(global_filter);
	global_filter = NULL;
}

// alocate new filter object and fill with the defaults
static filter_t *filter_create_obj(void)
{
	filter_t *filter = malloc(sizeof(filter_t));
	if (filter) {
		filter->type = NONE;
		filter->path = NULL;
		filter->len = 0;
		filter->matched = 0;
		filter->processed = 0;
		list_init(&filter->list);
	}
	return filter;
}

// free all nested filters
static void filter_destroy_obj(filter_t *_filter)
{
	if (_filter == NULL)
		return;

	filter_t *filter = _filter;
	stack_t stack;
	stack_init(&stack);

	stack_push(&stack, filter);

	while (!stack_is_empty(&stack)) {
		filter = (filter_t*)stack_top(&stack);
		if (filter->processed) {
			(void)free(filter->path);
			// asume that item->data is NULL
			list_empty(&filter->list);
			(void)free(filter);
			stack_pop(&stack);
			continue;
		}

		list_item_t *item = list_get_first(&filter->list);
		for (; item != NULL ; item = item->next) {
				filter_t *next_filter = (filter_t*)item->data;
				// we can use list_empty() later
				// we dont want to free filter right now
				// it will freed after popping
				item->data = NULL;
				stack_push(&stack, next_filter);
		}
		filter->processed = 1;
	}
	stack_destroy(&stack);
}

// create struct and push it to the top of stack
static void stack_push_vars(stack_t *_stack, int _level, int _offset, filter_t *_filter)
{
	if (_stack == NULL)
		return;

	stack_item_t *item = malloc(sizeof(stack_item_t));
	if (item == NULL)
		return;

	item->level = _level;
	item->offset = _offset;
	item->filter = _filter;

	stack_push(_stack, item);
}

// pop stack_item_t and free it
static void stack_pop_vars(stack_t *_stack)
{
	if (_stack == NULL)
		return;

	stack_item_t * item = (stack_item_t*)stack_top(_stack);
	free(item);
	stack_pop(_stack);
}

// pop all the stack_item_t and free them
static void stack_pop_all_vars(stack_t *_stack)
{
	if (_stack == NULL)
		return;

	while (!stack_is_empty(_stack))
		stack_pop_vars(_stack);
}

// reset filter to default, pop top and free
static void stack_pop_reset(stack_t *_stack)
{
	if (_stack == NULL)
		return;

	stack_item_t *stack_item = (stack_item_t*)stack_top(_stack);
	if (stack_item) {
		stack_item->filter->matched = 0;
		stack_item->filter->processed = 0;
	}
	free(stack_item);
	stack_pop(_stack);
}

// reset and pop all the stack_item_t
static void stack_pop_all_reset(stack_t *_stack)
{
	if (_stack == NULL)
		return;

	while (!stack_is_empty(_stack))
		stack_pop_reset(_stack);
}

// this funtion gets full path and checks it against filter
// returns 1 for keeping the file and 0 for dropping it
int filter_check(const char *_path)
{
	if (_path == NULL) {
		msg(LOG_ERR, "filter_check: path is NULL, something is wrong!");
		return 0;
	}

	filter_t *filter = global_filter;
	char *path = strdup(_path);
	size_t path_len = strlen(_path);
	size_t offset = 0;
	// Create a stack to store the filters that need to be checked
	stack_t stack;
	stack_init(&stack);

	int res = 0;
	int level = 0;

	stack_push_vars(&stack, level, offset, filter);

	while(!stack_is_empty(&stack)) {
		int matched = 0;
		filter->processed = 1;

		// this is starting branch of the algo
		// assuming that in root filter filter->path is NULL
		if (filter->path == NULL) {
			list_item_t *item = list_get_first(&filter->list);
			// push all the descendants to the stack
			for (; item != NULL ; item = item->next) {
				filter_t *next_filter = (filter_t*)item->data;
				stack_push_vars(&stack, level+1, offset, next_filter);
			}

		// usual branch, start with processing
		} else {
			// wildcard contition
			char *is_wildcard = strpbrk(filter->path, "?*[");
			if (is_wildcard) {
				int count = 0;
				char *filter_lim, *filter_old_lim;
				filter_lim = filter_old_lim = filter->path;

				char *path_lim, *path_old_lim;
				path_lim = path_old_lim = path+offset;

				// there can be wildcard in the dir name as well
				// we need to count how many chars can be eaten by wildcard
				while(1) {
					filter_lim = strchr(filter_lim, '/');
					path_lim = strchr(path_lim, '/');

					if (filter_lim) {
						count++;
						filter_old_lim = filter_lim;
						filter_lim++;
					} else
						break;

					if (path_lim) {
						path_old_lim = path_lim;
						path_lim++;
					} else
						break;

				}
				// put 0 after the last /
				char tmp = '\0';
				if (count && *(filter_old_lim+1) == '\0') {
					 tmp = *(path_old_lim+1);
					*(path_old_lim+1) = '\0';
				}

				// check fnmatch
				matched = !fnmatch(filter->path, path+offset, 0);

				// and set back
				if (count && *(filter_old_lim+1) == '\0')
					*(path_old_lim+1) = tmp;

				if (matched) {
					offset = path_old_lim - path+offset;
				}
			} else {
				// match normal path or just specific part of it
				matched = !strncmp(path+offset, filter->path, filter->len);
				if (matched)
					offset += filter->len;
			}

			if (matched) {
				level++;
				filter->matched = 1;

				// if matched we need ot push descendants to the stack
				list_item_t *item = list_get_first(&filter->list);

				// if there are no descendants and it is a wildcard then it's a match
				if (item == NULL && is_wildcard) {
					// if '+' ret 1 and if '-' ret 0
					res = filter->type == ADD ? 1 : 0;
					goto end;
				}

				// no descendants, and already compared whole path string so its a match
				if (item == NULL && path_len == offset) {
					// if '+' ret 1 and if '-' ret 0
					res = filter->type == ADD ? 1 : 0;
					goto end;
				}

				// push descendants to the stack
				for (; item != NULL ; item = item->next) {
					filter_t *next_filter = (filter_t*)item->data;
					stack_push_vars(&stack, level, offset, next_filter);
				}

			}

		}

		stack_item_t * stack_item = NULL;
		// popping processed filters from the top of the stack
		do {
			if (stack_item) {
				filter = stack_item->filter;
				offset = stack_item->offset;
				level = stack_item->level;

				// assuimg that nothing has matched on the upper level so it's a directory match
				if (filter->matched && filter->path[filter->len-1] == '/') {
					res = filter->type == ADD ? 1 : 0;
					goto end;
				}

				// reset processed flag
				stack_pop_reset(&stack);
			}

			stack_item = (stack_item_t*)stack_top(&stack);
		} while(stack_item && stack_item->filter->processed);

		if (!stack_item)
			break;

		filter = stack_item->filter;
		offset = stack_item->offset;
		level = stack_item->level;
	}

end:
	// Clean up the stack
	stack_pop_all_reset(&stack);
	stack_destroy(&stack);
	free(path);
	return res;
}

// load filter configuration file and fill the filter structure
int filter_load_file(void)
{
	int res = 0;
	FILE *stream = fopen(OLD_FILTER_FILE, "r");

	if (stream == NULL) {

		stream = fopen(FILTER_FILE, "r");
		if (stream == NULL) {
			msg(LOG_ERR, "Cannot open filter file %s", FILTER_FILE);
			return 1;
		}
	} else {
		msg(LOG_INFO, "Using old filter file: %s, use the new one: %s", OLD_FILTER_FILE, FILTER_FILE);
		msg(LOG_INFO, "Consider 'mv %s %s'", OLD_FILTER_FILE, FILTER_FILE);
	}

	ssize_t nread;
	size_t len = 0;
	char * line = NULL;
	long line_number = 0;
	int last_level = 0;

	stack_t stack;
	stack_init(&stack);
	stack_push_vars(&stack, last_level, 0, global_filter);

	while ((nread = getline(&line, &len, stream)) != -1) {
		line_number++;

		if (line[0] == '\0' || line[0] == '\n') {
			free(line);
			line = NULL;
			continue;
		}

		// get rid of the new line char
		char * new_line = strchr(line, '\n');
		if (new_line) {
			*new_line = '\0';
			len--;
		}

		int level = 1;
		char * rest = line;
		filter_type_t type = NONE;

		for (size_t i = 0 ; i < len ; i++) {
			switch (line[i]) {
				case ' ':
					level++;
					continue;
				case '+':
					type = ADD;
					break;
				case '-':
					type = SUB;
					break;
				case '#':
					type = COMMENT;
					break;
				default:
					type = BAD;
					break;
			}

			// continue with next char
			// skip + and space
			rest = fapolicyd_strtrim(&(line[i+2]));
			break;
		}

		// ignore comment
		if (type == COMMENT) {
			free(line);
			line = NULL;
			continue;
		}

		// if something bad return error
		if (type == BAD) {
			msg(LOG_ERR, "filter_load_file: cannot parse line number %ld, \"%s\"", line_number, line);
			free(line);
			line = NULL;
			goto bad;
		}

		filter_t * filter = filter_create_obj();

		if (filter) {
			filter->path = strdup(rest);
			filter->len = strlen(filter->path);
			filter->type = type;
		}

		// comparing level of indetantion between the last line and the current one
		last_level = ((stack_item_t*)stack_top(&stack))->level;
		if (level == last_level) {

			// since we are at the same level as filter before
			// we need to pop the previous filter from the top
			stack_pop_vars(&stack);

			// pushing filter to the list of top's children list
			list_prepend(&((stack_item_t*)stack_top(&stack))->filter->list, NULL, (void*)filter);

			// pushing filter to the top of the stack
			stack_push_vars(&stack, level, 0, filter);

		} else if (level == last_level + 1) {
			// this filter has higher level tha privious one
			// we wont do pop just push

			// pushing filter to the list of top's children list
			list_prepend(&((stack_item_t*)stack_top(&stack))->filter->list, NULL, (void*)filter);

			// pushing filter to the top of the stack
			stack_push_vars(&stack, level, 0, filter);

		} else if (level < last_level){
			// level of indentation dropped
			// we need to pop
			// +1 is meant for getting rid of the current level so we can again push
			for (int i = 0 ; i < last_level - level + 1; i++) {
				stack_pop_vars(&stack);
			}

			// pushing filter to the list of top's children list
			list_prepend(&((stack_item_t*)stack_top(&stack))->filter->list, NULL, (void*)filter);

			// pushing filter to the top of the stack
			stack_push_vars(&stack, level, 0, filter);

		} else {
			msg(LOG_ERR, "filter_load_file: paring error line: %ld, \"%s\"", line_number, line);
			filter_destroy_obj(filter);
			free(line);
			line = NULL;
			goto bad;
		}
	}

	if (line) {
		free(line);
		line = NULL;
	}

	goto good;
bad:
	res = 1;

good:
	fclose(stream);
	stack_pop_all_vars(&stack);
	stack_destroy(&stack);
	if (global_filter->list.count == 0) {
		msg(LOG_ERR, "filter_load_file: no valid filter provided in %s", FILTER_FILE);
	}
	return res;
}
