/*
* filter.c - filter for a trust source
* Copyright (c) 2023 Red Hat Inc.
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

/*
 * Overview
 * -------
 *
 * Filters are stored in a tree.  Each node describes a path fragment and
 * whether it should be kept (ADD) or dropped (SUB).  The tree is walked using
 * an explicit stack rather than recursion.  Stack items track the current
 * filter node, the depth level and an offset into the path being evaluated.
 *
 * Three major users of the stack exist:
 *
 *  - filter_check() walks the tree comparing a path against the filters.
 *  - filter_load_file() builds the tree from an indented configuration file.
 *  - filter_destroy_obj() iteratively frees the tree.
 *
 * Using a stack keeps memory usage predictable and avoids deep recursion when
 * filters contain many nested paths.
 *
 * Assumption: real-world filter nesting is shallow (Fedora default max = 4).
 * MAX_FILTER_DEPTH is set to 64 for safety; raise it if installers add deeper
 * trees.
 */

#include "config.h"
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <fnmatch.h>

#include "filter.h"
#include "stack.h"
#include "message.h"
#include "string-util.h"
#include "paths.h"

#pragma GCC optimize("O3")

filter_t *global_filter = NULL;
static FILE *trace = NULL;
#define FILTER_TRACE(fmt, ...) \
do { \
if (trace) \
	fprintf(trace, fmt, ##__VA_ARGS__); \
} while (0)

void filter_set_trace(FILE *stream)
{
	trace = stream;
}


static filter_t *filter_create_obj(void);
static void filter_destroy_obj(filter_t *_filter);

/*
 * filter_init - initialize module and global filter tree
 * Returns 0 on success and 1 on failure.
 */
int filter_init(void)
{
	global_filter = filter_create_obj();
	if (global_filter == NULL)
		return 1;

	return 0;
}

/*
 * filter_destroy - free global filter tree
 */
void filter_destroy(void)
{
	filter_destroy_obj(global_filter);
	global_filter = NULL;
}

/*
 * filter_create_obj - allocate filter object and fill with defaults
 * Returns pointer to new object or NULL on failure.
 */
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

/*
 * filter_destroy_obj - free filter tree rooted at _filter
 * Uses an explicit stack to avoid deep recursion.
 */
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
			// assume that item->data is NULL (list nodes were
			// cleared earlier)
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
		/* mark node as processed so it will be freed on next pass */
		filter->processed = 1;
	}
	stack_destroy(&stack);
}

/*
 * stack_push_vars - create context item & push it to the top of traversal stack
 * Returns 0 on success and -1 if MAX_FILTER_DEPTH would be exceeded.
 */
static int stack_push_vars(stack_t *_stack, stack_item_t *buf, int *sp,
			   int _level, int _offset, filter_t *_filter)
{
	if (_stack == NULL || buf == NULL || sp == NULL)
		return -1;
	if (*sp >= MAX_FILTER_DEPTH)
		return -1; /* TODO: trie rewrite to remove depth limit */

	stack_item_t *item = &buf[(*sp)++];
	item->level = _level;
	item->offset = _offset;
	item->filter = _filter;

	stack_push(_stack, item);
	return 0;
}

/*
 * stack_pop_vars - pop context item from traversal stack
 */
static void stack_pop_vars(stack_t *_stack, int *sp)
{
	if (_stack == NULL || sp == NULL || *sp <= 0)
		return;

	stack_pop(_stack);
	(*sp)--;
}

/*
 * stack_pop_all_vars - pop all context items
 */
static void stack_pop_all_vars(stack_t *_stack, int *sp)
{
	if (_stack == NULL || sp == NULL)
		return;

	while (!stack_is_empty(_stack))
		stack_pop_vars(_stack, sp);
}

/*
 * stack_pop_reset - reset flags and pop top item
 */
static void stack_pop_reset(stack_t *_stack, int *sp)
{
	if (_stack == NULL || sp == NULL || *sp <= 0)
		return;

	stack_item_t *item = (stack_item_t *)stack_top(_stack);
	if (item && item->filter) {
		item->filter->processed = 0;
		item->filter->matched = 0;
	}

	stack_pop(_stack);
	(*sp)--;
}

/*
 * stack_pop_all_reset - reset and pop all stack items
 */
static void stack_pop_all_reset(stack_t *_stack, int *sp)
{
	if (_stack == NULL || sp == NULL)
		return;

	while (!stack_is_empty(_stack))
		stack_pop_reset(_stack, sp);
}

/*
 * filter_check - compare path against loaded filters
 * @_path: full path of file to test
 * Returns FILTER_ALLOW if file should be kept, FILTER_DENY if it should be
 * dropped, or FILTER_ERR_DEPTH if MAX_FILTER_DEPTH is exceeded.
 */
filter_rc_t filter_check(const char *_path)
{
	if (_path == NULL) {
		msg(LOG_ERR, "filter_check: path is NULL, something is wrong!");
		return 0;
	}

	filter_t *filter = global_filter;
	size_t path_len = strlen(_path);
	char *path = alloca(path_len + 1);
	strcpy(path, _path);
	/* Reject paths with parent directory references */
	if ((path[0] == '.' && path[1] == '.' &&
		(path[2] == '/' || path[2] == '\0')) ||
		strstr(path, "/../") != NULL ||
		    (path_len >= 3 && strcmp(path + path_len - 3, "/..") == 0))
		return FILTER_DENY;
	/* offset tracks how much of the path has already matched */
	size_t offset = 0;
	/* Create a stack to store the filters that need to be checked */
	stack_t stack;
	stack_init(&stack);
	stack_item_t stack_buf[MAX_FILTER_DEPTH];
	int sp = 0;

	filter_rc_t res = FILTER_DENY;
	int level = 0;

	if (stack_push_vars(&stack, stack_buf, &sp, level, offset, filter)) {
		msg(LOG_WARNING,
		    "fapolicyd: rule nesting exceeds MAX_FILTER_DEPTH (%d)\n",
		    MAX_FILTER_DEPTH);
		stack_destroy(&stack);
		return FILTER_ERR_DEPTH; /* TODO: trie rewrite removes limit */
	}

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
				if (stack_push_vars(&stack, stack_buf, &sp,
						    level+1, offset,
						    next_filter)) {
					msg(LOG_WARNING,
		    "fapolicyd: rule nesting exceeds MAX_FILTER_DEPTH (%d)\n",
					    MAX_FILTER_DEPTH);
					res = FILTER_ERR_DEPTH;
					goto end;
				}
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
				// we need to count how many chars can be eaten
				// by wildcard
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

				// check fnmatch against remaining path
				matched = !fnmatch(filter->path, path+offset,0);

				// restore original path string
				if (count && *(filter_old_lim+1) == '\0')
					*(path_old_lim+1) = tmp;

				if (matched) {
					offset = path_old_lim - path+offset;
				}
			} else {
				// match normal path or just specific part of it
				matched = !strncmp(path+offset, filter->path,
						   filter->len);
				if (matched)
					offset += filter->len;
			}

			if (matched) {
				level++;
				filter->matched = 1;

				// if matched we need ot push descendants
				// to the stack
				list_item_t *item = list_get_first(&filter->list);

				// if there are no descendants and it is
				// a wildcard then it's a match
				if (item == NULL && is_wildcard) {
					// if '+' ret 1 and if '-' ret 0
					res = filter->type == ADD ?
						FILTER_ALLOW : FILTER_DENY;
					goto end;
				}

				// no descendants, and already compared
				// whole path string so its a match
				if (item == NULL && path_len == offset) {
					// if '+' ret 1 and if '-' ret 0
					res = filter->type == ADD ?
						FILTER_ALLOW : FILTER_DENY;
					goto end;
				}

				// push descendants to the stack
				for (; item != NULL ; item = item->next) {
					filter_t *next_filter = (filter_t*)item->data;
					if (stack_push_vars(&stack, stack_buf,
							    &sp, level, offset,
							    next_filter)) {
						msg(LOG_WARNING,
		    "fapolicyd: rule nesting exceeds MAX_FILTER_DEPTH (%d)\n",
						    MAX_FILTER_DEPTH);
						res = FILTER_ERR_DEPTH;
						goto end;
					}
				}

			}

		}

		if (filter->type != NONE) {
			const char *rule = (filter->path && *filter->path) ?
				filter->path : "/";
			FILTER_TRACE("%s %s %s\n",
				filter->type == ADD ? "allow" : "deny",
				rule, matched ? "match" : "no match");
		}

		stack_item_t * stack_item = NULL;
		// pop already processed filters from the top of the stack
		do {
		if (stack_item) {
			filter = stack_item->filter;
			offset = stack_item->offset;
				level = stack_item->level;

				// assuimg that nothing has matched on the
				// upper level so it's a directory match
				if (filter->matched &&
				    filter->path[filter->len-1] == '/') {
					res = filter->type == ADD ?
						FILTER_ALLOW : FILTER_DENY;
					goto end;
				}

				// reset processed flag
				stack_pop_reset(&stack, &sp);
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
	FILTER_TRACE("decision %s\n",
		res == FILTER_ALLOW ? "include" : "exclude");
	// Clean up the stack
	stack_pop_all_reset(&stack, &sp);
	stack_destroy(&stack);
	return res;
}

/*
 * filter_load_file - load filter configuration and build tree
 * @path: optional configuration file path, defaults to FILTER_FILE
 * Returns 0 on success and 1 on error.
 */
int filter_load_file(const char *path)
{
	int res = 0;
	FILE *stream;

	msg(LOG_DEBUG, "Loading filter");
	if (path == NULL) {
		stream = fopen(OLD_FILTER_FILE, "r");

		if (stream == NULL) {

			stream = fopen(FILTER_FILE, "r");
			if (stream == NULL) {
				msg(LOG_ERR,
				    "Cannot open filter file %s", FILTER_FILE);
				return 1;
			}
		} else {
			msg(LOG_INFO,
			    "Using old filter file: %s, use the new one: %s",
			    OLD_FILTER_FILE, FILTER_FILE);
			msg(LOG_INFO, "Consider 'mv %s %s'",
			    OLD_FILTER_FILE, FILTER_FILE);
		}
	} else {
		stream = fopen(path, "r");
		if (stream == NULL) {
			msg(LOG_ERR, "Cannot open filter file %s", path);
			return 1;
		}
	}

	ssize_t nread;
	size_t len = 0;
	char * line = NULL;
	long line_number = 0;
	int last_level = 0;

	stack_t stack;
	stack_init(&stack);
	stack_item_t stack_buf[MAX_FILTER_DEPTH];
	int sp = 0;
	/* root of the tree is already allocated */
	if (stack_push_vars(&stack, stack_buf, &sp, last_level, 0,
			    global_filter)) {
					msg(LOG_WARNING,
		    "fapolicyd: rule nesting exceeds MAX_FILTER_DEPTH (%d)\n",
		    MAX_FILTER_DEPTH);
		fclose(stream);
		return 1; /* depth too deep */
	}

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
			msg(LOG_ERR,
		       "filter_load_file: cannot parse line number %ld, \"%s\"",
				line_number, line);
			free(line);
			line = NULL;
			goto bad;
		}

		filter_t * filter = filter_create_obj();
		if (!filter) {
			free(line);
			line = NULL;
			goto bad;
		}

		filter->path = strdup(rest);
		if (filter->path == NULL) {
			filter_destroy_obj(filter);
			free(line);
			line = NULL;
			goto bad;
		}
		filter->len = strlen(filter->path);
		filter->type = type;

		// compare indetention between the last and current line
		last_level = ((stack_item_t*)stack_top(&stack))->level;
		if (level == last_level) {

			// since we are at the same level as filter before
			// we need to pop the previous filter from the top
			stack_pop_vars(&stack, &sp);

			// pushing filter to the list of top's children list
			list_prepend(
			    &((stack_item_t*)stack_top(&stack))->filter->list,
			    NULL, (void*)filter);

			// pushing filter to the top of the stack
			if (stack_push_vars(&stack, stack_buf, &sp, level, 0,
					    filter)) {
				msg(LOG_WARNING,
		    "fapolicyd: rule nesting exceeds MAX_FILTER_DEPTH (%d)\n",
					MAX_FILTER_DEPTH);
				filter_destroy_obj(filter);
				free(line);
				line = NULL;
				goto bad;
			}

		} else if (level == last_level + 1) {
			// this filter has higher level tha privious one
			// we wont do pop just push

			// pushing filter to the list of top's children list
			list_prepend(
			    &((stack_item_t*)stack_top(&stack))->filter->list,
			    NULL, (void*)filter);

			// pushing filter to the top of the stack
			if (stack_push_vars(&stack, stack_buf, &sp, level, 0,
					    filter)) {
						msg(LOG_WARNING,
		    "fapolicyd: rule nesting exceeds MAX_FILTER_DEPTH (%d)\n",
					MAX_FILTER_DEPTH);
				filter_destroy_obj(filter);
				free(line);
				line = NULL;
				goto bad;
			}

		} else if (level < last_level){
			// level of indentation dropped, we need to pop
			// +1 is meant for getting rid of the current
			// level so we can push again
			for (int i = 0 ; i < last_level - level + 1; i++) {
				stack_pop_vars(&stack, &sp);
			}

			// pushing filter to the list of top's children list
			list_prepend(
			    &((stack_item_t*)stack_top(&stack))->filter->list,
			    NULL, (void*)filter);

			// pushing filter to the top of the stack
			if (stack_push_vars(&stack, stack_buf, &sp, level, 0,
					    filter)) {
				msg(LOG_WARNING,
		    "fapolicyd: rule nesting exceeds MAX_FILTER_DEPTH (%d)\n",
					MAX_FILTER_DEPTH);
				filter_destroy_obj(filter);
				free(line);
				line = NULL;
				goto bad;
			}

		} else {
			msg(LOG_ERR,
			    "filter_load_file: paring error line: %ld, \"%s\"",
			    line_number, line);
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
	stack_pop_all_vars(&stack, &sp);
	stack_destroy(&stack);
	if (global_filter->list.count == 0) {
		const char *conf_file = path ? path : FILTER_FILE;
		msg(LOG_ERR, "filter_load_file: no valid filter provided in %s",
		    conf_file);
	}
	return res;
}

/*
 * These are some ideas to improve performance if the number of rules grows
 * or we find this is holding up trustdb restablishment in the future:
 *
 * Speed-up steps from simplest to most involved
 *
 * 1. Compute and cache wildcard metadata at load time
 * Add two fields to filter_t: bool has_wildcard and char last_char.
 * Set them once in filter_load_file().
 * During matching skip strpbrk() and the separator-count loop unless
 * has_wildcard is true; for plain prefixes just use memcmp().
 *
 * 2. Stop copying the path
 * Instead of alloca+strcpy, keep a const char *p = _path; pointer and move
 * it with offsets.
 * If mutability is required only for the “temporarily NUL-terminate”
 * trick, maintain a small struct { size_t pos; char saved; } stack
 * and restore the byte after fnmatch.
 *
 * 3. Reset node flags with a generation counter
 * Give filter_t a 32-bit vis_tag and increment a global visit_id each
 * time filter_check() starts.
 * A node is “visited” when vis_tag == visit_id; no memory writes are
 * needed to “unvisit” between calls, eliminating persistent
 * matched/processed state and making the code thread-friendly.
 *
 * 4. Group children into two vectors
 * On load, partition each node’s children into
 * • “literal” (no wildcard)
 * • “pattern” (has wildcard)
 * Store literals in a sorted array and binary-search them; patterns stay
 * in a small list evaluated with fnmatch().
 * ROI: most look-ups stop after a logarithmic search without polling
 * wildcard siblings.
 *
 * 5. Build a prefix-trie
 * Instead of a general linked list, compile the filter into a radix tree
 * keyed by path components.
 * Each node then needs at most one comparison per component; backtracking
 * is unnecessary. Memory usage stays modest because rules share prefixes.
 *
 * 6. Pre-compile glob patterns into DFA
 * Libraries like libglob/libtre can compile POSIX globs into a mini-automaton.
 * The matcher then advances the DFA over the path once, rather than
 * calling fnmatch() repeatedly.
 *
 * 7. Batch evaluation / directory memoisation
 * When scanning entire RPM databases the same directory prefix recurs
 * thousands of times (/usr/lib/ vs. every .so).
 * Cache the verdict for each directory path; skip evaluation for children
 *  once an ancestor’s decision is known.
 *
 */
