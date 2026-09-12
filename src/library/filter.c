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
 * filter node and an offset into the path being evaluated.
 *
 * Traversal state is kept locally:
 *
 *  - filter_check() walks the tree comparing a path against the filters.
 *  - filter_load_file() tracks ancestors by their indentation level.
 *  - filter_destroy_obj() iteratively frees the tree.
 *
 * Using a stack keeps memory usage predictable and avoids deep recursion when
 * filters contain many nested paths.
 *
 * filter_check() is intentionally a read-only walk over the compiled filter
 * tree. Trust database imports are serialized today, but the tree is shared
 * library state and future import backends may want to reuse one filter
 * generation. Per-check traversal flags therefore live in stack_item_t, not in
 * filter_t nodes.
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
#include <limits.h>

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
static size_t filter_count_nodes(filter_t *root);

typedef struct {
	int offset;
	int processed;
	int matched;
	filter_t *filter;
} stack_item_t;

struct filter_stack {
	stack_item_t *items;
	size_t count;
	size_t capacity;
};

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
		filter->line_number = 0;
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
 * filter_count_nodes - count filter nodes in a tree
 * @root: root node of filter tree
 * Returns number of nodes reachable from @root.
 */
static size_t filter_count_nodes(filter_t *root)
{
	size_t count = 0;
	stack_t stack;

	if (root == NULL)
		return 0;

	stack_init(&stack);
	stack_push(&stack, root);

	while (!stack_is_empty(&stack)) {
		filter_t *filter = (filter_t *)stack_top(&stack);
		list_item_t *item;

		stack_pop(&stack);
		count++;

		for (item = list_get_first(&filter->list); item != NULL;
		     item = item->next)
			stack_push(&stack, item->data);
	}

	stack_destroy(&stack);
	return count;
}

/*
 * filter_stack_push - save a filter and its path position for traversal.
 * @stack: array of traversal frames, with count and capacity.
 * @filter: filter node to push.
 * @offset: current offset in the matched path.
 * Returns 0 on success and -1 if the capacity would be exceeded.
 */
static int filter_stack_push(struct filter_stack *stack, filter_t *filter,
			     int offset)
{
	if (stack->count >= stack->capacity)
		return -1;

	stack->items[stack->count++] = (stack_item_t) {
		.offset = offset,
		.filter = filter,
	};
	return 0;
}

/*
 * filter_check - compare path against loaded filters
 * @_path: full path of file to test
 * Returns FILTER_ALLOW if file should be kept, FILTER_DENY if it should be
 * dropped, or FILTER_ERR_DEPTH if traversal state cannot be allocated
 * (treated the same as a deny by callers to keep processing other paths).
 */
__attribute__((hot))
filter_rc_t filter_check(const char *_path)
{
	if (_path == NULL) {
		msg(LOG_ERR, "filter_check: path is NULL, something is wrong!");
		return 0;
	}

	filter_t *filter = global_filter;
	size_t source_len = strnlen(_path, PATH_MAX);
	char *path = alloca(source_len + 1);
	size_t path_len = 0;

	/* Linux treats repeated separators as one. Normalize before matching
	 * so spelling alone cannot bypass directory exclusions or exceptions.
	 * Do not resolve the path: trust imports need not name existing files. */
	for (size_t i = 0; i < source_len; i++) {
		if (_path[i] == '/' && path_len && path[path_len - 1] == '/')
			continue;
		path[path_len++] = _path[i];
	}
	path[path_len] = 0;
	if (path_len != source_len)
		FILTER_TRACE("normalized path: %s\n", path);
	/* Reject paths with parent directory references */
	if ((path[0] == '.' && path[1] == '.' &&
		(path[2] == '/' || path[2] == '\0')) ||
		strstr(path, "/../") != NULL ||
		    (path_len >= 3 && strcmp(path + path_len - 3, "/..") == 0))
		return FILTER_DENY;
	/* offset tracks how much of the path has already matched */
	size_t offset = 0;
	/* The frame array is the stack; no separate linked nodes are needed.
	 * Capacity counts nodes, not depth, because siblings are also pending. */
	struct filter_stack stack = {
		.capacity = filter_count_nodes(global_filter),
	};

	if (stack.capacity == 0)
		return FILTER_DENY;

	stack.items = calloc(stack.capacity, sizeof(*stack.items));
	if (stack.items == NULL) {
		msg(LOG_ERR, "fapolicyd: cannot allocate filter traversal stack");
		return FILTER_ERR_DEPTH;
	}

	filter_rc_t res = FILTER_DENY;
	const filter_t *deciding = NULL;
	const char *reason = NULL;
	stack_item_t *stack_item;

	/* The nonempty tree always has room for its root frame. */
	stack.items[0].filter = filter;
	stack.count = 1;

	while (stack.count) {
		int matched = 0;
		stack_item = &stack.items[stack.count - 1];
		stack_item->processed = 1;
		filter = stack_item->filter;

		// this is starting branch of the algo
		// assuming that in root filter filter->path is NULL
		if (filter->path == NULL) {
			list_item_t *item = list_get_first(&filter->list);
			// push all the descendants to the stack
			for (; item != NULL ; item = item->next) {
				filter_t *next_filter = (filter_t*)item->data;
				if (filter_stack_push(&stack, next_filter,
						      offset)) {
					msg(LOG_WARNING,
		    "fapolicyd: filter traversal stack exhausted\n");
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

				if (matched)
					offset = (path_old_lim - path) + offset;
			} else {
				// match normal path or just specific part of it
				matched = !strncmp(path+offset, filter->path,
						   filter->len);
				if (matched)
					offset += filter->len;
			}

			if (matched) {
				stack_item->matched = 1;

				// if matched we need ot push descendants
				// to the stack
				list_item_t *item=list_get_first(&filter->list);

				/* A leaf matches after a successful wildcard or
				 * when its literal path was consumed entirely. */
				if (item == NULL &&
				    (is_wildcard || path_len == offset)) {
					const char *rule = (filter->path &&
							*filter->path) ?
							filter->path : "/";
					FILTER_TRACE("%s %s %s\n",
						     filter->type == ADD ?
						     "allow" : "deny",
						     rule, "match");
					// if '+' ret 1 and if '-' ret 0
					res = filter->type == ADD ?
						FILTER_ALLOW : FILTER_DENY;
					deciding = filter;
					reason = "leaf match";
					goto end;
				}

				// push descendants to the stack
				for (; item != NULL ; item = item->next) {
					filter_t *next_filter = (filter_t*)item->data;
					if (filter_stack_push(&stack, next_filter,
							      offset)) {
						msg(LOG_WARNING,
		    "fapolicyd: filter traversal stack exhausted\n");
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

		stack_item = NULL;
		// pop already processed filters from the top of the stack
		do {
			if (stack_item) {
				filter = stack_item->filter;

				// assuimg that nothing has matched on the
				// upper level so it's a directory match
				if (stack_item->matched &&
				    filter->path[filter->len-1] == '/') {
					res = filter->type == ADD ?
						FILTER_ALLOW : FILTER_DENY;
					deciding = filter;
					reason = "directory fallback";
					goto end;
				}

				stack.count--;
			}

			stack_item = stack.count ?
				&stack.items[stack.count - 1] : NULL;
		} while(stack_item && stack_item->processed);

		if (!stack_item)
			break;

		offset = stack_item->offset;
	}

end:
	if (deciding)
		FILTER_TRACE("deciding rule: %s %s (%s)\n",
			     deciding->type == ADD ? "allow" : "deny",
			     deciding->path, reason);
	else
		FILTER_TRACE("%s\n", res == FILTER_ERR_DEPTH ?
			     "filter traversal failed" : "default: exclude");
	FILTER_TRACE("decision %s\n",
		res == FILTER_ALLOW ? "include" : "exclude");
	free(stack.items);
	return res;
}

/*
 * filter_prune_list - Remove list entries that do not pass the filter.
 * @list: List of paths to be checked.
 * @path: Optional configuration file path, defaults to FILTER_FILE.
 *
 * Initializes the filter module, loads the configuration, and walks the
 * supplied list. Any entry that is not allowed by the filter is removed.
 * Returns 0 on success and 1 if initialization, loading, or evaluation fails.
 */
int filter_prune_list(list_t *list, const char *path)
{
	if (list == NULL)
		return 1;

	if (filter_init())
		return 1;
	if (filter_load_file(path)) {
		filter_destroy();
	return 1;
	}

	list_item_t *lptr = list->first, *prev = NULL;

	while (lptr) {
		list_item_t *next = lptr->next;
		filter_rc_t res = filter_check(lptr->index);
		if (res == FILTER_ALLOW) {
			prev = lptr;
			lptr = next;
			continue;
		}

		if (res == FILTER_ERR_DEPTH)
			msg(LOG_WARNING,
			    "filter nesting exceeds MAX_FILTER_DEPTH for %s; excluding",
			    (char *)lptr->index);

		if (prev)
			prev->next = lptr->next;
		else
			list->first = lptr->next;
		if (!lptr->next)
			list->last = prev;
		list_destroy_item(&lptr);
		--list->count;
		lptr = next;
	}

	filter_destroy();
	return 0;
}

/*
 * filter_validate - warn about suspicious refinements in a loaded tree.
 * @path: configuration filename used in warning messages.
 * Returns nothing and never changes rules or their decisions. The loader
 * bounds the depth, so one pending sibling per level needs no allocation.
 */
static void filter_validate(const char *path)
{
	const list_item_t *pending[MAX_FILTER_DEPTH];
	size_t depth = 0;

	pending[0] = list_get_first(&global_filter->list);
	for (;;) {
		const list_item_t *item = pending[depth];
		const filter_t *filter;

		if (item == NULL) {
			if (depth == 0)
				break;
			depth--;
			continue;
		}
		filter = item->data;
		pending[depth] = item->next;
		if (filter->list.count == 0)
			continue;
		/* A file/glob parent can gate children, but cannot supply the
		 * fallback that authors commonly intend for their exceptions. */
		if (filter->len == 0 || filter->path[filter->len - 1] != '/')
			msg(LOG_WARNING,
			    "%s:%ld: rule '%c %s' has child rules but is not a "
			    "directory rule. If no child matches, its %s decision "
			    "does not apply; an enclosing directory rule or the "
			    "default decides.", path, filter->line_number,
			    filter->type == ADD ? '+' : '-', filter->path,
			    filter->type == ADD ? "include" : "exclude");
		pending[++depth] = list_get_first(&filter->list);
	}
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

			path = FILTER_FILE;
			stream = fopen(path, "r");
			if (stream == NULL) {
				msg(LOG_ERR,
				    "Cannot open filter file %s", FILTER_FILE);
				return 1;
			}
		} else {
			path = OLD_FILTER_FILE;
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

	size_t len = 0;
	char * line = NULL;
	long line_number = 0;
	int last_level = 0;

	/* Indentation identifies the parent directly. Keep only the most recent
	 * node at each level; siblings replace that level's previous entry. */
	filter_t *ancestors[MAX_FILTER_DEPTH] = { global_filter };

	while (getline(&line, &len, stream) != -1) {
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
		filter->line_number = line_number;

		if (level > last_level + 1) {
			msg(LOG_ERR,
			    "filter_load_file: paring error line: %ld, \"%s\"",
			    line_number, line);
			filter_destroy_obj(filter);
			free(line);
			line = NULL;
			goto bad;
		}

		/* Check capacity before linking the node so an excessive depth
		 * cannot leave a freed child attached to the tree. */
		if (level >= MAX_FILTER_DEPTH) {
			msg(LOG_WARNING,
		    "fapolicyd: rule nesting exceeds MAX_FILTER_DEPTH (%d)",
			    MAX_FILTER_DEPTH);
			filter_destroy_obj(filter);
			free(line);
			line = NULL;
			goto bad;
		}

		/* Prepend preserves file order when the checker pushes children
		 * onto its stack and visits the last pushed child first. */
		list_prepend(&ancestors[level - 1]->list, NULL, (void *)filter);
		ancestors[level] = filter;
		last_level = level;
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
	if (res == 0)
		filter_validate(path);
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
