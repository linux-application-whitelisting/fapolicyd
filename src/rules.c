/*
* rules.c - Minimal linked list set of rules
* Copyright (c) 2016 Red Hat Inc., Durham, North Carolina.
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
* Free Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*
* Authors:
*   Steve Grubb <sgrubb@redhat.com>
*/

#include "config.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "policy.h"
#include "rules.h"
#include "nv.h"
#include "message.h"
#include "file.h" // This seems wrong

//#define DEBUG

void rules_create(llist *l)
{
	l->head = NULL;
	l->cur = NULL;
	l->cnt = 0;
}

void rules_first(llist *l)
{
	l->cur = l->head;
}

void rules_last(llist *l)
{
        register lnode* window;
	
	if (l->head == NULL)
		return;

        window = l->head;
	while (window->next)
		window = window->next;

	l->cur = window;
}

lnode *rules_next(llist *l)
{
	if (l->cur == NULL)
		return NULL;

	l->cur = l->cur->next;
	return l->cur;
}

#ifdef DEBUG
static void sanity_check_node(lnode *n, const char *id)
{
	unsigned int j, cnt;

	if (n->s_count > MAX_FIELDS) {
		msg(LOG_DEBUG, "%s - node s_count is out of range %u",
				id, n->s_count);
		abort();
	}
	if (n->o_count > MAX_FIELDS) {
		msg(LOG_DEBUG, "%s - node o_count is out of range %u",
				id, n->o_count);
		abort();
	}

	if (n->s_count) {
		cnt = 0;
		for (j = 0; j < MAX_FIELDS; j++) {
			if (n->s[j].type != 0xFF) {
				cnt++;
				if (n->s[j].type < SUBJ_START ||
					n->s[j].type > SUBJ_END) {
					msg(LOG_DEBUG,
					"%s - subject type is out of range %d",
						id, n->s[j].type);
					abort();
				}
			}
		}
		if (cnt != n->s_count) {
			msg(LOG_DEBUG, "%s - subject cnt mismatch %u!=%u",
						id, cnt, n->s_count);
			abort();
		}
	}
	if (n->o_count) {
		cnt = 0;
		for (j = 0; j < MAX_FIELDS; j++) {
			if (n->o[j].type != 0xFF) {
				cnt++;
				if (n->o[j].type < OBJ_START ||
					n->o[j].type > OBJ_END) {
					msg(LOG_DEBUG,
					"%s - object type is out of range %d",
						id, n->o[j].type);
					abort();
				}
			}
		}
		if (cnt != n->o_count) {
			msg(LOG_DEBUG, "%s - object cnt mismatch %u!=%u",
						id, cnt, n->o_count);
			abort();
		}
	}
}
#else
#define sanity_check_node(a, b) do {} while(0)
#endif

#ifdef DEBUG
static void sanity_check_list(llist *l, const char *id)
{
	unsigned int i;

	lnode *n = l->head;
	if (n == NULL)
		return;

	if (l->cnt == 0) {
		msg(LOG_DEBUG, "%s - zero length cnt found", id);
		abort();
	}

	i = 1;
	while (n->next) {
		if (i == l->cnt) {
			msg(LOG_DEBUG, "%s - forward loop found %u", id, i);
			abort();
		}
		sanity_check_node(n, id);
		i++;
		n = n->next;
	}
	if (i != l->cnt) {
		msg(LOG_DEBUG, "%s - count mismatch %u!=%u", id, i, l->cnt);
		abort();
	}
}
#else
#define sanity_check_list(a, b) do {} while(0)
#endif

int assign_subject(lnode *n, int type, char *ptr2, int lineno)
{
	// assign the subject
	unsigned int i = n->s_count;

	sanity_check_node(n, "assign_subject - 1");
	n->s[i].type = type;
	if (n->s[i].type >= COMM) {
		n->s[i].str = strdup(ptr2);
		if (n->s[i].str == NULL) {
			msg(LOG_ERR, "memory allocation error in line %d",
				lineno);
			return 1;
		}
	} else {
		errno = 0;
		n->s[i].val = strtol(ptr2, NULL, 10);
		if (errno) {
			msg(LOG_ERR, "Error converting val (%s) in line %d",
				ptr2, lineno);
			return 2;
		}
	}

	n->s_count++;
	sanity_check_node(n, "assign_subject - 2");

	return 0;
}

int assign_object(lnode *n, int type, char *ptr2, int lineno)
{
	// assign the object
	unsigned int i = n->o_count;

	sanity_check_node(n, "assign_object - 1");
	n->o[i].type = type;
	n->o[i].o = strdup(ptr2);
	if (n->o[i].o == NULL) {
		msg(LOG_ERR, "memory allocation error in line %d",
			lineno);
		return 1;
	}
	if (n->o[i].type == ODIR)
		n->o[i].len = strlen(n->o[i].o);
	else
		n->o[i].len = 0;

	n->o_count++;
	sanity_check_node(n, "assign_object - 2");

	return 0;
}

/*
 * Returns: -1 nothing, 0 OK, >0 error
 */
static int nv_split(char *buf, lnode *n, int lineno)
{
	char *ptr, *ptr2;

	ptr = strtok(buf, " ");
	if (ptr == NULL)
		return -1; /* If there's nothing, go to next line */
	if (ptr[0] == '#')
		return -1; /* If there's a comment, go to next line */

	// Load decision
	n->d = dec_name_to_val(ptr);
	if ((int)n->d == -1) {
		msg(LOG_ERR, "Invalid decision (%s) in line %d",
				ptr, lineno);
		return 1;
	}

	while ((ptr = strtok(NULL, " "))) {
		int type;

		ptr2 = strchr(ptr, '=');
		if (ptr2) {
			*ptr2 = 0;
			ptr2++;
			type = subj_name_to_val(ptr);
			if (type == -1) {
				type = obj_name_to_val(ptr);
				if (type == -1) {
					msg(LOG_ERR,
					"Field type (%s) is unknown in line %d",
						ptr, lineno);
					return 2;
				} else
					assign_object(n, type, ptr2, lineno);
			} else
				assign_subject(n, type, ptr2, lineno);
		} else if (strcasecmp(ptr, "all") == 0) {
			if (n->s_count == 0) {
				type = ALL_SUBJ;
				assign_subject(n, type, "", lineno);
			} else if (n->o_count == 0) {
				type = ALL_OBJ;
				assign_object(n, type, "", lineno);
			} else {
				msg(LOG_ERR,
			"All can only be used in place of a subject or object");
				return 3;
			}
		} else {
			msg(LOG_ERR, "'=' is missing for field %s, in line %d",
				ptr, lineno);
			return 4;
		}
	}

	// do one last sanity check for missing subj or obj
	if (n->s_count == 0) {
		msg(LOG_ERR, "Subject is missing in line %d", lineno);
		return 5;
	}
	if (n->o_count == 0) {
		msg(LOG_ERR, "Object is missing in line %d", lineno);
		return 6;
	}
	return 0;	
}

// Returns 0 if success and 1 on rule failure.
int rules_append(llist *l, char *buf, unsigned int lineno)
{
	lnode* newnode;

	sanity_check_list(l, "rules_append - 1");
	if (buf) { // parse up the rule
		unsigned int i;
		newnode = malloc(sizeof(lnode));
		newnode->s_count = newnode->o_count = 0;
		for (i=0; i<MAX_FIELDS; i++) {
			newnode->s[i].type = 0xFF;
			newnode->o[i].type = 0xFF;
		}
		int rc = nv_split(buf, newnode, lineno);
		if (rc) {
			free(newnode);
			if (rc < 0)
				return 0;
			else
				return 1;
		}
	} else
		return 1;

	newnode->next = NULL;
	rules_last(l);

	// if we are at top, fix this up
	if (l->head == NULL)
		l->head = newnode;
	else	// Otherwise add pointer to newnode
		l->cur->next = newnode;

	// make newnode current
	l->cur = newnode;
	newnode->num = l->cnt;
	l->cnt++;
	sanity_check_list(l, "rules_append - 2");

	return 0;
}

// In this table, the number is string length
static const nv_t dirs[] = {
	{ 5, "/etc/"},
	{ 5, "/usr/"},
	{ 5, "/bin/"},
	{ 6, "/sbin/"},
	{ 5, "/lib/"},
	{ 7, "/lib64/"},
	{13, "/usr/libexec/"}
};
#define NUM_DIRS sizeof(dirs)/sizeof(dirs[0])

// Returns 0 if no match, 1 if a match
static int check_dirs(unsigned int i, const char *path)
{
	// Iterate across the lists looking for a match.
	// If we match, stop iterating and return a decision.
	for (; i< NUM_DIRS; i++) {
		// Check to see if we even care about this path
		if (strncmp(path, dirs[i].name, dirs[i].value) == 0)
			return 1;
	}
	return 0;
}

// Returns 0 if no match, 1 if a match
static int obj_dir_test(object_attr_t *o, object_attr_t *obj)
{
	// We allow a special 'systemdirs' macro
	if ((o->len == 10) && strcmp(o->o, "systemdirs") == 0)
		return check_dirs(0, obj->o);
	// Execdirs doesn't have /etc in its list
	else if ((o->len == 8) && strcmp(o->o, "execdirs") == 0)
		return check_dirs(1, obj->o);
	else if ((o->len == 10) && strcasecmp(o->o, "unpackaged") == 0) {
		if (check_packaged_from_file(obj->o))
			return 0;
	// Just a normal dir test
	} else if (strncmp(obj->o, o->o, o->len))
		return 0;

	return 1;
}

// Returns 0 if no match, 1 if a match
static int subj_dir_test(subject_attr_t *s, subject_attr_t *subj)
{
	unsigned int len = strlen(s->str);

	// We allow a special 'systemdirs' macro
	if ((len == 10) && strcmp(s->str, "systemdirs") == 0)
		return check_dirs(0, subj->str);

	// Execdirs doesn't have /etc in its list
	else if ((len == 8) && strcmp(s->str, "execdirs") == 0)
		return check_dirs(1, subj->str);
	else if ((len == 10) && strcasecmp(s->str, "unpackaged") == 0) {
		if (check_packaged_from_file(subj->str))
			return 0;

	// Just a normal dir test.
	} else if (strncmp(subj->str, s->str, len))
		return 0;
	return 1;
}

// Returns 0 if no match, 1 if a match, -1 on error
static int check_subject(lnode *r, event_t *e)
{
	unsigned int cnt = 0;

	sanity_check_node(r, "check_subject");
	while (cnt < r->s_count) {
		unsigned int type = r->s[cnt].type;
		if (type != ALL_SUBJ) {
			subject_attr_t *subj = get_subj_attr(e, type);
			if (subj == NULL) {
				cnt++;
				continue;
			}

			// If mismatch, we don't care
			if (type >= COMM) {
				// can't happen unless out of memory
				if (subj->str == NULL) {
					cnt++;
					continue;
				}
				//  For directories we only do a partial
				//  match.  Any child dir would also match.
				if (type == EXE_DIR) {
					int rc = subj_dir_test(&(r->s[cnt]),
								subj);
					if (rc == 0)
						return 0;
				} else if (type == EXE &&
				   strcasecmp(r->s[cnt].str, "unpackaged")==0) {
					if (check_packaged_from_file(subj->str))
						return 0;
				} else if (strcmp(subj->str, r->s[cnt].str))
					return 0;
			} else if (subj->val != r->s[cnt].val)
					return 0;
		}
		cnt++;
	}

	return 1;
}

// Returns 0 if no match, 1 if a match
static decision_t check_object(lnode *r, event_t *e)
{
	unsigned int cnt = 0;

	sanity_check_node(r, "check_object");
	while (cnt < r->o_count) {
		if (r->o[cnt].type != ALL_OBJ) {
			object_attr_t *obj = get_obj_attr(e, r->o[cnt].type);
			// can't happen unless out of memory
			if (obj == NULL || obj->o == NULL) {
				cnt++;
				continue;
			}

			//  For directories (and unpackaged), we only do a
			//  partial match.  Any child dir would also match.
			if (r->o[cnt].type == ODIR) {
				int rc = obj_dir_test(&(r->o[cnt]), obj);
				if (rc == 0)
					return 0;
			} else if (r->o[cnt].type == PATH &&
				 strcasecmp(r->s[cnt].str, "unpackaged") == 0) {
				if (check_packaged_from_file(obj->o))
					return 0;
			} else if (strcmp(obj->o, r->o[cnt].o))
					return 0;
		}
		cnt++;
	}

	return 1;
}

decision_t rule_evaluate(lnode *r, event_t *e)
{
	int d;

	// Check the subject
	d = check_subject(r, e);
	if (d == 0)	// No match
		return NO_OPINION;

	// Check the object
	d = check_object(r, e);
	if (d == 0)	// No match
		return NO_OPINION;
	return r->d;
}

void rules_clear(llist* l)
{
	lnode* nextnode;
	register lnode* current;

	current = l->head;
	while (current) {
		unsigned int i;

		nextnode=current->next;
		i = 0;
		while (i < current->s_count) {
			if (current->s[i].type >= COMM)
				free(current->s[i].str);
			i++;
		}
		i = 0;
		while (i < current->o_count) {
			free(current->o[i].o);
			i++;
		}
		free(current);
		current=nextnode;
	}
	l->head = NULL;
	l->cur = NULL;
	l->cnt = 0;
}

