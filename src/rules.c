/*
* rules.c - Minimal linked list set of rules
* Copyright (c) 2016,2018,2019 Red Hat Inc., Durham, North Carolina.
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
*   Steve Grubb <sgrubb@redhat.com>
*/

#include "config.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pwd.h>
#include <ctype.h>
#include "policy.h"
#include "rules.h"
#include "nv.h"
#include "message.h"
#include "file.h" // This seems wrong
#include "database.h"

//#define DEBUG
#define UNUSED 0xFF

// Pattern detection
#define SYSTEM_LD_CACHE "/etc/ld.so.cache"
#define PATTERN_NORMAL_STR "normal"
#define PATTERN_NORMAL_VAL 0
#define PATTERN_LD_PRELOAD_STR "ld_preload"
//#define PATTERN_LD_PRELOAD_VAL 1
#define PATTERN_BAD_INTERPRETER_STR "bad_interpreter"
#define PATTERN_BAD_INTERPRETER_VAL 2
#define PATTERN_LD_SO_STR "ld_so"
#define PATTERN_LD_SO_VAL 3
#define PATTERN_STATIC_STR "static"
#define PATTERN_STATIC_VAL 4

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

	if (n == NULL) {
		msg(LOG_DEBUG, "node is NULL");
		abort();
	}

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
			if (n->s[j].type != UNUSED) {
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
			if (n->o[j].type != UNUSED) {
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

static int assign_subject(lnode *n, int type, const char *ptr2, int lineno)
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
		if (n->s[i].type == PATTERN) {
			if (strcasecmp(ptr2, PATTERN_LD_PRELOAD_STR) == 0) {
				msg(LOG_ERR,
				"ld_preload is a deprecated pattern in line %d",
					lineno);
				return 3;
//				n->s[i].val = PATTERN_LD_PRELOAD_VAL;
//			} else if (strcasecmp(ptr2,
//					PATTERN_BAD_INTERPRETER_STR) == 0) {
//				n->s[i].val = PATTERN_BAD_INTERPRETER_VAL;
			} else if (strcasecmp(ptr2,
					PATTERN_LD_SO_STR) == 0) {
				n->s[i].val = PATTERN_LD_SO_VAL;
			} else if (strcasecmp(ptr2, PATTERN_STATIC_STR) == 0) {
				n->s[i].val = PATTERN_STATIC_VAL;
			} else {
				msg(LOG_ERR,
					"Unknown pattern value %s in line %d",
					ptr2, lineno);
				return 2;
			}
		} else {
			if (isdigit(*ptr2)) {
				errno = 0;
				n->s[i].val = strtol(ptr2, NULL, 10);
				if (errno) {
					msg(LOG_ERR,
					"Error converting val (%s) in line %d",
						ptr2, lineno);
					return 2;
				}
			// Support names for auid and uid entries
			} else if (n->s[i].type == AUID ||
					n->s[i].type == UID) {
				struct passwd *pw = getpwnam(ptr2);
				if (pw == NULL) {
					msg(LOG_ERR, "user %s is unknown",
							ptr2);
					exit(1);
				}
                                n->s[i].val = pw->pw_uid;
				endpwent();
			}
		}
	}

	n->s_count++;
	sanity_check_node(n, "assign_subject - 2");

	return 0;
}

static int assign_object(lnode *n, int type, const char *ptr2, int lineno)
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
				if (assign_subject(n, type, ptr2, lineno) == 3)
					return -1;
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
		newnode->s_count = 0;
		newnode->o_count = 0;
		for (i=0; i<MAX_FIELDS; i++) {
			newnode->s[i].type = UNUSED;
			newnode->o[i].type = UNUSED;
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
#define NUM_DIRS (sizeof(dirs)/sizeof(dirs[0]))

// Returns 0 if no match, 1 if a match
static int check_dirs(unsigned int i, const char *path)
{
	// Iterate across the lists looking for a match.
	// If we match, stop iterating and return a decision.
	for (; i < NUM_DIRS; i++) {
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
	else if ((o->len == 10) && strcasecmp(o->o, "untrusted") == 0) {
		if (check_trust_database(obj->o))
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
	else if ((len == 10) && strcasecmp(s->str, "untrusted") == 0) {
		if (check_trust_database(subj->str))
			return 0;

	// Just a normal dir test.
	} else if (strncmp(subj->str, s->str, len))
		return 0;
	return 1;
}

/*
 * Notes about elf program startup
 * ===============================
 * The run time linker will do the folowing:
 * 1) kernel loads executable
 * 2) kernel attaches ld-2.2x.so to executable memory and turns over execution
 * 3) rtl loads LD_AUDIT libs
 * 4) rtl loads LD_PRELOAD libs
 * 5) rtl next loads /etc/ld.so.preload libs
 *
 * Then for each dependency:
 * Call into LD_AUDIT la_objsearch() to modify path/name and try
 * 1) RPATH in object
 * 2) RPATH in executable
 * 3) LD_LIBRARY_PATH: for each path, iterate permutations of
 *    tls, x86_64, haswell, & plain path
 * 4) RUNPATH in object
 * 5) Try the name as found in the object
 * 6) Consult /etc/ld.so.cache
 * 7) Try default path (can't find where string table is)
 *
 * LD_AUDIT modules can add arbitrary early file system actions because
 * the may also call open. They can also trigger loading another copy of
 * libc.so.6.
 *
 * Patterns
 * ========
 * Normal:
 *    exe=/usr/bin/bash file=/usr/bin/ls
 *    exe=/usr/bin/bash file=/usr/lib64/ld-2.27.so
 *    exe=/usr/bin/ls file=/etc/ld.so.cache
 *    exe=/usr/bin/ls file=/usr/lib64/libselinux.so.1
 *
 * runtime linker started:
 *    exe=/usr/bin/bash file=/usr/lib64/ld-2.27.so
 *    exe=/usr/bin/bash file=/usr/bin/ls
 *    exe=/usr/lib64/ld-2.27.so file=/etc/ld.so.cache
 *    exe=/usr/lib64/ld-2.27.so file=/usr/lib64/libselinux.so.1
 *
 * LD_PRELOAD=libaudit no LD_LIBRARY_PATH:
 *    exe=/usr/bin/bash file=/usr/bin/ls
 *    exe=/usr/bin/bash file=/usr/lib64/ld-2.27.so
 *    exe=/usr/bin/ls file=/usr/lib64/libaudit.so.1.0.0
 *    exe=/usr/bin/ls file=/etc/ld.so.cache
 *    exe=/usr/bin/ls file=/usr/lib64/libselinux.so.1
 *
 * LD_PRELOAD=libaudit with LD_LIBRARY_PATH:
 *    exe=/usr/bin/bash file=/usr/bin/ls
 *    exe=/usr/bin/bash file=/usr/lib64/ld-2.28.so
 *    exe=/usr/bin/ls file=/usr/lib64/libaudit.so.1.0.0
 *    exe=/usr/bin/ls file=/usr/lib64/libselinux.so.1
 *
 * /etc/ld.so.preload:
 *    exe=/usr/bin/bash file=/usr/bin/ls
 *    exe=/usr/bin/bash file=/usr/lib64/ld-2.27.so
 *    exe=/usr/bin/ls file=/etc/ld.so.preload
 *    exe=/usr/bin/ls file=/usr/lib64/libaudit.so.1.0.0
 *
 *    This means only first two can be counted on. Looking for ld.so.cache
 *    is no good because its almost the last option.
 */

//#define NEW_WAY 1

// Returns 0 if no match, 1 if a match, -1 on error
static int subj_pattern_test(subject_attr_t *s, event_t *e)
{
	int rc = 0;
	struct proc_info *pinfo = e->s->info;

	// If still collecting, and its an elf file, we can't decide yet.
	if (pinfo->state == STATE_COLLECTING) {
		if (pinfo->elf_info == 0) {
			pinfo->state = STATE_NOT_ELF;
			clear_proc_info(pinfo);
		}
		return rc;
	}

	// Do the analysis
#ifdef NEW_WAY
	// What if this is already running pgm and we were
	// evicted from cache and are now recovering?
	if (pinfo->state == STATE_PARTIAL) {
msg(LOG_DEBUG, "path1: %s", pinfo->path1);
msg(LOG_DEBUG, "path2: %s", pinfo->path2);
		if (strcmp(pinfo->path1, SYSTEM_LD_SO) == 0)
			pinfo->state = STATE_LD_SO;
		else if (strcmp(pinfo->path2, SYSTEM_LD_SO)) {
			// When programs start, its either ld.so or themselves
			// There is no other way they start. So, if there is a
			// miscompare, then we must have started a while ago.
			subject_attr_t *sub = get_subj_attr(e, EXE);
			// FIXME: The problem here is that the exe name
			// gets set by ld.so. At partial match we do not
			// know if we are recovering from eviction or
			// this is the wrong interp. If we got the execve
			// access notification, we can fix this use case.
			if (strcmp(pinfo->path1, sub->str) == 0)
				pinfo->state = STATE_BAD_INTERPRETER;
		}
	} else if (pinfo->state == STATE_FULL) {
		if (pinfo->elf_info & HAS_ERROR) {
			pinfo->state = STATE_BAD_ELF;
			clear_proc_info(pinfo);
			return -1;
		}
		// When programs start, its either ld.so or themselves
		// There is no other way they start. So, if there is a
		// miscompare, then we must have started a while ago.
		subject_attr_t *sub = get_subj_attr(e, EXE);
		if (strcmp(pinfo->path1, sub->str)) {
			pinfo->state = STATE_NORMAL;
		} else {
			if (strcmp(pinfo->path3, SYSTEM_LD_CACHE) == 0)
				pinfo->state = STATE_NORMAL;
//			else
//				pinfo->state = STATE_LD_PRELOAD;
		}
	}

#else  //  OLD WAY
	if (pinfo->state == STATE_FULL) {
		if (pinfo->elf_info & HAS_ERROR) {
			pinfo->state = STATE_BAD_ELF;
			clear_proc_info(pinfo);
			return -1;
		}
		// When programs start, its either ld.so or themselves
		// There is no other way they start. So, if there is a
		// miscompare, then we must have started a while ago.
		subject_attr_t *sub = get_subj_attr(e, EXE);
		if (strcmp(pinfo->path1, sub->str))
			// If we hit this, we assume program is already running
			pinfo->state = STATE_NORMAL;
		else if (strcmp(pinfo->path1, SYSTEM_LD_SO) == 0)
			// First thing is ld.so when its used
			pinfo->state = STATE_LD_SO;
		else {
			// To get here, pgm matched path1
			if (strcmp(pinfo->path2, SYSTEM_LD_SO) == 0) {
				// To get here interp is ld.so
				if (strcmp(pinfo->path3, SYSTEM_LD_CACHE) == 0
				   || (pinfo->elf_info & HAS_RPATH))
					// ld.so normally checks cache first
					pinfo->state = STATE_NORMAL;
//				else
					// but preload does the preload
//					pinfo->state = STATE_LD_PRELOAD;
			} else
				// To get here wrong interp used
				pinfo->state = STATE_BAD_INTERPRETER;
		}
	}
#endif
	if (pinfo->state == STATE_PARTIAL) {
		if ((pinfo->elf_info & IS_ELF) &&
				((pinfo->elf_info & HAS_DYNAMIC) == 0))
			pinfo->state = STATE_STATIC;
	}

	// If nothing detected, then we cannot decide yet
	if (pinfo->state == STATE_PARTIAL)
		return rc;

	// Make a decision
	switch (s->val)
	{
		case PATTERN_NORMAL_VAL:
			if (pinfo->state == STATE_NORMAL)
				rc = 1;
			break;
/*		case PATTERN_LD_PRELOAD_VAL:
			if (pinfo->state == STATE_LD_PRELOAD) {
				rc = 1;
				//msg(LOG_DEBUG, "path1: %s", pinfo->path1);
				//msg(LOG_DEBUG, "path2: %s", pinfo->path2);
				//msg(LOG_DEBUG, "path3: %s", pinfo->path3);
			}
			break; */
		case PATTERN_BAD_INTERPRETER_VAL:
			if (pinfo->state == STATE_BAD_INTERPRETER)
				rc = 1;
			break;
		case PATTERN_LD_SO_VAL:
			if (pinfo->state == STATE_LD_SO)
				rc = 1;
			break;
		case PATTERN_STATIC_VAL:
			if (pinfo->state == STATE_STATIC)
				rc = 1;
			break;
	}

	// Done with the paths
	clear_proc_info(pinfo);

	return rc;
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
			if (subj == NULL && type != PATTERN) {
				cnt++;
				continue;
			}

			// If mismatch, we don't care
			if (type == PATTERN) {
					int rc = subj_pattern_test
							(&(r->s[cnt]), e);
					if (rc == 0)
						return 0;
					// If there was an error, consider it
					// a match since deny is likely
					if (rc == -1)
						return 1;
			} else if (type >= COMM) {
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
				   strcasecmp(r->s[cnt].str, "untrusted")==0) {
					if (check_trust_database(subj->str))
						return 0;
				} else if (strcmp(subj->str, r->s[cnt].str))
					return 0;
			} else if (subj && subj->val != r->s[cnt].val)
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

			//  For directories (and untrusted), we only do a
			//  partial match.  Any child dir would also match.
			if (r->o[cnt].type == ODIR) {
				int rc = obj_dir_test(&(r->o[cnt]), obj);
				if (rc == 0)
					return 0;
			} else if (r->o[cnt].type == PATH &&
				 (r->s[cnt].type == EXE ||
				     r->s[cnt].type == EXE_DIR) &&
				 strcasecmp(r->s[cnt].str, "untrusted") == 0) {
				if (check_trust_database(obj->o))
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

void rules_unsupport_audit(llist *l)
{
#ifdef USE_AUDIT
	register lnode *current = l->head;
	int warn = 0;

	while (current) {
		if (current->d & AUDIT)
			warn = 1;
		current->d &= ~AUDIT;
		current=current->next;
	}
	if (warn) {
		msg(LOG_WARNING,
		    "Rules with audit events are not supported by the kernel");
		msg(LOG_NOTICE, "Converting rules to non-audit rules");
	}
#endif
}

void rules_clear(llist *l)
{
	lnode *nextnode;
	register lnode *current = l->head;

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
