/*
* rules.c - Minimal linked list set of rules
* Copyright (c) 2016,2018,2019-20 Red Hat Inc.
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
*   Radovan Sroka <rsroka@redhat.com>
*/

#include "config.h"
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>
#include <ctype.h>
#include <stdint.h>

#include "attr-sets.h"
#include "policy.h"
#include "rules.h"
#include "nv.h"
#include "message.h"
#include "file.h" // This seems wrong
#include "database.h"
#include "process.h"
#include "subject-attr.h"
#include "object-attr.h"
#include "string-util.h"
#include "gcc-attributes.h"

//#define DEBUG
#define UNUSED 0xFF

enum rule_parse_result {
	RULE_PARSE_SKIP = -1,
	RULE_PARSE_OK = 0,
	RULE_PARSE_ERROR = 1
};

// Pattern detection
#define SYSTEM_LD_CACHE "/etc/ld.so.cache"
#define PATTERN_NORMAL_STR "normal"
#define PATTERN_NORMAL_VAL 0
#define PATTERN_LD_SO_STR "ld_so"
#define PATTERN_LD_SO_VAL 1
#define PATTERN_STATIC_STR "static"
#define PATTERN_STATIC_VAL 2
#define PATTERN_LD_PRELOAD_STR "ld_preload"
#define PATTERN_LD_PRELOAD_VAL 3

static int assign_subject(llist *l, lnode *n, int type,
			  const char *ptr2, int lineno) __wur;
static int assign_object(llist *l, lnode *n, int type,
			 const char *ptr2, int lineno) __wur;

int rules_create(llist *l)
{
	l->head = NULL;
	l->cur = NULL;
	l->cnt = 0;
	l->sets = attr_sets_create();
	if (!l->sets)
		return 1;

	l->proc_status_mask = 0;

	return  0;
}


void rules_first(llist *l)
{
	l->cur = l->head;
}


static void rules_last(llist *l)
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


/*
 * If subject is trusted function returns true, false otherwise.
 */
static bool is_subj_trusted(event_t *e)
{
	subject_attr_t *trusted = get_subj_attr(e, SUBJ_TRUST);

	if (!trusted)
		return 0;
	return trusted->uval;
}


/*
 * If object is trusted function returns true, false otherwise.
 */
static bool is_obj_trusted(event_t *e)
{
	object_attr_t *trusted = get_obj_attr(e, OBJ_TRUST);

	if (!trusted)
		return 0;
	return trusted->val;
}

/*
 * It takes something like "% set    "  and it returns "set"

 */

static char * parse_set_name(char * buf)
{
	// replace % with space
	buf[0] = ' ';
	char * name = fapolicyd_strtrim(buf);
	if (!name)
		return NULL;

	// little validation
	for (int i = 0 ; name[i] ; i++) {
		if (!(isalnum(name[i]) || name[i] == '_' )) {
			return NULL;
		}
	}
	return buf;
}

#define GROUP_NAME_SIZE 64

static const char *data_type_to_name(int type)
{
	switch (type) {
		case STRING:
			return "STRING";
		case SIGNED:
			return "SIGNED";
		case UNSIGNED:
			return "UNSIGNED";
		default:
			return "UNKNOWN";
	}
}

static int assign_subject(llist *l, lnode *n, int type,
			  const char *ptr2, int lineno)
{
	// assign the subject
	unsigned int i = n->s_count;
	attr_sets_t *sets = l->sets;
	attr_sets_entry_t *set = NULL;
	attr_sets_entry_t *owned_set = NULL;

	sanity_check_node(n, "assign_subject - 1");
	n->s[i].type = type;

	// Opportunistically mark the fields that might be needed for
	// rule evaluation so that we gather them all at once later.
	if (type == UID)
		l->proc_status_mask |= PROC_STAT_UID;
	else if (type == PPID)
		l->proc_status_mask |= PROC_STAT_PPID;
	else if (type == GID)
		l->proc_status_mask |= PROC_STAT_GID;
	else if (type == COMM)
		l->proc_status_mask |= PROC_STAT_COMM;

	char *ptr, *saved, *tmp = strdup(ptr2);
	if (tmp == NULL) {
		msg(LOG_ERR, "memory allocation error in line %d",
			lineno);
		return 1;
	}


	// use already defined set
	if (tmp[0] == '%') {
		char * defined_set = parse_set_name(tmp);
		if (!defined_set) {
			msg(LOG_ERR, "rules: line:%d: assign_subject: "
				"cannot obtain set name from \'%s\'",
				lineno, tmp);
			goto free_and_error;
		}

		set = attr_sets_find(sets, defined_set);
		if (!set) {
			msg(LOG_ERR, "rules: line:%d: assign_subject: "
				"set \'%s\' was not defined before",
				lineno, defined_set);
			goto free_and_error;
		}

		// we cannot assign any set to these attributes
		if (type == SUBJ_TRUST || type == PATTERN) {
			msg(LOG_ERR, "rules: line:%d: assign_subject: "
				"cannot assign any set to %s",
				lineno, subj_val_to_name(type, RULE_FMT_COLON));
			goto free_and_error;
		}

		/*
		 * GID is a numeric subject attribute, but its enum value lives
		 * below the string attributes after SUBJ_TRUST.
		 */
		if (type <= PPID || type == GID) {
			int expected = (type == PID || type == PPID) ?
							SIGNED : UNSIGNED;
			if (set->type != expected) {
				msg(LOG_ERR, "rules: line:%d: assign_subject: "
					"cannot assign %%%s which has %s type "
					"to %s (%s expected)",
					lineno, defined_set,
					data_type_to_name(set->type),
					subj_val_to_name(type, RULE_FMT_COLON),
					data_type_to_name(expected));
				goto free_and_error;
			}
		}

		if (type >= COMM && set->type != STRING) {
			msg(LOG_ERR, "rules: line:%d: assign_subject: "
				"cannot assign %%%s which has %s type to %s "
				"(STRING expected)",
				lineno, defined_set,
				data_type_to_name(set->type),
				subj_val_to_name(type, RULE_FMT_COLON));
			goto free_and_error;
		}


		n->s[i].set = set;
		goto finalize;
	}


	// for debug output
	char name[GROUP_NAME_SIZE];
	memset(name, 0, GROUP_NAME_SIZE);
	snprintf(name, GROUP_NAME_SIZE-1, "_rule-line-%d-subj-%s", lineno,
		 subj_val_to_name(type, RULE_FMT_COLON));

	switch(n->s[i].type) {

	case ALL_SUBJ:
		break;

	// numbers -> multiple value
	case AUID:
	case UID:
	case SESSIONID:
	case GID:
	case PID:
	case PPID: {
		int set_type = (n->s[i].type == PID ||
				n->s[i].type == PPID) ? SIGNED : UNSIGNED;

		owned_set = attr_set_create(name, set_type);
		set = owned_set;
		if (!set)
			goto free_and_error;

		ptr = strtok_r(tmp, ",", &saved);
		while (ptr) {
			ptr = fapolicyd_strtrim(ptr);
			if (!ptr || *ptr == '\0') {
				ptr = strtok_r(NULL, ",", &saved);
				continue;
			}
			if (isdigit((unsigned char)*ptr) || *ptr == '-') {
				errno = 0;
				if (n->s[i].type == PID || n->s[i].type == PPID) {
					long val = strtol(ptr, NULL, 10);
					if (errno) {
						msg(LOG_ERR,
							"Error converting val (%s) in line %d",
							ptr, lineno);
						goto free_and_error;
					} else if (attr_set_append_int(set,
							(int64_t)val)) {
						goto free_and_error;
					}
				} else {
					if (*ptr == '-') {
						msg(LOG_ERR,
							"rules: line:%d: assign_subject: "
							"negative value %s not allowed for %s",
							lineno, ptr,
							subj_val_to_name(type,
							    RULE_FMT_COLON));
						goto free_and_error;
					}
					unsigned long val = strtoul(ptr, NULL, 10);
					if (errno) {
						msg(LOG_ERR,
							"Error converting val (%s) in line %d",
							ptr, lineno);
						goto free_and_error;
					} else if (attr_set_append_int(set,
							(int64_t)val)) {
						goto free_and_error;
					}
				}

			// Support names for auid and uid entries
			} else if (n->s[i].type == AUID ||
					n->s[i].type == UID) {
				struct passwd *pw = getpwnam(ptr);
				if (pw == NULL) {
					msg(LOG_ERR, "user %s is unknown",
						ptr);
					goto free_and_error;
				}
				unsigned int val = pw->pw_uid;
				endpwent();

				if (attr_set_append_int(set, (int64_t)val))
					goto free_and_error;

			} else if (n->s[i].type == GID) {
				struct group *gr = getgrnam(ptr);
				if (gr == NULL) {
					msg(LOG_ERR, "group %s is unknown",
						ptr);
					goto free_and_error;
				}
				unsigned int val = gr->gr_gid;
				endgrent();

				if (attr_set_append_int(set, (int64_t)val))
					goto free_and_error;
			}

			ptr = strtok_r(NULL, ",", &saved);
		}
		if (attr_sets_add(sets, set))
			goto free_and_error;
		n->s[i].set = set;
		owned_set = NULL;
		break;

	} // case

	// single value exception
	case PATTERN: {
		if (strchr(tmp, ',')) {
			msg(LOG_ERR, "rules: line:%d: assign_subject: "
				"pattern can handle only single value",
				lineno);
			goto free_and_error;
		}

		if (strcmp(tmp,	PATTERN_LD_SO_STR) == 0) {
			n->s[i].uval = PATTERN_LD_SO_VAL;
		} else if (strcmp(tmp, PATTERN_NORMAL_STR) == 0) {
			n->s[i].uval = PATTERN_NORMAL_VAL;
		} else if (strcmp(tmp, PATTERN_STATIC_STR) == 0) {
			n->s[i].uval = PATTERN_STATIC_VAL;
		} else if (strcmp(tmp, PATTERN_LD_PRELOAD_STR) == 0) {
			n->s[i].uval = PATTERN_LD_PRELOAD_VAL;
		} else {
			msg(LOG_ERR,
				"Unknown pattern value %s in line %d",
				tmp, lineno);
			goto free_and_error;
		}
		break;

	} // case

	// single value exception
	case SUBJ_TRUST: {
		if (strchr(tmp, ',')) {
			msg(LOG_ERR, "rules: line:%d: assign_subject: "
				"trust can handle only single value",
				lineno);
			goto free_and_error;
		}

		errno = 0;
		unsigned long val = strtoul(tmp, NULL, 10);
		if (errno) {
			msg(LOG_ERR,
				"Error converting val (%s) in line %d",
				tmp, lineno);
			goto free_and_error;
		} else {
			if (val != 1 && val != 0) {
				msg(LOG_ERR, "rules: line:%d: assign_subject: "
					"trust can be set to 1 or 0", lineno);
				goto free_and_error;
			}
			n->s[i].uval = (unsigned int)val;
		}

		break;

	} // case

	// regular strings -> multiple value
	case COMM:
	case EXE:
	case EXE_DIR:
	case EXE_TYPE: {
		owned_set = attr_set_create(name, STRING);
		set = owned_set;
		if (!set)
			goto free_and_error;

		ptr = strtok_r(tmp, ",", &saved);
		while (ptr) {
			if (!attr_set_check_str(set, ptr) &&
			    attr_set_append_str(set, ptr))
				goto free_and_error;
			ptr = strtok_r(NULL, ",", &saved);
		}

		if (attr_sets_add(sets, set))
			goto free_and_error;
		n->s[i].set = set;
		owned_set = NULL;
		break;
	} // case

	// should not happen
	default: {
		msg(LOG_ERR, "assign_subject: fatal error "
			"-> this should not happen!");
		goto free_and_error;
	} // case

	} // switch

finalize:
	n->s_count++;
	free(tmp);
	sanity_check_node(n, "assign_subject - 2");
	return 0;

 free_and_error:
	attr_set_destroy(owned_set);
	free(tmp);
	return 1;
}


static int assign_object(llist *l, lnode *n, int type,
			 const char *ptr2, int lineno)
{
	// assign the object
	unsigned int i = n->o_count;
	attr_sets_t *sets = l->sets;
	attr_sets_entry_t *set = NULL;
	attr_sets_entry_t *owned_set = NULL;

	sanity_check_node(n, "assign_object - 1");
	n->o[i].type = type;

	char *ptr, *saved, *tmp = strdup(ptr2);
	if (tmp == NULL) {
		msg(LOG_ERR, "memory allocation error in line %d",
			lineno);
		return 1;
	}


	// use already defined set
	if (tmp[0] == '%') {
		char * defined_set = parse_set_name(tmp);
		if (!defined_set) {
			msg(LOG_ERR, "rules: line:%d: assign_object: "
				"cannot obtain set name from \'%s\'",
				lineno, tmp);
			goto free_and_error;
		}

		set = attr_sets_find(sets, defined_set);
		if (!set) {
			msg(LOG_ERR, "rules: line:%d: assign_object: "
				"set \'%s\' was not defined before",
				lineno, defined_set);
			goto free_and_error;
		}

		// we cannot assign any set to these attributes
		if (type == OBJ_TRUST) {
			msg(LOG_ERR, "rules: line:%d: assign_object: "
				"cannot assign any set to %s",
				lineno, obj_val_to_name(type));
			goto free_and_error;
		}

		// strings
		if (set->type != STRING) {
			msg(LOG_ERR, "rules: line:%d: assign_object: "
				"cannot assign SIGNED set %s to the STRING "
				"attribute",
				lineno, defined_set);
			goto free_and_error;
		}


		n->o[i].set = set;
		goto finalize;
	}

	// for debug output
	char name[GROUP_NAME_SIZE];
	memset(name, 0, GROUP_NAME_SIZE);
	snprintf(name, GROUP_NAME_SIZE-1, "_rule-line-%d-obj-%s", lineno,
		 obj_val_to_name(type));



	switch(n->o[i].type) {

	case ALL_OBJ:
		break;

	case OBJ_TRUST: {
		if (strchr(tmp, ',')) {
			msg(LOG_ERR, "rules: line:%d: assign_object: "
				"trust can handle only single value",
				lineno);
			goto free_and_error;
		}

		errno = 0;
		long val = strtol(tmp, NULL, 10);
		if (errno) {
			msg(LOG_ERR,
				"Error converting val (%s) in line %d",
				tmp, lineno);
			goto free_and_error;
		} else {
			if (val != 1 && val != 0) {
				msg(LOG_ERR, "rules: line:%d: assign_object: "
					"trust can be set to 1 or 0", lineno);
				goto free_and_error;
			}
			n->o[i].val = val;
		}
		break;

	} // case


	case ODIR:
	case PATH:
	case DEVICE:
	case FTYPE:
	case FILE_HASH:
	case FMODE: {
		owned_set = attr_set_create(name, STRING);
		set = owned_set;
		if (!set)
			goto free_and_error;

		ptr = strtok_r(tmp, ",", &saved);
		while (ptr) {
			if (!attr_set_check_str(set, ptr) &&
			    attr_set_append_str(set, ptr))
				goto free_and_error;
			ptr = strtok_r(NULL, ",", &saved);
		}

		if (attr_sets_add(sets, set))
			goto free_and_error;
		n->o[i].set = set;
		owned_set = NULL;

		break;
	} // case

	// should not happen
	default: {
		msg(LOG_ERR, "assign_object: fatal error "
			"-> this should not happen!");
		goto free_and_error;
	} // case

	} // switch


 finalize:
	n->o_count++;
	free(tmp);
	sanity_check_node(n, "assign_object - 2");
	return 0;

 free_and_error:
	attr_set_destroy(owned_set);
	free(tmp);
	return 1;
}


static int parse_new_format(llist *l, lnode *n, int lineno)
{
	int state = 0;  // 0 == subj, 1 == obj
	char *ptr;

	while ((ptr = strtok(NULL, " "))) {
		int type;
		char *ptr2 = strchr(ptr, '=');

		if (ptr2) {
			*ptr2 = 0;
			ptr2++;
			if (state == 0) {
				type = subj_name_to_val(ptr, 2);
				if (type == -1) {
					msg(LOG_ERR,
					"Field type (%s) is unknown in line %d",
						ptr, lineno);
					return 1;
				}
				if (assign_subject(l, n, type, ptr2, lineno))
					return 1;
			} else {
				type = obj_name_to_val(ptr);
				if (type == -1) {
					msg(LOG_ERR,
					"Field type (%s) is unknown in line %d",
						ptr, lineno);
					return 2;
				} else if (assign_object(l, n, type, ptr2,
							 lineno))
					return 1;
			}
		} else if (state == 0 && strcmp(ptr, ":") == 0)
			state = 1;
		else if (strcmp(ptr, "all") == 0) {
			if (state == 0) {
				type = ALL_SUBJ;
				if (assign_subject(l, n, type, "", lineno))
					return 1;
			} else {
				type = ALL_OBJ;
				if (assign_object(l, n, type, "", lineno))
					return 1;
			}
		} else {
			msg(LOG_ERR, "'=' is missing for field %s, in line %d",
				ptr, lineno);
			return 5;
		}
	}
	return 0;
}

/*
 * parse_set_line - parse an attribute set definition
 * @sets: rule-load registry that owns named sets
 * @line: rule file line that starts with a '%' set name
 * @lineno: rule file line number used for diagnostics
 *
 * The parser validates the set name, infers whether the values are strings
 * or integers, creates the set, and appends every parsed value. Set lines
 * define parser state only; they do not become policy rule nodes.
 *
 * Returns: 0 on success, 1 on parse or allocation errors.
 */
static int parse_set_line(attr_sets_t *sets, const char *line, int lineno)
{
	attr_sets_entry_t *set = NULL;

	if (!line)
		return 1;

	char * l = strdup(line);
	if (!l) {
		return 1;
	}

	char * sep = strchr(l, '=');
	if (!sep) {
		msg(LOG_ERR, "rules.conf:%d: parse_set_line: "
			"Cannot parse line, no separator \"=\"", lineno);
		goto free_and_error;
	} else {
		*sep = '\0';
	}

	char * name = parse_set_name(l);
	if (!name) {
		msg(LOG_ERR, "rules.conf:%d: parse_set_line: "
			"Cannot parse name of the set", lineno);
	        goto free_and_error;
	}

	if (attr_sets_find(sets, name)) {
		msg(LOG_ERR, "rules.conf:%d: parse_set_line: "
			"set %s was already defined!", lineno, name);
		goto free_and_error;
	}


	char *ptr, *saved, *tmp = sep + 1;
	char *values = NULL;

	tmp = fapolicyd_strtrim(tmp);

	int type = STRING;
	bool numeric_found = false;

	values = strdup(tmp);
	if (!values)
		goto free_and_error;

	char *val_ptr, *val_saved;
	val_ptr = strtok_r(values, ",", &val_saved);
	while (val_ptr) {
		char *token = fapolicyd_strtrim(val_ptr);
		if (!token || *token == '\0') {
			val_ptr = strtok_r(NULL, ",", &val_saved);
			continue;
		}

		errno = 0;
		char *endptr = NULL;
		long long sval = strtoll(token, &endptr, 10);
		if (errno == 0 && endptr && *endptr == '\0') {
			numeric_found = true;
			if (sval < 0)
				type = SIGNED;
			else if (type != SIGNED)
				type = UNSIGNED;
		} else {
			type = STRING;
			numeric_found = false;
			break;
		}

		val_ptr = strtok_r(NULL, ",", &val_saved);
	}

	if (!numeric_found)
		type = STRING;

	free(values);
	values = NULL;

	set = attr_set_create(name, type);
	if (!set)
		goto free_and_error;

	ptr = strtok_r(tmp, ",", &saved);
	while (ptr) {
		ptr = fapolicyd_strtrim(ptr);
		if (!ptr || *ptr == '\0') {
			ptr = strtok_r(NULL, ",", &saved);
			continue;
		}
		if (type == STRING) {
			if (attr_set_append_str(set, ptr))
				goto free_and_error;
		} else if (type == SIGNED) {
			errno = 0;
			long val = strtol(ptr, NULL, 10);
			if (errno) {
				msg(LOG_ERR,
					"Error converting val (%s) in line %d",
					ptr, lineno);
				goto free_and_error;
			} else if (attr_set_append_int(set, (int64_t)val))
				goto free_and_error;

		} else if (type == UNSIGNED) {
			if (*ptr == '-') {
				msg(LOG_ERR,
					"Error converting val (%s) in line %d",
					ptr, lineno);
				goto free_and_error;
			}
			errno = 0;
			unsigned long val = strtoul(ptr, NULL, 10);
			if (errno) {
				msg(LOG_ERR,
					"Error converting val (%s) in line %d",
					ptr, lineno);
				goto free_and_error;
			} else if (attr_set_append_int(set, (int64_t)val))
				goto free_and_error;
		}
		ptr = strtok_r(NULL, ",", &saved);
	}

	if (attr_sets_add(sets, set))
		goto free_and_error;
	set = NULL;

	free(l);
	return 0;

 free_and_error:
	attr_set_destroy(set);
	free(l);
	return 1;
}

/*
 * nv_split - parse one rule file line
 * @sets: rule-load registry that owns parsed attribute sets
 * @buf: mutable rule file line to parse
 * @n: rule node populated when the line contains a policy rule
 * @lineno: rule file line number used for diagnostics
 *
 * Empty lines, comments, and attribute set definitions are handled by the
 * parser but should not be appended as policy rule nodes. Those successful
 * non-rule lines return RULE_PARSE_SKIP.
 *
 * Returns: RULE_PARSE_OK when @n contains a rule, RULE_PARSE_SKIP when the
 * line should not append a rule node, or RULE_PARSE_ERROR on parse failure.
 */
static enum rule_parse_result nv_split(llist *l, char *buf, lnode *n,
				       int lineno)
{
	char *ptr, *ptr2;
	rformat_t format = RULE_FMT_ORIG;
	attr_sets_t *sets = l->sets;

	if (strchr(buf, ':'))
		format = RULE_FMT_COLON;
	n->format = format;

	ptr = strtok(buf, " ");
	if (ptr == NULL)
		return RULE_PARSE_SKIP;
	if (ptr[0] == '#')
		return RULE_PARSE_SKIP;
	if (ptr[0] == '%') {
		if (parse_set_line(sets, ptr, lineno))
			return RULE_PARSE_ERROR;
		return RULE_PARSE_SKIP;
	}

	// Load decision
	n->d = dec_name_to_val(ptr);
	if ((int)n->d == -1) {
		msg(LOG_ERR, "Invalid decision (%s) in line %d",
				ptr, lineno);
		return RULE_PARSE_ERROR;
	}

	// Default access permission is open
	n->a = OPEN_ACC;

	while ((ptr = strtok(NULL, " "))) {
		int type;

		ptr2 = strchr(ptr, '=');
		if (ptr2) {
			*ptr2 = 0;
			ptr2++;
			if (format == RULE_FMT_COLON) {
				if (strcmp(ptr, "perm") == 0) {
					if (strcmp(ptr2, "execute") == 0)
						n->a = EXEC_ACC;
					else if (strcmp(ptr2, "any") == 0)
						n->a = ANY_ACC;
					else if (strcmp(ptr2, "open")) {
						msg(LOG_ERR,
				"Access permission (%s) is unknown in line %d",
							ptr2, lineno);
						return RULE_PARSE_ERROR;
					}
				} else {
					type = subj_name_to_val(ptr, 2);
					if (type == -1) {
						msg(LOG_ERR,
					"Field type (%s) is unknown in line %d",
							ptr, lineno);
						return RULE_PARSE_ERROR;
					}
					if (assign_subject(l, n, type, ptr2,
							   lineno))
						return RULE_PARSE_ERROR;
				}
				if (parse_new_format(l, n, lineno))
					return RULE_PARSE_ERROR;
				goto finish_up;
			}
			type = subj_name_to_val(ptr, format);
			if (type == -1) {
				type = obj_name_to_val(ptr);
				if (type == -1) {
					msg(LOG_ERR,
					"Field type (%s) is unknown in line %d",
						ptr, lineno);
					return RULE_PARSE_ERROR;
				} else if (assign_object(l, n, type, ptr2,
							 lineno))
					return RULE_PARSE_ERROR;
			} else if (assign_subject(l, n, type, ptr2, lineno))
				return RULE_PARSE_ERROR;
		} else if (strcmp(ptr, "all") == 0) {
			if (n->s_count == 0) {
				type = ALL_SUBJ;
				if (assign_subject(l, n, type, "", lineno))
					return RULE_PARSE_ERROR;
			} else if (n->o_count == 0) {
				type = ALL_OBJ;
				if (assign_object(l, n, type, "", lineno))
					return RULE_PARSE_ERROR;
			} else {
				msg(LOG_ERR,
			"All can only be used in place of a subject or object");
				return RULE_PARSE_ERROR;
			}
		} else {
			msg(LOG_ERR, "'=' is missing for field %s, in line %d",
				ptr, lineno);
			return RULE_PARSE_ERROR;
		}
	}

finish_up:
	// do one last sanity check for missing subj or obj
	if (n->s_count == 0) {
		msg(LOG_ERR, "Subject is missing in line %d", lineno);
		return RULE_PARSE_ERROR;
	}
	if (n->o_count == 0) {
		msg(LOG_ERR, "Object is missing in line %d", lineno);
		return RULE_PARSE_ERROR;
	}
	return RULE_PARSE_OK;
}


// This function take a whole rule as input and passes it to nv_split.
// Returns 0 if success and 1 on rule failure.
int rules_append(llist *l, char *buf, unsigned int lineno)
{
	lnode* newnode;

	sanity_check_list(l, "rules_append - 1");
	if (buf && l->sets) { // parse up the rule
		unsigned int i;
		newnode = malloc(sizeof(lnode));
		if (newnode == NULL)
			return 1;

		memset(newnode, 0, sizeof(lnode));
		newnode->s_count = 0;
		newnode->o_count = 0;
		atomic_init(&newnode->hits, 0);
		newnode->text = strdup(buf);
		if (newnode->text == NULL) {
			free(newnode);
			return 1;
		}
		for (i=0; i<MAX_FIELDS; i++) {
			newnode->s[i].type = UNUSED;
			newnode->o[i].type = UNUSED;
		}
		enum rule_parse_result rc = nv_split(l, buf, newnode,
						     lineno);
		if (rc == RULE_PARSE_SKIP) {
			free(newnode->text);
			free(newnode);
			return 0;
		} else if (rc == RULE_PARSE_ERROR) {
			free(newnode->text);
			free(newnode);
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
 *
 * kworker:
 *    exe=kworker/u130:6 : path=/usr/bin/cat
 *    exe=kworker/u130:6 : path=/usr/lib64/ld-linux-x86-64.so.2
 *    exe=/usr/bin/cat : path=/etc/ld.so.cache
 *    exe=/usr/bin/cat : path=/usr/lib64/libc.so.6
 *
 *    Springs to life without ever being an object. Becomes STATE_NORMAL.
 */

// Returns 0 if no match, 1 if a match, -1 on error
static int subj_pattern_test(const subject_attr_t *s, event_t *e)
{
	int rc = 0;
	struct proc_info *pinfo = e->s->info;

	// At this point, we have only 1 or 2 paths.
	if (pinfo->state < STATE_FULL) {
		// if it's not an elf file, we're done
		if (pinfo->elf_info == 0) {
			pinfo->state = STATE_NOT_ELF;
			clear_proc_info(pinfo);
		}
		// If its a static, make a decision. EXEC_PERM will cause
		// a follow up open request. We change state here and will
		// go all the way to static on the open request.
		else if ((pinfo->elf_info & IS_ELF) &&
				(pinfo->state == STATE_COLLECTING) &&
				((pinfo->elf_info & HAS_DYNAMIC) == 0)) {
			pinfo->state = STATE_STATIC_REOPEN;
			goto make_decision;
		} else if (pinfo->state == STATE_STATIC_PARTIAL)
			goto make_decision;
		else if ((e->type & FAN_OPEN_EXEC_PERM) && pinfo->path1 &&
				strcmp(pinfo->path1, SYSTEM_LD_SO) == 0) {
			pinfo->state = STATE_LD_SO;
			msg(LOG_DEBUG, "pid %d ld.so exec path1=%s path2=%s",
			    pinfo->pid, pinfo->path1 ? pinfo->path1 : "(null)",
			    pinfo->path2 ? pinfo->path2 : "(null)");
			goto make_decision;
		}
		// otherwise, we don't have enough info for a decision
		return rc;
	}

	// Do the analysis
	if (pinfo->state == STATE_FULL) {
		if (pinfo->elf_info & HAS_ERROR) {
			pinfo->state = STATE_BAD_ELF;
			clear_proc_info(pinfo);
			return -1;
		}

		// Pattern detection is only static or not, ld.so started or
		// not. That means everything else is normal.
		if (strcmp(pinfo->path1, SYSTEM_LD_SO) == 0) {
			// First thing is ld.so when its used - detected above
			pinfo->state = STATE_LD_SO;
		msg(LOG_DEBUG, "pid %d ld.so early path1=%s path2=%s",
		    pinfo->pid, pinfo->path1, pinfo->path2);
		} else    // To get here, pgm matched path1
			pinfo->state = STATE_NORMAL;
	}

	// Make a decision
make_decision:
	switch (s->uval)
	{
		case PATTERN_NORMAL_VAL:
			if (pinfo->state == STATE_NORMAL)
				rc = 1;
			break;
		case PATTERN_LD_SO_VAL:
			if (pinfo->state == STATE_LD_SO)
				rc = 1;
			break;
		case PATTERN_STATIC_VAL:
			if ((pinfo->state == STATE_STATIC_REOPEN) ||
				(pinfo->state == STATE_STATIC_PARTIAL) ||
				(pinfo->state == STATE_STATIC))
				rc = 1;
			break;
		case PATTERN_LD_PRELOAD_VAL: {
			int env = check_environ_from_pid(pinfo->pid);
			if (env == 1) {
				pinfo->state = STATE_LD_PRELOAD;
				rc = 1;
			} }
			break;
	}

	// Done with the paths
	clear_proc_info(pinfo);

	return rc;
}


// Returns 0 if no match, 1 if a match
static int check_access(const lnode *r, const event_t *e)
{
	access_t perm;

	if (r->a == ANY_ACC)
		return 1;

	if (e->type & FAN_OPEN_EXEC_PERM)
		perm = EXEC_ACC;
	else
		perm = OPEN_ACC;

	return r->a == perm;
}


// Returns 0 if no match, 1 if a match, -1 on error
__attribute__((hot))
static int check_subject(lnode *r, event_t *e)
{
	unsigned int cnt = 0;

	sanity_check_node(r, "check_subject");

	while (cnt < r->s_count) {
		unsigned int type = r->s[cnt].type;
		subject_attr_t *subj = NULL;

		// optimize get_subj_attr call if possible
		if (type == ALL_SUBJ) {
			cnt++;
			continue;
		} else {
			subj = get_subj_attr(e, type);
		}

		if (subj == NULL && type != PATTERN) {
			cnt++;
			continue;
		}

		switch(type) {

		// numbers -> multiple value
		case AUID:
		case SESSIONID: {
			if (!attr_set_check_int(r->s[cnt].set,
						(int64_t)subj->uval))
				return 0;
			break;
		}
		case UID:
			/*
			 * A process can present multiple UID values (real,
			 * effective, saved, filesystem).  Require the rule's
			 * UID set to intersect the complete credential set the
			 * subject cached so that any matching identity
			 * authorizes the rule.
			 */
			if (!avl_intersection(&(r->s[cnt].set->tree),
					      &(subj->set->tree)))
				return 0;
			break;
		case PID:
		case PPID: {
			if (!attr_set_check_int(r->s[cnt].set,
						(int64_t)subj->pid))
				return 0;
 			break;
		} // case

		// GID is unique in that process can have multiple and
		// rules can have multiple
		case GID:
			if (!avl_intersection(&(r->s[cnt].set->tree),
					     &(subj->set->tree)))
				return 0;
			break;

		// single value exception
		case PATTERN: {
			int rc = subj_pattern_test(&(r->s[cnt]), e);

			if (rc == 0)
				return 0;
			// If there was an error, consider it
			// a match since deny is likely
			if (rc == -1)
				return 1;

			break;
		} // case


		// single value exception
		case SUBJ_TRUST: {
			if (subj->uval != r->s[cnt].uval)
				return 0;
			break;
		} // case


		// regular strings -> multiple value
		case EXE: {
			if (!subj->str) {
				break;
			}

			/*
			 * "untrusted" is a macro-style match. If requested, and the
			 * subject is not trusted, this attribute matches immediately.
			 *
			 * Otherwise, fall back to exact string match semantics so
			 * explicit paths in the set continue to work.
			 */
			if (attr_set_check_str(r->s[cnt].set, "untrusted") &&
			    !is_subj_trusted(e))
				break;

			if (!attr_set_check_str(r->s[cnt].set, subj->str))
				return 0;

			break;
		} // case


		case COMM:
		case EXE_TYPE: {
			if (!subj->str)
				break;

			if (!attr_set_check_str(r->s[cnt].set, subj->str))
				return 0;

			break;
		} // case


		case EXE_DIR: {
			int macro_match = 0;

			if (!subj->str) {
				break;
			}

			if (attr_set_check_str(r->s[cnt].set, "execdirs"))
				if (check_dirs(1, subj->str))
					macro_match = 1;

			if (attr_set_check_str(r->s[cnt].set, "systemdirs"))
				if (check_dirs(0, subj->str))
					macro_match = 1;

			// DEPRECATED
			if (attr_set_check_str(r->s[cnt].set, "untrusted"))
				if (!is_subj_trusted(e))
					macro_match = 1;

			/*
			 * Macros are alternatives to literal directory prefixes.
			 * If any macro matched, this attribute is satisfied.
			 */
			if (macro_match)
				break;

			// check partial match (via strncmp)
			// subdir test
			if (!attr_set_check_pstr(r->s[cnt].set, subj->str))
				return 0;

			break;
		} // case


		default:
			return -1;

		} // switch


		cnt++;
	}

	return 1;
}


// Returns 0 if no match, 1 if a match
__attribute__((hot))
static decision_t check_object(lnode *r, event_t *e)
{
	unsigned int cnt = 0;

	sanity_check_node(r, "check_object");
	while (cnt < r->o_count) {
		unsigned int type = r->o[cnt].type;
		object_attr_t *obj = NULL;

		// optimize get_obj_attr call if possible
		if (type == ALL_OBJ) {
			cnt++;
			continue;
		} else {
			obj = get_obj_attr(e, type);
		}

		if (obj == NULL) {
			cnt++;
			continue;
		}

		switch(type) {

		case OBJ_TRUST: {
			// obj->val holds (0|1) as int
			if (obj->val != r->o[cnt].val)
				return 0;
			break;
		} // case


		case FTYPE: {

			if (attr_set_check_str(r->o[cnt].set, "any"))
				break;
		}

		// fall through

		case PATH:
		  // skip if fall through
		  if (type == PATH) {
			if (r->s[cnt].type == EXE || r->s[cnt].type == EXE_DIR)
				if (attr_set_check_str(r->s[cnt].set,
						       "untrusted"))
					if (is_obj_trusted(e))
						return 0;
		}

		// fall through

		case DEVICE:
		case FILE_HASH:
		case FMODE: {

			if (!obj->o) {
				// Treat errors as denial for file hash lookups
				if (type == FILE_HASH)
					return 0;
				break;
			}

			if (!attr_set_check_str(r->o[cnt].set, obj->o))
				return 0;

			break;
		} // case


		case ODIR: {
			int macro_match = 0;

			if (!obj->o) {
				break;
			}

			if (attr_set_check_str(r->o[cnt].set, "execdirs"))
				if (check_dirs(1, obj->o))
					macro_match = 1;

			if (attr_set_check_str(r->o[cnt].set, "systemdirs"))
				if (check_dirs(0, obj->o))
					macro_match = 1;

			// DEPRECATED
			if (attr_set_check_str(r->o[cnt].set, "untrusted"))
				if (!is_obj_trusted(e))
					macro_match = 1;

			/*
			 * Keep macro keywords and literal directory prefixes as
			 * ORed alternatives for dir matching.
			 */
			if (macro_match)
				break;

			// check partial match (via strncmp)
			// subdir test
			if (!attr_set_check_pstr(r->o[cnt].set, obj->o))
				return 0;

			break;
		} // case


		// should not happen
		default: {
			return -1;
		} // case

		} // switch

		cnt++;
	}

	return 1;
}


__attribute__((hot))
decision_t rule_evaluate(lnode *r, event_t *e)
{
	int d;

	// Check access permission
	d = check_access(r, e);
	if (d == 0)	// No match
		return NO_OPINION;

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

/*
 * rules_record_hit - count a rule that made the final policy decision.
 * @r: rule whose allow or deny decision ended evaluation.
 *
 * Rule hits are per active ruleset generation; publishing a new generation
 * replaces the rule nodes and starts their counters at zero.
 */
void rules_record_hit(lnode *r)
{
	if (r)
		atomic_fetch_add_explicit(&r->hits, 1, memory_order_relaxed);
}

/*
 * rules_hits_report - write per-rule hit counters in rule order.
 * @f: output stream.
 * @l: active rule list to report.
 *
 * Returns nothing.
 */
void rules_hits_report(FILE *f, const llist *l)
{
	const lnode *r;
	unsigned long max_hits = 0;
	int hits_width;

	if (f == NULL || l == NULL)
		return;

	for (r = rules_first_node(l); r; r = rules_next_node(r)) {
		unsigned long hits = atomic_load_explicit(&r->hits,
							memory_order_relaxed);

		if (hits > max_hits)
			max_hits = hits;
	}

	if (max_hits < 1000000UL)
		hits_width = 6;
	else if (max_hits <= UINT32_MAX)
		hits_width = 10;
	else
		hits_width = 20;

	for (r = rules_first_node(l); r; r = rules_next_node(r))
		fprintf(f, "Hits/rule: %3u %*lu %s\n", r->num + 1,
			hits_width,
			atomic_load_explicit(&r->hits, memory_order_relaxed),
			r->text ? r->text : "");
}


void rules_unsupport_audit(const llist *l)
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
		nextnode=current->next;
		free(current->text);
		free(current);
		current=nextnode;
	}
	l->head = NULL;
	l->cur = NULL;
	l->cnt = 0;
	attr_sets_destroy(l->sets);
	l->sets = NULL;

	l->proc_status_mask = 0;
}

/*
 * rules_get_proc_status_mask - Report /proc status fields needed by rules.
 *
 * Return: bitmap of PROC_STAT_* values observed while parsing the current
 * rule set. The mask guides process attribute collection so we only read
 * /proc/<pid>/status once for all requested fields.
 */
unsigned int rules_get_proc_status_mask(const llist *l)
{
	if (!l)
		return 0;

	return l->proc_status_mask;
}
