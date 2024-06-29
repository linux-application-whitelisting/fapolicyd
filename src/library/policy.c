/*
 * policy.c - functions that encapsulate the notion of a policy
 * Copyright (c) 2016,2019-24 Red Hat Inc.
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

#include "attr-sets.h"
#include "config.h"
#include <stdbool.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <limits.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdatomic.h>

#include "database.h"
#include "escape.h"
#include "file.h"
#include "rules.h"
#include "policy.h"
#include "nv.h"
#include "message.h"
#include "gcc-attributes.h"
#include "string-util.h"
#include "paths.h"
#include "llist.h"

#define MAX_SYSLOG_FIELDS	21
#define NGID_LIMIT		32

static llist rules;
static unsigned long allowed = 0, denied = 0;
static nvlist_t fields[MAX_SYSLOG_FIELDS];
static unsigned int num_fields;

extern volatile atomic_bool stop;
volatile atomic_bool reload_rules = false;

static const nv_t table[] = {
{       NO_OPINION, "no-opinion" },
{       ALLOW, "allow" },
{       DENY, "deny" },
#ifdef USE_AUDIT
{       ALLOW_AUDIT, "allow_audit" },
{       DENY_AUDIT, "deny_audit" },
#endif
{       ALLOW_SYSLOG, "allow_syslog" },
{       DENY_SYSLOG, "deny_syslog" },
{       ALLOW_LOG, "allow_log" },
{       DENY_LOG, "deny_log" }
};

extern unsigned int debug_mode;
extern unsigned int permissive;

extern list_t wildcards;

#define MAX_DECISIONS (sizeof(table)/sizeof(table[0]))

// These are the constants for things not subj or obj
#define F_RULE 30
#define F_DECISION 31
#define F_PERM 32
#define F_COLON 33

#ifdef FAN_AUDIT_RULE_NUM
struct fan_audit_response
{
	struct fanotify_response r;
	struct fanotify_response_info_audit_rule a;
};
#endif

#define WB_SIZE 512
static char *working_buffer = NULL;

// This function returns 1 on success and 0 on failure
static int parsing_obj;
static int lookup_field(const char *ptr)
{
	if (strcmp("rule", ptr) == 0) {
		fields[num_fields].name = strdup(ptr);
		fields[num_fields].item = F_RULE;
		goto success;
	} else if (strcmp("dec", ptr) == 0) {
		fields[num_fields].name = strdup(ptr);
		fields[num_fields].item = F_DECISION;
		goto success;
	} else if (strcmp("perm", ptr) == 0) {
		fields[num_fields].name = strdup(ptr);
		fields[num_fields].item = F_PERM;
		goto success;
	} else if (strcmp(":", ptr) == 0) {
		fields[num_fields].name = strdup(ptr);
		fields[num_fields].item = F_COLON;
		parsing_obj = 1;
		goto success;
	}

	if (parsing_obj == 0) {
		int ret_val = subj_name_to_val(ptr, RULE_FMT_COLON);
		if (ret_val >= 0) {
			if (ret_val == ALL_SUBJ || ret_val == PATTERN ||
			    ret_val > EXE) {
				msg(LOG_ERR,
				   "%s cannot be used in syslog_format", ptr);
			} else {
				fields[num_fields].name = strdup(ptr);
				fields[num_fields].item = ret_val;
				goto success;
			}
		}
	} else {
		int ret_val = obj_name_to_val(ptr);
		if (ret_val >= 0) {
			if (ret_val == ALL_OBJ) {
				msg(LOG_ERR,
				    "%s cannot be used in syslog_format", ptr);
			} else {
				fields[num_fields].name = strdup(ptr);
				fields[num_fields].item = ret_val;
				goto success;
			}
		}
	}

	return 0;
success:
	num_fields++;
	return 1;
}


// This function returns 1 on success, 0 on failure
static int parse_syslog_format(const char *syslog_format)
{
	char *ptr, *saved, *tformat;
	int rc = 1;

	if (strchr(syslog_format, ':') == NULL) {
		msg(LOG_ERR, "syslog_format does not have a ':'");
		return 0;
	}

	num_fields = 0;
	parsing_obj = 0;
	tformat = strdup(syslog_format);

	// Must be delimited by comma
	ptr = strtok_r(tformat, ",", &saved);
	while (ptr && rc && num_fields < MAX_SYSLOG_FIELDS) {
		rc = lookup_field(ptr);
		if (rc == 0)
			msg(LOG_ERR, "Field %s invalid for syslog_format", ptr);
		ptr = strtok_r(NULL, ",", &saved);
	}
	free(tformat);

	return rc;
}

int dec_name_to_val(const char *name)
{
        unsigned int i = 0;
        while (i < MAX_DECISIONS) {
                if (strcmp(name, table[i].name) == 0)
                        return table[i].value;
                i++;
        }
        return -1;
}

static const char *dec_val_to_name(unsigned int v)
{
	unsigned int i = 0;
        while (i < MAX_DECISIONS) {
		if (v == table[i].value)
	                return table[i].name;
		i++;
	}
        return NULL;
}

static FILE *open_file(void)
{
	int fd;
	FILE *f;
	// Now open the file and load them one by one. We default to
	// opening the old file first in case there are both
	fd = open(OLD_RULES_FILE, O_NOFOLLOW|O_RDONLY);
	if (fd < 0) {
		// See if the new rules exist
		fd = open(RULES_FILE, O_NOFOLLOW|O_RDONLY);
		if (fd < 0) {
			msg(LOG_ERR, "Error opening rules file (%s)",
				strerror(errno));
			return NULL;
		}
	}

    struct stat sb;
    if (fstat(fd, &sb)) {
        msg(LOG_ERR, "Failed to stat rule file %s", strerror(errno));
        close(fd);
        return NULL;
    }

    char *sha_buf = get_hash_from_fd2(fd, sb.st_size, 1);
    if (sha_buf) {
        msg(LOG_INFO, "Ruleset identity: %s", sha_buf);
        free(sha_buf);
    } else {
        msg(LOG_WARNING, "Failed to hash rule identity %s", strerror(errno));
    }

    f = fdopen(fd, "r");
	if (f == NULL) {
		msg(LOG_ERR, "Error - fdopen failed (%s)",
			strerror(errno));
	}

	return f;
}

// Returns 0 on success and 1 on error
static int _load_rules(const conf_t *_config, FILE *f)
{
	int rc, lineno = 1;
	char *line = NULL;
	size_t len = 0;

	if (rules_create(&rules))
		return 1;

	msg(LOG_DEBUG, "Loading rule file:");

	while (getline(&line, &len, f) != -1) {
		char *ptr = strchr(line, 0x0a);
		if (ptr)
			*ptr = 0;
		msg(LOG_DEBUG, "%s", line);

		// Get wildcards by keyword from the rule and add to the list
		char wc_key[16] = "path=";
		char *wc_data = strstr(line, wc_key);
		if (wc_data) {
			if (strpbrk(wc_data, "?*[" ) != NULL) {
				char *wildcard = malloc(strlen(wc_data));
				sscanf(wc_data, strcat(wc_key,"%s"), wildcard);
				if (!list_contains(&wildcards, wildcard)) {
					msg(LOG_DEBUG, "Add to the list discovered wildcard %s", wildcard);
					list_append(&wildcards, wildcard, wildcard);
				}
			}
		}

		rc = rules_append(&rules, line, lineno);
		if (rc) {
			free(line);
			return 1;
		}
		lineno++;
	}
	free(line);

	rules_regen_sets(&rules);

	if (rules.cnt == 0) {
		msg(LOG_INFO, "No rules in file - exiting");
		return 1;
	} else {
		msg(LOG_DEBUG, "Loaded %u rules", rules.cnt);
	}

	rc = parse_syslog_format(_config->syslog_format);
	if (!rc || num_fields == 0)
		return 1;

	return 0;
}

int load_rules(const conf_t *_config)
{
	if (init_attr_sets())
		return 1;

	FILE * f = open_file();
	if (f == NULL) {
		destroy_attr_sets();
		return 1;
	}

	int res = _load_rules(_config, f);
	fclose(f);

	if (res) {
		destroy_attr_sets();
		return 1;
	}

	return 0;
}

void destroy_rules(void)
{
	unsigned int i = 0;

	rules_clear(&rules);

	// Remove wildcards as well
	list_empty(&wildcards);

	while (i < num_fields) {
		free((void *)fields[i].name);
		i++;
	}

	destroy_attr_sets();
	if (stop)
		free(working_buffer);
}

void set_reload_rules(void)
{
	reload_rules = true;
}

static FILE * ff = NULL;
int load_rule_file(void)
{
	if (ff) {
		fclose(ff);
		ff = NULL;
	}

	ff = open_file();
	if (ff == NULL)
		return 1;

	return 0;
}

int do_reload_rules(const conf_t *_config)
{
	destroy_rules();

	if (init_attr_sets())
		return 1;

	_load_rules(_config, ff);

	fclose(ff);
	ff = NULL;
	return 0;
}

static char *format_value(int item, unsigned int num, decision_t results,
	event_t *e) __attr_dealloc_free;
static char *format_value(int item, unsigned int num, decision_t results,
	event_t *e)
{
	char *out = NULL;

	if (item >= F_RULE) {
		switch (item) {
		case F_RULE:
			if (asprintf(&out, "%u", num+1) < 0)
				out = NULL;
			break;
		case F_DECISION:
			if (asprintf(&out, "%s", dec_val_to_name(results)) < 0)
				out = NULL;
			break;
		case F_PERM:
			if (asprintf(&out, "%s",
					e->type & FAN_OPEN_EXEC_PERM ?
					"execute" : "open") < 0)
				out = NULL;
			break;
		case F_COLON:
			if (asprintf(&out, ":") < 0)
				out = NULL;
			break;
		}
	} else if (item >= OBJ_START) {
		object_attr_t *obj = get_obj_attr(e, item);
		if (item != OBJ_TRUST) {
			char * str = obj ? obj->o : "?";
			size_t need_escape = check_escape_shell(str);

			if (need_escape)
				// need_escape contains potential size of escaped string
				str = escape_shell(str, need_escape);

			if (asprintf(&out, "%s", str ? str : "??") < 0)
				out = NULL;

		} else {
		    if (asprintf(&out, "%d", obj ? (obj->val ? 1 : 0) : 9) < 0)
				out = NULL;
		}
	} else {
		subject_attr_t *subj = get_subj_attr(e, item);
		if (item < GID) {
			if (asprintf(&out, "%d", subj ? subj->val : -2) < 0)
				out = NULL;
		} else if (item >= COMM) {
			char * str = subj ? subj->str : "?";
			size_t need_escape = check_escape_shell(str);

			if (need_escape)
				// need_escape contains potential size of escaped string
				str = escape_shell(str, need_escape);

			if (asprintf(&out, "%s", str ? str : "??") < 0)
				out = NULL;

		} else { // GID only log first 32
			out = malloc(NGID_LIMIT*12);
			if (out && subj->set) {
				char buf[12];
				char *ptr = out;
				int cnt = 0;
				avl_iterator i;
				avl_int_data_t *grp;
				for (grp = (avl_int_data_t *)
				           avl_first(&i, &(subj->set->tree));
				           grp && cnt < NGID_LIMIT;
					   grp=(avl_int_data_t *)avl_next(&i)) {
					if (ptr == out)
						snprintf(buf, sizeof(buf),
							 "%d", grp->num);
					else
						snprintf(buf, sizeof(buf),
							 ",%d", grp->num);
					ptr = stpcpy(ptr, buf);
					cnt++;
				}
			} else if (out)
				strcpy(out, "?");
		}
	}
	return out;
}

// This is like memccpy except it returns the pointer to the NIL byte so
// that we are positioned for the next concatenation. Also, since we know
// we are always looking for NIL, just hard code it.
static void *fmemccpy(void* restrict dst, const void* restrict src, ssize_t n)
{
	if (n <= 0)
		return dst;

	const char *s = src;
	char *ret = dst;
	for ( ; n; ++ret, ++s, --n) {
		*ret = *s;
		if ((unsigned char)*ret == (unsigned char)'\0')
			return ret;
	}
	return ret;
}


static void log_it2(unsigned int num, decision_t results, event_t *e)
{
	int mode = results & SYSLOG ? LOG_INFO : LOG_DEBUG;
	unsigned int i;
	int dsize;
	char *p1, *p2, *val;

	if (working_buffer == NULL) {
		working_buffer = malloc(WB_SIZE);
		if (working_buffer == NULL) {
			msg(LOG_ERR, "No working buffer for logging");
			return;
		}
	}

	dsize = WB_SIZE;
	p1 = p2 = working_buffer; // Dummy assignment for p1 to quiet warnings
	for (i = 0; i < num_fields && dsize; i++)
	{
		if (dsize < WB_SIZE) {
			// This is skipped first pass, p1 is initialized below
			p2 = fmemccpy(p1, " ", dsize);
			dsize -= p2 - p1;
		}
		p1 = fmemccpy(p2, fields[i].name, dsize);
		dsize -= p1 - p2;
		if (fields[i].item != F_COLON) {
			p2 = fmemccpy(p1, "=", dsize);
			dsize -= p2 - p1;
			val = format_value(fields[i].item, num, results, e);
			p1 = fmemccpy(p2, val ? val : "?", dsize);
			dsize -= p1 - p2;
			free(val);
		}
	}
	working_buffer[WB_SIZE-1] = 0;	// Just in case
	msg(mode, "%s", working_buffer);
}


decision_t process_event(event_t *e)
{
	decision_t results = NO_OPINION;

	/* populate the event struct and iterate over the rules */
	rules_first(&rules);
	lnode *r = rules_get_cur(&rules);
	int cnt = 0;
	while (r) {
		//msg(LOG_INFO, "process_event: rule %d", cnt);
		results = rule_evaluate(r, e);
		// If a rule has an opinion, stop and use it
		if (results != NO_OPINION)
			break;
		r = rules_next(&rules);
		cnt++;
	}

	// Output some information if debugging on or syslogging requested
	if ( (results & SYSLOG) || (debug_mode == 1) ||
	     (debug_mode > 1 && (results & DENY)) )
		log_it2(r ? r->num : 0xFFFFFFFF, results, e);

	// Record which rule (rules are 1 based when listed by the cli tool)
	if (r)
		e->num = r->num + 1;

	// If we are not in permissive mode, return any decision
	if (results != NO_OPINION)
		return results;

	return ALLOW;
}

#ifdef FAN_AUDIT_RULE_NUM
static int test_info_api(int fd)
{
	int rc;
	struct fan_audit_response f;

	f.r.fd = FAN_NOFD;
	f.r.response = FAN_DENY | FAN_INFO;
	f.a.hdr.type = FAN_RESPONSE_INFO_AUDIT_RULE;
	f.a.hdr.pad = 0;
	f.a.hdr.len = sizeof(struct fanotify_response_info_audit_rule);
	f.a.rule_number = 0;
	f.a.subj_trust = 2;
	f.a.obj_trust = 2;
	rc = write(fd, &f, sizeof(struct fan_audit_response));
	msg(LOG_DEBUG, "Rule number API supported %s", rc < 0 ? "no" : "yes");
	if (rc < 0)
		return 0;
	else
		return 1;
}
#endif

void reply_event(int fd, const struct fanotify_event_metadata *metadata,
		unsigned reply, event_t *e)
{
	close(metadata->fd);
#ifdef FAN_AUDIT_RULE_NUM
	static int use_new = 2;
	if (use_new == 2)
		use_new = test_info_api(fd);
	if (reply & FAN_AUDIT && use_new) {
		struct fan_audit_response f;
		subject_attr_t *sn;
		object_attr_t *obj;

		f.r.fd = metadata->fd;
		f.r.response = reply | FAN_INFO;
		f.a.hdr.type = FAN_RESPONSE_INFO_AUDIT_RULE;
		f.a.hdr.pad = 0;
		f.a.hdr.len = sizeof(struct fanotify_response_info_audit_rule);
		if (e)
			f.a.rule_number = e->num;
		else
			f.a.rule_number = 0;

		// Subj trust is rare. See if we have it.
		if (e && (sn = subject_access(e->s, SUBJ_TRUST))) {
			f.a.subj_trust = sn->val;
		} else
			f.a.subj_trust = 2;
		// All objects have a trust value
		if (e && (obj = get_obj_attr(e, OBJ_TRUST))) {
			f.a.obj_trust = obj->val;
		} else
			f.a.obj_trust = 2;
		write(fd, &f, sizeof(struct fan_audit_response));
		return;
	}
#endif
	struct fanotify_response response;

	response.fd = metadata->fd;
	response.response = reply;
	write(fd, &response, sizeof(struct fanotify_response));
}


void make_policy_decision(const struct fanotify_event_metadata *metadata,
						int fd, uint64_t mask)
{
	event_t e;
	int decision;

	if (new_event(metadata, &e))
		decision = FAN_DENY;
	else {
		lock_rule();
		decision = process_event(&e);
		unlock_rule();
	}

	if ((decision & DENY) == DENY)
		denied++;
	else
		allowed++;

	if (metadata->mask & mask) {
		// if in debug mode, do not allow audit events
		if (debug_mode)
			decision &= ~AUDIT;

		// If permissive, always allow and honor the audit bit
		// if not in debug mode
		if (permissive)
			reply_event(fd, metadata,FAN_ALLOW | (decision & AUDIT),
					&e);
		else
			reply_event(fd, metadata, decision & FAN_RESPONSE_MASK,
					&e);
	}
}


unsigned long getAllowed(void)
{
	return allowed;
}


unsigned long getDenied(void)
{
	return denied;
}


void policy_no_audit(void)
{
	rules_unsupport_audit(&rules);
}
