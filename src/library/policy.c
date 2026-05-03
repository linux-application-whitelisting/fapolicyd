/*
 * policy.c - functions that encapsulate the notion of a policy
 * Copyright (c) 2016,2019-25 Red Hat Inc.
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
#include <stdio.h>
#include <fcntl.h>
#include <stdatomic.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <limits.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdatomic.h>

#include "database.h"
#include "decision-timing.h"
#include "escape.h"
#include "failure-action.h"
#include "file.h"
#include "policy-metrics.h"
#include "rules.h"
#include "policy.h"
#include "nv.h"
#include "message.h"
#include "gcc-attributes.h"
#include "string-util.h"
#include "paths.h"
#include "conf.h"
#include "process.h"

#define MAX_SYSLOG_FIELDS	21	// Only 20 fields are defined for
					// decision, permission, obj & subj
#define NGID_LIMIT		32	// Limit buffer size allocated for
					// subject to not waste memory

/*
 * policy_snapshot - coherent policy generation used for decisions
 *
 * The rule list owns parsed rule nodes and attribute sets. The same snapshot
 * also owns syslog fields, proc-status masks, the rule count, and the hashed
 * rule-file identity so all parser side effects publish as one unit.
 */
struct policy_snapshot {
	llist rules;
	nvlist_t fields[MAX_SYSLOG_FIELDS];
	unsigned int num_fields;
	unsigned int rules_proc_status_mask;
	unsigned int syslog_proc_status_mask;
	unsigned int rule_count;
	char *rule_file_identity;
};

/*
 * active_policy - currently published policy generation
 *
 * Evaluation and reload both run under the rule lock, so pointer replacement
 * and old-snapshot destruction are serialized with policy readers.
 */
static struct policy_snapshot *active_policy;
/*
 * active_*_proc_status_mask - atomic copies of active snapshot masks
 *
 * Event construction reads these without taking the rule lock so proc-status
 * collection can request fields required by the active rules and log format.
 */
static atomic_uint active_rules_proc_status_mask;
static atomic_uint active_syslog_proc_status_mask;

extern atomic_bool stop;
atomic_bool reload_rules = false;

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
extern conf_t config;

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
static void *fmemccpy(void* restrict dst, const void* restrict src, size_t n)
	__attr_access((__write_only__, 1, 3))
	__attr_access((__read_only__, 2, 3));

/*
 * free_syslog_fields - release syslog format fields in a policy snapshot
 * @policy: snapshot whose syslog field array should be reset.
 * Returns nothing.
 */
static void free_syslog_fields(struct policy_snapshot *policy)
{
	unsigned int i = 0;

	while (i < policy->num_fields) {
		free((void *)policy->fields[i].name);
		policy->fields[i].name = NULL;
		i++;
	}

	policy->num_fields = 0;
	policy->syslog_proc_status_mask = 0;
}

/*
 * policy_snapshot_destroy - release one policy snapshot
 * @policy: snapshot to destroy, or NULL.
 * Returns nothing.
 */
static void policy_snapshot_destroy(struct policy_snapshot *policy)
{
	if (!policy)
		return;

	rules_clear(&policy->rules);
	free_syslog_fields(policy);
	free(policy->rule_file_identity);
	free(policy);
}

/*
 * policy_snapshot_create - allocate an unpublished policy snapshot
 * @identity: optional rule file identity string, transferred to the snapshot
 *
 * The caller builds rules and syslog fields in this private object. It is
 * only installed as the active policy after every parser stage succeeds.
 *
 * Returns: snapshot pointer on success, NULL on allocation failure.
 */
static struct policy_snapshot *policy_snapshot_create(char *identity)
{
	struct policy_snapshot *policy = calloc(1, sizeof(*policy));

	if (!policy) {
		free(identity);
		return NULL;
	}

	if (rules_create(&policy->rules)) {
		free(identity);
		free(policy);
		return NULL;
	}

	policy->rule_file_identity = identity;
	return policy;
}

/*
 * add_syslog_field - append one parsed syslog format field
 * @policy: candidate policy snapshot receiving the field.
 * @name: field name to copy into the snapshot.
 * @item: field identifier used when formatting policy logs.
 * Returns 1 on success, 0 on allocation or capacity failure.
 */
static int add_syslog_field(struct policy_snapshot *policy, const char *name,
			    int item)
{
	if (policy->num_fields >= MAX_SYSLOG_FIELDS)
		return 0;

	policy->fields[policy->num_fields].name = strdup(name);
	if (!policy->fields[policy->num_fields].name) {
		msg(LOG_ERR, "No memory for syslog_format field %s", name);
		return 0;
	}

	policy->fields[policy->num_fields].item = item;
	policy->num_fields++;
	return 1;
}

static int lookup_field(struct policy_snapshot *policy, const char *ptr)
{
	if (strcmp("rule", ptr) == 0) {
		return add_syslog_field(policy, ptr, F_RULE);
	} else if (strcmp("dec", ptr) == 0) {
		return add_syslog_field(policy, ptr, F_DECISION);
	} else if (strcmp("perm", ptr) == 0) {
		return add_syslog_field(policy, ptr, F_PERM);
	} else if (strcmp(":", ptr) == 0) {
		parsing_obj = 1;
		return add_syslog_field(policy, ptr, F_COLON);
	}

	if (parsing_obj == 0) {
		int ret_val = subj_name_to_val(ptr, RULE_FMT_COLON);
		if (ret_val >= 0) {
			if (ret_val == ALL_SUBJ || ret_val == PATTERN ||
			    ret_val > EXE) {
				msg(LOG_ERR,
				   "%s cannot be used in syslog_format", ptr);
			} else {
				// Opportunistically mark the fields that might
				// be needed for logging so that we gather
				// them all at once later.
				switch (ret_val) {
				case UID:
				    policy->syslog_proc_status_mask |=
					    PROC_STAT_UID;
				    break;
				case PPID:
				    policy->syslog_proc_status_mask |=
					    PROC_STAT_PPID;
				    break;
				case GID:
				    policy->syslog_proc_status_mask |=
					    PROC_STAT_GID;
				    break;
				case COMM:
				    policy->syslog_proc_status_mask |=
					    PROC_STAT_COMM;
				    break;
				default:
				    break;
				}
				return add_syslog_field(policy, ptr, ret_val);
			}
		}
	} else {
		int ret_val = obj_name_to_val(ptr);
		if (ret_val >= 0) {
			if (ret_val == ALL_OBJ) {
				msg(LOG_ERR,
				    "%s cannot be used in syslog_format", ptr);
			} else {
				return add_syslog_field(policy, ptr, ret_val);
			}
		}
	}

	return 0;
}


// This function returns 1 on success, 0 on failure
static int parse_syslog_format(struct policy_snapshot *policy,
			       const char *syslog_format)
{
	char *ptr, *saved, *tformat;
	int rc = 1;

	if (!syslog_format) {
		msg(LOG_ERR, "syslog_format is not configured");
		return 0;
	}

	if (strchr(syslog_format, ':') == NULL) {
		msg(LOG_ERR, "syslog_format does not have a ':'");
		return 0;
	}

	free_syslog_fields(policy);
	parsing_obj = 0;
	tformat = strdup(syslog_format);
	if (!tformat) {
		msg(LOG_ERR, "No memory for syslog_format");
		return 0;
	}

	// Must be delimited by comma
	ptr = strtok_r(tformat, ",", &saved);
	while (ptr && rc && policy->num_fields < MAX_SYSLOG_FIELDS) {
		rc = lookup_field(policy, ptr);
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

static FILE *open_file(char **identity)
{
	int fd;
	FILE *f;

	if (identity)
		*identity = NULL;

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

	char *sha_buf = get_hash_from_fd2(fd, sb.st_size, FILE_HASH_ALG_SHA256);
	if (sha_buf) {
		if (identity)
			*identity = sha_buf;
		else
			free(sha_buf);
	} else {
		msg(LOG_WARNING, "Failed to hash rule identity %s",
		    strerror(errno));
	}

	f = fdopen(fd, "r");
	if (f == NULL) {
		msg(LOG_ERR, "Error - fdopen failed (%s)", strerror(errno));
		free(identity ? *identity : NULL);
		if (identity)
			*identity = NULL;
		close(fd);
	}

	return f;
}

/*
 * log_policy_update_failure - report an unsuccessful policy update
 * @void: no arguments are required.
 * Returns nothing.
 */
static void log_policy_update_failure(void)
{
	if (active_policy)
		msg(LOG_ERR, "Daemon configuration update failed; "
		    "previous policy preserved");
	else
		msg(LOG_ERR, "Daemon configuration update failed; "
		    "no policy installed");
}

/*
 * publish_policy_snapshot - install a fully validated policy snapshot
 * @policy: candidate snapshot built by build_policy_snapshot().
 * Returns nothing.
 */
static void publish_policy_snapshot(struct policy_snapshot *policy)
{
	struct policy_snapshot *old = active_policy;

	policy->rule_count = policy->rules.cnt;
	policy->rules_proc_status_mask =
		rules_get_proc_status_mask(&policy->rules);

	/*
	 * Transaction point: after this assignment, new decisions use the
	 * candidate policy. Everything before this must be able to fail while
	 * leaving the old active_policy untouched.
	 */
	active_policy = policy;
	policy_metrics_record_ruleset_update();
	atomic_store_explicit(&active_rules_proc_status_mask,
			      policy->rules_proc_status_mask,
			      memory_order_release);
	atomic_store_explicit(&active_syslog_proc_status_mask,
			      policy->syslog_proc_status_mask,
			      memory_order_release);

	if (policy->rule_file_identity)
		msg(LOG_INFO, "Ruleset identity: %s",
		    policy->rule_file_identity);
	msg(LOG_INFO, "Daemon rules updated");

	policy_snapshot_destroy(old);
}

/*
 * build_policy_snapshot - parse rules and syslog fields into a candidate
 * @_config: daemon configuration containing the syslog format.
 * @f: already opened rule file stream.
 * @identity: optional rule-file identity string consumed by the candidate.
 * @out: receives the validated snapshot on success.
 *
 * Returns 0 on success, 1 on parser, read, or allocation failure. On failure,
 * the active policy is not changed and @identity has been consumed.
 */
static int build_policy_snapshot(const conf_t *_config, FILE *f,
				 char *identity,
				 struct policy_snapshot **out)
{
	int rc, lineno = 1;
	char *line = NULL;
	size_t len = 0;
	struct policy_snapshot *policy = policy_snapshot_create(identity);

	*out = NULL;
	if (!policy)
		return 1;


	msg(LOG_DEBUG, "Loading rule file:");

	while (getline(&line, &len, f) != -1) {
		char *ptr = strchr(line, 0x0a);
		if (ptr)
			*ptr = 0;
		msg(LOG_DEBUG, "%s", line);
		rc = rules_append(&policy->rules, line, lineno);
		if (rc) {
			free(line);
			policy_snapshot_destroy(policy);
			return 1;
		}
		lineno++;
	}
	free(line);

	if (ferror(f)) {
		msg(LOG_ERR, "Error reading rules file (%s)",
		    strerror(errno));
		policy_snapshot_destroy(policy);
		return 1;
	}

	if (policy->rules.cnt == 0) {
		msg(LOG_INFO, "No rules in file - exiting");
		policy_snapshot_destroy(policy);
		return 1;
	} else {
		msg(LOG_DEBUG, "Loaded %u rules", policy->rules.cnt);
	}

	rc = parse_syslog_format(policy, _config->syslog_format);
	if (!rc || policy->num_fields == 0) {
		policy_snapshot_destroy(policy);
		return 1;
	}

	*out = policy;
	return 0;
}

int load_rules(const conf_t *_config)
{
	char *identity = NULL;
	struct policy_snapshot *policy = NULL;
	FILE * f = open_file(&identity);

	if (f == NULL) {
		log_policy_update_failure();
		return 1;
	}

	int res = build_policy_snapshot(_config, f, identity, &policy);
	fclose(f);

	if (res) {
		log_policy_update_failure();
		return 1;
	}

	publish_policy_snapshot(policy);
	return 0;
}

/*
 * load_rules_from_stream - load policy from a caller-owned stream
 * @_config: daemon configuration containing the syslog format.
 * @f: rule stream positioned at the beginning.
 *
 * Returns 0 on success, 1 on failure. This helper exists so tests can exercise
 * the same transactional publish path without depending on /etc paths.
 */
int load_rules_from_stream(const conf_t *_config, FILE *f)
{
	struct policy_snapshot *policy = NULL;

	if (!f) {
		log_policy_update_failure();
		return 1;
	}

	if (build_policy_snapshot(_config, f, NULL, &policy)) {
		log_policy_update_failure();
		return 1;
	}

	publish_policy_snapshot(policy);
	return 0;
}

void destroy_rules(void)
{
	policy_snapshot_destroy(active_policy);
	active_policy = NULL;
	atomic_store_explicit(&active_rules_proc_status_mask, 0,
			      memory_order_release);
	atomic_store_explicit(&active_syslog_proc_status_mask, 0,
			      memory_order_release);

	if (stop) {
		free(working_buffer);
		working_buffer = NULL;
	}
}

unsigned int policy_get_syslog_proc_status_mask(void)
{
	return atomic_load_explicit(&active_syslog_proc_status_mask,
				    memory_order_acquire);
}

/*
 * policy_get_rules_proc_status_mask - return active rule proc-status mask
 * @void: no arguments are required.
 * Returns a bitmap of PROC_STAT_* fields required by the active rules.
 */
unsigned int policy_get_rules_proc_status_mask(void)
{
	return atomic_load_explicit(&active_rules_proc_status_mask,
				    memory_order_acquire);
}

/*
 * getReplyErrors - return fanotify response write error count.
 * Returns the number of fanotify response writes that failed or appeared
 * incomplete.
 */
unsigned long getReplyErrors(void)
{
	return failure_action_count(FAILURE_REASON_RESPONSE_WRITE_FAILURE);
}

void set_reload_rules(void)
{
	reload_rules = true;
}

/*
 * ff - pending reload rule file opened before taking the rule lock.
 * ff_identity - SHA256 identity for @ff, transferred to the new snapshot.
 *
 * load_rule_file() prepares these so do_reload_rules() can spend the locked
 * section parsing and publishing rather than opening and hashing policy files.
 */
static FILE * ff = NULL;
static char *ff_identity;
int load_rule_file(void)
{
	if (ff) {
		fclose(ff);
		ff = NULL;
	}
	free(ff_identity);
	ff_identity = NULL;

	ff = open_file(&ff_identity);
	if (ff == NULL)
		return 1;

	return 0;
}

int do_reload_rules(const conf_t *_config)
{
	struct policy_snapshot *policy = NULL;
	char *identity = ff_identity;

	ff_identity = NULL;
	if (!ff) {
		free(identity);
		msg(LOG_ERR, "Rule reload failed: no rule file is open");
		failure_action_record(FAILURE_REASON_RULE_RELOAD_FAILURE);
		log_policy_update_failure();
		return 1;
	}

	int rc = build_policy_snapshot(_config, ff, identity, &policy);

	fclose(ff);
	ff = NULL;
	if (rc) {
		failure_action_record(FAILURE_REASON_RULE_RELOAD_FAILURE);
		log_policy_update_failure();
		return 1;
	}

	publish_policy_snapshot(policy);
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
			char *tmp = NULL;
			size_t need_escape = check_escape_shell(str);

			if (need_escape) {
				// need_escape contains potential size of escaped string
				tmp = escape_shell(str, need_escape);
				str = tmp;
			}

			if (asprintf(&out, "%s", str ? str : "??") < 0)
				out = NULL;

			free(tmp);
		} else
		    if (asprintf(&out, "%d", obj ? (obj->val ? 1 : 0) : 9) < 0)
				out = NULL;
	} else {
		subject_attr_t *subj = get_subj_attr(e, item);
		if (item == PID || item == PPID) {
			if (asprintf(&out, "%d", subj ? subj->pid : 0) < 0)
				out = NULL;
		} else if (item < GID && item != UID) {
			if (asprintf(&out, "%u", subj ? subj->uval : 0) < 0)
				out = NULL;
		} else if (item >= COMM) {
			char * str = subj ? subj->str : "?";
			char *tmp = NULL;
			size_t need_escape = check_escape_shell(str);

			if (need_escape) {
				// need_escape contains potential size of escaped string
				tmp = escape_shell(str, need_escape);
				str = tmp;
			}

			if (asprintf(&out, "%s", str ? str : "??") < 0)
				out = NULL;
			free(tmp);

		} else { // UID/GID only log first 32
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
					if (ptr == out) {
						snprintf(buf, sizeof(buf),
							 "%llu",
						  (unsigned long long)grp->num);
					} else {
						snprintf(buf, sizeof(buf),
							 ",%llu",
						  (unsigned long long)grp->num);
					}
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
static void *fmemccpy(void* restrict dst, const void* restrict src, size_t n)
{
	if (n == 0)
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


static void log_it(const struct policy_snapshot *policy, unsigned int num,
		   decision_t results, event_t *e)
{
	struct decision_timing_span timing;
	int mode = results & SYSLOG ? LOG_INFO : LOG_DEBUG;
	unsigned int i;
	size_t dsize;
	ptrdiff_t written;
	char *p1, *p2, *val;

	decision_timing_stage_begin(
		DECISION_TIMING_STAGE_SYSLOG_DEBUG_FORMAT, &timing);
	if (working_buffer == NULL) {
		working_buffer = malloc(WB_SIZE);
		if (working_buffer == NULL) {
			msg(LOG_ERR, "No working buffer for logging");
			decision_timing_stage_end(&timing);
			return;
		}
	}

	dsize = WB_SIZE;
	p1 = p2 = working_buffer; // Dummy assignment for p1 to quiet warnings
	for (i = 0; i < policy->num_fields && dsize; i++)
	{
		if (dsize < WB_SIZE) {
			// This is skipped first pass, p1 is initialized below
			p2 = fmemccpy(p1, " ", dsize);
			written = p2 - p1;
			if ((size_t)written > dsize)
				break;
			dsize -= (size_t)written;
		}
		p1 = fmemccpy(p2, policy->fields[i].name, dsize);
		written = p1 - p2;
		if ((size_t)written > dsize)
			break;
		dsize -= (size_t)written;
		if (policy->fields[i].item != F_COLON) {
			p2 = fmemccpy(p1, "=", dsize);
			written = p2 - p1;
			if ((size_t)written > dsize)
				break;
			dsize -= (size_t)written;
			val = format_value(policy->fields[i].item, num,
					   results, e);
			p1 = fmemccpy(p2, val ? val : "?", dsize);
			written = p1 - p2;
			if ((size_t)written > dsize) {
				free(val);
				break;
			}
			dsize -= (size_t)written;
			free(val);
		}
	}
	working_buffer[WB_SIZE-1] = 0;	// Just in case
	msg(mode, "%s", working_buffer);
	decision_timing_stage_end(&timing);
}


/*
 * process_event_with_source - evaluate policy and report decision source
 * @e: event to evaluate.
 * @source: optional output receiving rule or fallthrough source.
 *
 * Returns the access decision. A no-opinion policy result remains compatible
 * with historical behavior by returning ALLOW and reporting fallthrough.
 */
decision_t process_event_with_source(event_t *e, decision_source_t *source,
		struct decision_timing_span *response_timing)
{
	decision_t results = NO_OPINION;
	struct policy_snapshot *policy = active_policy;
	decision_timing_driver_t previous_driver;
	struct decision_timing_span eval_timing;
	lnode *r;

	if (source)
		*source = DECISION_SOURCE_FALLTHROUGH;

	if (!policy) {
		if (response_timing)
			decision_timing_stage_begin(
				DECISION_TIMING_STAGE_RESPONSE_TOTAL,
				response_timing);
		return ALLOW;
	}

	/* Use a local cursor so concurrent readers do not share list state. */
	//int cnt = 0;
	previous_driver = decision_timing_driver_push(
		DECISION_TIMING_DRIVER_EVALUATION);
	decision_timing_stage_begin(DECISION_TIMING_STAGE_RULE_EVALUATION,
				    &eval_timing);
	for (r = rules_first_node(&policy->rules); r;
	     r = rules_next_node(r)) {
		//msg(LOG_INFO, "process_event: rule %d", cnt);
		results = rule_evaluate(r, e);
		// If a rule has an opinion, stop and use it
		if (results != NO_OPINION)
			break;
		//cnt++;
	}
	if (r)
		rules_record_hit(r);
	decision_timing_stage_end(&eval_timing);
	decision_timing_driver_pop(previous_driver);

	if (response_timing)
		decision_timing_stage_begin(DECISION_TIMING_STAGE_RESPONSE_TOTAL,
					    response_timing);

	// Output some information if debugging on or syslogging requested
	if ( (results & SYSLOG) || (debug_mode == 1) ||
	     (debug_mode > 1 && (results & DENY)) ) {
		previous_driver = decision_timing_driver_push(
			DECISION_TIMING_DRIVER_RESPONSE);
		log_it(policy, r ? r->num : 0xFFFFFFFF, results, e);
		decision_timing_driver_pop(previous_driver);
	}

	// Record which rule (rules are 1 based when listed by the cli tool)
	if (r) {
		e->num = r->num + 1;
		if (source)
			*source = DECISION_SOURCE_RULE;
	}

	// If we are not in permissive mode, return any decision
	if (results != NO_OPINION)
		return results;

	return ALLOW;
}

/*
 * process_event - evaluate policy using the compatibility decision API
 * @e: event to evaluate.
 * Returns the access decision without exposing source metadata.
 */
decision_t process_event(event_t *e)
{
	return process_event_with_source(e, NULL, NULL);
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
	struct decision_timing_span prep_timing;
	struct decision_timing_span write_timing;

#ifdef FAN_AUDIT_RULE_NUM
	static int use_new = 2;
	if (use_new == 2)
		use_new = test_info_api(fd);
	if (reply & FAN_AUDIT && use_new) {
		struct fan_audit_response f;
		subject_attr_t *sn;
		object_attr_t *obj;

		decision_timing_stage_begin(
			DECISION_TIMING_STAGE_AUDIT_RESPONSE_PREP,
			&prep_timing);
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
		if (e && (sn = subject_access(e->s, SUBJ_TRUST)))
			f.a.subj_trust = sn->uval;
		else
			f.a.subj_trust = 2;
		// All objects have a trust value
		if (e && (obj = get_obj_attr(e, OBJ_TRUST))) {
			f.a.obj_trust = obj->val;
		} else
			f.a.obj_trust = 2;
		decision_timing_stage_end(&prep_timing);
		errno = 0;
		decision_timing_stage_begin(
			DECISION_TIMING_STAGE_FANOTIFY_RESPONSE_WRITE,
			&write_timing);
		if (write(fd, &f, sizeof(struct fan_audit_response)) <
				(ssize_t)sizeof(struct fanotify_response) ||
				errno)
			failure_action_record(
			    FAILURE_REASON_RESPONSE_WRITE_FAILURE);
		decision_timing_stage_end(&write_timing);
		goto out;
	}
#endif
	struct fanotify_response response;

	decision_timing_stage_begin(
		DECISION_TIMING_STAGE_AUDIT_RESPONSE_PREP, &prep_timing);
	response.fd = metadata->fd;
	response.response = reply;
	decision_timing_stage_end(&prep_timing);
	errno = 0;
	decision_timing_stage_begin(
		DECISION_TIMING_STAGE_FANOTIFY_RESPONSE_WRITE,
		&write_timing);
	if (write(fd, &response, sizeof(struct fanotify_response)) <
			(ssize_t)sizeof(struct fanotify_response) || errno)
		failure_action_record(
		    FAILURE_REASON_RESPONSE_WRITE_FAILURE);
	decision_timing_stage_end(&write_timing);
out:
	// Close this last so that no other thread can open a file which
	// reclaims this fd number before we render a decision.
	close(metadata->fd);
}

/*
 * log_event_build_deny - explain a deny before rule evaluation exists.
 * @decision_event: event envelope that failed construction.
 *
 * The normal debug-deny path logs from process_event_with_source(), but event
 * construction failures deny before there is an event_t or rule context to
 * format. Emit a minimal diagnostic so denied counters are visible during
 * --debug-deny runs.
 */
static void log_event_build_deny(const decision_event_t *decision_event)
{
	const struct fanotify_event_metadata *metadata;

	if (debug_mode <= 1 || decision_event == NULL)
		return;

	metadata = &decision_event->metadata;
	msg(LOG_DEBUG,
	    "dec=deny reason=event-build pid=%d fd=%d mask=0x%llx "
	    "subject_slot=%u",
	    metadata->pid, metadata->fd, (unsigned long long)metadata->mask,
	    decision_event->subject_slot);
}

/*
 * make_policy_decision - build an event, evaluate policy, and reply.
 * @decision_event: internal event envelope owning the fanotify metadata fd.
 * @fd: fanotify listener fd used for permission responses.
 * @mask: permission-event mask that requires a fanotify reply.
 *
 * completed_subject_slot is set when processing leaves the event's subject
 * slot empty or at STATE_FULL or later, allowing the decision thread to
 * release deferred events for that slot.
 */
void make_policy_decision(decision_event_t *decision_event, int fd,
		uint64_t mask)
{
	const struct fanotify_event_metadata *metadata =
		&decision_event->metadata;
	event_t e = { 0 };
	int decision;
	event_t *metric_event = NULL;
	decision_source_t source = DECISION_SOURCE_FALLTHROUGH;
	struct decision_timing_span event_timing;
	struct decision_timing_span rule_wait_timing;
	struct decision_timing_span response_timing = { 0 };
	decision_timing_driver_t previous_driver;

	decision_timing_stage_begin(DECISION_TIMING_STAGE_EVENT_BUILD,
				    &event_timing);
	if (decision_event->subject_slot == DECISION_EVENT_NO_SLOT)
		decision_event->subject_slot = event_subject_slot(metadata->pid);
	decision_event->completed_subject_slot = DECISION_EVENT_NO_SLOT;
	if (new_event(metadata, &e)) {
		decision = FAN_DENY;
		log_event_build_deny(decision_event);
	} else {
		decision_timing_stage_end(&event_timing);
		metric_event = &e;
		decision_timing_stage_begin(
			DECISION_TIMING_STAGE_RULE_LOCK_WAIT,
			&rule_wait_timing);
		lock_rule();
		decision_timing_stage_end(&rule_wait_timing);
		decision = process_event_with_source(&e, &source,
						     &response_timing);
		unlock_rule();
	}
	if (metric_event == NULL)
		decision_timing_stage_end(&event_timing);

	previous_driver = decision_timing_driver_push(
		DECISION_TIMING_DRIVER_RESPONSE);
	policy_metrics_record_decision(decision, metric_event, source);
	decision_timing_driver_pop(previous_driver);

	if (metadata->mask & mask) {
		previous_driver = decision_timing_driver_push(
			DECISION_TIMING_DRIVER_RESPONSE);
		// if in debug mode, do not allow audit events
		if (debug_mode)
			decision &= ~AUDIT;

		// If permissive, always allow and honor the audit bit
		// if not in debug mode
		if (__atomic_load_n(&config.permissive, __ATOMIC_RELAXED))
			reply_event(fd, metadata, FAN_ALLOW | (decision & AUDIT),
					metric_event);
		else
			reply_event(fd, metadata, decision & FAN_RESPONSE_MASK,
					metric_event);
		decision_timing_driver_pop(previous_driver);
	}
	decision_timing_stage_end(&response_timing);

	if (decision_event->subject_slot != DECISION_EVENT_NO_SLOT &&
	    event_subject_slot_is_unblocked(decision_event->subject_slot))
		decision_event->completed_subject_slot =
			decision_event->subject_slot;
}


void policy_no_audit(void)
{
	if (active_policy)
		rules_unsupport_audit(&active_policy->rules);
}

/*
 * policy_rule_hits_report - write per-rule hit counters for the active policy.
 * @f: output stream.
 *
 * The rule mutex protects the active snapshot from reload destruction while
 * the report walks rule nodes and source text.
 */
void policy_rule_hits_report(FILE *f)
{
	struct policy_snapshot *policy;

	if (f == NULL || active_policy == NULL)
		return;

	lock_rule();
	policy = active_policy;
	if (policy)
		rules_hits_report(f, &policy->rules);
	unlock_rule();
}
