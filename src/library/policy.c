/*
 * policy.c - functions that encapsulate the notion of a policy
 * Copyright (c) 2016-26 Red Hat Inc.
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
#include <pthread.h>
#include <time.h>

#include "database.h"
#include "decision-config.h"
#include "decision-context.h"
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
#define WB_SIZE 512
#define VALIDATION_SYSLOG_FORMAT "rule,dec,perm,auid,pid,exe,:,path,ftype"

/*
 * policy_snapshot - coherent policy generation used for decisions
 *
 * The rule list owns parsed rule nodes and attribute sets. The same snapshot
 * also owns syslog fields, proc-status masks, the rule count, and the hashed
 * rule-file identity so all parser side effects publish as one unit.
 */
struct policy_snapshot {
	atomic_uint refs;
	llist rules;
	nvlist_t fields[MAX_SYSLOG_FIELDS];
	unsigned int num_fields;
	unsigned int rules_proc_status_mask;
	unsigned int syslog_proc_status_mask;
	unsigned int rule_count;
	unsigned int generation;
	time_t effective_since;
	char *rule_file_identity;
};

struct policy_log_record {
	const struct policy_snapshot *policy;
	unsigned int rule_num;
	decision_t results;
	char message[WB_SIZE];
	int priority;
	bool enabled;
};

/*
 * active_policy - currently published policy generation
 *
 * policy_snapshot_lock serializes active pointer replacement with readers
 * taking a reference. Evaluation uses a pinned snapshot reference so reload can
 * publish a new policy without waiting for old decisions to finish.
 */
static _Atomic(struct policy_snapshot *) active_policy;
static pthread_mutex_t policy_snapshot_lock = PTHREAD_MUTEX_INITIALIZER;
static atomic_uint next_policy_generation;
static __thread struct policy_snapshot *pinned_policy_snapshot;
static __thread int policy_snapshot_is_pinned;

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
 * policy_snapshot_free - release one unreferenced policy snapshot
 * @policy: snapshot to free, or NULL.
 * Returns nothing.
 */
static void policy_snapshot_free(struct policy_snapshot *policy)
{
	if (!policy)
		return;

	rules_clear(&policy->rules);
	free_syslog_fields(policy);
	free(policy->rule_file_identity);
	free(policy);
}

/*
 * policy_snapshot_get - take a read reference on a policy snapshot
 * @policy: snapshot to reference, or NULL.
 * Returns nothing.
 */
static void policy_snapshot_get(struct policy_snapshot *policy)
{
	if (policy)
		atomic_fetch_add_explicit(&policy->refs, 1,
					  memory_order_relaxed);
}

/*
 * policy_snapshot_put - release a policy snapshot read reference
 * @policy: snapshot reference to release, or NULL.
 * Returns nothing.
 */
static void policy_snapshot_put(struct policy_snapshot *policy)
{
	if (!policy)
		return;

	if (atomic_fetch_sub_explicit(&policy->refs, 1,
				      memory_order_acq_rel) == 1)
		policy_snapshot_free(policy);
}

/*
 * policy_snapshot_pin_active - pin the current active policy
 * @void: no arguments are required.
 *
 * The lock keeps a publisher from dropping the active reference between the
 * pointer load and the reader's reference increment.
 *
 * Returns the pinned policy snapshot, or NULL if no policy is active.
 */
static struct policy_snapshot *policy_snapshot_pin_active(void)
{
	struct policy_snapshot *policy;

	pthread_mutex_lock(&policy_snapshot_lock);
	/*
	 * The active pointer owns one reference. Readers must increment that
	 * count while publication is blocked, otherwise a reload could exchange
	 * the pointer and drop the last reference before this reader is pinned.
	 */
	policy = atomic_load_explicit(&active_policy, memory_order_acquire);
	policy_snapshot_get(policy);
	pthread_mutex_unlock(&policy_snapshot_lock);
	return policy;
}

/*
 * policy_snapshot_begin_read - get the policy for this read path
 * @release: set to nonzero when the caller must release @policy.
 *
 * Permission-event threads pin one policy through event construction and rule
 * evaluation. Other callers take a short-lived reference here.
 *
 * Returns the snapshot to use, or NULL if no policy is active.
 */
static struct policy_snapshot *policy_snapshot_begin_read(int *release)
{
	if (release)
		*release = 0;
	/*
	 * A permission event pins one policy at make_policy_decision() entry.
	 * Reuse it so /proc status collection, rule evaluation, and log
	 * formatting cannot accidentally observe different reload generations.
	 */
	if (policy_snapshot_is_pinned)
		return pinned_policy_snapshot;

	if (release)
		*release = 1;
	return policy_snapshot_pin_active();
}

/*
 * policy_snapshot_end_read - release a read snapshot when needed
 * @policy: snapshot returned by policy_snapshot_begin_read().
 * @release: nonzero when @policy has a private read reference.
 * Returns nothing.
 */
static void policy_snapshot_end_read(struct policy_snapshot *policy,
				     int release)
{
	if (release)
		policy_snapshot_put(policy);
}

/*
 * policy_snapshot_pin_current - pin active policy for this thread
 * @void: no arguments are required.
 *
 * Event construction and rule evaluation must use one generation so proc-status
 * collection, rules, attr sets, and syslog fields match.
 *
 * Returns the pinned policy snapshot, or NULL if no policy is active.
 */
static struct policy_snapshot *policy_snapshot_pin_current(void)
{
	struct policy_snapshot *policy = policy_snapshot_pin_active();

	pinned_policy_snapshot = policy;
	policy_snapshot_is_pinned = 1;
	return policy;
}

/*
 * policy_snapshot_unpin_current - unpin a thread policy generation
 * @policy: snapshot returned by policy_snapshot_pin_current().
 * Returns nothing.
 */
static void policy_snapshot_unpin_current(struct policy_snapshot *policy)
{
	if (policy_snapshot_is_pinned && pinned_policy_snapshot == policy) {
		pinned_policy_snapshot = NULL;
		policy_snapshot_is_pinned = 0;
	}
	policy_snapshot_put(policy);
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
	atomic_init(&policy->refs, 1);

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
	struct policy_snapshot *policy;

	policy = atomic_load_explicit(&active_policy, memory_order_acquire);
	if (policy)
		msg(LOG_ERR, "Daemon configuration update failed; "
		    "previous policy preserved");
	else
		msg(LOG_ERR, "Daemon configuration update failed; "
		    "no policy installed");
}

/*
 * copy_syslog_format - copy syslog format for one policy build
 * @_config: daemon configuration containing syslog_format.
 * @out: receives a copied syslog_format string, or NULL when absent.
 *
 * The daemon updates config.syslog_format under the legacy rule mutex during
 * SIGHUP reconfiguration. Snapshot builds only need the mutex long enough to
 * copy the string; holding it while parsing policy would block decisions.
 *
 * Returns 0 on success or 1 on allocation failure.
 */
static int copy_syslog_format(const conf_t *_config, char **out)
{
	int had_format = 0;

	*out = NULL;
	lock_rule();
	if (_config && _config->syslog_format) {
		had_format = 1;
		*out = strdup(_config->syslog_format);
	}
	unlock_rule();

	if (had_format && *out == NULL) {
		msg(LOG_ERR, "No memory for syslog_format");
		return 1;
	}

	return 0;
}

/*
 * publish_policy_snapshot - install a fully validated policy snapshot
 * @policy: candidate snapshot built by build_policy_snapshot().
 * Returns nothing.
 */
static void publish_policy_snapshot(struct policy_snapshot *policy)
{
	struct policy_snapshot *old;
	time_t now;

	policy->rule_count = policy->rules.cnt;
	policy->rules_proc_status_mask =
		rules_get_proc_status_mask(&policy->rules);

	/*
	 * Transaction point: after this exchange, new decisions use the
	 * candidate policy. Everything before this must be able to fail while
	 * leaving the old active_policy untouched.
	 *
	 * The candidate arrives with one reference, which becomes the active
	 * pointer's reference. Readers that already pinned the old generation
	 * continue using it until they drop their references below.
	 */
	pthread_mutex_lock(&policy_snapshot_lock);
	now = time(NULL);
	policy->effective_since = now == (time_t)-1 ? 0 : now;
	policy->generation = atomic_fetch_add_explicit(
		&next_policy_generation, 1, memory_order_relaxed) + 1;
	old = atomic_exchange_explicit(&active_policy, policy,
				       memory_order_acq_rel);
	policy_metrics_record_ruleset_update(policy->generation,
					     policy->effective_since);
	pthread_mutex_unlock(&policy_snapshot_lock);

	if (policy->rule_file_identity)
		msg(LOG_INFO, "Ruleset identity: %s",
		    policy->rule_file_identity);
	msg(LOG_INFO, "Daemon rules updated");

	/*
	 * Drop the old active reference after publishing. If a reader still has
	 * the old snapshot pinned, this only decrements the count; final
	 * reclamation happens when the last reader calls policy_snapshot_put().
	 */
	policy_snapshot_put(old);
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
	char *syslog_format = NULL;
	size_t len = 0;
	struct policy_snapshot *policy = policy_snapshot_create(identity);

	*out = NULL;
	if (!policy)
		return 1;

	if (copy_syslog_format(_config, &syslog_format)) {
		policy_snapshot_put(policy);
		return 1;
	}

	msg(LOG_DEBUG, "Loading rule file:");

	while (getline(&line, &len, f) != -1) {
		char *ptr = strchr(line, 0x0a);
		if (ptr)
			*ptr = 0;
		msg(LOG_DEBUG, "%s", line);
		rc = rules_append(&policy->rules, line, lineno);
		if (rc) {
			free(line);
			free(syslog_format);
			policy_snapshot_put(policy);
			return 1;
		}
		lineno++;
	}
	free(line);

	if (ferror(f)) {
		msg(LOG_ERR, "Error reading rules file (%s)",
		    strerror(errno));
		free(syslog_format);
		policy_snapshot_put(policy);
		return 1;
	}

	if (policy->rules.cnt == 0) {
		msg(LOG_INFO, "No rules in file - exiting");
		free(syslog_format);
		policy_snapshot_put(policy);
		return 1;
	} else {
		msg(LOG_DEBUG, "Loaded %u rules", policy->rules.cnt);
	}

	rc = parse_syslog_format(policy, syslog_format);
	free(syslog_format);
	if (!rc || policy->num_fields == 0) {
		policy_snapshot_put(policy);
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

/*
 * validate_rules_from_stream - parse policy without publishing it.
 * @f: rule stream positioned at the beginning.
 *
 * Returns 0 when the daemon parser accepts the candidate policy, 1 otherwise.
 */
int validate_rules_from_stream(FILE *f)
{
	conf_t validation_config = {
		.syslog_format = VALIDATION_SYSLOG_FORMAT
	};
	struct policy_snapshot *policy = NULL;

	if (!f)
		return 1;

	/*
	 * Rule validation only needs a valid syslog_format so the daemon policy
	 * snapshot parser can run without depending on /etc/fapolicyd.conf.
	 */
	if (build_policy_snapshot(&validation_config, f, NULL, &policy))
		return 1;

	policy_snapshot_put(policy);
	return 0;
}

void destroy_rules(void)
{
	struct decision_context *ctx = decision_context_current();
	struct policy_snapshot *policy, *pinned;

	pthread_mutex_lock(&policy_snapshot_lock);
	policy = atomic_exchange_explicit(&active_policy, NULL,
					  memory_order_acq_rel);
	atomic_store_explicit(&next_policy_generation, 0,
			      memory_order_relaxed);
	pthread_mutex_unlock(&policy_snapshot_lock);

	pinned = pinned_policy_snapshot;
	pinned_policy_snapshot = NULL;
	policy_snapshot_is_pinned = 0;
	policy_snapshot_put(pinned);
	policy_snapshot_put(policy);


	if (stop) {
		free(ctx->working_buffer);
		ctx->working_buffer = NULL;
	}
}

unsigned int policy_get_syslog_proc_status_mask(void)
{
	struct policy_snapshot *policy;
	unsigned int mask = 0;
	int release;

	/*
	 * Separate mask getters are kept for existing callers. Code that needs
	 * both rule and syslog masks should use policy_get_proc_status_mask()
	 * so both values definitely come from one pinned generation.
	 */
	policy = policy_snapshot_begin_read(&release);
	if (policy)
		mask = policy->syslog_proc_status_mask;
	policy_snapshot_end_read(policy, release);
	return mask;
}

/*
 * policy_get_rules_proc_status_mask - return active rule proc-status mask
 * @void: no arguments are required.
 * Returns a bitmap of PROC_STAT_* fields required by the active rules.
 */
unsigned int policy_get_rules_proc_status_mask(void)
{
	struct policy_snapshot *policy;
	unsigned int mask = 0;
	int release;

	/*
	 * This returns one field from the currently pinned generation when the
	 * caller is inside a decision, otherwise from a short-lived active
	 * snapshot reference.
	 */
	policy = policy_snapshot_begin_read(&release);
	if (policy)
		mask = policy->rules_proc_status_mask;
	policy_snapshot_end_read(policy, release);
	return mask;
}

/*
 * policy_get_proc_status_mask - return all active policy proc-status needs
 * @void: no arguments are required.
 * Returns the combined rule and syslog proc-status mask for one generation.
 */
unsigned int policy_get_proc_status_mask(void)
{
	struct policy_snapshot *policy;
	unsigned int mask = 0;
	int release;

	policy = policy_snapshot_begin_read(&release);
	if (policy) {
		/*
		 * Read both masks from the same snapshot. Splitting this into
		 * independent globals lets reload mix old rule requirements
		 * with new syslog fields, which is exactly what snapshots avoid.
		 */
		mask = policy->rules_proc_status_mask;
		mask |= policy->syslog_proc_status_mask;
	}
	policy_snapshot_end_read(policy, release);
	return mask;
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
 * ff - pending reload rule file opened before parsing starts.
 * ff_identity - SHA256 identity for @ff, transferred to the new snapshot.
 *
 * load_rule_file() prepares these so do_reload_rules() can spend its time
 * parsing and publishing rather than opening and hashing policy files.
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
			if (out == NULL)
				return NULL;

			/*
			 * A process can exit while a non-permission event is being
			 * reported.  Failed procfs lookups and incomplete status data
			 * must not turn logging into a NULL dereference or an
			 * uninitialized string read.
			 */
			if (subj == NULL || subj->set == NULL ||
			    attr_set_empty(subj->set)) {
				strcpy(out, "?");
			} else {
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
				if (ptr == out)
					strcpy(out, "?");
			}
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


/*
 * policy_log_record_format - fully render one decision log record.
 * @e: event whose attributes must be materialized before a permission reply.
 * @record: owned destination retained until post-reply emission.
 *
 * Returns nothing.  The formatted text is copied out of the worker buffer so
 * the post-reply emitter cannot make lazy process or file lookups.
 */
static void policy_log_record_format(struct policy_log_record *record,
		event_t *e)
{
	struct decision_context *ctx = decision_context_current();
	struct decision_timing_span timing;
	int mode;
	unsigned int i;
	size_t dsize;
	ptrdiff_t written;
	char *p1, *p2, *val;

	if (record == NULL)
		return;

	record->enabled = false;
	if (record->policy == NULL)
		return;
	mode = record->results & SYSLOG ? LOG_INFO : LOG_DEBUG;

	decision_timing_stage_begin(
		DECISION_TIMING_STAGE_SYSLOG_DEBUG_FORMAT, &timing);
	if (ctx->working_buffer == NULL) {
		ctx->working_buffer = malloc(WB_SIZE);
		if (ctx->working_buffer == NULL) {
			strcpy(record->message, "No working buffer for logging");
			record->policy = NULL;
			record->priority = LOG_ERR;
			record->enabled = true;
			decision_timing_stage_end(&timing);
			return;
		}
	}

	ctx->working_buffer[0] = '\0';
	dsize = WB_SIZE;
	p1 = p2 = ctx->working_buffer; // Dummy assignment for p1 to quiet warnings
	for (i = 0; i < record->policy->num_fields && dsize; i++)
	{
		if (dsize < WB_SIZE) {
			// This is skipped first pass, p1 is initialized below
			p2 = fmemccpy(p1, " ", dsize);
			written = p2 - p1;
			if ((size_t)written > dsize)
				break;
			dsize -= (size_t)written;
		}
		p1 = fmemccpy(p2, record->policy->fields[i].name, dsize);
		written = p1 - p2;
		if ((size_t)written > dsize)
			break;
		dsize -= (size_t)written;
		if (record->policy->fields[i].item != F_COLON) {
			p2 = fmemccpy(p1, "=", dsize);
			written = p2 - p1;
			if ((size_t)written > dsize)
				break;
			dsize -= (size_t)written;
			val = format_value(record->policy->fields[i].item,
					   record->rule_num, record->results, e);
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
	ctx->working_buffer[WB_SIZE-1] = 0;	// Just in case
	strcpy(record->message, ctx->working_buffer);
	record->policy = NULL;
	record->priority = mode;
	record->enabled = true;
	decision_timing_stage_end(&timing);
}

/*
 * policy_log_record_emit - emit a pre-rendered decision log record.
 * @record: fully formatted log text captured during policy evaluation.
 *
 * Returns nothing. This only queues or writes the finished text; it never
 * consults the event after the fanotify response is sent.
 */
static void policy_log_record_emit(const struct policy_log_record *record)
{
	decision_timing_driver_t previous_driver;

	if (record == NULL || !record->enabled)
		return;

	previous_driver = decision_timing_driver_push(
		DECISION_TIMING_DRIVER_RESPONSE);
	msg(record->priority, "%s", record->message);
	decision_timing_driver_pop(previous_driver);
}

/*
 * process_event_evaluate - evaluate policy and optionally delay logging
 * @e: event to evaluate.
 * @source: optional output receiving rule or fallthrough source.
 * @response_timing: optional response timing span started after evaluation.
 * @log_record: optional destination for a delayed log record.
 *
 * Returns the access decision. When @log_record is supplied and the caller is
 * using a pinned policy snapshot, decision logging is captured for later
 * emission. Otherwise logging happens before a temporary policy reference is
 * released.
 */
static decision_t process_event_evaluate(event_t *e,
		decision_source_t *source,
		struct decision_timing_span *response_timing,
		struct policy_log_record *log_record)
{
	decision_t results = NO_OPINION;
	decision_t decision;
	struct policy_snapshot *policy;
	decision_timing_driver_t previous_driver;
	struct decision_timing_span eval_timing;
	struct policy_log_record immediate_log;
	struct policy_log_record *record;
	lnode *r;
	int release_policy;

	if (log_record)
		memset(log_record, 0, sizeof(*log_record));
	if (source)
		*source = DECISION_SOURCE_FALLTHROUGH;

	policy = policy_snapshot_begin_read(&release_policy);
	if (!policy) {
		if (response_timing)
			decision_timing_stage_begin(
				DECISION_TIMING_STAGE_RESPONSE_TOTAL,
				response_timing);
		return ALLOW;
	}

	/*
	 * The snapshot reference keeps rules, attr sets, and syslog fields
	 * alive for this whole evaluation. The list cursor is local so
	 * concurrent readers can walk the same immutable rule list safely.
	 */
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
		/*
		 * FIXME: Pre-reply log formatting, and object trust added to
		 * FAN_AUDIT in reply_event_write(), can lazily hash files or
		 * invoke libmagic. Investigate cached audit values and
		 * splitting live subject capture from post-reply object work.
		 */
		if (log_record) {
			/*
			 * Permission events keep the process pinned until the caller
			 * writes a verdict.  Resolve every syslog field now, then let
			 * the caller defer only the potentially blocking log delivery.
			 */
			record = log_record;
		} else {
			memset(&immediate_log, 0, sizeof(immediate_log));
			record = &immediate_log;
		}
		previous_driver = decision_timing_driver_push(
			DECISION_TIMING_DRIVER_RESPONSE);
		record->policy = policy;
		record->rule_num = r ? r->num : 0xFFFFFFFF;
		record->results = results;
		policy_log_record_format(record, e);
		decision_timing_driver_pop(previous_driver);
		if (!log_record)
			policy_log_record_emit(record);
	}

	// Record which rule (rules are 1 based when listed by the cli tool)
	if (r) {
		e->num = r->num + 1;
		if (source)
			*source = DECISION_SOURCE_RULE;
	}

	// If we are not in permissive mode, return any decision
	if (results != NO_OPINION)
		decision = results;
	else
		decision = ALLOW;

	/*
	 * All callers format logs before releasing the policy snapshot because the
	 * formatter reads its syslog field array. Permission callers retain only
	 * the owned text for emission after the fanotify response is written.
	 */
	policy_snapshot_end_read(policy, release_policy);
	return decision;
}

/*
 * process_event_with_source - evaluate policy and report decision source
 * @e: event to evaluate.
 * @source: optional output receiving rule or fallthrough source.
 * @response_timing: optional response timing span started after evaluation.
 *
 * Returns the access decision. A no-opinion policy result remains compatible
 * with historical behavior by returning ALLOW and reporting fallthrough.
 */
decision_t process_event_with_source(event_t *e, decision_source_t *source,
		struct decision_timing_span *response_timing)
{
	return process_event_evaluate(e, source, response_timing, NULL);
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
static int response_info_supported = 0;

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

/*
 * The daemon has one fanotify permission group. Keep its original descriptor
 * number after shutdown so workers holding that number can recognize a retired
 * group instead of writing to an unrelated file that reused the descriptor.
 */
static pthread_rwlock_t response_fd_lock = PTHREAD_RWLOCK_INITIALIZER;
static int managed_response_fd = -1;
static bool managed_response_closed = true;

/*
 * reply_event_init - pre-probe extended fanotify response support.
 * @fd: fanotify listener fd used for permission responses.
 * Returns 0 on success or 1 when initialization cannot be attempted.
 */
int reply_event_init(int fd)
{
#ifdef FAN_AUDIT_RULE_NUM
	if (fd < 0) {
		errno = EBADF;
		msg(LOG_ERR,
		    "Cannot initialize fanotify response info support: "
		    "bad fd (%s)", strerror(errno));
		response_info_supported = 0;
		return 1;
	}

	response_info_supported = test_info_api(fd);
#endif
	pthread_rwlock_wrlock(&response_fd_lock);
	managed_response_fd = fd;
	managed_response_closed = false;
	pthread_rwlock_unlock(&response_fd_lock);
	return 0;
}

/*
 * reply_event_close_group - retire and close the permission fanotify group.
 * @group_fd: atomic descriptor owned by notify.c.
 *
 * Normal shutdown closes the group before joining threads because a worker
 * can be blocked in a watched open that only group closure can release after
 * the main reader exits. Serialize that close with response writes and retain
 * the original descriptor number so late worker cleanup cannot write to a
 * reused descriptor. This function is not async-signal-safe.
 *
 * Returns nothing.
 */
void reply_event_close_group(atomic_int *group_fd)
{
	int fd;

	if (group_fd == NULL)
		return;

	pthread_rwlock_wrlock(&response_fd_lock);
	managed_response_closed = true;
	fd = atomic_exchange_explicit(group_fd, -1, memory_order_relaxed);
	if (fd >= 0)
		(void)close(fd);
	pthread_rwlock_unlock(&response_fd_lock);
}

/*
 * reply_event_write - write a fanotify response without closing event fd.
 * @fd: fanotify listener fd used for permission responses.
 * @metadata: permission event metadata to answer.
 * @reply: FAN_ALLOW/FAN_DENY response bits.
 * @e: optional event used for audit response details.
 *
 * Returns nothing. The caller keeps ownership of metadata->fd and closes it
 * after writing the response; permission-event log fields are pre-rendered.
 */
static void reply_event_write(int fd,
		const struct fanotify_event_metadata *metadata,
		unsigned reply, event_t *e)
{
	struct decision_timing_span prep_timing;
	struct decision_timing_span write_timing;

#ifdef FAN_AUDIT_RULE_NUM
	/*
	 * FIXME: Persist FAN_ENABLE_AUDIT support across policy reloads, mask
	 * FAN_AUDIT when unavailable, and investigate safely retrying a failed
	 * FAN_INFO response as a plain response so permission events are
	 * answered.
	 */
	if (reply & FAN_AUDIT && response_info_supported) {
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
		// FAN_INFO replies include the audit record after the base response.
		if (write(fd, &f, sizeof(f)) < (ssize_t)sizeof(f) || errno)
			failure_action_record(
			    FAILURE_REASON_RESPONSE_WRITE_FAILURE);
		decision_timing_stage_end(&write_timing);
		return;
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
}

void reply_event(int fd, const struct fanotify_event_metadata *metadata,
		unsigned reply, event_t *e)
{
	int managed = managed_response_fd >= 0 && fd == managed_response_fd;

	if (managed)
		pthread_rwlock_rdlock(&response_fd_lock);
	if (!managed || !managed_response_closed)
		reply_event_write(fd, metadata, reply, e);
	if (managed)
		pthread_rwlock_unlock(&response_fd_lock);
	if (metadata->fd >= 0)
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
	const struct decision_config *decision_config = decision_config_pin();
	struct policy_snapshot *policy_snapshot;
	const struct fanotify_event_metadata *metadata =
		&decision_event->metadata;
	event_t e = { 0 };
	int decision;
	event_t *metric_event = NULL;
	decision_source_t source = DECISION_SOURCE_FALLTHROUGH;
	struct decision_timing_span event_timing;
	struct decision_timing_span response_timing = { 0 };
	decision_timing_driver_t previous_driver;
	struct policy_log_record log_record = { 0 };
	bool log_build_deny = false;
	bool event_fd_closed = false;

	/*
	 * Pin before new_event(): building subject attributes may call
	 * policy_get_proc_status_mask(). That mask must describe the same
	 * generation that rule evaluation and syslog formatting will use.
	 */
	policy_snapshot = policy_snapshot_pin_current();
	decision_timing_stage_begin(DECISION_TIMING_STAGE_EVENT_BUILD,
				    &event_timing);
	if (decision_event->subject_slot == DECISION_EVENT_NO_SLOT)
		decision_event->subject_slot = event_subject_slot(metadata->pid);
	decision_event->completed_subject_slot = DECISION_EVENT_NO_SLOT;
	if (new_event(metadata, &e)) {
		decision = FAN_DENY;
		log_build_deny = true;
	} else {
		decision_timing_stage_end(&event_timing);
		metric_event = &e;
		/*
		 * No rule mutex is needed here. policy_snapshot_pin_current()
		 * keeps the selected immutable generation alive while reload can
		 * parse and publish a replacement without blocking decisions.
		 */
		decision = process_event_evaluate(&e, &source,
						  &response_timing,
						  &log_record);
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
		if (decision_config_permissive(decision_config))
			reply_event_write(fd, metadata,
					  FAN_ALLOW | (decision & AUDIT),
					  metric_event);
		else
			reply_event_write(fd, metadata,
					  decision & FAN_RESPONSE_MASK,
					  metric_event);
		decision_timing_driver_pop(previous_driver);
		/* Log fields were materialized before the reply, so release it now. */
		if (metadata->fd >= 0) {
			close(metadata->fd);
			event_fd_closed = true;
		}
	}
	/*
	 * process_event_evaluate() rendered the complete decision log while this
	 * permission event still pinned the subject. Emit only that owned text
	 * after the verdict so journald, rsyslog, or another logging component
	 * cannot delay the fanotify response.
	 */
	if (log_build_deny)
		log_event_build_deny(decision_event);
	else
		policy_log_record_emit(&log_record);
	if (!event_fd_closed && metadata->fd >= 0)
		close(metadata->fd);
	decision_timing_stage_end(&response_timing);

	if (decision_event->subject_slot != DECISION_EVENT_NO_SLOT &&
	    event_subject_slot_is_unblocked(decision_event->subject_slot))
		decision_event->completed_subject_slot =
			decision_event->subject_slot;
	policy_snapshot_unpin_current(policy_snapshot);
	decision_config_unpin(decision_config);
}


void policy_no_audit(void)
{
	struct policy_snapshot *policy;

	/*
	 * This runs during fanotify initialization, before decision workers are
	 * active. Hold the publication lock anyway so the active pointer cannot
	 * change while the one permitted in-place rule adjustment is made.
	 */
	pthread_mutex_lock(&policy_snapshot_lock);
	policy = atomic_load_explicit(&active_policy, memory_order_acquire);
	if (policy)
		rules_unsupport_audit(&policy->rules);
	pthread_mutex_unlock(&policy_snapshot_lock);
}

/*
 * policy_rule_hits_report - write per-rule hit counters for the active policy.
 * @f: output stream.
 *
 * A snapshot reference protects the active rules while the report walks rule
 * nodes and source text.
 */
void policy_rule_hits_report(FILE *f)
{
	policy_rule_hits_report_reset(f, 0);
}

/*
 * policy_rule_hits_report_reset - write per-rule hit counters.
 * @f: output stream.
 * @reset: non-zero resets counters after copying them.
 *
 * Rule hit counters naturally start fresh when a new ruleset generation is
 * published. Manual metric resets also clear them so operators can run a
 * focused test against the currently loaded rules without reloading policy.
 */
void policy_rule_hits_report_reset(FILE *f, int reset)
{
	struct policy_snapshot *policy;
	int release_policy;

	if (f == NULL)
		return;

	/*
	 * Reports are not permission events, so they take their own short
	 * snapshot reference. A concurrent reload may publish a new generation,
	 * but this report keeps walking the generation it started with.
	 */
	policy = policy_snapshot_begin_read(&release_policy);
	if (policy)
		rules_hits_report_reset(f, &policy->rules, reset);
	policy_snapshot_end_read(policy, release_policy);
}
