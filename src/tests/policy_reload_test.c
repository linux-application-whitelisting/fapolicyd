/*
 * policy_reload_test.c - verify failed rule reloads are transactional
 *
 * The test loads an initial policy, then attempts reloads that fail before
 * syslog parsing and during syslog parsing. In both cases, the previously
 * published policy and its syslog field list must remain active.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <error.h>
#include <stdatomic.h>

#include "conf.h"
#include "attr-lookup-metrics.h"
#include "policy.h"
#include "policy-metrics.h"
#include "subject.h"
#include "object.h"
#include "event.h"
#include "message.h"

#define LOGBUF 4096
#define OLD_SYSLOG_FORMAT "rule,dec,perm,auid,:,path"
#define PID_SYSLOG_FORMAT "rule,dec,perm,pid,:,path"

extern atomic_bool stop;

/*
 * load_text_policy - load a policy from an in-memory rule string
 * @cfg: configuration providing syslog_format.
 * @rules: newline-terminated policy text.
 * Returns 0 on success, 1 on load failure.
 */
static int load_text_policy(const conf_t *cfg, const char *rules)
{
	FILE *f;
	int rc;

	f = fmemopen((void *)rules, strlen(rules), "r");
	if (!f)
		error(1, errno, "fmemopen failed");

	rc = load_rules_from_stream(cfg, f);
	fclose(f);
	return rc;
}

/*
 * prep_event - allocate and populate an event for policy evaluation
 * @e: event to initialize
 * @auid: subject audit uid
 * @path: object path
 *
 * Returns: none.
 */
static void prep_event(event_t *e, unsigned int auid, const char *path)
{
	subject_attr_t sattr = { .type = AUID, .uval = auid };
	object_attr_t oattr = { .type = PATH, .o = strdup(path) };

	memset(e, 0, sizeof(*e));
	e->s = malloc(sizeof(s_array));
	e->o = malloc(sizeof(o_array));
	if (!e->s || !e->o || !oattr.o)
		error(1, errno, "event allocation failed");

	if (subject_create(e->s) || object_create(e->o))
		error(1, errno, "event array allocation failed");

	e->s->info = calloc(1, sizeof(struct proc_info));
	if (!e->s->info)
		error(1, errno, "proc_info allocation failed");

	if (subject_add(e->s, &sattr))
		error(1, 0, "subject_add failed");
	if (object_add(e->o, &oattr))
		error(1, 0, "object_add failed");
}

/*
 * free_event - release memory allocated by prep_event()
 * @e: event to clear.
 * Returns nothing.
 */
static void free_event(event_t *e)
{
	subject_clear(e->s);
	object_clear(e->o);
	free(e->s);
	free(e->o);
}

/*
 * add_cached_object_attrs - add attributes policy metrics may summarize
 * @e: event receiving cached object attributes.
 * Returns nothing.
 */
static void add_cached_object_attrs(event_t *e)
{
	object_attr_t trust = { .type = OBJ_TRUST, .val = 1 };
	object_attr_t ftype = {
		.type = FTYPE,
		.o = strdup("application/x-executable")
	};

	if (!ftype.o)
		error(1, errno, "ftype allocation failed");
	if (object_add(e->o, &trust))
		error(1, 0, "object_add trust failed");
	if (object_add(e->o, &ftype))
		error(1, 0, "object_add ftype failed");
}

/*
 * reset_object_attr_metrics - clear object lookup metrics used by this test
 * Returns nothing.
 */
static void reset_object_attr_metrics(void)
{
	struct attr_lookup_metric_snapshot snapshot;

	attr_lookup_metrics_object_snapshot(PATH, &snapshot, 1);
	attr_lookup_metrics_object_snapshot(OBJ_TRUST, &snapshot, 1);
	attr_lookup_metrics_object_snapshot(FTYPE, &snapshot, 1);
}

/*
 * require_no_object_attr_metrics - verify no lazy object getter was invoked
 * @phase: diagnostic label included in failure messages.
 * Returns nothing.
 */
static void require_no_object_attr_metrics(const char *phase)
{
	struct attr_lookup_metric_snapshot snapshot;
	object_type_t types[] = { PATH, OBJ_TRUST, FTYPE };
	unsigned int i;

	for (i = 0; i < sizeof(types) / sizeof(types[0]); i++) {
		if (attr_lookup_metrics_object_snapshot(types[i], &snapshot, 0))
			error(1, 0, "%s: object metric snapshot failed", phase);
		if (snapshot.requests || snapshot.lookups)
			error(1, 0, "%s: %s getter used by metrics: %llu/%llu",
			      phase, obj_val_to_name(types[i]), snapshot.requests,
			      snapshot.lookups);
	}
}

/*
 * reset_policy_metrics - clear counters that this test inspects
 * Returns nothing.
 */
static void reset_policy_metrics(void)
{
	decision_metrics_t metrics;

	getAllowedReset(1);
	getDeniedReset(1);
	getDecisionMetricsReset(&metrics, 1);
}

/*
 * process_capture - evaluate an event and capture stderr logging output
 * @e: event to evaluate.
 * @buf: destination for captured stderr text.
 * @buflen: size of @buf.
 * Returns the decision from process_event().
 */
static decision_t process_capture(event_t *e, char *buf, size_t buflen,
				  decision_source_t *source)
{
	decision_t decision;
	ssize_t r;
	int p[2];
	int save;

	if (pipe(p))
		error(1, errno, "pipe failed");

	fflush(stderr);
	save = dup(STDERR_FILENO);
	if (save == -1)
		error(1, errno, "dup failed");
	if (dup2(p[1], STDERR_FILENO) == -1)
		error(1, errno, "dup2 failed");
	close(p[1]);

	decision = process_event_with_source(e, source, NULL);

	fflush(stderr);
	if (dup2(save, STDERR_FILENO) == -1)
		error(1, errno, "dup2 restore failed");
	close(save);

	r = read(p[0], buf, buflen - 1);
	if (r < 0)
		r = 0;
	buf[r] = '\0';
	close(p[0]);
	return decision;
}

/*
 * process_path - evaluate one event for a path.
 * @path: object path to place on the event.
 * Returns the policy decision.
 */
static decision_t process_path(const char *path)
{
	char log[LOGBUF];
	event_t e;
	decision_t decision;

	prep_event(&e, 1000, path);
	decision = process_capture(&e, log, sizeof(log), NULL);
	free_event(&e);
	return decision;
}

/*
 * read_rule_hits_report - capture the per-rule hit report.
 * @buf: destination for captured report text.
 * @buflen: size of @buf.
 * @reset: non-zero resets counters after copying them.
 * Returns nothing.
 */
static void read_rule_hits_report(char *buf, size_t buflen, int reset)
{
	FILE *f;
	size_t used;

	f = tmpfile();
	if (!f)
		error(1, errno, "tmpfile failed");

	policy_rule_hits_report_reset(f, reset);
	fflush(f);
	rewind(f);
	used = fread(buf, 1, buflen - 1, f);
	buf[used] = '\0';
	fclose(f);
}

/*
 * require_old_policy - verify the initially loaded policy is still active
 * @phase: label included in failure diagnostics.
 * Returns nothing.
 */
static void require_old_policy(const char *phase)
{
	char log[LOGBUF];
	event_t e;
	decision_t decision;

	prep_event(&e, 1000, "/bin/ls");
	decision = process_capture(&e, log, sizeof(log), NULL);
	free_event(&e);

	if (decision != ALLOW_SYSLOG)
		error(1, 0, "%s: old allow_syslog policy not preserved",
		      phase);
	if (strstr(log, "dec=allow_syslog") == NULL)
		error(1, 0, "%s: old decision missing from log: %s",
		      phase, log);
	if (strstr(log, "auid=1000") == NULL)
		error(1, 0, "%s: old syslog auid field missing: %s",
		      phase, log);
	if (strstr(log, " path=/bin/ls") == NULL)
		error(1, 0, "%s: old syslog path field missing: %s",
		      phase, log);
	if (strstr(log, " pid=") != NULL)
		error(1, 0, "%s: stale reload syslog field leaked: %s",
		      phase, log);
}

/*
 * require_decision_sources - verify policy evaluation reports rule/fallback
 * @void: no arguments are required.
 * Returns nothing.
 */
static void require_decision_sources(void)
{
	char log[LOGBUF];
	event_t e;
	decision_t decision;
	decision_source_t source;

	prep_event(&e, 1000, "/bin/ls");
	decision = process_capture(&e, log, sizeof(log), &source);
	free_event(&e);
	if (decision != ALLOW_SYSLOG || source != DECISION_SOURCE_RULE)
		error(1, 0, "rule allow source not reported");

	prep_event(&e, 1000, "/bin/cat");
	decision = process_capture(&e, log, sizeof(log), &source);
	free_event(&e);
	if (decision != ALLOW || source != DECISION_SOURCE_FALLTHROUGH)
		error(1, 0, "fallthrough allow source not reported");
}

/*
 * require_fallthrough_metrics_use_cached_attrs - prevent lazy metric lookups
 * @void: no arguments are required.
 * Returns nothing.
 */
static void require_fallthrough_metrics_use_cached_attrs(void)
{
	decision_metrics_t metrics;
	event_t e;

	reset_policy_metrics();
	reset_object_attr_metrics();

	prep_event(&e, 1000, "/bin/ls");
	e.type = FAN_OPEN_EXEC_PERM;
	add_cached_object_attrs(&e);
	policy_metrics_record_decision(ALLOW, &e,
				       DECISION_SOURCE_FALLTHROUGH);
	free_event(&e);

	require_no_object_attr_metrics("fallthrough metrics");
	getDecisionMetricsReset(&metrics, 1);
	getAllowedReset(1);

	if (metrics.allowed_by_fallthrough != 1 ||
	    metrics.fallthrough_execute != 1 ||
	    metrics.fallthrough_trusted != 1 ||
	    metrics.fallthrough_executable != 1)
		error(1, 0, "fallthrough metrics did not use cached attrs");
	if (metrics.fallthrough_unknown_ftype ||
	    metrics.fallthrough_trust_unknown)
		error(1, 0, "cached fallthrough attrs reported as unknown");
}

/*
 * require_rule_hit_counters - verify per-rule hits and generation reset.
 * @cfg: configuration providing syslog_format.
 * Returns nothing.
 */
static void require_rule_hit_counters(const conf_t *cfg)
{
	char report[LOGBUF];

	if (load_text_policy(cfg,
	    "allow perm=any auid=1000 : path=/bin/ls\n"
	    "deny perm=any auid=1000 : path=/bin/rm\n"))
		error(1, 0, "rule hit policy load failed");

	if (process_path("/bin/ls") != ALLOW)
		error(1, 0, "allow rule did not match");
	if (process_path("/bin/ls") != ALLOW)
		error(1, 0, "allow rule did not match second event");
	if (process_path("/bin/rm") != DENY)
		error(1, 0, "deny rule did not match");
	if (process_path("/bin/cat") != ALLOW)
		error(1, 0, "fallthrough path was not allowed");

	read_rule_hits_report(report, sizeof(report), 0);
	if (strstr(report,
	    "Hits/rule:   1      2 allow perm=any auid=1000 : path=/bin/ls\n")
	    == NULL)
		error(1, 0, "allow rule hit report missing: %s", report);
	if (strstr(report,
	    "Hits/rule:   2      1 deny perm=any auid=1000 : path=/bin/rm\n")
	    == NULL)
		error(1, 0, "deny rule hit report missing: %s", report);
	if (strstr(report, "/bin/cat") != NULL)
		error(1, 0, "fallthrough path appeared in rule hits: %s",
		      report);

	read_rule_hits_report(report, sizeof(report), 1);
	if (strstr(report,
	    "Hits/rule:   1      2 allow perm=any auid=1000 : path=/bin/ls\n")
	    == NULL)
		error(1, 0, "reset report lost allow rule hits: %s", report);
	if (strstr(report,
	    "Hits/rule:   2      1 deny perm=any auid=1000 : path=/bin/rm\n")
	    == NULL)
		error(1, 0, "reset report lost deny rule hits: %s", report);

	read_rule_hits_report(report, sizeof(report), 0);
	if (strstr(report,
	    "Hits/rule:   1      0 allow perm=any auid=1000 : path=/bin/ls\n")
	    == NULL)
		error(1, 0, "manual reset did not clear allow hits: %s",
		      report);
	if (strstr(report,
	    "Hits/rule:   2      0 deny perm=any auid=1000 : path=/bin/rm\n")
	    == NULL)
		error(1, 0, "manual reset did not clear deny hits: %s", report);

	if (process_path("/bin/rm") != DENY)
		error(1, 0, "deny rule did not match after manual reset");

	read_rule_hits_report(report, sizeof(report), 0);
	if (strstr(report,
	    "Hits/rule:   2      1 deny perm=any auid=1000 : path=/bin/rm\n")
	    == NULL)
		error(1, 0, "deny rule did not count after manual reset: %s",
		      report);

	if (load_text_policy(cfg,
	    "allow perm=any auid=1000 : path=/bin/ls\n"
	    "deny perm=any auid=1000 : path=/bin/rm\n"))
		error(1, 0, "rule hit policy reload failed");

	read_rule_hits_report(report, sizeof(report), 0);
	if (strstr(report,
	    "Hits/rule:   1      0 allow perm=any auid=1000 : path=/bin/ls\n")
	    == NULL)
		error(1, 0, "allow rule hits did not reset: %s", report);
	if (strstr(report,
	    "Hits/rule:   2      0 deny perm=any auid=1000 : path=/bin/rm\n")
	    == NULL)
		error(1, 0, "deny rule hits did not reset: %s", report);
}

/*
 * main - exercise transactional reload failure paths
 * @void: no arguments are required.
 * Returns 0 on success. Exits with error() on test failure.
 */
int main(void)
{
	conf_t good_cfg = { .syslog_format = OLD_SYSLOG_FORMAT };
	conf_t pid_cfg = { .syslog_format = PID_SYSLOG_FORMAT };
	conf_t bad_syslog_cfg = {
		.syslog_format = "rule,dec,perm,pid,:,path,bogus"
	};

	set_message_mode(MSG_STDERR, DBG_NO);

	if (load_text_policy(&good_cfg,
	    "allow_syslog perm=any auid=1000 : path=/bin/ls\n"))
		error(1, 0, "initial policy load failed");
	require_old_policy("initial load");
	require_decision_sources();
	require_fallthrough_metrics_use_cached_attrs();

	if (load_text_policy(&pid_cfg,
	    "deny_syslog perm=any auid=1000 uid=-1 : path=/bin/ls\n") == 0)
		error(1, 0, "invalid rule reload succeeded");
	require_old_policy("invalid rule reload");

	if (load_text_policy(&bad_syslog_cfg,
	    "deny_syslog perm=any auid=1000 : path=/bin/ls\n") == 0)
		error(1, 0, "invalid syslog reload succeeded");
	require_old_policy("invalid syslog reload");
	require_rule_hit_counters(&good_cfg);

	atomic_store(&stop, true);
	destroy_rules();
	return 0;
}
