/*
 * state-report.c - daemon state report coordination
 * Copyright (c) 2026 Red Hat Inc.
 * All Rights Reserved.
 *
 * This software may be freely redistributed and/or modified under the
 * terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2, or (at your option) any
 * later version.
 */

#include "config.h"
#include <errno.h>
#include <fcntl.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include "attr-lookup-metrics.h"
#include "daemon-config.h"
#include "decision-timing.h"
#include "failure-action.h"
#include "fanotify-fs-error.h"
#include "message.h"
#include "notify.h"
#include "paths.h"
#include "policy.h"
#include "state-report.h"

extern atomic_bool run_stats;
extern atomic_uint signal_report_requests;
extern atomic_uint signal_report_intent;
extern atomic_uint signal_report_reset_requests;
extern atomic_int signal_report_reset_request_pid;
extern atomic_int signal_report_reset_request_uid;
extern conf_t config;

static time_t last_metrics_reset;

/*
 * state_report_operating_mode - write health and control state.
 * @f: report stream.
 * @mode: operating mode snapshot and active timing configuration.
 * Returns nothing.
 */
void state_report_operating_mode(FILE *f,
		const struct state_report_operating_mode *mode)
{
	if (f == NULL || mode == NULL)
		return;

	fprintf(f, "Operating mode:\n");
	fprintf(f, "Permissive: %s\n",
		mode->permissive ? "true" : "false");
	fprintf(f, "Integrity: %s\n",
		mode->integrity ? mode->integrity : "unknown");
	fprintf(f, "reset_strategy: %s\n",
		mode->reset_strategy ? mode->reset_strategy : "unknown");
	decision_timing_control_report(f, mode->config);
	decision_timing_history_report(f);
	fprintf(f, "Ruleset generation: %u\n", mode->ruleset_generation);
}

/*
 * usr1_handler - request work from SIGUSR1.
 * @sig: signal number.
 * @info: sender identity supplied by sigaction.
 * @context: unused signal context.
 * Returns nothing.
 */
void usr1_handler(int sig __attribute__((unused)),
		siginfo_t *info, void *context __attribute__((unused)))
{
	if (info && info->si_code == SI_QUEUE) {
		report_intent_t intent = info->si_value.sival_int;

		if (intent == REPORT_INTENT_TIMING_ARM ||
		    intent == REPORT_INTENT_TIMING_STOP) {
			decision_timing_signal_request(intent, info->si_pid,
						       info->si_uid);
			nudge_queue();
			return;
		}

		if (intent == REPORT_INTENT_RESET_METRICS) {
			atomic_store_explicit(&signal_report_reset_request_pid,
					      info->si_pid,
					      memory_order_relaxed);
			atomic_store_explicit(&signal_report_reset_request_uid,
					      info->si_uid,
					      memory_order_relaxed);
			atomic_fetch_add_explicit(
				&signal_report_reset_requests, 1,
				memory_order_relaxed);
		}
		if (intent == REPORT_INTENT_STATUS ||
		    intent == REPORT_INTENT_METRICS ||
		    intent == REPORT_INTENT_RESET_METRICS)
			atomic_store_explicit(&signal_report_intent, intent,
					      memory_order_relaxed);
	}
	atomic_fetch_add_explicit(&signal_report_requests, 1,
				  memory_order_relaxed);
	run_stats = true;
	nudge_queue();
}

/*
 * format_metrics_reset_time - format the last metric reset timestamp.
 * @buf: destination buffer.
 * @buf_size: destination size.
 * Returns @buf.
 */
static const char *format_metrics_reset_time(char *buf, size_t buf_size)
{
	struct tm tm;

	if (buf_size == 0)
		return buf;

	if (last_metrics_reset == 0) {
		strncpy(buf, "never", buf_size - 1);
		buf[buf_size - 1] = 0;
		return buf;
	}

	if (localtime_r(&last_metrics_reset, &tm) == NULL ||
	    strftime(buf, buf_size, "%Y-%m-%d %H:%M:%S %z", &tm) == 0) {
		strncpy(buf, "unavailable", buf_size - 1);
		buf[buf_size - 1] = 0;
	}

	return buf;
}

/*
 * state_report_log_reset_strategy - record how runtime metric resets work.
 * @strategy: configured reset strategy.
 * Returns nothing.
 */
void state_report_log_reset_strategy(reset_strategy_t strategy)
{
	switch (strategy) {
	case RESET_NEVER:
		msg(LOG_INFO,
		    "Metrics resets disabled; counters grow for daemon lifetime");
		break;
	case RESET_AUTO:
		msg(LOG_INFO,
		    "Metrics resets will occur only by interval timer reports");
		break;
	case RESET_MANUAL:
		msg(LOG_INFO,
		    "Metrics resets will occur only by privileged signal reports");
		break;
	}
}

/*
 * open_report_file - open a report file for overwrite without symlinks.
 * @path: report path to open.
 * Return codes:
 * >= 0 - writable file descriptor
 *  -1 - open or validation failed (errno set)
 */
static int open_report_file(const char *path)
{
	struct stat st;
	int sfd;

	sfd = open(path,
		O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW,
		0640);
	if (sfd < 0)
		return -1;

	if (fstat(sfd, &st) == -1 || !S_ISREG(st.st_mode)) {
		close(sfd);
		errno = EINVAL;
		return -1;
	}

	return sfd;
}

/*
 * open_report_stream - open a report stream and log failures.
 * @path: report path to open.
 * Returns a FILE stream, or NULL on failure.
 */
static FILE *open_report_stream(const char *path)
{
	int fd = open_report_file(path);
	FILE *f;

	if (fd < 0) {
		msg(LOG_WARNING, "cannot open %s: %s",
			path, strerror(errno));
		return NULL;
	}

	f = fdopen(fd, "w");
	if (!f) {
		msg(LOG_WARNING, "cannot fdopen %s: %s",
			path, strerror(errno));
		close(fd);
		return NULL;
	}

	return f;
}

/*
 * decision_report - write policy decision metrics.
 * @f: output stream.
 * Returns nothing.
 */
void decision_report(FILE *f)
{
	decision_report_reset(f, 0);
}

/*
 * decision_report_reset - write policy and failure metrics.
 * @f: output stream.
 * @reset: non-zero resets interval counters after copying them.
 * Returns nothing.
 */
void decision_report_reset(FILE *f, int reset)
{
	failure_action_metrics_t failures;

	if (f == NULL)
		return;

	failure_action_snapshot(&failures, reset);
	decision_report_reset_with_failures(f, reset, &failures);
	decision_failure_action_report(f, &failures);
}

/*
 * decision_report_metrics_reset - write decision outcome metrics.
 * @f: output stream.
 * @reset: non-zero resets counters after copying them.
 * Returns nothing.
 */
void decision_report_metrics_reset(FILE *f, int reset)
{
	decision_metrics_t metrics;
	char reset_time[64];

	if (f == NULL)
		return;

	getDecisionMetricsReset(&metrics, reset);

	fprintf(f, "Last metrics reset: %s\n",
		format_metrics_reset_time(reset_time, sizeof(reset_time)));
	fprintf(f, "Ruleset generation: %u\n", metrics.ruleset_generation);

	fprintf(f, "\nDecision outcomes:\n");
	fprintf(f, "Allowed accesses: %lu\n", getAllowedReset(reset));
	fprintf(f, "Denied accesses: %lu\n", getDeniedReset(reset));
	fprintf(f, "Allowed by rule: %lu\n", metrics.allowed_by_rule);
	fprintf(f, "Allowed by fallthrough: %lu\n",
		metrics.allowed_by_fallthrough);
	if (metrics.allowed_by_fallthrough) {
		fprintf(f, "Allowed by fallthrough open: %lu\n",
			metrics.fallthrough_open);
		fprintf(f, "Allowed by fallthrough execute: %lu\n",
			metrics.fallthrough_execute);
		fprintf(f, "Allowed by fallthrough trusted: %lu\n",
			metrics.fallthrough_trusted);
		fprintf(f, "Allowed by fallthrough untrusted: %lu\n",
			metrics.fallthrough_untrusted);
		fprintf(f, "Allowed by fallthrough trust unknown: %lu\n",
			metrics.fallthrough_trust_unknown);
		fprintf(f, "Allowed by fallthrough executable: %lu\n",
			metrics.fallthrough_executable);
		fprintf(f, "Allowed by fallthrough programmatic: %lu\n",
			metrics.fallthrough_programmatic);
		fprintf(f, "Allowed by fallthrough sharedlib: %lu\n",
			metrics.fallthrough_sharedlib);
		fprintf(f, "Allowed by fallthrough unknown ftype: %lu\n",
			metrics.fallthrough_unknown_ftype);
		fprintf(f, "Allowed by fallthrough other ftype: %lu\n",
			metrics.fallthrough_other_ftype);
	}
}

/*
 * decision_report_reset_with_failures - write policy metrics.
 * @f: output stream.
 * @reset: non-zero resets interval counters after copying them.
 * @failures: failure action metrics snapshot for reliability counters.
 * Returns nothing.
 */
void decision_report_reset_with_failures(FILE *f, int reset,
		const failure_action_metrics_t *failures)
{
	decision_metrics_t metrics;

	if (f == NULL || failures == NULL)
		return;

	getDecisionMetricsReset(&metrics, reset);

	// Report results
	fprintf(f, "Kernel Queue Overflow: %lu\n",
		failure_action_metrics_count(failures,
			FAILURE_REASON_KERNEL_QUEUE_OVERFLOW));
	fprintf(f, "Filesystem Errors: %lu\n",
		failure_action_metrics_count(failures,
			FAILURE_REASON_FANOTIFY_FS_ERROR));
	fprintf(f, "Reply Errors: %lu\n",
		failure_action_metrics_count(failures,
			FAILURE_REASON_RESPONSE_WRITE_FAILURE));
	fprintf(f, "Allowed accesses: %lu\n", getAllowedReset(reset));
	fprintf(f, "Denied accesses: %lu\n", getDeniedReset(reset));
	fprintf(f, "Allowed by rule: %lu\n", metrics.allowed_by_rule);
	fprintf(f, "Allowed by fallthrough: %lu\n",
		metrics.allowed_by_fallthrough);
	if (metrics.allowed_by_fallthrough) {
		fprintf(f, "Allowed by fallthrough open: %lu\n",
			metrics.fallthrough_open);
		fprintf(f, "Allowed by fallthrough execute: %lu\n",
			metrics.fallthrough_execute);
		fprintf(f, "Allowed by fallthrough trusted: %lu\n",
			metrics.fallthrough_trusted);
		fprintf(f, "Allowed by fallthrough untrusted: %lu\n",
			metrics.fallthrough_untrusted);
		fprintf(f, "Allowed by fallthrough trust unknown: %lu\n",
			metrics.fallthrough_trust_unknown);
		fprintf(f, "Allowed by fallthrough executable: %lu\n",
			metrics.fallthrough_executable);
		fprintf(f, "Allowed by fallthrough programmatic: %lu\n",
			metrics.fallthrough_programmatic);
		fprintf(f, "Allowed by fallthrough sharedlib: %lu\n",
			metrics.fallthrough_sharedlib);
		fprintf(f, "Allowed by fallthrough unknown ftype: %lu\n",
			metrics.fallthrough_unknown_ftype);
		fprintf(f, "Allowed by fallthrough other ftype: %lu\n",
			metrics.fallthrough_other_ftype);
	}
	fprintf(f, "Ruleset generation: %u\n", metrics.ruleset_generation);
	policy_rule_hits_report_reset(f, reset);
	attr_lookup_metrics_report(f, reset);
}

/*
 * decision_failure_action_report - write failure action metrics.
 * @f: output stream.
 * @failures: failure action metrics snapshot to report.
 * Returns nothing.
 */
void decision_failure_action_report(FILE *f,
		const failure_action_metrics_t *failures)
{
	if (f == NULL || failures == NULL)
		return;

	failure_action_metrics_report(f, failures);
}

/*
 * metric_reset_allowed - decide whether a report should reset counters.
 * @reason: why the report is being generated.
 * @reset_requests: number of pending signal-based reset requests.
 * Returns 1 when counters should be reset after this report snapshot.
 */
static int metric_reset_allowed(enum state_report_reason reason,
			unsigned int reset_requests)
{
	reset_strategy_t strategy;
	int uid;

	strategy = __atomic_load_n(&config.reset_strategy, __ATOMIC_RELAXED);
	if (strategy == RESET_AUTO && reason == STATE_REPORT_INTERVAL)
		return 1;
	uid = atomic_load_explicit(&signal_report_reset_request_uid,
				   memory_order_relaxed);
	if (strategy == RESET_MANUAL && reason == STATE_REPORT_SIGNAL &&
	    reset_requests && uid == 0)
		return 1;
	return 0;
}

/*
 * log_manual_metric_reset - log a manual reset request from SIGUSR1.
 * @reset_requests: number of requests consumed by this report.
 * @reset: non-zero when the request reset counters.
 * Returns nothing.
 */
static void log_manual_metric_reset(unsigned int reset_requests, int reset)
{
	reset_strategy_t strategy;
	int pid, uid;

	if (reset_requests == 0)
		return;

	strategy = __atomic_load_n(&config.reset_strategy, __ATOMIC_RELAXED);
	if (strategy != RESET_MANUAL)
		return;

	pid = atomic_load_explicit(&signal_report_reset_request_pid,
				   memory_order_relaxed);
	uid = atomic_load_explicit(&signal_report_reset_request_uid,
				   memory_order_relaxed);

	if (pid > 0)
		msg(LOG_INFO,
		    "Manual metrics reset requested by pid=%d uid=%d "
		    "(requests=%u): %s",
		    pid, uid, reset_requests,
		    reset ? "resetting counters after metrics report" :
		    "not resetting counters");
	else
		msg(LOG_INFO,
		    "Manual metrics reset requested (requests=%u): %s",
		    reset_requests,
		    reset ? "resetting counters after metrics report" :
		    "not resetting counters");

	if (!reset) {
		if (strategy == RESET_MANUAL && uid != 0)
			msg(LOG_INFO,
			    "Manual metrics reset ignored because uid=%d "
			    "is not privileged",
			    uid);
		else
			msg(LOG_INFO,
			    "Manual metrics reset ignored because report was not "
			    "signal based");
	}
}

/*
 * state_report_intent_for_write - consume the pending report intent.
 * @reason: report trigger used to decide the default.
 * @requests: number of signal report requests consumed.
 * Returns the report intent to write.
 */
static report_intent_t state_report_intent_for_write(
		enum state_report_reason reason, unsigned int requests)
{
	unsigned int intent;

	if (reason == STATE_REPORT_INTERVAL || requests == 0)
		return REPORT_INTENT_STATUS;

	intent = atomic_exchange_explicit(&signal_report_intent,
					  REPORT_INTENT_STATUS,
					  memory_order_relaxed);
	switch (intent) {
	case REPORT_INTENT_STATUS:
	case REPORT_INTENT_METRICS:
	case REPORT_INTENT_RESET_METRICS:
		return intent;
	case REPORT_INTENT_TIMING_ARM:
	case REPORT_INTENT_TIMING_STOP:
		break;
	}

	return REPORT_INTENT_STATUS;
}

/*
 * write_state_report_file - write the daemon state report.
 * Returns 0 on success, non-zero on open failure.
 */
static int write_state_report_file(void)
{
	FILE *f = open_report_stream(STAT_REPORT);

	if (!f)
		return -1;

	do_state_report(f, 0);
	fclose(f);
	return 0;
}

/*
 * write_metrics_report_file - write the daemon metrics report.
 * @reset: non-zero resets metrics after snapshotting them.
 * Returns 0 on success, non-zero on open failure.
 */
static int write_metrics_report_file(int reset)
{
	FILE *f = open_report_stream(METRICS_REPORT);

	if (!f)
		return -1;

	do_metrics_report_reset(f, reset);
	fclose(f);
	return 0;
}

/*
 * record_metrics_reset - remember a successful metrics reset time.
 * Returns nothing.
 */
static void record_metrics_reset(void)
{
	time_t now = time(NULL);

	if (now != (time_t)-1)
		last_metrics_reset = now;
}

/*
 * state_report_write - write a state report to the standard location.
 * @reason: report trigger used to apply reset_strategy.
 * Returns nothing.
 */
void state_report_write(enum state_report_reason reason)
{
	unsigned int reset_requests;
	unsigned int report_requests;
	report_intent_t intent;
	int reset;

	report_requests = atomic_exchange_explicit(&signal_report_requests, 0,
						  memory_order_relaxed);
	reset_requests = atomic_exchange_explicit(&signal_report_reset_requests,
						  0, memory_order_relaxed);
	reset = metric_reset_allowed(reason, reset_requests);
	log_manual_metric_reset(reset_requests, reset);

	if (reason == STATE_REPORT_INTERVAL) {
		write_state_report_file();
		if (write_metrics_report_file(reset) == 0 && reset)
			record_metrics_reset();
		return;
	}

	intent = state_report_intent_for_write(reason, report_requests);
	if (intent == REPORT_INTENT_METRICS ||
	    intent == REPORT_INTENT_RESET_METRICS) {
		if (write_metrics_report_file(reset) == 0 && reset)
			record_metrics_reset();
		return;
	}

	write_state_report_file();
}

/*
 * state_report_reason_for_triggers - classify the pending report trigger.
 * @expired: non-zero when the interval timer expired.
 * Returns the trigger to use when applying reset_strategy.
 */
enum state_report_reason state_report_reason_for_triggers(int expired)
{
	if (atomic_load_explicit(&signal_report_requests,
				 memory_order_relaxed))
		return STATE_REPORT_SIGNAL;
	return expired ? STATE_REPORT_INTERVAL : STATE_REPORT_SIGNAL;
}
