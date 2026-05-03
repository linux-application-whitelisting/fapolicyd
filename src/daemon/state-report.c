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
#include <unistd.h>
#include "daemon-config.h"
#include "decision-timing.h"
#include "failure-action.h"
#include "message.h"
#include "notify.h"
#include "paths.h"
#include "policy.h"
#include "state-report.h"

extern atomic_bool run_stats;
extern atomic_uint signal_report_requests;
extern atomic_uint signal_report_reset_requests;
extern atomic_int signal_report_reset_request_pid;
extern atomic_int signal_report_reset_request_uid;
extern conf_t config;

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
	}
	atomic_fetch_add_explicit(&signal_report_requests, 1,
				  memory_order_relaxed);
	run_stats = true;
	nudge_queue();
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
 * open_stat_report - open status report file for overwrite without symlinks.
 * Return codes:
 * >= 0 - writable file descriptor for STAT_REPORT
 *  -1 - open or validation failed (errno set)
 */
static int open_stat_report(void)
{
	struct stat st;
	int sfd;

	sfd = open(STAT_REPORT,
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
	policy_rule_hits_report(f);
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
		    reset ? "resetting counters after state report" :
		    "not resetting counters");
	else
		msg(LOG_INFO,
		    "Manual metrics reset requested (requests=%u): %s",
		    reset_requests,
		    reset ? "resetting counters after state report" :
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
 * state_report_write - write a state report to the standard location.
 * @reason: report trigger used to apply reset_strategy.
 * Returns nothing.
 */
void state_report_write(enum state_report_reason reason)
{
	int sr_fd = open_stat_report();
	FILE *f;
	unsigned int reset_requests;
	int reset;

	if (sr_fd < 0) {
		msg(LOG_WARNING, "cannot open %s: %s",
			STAT_REPORT, strerror(errno));
		return;
	}

	f = fdopen(sr_fd, "w");
	if (!f) {
		msg(LOG_WARNING, "cannot fdopen %s: %s",
			STAT_REPORT, strerror(errno));
		close(sr_fd);
		return;
	}

	(void)atomic_exchange_explicit(&signal_report_requests, 0,
				       memory_order_relaxed);
	reset_requests = atomic_exchange_explicit(&signal_report_reset_requests,
						  0, memory_order_relaxed);
	reset = metric_reset_allowed(reason, reset_requests);
	log_manual_metric_reset(reset_requests, reset);
	do_stat_report_reset(f, 0, reset);
	fclose(f);
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
