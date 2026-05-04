/*
 * failure-action.c - internal failure action model
 * Copyright (c) 2026 Red Hat Inc.
 * All Rights Reserved.
 *
 * This software may be freely redistributed and/or modified under the
 * terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2, or (at your option) any
 * later version.
 */

#include "config.h"
#include <stdatomic.h>
#include "failure-action.h"

struct failure_definition {
	const char *name;
	failure_action_t action;
};

/*
 * failure_definitions - known daemon reliability failures
 *
 * Every failure starts in observe mode. Existing compatibility behavior, such
 * as queue-full denial or the deadman kill, stays at the call site until later
 * high-security configuration can choose fail-closed or degraded actions here.
 */
static const struct failure_definition failure_definitions[] = {
	[FAILURE_REASON_QUEUE_FULL] = {
		"queue_full", FAILURE_ACTION_OBSERVE
	},
	[FAILURE_REASON_KERNEL_QUEUE_OVERFLOW] = {
		"kernel_queue_overflow", FAILURE_ACTION_OBSERVE
	},
	[FAILURE_REASON_WORKER_STALL] = {
		"worker_stall", FAILURE_ACTION_OBSERVE
	},
	[FAILURE_REASON_RULE_RELOAD_FAILURE] = {
		"rule_reload_failure", FAILURE_ACTION_OBSERVE
	},
	[FAILURE_REASON_TRUST_RELOAD_FAILURE] = {
		"trust_reload_failure", FAILURE_ACTION_OBSERVE
	},
	[FAILURE_REASON_RESPONSE_WRITE_FAILURE] = {
		"response_write_failure", FAILURE_ACTION_OBSERVE
	},
	[FAILURE_REASON_FANOTIFY_FS_ERROR] = {
		"fanotify_filesystem_error", FAILURE_ACTION_OBSERVE
	},
};

static atomic_ulong failure_counts[FAILURE_REASON_MAX];

/*
 * failure_reason_valid - determine whether a reason enum is known.
 * @reason: failure reason supplied by a caller.
 * Returns 1 for a valid reason and 0 otherwise.
 */
static int failure_reason_valid(failure_reason_t reason)
{
	return reason >= 0 && reason < FAILURE_REASON_MAX &&
	       failure_definitions[reason].name != NULL;
}

/*
 * failure_reason_name - return the stable metric name for a failure.
 * @reason: failure reason supplied by a caller.
 * Returns the stable reason name or "unknown".
 */
const char *failure_reason_name(failure_reason_t reason)
{
	if (!failure_reason_valid(reason))
		return "unknown";

	return failure_definitions[reason].name;
}

/*
 * failure_reason_action - return the current configured failure action.
 * @reason: failure reason supplied by a caller.
 *
 * Today all reasons observe only. Keeping this query separate from the counter
 * lets later configuration change behavior without touching every call site.
 *
 * Returns the configured action for @reason.
 */
failure_action_t failure_reason_action(failure_reason_t reason)
{
	if (!failure_reason_valid(reason))
		return FAILURE_ACTION_OBSERVE;

	return failure_definitions[reason].action;
}

/*
 * failure_action_name - return the stable name for a failure action.
 * @action: action enum to describe.
 * Returns the action name or "unknown".
 */
const char *failure_action_name(failure_action_t action)
{
	switch (action) {
	case FAILURE_ACTION_OBSERVE:
		return "observe";
	}

	return "unknown";
}

/*
 * failure_action_record - count one observed daemon failure.
 * @reason: failure reason to increment.
 *
 * Returns the new counter value for valid reasons, 0 for unknown reasons.
 */
unsigned long failure_action_record(failure_reason_t reason)
{
	if (!failure_reason_valid(reason))
		return 0;

	return atomic_fetch_add_explicit(&failure_counts[reason], 1,
					 memory_order_relaxed) + 1;
}

/*
 * failure_action_count - return the count for one failure reason.
 * @reason: failure reason to read.
 * Returns the current counter value, or 0 for unknown reasons.
 */
unsigned long failure_action_count(failure_reason_t reason)
{
	if (!failure_reason_valid(reason))
		return 0;

	return atomic_load_explicit(&failure_counts[reason],
				    memory_order_relaxed);
}

/*
 * failure_action_snapshot - copy failure counters, optionally resetting them.
 * @metrics: destination metrics snapshot.
 * @reset: non-zero resets counters after copying them.
 * Returns nothing.
 */
void failure_action_snapshot(failure_action_metrics_t *metrics, int reset)
{
	failure_reason_t reason;

	if (metrics == NULL)
		return;

	for (reason = 0; reason < FAILURE_REASON_MAX; reason++) {
		if (reset)
			metrics->counts[reason] = atomic_exchange_explicit(
				&failure_counts[reason], 0,
				memory_order_relaxed);
		else
			metrics->counts[reason] = failure_action_count(reason);
	}
}

/*
 * failure_action_metrics_count - read one value from a metrics snapshot.
 * @metrics: metrics returned by failure_action_snapshot().
 * @reason: failure reason to read.
 * Returns the snapshot value, or 0 for unknown reasons.
 */
unsigned long failure_action_metrics_count(
		const failure_action_metrics_t *metrics,
		failure_reason_t reason)
{
	if (metrics == NULL || !failure_reason_valid(reason))
		return 0;

	return metrics->counts[reason];
}

/*
 * failure_action_metrics_report - print failure action metric snapshot.
 * @f: report stream.
 * @metrics: metrics returned by failure_action_snapshot().
 * Returns nothing.
 */
void failure_action_metrics_report(FILE *f,
		const failure_action_metrics_t *metrics)
{
	failure_reason_t reason;

	if (f == NULL || metrics == NULL)
		return;

	for (reason = 0; reason < FAILURE_REASON_MAX; reason++)
		fprintf(f, "Failure action %s (%s): %lu\n",
			failure_reason_name(reason),
			failure_action_name(failure_reason_action(reason)),
			failure_action_metrics_count(metrics, reason));
}

/*
 * failure_action_report - print current failure action counters.
 * @f: report stream.
 * Returns nothing.
 */
void failure_action_report(FILE *f)
{
	failure_action_metrics_t metrics;

	failure_action_snapshot(&metrics, 0);
	failure_action_metrics_report(f, &metrics);
}
