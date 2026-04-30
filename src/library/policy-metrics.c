/*
 * policy-metrics.c - policy decision counters and default-allow details
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
#include <string.h>
#include "event.h"
#include "policy-metrics.h"

static atomic_ulong allowed = 0, denied = 0;
static atomic_ulong allowed_by_rule;
static atomic_ulong allowed_by_fallthrough;
static atomic_ulong fallthrough_open;
static atomic_ulong fallthrough_execute;
static atomic_ulong fallthrough_trusted;
static atomic_ulong fallthrough_untrusted;
static atomic_ulong fallthrough_trust_unknown;
static atomic_ulong fallthrough_executable;
static atomic_ulong fallthrough_programmatic;
static atomic_ulong fallthrough_sharedlib;
static atomic_ulong fallthrough_unknown_ftype;
static atomic_ulong fallthrough_other_ftype;
static atomic_uint ruleset_generation;

/*
 * policy_metrics_record_ruleset_update - count a published policy generation.
 * Returns nothing.
 */
void policy_metrics_record_ruleset_update(void)
{
	atomic_fetch_add_explicit(&ruleset_generation, 1,
				  memory_order_relaxed);
}

/*
 * ftype_is_programmatic - classify ftypes commonly loaded by interpreters
 * @ftype: MIME type reported for the object.
 * Returns 1 when @ftype names language source, bytecode, jars, or scripts.
 */
static int ftype_is_programmatic(const char *ftype)
{
	if (strncmp(ftype, "text/x-", 7) == 0)
		return 1;
	if (strstr(ftype, "javascript"))
		return 1;
	if (strstr(ftype, "bytecode"))
		return 1;
	if (strstr(ftype, "script"))
		return 1;
	if (strcmp(ftype, "application/java-archive") == 0)
		return 1;
	if (strcmp(ftype, "application/x-java-applet") == 0)
		return 1;
	if (strcmp(ftype, "application/x-elc") == 0)
		return 1;

	return 0;
}

/*
 * count_fallthrough_ftype - bucket object ftype for default-allow reporting
 * @e: event whose object ftype should be classified.
 * Returns nothing.
 */
static void count_fallthrough_ftype(event_t *e)
{
	object_attr_t *ftype = get_obj_attr(e, FTYPE);
	const char *name = ftype ? ftype->o : NULL;

	if (!name || name[0] == 0) {
		atomic_fetch_add_explicit(&fallthrough_unknown_ftype, 1,
					  memory_order_relaxed);
		return;
	}

	if (strcmp(name, "application/x-sharedlib") == 0) {
		atomic_fetch_add_explicit(&fallthrough_sharedlib, 1,
					  memory_order_relaxed);
		return;
	}
	if (strstr(name, "executable") ||
	    strcmp(name, "application/x-bad-elf") == 0) {
		atomic_fetch_add_explicit(&fallthrough_executable, 1,
					  memory_order_relaxed);
		return;
	}
	if (ftype_is_programmatic(name)) {
		atomic_fetch_add_explicit(&fallthrough_programmatic, 1,
					  memory_order_relaxed);
		return;
	}

	atomic_fetch_add_explicit(&fallthrough_other_ftype, 1,
				  memory_order_relaxed);
}

/*
 * count_fallthrough_details - record low-cardinality default-allow dimensions
 * @e: event that reached the no-opinion allow path.
 * Returns nothing.
 */
static void count_fallthrough_details(event_t *e)
{
	object_attr_t *trust;

	if (e->type & FAN_OPEN_EXEC_PERM)
		atomic_fetch_add_explicit(&fallthrough_execute, 1,
					  memory_order_relaxed);
	else
		atomic_fetch_add_explicit(&fallthrough_open, 1,
					  memory_order_relaxed);

	trust = get_obj_attr(e, OBJ_TRUST);
	if (!trust)
		atomic_fetch_add_explicit(&fallthrough_trust_unknown, 1,
					  memory_order_relaxed);
	else if (trust->val)
		atomic_fetch_add_explicit(&fallthrough_trusted, 1,
					  memory_order_relaxed);
	else
		atomic_fetch_add_explicit(&fallthrough_untrusted, 1,
					  memory_order_relaxed);

	count_fallthrough_ftype(e);
}

/*
 * count_allow_source - record whether an allow came from a rule or fallback
 * @e: event that was allowed.
 * @source: source reported by process_event_with_source().
 * Returns nothing.
 */
static void count_allow_source(event_t *e, decision_source_t source)
{
	if (source == DECISION_SOURCE_RULE) {
		atomic_fetch_add_explicit(&allowed_by_rule, 1,
					  memory_order_relaxed);
		return;
	}

	atomic_fetch_add_explicit(&allowed_by_fallthrough, 1,
				  memory_order_relaxed);
	if (e)
		count_fallthrough_details(e);
}

/*
 * policy_metrics_record_decision - count a policy decision.
 * @decision: decision returned by policy evaluation.
 * @e: event used for allow detail bucketing, or NULL when unavailable.
 * @source: whether the allow came from a rule or default fallthrough.
 * Returns nothing.
 */
void policy_metrics_record_decision(decision_t decision, event_t *e,
		decision_source_t source)
{
	if ((decision & DENY) == DENY) {
		atomic_fetch_add_explicit(&denied, 1, memory_order_relaxed);
		return;
	}

	atomic_fetch_add_explicit(&allowed, 1, memory_order_relaxed);
	count_allow_source(e, source);
}

/*
 * getAllowed - copy the lifetime allowed counter.
 * Returns the current allowed decision count.
 */
unsigned long getAllowed(void)
{
	return getAllowedReset(0);
}

/*
 * getDenied - copy the lifetime denied counter.
 * Returns the current denied decision count.
 */
unsigned long getDenied(void)
{
	return getDeniedReset(0);
}

/*
 * policy_counter_snapshot - copy one policy counter and optionally reset it.
 * @counter: atomic counter to read.
 * @reset: non-zero resets the counter after copying it.
 * Returns the copied counter value.
 */
static unsigned long policy_counter_snapshot(atomic_ulong *counter, int reset)
{
	if (reset)
		return atomic_exchange_explicit(counter, 0,
						memory_order_relaxed);

	return atomic_load_explicit(counter, memory_order_relaxed);
}

/*
 * getAllowedReset - copy the allowed counter, optionally resetting it.
 * @reset: non-zero resets the counter after copying it.
 * Returns the copied counter value.
 */
unsigned long getAllowedReset(int reset)
{
	return policy_counter_snapshot(&allowed, reset);
}

/*
 * getDeniedReset - copy the denied counter, optionally resetting it.
 * @reset: non-zero resets the counter after copying it.
 * Returns the copied counter value.
 */
unsigned long getDeniedReset(int reset)
{
	return policy_counter_snapshot(&denied, reset);
}

/*
 * getDecisionMetrics - copy policy decision counters for reporting
 * @metrics: destination metrics snapshot.
 * Returns nothing.
 */
void getDecisionMetrics(decision_metrics_t *metrics)
{
	getDecisionMetricsReset(metrics, 0);
}

/*
 * getDecisionMetricsReset - copy policy decision counters for reporting.
 * @metrics: destination metrics snapshot.
 * @reset: non-zero resets interval counters after copying them.
 *
 * Ruleset generation identifies the active policy and is never reset.
 * Returns nothing.
 */
void getDecisionMetricsReset(decision_metrics_t *metrics, int reset)
{
	if (!metrics)
		return;

	metrics->allowed_by_rule =
		policy_counter_snapshot(&allowed_by_rule, reset);
	metrics->allowed_by_fallthrough =
		policy_counter_snapshot(&allowed_by_fallthrough, reset);
	metrics->fallthrough_open =
		policy_counter_snapshot(&fallthrough_open, reset);
	metrics->fallthrough_execute =
		policy_counter_snapshot(&fallthrough_execute, reset);
	metrics->fallthrough_trusted =
		policy_counter_snapshot(&fallthrough_trusted, reset);
	metrics->fallthrough_untrusted =
		policy_counter_snapshot(&fallthrough_untrusted, reset);
	metrics->fallthrough_trust_unknown =
		policy_counter_snapshot(&fallthrough_trust_unknown, reset);
	metrics->fallthrough_executable =
		policy_counter_snapshot(&fallthrough_executable, reset);
	metrics->fallthrough_programmatic =
		policy_counter_snapshot(&fallthrough_programmatic, reset);
	metrics->fallthrough_sharedlib =
		policy_counter_snapshot(&fallthrough_sharedlib, reset);
	metrics->fallthrough_unknown_ftype =
		policy_counter_snapshot(&fallthrough_unknown_ftype, reset);
	metrics->fallthrough_other_ftype =
		policy_counter_snapshot(&fallthrough_other_ftype, reset);
	metrics->ruleset_generation =
		atomic_load_explicit(&ruleset_generation,
				     memory_order_relaxed);
}
