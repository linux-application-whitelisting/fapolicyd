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
#include <time.h>
#include "decision-context.h"
#include "event.h"
#include "policy-metrics.h"

static atomic_uint ruleset_generation;
static atomic_llong ruleset_effective_since;

/*
 * policy_metrics_record_ruleset_update - publish active policy generation.
 * @generation: policy snapshot generation just published.
 * @effective_since: time the policy snapshot became active.
 * Returns nothing.
 */
void policy_metrics_record_ruleset_update(unsigned int generation,
					  time_t effective_since)
{
	atomic_store_explicit(&ruleset_effective_since,
			      (long long)effective_since,
			      memory_order_relaxed);
	atomic_store_explicit(&ruleset_generation, generation,
			      memory_order_relaxed);
}

/*
 * cached_object_attr - read an object attribute without lazy materialization
 * @e: event whose cached object attribute list should be inspected.
 * @type: object attribute type to read.
 * Returns the cached attribute, or NULL when the event never needed it.
 */
static object_attr_t *cached_object_attr(const event_t *e, object_type_t type)
{
	if (!e || !e->o)
		return NULL;

	return object_access(e->o, type);
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
 * count_fallthrough_ftype - bucket cached object ftype for reporting
 * @counters: decision counter block to update.
 * @e: event whose object ftype should be classified if it is already cached.
 * Returns nothing.
 */
static void count_fallthrough_ftype(struct decision_policy_counters *counters,
		event_t *e)
{
	object_attr_t *ftype = cached_object_attr(e, FTYPE);
	const char *name = ftype ? ftype->o : NULL;

	if (!name || name[0] == 0) {
		atomic_fetch_add_explicit(
			&counters->fallthrough_unknown_ftype, 1,
			memory_order_relaxed);
		return;
	}

	if (strcmp(name, "application/x-sharedlib") == 0) {
		atomic_fetch_add_explicit(&counters->fallthrough_sharedlib, 1,
					  memory_order_relaxed);
		return;
	}
	if (strstr(name, "executable") ||
	    strcmp(name, "application/x-bad-elf") == 0) {
		atomic_fetch_add_explicit(&counters->fallthrough_executable, 1,
					  memory_order_relaxed);
		return;
	}
	if (ftype_is_programmatic(name)) {
		atomic_fetch_add_explicit(
			&counters->fallthrough_programmatic, 1,
			memory_order_relaxed);
		return;
	}

	atomic_fetch_add_explicit(&counters->fallthrough_other_ftype, 1,
				  memory_order_relaxed);
}

/*
 * count_fallthrough_details - record low-cardinality default-allow dimensions
 * @counters: decision counter block to update.
 * @e: event that reached the no-opinion allow path.
 * Returns nothing.
 */
static void count_fallthrough_details(
		struct decision_policy_counters *counters, event_t *e)
{
	object_attr_t *trust;

	if (e->type & FAN_OPEN_EXEC_PERM)
		atomic_fetch_add_explicit(&counters->fallthrough_execute, 1,
					  memory_order_relaxed);
	else
		atomic_fetch_add_explicit(&counters->fallthrough_open, 1,
					  memory_order_relaxed);

	/*
	 * Decision metrics run before the fanotify response is written. Use only
	 * cached attributes from policy evaluation; get_obj_attr() can perform
	 * trust database, integrity hash, and MIME/libmagic work here.
	 */
	trust = cached_object_attr(e, OBJ_TRUST);
	if (!trust)
		atomic_fetch_add_explicit(
			&counters->fallthrough_trust_unknown, 1,
			memory_order_relaxed);
	else if (trust->val)
		atomic_fetch_add_explicit(&counters->fallthrough_trusted, 1,
					  memory_order_relaxed);
	else
		atomic_fetch_add_explicit(&counters->fallthrough_untrusted, 1,
					  memory_order_relaxed);

	count_fallthrough_ftype(counters, e);
}

/*
 * count_allow_source - record whether an allow came from a rule or fallback
 * @counters: decision counter block to update.
 * @e: event that was allowed.
 * @source: source reported by process_event_with_source().
 * Returns nothing.
 */
static void count_allow_source(struct decision_policy_counters *counters,
		event_t *e, decision_source_t source)
{
	if (source == DECISION_SOURCE_RULE) {
		atomic_fetch_add_explicit(&counters->allowed_by_rule, 1,
					  memory_order_relaxed);
		return;
	}

	atomic_fetch_add_explicit(&counters->allowed_by_fallthrough, 1,
				  memory_order_relaxed);
	if (e)
		count_fallthrough_details(counters, e);
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
	struct decision_policy_counters *counters =
		&decision_context_current()->policy_counters;

	if ((decision & DENY) == DENY) {
		atomic_fetch_add_explicit(&counters->denied, 1,
					  memory_order_relaxed);
		return;
	}

	atomic_fetch_add_explicit(&counters->allowed, 1,
				  memory_order_relaxed);
	count_allow_source(counters, e, source);
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

enum policy_counter_id {
	POLICY_COUNTER_ALLOWED,
	POLICY_COUNTER_DENIED,
};

struct policy_counter_snapshot {
	enum policy_counter_id id;
	unsigned long total;
	int reset;
};

struct decision_metrics_snapshot {
	decision_metrics_t *metrics;
	int reset;
};

/*
 * policy_counter_from_context - select one lifetime counter from a context.
 * @counters: worker-local policy counter block.
 * @id: counter requested by a public getter.
 *
 * Returns the requested atomic counter, or NULL if @id is not valid.
 */
static atomic_ulong *policy_counter_from_context(
		struct decision_policy_counters *counters,
		enum policy_counter_id id)
{
	switch (id) {
	case POLICY_COUNTER_ALLOWED:
		return &counters->allowed;
	case POLICY_COUNTER_DENIED:
		return &counters->denied;
	default:
		return NULL;
	}
}

/*
 * policy_counter_snapshot_context - add one worker counter to an aggregate.
 * @ctx: worker context being sampled.
 * @data: struct policy_counter_snapshot aggregate.
 * Returns nothing.
 */
static void policy_counter_snapshot_context(struct decision_context *ctx,
		void *data)
{
	struct policy_counter_snapshot *snapshot = data;
	atomic_ulong *counter;

	if (ctx == NULL || snapshot == NULL)
		return;

	counter = policy_counter_from_context(&ctx->policy_counters,
					      snapshot->id);
	if (counter)
		snapshot->total += policy_counter_snapshot(counter,
							   snapshot->reset);
}

/*
 * policy_counter_total_reset - aggregate one policy counter across workers.
 * @id: counter to copy.
 * @reset: non-zero resets counters after copying them.
 * Returns the aggregate counter value.
 */
static unsigned long policy_counter_total_reset(enum policy_counter_id id,
		int reset)
{
	struct policy_counter_snapshot snapshot = {
		.id = id,
		.reset = reset,
	};

	decision_context_for_each(policy_counter_snapshot_context, &snapshot);
	return snapshot.total;
}

/*
 * getAllowedReset - copy the allowed counter, optionally resetting it.
 * @reset: non-zero resets the counter after copying it.
 * Returns the copied counter value.
 */
unsigned long getAllowedReset(int reset)
{
	return policy_counter_total_reset(POLICY_COUNTER_ALLOWED, reset);
}

/*
 * getDeniedReset - copy the denied counter, optionally resetting it.
 * @reset: non-zero resets the counter after copying it.
 * Returns the copied counter value.
 */
unsigned long getDeniedReset(int reset)
{
	return policy_counter_total_reset(POLICY_COUNTER_DENIED, reset);
}

/*
 * decision_metrics_add_context - add one worker's decision counters.
 * @ctx: worker context being sampled.
 * @data: struct decision_metrics_snapshot aggregate.
 * Returns nothing.
 */
static void decision_metrics_add_context(struct decision_context *ctx,
		void *data)
{
	struct decision_metrics_snapshot *snapshot = data;
	decision_metrics_t *metrics;
	struct decision_policy_counters *counters;

	if (ctx == NULL || snapshot == NULL || snapshot->metrics == NULL)
		return;

	metrics = snapshot->metrics;
	counters = &ctx->policy_counters;
	metrics->allowed_by_rule +=
		policy_counter_snapshot(&counters->allowed_by_rule,
					snapshot->reset);
	metrics->allowed_by_fallthrough +=
		policy_counter_snapshot(&counters->allowed_by_fallthrough,
					snapshot->reset);
	metrics->fallthrough_open +=
		policy_counter_snapshot(&counters->fallthrough_open,
					snapshot->reset);
	metrics->fallthrough_execute +=
		policy_counter_snapshot(&counters->fallthrough_execute,
					snapshot->reset);
	metrics->fallthrough_trusted +=
		policy_counter_snapshot(&counters->fallthrough_trusted,
					snapshot->reset);
	metrics->fallthrough_untrusted +=
		policy_counter_snapshot(&counters->fallthrough_untrusted,
					snapshot->reset);
	metrics->fallthrough_trust_unknown +=
		policy_counter_snapshot(&counters->fallthrough_trust_unknown,
					snapshot->reset);
	metrics->fallthrough_executable +=
		policy_counter_snapshot(&counters->fallthrough_executable,
					snapshot->reset);
	metrics->fallthrough_programmatic +=
		policy_counter_snapshot(&counters->fallthrough_programmatic,
					snapshot->reset);
	metrics->fallthrough_sharedlib +=
		policy_counter_snapshot(&counters->fallthrough_sharedlib,
					snapshot->reset);
	metrics->fallthrough_unknown_ftype +=
		policy_counter_snapshot(&counters->fallthrough_unknown_ftype,
					snapshot->reset);
	metrics->fallthrough_other_ftype +=
		policy_counter_snapshot(&counters->fallthrough_other_ftype,
					snapshot->reset);
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
	struct decision_metrics_snapshot snapshot = {
		.metrics = metrics,
		.reset = reset,
	};

	if (!metrics)
		return;

	memset(metrics, 0, sizeof(*metrics));
	decision_context_for_each(decision_metrics_add_context, &snapshot);
	metrics->ruleset_generation =
		atomic_load_explicit(&ruleset_generation,
				     memory_order_relaxed);
	metrics->ruleset_effective_since =
		(time_t)atomic_load_explicit(&ruleset_effective_since,
					     memory_order_relaxed);
}
