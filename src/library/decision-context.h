/*
 * decision-context.h - per-decision mutable state
 *
 * Copyright (c) 2026 Red Hat Inc.
 * All Rights Reserved.
 *
 * This software may be freely redistributed and/or modified under the
 * terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your
 * option) any later version.
 */

#ifndef DECISION_CONTEXT_HEADER
#define DECISION_CONTEXT_HEADER

#include <stdbool.h>
#include <stdatomic.h>
#include <sys/types.h>
#include <magic.h>
#include "decision-defer.h"
#include "lru.h"
#include "message.h"

struct udev;
struct conf;

struct file_device_cache {
	dev_t device;
	char *devname;
};

/*
 * decision_policy_counters - policy metrics updated by decision processing.
 *
 * Ruleset generation is deliberately not part of this block because rules can
 * be published before the daemon allocates the runtime decision context.
 */
struct decision_policy_counters {
	atomic_ulong allowed;
	atomic_ulong denied;
	atomic_ulong allowed_by_rule;
	atomic_ulong allowed_by_fallthrough;
	atomic_ulong fallthrough_open;
	atomic_ulong fallthrough_execute;
	atomic_ulong fallthrough_trusted;
	atomic_ulong fallthrough_untrusted;
	atomic_ulong fallthrough_trust_unknown;
	atomic_ulong fallthrough_executable;
	atomic_ulong fallthrough_programmatic;
	atomic_ulong fallthrough_sharedlib;
	atomic_ulong fallthrough_unknown_ftype;
	atomic_ulong fallthrough_other_ftype;
};

/*
 * decision_context - mutable state owned by one decision processor.
 *
 * There is only one active instance today. Keeping the hot-path caches,
 * logging buffer, counters, and defer queue behind this object makes the
 * ownership boundary explicit before multiple decision workers are added.
 */
struct decision_context {
	unsigned int worker_id;
	Queue *subject_cache;
	Queue *object_cache;
	char *working_buffer;
	bool object_cache_warned;
	atomic_uint early_subject_cache_evictions;
	atomic_uint building_tracer_evict_count;
	atomic_uint building_stale_evict_count;
	struct message_rate_limit building_tracer_rate_limit;
	struct message_rate_limit building_stale_rate_limit;
	struct decision_defer_queue defer_queue;
	struct decision_defer_metrics last_defer_metrics;
	struct decision_policy_counters policy_counters;
	/* File helpers keep mutable parser/cache state private to a worker. */
	struct udev *file_udev;
	magic_t magic_fast;
	magic_t magic_full;
	struct file_device_cache device_cache;
	/* Reporting walks registered worker contexts without owning them. */
	struct decision_context *report_next;
	bool report_registered;
};

typedef void (*decision_context_iter_fn)(struct decision_context *ctx,
		void *data);

struct decision_context *decision_context_current(void);
void decision_context_set_current(struct decision_context *ctx);
void decision_context_close_file_helpers(struct decision_context *ctx);
void decision_context_set_worker_id(struct decision_context *ctx,
		unsigned int worker_id);
struct decision_context *decision_context_create(const struct conf *config);
void decision_context_destroy(struct decision_context *ctx);
void decision_context_for_each(decision_context_iter_fn iter, void *data);

#endif
