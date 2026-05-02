/*
 * decision-timing.h - bounded decision timing diagnostics
 * Copyright (c) 2026 Red Hat Inc.
 * All Rights Reserved.
 *
 * This software may be freely redistributed and/or modified under the
 * terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2, or (at your option) any
 * later version.
 */

#ifndef DECISION_TIMING_HEADER
#define DECISION_TIMING_HEADER

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>
#include "conf.h"

#if defined(__GNUC__) || defined(__clang__)
#define DECISION_TIMING_UNLIKELY(x) __builtin_expect(!!(x), 0)
#else
#define DECISION_TIMING_UNLIKELY(x) (x)
#endif

/*
 * Timing stage names are emitted as phase:operation[:child].  Some lazy
 * helper operations are grouped under evaluation even when a rare response
 * path asks for them, because rules are the dominant driver and the report
 * is intended to explain the decision flow at a glance.
 */
typedef enum {
	DECISION_TIMING_STAGE_TOTAL,
	DECISION_TIMING_STAGE_QUEUE_WAIT,
	DECISION_TIMING_STAGE_EVENT_BUILD,
	DECISION_TIMING_STAGE_CACHE_FLUSH,
	DECISION_TIMING_STAGE_PROC_FINGERPRINT,
	DECISION_TIMING_STAGE_PROC_STATUS_EXE_LOOKUP,
	DECISION_TIMING_STAGE_FD_STAT,
	DECISION_TIMING_STAGE_FD_PATH_RESOLUTION,
	DECISION_TIMING_STAGE_TYPE_ELF_DETECTION,
	DECISION_TIMING_STAGE_MIME_FAST_CLASSIFICATION,
	DECISION_TIMING_STAGE_MIME_GATHER_ELF,
	DECISION_TIMING_STAGE_LIBMAGIC_FALLBACK,
	DECISION_TIMING_STAGE_HASH_IMA,
	DECISION_TIMING_STAGE_TRUST_DB_LOOKUP,
	DECISION_TIMING_STAGE_TRUST_DB_LOCK_WAIT,
	DECISION_TIMING_STAGE_TRUST_DB_READ,
	DECISION_TIMING_STAGE_RULE_LOCK_WAIT,
	DECISION_TIMING_STAGE_RULE_EVALUATION,
	DECISION_TIMING_STAGE_RESPONSE_TOTAL,
	DECISION_TIMING_STAGE_SYSLOG_DEBUG_FORMAT,
	DECISION_TIMING_STAGE_AUDIT_RESPONSE_PREP,
	DECISION_TIMING_STAGE_FANOTIFY_RESPONSE_WRITE,
	DECISION_TIMING_STAGE_COUNT
} decision_timing_stage_t;

struct decision_timing_context {
	bool armed;
	unsigned int worker_id;
	uint64_t total_start_ns;
};

struct decision_timing_span {
	bool active;
	decision_timing_stage_t stage;
	uint64_t start_ns;
};

typedef unsigned int (*decision_timing_queue_depth_reset_fn)(void *ctx);
typedef unsigned int (*decision_timing_queue_depth_restore_fn)(void *ctx,
		unsigned int saved);

extern __thread struct decision_timing_context decision_timing_tls;

void decision_timing_apply_config(timing_collection_t mode);
void decision_timing_set_queue_depth_hooks(
		decision_timing_queue_depth_reset_fn reset,
		decision_timing_queue_depth_restore_fn restore,
		void *ctx);
void decision_timing_signal_request(report_intent_t intent, pid_t pid,
		uid_t uid);
void decision_timing_process_requests(const conf_t *config);
void decision_timing_control_report(FILE *f, const conf_t *config);
void decision_timing_history_report(FILE *f);
void decision_timing_decision_begin(unsigned int worker_id);
void decision_timing_decision_end(void);
uint64_t decision_timing_queue_enqueue_time(void);
void decision_timing_queue_dequeued(uint64_t enqueue_ns);
void decision_timing_stage_begin_slow(decision_timing_stage_t stage,
		struct decision_timing_span *span);
void decision_timing_stage_end_slow(struct decision_timing_span *span);

/*
 * decision_timing_stage_begin - start timing a stage for this event.
 * @stage: stage being measured.
 * @span: caller-owned span storage.
 * Returns nothing.
 *
 * The armed flag is copied to thread-local state once per dequeued event.
 * When the event is unarmed this inline fast path does not call clock_gettime,
 * update histograms, or touch timing counters.
 */
static inline void decision_timing_stage_begin(decision_timing_stage_t stage,
		struct decision_timing_span *span)
{
	span->active = false;
	if (DECISION_TIMING_UNLIKELY(decision_timing_tls.armed))
		decision_timing_stage_begin_slow(stage, span);
}

/*
 * decision_timing_stage_end - finish timing a stage for this event.
 * @span: span previously passed to decision_timing_stage_begin().
 * Returns nothing.
 */
static inline void decision_timing_stage_end(struct decision_timing_span *span)
{
	if (DECISION_TIMING_UNLIKELY(span->active))
		decision_timing_stage_end_slow(span);
}

#endif
