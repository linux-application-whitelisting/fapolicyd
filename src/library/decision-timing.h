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
 * Timing stage names are emitted as phase:operation[:child]. Lazy helpers
 * that can be driven by multiple code paths get separate phase-specific rows
 * so the report can distinguish rule evaluation from response logging/audit.
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
	DECISION_TIMING_STAGE_EVAL_MIME_DETECTION,
	DECISION_TIMING_STAGE_EVAL_MIME_FAST_CLASSIFICATION,
	DECISION_TIMING_STAGE_EVAL_MIME_GATHER_ELF,
	DECISION_TIMING_STAGE_EVAL_MIME_LIBMAGIC_FALLBACK,
	DECISION_TIMING_STAGE_RESPONSE_MIME_DETECTION,
	DECISION_TIMING_STAGE_RESPONSE_MIME_FAST_CLASSIFICATION,
	DECISION_TIMING_STAGE_RESPONSE_MIME_GATHER_ELF,
	DECISION_TIMING_STAGE_RESPONSE_MIME_LIBMAGIC_FALLBACK,
	DECISION_TIMING_STAGE_HASH_IMA,
	DECISION_TIMING_STAGE_HASH_SHA,
	DECISION_TIMING_STAGE_EVAL_TRUST_DB_LOOKUP,
	DECISION_TIMING_STAGE_EVAL_TRUST_DB_LOCK_WAIT,
	DECISION_TIMING_STAGE_EVAL_TRUST_DB_READ,
	DECISION_TIMING_STAGE_RESPONSE_TRUST_DB_LOOKUP,
	DECISION_TIMING_STAGE_RESPONSE_TRUST_DB_LOCK_WAIT,
	DECISION_TIMING_STAGE_RESPONSE_TRUST_DB_READ,
	DECISION_TIMING_STAGE_RULE_LOCK_WAIT,
	DECISION_TIMING_STAGE_RULE_EVALUATION,
	DECISION_TIMING_STAGE_RESPONSE_TOTAL,
	DECISION_TIMING_STAGE_SYSLOG_DEBUG_FORMAT,
	DECISION_TIMING_STAGE_AUDIT_RESPONSE_PREP,
	DECISION_TIMING_STAGE_FANOTIFY_RESPONSE_WRITE,
	DECISION_TIMING_STAGE_COUNT
} decision_timing_stage_t;

typedef enum {
	DECISION_TIMING_DRIVER_EVALUATION,
	DECISION_TIMING_DRIVER_RESPONSE,
	DECISION_TIMING_DRIVER_COUNT
} decision_timing_driver_t;

typedef enum {
	DECISION_TIMING_MIME_TOTAL,
	DECISION_TIMING_MIME_FAST_CLASSIFICATION,
	DECISION_TIMING_MIME_GATHER_ELF,
	DECISION_TIMING_MIME_LIBMAGIC_FALLBACK
} decision_timing_mime_stage_t;

typedef enum {
	DECISION_TIMING_TRUST_DB_TOTAL,
	DECISION_TIMING_TRUST_DB_LOCK_WAIT,
	DECISION_TIMING_TRUST_DB_READ
} decision_timing_trust_db_stage_t;

struct decision_timing_context {
	bool armed;
	unsigned int worker_id;
	decision_timing_driver_t driver;
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
void decision_timing_mime_stage_begin_slow(decision_timing_mime_stage_t stage,
		struct decision_timing_span *span);
void decision_timing_trust_db_stage_begin_slow(
		decision_timing_trust_db_stage_t stage,
		struct decision_timing_span *span);

#ifdef TEST_DECISION_TIMING_REPORT
struct decision_timing_test_stage_sample {
	decision_timing_stage_t stage;
	unsigned long long count;
	unsigned long long total_ns;
	unsigned long long max_ns;
	unsigned int bucket;
};

struct decision_timing_test_report_input {
	unsigned long long duration_ns;
	unsigned int max_queue_depth;
	unsigned int q_size;
};

void decision_timing_test_write_report(FILE *f,
	const struct decision_timing_test_stage_sample *samples,
	unsigned int sample_count,
	const struct decision_timing_test_report_input *input);
#endif

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
 * decision_timing_mime_stage_begin - start timing a MIME helper stage.
 * @stage: MIME helper substage.
 * @span: caller-owned span storage.
 * Returns nothing.
 */
static inline void decision_timing_mime_stage_begin(
		decision_timing_mime_stage_t stage,
		struct decision_timing_span *span)
{
	span->active = false;
	if (DECISION_TIMING_UNLIKELY(decision_timing_tls.armed))
		decision_timing_mime_stage_begin_slow(stage, span);
}

/*
 * decision_timing_trust_db_stage_begin - start timing a trust DB helper stage.
 * @stage: trust DB helper substage.
 * @span: caller-owned span storage.
 * Returns nothing.
 */
static inline void decision_timing_trust_db_stage_begin(
		decision_timing_trust_db_stage_t stage,
		struct decision_timing_span *span)
{
	span->active = false;
	if (DECISION_TIMING_UNLIKELY(decision_timing_tls.armed))
		decision_timing_trust_db_stage_begin_slow(stage, span);
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

/*
 * decision_timing_driver_push - set the current logical timing driver.
 * @driver: driver to use for nested lazy helper measurements.
 * Returns the previous driver.
 */
static inline decision_timing_driver_t decision_timing_driver_push(
		decision_timing_driver_t driver)
{
	decision_timing_driver_t previous = decision_timing_tls.driver;

	if (DECISION_TIMING_UNLIKELY(decision_timing_tls.armed))
		decision_timing_tls.driver = driver;

	return previous;
}

/*
 * decision_timing_driver_pop - restore the previous timing driver.
 * @driver: driver returned by decision_timing_driver_push().
 * Returns nothing.
 */
static inline void decision_timing_driver_pop(
		decision_timing_driver_t driver)
{
	if (DECISION_TIMING_UNLIKELY(decision_timing_tls.armed))
		decision_timing_tls.driver = driver;
}

#endif
