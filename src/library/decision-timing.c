/*
 * decision-timing.c - bounded decision timing diagnostics
 * Copyright (c) 2026 Red Hat Inc.
 * All Rights Reserved.
 *
 * This software may be freely redistributed and/or modified under the
 * terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2, or (at your option) any
 * later version.
 */

/*
 * Overview
 * --------
 *
 * Decision timing is an opt-in diagnostic window for explaining where
 * fapolicyd spends time while callers are blocked on fanotify permission
 * events.  It is meant for QE, stress runs, field diagnosis and sizing work,
 * not for permanent always-on tracing.
 *
 * Normal operation keeps timing disabled.  When disabled, the decision path
 * copies one armed flag into thread-local state for each dequeued event, and
 * the inline stage helpers return without calling clock_gettime(), updating
 * histograms, or touching shared counters.  A privileged manual start request
 * resets the bounded metric blocks and arms collection.  A stop request
 * disarms collection, snapshots the aggregates and writes TIMING_REPORT.
 * Queue wait is measured separately from dequeue-to-reply decision time so
 * reports can distinguish backlog from slow work inside a decision.
 *
 * Each worker owns a padded block of stage metrics.  A stage records only a
 * count, total nanoseconds, max nanoseconds and fixed latency buckets.  The
 * daemon intentionally does not store one record per decision; that keeps
 * memory bounded for stress tests that may generate millions of events and
 * avoids turning the measurement system into the workload.
 *
 * Stage rows are operation histograms.  They may be nested and some helpers
 * are lazy, so rows are not expected to add up to decision:total.  Lazy
 * helper costs that can be caused by either rule evaluation or response
 * formatting use a thread-local "driver" so the report can show evaluation
 * versus response attribution.
 *
 * The report path does the expensive work after collection stops: aggregate
 * worker blocks, rank stages, derive bucket percentiles and emit short
 * observations about queueing, helper cost, tail latency and debug-heavy
 * response formatting.
 *
 * Assumption: normal deployments leave timing_collection=off.  Manual timing
 * runs are short diagnostic windows, and worker-local blocks are kept from
 * the beginning so future decision-worker pools do not contend on one global
 * histogram.
 */

#include "config.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include "decision-timing.h"
#include "message.h"
#include "paths.h"

#define DECISION_TIMING_MAX_WORKERS 32
#define DECISION_TIMING_BUCKETS 14
#define DECISION_TIMING_STAGE_WIDTH 48
#define DECISION_TIMING_PHASE_WIDTH 16
#define DECISION_TIMING_HELPER_WIDTH 44
#define DECISION_TIMING_DRIVER_WIDTH 32
#define DECISION_TIMING_TAIL_STAGE_LIMIT 5
#define NSEC_PER_SEC 1000000000ULL
#define IDLE_WORKLOAD_RATE_MULTIPLIER 2.0
#define RESPONSE_FORMATTING_DOMINANT 50.0
#define TRUST_DB_LOCK_TINY_SHARE 1.0
#define HASH_RARE_SHARE 10.0

/* Fixed-size aggregate for one stage in one worker's timing block. */
struct decision_timing_stage_metrics {
	atomic_ullong count;
	atomic_ullong total_ns;
	atomic_ullong max_ns;
	atomic_ullong buckets[DECISION_TIMING_BUCKETS];
};

/*
 * Keep worker blocks cache-line separated so future decision workers can
 * update their own histograms without false sharing.
 */
struct decision_timing_worker_block {
	struct decision_timing_stage_metrics stages[DECISION_TIMING_STAGE_COUNT];
} __attribute__((aligned(64)));

struct decision_timing_stage_snapshot {
	unsigned long long count;
	unsigned long long total_ns;
	unsigned long long max_ns;
	unsigned long long buckets[DECISION_TIMING_BUCKETS];
};

struct decision_timing_stage_order {
	unsigned int stages[DECISION_TIMING_STAGE_COUNT];
	unsigned int count;
};

struct decision_timing_report_ctx {
	FILE *f;
	const struct decision_timing_stage_snapshot *totals;
	const struct decision_timing_stage_order *order;
	unsigned long long decisions;
	unsigned long long duration_ns;
	unsigned int max_queue_depth;
	unsigned int q_size;
};

struct decision_timing_named_stage {
	decision_timing_stage_t stage;
	const char *name;
};

struct decision_timing_helper_row {
	const char *name;
	decision_timing_stage_t eval_stage;
	decision_timing_stage_t response_stage;
	bool by_driver;
};

struct decision_timing_tail_row {
	decision_timing_stage_t stage;
	unsigned long long over_10ms;
	unsigned long long over_50ms;
};

enum decision_timing_stop_reason {
	DECISION_TIMING_STOP_MANUAL,
	DECISION_TIMING_STOP_OVERFLOW
};

static const unsigned long long
bucket_limits_ns[DECISION_TIMING_BUCKETS - 1] = {
	1000ULL,
	5000ULL,
	10000ULL,
	50000ULL,
	100000ULL,
	500000ULL,
	1000000ULL,
	5000000ULL,
	10000000ULL,
	25000000ULL,
	50000000ULL,
	100000000ULL,
	250000000ULL
};

static const char *bucket_names[DECISION_TIMING_BUCKETS] = {
	"<=1us",
	"<=5us",
	"<=10us",
	"<=50us",
	"<=100us",
	"<=500us",
	"<=1ms",
	"<=5ms",
	"<=10ms",
	"<=25ms",
	"<=50ms",
	"<=100ms",
	"<=250ms",
	">250ms"
};

static const char *stage_names[DECISION_TIMING_STAGE_COUNT] = {
	"decision:total",
	"time_in_queue:total",
	"event_build:total",
	"event_build:cache_flush",
	"event_build:proc_fingerprint",
	"evaluation:proc_detail_lookup",
	"event_build:fd_stat",
	"evaluation:fd_path_resolution",
	"evaluation:mime_detection:total",
	"evaluation:mime_detection:fast_classification",
	"evaluation:mime_detection:gather_elf",
	"evaluation:mime_detection:libmagic_fallback",
	"response:mime_detection:total",
	"response:mime_detection:fast_classification",
	"response:mime_detection:gather_elf",
	"response:mime_detection:libmagic_fallback",
	"evaluation:hash_ima:total",
	"evaluation:hash_sha:total",
	"evaluation:trust_db_lookup:total",
	"evaluation:trust_db_lookup:lock_wait",
	"evaluation:trust_db_lookup:read",
	"response:trust_db_lookup:total",
	"response:trust_db_lookup:lock_wait",
	"response:trust_db_lookup:read",
	"evaluation:lock_wait",
	"evaluation:total",
	"response:total",
	"response:syslog_debug_format:total",
	"response:audit_metadata:total",
	"response:fanotify_write"
};

/*
 * decision_timing_mode_name - return a timing mode name.
 * @mode: timing_collection_t value to describe.
 * Returns a printable mode name.
 */
static const char *decision_timing_mode_name(timing_collection_t mode)
{
	switch (mode) {
	case TIMING_COLLECTION_OFF:
		return "off";
	case TIMING_COLLECTION_MANUAL:
		return "manual";
	}

	return "unknown";
}

/*
 * config_timing_mode - atomically read the active timing mode.
 * @config: active daemon configuration.
 * Returns the configured timing collection mode.
 */
static timing_collection_t config_timing_mode(const conf_t *config)
{
	return __atomic_load_n(&config->timing_collection, __ATOMIC_RELAXED);
}

static struct decision_timing_worker_block workers[DECISION_TIMING_MAX_WORKERS];
static atomic_bool timing_armed;
/*
 * active_workers is one today.  The storage and report aggregation already
 * support more workers so timing remains local when the decision path grows.
 */
static atomic_uint active_workers = 1;
static atomic_uint arm_requests;
static atomic_uint stop_requests;
static atomic_int arm_request_pid = -1;
static atomic_int arm_request_uid = -1;
static atomic_int stop_request_pid = -1;
static atomic_int stop_request_uid = -1;
static atomic_long last_arm_time;
static atomic_long last_stop_time;
static atomic_long run_start_time;
static atomic_ullong run_start_mono_ns;
static atomic_ullong run_stop_mono_ns;
static atomic_uint run_max_queue_depth;
static atomic_uint saved_max_queue_depth;
static atomic_bool queue_depth_active;
static atomic_bool queue_depth_restore_requests;
static decision_timing_queue_depth_reset_fn queue_depth_reset;
static decision_timing_queue_depth_restore_fn queue_depth_restore;
static void *queue_depth_ctx;
static atomic_uint overflow_stop_requests;
static atomic_int stop_reason = DECISION_TIMING_STOP_MANUAL;
static atomic_int stop_reason_stage = -1;
static atomic_bool missing_helper_driver_logged;

__thread struct decision_timing_context decision_timing_tls;

/*
 * ns_now - read monotonic time in nanoseconds.
 * Returns monotonic nanoseconds, or 0 if the clock cannot be read.
 */
static uint64_t ns_now(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts))
		return 0;

	return (uint64_t)ts.tv_sec * NSEC_PER_SEC + (uint64_t)ts.tv_nsec;
}

/*
 * bucket_for_duration - find the latency bucket for a duration.
 * @ns: elapsed nanoseconds.
 * Returns the bucket index.
 */
static unsigned int bucket_for_duration(uint64_t ns)
{
	unsigned int i;

	for (i = 0; i < DECISION_TIMING_BUCKETS - 1; i++) {
		if (ns <= bucket_limits_ns[i])
			return i;
	}

	return DECISION_TIMING_BUCKETS - 1;
}

/*
 * update_max - atomically retain the highest observed value.
 * @max: metric to update.
 * @value: candidate maximum.
 * Returns nothing.
 */
static void update_max(atomic_ullong *max, unsigned long long value)
{
	unsigned long long old;

	old = atomic_load_explicit(max, memory_order_relaxed);
	while (value > old &&
	       !atomic_compare_exchange_weak_explicit(max, &old, value,
			memory_order_relaxed, memory_order_relaxed))
		;
}

/*
 * metric_add_unless_overflow - add to a counter without wrapping.
 * @value: counter to update.
 * @add: value to add.
 * Returns true on success, false if the addition would overflow.
 */
static bool metric_add_unless_overflow(atomic_ullong *value,
		unsigned long long add)
{
	unsigned long long old;

	old = atomic_load_explicit(value, memory_order_relaxed);
	for (;;) {
		if (old > ULLONG_MAX - add)
			return false;
		if (atomic_compare_exchange_weak_explicit(value, &old,
				old + add, memory_order_relaxed,
				memory_order_relaxed))
			return true;
	}
}

/*
 * decision_timing_overflow_stop - stop collection before counters wrap.
 * @stage: stage whose counters would overflow.
 * Returns nothing.
 *
 * The report is written from decision_timing_process_requests() so the hot
 * path only disarms collection and records why the run stopped.
 */
static void decision_timing_overflow_stop(decision_timing_stage_t stage)
{
	decision_timing_tls.armed = false;
	if (!atomic_exchange_explicit(&timing_armed, false,
			memory_order_acq_rel))
		return;

	atomic_store_explicit(&last_stop_time, (long)time(NULL),
			      memory_order_relaxed);
	atomic_store_explicit(&run_stop_mono_ns, ns_now(),
			      memory_order_relaxed);
	atomic_store_explicit(&stop_reason, DECISION_TIMING_STOP_OVERFLOW,
			      memory_order_relaxed);
	atomic_store_explicit(&stop_reason_stage, (int)stage,
			      memory_order_relaxed);
	atomic_fetch_add_explicit(&overflow_stop_requests, 1,
				  memory_order_relaxed);
	msg(LOG_WARNING,
	    "Decision timing stopped because %s counters would overflow",
	    stage_names[stage]);
}

/*
 * record_stage - update the current worker's aggregate for one stage.
 * @stage: stage to update.
 * @ns: elapsed nanoseconds.
 * Returns nothing.
 */
static void record_stage(decision_timing_stage_t stage, uint64_t ns)
{
	struct decision_timing_stage_metrics *metrics;
	unsigned int bucket;
	unsigned int worker_id;

	if (stage >= DECISION_TIMING_STAGE_COUNT)
		return;
	worker_id = decision_timing_tls.worker_id;
	if (worker_id >= DECISION_TIMING_MAX_WORKERS)
		return;

	metrics = &workers[worker_id].stages[stage];
	bucket = bucket_for_duration(ns);
	if (!metric_add_unless_overflow(&metrics->count, 1))
		goto overflow;
	if (!metric_add_unless_overflow(&metrics->total_ns, ns))
		goto overflow;
	if (!metric_add_unless_overflow(&metrics->buckets[bucket], 1))
		goto overflow;
	update_max(&metrics->max_ns, ns);
	return;

overflow:
	decision_timing_overflow_stop(stage);
}

/*
 * reset_worker_blocks - clear all per-worker timing aggregates.
 * Returns nothing.
 */
static void reset_worker_blocks(void)
{
	unsigned int worker, stage, bucket;

	for (worker = 0; worker < DECISION_TIMING_MAX_WORKERS; worker++) {
		for (stage = 0; stage < DECISION_TIMING_STAGE_COUNT; stage++) {
			struct decision_timing_stage_metrics *metrics =
				&workers[worker].stages[stage];

			atomic_store_explicit(&metrics->count, 0,
					      memory_order_relaxed);
			atomic_store_explicit(&metrics->total_ns, 0,
					      memory_order_relaxed);
			atomic_store_explicit(&metrics->max_ns, 0,
					      memory_order_relaxed);
			for (bucket = 0; bucket < DECISION_TIMING_BUCKETS;
			     bucket++)
				atomic_store_explicit(&metrics->buckets[bucket],
						      0,
						      memory_order_relaxed);
		}
	}
}

/*
 * snapshot_stage - add one stage's metrics into an aggregate snapshot.
 * @dst: aggregate snapshot to update.
 * @src: live per-worker metrics.
 * Returns nothing.
 */
static void snapshot_stage(struct decision_timing_stage_snapshot *dst,
		const struct decision_timing_stage_metrics *src)
{
	unsigned int i;
	unsigned long long max;

	dst->count += atomic_load_explicit(&src->count, memory_order_relaxed);
	dst->total_ns += atomic_load_explicit(&src->total_ns,
					      memory_order_relaxed);
	max = atomic_load_explicit(&src->max_ns, memory_order_relaxed);
	if (max > dst->max_ns)
		dst->max_ns = max;
	for (i = 0; i < DECISION_TIMING_BUCKETS; i++)
		dst->buckets[i] += atomic_load_explicit(&src->buckets[i],
							memory_order_relaxed);
}

/*
 * open_timing_report - open timing report file for overwrite without symlinks.
 * Return codes:
 * >= 0 - writable file descriptor for TIMING_REPORT
 *  -1 - open or validation failed (errno set)
 */
static int open_timing_report(void)
{
	struct stat st;
	int tfd;

	tfd = open(TIMING_REPORT,
		O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW,
		0640);
	if (tfd < 0)
		return -1;

	if (fstat(tfd, &st) == -1 || !S_ISREG(st.st_mode)) {
		close(tfd);
		errno = EINVAL;
		return -1;
	}

	return tfd;
}

/*
 * format_report_time - format a wall-clock control timestamp.
 * @when: timestamp to format.
 * @buf: destination buffer.
 * @buf_len: size of @buf.
 * Returns @buf.
 */
static const char *format_report_time(long when, char *buf, size_t buf_len)
{
	struct tm tm;
	time_t t = (time_t)when;

	if (when <= 0) {
		strncpy(buf, "never", buf_len - 1);
		buf[buf_len - 1] = 0;
		return buf;
	}

	if (localtime_r(&t, &tm) == NULL ||
	    strftime(buf, buf_len, "%Y-%m-%d %H:%M:%S %z", &tm) == 0) {
		strncpy(buf, "unavailable", buf_len - 1);
		buf[buf_len - 1] = 0;
	}

	return buf;
}

/*
 * format_count - format an integer count with thousands separators.
 * @value: count to format.
 * @buf: destination buffer.
 * @buf_len: size of @buf.
 * Returns nothing.
 */
static void format_count(unsigned long long value, char *buf, size_t buf_len)
{
	char tmp[32], grouped[48];
	size_t src, dst, group = 0;

	if (buf_len == 0)
		return;

	snprintf(tmp, sizeof(tmp), "%llu", value);
	src = strlen(tmp);
	dst = src + (src ? (src - 1) / 3 : 0);
	if (dst >= sizeof(grouped)) {
		strncpy(buf, tmp, buf_len - 1);
		buf[buf_len - 1] = 0;
		return;
	}

	grouped[dst] = 0;
	while (src > 0) {
		if (group == 3) {
			grouped[--dst] = ',';
			group = 0;
		}
		grouped[--dst] = tmp[--src];
		group++;
	}

	strncpy(buf, grouped, buf_len - 1);
	buf[buf_len - 1] = 0;
}

/*
 * format_scaled_time - format a scaled time value with compact precision.
 * @value: scaled value.
 * @unit: unit suffix.
 * @buf: destination buffer.
 * @buf_len: size of @buf.
 * Returns nothing.
 */
static void format_scaled_time(double value, const char *unit, char *buf,
		size_t buf_len)
{
	if (value >= 100.0)
		snprintf(buf, buf_len, "%.0f %s", value, unit);
	else if (value >= 10.0)
		snprintf(buf, buf_len, "%.1f %s", value, unit);
	else
		snprintf(buf, buf_len, "%.2f %s", value, unit);
}

/*
 * format_human_duration - format nanoseconds for human report output.
 * @ns: duration in nanoseconds.
 * @buf: destination buffer.
 * @buf_len: size of @buf.
 * Returns nothing.
 */
static void format_human_duration(unsigned long long ns, char *buf,
		size_t buf_len)
{
	if (ns < 1000ULL)
		snprintf(buf, buf_len, "%llu ns", ns);
	else if (ns < 1000000ULL)
		format_scaled_time((double)ns / 1000.0, "us", buf, buf_len);
	else if (ns < 1000000000ULL)
		format_scaled_time((double)ns / 1000000.0, "ms", buf,
				   buf_len);
	else
		format_scaled_time((double)ns / 1000000000.0, "s", buf,
				   buf_len);
}

/*
 * format_hms_duration - format nanoseconds as H:MM:SS.
 * @ns: duration in nanoseconds.
 * @buf: destination buffer.
 * @buf_len: size of @buf.
 * Returns nothing.
 */
static void format_hms_duration(unsigned long long ns, char *buf,
		size_t buf_len)
{
	unsigned long long seconds = ns / 1000000000ULL;
	unsigned long long hours = seconds / 3600ULL;
	unsigned long long minutes = (seconds % 3600ULL) / 60ULL;

	seconds %= 60ULL;
	snprintf(buf, buf_len, "%llu:%02llu:%02llu", hours, minutes,
		 seconds);
}

/*
 * bucket_cumulative_count - count observations up to a latency bucket.
 * @src: snapshot to inspect.
 * @bucket: inclusive bucket index.
 * Returns the cumulative count.
 */
static unsigned long long bucket_cumulative_count(
		const struct decision_timing_stage_snapshot *src,
		unsigned int bucket)
{
	unsigned long long count = 0;
	unsigned int i;

	if (bucket >= DECISION_TIMING_BUCKETS)
		bucket = DECISION_TIMING_BUCKETS - 1;

	for (i = 0; i <= bucket; i++)
		count += src->buckets[i];

	return count;
}

/*
 * percent_of_count - calculate a percentage from two counts.
 * @value: numerator.
 * @total: denominator.
 * Returns the percentage, or zero when @total is zero.
 */
static double percent_of_count(unsigned long long value,
		unsigned long long total)
{
	if (total == 0)
		return 0.0;

	return ((double)value * 100.0) / (double)total;
}

/*
 * percentile_bucket - estimate a percentile from fixed latency buckets.
 * @src: snapshot to inspect.
 * @percentile: percentile to estimate, from 1 to 100.
 * Returns a human bucket label.
 */
static const char *percentile_bucket(
		const struct decision_timing_stage_snapshot *src,
		unsigned int percentile)
{
	unsigned long long cumulative = 0, target;
	unsigned int i;

	if (src->count == 0)
		return "n/a";

	if (percentile > 100)
		percentile = 100;
	if (percentile == 0)
		percentile = 1;

	target = (src->count * percentile + 99) / 100;
	if (target == 0)
		target = 1;

	for (i = 0; i < DECISION_TIMING_BUCKETS; i++) {
		cumulative += src->buckets[i];
		if (cumulative >= target)
			return bucket_names[i];
	}

	return bucket_names[DECISION_TIMING_BUCKETS - 1];
}

/*
 * percentile_bucket_index - estimate a percentile bucket index.
 * @src: snapshot to inspect.
 * @percentile: percentile to estimate, from 1 to 100.
 * Returns a bucket index, or DECISION_TIMING_BUCKETS when no samples exist.
 */
static unsigned int percentile_bucket_index(
		const struct decision_timing_stage_snapshot *src,
		unsigned int percentile)
{
	unsigned long long cumulative = 0, target;
	unsigned int i;

	if (src->count == 0)
		return DECISION_TIMING_BUCKETS;

	if (percentile > 100)
		percentile = 100;
	if (percentile == 0)
		percentile = 1;

	target = (src->count * percentile + 99) / 100;
	if (target == 0)
		target = 1;

	for (i = 0; i < DECISION_TIMING_BUCKETS; i++) {
		cumulative += src->buckets[i];
		if (cumulative >= target)
			return i;
	}

	return DECISION_TIMING_BUCKETS - 1;
}

/*
 * bucket_count_above - count observations above a latency threshold bucket.
 * @src: snapshot to inspect.
 * @bucket: bucket at or below the threshold.
 * Returns observations in buckets above @bucket.
 */
static unsigned long long bucket_count_above(
		const struct decision_timing_stage_snapshot *src,
		unsigned int bucket)
{
	if (src->count == 0)
		return 0;
	if (bucket >= DECISION_TIMING_BUCKETS - 1)
		return 0;

	return src->count - bucket_cumulative_count(src, bucket);
}

/*
 * sample_has_tail - test whether a sample has high-end tail observations.
 * @src: snapshot to inspect.
 * Returns true if any observation is above 10ms.
 */
static bool sample_has_tail(const struct decision_timing_stage_snapshot *src)
{
	return bucket_count_above(src, 8) != 0;
}

/*
 * write_tail_counts - write compact high-end tail counts.
 * @f: output stream.
 * @src: snapshot to inspect.
 * @label: true to prefix the line with "tail:".
 * Returns nothing.
 */
static void write_tail_counts(FILE *f,
		const struct decision_timing_stage_snapshot *src, bool label)
{
	static const struct {
		const char *name;
		unsigned int bucket;
	} tails[] = {
		{ ">10ms", 8 },
		{ ">25ms", 9 },
		{ ">50ms", 10 },
		{ ">100ms", 11 },
		{ ">250ms", 12 },
	};
	char count[32];
	unsigned int i;
	bool any = false;

	if (label)
		fprintf(f, "tail:");
	for (i = 0; i < sizeof(tails) / sizeof(tails[0]); i++) {
		unsigned long long value = bucket_count_above(src,
							      tails[i].bucket);

		if (value == 0)
			continue;
		format_count(value, count, sizeof(count));
		fprintf(f, "%s%s %s/%.1f%%",
			any ? ", " : (label ? " " : ""),
			tails[i].name, count, percent_of_count(value,
			src->count));
		any = true;
	}
	fputc('\n', f);
}

/*
 * write_tail_summary - write labeled high-end tail counts.
 * @f: output stream.
 * @src: snapshot to inspect.
 * Returns nothing.
 */
static void write_tail_summary(FILE *f,
		const struct decision_timing_stage_snapshot *src)
{
	write_tail_counts(f, src, true);
}

/*
 * sort_stages_by_total - rank observed stages by total time descending.
 * @totals: aggregate stage snapshots.
 * @order: output order.
 * Returns nothing.
 */
static void sort_stages_by_total(
		const struct decision_timing_stage_snapshot *totals,
		struct decision_timing_stage_order *order)
{
	unsigned int i, j;

	order->count = 0;
	for (i = 0; i < DECISION_TIMING_STAGE_COUNT; i++) {
		if (totals[i].count)
			order->stages[order->count++] = i;
	}

	for (i = 0; i < order->count; i++) {
		for (j = i + 1; j < order->count; j++) {
			unsigned int left = order->stages[i];
			unsigned int right = order->stages[j];

			if (totals[right].total_ns > totals[left].total_ns) {
				order->stages[i] = right;
				order->stages[j] = left;
			}
		}
	}
}

/*
 * find_slowest_stage - find the observed stage with the largest max.
 * @totals: aggregate stage snapshots.
 * @stage_out: output stage index.
 * Returns true when a stage was found.
 */
static bool find_slowest_stage(
		const struct decision_timing_stage_snapshot *totals,
		unsigned int *stage_out)
{
	unsigned int i, stage = 0;
	unsigned long long max = 0;

	for (i = 1; i < DECISION_TIMING_STAGE_COUNT; i++) {
		if (totals[i].count && totals[i].max_ns > max) {
			max = totals[i].max_ns;
			stage = i;
		}
	}

	if (stage == 0)
		return false;

	*stage_out = stage;
	return true;
}

/*
 * stage_observed - test whether a stage has any samples.
 * @ctx: report context.
 * @stage: stage to inspect.
 * Returns true when the stage has at least one observation.
 */
static bool stage_observed(const struct decision_timing_report_ctx *ctx,
		decision_timing_stage_t stage)
{
	if (stage >= DECISION_TIMING_STAGE_COUNT)
		return false;

	return ctx->totals[stage].count != 0;
}

/*
 * stage_avg_ns - calculate average observed latency for a stage.
 * @sample: stage aggregate.
 * Returns average nanoseconds, or zero for an empty stage.
 */
static unsigned long long stage_avg_ns(
		const struct decision_timing_stage_snapshot *sample)
{
	if (sample->count == 0)
		return 0;

	return sample->total_ns / sample->count;
}

/*
 * stage_snapshot_add - add one stage snapshot to an aggregate.
 * @dst: aggregate snapshot to update.
 * @src: snapshot to add.
 * Returns nothing.
 */
static void stage_snapshot_add(struct decision_timing_stage_snapshot *dst,
		const struct decision_timing_stage_snapshot *src)
{
	unsigned int i;

	dst->count += src->count;
	dst->total_ns += src->total_ns;
	if (src->max_ns > dst->max_ns)
		dst->max_ns = src->max_ns;
	for (i = 0; i < DECISION_TIMING_BUCKETS; i++)
		dst->buckets[i] += src->buckets[i];
}

/*
 * helper_snapshot - build a combined snapshot for one helper row.
 * @ctx: report context.
 * @row: helper row to aggregate.
 * @dst: output aggregate.
 * Returns nothing.
 */
static void helper_snapshot(const struct decision_timing_report_ctx *ctx,
		const struct decision_timing_helper_row *row,
		struct decision_timing_stage_snapshot *dst)
{
	memset(dst, 0, sizeof(*dst));
	if (row->eval_stage < DECISION_TIMING_STAGE_COUNT)
		stage_snapshot_add(dst, &ctx->totals[row->eval_stage]);
	if (row->response_stage < DECISION_TIMING_STAGE_COUNT)
		stage_snapshot_add(dst, &ctx->totals[row->response_stage]);
}

/*
 * stage_calls_per_decision - calculate a stage's calls per decision.
 * @ctx: report context.
 * @stage: stage to inspect.
 * Returns calls per timed decision.
 */
static double stage_calls_per_decision(
		const struct decision_timing_report_ctx *ctx,
		decision_timing_stage_t stage)
{
	if (ctx->decisions == 0)
		return 0.0;

	return (double)ctx->totals[stage].count / (double)ctx->decisions;
}

/*
 * sample_calls_per_decision - calculate calls per decision for a snapshot.
 * @ctx: report context.
 * @sample: aggregate sample.
 * Returns calls per timed decision.
 */
static double sample_calls_per_decision(
		const struct decision_timing_report_ctx *ctx,
		const struct decision_timing_stage_snapshot *sample)
{
	if (ctx->decisions == 0)
		return 0.0;

	return (double)sample->count / (double)ctx->decisions;
}

/*
 * stage_amortized_ns - calculate stage time amortized over all decisions.
 * @ctx: report context.
 * @stage: stage to inspect.
 * Returns nanoseconds per timed decision.
 */
static unsigned long long stage_amortized_ns(
		const struct decision_timing_report_ctx *ctx,
		decision_timing_stage_t stage)
{
	if (ctx->decisions == 0)
		return 0;

	return ctx->totals[stage].total_ns / ctx->decisions;
}

/*
 * sample_amortized_ns - calculate sample time amortized over all decisions.
 * @ctx: report context.
 * @sample: aggregate sample.
 * Returns nanoseconds per timed decision.
 */
static unsigned long long sample_amortized_ns(
		const struct decision_timing_report_ctx *ctx,
		const struct decision_timing_stage_snapshot *sample)
{
	if (ctx->decisions == 0)
		return 0;

	return sample->total_ns / ctx->decisions;
}

/*
 * stage_time_share - calculate what share one stage is of another stage.
 * @ctx: report context.
 * @part: stage that contributes time.
 * @whole: stage that represents the larger total.
 * Returns percentage share, or zero when the whole stage has no total.
 */
static double stage_time_share(const struct decision_timing_report_ctx *ctx,
		decision_timing_stage_t part, decision_timing_stage_t whole)
{
	if (ctx->totals[whole].total_ns == 0)
		return 0.0;

	return ((double)ctx->totals[part].total_ns * 100.0) /
		(double)ctx->totals[whole].total_ns;
}

/*
 * find_largest_named_stage - find observed named row with largest total time.
 * @ctx: report context.
 * @rows: stage list to inspect.
 * @row_count: number of entries in @rows.
 * @row_out: selected row index.
 * Returns true when an observed row was found.
 */
static bool find_largest_named_stage(
		const struct decision_timing_report_ctx *ctx,
		const struct decision_timing_named_stage *rows,
		unsigned int row_count, unsigned int *row_out)
{
	unsigned int i, best = 0;
	unsigned long long total = 0;

	for (i = 0; i < row_count; i++) {
		decision_timing_stage_t stage = rows[i].stage;

		if (!stage_observed(ctx, stage))
			continue;
		if (ctx->totals[stage].total_ns > total) {
			total = ctx->totals[stage].total_ns;
			best = i;
		}
	}

	if (total == 0)
		return false;

	*row_out = best;
	return true;
}

/*
 * write_overall_latency - write human total decision latency summary.
 * @f: output stream.
 * @total: total decision latency snapshot.
 * Returns nothing.
 */
static void write_overall_latency(FILE *f,
		const struct decision_timing_stage_snapshot *total)
{
	char avg[32], max[32];
	unsigned long long avg_ns = 0;

	fprintf(f, "\nOverall decision latency:\n");
	if (total->count == 0) {
		fprintf(f, "  no decisions observed\n");
		return;
	}

	avg_ns = total->total_ns / total->count;
	format_human_duration(avg_ns, avg, sizeof(avg));
	format_human_duration(total->max_ns, max, sizeof(max));
	fprintf(f, "  avg %s, max %s\n", avg, max);
	fprintf(f, "  p50 bucket %s, p95 bucket %s, p99 bucket %s\n",
		percentile_bucket(total, 50),
		percentile_bucket(total, 95),
		percentile_bucket(total, 99));
	fprintf(f,
		"  <=50us %.1f%%, <=100us %.1f%%, <=500us %.1f%%, "
		"<=1ms %.1f%%, >10ms %.1f%%\n",
		percent_of_count(bucket_cumulative_count(total, 3),
				 total->count),
		percent_of_count(bucket_cumulative_count(total, 4),
				 total->count),
		percent_of_count(bucket_cumulative_count(total, 5),
				 total->count),
		percent_of_count(bucket_cumulative_count(total, 6),
				 total->count),
		percent_of_count(bucket_count_above(total, 8), total->count));
	if (sample_has_tail(total)) {
		fprintf(f, "  ");
		write_tail_summary(f, total);
	}
}

/*
 * write_queueing - write queue wait summary.
 * @ctx: report context.
 * Returns nothing.
 */
static void write_queueing(const struct decision_timing_report_ctx *ctx)
{
	const struct decision_timing_stage_snapshot *queue =
		&ctx->totals[DECISION_TIMING_STAGE_QUEUE_WAIT];
	char avg[32], max[32], total[32];

	fprintf(ctx->f, "\nQueueing:\n");
	if (queue->count == 0) {
		fprintf(ctx->f, "  not observed\n");
		fprintf(ctx->f, "  max queue depth: %u\n",
			ctx->max_queue_depth);
		return;
	}

	format_human_duration(stage_avg_ns(queue), avg, sizeof(avg));
	format_human_duration(queue->max_ns, max, sizeof(max));
	format_human_duration(queue->total_ns, total, sizeof(total));
	fprintf(ctx->f, "  avg wait: %s\n", avg);
	fprintf(ctx->f, "  max wait: %s\n", max);
	fprintf(ctx->f, "  p95 bucket: %s\n",
		percentile_bucket(queue, 95));
	fprintf(ctx->f, "  total queued time: %s\n", total);
	fprintf(ctx->f, "  max queue depth: %u\n", ctx->max_queue_depth);
}

/*
 * write_phase_row - write one phase timing row.
 * @ctx: report context.
 * @name: displayed phase name.
 * @stage: stage that stores the phase total.
 * @note: optional note for the phase row.
 * Returns nothing.
 */
static void write_phase_row(const struct decision_timing_report_ctx *ctx,
		const char *name, decision_timing_stage_t stage,
		const char *note)
{
	const struct decision_timing_stage_snapshot *sample =
		&ctx->totals[stage];
	char calls[32], total[32], avg[32], max[32];

	format_count(sample->count, calls, sizeof(calls));
	format_human_duration(sample->total_ns, total, sizeof(total));
	format_human_duration(stage_avg_ns(sample), avg, sizeof(avg));
	format_human_duration(sample->max_ns, max, sizeof(max));

	fprintf(ctx->f, "%-*s %10s %10.2f %10s %10s %10s %12s   %s\n",
		DECISION_TIMING_PHASE_WIDTH, name, calls,
		stage_calls_per_decision(ctx, stage), total, avg, max,
		percentile_bucket(sample, 95), note ? note : "");
}

/*
 * write_response_format_note - explain debug formatting share when visible.
 * @ctx: report context.
 * Returns nothing.
 */
static void write_response_format_note(
		const struct decision_timing_report_ctx *ctx)
{
	char format_total[32], response_total[32];

	if (!stage_observed(ctx, DECISION_TIMING_STAGE_RESPONSE_TOTAL) ||
	    !stage_observed(ctx, DECISION_TIMING_STAGE_SYSLOG_DEBUG_FORMAT))
		return;
	if (stage_time_share(ctx, DECISION_TIMING_STAGE_SYSLOG_DEBUG_FORMAT,
			DECISION_TIMING_STAGE_RESPONSE_TOTAL) <
			RESPONSE_FORMATTING_DOMINANT)
		return;

	format_human_duration(
		ctx->totals[DECISION_TIMING_STAGE_SYSLOG_DEBUG_FORMAT].total_ns,
		format_total, sizeof(format_total));
	format_human_duration(
		ctx->totals[DECISION_TIMING_STAGE_RESPONSE_TOTAL].total_ns,
		response_total, sizeof(response_total));
	fprintf(ctx->f, "\nResponse note:\n");
	fprintf(ctx->f,
		"  response:syslog_debug_format accounts for %s of %s response time.\n",
		format_total, response_total);
	fprintf(ctx->f,
		"  In manual/debug-heavy runs this may overstate daemon-mode "
		"response cost.\n");
}

/*
 * write_phase_timing - write the high-level decision phase table.
 * @ctx: report context.
 * Returns nothing.
 */
static void write_phase_timing(const struct decision_timing_report_ctx *ctx)
{
	static const struct decision_timing_named_stage phases[] = {
		{ DECISION_TIMING_STAGE_EVENT_BUILD, "event_build" },
		{ DECISION_TIMING_STAGE_RULE_EVALUATION, "evaluation" },
		{ DECISION_TIMING_STAGE_RESPONSE_TOTAL, "response" },
	};
	unsigned int i;
	bool any = false;

	fprintf(ctx->f, "\nDecision phase timing:\n");
	fprintf(ctx->f, "%-*s %10s %10s %10s %10s %10s %12s   %s\n",
		DECISION_TIMING_PHASE_WIDTH,
		"Phase", "Calls", "Calls/Dec", "Total", "Avg",
		"Max", "p95 bucket", "Notes");

	for (i = 0; i < sizeof(phases) / sizeof(phases[0]); i++) {
		const char *note = "";
		decision_timing_stage_t stage = phases[i].stage;

		if (!stage_observed(ctx, stage))
			continue;
		if (stage == DECISION_TIMING_STAGE_RESPONSE_TOTAL &&
		    stage_time_share(ctx,
			DECISION_TIMING_STAGE_SYSLOG_DEBUG_FORMAT,
			DECISION_TIMING_STAGE_RESPONSE_TOTAL) >=
			RESPONSE_FORMATTING_DOMINANT)
			note = "syslog/debug-heavy";
		write_phase_row(ctx, phases[i].name, stage, note);
		any = true;
	}

	if (!any)
		fprintf(ctx->f, "  not observed\n");
	write_response_format_note(ctx);
}

/*
 * write_helper_attribution_intro - explain helper driver attribution.
 * @f: output stream.
 * Returns nothing.
 */
static void write_helper_attribution_intro(FILE *f)
{
	fprintf(f, "\nLazy helper attribution:\n");
	fprintf(f,
		"  Helper timings are attributed to the active logical driver: "
		"evaluation or response.\n");
	fprintf(f,
		"  Combined totals are evaluation + response.\n");
}

static const struct decision_timing_helper_row helper_rows[] = {
	{
		"mime_detection:total",
		DECISION_TIMING_STAGE_EVAL_MIME_DETECTION,
		DECISION_TIMING_STAGE_RESPONSE_MIME_DETECTION,
		true
	},
	{
		"mime_detection:fast_classification",
		DECISION_TIMING_STAGE_EVAL_MIME_FAST_CLASSIFICATION,
		DECISION_TIMING_STAGE_RESPONSE_MIME_FAST_CLASSIFICATION,
		true
	},
	{
		"mime_detection:gather_elf",
		DECISION_TIMING_STAGE_EVAL_MIME_GATHER_ELF,
		DECISION_TIMING_STAGE_RESPONSE_MIME_GATHER_ELF,
		true
	},
	{
		"mime_detection:libmagic_fallback",
		DECISION_TIMING_STAGE_EVAL_MIME_LIBMAGIC_FALLBACK,
		DECISION_TIMING_STAGE_RESPONSE_MIME_LIBMAGIC_FALLBACK,
		true
	},
	{
		"trust_db_lookup:total",
		DECISION_TIMING_STAGE_EVAL_TRUST_DB_LOOKUP,
		DECISION_TIMING_STAGE_RESPONSE_TRUST_DB_LOOKUP,
		true
	},
	{
		"trust_db_lookup:read",
		DECISION_TIMING_STAGE_EVAL_TRUST_DB_READ,
		DECISION_TIMING_STAGE_RESPONSE_TRUST_DB_READ,
		true
	},
	{
		"trust_db_lookup:lock_wait",
		DECISION_TIMING_STAGE_EVAL_TRUST_DB_LOCK_WAIT,
		DECISION_TIMING_STAGE_RESPONSE_TRUST_DB_LOCK_WAIT,
		true
	},
	{
		"hash_ima:total",
		DECISION_TIMING_STAGE_HASH_IMA,
		DECISION_TIMING_STAGE_COUNT,
		false
	},
	{
		"hash_sha:total",
		DECISION_TIMING_STAGE_HASH_SHA,
		DECISION_TIMING_STAGE_COUNT,
		false
	},
	{
		"proc_detail_lookup",
		DECISION_TIMING_STAGE_PROC_STATUS_EXE_LOOKUP,
		DECISION_TIMING_STAGE_COUNT,
		false
	},
};

#define HELPER_ROW_MIME_TOTAL 0
#define HELPER_ROW_MIME_FAST 1
#define HELPER_ROW_MIME_GATHER 2
#define HELPER_ROW_MIME_LIBMAGIC 3
#define HELPER_ROW_TRUST_TOTAL 4
#define HELPER_ROW_TRUST_READ 5
#define HELPER_ROW_TRUST_LOCK 6
#define HELPER_ROW_HASH_IMA 7
#define HELPER_ROW_HASH_SHA 8
#define HELPER_ROW_PROC_DETAIL 9

static const unsigned int helper_total_rows[] = {
	HELPER_ROW_MIME_TOTAL,
	HELPER_ROW_TRUST_TOTAL,
	HELPER_ROW_HASH_IMA,
	HELPER_ROW_HASH_SHA,
	HELPER_ROW_PROC_DETAIL
};

/*
 * find_largest_helper - find helper total row with largest combined time.
 * @ctx: report context.
 * @row_out: selected helper_rows index.
 * @sample_out: selected combined sample.
 * Returns true when an observed helper was found.
 */
static bool find_largest_helper(const struct decision_timing_report_ctx *ctx,
		unsigned int *row_out,
		struct decision_timing_stage_snapshot *sample_out)
{
	struct decision_timing_stage_snapshot sample;
	unsigned int i, best = 0;
	unsigned long long total = 0;

	for (i = 0; i < sizeof(helper_total_rows) / sizeof(helper_total_rows[0]);
	     i++) {
		unsigned int row = helper_total_rows[i];

		helper_snapshot(ctx, &helper_rows[row], &sample);
		if (sample.total_ns > total) {
			total = sample.total_ns;
			best = row;
			if (sample_out)
				*sample_out = sample;
		}
	}

	if (total == 0)
		return false;

	if (row_out)
		*row_out = best;
	return true;
}

/*
 * write_helper_driver_row - write one helper driver attribution row.
 * @ctx: report context.
 * @row: helper row to display.
 * Returns true when the row was observed.
 */
static bool write_helper_driver_row(
		const struct decision_timing_report_ctx *ctx,
		const struct decision_timing_helper_row *row)
{
	struct decision_timing_stage_snapshot combined;
	char eval[32], response[32], total[32];
	double response_share = 0.0;
	size_t name_len;
	int eval_width = 12;

	if (!row->by_driver)
		return false;

	helper_snapshot(ctx, row, &combined);
	if (combined.count == 0)
		return false;

	format_human_duration(ctx->totals[row->eval_stage].total_ns,
			      eval, sizeof(eval));
	format_human_duration(ctx->totals[row->response_stage].total_ns,
			      response, sizeof(response));
	format_human_duration(combined.total_ns, total, sizeof(total));
	if (combined.total_ns)
		response_share =
			((double)ctx->totals[row->response_stage].total_ns *
			 100.0) / (double)combined.total_ns;

	name_len = strlen(row->name);
	if (name_len > DECISION_TIMING_DRIVER_WIDTH)
		eval_width -= name_len - DECISION_TIMING_DRIVER_WIDTH;
	if (eval_width < 1)
		eval_width = 1;

	fprintf(ctx->f, "%-*s %*s %15s %12s %10.1f%%\n",
		DECISION_TIMING_DRIVER_WIDTH, row->name, eval_width, eval,
		response, total, response_share);
	return true;
}

/*
 * write_helper_by_driver - write phase-specific helper attribution.
 * @ctx: report context.
 * Returns nothing.
 */
static void write_helper_by_driver(
		const struct decision_timing_report_ctx *ctx)
{
	unsigned int i;
	bool any = false;

	fprintf(ctx->f, "\nLazy helper attribution by driver:\n");
	fprintf(ctx->f, "%-*s %12s %15s %12s %10s\n",
		DECISION_TIMING_DRIVER_WIDTH,
		"Helper", "Eval total", "Response total", "Combined",
		"Response %");

	for (i = 0; i < sizeof(helper_rows) / sizeof(helper_rows[0]); i++)
		any |= write_helper_driver_row(ctx, &helper_rows[i]);

	if (!any)
		fprintf(ctx->f, "  not observed\n");
}

/*
 * write_helper_row - write one combined lazy helper attribution row.
 * @ctx: report context.
 * @row: helper row to display.
 * Returns true when the row was observed.
 */
static bool write_helper_row(const struct decision_timing_report_ctx *ctx,
		const struct decision_timing_helper_row *row)
{
	struct decision_timing_stage_snapshot sample;
	char calls[32], total[32], avg[32], amortized[32], max[32];

	helper_snapshot(ctx, row, &sample);
	if (sample.count == 0)
		return false;

	format_count(sample.count, calls, sizeof(calls));
	format_human_duration(sample.total_ns, total, sizeof(total));
	format_human_duration(stage_avg_ns(&sample), avg, sizeof(avg));
	format_human_duration(sample_amortized_ns(ctx, &sample), amortized,
			      sizeof(amortized));
	format_human_duration(sample.max_ns, max, sizeof(max));

	fprintf(ctx->f, "%-*s %10s %10.2f %10s %10s %10s %10s %12s\n",
		DECISION_TIMING_HELPER_WIDTH, row->name, calls,
		sample_calls_per_decision(ctx, &sample), total, avg,
		amortized, max, percentile_bucket(&sample, 95));
	return true;
}

/*
 * write_lazy_helpers - write grouped lazy helper attribution rows.
 * @ctx: report context.
 * Returns nothing.
 */
static void write_lazy_helpers(const struct decision_timing_report_ctx *ctx)
{
	unsigned int i;
	bool any = false;

	fprintf(ctx->f, "\nCombined lazy helper attribution:\n");
	fprintf(ctx->f, "%-*s %10s %10s %10s %10s %10s %10s %12s\n",
		DECISION_TIMING_HELPER_WIDTH,
		"Helper path", "Calls", "Calls/Dec", "Total",
		"Avg/call", "Amort/Dec", "Max", "p95 bucket");

	for (i = 0; i < sizeof(helper_rows) / sizeof(helper_rows[0]); i++) {
		if (write_helper_row(ctx, &helper_rows[i]))
			any = true;
	}

	if (!any)
		fprintf(ctx->f, "  not observed\n");
}

/*
 * write_idle_observation - compare wall-clock and active decision rates.
 * @ctx: report context.
 * Returns true when an observation was written.
 */
static bool write_idle_observation(
		const struct decision_timing_report_ctx *ctx)
{
	const struct decision_timing_stage_snapshot *decision =
		&ctx->totals[DECISION_TIMING_STAGE_TOTAL];
	double wall_rate, active_rate;

	if (ctx->duration_ns == 0 || decision->total_ns == 0 ||
	    ctx->decisions == 0)
		return false;

	wall_rate = (double)ctx->decisions /
		((double)ctx->duration_ns / (double)NSEC_PER_SEC);
	active_rate = (double)ctx->decisions /
		((double)decision->total_ns / (double)NSEC_PER_SEC);
	if (active_rate < wall_rate * IDLE_WORKLOAD_RATE_MULTIPLIER)
		return false;

	fprintf(ctx->f,
		"  The workload was mostly idle: wall-clock rate is %.1f/sec, "
		"active decision rate is %.1f/sec.\n",
		wall_rate, active_rate);
	return true;
}

/*
 * write_queueing_observation - describe queue depth and wait behavior.
 * @ctx: report context.
 * Returns true when an observation was written.
 */
static bool write_queueing_observation(
		const struct decision_timing_report_ctx *ctx)
{
	const struct decision_timing_stage_snapshot *queue =
		&ctx->totals[DECISION_TIMING_STAGE_QUEUE_WAIT];
	const char *p95;
	char max[32];
	double fullness;

	if (queue->count == 0)
		return false;

	p95 = percentile_bucket(queue, 95);
	format_human_duration(queue->max_ns, max, sizeof(max));
	if (ctx->q_size == 0) {
		fprintf(ctx->f,
			"  Queueing: p95 wait %s, max wait %s, max queue depth %u.\n",
			p95, max, ctx->max_queue_depth);
		return true;
	}

	fullness = ((double)ctx->max_queue_depth * 100.0) /
		(double)ctx->q_size;
	if (ctx->max_queue_depth <= 1) {
		fprintf(ctx->f,
			"  Queueing was minimal: max queue depth %u of %u, "
			"p95 wait %s, max wait %s.\n",
			ctx->max_queue_depth, ctx->q_size, p95, max);
	} else if (fullness < 25.0 &&
		   percentile_bucket_index(queue, 95) <= 4) {
		fprintf(ctx->f,
			"  Queueing was low with small bursts: max "
			"queue depth %u of %u (%.1f%%), p95 wait %s, "
			"max wait %s.\n",
			ctx->max_queue_depth, ctx->q_size, fullness, p95,
			max);
	} else if (fullness < 50.0) {
		fprintf(ctx->f,
			"  Queueing showed moderate bursts: max queue depth "
			"%u of %u (%.1f%%), p95 wait %s, max wait %s.\n",
			ctx->max_queue_depth, ctx->q_size, fullness, p95,
			max);
	} else if (fullness < 80.0) {
		fprintf(ctx->f,
			"  Queueing showed significant backlog pressure: "
			"max queue depth %u of %u (%.1f%%), p95 wait %s, "
			"max wait %s.\n",
			ctx->max_queue_depth, ctx->q_size, fullness, p95,
			max);
	} else {
		fprintf(ctx->f,
			"  Queueing approached capacity: max queue depth %u "
			"of %u (%.1f%%), p95 wait %s, max wait %s.\n",
			ctx->max_queue_depth, ctx->q_size, fullness, p95,
			max);
	}

	return true;
}

/*
 * write_response_observation - describe response formatting dominance.
 * @ctx: report context.
 * Returns true when an observation was written.
 */
static bool write_response_observation(
		const struct decision_timing_report_ctx *ctx)
{
	char debug_total[32], response_total[32];

	if (!stage_observed(ctx, DECISION_TIMING_STAGE_RESPONSE_TOTAL) ||
	    !stage_observed(ctx, DECISION_TIMING_STAGE_SYSLOG_DEBUG_FORMAT))
		return false;
	if (stage_time_share(ctx, DECISION_TIMING_STAGE_SYSLOG_DEBUG_FORMAT,
			DECISION_TIMING_STAGE_RESPONSE_TOTAL) <
			RESPONSE_FORMATTING_DOMINANT)
		return false;

	format_human_duration(
		ctx->totals[DECISION_TIMING_STAGE_SYSLOG_DEBUG_FORMAT].total_ns,
		debug_total, sizeof(debug_total));
	format_human_duration(
		ctx->totals[DECISION_TIMING_STAGE_RESPONSE_TOTAL].total_ns,
		response_total, sizeof(response_total));
	fprintf(ctx->f,
		"  Manual/debug response formatting dominates response time: "
		"%s of %s response time.\n",
		debug_total, response_total);
	return true;
}

/*
 * write_mime_observations - describe MIME helper cost shares.
 * @ctx: report context.
 * Returns true when any observation was written.
 */
static bool write_mime_observations(
		const struct decision_timing_report_ctx *ctx)
{
	struct decision_timing_stage_snapshot mime;
	struct decision_timing_stage_snapshot fallback;
	struct decision_timing_stage_snapshot fast;
	struct decision_timing_stage_snapshot gather;
	struct decision_timing_stage_snapshot largest_sample;
	unsigned int largest;
	char total[32], amortized[32];
	bool any = false;

	helper_snapshot(ctx, &helper_rows[HELPER_ROW_MIME_TOTAL], &mime);
	if (mime.count == 0)
		return false;

	if (find_largest_helper(ctx, &largest, &largest_sample) &&
	    largest == HELPER_ROW_MIME_TOTAL) {
		format_human_duration(largest_sample.total_ns, total,
				      sizeof(total));
		fprintf(ctx->f,
			"  MIME detection is the largest helper cost (%s).\n",
			total);
		any = true;
	}

	helper_snapshot(ctx, &helper_rows[HELPER_ROW_MIME_LIBMAGIC],
			&fallback);
	if (fallback.count == 0)
		return any;

	helper_snapshot(ctx, &helper_rows[HELPER_ROW_MIME_FAST], &fast);
	helper_snapshot(ctx, &helper_rows[HELPER_ROW_MIME_GATHER], &gather);
	format_human_duration(sample_amortized_ns(ctx, &fallback),
		amortized, sizeof(amortized));
	if (fallback.total_ns >= fast.total_ns &&
	    fallback.total_ns >= gather.total_ns) {
		fprintf(ctx->f,
			"  libmagic fallback is the biggest MIME contributor: "
			"%.1f%% of MIME calls, %.1f%% of MIME time, %s "
			"amortized per decision.\n",
			percent_of_count(fallback.count, mime.count),
			percent_of_count(fallback.total_ns, mime.total_ns),
			amortized);
	} else {
		fprintf(ctx->f,
			"  libmagic fallback accounts for %.1f%% of MIME calls, "
			"%.1f%% of MIME time, %s amortized per decision.\n",
			percent_of_count(fallback.count, mime.count),
			percent_of_count(fallback.total_ns, mime.total_ns),
			amortized);
	}

	return true;
}

/*
 * write_hash_observation - describe rare integrity measurement cost.
 * @ctx: report context.
 * @stage: stage that stores the integrity measurement.
 * @name: report helper name.
 * Returns true when an observation was written.
 */
static bool write_hash_observation(const struct decision_timing_report_ctx *ctx,
		decision_timing_stage_t stage, const char *name)
{
	const struct decision_timing_stage_snapshot *hash = &ctx->totals[stage];
	double call_share;
	char avg[32], amortized[32];

	if (!stage_observed(ctx, stage) || ctx->decisions == 0)
		return false;

	call_share = percent_of_count(hash->count, ctx->decisions);
	if (call_share >= HASH_RARE_SHARE)
		return false;

	format_human_duration(stage_avg_ns(hash), avg, sizeof(avg));
	format_human_duration(stage_amortized_ns(ctx, stage), amortized,
			      sizeof(amortized));
	fprintf(ctx->f,
		"  %s is rare but expensive: %.1f%% of decisions, "
		"%s avg when called, %s amortized per decision.\n",
		name, call_share, avg, amortized);
	return true;
}

/*
 * write_trust_db_observation - describe trust DB lock versus read cost.
 * @ctx: report context.
 * Returns true when an observation was written.
 */
static bool write_trust_db_observation(
		const struct decision_timing_report_ctx *ctx)
{
	struct decision_timing_stage_snapshot lock;
	struct decision_timing_stage_snapshot read;
	double lock_share;

	helper_snapshot(ctx, &helper_rows[HELPER_ROW_TRUST_LOCK], &lock);
	helper_snapshot(ctx, &helper_rows[HELPER_ROW_TRUST_READ], &read);
	if (lock.count == 0 || read.count == 0)
		return false;

	if (read.total_ns == 0)
		return false;
	lock_share = ((double)lock.total_ns * 100.0) /
		(double)read.total_ns;
	if (lock_share > TRUST_DB_LOCK_TINY_SHARE)
		return false;

	fprintf(ctx->f,
		"  trust DB lock wait is negligible; trust DB read time is "
		"the relevant cost.\n");
	return true;
}

/*
 * write_tldr_mime - write a compact MIME helper timing finding.
 * @ctx: report context.
 * Returns true when a finding was written.
 */
static bool write_tldr_mime(const struct decision_timing_report_ctx *ctx)
{
	struct decision_timing_stage_snapshot mime;
	struct decision_timing_stage_snapshot fallback;
	struct decision_timing_stage_snapshot fast;
	struct decision_timing_stage_snapshot gather;
	struct decision_timing_stage_snapshot largest_sample;
	unsigned int largest;
	char total[32];

	helper_snapshot(ctx, &helper_rows[HELPER_ROW_MIME_TOTAL], &mime);
	if (mime.count == 0)
		return false;
	if (!find_largest_helper(ctx, &largest, &largest_sample) ||
	    largest != HELPER_ROW_MIME_TOTAL)
		return false;

	helper_snapshot(ctx, &helper_rows[HELPER_ROW_MIME_LIBMAGIC],
			&fallback);
	helper_snapshot(ctx, &helper_rows[HELPER_ROW_MIME_FAST], &fast);
	helper_snapshot(ctx, &helper_rows[HELPER_ROW_MIME_GATHER], &gather);
	format_human_duration(largest_sample.total_ns, total, sizeof(total));
	if (fallback.count && fallback.total_ns >= fast.total_ns &&
	    fallback.total_ns >= gather.total_ns)
		fprintf(ctx->f,
			"  - MIME detection dominates helper time (%s); "
			"libmagic fallback is the biggest contributor.\n",
			total);
	else
		fprintf(ctx->f,
			"  - MIME detection is the largest helper cost (%s).\n",
			total);

	return true;
}

/*
 * write_tldr_response - write a compact response formatting finding.
 * @ctx: report context.
 * Returns true when a finding was written.
 */
static bool write_tldr_response(
		const struct decision_timing_report_ctx *ctx)
{
	char debug_total[32], response_total[32];

	if (!stage_observed(ctx, DECISION_TIMING_STAGE_RESPONSE_TOTAL) ||
	    !stage_observed(ctx, DECISION_TIMING_STAGE_SYSLOG_DEBUG_FORMAT))
		return false;
	if (stage_time_share(ctx, DECISION_TIMING_STAGE_SYSLOG_DEBUG_FORMAT,
			DECISION_TIMING_STAGE_RESPONSE_TOTAL) <
			RESPONSE_FORMATTING_DOMINANT)
		return false;

	format_human_duration(
		ctx->totals[DECISION_TIMING_STAGE_SYSLOG_DEBUG_FORMAT].total_ns,
		debug_total, sizeof(debug_total));
	format_human_duration(
		ctx->totals[DECISION_TIMING_STAGE_RESPONSE_TOTAL].total_ns,
		response_total, sizeof(response_total));
	fprintf(ctx->f,
		"  - Manual/debug response formatting accounts for %s "
		"of %s response time.\n",
		debug_total, response_total);
	return true;
}

/*
 * write_tldr_queueing - write a compact queueing finding.
 * @ctx: report context.
 * Returns true when a finding was written.
 */
static bool write_tldr_queueing(
		const struct decision_timing_report_ctx *ctx)
{
	const struct decision_timing_stage_snapshot *queue =
		&ctx->totals[DECISION_TIMING_STAGE_QUEUE_WAIT];
	const char *p95;
	char max[32];
	double fullness = 0.0;

	if (queue->count == 0)
		return false;

	p95 = percentile_bucket(queue, 95);
	format_human_duration(queue->max_ns, max, sizeof(max));
	if (ctx->q_size)
		fullness = ((double)ctx->max_queue_depth * 100.0) /
			(double)ctx->q_size;

	if (ctx->q_size && fullness < 25.0 &&
	    percentile_bucket_index(queue, 95) <= 4)
		fprintf(ctx->f,
			"  - Queueing is healthy; max queue depth %u of %u, "
			"p95 wait %s.\n",
			ctx->max_queue_depth, ctx->q_size, p95);
	else if (ctx->q_size)
		fprintf(ctx->f,
			"  - Queueing pressure reached max depth %u of %u "
			"(%.1f%%), p95 wait %s, max wait %s.\n",
			ctx->max_queue_depth, ctx->q_size, fullness, p95,
			max);
	else
		fprintf(ctx->f,
			"  - Queueing p95 wait %s, max wait %s, "
			"max queue depth %u.\n",
			p95, max, ctx->max_queue_depth);

	return true;
}

/*
 * write_tldr - write dominant timing findings near the report top.
 * @ctx: report context.
 * Returns nothing.
 */
static void write_tldr(const struct decision_timing_report_ctx *ctx)
{
	unsigned int findings = 0;

	fprintf(ctx->f, "\nTL;DR:\n");
	if (write_tldr_mime(ctx))
		findings++;
	if (write_tldr_response(ctx))
		findings++;
	if (write_tldr_queueing(ctx))
		findings++;
	if (findings == 0)
		fprintf(ctx->f, "  - No dominant timing findings observed.\n");
}

/*
 * write_derived_observations - write deterministic report observations.
 * @ctx: report context.
 * Returns nothing.
 */
static void write_derived_observations(
		const struct decision_timing_report_ctx *ctx)
{
	bool any = false;

	fprintf(ctx->f, "\nDerived observations:\n");
	any |= write_queueing_observation(ctx);
	any |= write_idle_observation(ctx);
	any |= write_response_observation(ctx);
	any |= write_mime_observations(ctx);
	any |= write_hash_observation(ctx, DECISION_TIMING_STAGE_HASH_IMA,
				      "hash_ima");
	any |= write_hash_observation(ctx, DECISION_TIMING_STAGE_HASH_SHA,
				      "hash_sha");
	any |= write_trust_db_observation(ctx);
	if (!any)
		fprintf(ctx->f, "  none\n");
}

/*
 * write_stage_table - write observed stages ranked by total time.
 * @ctx: report context.
 * Returns nothing.
 */
static void write_stage_table(const struct decision_timing_report_ctx *ctx)
{
	unsigned int i;

	fprintf(ctx->f, "\nDetailed stage timing, sorted by total time:\n");
	fprintf(ctx->f, "%-*s %10s %14s %10s %10s %10s %12s\n",
		DECISION_TIMING_STAGE_WIDTH,
		"Stage", "Calls", "Calls/Dec", "Total", "Avg",
		"Max", "p95 bucket");

	for (i = 0; i < ctx->order->count; i++) {
		unsigned int stage = ctx->order->stages[i];
		char calls[32], total[32], avg[32], max[32];
		unsigned long long avg_ns;
		double calls_per_decision = 0.0;

		if (ctx->decisions)
			calls_per_decision =
				(double)ctx->totals[stage].count /
				(double)ctx->decisions;
		avg_ns = stage_avg_ns(&ctx->totals[stage]);
		format_count(ctx->totals[stage].count, calls, sizeof(calls));
		format_human_duration(ctx->totals[stage].total_ns, total,
				      sizeof(total));
		format_human_duration(avg_ns, avg, sizeof(avg));
		format_human_duration(ctx->totals[stage].max_ns, max,
				      sizeof(max));

		fprintf(ctx->f,
			"%-*s %10s %14.2f %10s %10s %10s %12s\n",
			DECISION_TIMING_STAGE_WIDTH, stage_names[stage],
			calls, calls_per_decision, total, avg, max,
			percentile_bucket(&ctx->totals[stage], 95));
	}
}

/*
 * tail_stage_parent_prefix - find the parent prefix for a :total stage.
 * @name: stage name.
 * @len: destination for parent prefix length.
 * Returns true if @name is a parent stage.
 */
static bool tail_stage_parent_prefix(const char *name, size_t *len)
{
	static const char suffix[] = ":total";
	size_t name_len = strlen(name);
	size_t suffix_len = sizeof(suffix) - 1;

	if (name_len <= suffix_len)
		return false;
	if (strcmp(name + name_len - suffix_len, suffix) != 0)
		return false;

	*len = name_len - suffix_len;
	return true;
}

/*
 * tail_stage_is_parent - test whether one stage name is a parent of another.
 * @parent: possible parent stage name.
 * @child: possible child stage name.
 * Returns true when @child is under @parent's :total prefix.
 */
static bool tail_stage_is_parent(const char *parent, const char *child)
{
	size_t len;

	if (!tail_stage_parent_prefix(parent, &len))
		return false;

	return strncmp(parent, child, len) == 0 && child[len] == ':';
}

/*
 * tail_counts_near - test whether two tail counts are nearly the same.
 * @a: first count.
 * @b: second count.
 * Returns true when the counts differ by no more than five percent.
 */
static bool tail_counts_near(unsigned long long a, unsigned long long b)
{
	unsigned long long high, low;

	if (a == 0 || b == 0)
		return false;

	high = a > b ? a : b;
	low = a > b ? b : a;
	return (high - low) * 100 <= high * 5;
}

/*
 * tail_row_duplicate - suppress near-identical parent/child tail rows.
 * @selected: selected rows.
 * @selected_count: number of selected rows.
 * @candidate: row being considered.
 * Returns true when @candidate would add duplicate parent/child noise.
 */
static bool tail_row_duplicate(const struct decision_timing_tail_row *selected,
		unsigned int selected_count,
		const struct decision_timing_tail_row *candidate)
{
	const char *candidate_name = stage_names[candidate->stage];
	unsigned int i;

	for (i = 0; i < selected_count; i++) {
		const char *selected_name = stage_names[selected[i].stage];

		if (!tail_counts_near(selected[i].over_10ms,
				      candidate->over_10ms))
			continue;
		if (tail_stage_is_parent(selected_name, candidate_name) ||
		    tail_stage_is_parent(candidate_name, selected_name))
			return true;
	}

	return false;
}

/*
 * sort_tail_rows - rank stage tail rows by high-end occurrence count.
 * @ctx: report context.
 * @rows: rows to sort.
 * @count: number of rows.
 * Returns nothing.
 */
static void sort_tail_rows(const struct decision_timing_report_ctx *ctx,
		struct decision_timing_tail_row *rows, unsigned int count)
{
	unsigned int i;

	for (i = 1; i < count; i++) {
		struct decision_timing_tail_row row = rows[i];
		unsigned int j = i;

		while (j > 0) {
			const struct decision_timing_tail_row *prev =
				&rows[j - 1];
			bool move = false;

			if (row.over_10ms > prev->over_10ms)
				move = true;
			else if (row.over_10ms == prev->over_10ms &&
				 row.over_50ms > prev->over_50ms)
				move = true;
			else if (row.over_10ms == prev->over_10ms &&
				 row.over_50ms == prev->over_50ms &&
				 ctx->totals[row.stage].total_ns >
				 ctx->totals[prev->stage].total_ns)
				move = true;
			else if (row.over_10ms == prev->over_10ms &&
				 row.over_50ms == prev->over_50ms &&
				 ctx->totals[row.stage].total_ns ==
				 ctx->totals[prev->stage].total_ns &&
				 row.stage < prev->stage)
				move = true;
			if (!move)
				break;

			rows[j] = rows[j - 1];
			j--;
		}
		rows[j] = row;
	}
}

/*
 * write_stage_tail_summary - write limited tail summaries for hot stage rows.
 * @ctx: report context.
 * Returns nothing.
 */
static void write_stage_tail_summary(
		const struct decision_timing_report_ctx *ctx)
{
	struct decision_timing_tail_row rows[DECISION_TIMING_STAGE_COUNT];
	struct decision_timing_tail_row selected[DECISION_TIMING_STAGE_COUNT];
	unsigned int i, count = 0, selected_count = 0;

	for (i = 0; i < DECISION_TIMING_STAGE_COUNT; i++) {
		unsigned long long over_10ms =
			bucket_count_above(&ctx->totals[i], 8);

		if (over_10ms == 0)
			continue;
		rows[count].stage = i;
		rows[count].over_10ms = over_10ms;
		rows[count].over_50ms = bucket_count_above(&ctx->totals[i],
							   10);
		count++;
	}
	if (count == 0)
		return;

	sort_tail_rows(ctx, rows, count);
	for (i = 0; i < count; i++) {
		if (selected_count >= DECISION_TIMING_TAIL_STAGE_LIMIT &&
		    rows[i].over_50ms == 0)
			continue;
		if (tail_row_duplicate(selected, selected_count, &rows[i]))
			continue;
		selected[selected_count++] = rows[i];
	}
	if (selected_count == 0)
		return;

	fprintf(ctx->f, "\nStage tail summary:\n");
	for (i = 0; i < selected_count; i++) {
		decision_timing_stage_t stage = selected[i].stage;

		fprintf(ctx->f, "  %s: ", stage_names[stage]);
		write_tail_counts(ctx->f, &ctx->totals[stage], false);
	}
}

/*
 * write_not_observed - list stages that were not observed.
 * @ctx: report context.
 * Returns nothing.
 */
static void write_not_observed(const struct decision_timing_report_ctx *ctx)
{
	unsigned int i;
	bool any = false;

	fprintf(ctx->f, "\nNot observed:\n  ");
	for (i = 1; i < DECISION_TIMING_STAGE_COUNT; i++) {
		if (ctx->totals[i].count)
			continue;
		fprintf(ctx->f, "%s%s", any ? ", " : "", stage_names[i]);
		any = true;
	}
	if (!any)
		fprintf(ctx->f, "none");
	fputc('\n', ctx->f);
}

/*
 * write_notes - write a short interpretation footer.
 * @ctx: report context.
 * Returns nothing.
 */
static void write_notes(const struct decision_timing_report_ctx *ctx)
{
	static const struct decision_timing_named_stage phases[] = {
		{ DECISION_TIMING_STAGE_EVENT_BUILD, "event_build" },
		{ DECISION_TIMING_STAGE_RULE_EVALUATION, "evaluation" },
		{ DECISION_TIMING_STAGE_RESPONSE_TOTAL, "response" },
	};
	static const struct decision_timing_named_stage daemon_phases[] = {
		{ DECISION_TIMING_STAGE_EVENT_BUILD, "event_build" },
		{ DECISION_TIMING_STAGE_RULE_EVALUATION, "evaluation" },
	};
	struct decision_timing_stage_snapshot helper_sample;
	unsigned int stage, row;
	char duration[32];

	fprintf(ctx->f, "\nNotes:\n");
	if (stage_observed(ctx, DECISION_TIMING_STAGE_QUEUE_WAIT)) {
		format_human_duration(
			ctx->totals[DECISION_TIMING_STAGE_QUEUE_WAIT].total_ns,
			duration, sizeof(duration));
		fprintf(ctx->f,
			"  Largest queued-time contributor: time_in_queue:total (%s)\n",
			duration);
	}
	if (find_largest_helper(ctx, &row, &helper_sample)) {
		format_human_duration(helper_sample.total_ns, duration,
				      sizeof(duration));
		fprintf(ctx->f, "  Largest helper contributor: %s (%s)\n",
			helper_rows[row].name, duration);
	}
	if (find_largest_named_stage(ctx, phases,
			sizeof(phases) / sizeof(phases[0]), &row)) {
		stage = phases[row].stage;
		format_human_duration(ctx->totals[stage].total_ns, duration,
				      sizeof(duration));
		if (stage == DECISION_TIMING_STAGE_RESPONSE_TOTAL &&
		    stage_time_share(ctx,
			DECISION_TIMING_STAGE_SYSLOG_DEBUG_FORMAT,
			DECISION_TIMING_STAGE_RESPONSE_TOTAL) >=
			RESPONSE_FORMATTING_DOMINANT) {
			fprintf(ctx->f,
				"  Largest manual/debug phase contributor: "
				"response (%s, syslog/debug-heavy)\n",
				duration);
			if (find_largest_named_stage(ctx, daemon_phases,
				sizeof(daemon_phases) / sizeof(daemon_phases[0]),
				&row)) {
				stage = daemon_phases[row].stage;
				format_human_duration(
					ctx->totals[stage].total_ns,
					duration, sizeof(duration));
				fprintf(ctx->f,
					"  Largest daemon-relevant decision phase contributor: %s (%s)\n",
					daemon_phases[row].name, duration);
			}
		} else {
			fprintf(ctx->f,
				"  Largest decision phase contributor: %s (%s)\n",
				phases[row].name, duration);
		}
	}
	if (find_slowest_stage(ctx->totals, &stage)) {
		format_human_duration(ctx->totals[stage].max_ns, duration,
				      sizeof(duration));
		fprintf(ctx->f, "  Slowest observed row by max: %s (%s)\n",
			stage_names[stage], duration);
	}
}

/*
 * write_report_sections - write the report detail sections after run summary.
 * @ctx: report context.
 * Returns nothing.
 */
static void write_report_sections(const struct decision_timing_report_ctx *ctx)
{
	write_tldr(ctx);
	write_overall_latency(ctx->f, &ctx->totals[DECISION_TIMING_STAGE_TOTAL]);
	write_queueing(ctx);
	write_phase_timing(ctx);
	write_helper_attribution_intro(ctx->f);
	write_helper_by_driver(ctx);
	write_lazy_helpers(ctx);
	write_derived_observations(ctx);
	write_stage_table(ctx);
	write_stage_tail_summary(ctx);
	write_not_observed(ctx);
	write_notes(ctx);
}

#ifdef TEST_DECISION_TIMING_REPORT
/*
 * decision_timing_test_write_report - format a synthetic timing report.
 * @f: output stream.
 * @samples: synthetic stage samples.
 * @sample_count: number of entries in @samples.
 * @input: synthetic run-level inputs.
 * Returns nothing.
 */
void decision_timing_test_write_report(FILE *f,
	const struct decision_timing_test_stage_sample *samples,
	unsigned int sample_count,
	const struct decision_timing_test_report_input *input)
{
	struct decision_timing_stage_snapshot totals[DECISION_TIMING_STAGE_COUNT];
	struct decision_timing_stage_order order;
	struct decision_timing_report_ctx report;
	unsigned int i;

	memset(totals, 0, sizeof(totals));
	for (i = 0; i < sample_count; i++) {
		decision_timing_stage_t stage = samples[i].stage;
		unsigned int bucket = samples[i].bucket;

		if (stage >= DECISION_TIMING_STAGE_COUNT)
			continue;
		if (bucket >= DECISION_TIMING_BUCKETS)
			bucket = DECISION_TIMING_BUCKETS - 1;

		totals[stage].count += samples[i].count;
		totals[stage].total_ns += samples[i].total_ns;
		if (samples[i].max_ns > totals[stage].max_ns)
			totals[stage].max_ns = samples[i].max_ns;
		totals[stage].buckets[bucket] += samples[i].count;
	}

	sort_stages_by_total(totals, &order);
	report.f = f;
	report.totals = totals;
	report.order = &order;
	report.decisions = totals[DECISION_TIMING_STAGE_TOTAL].count;
	report.duration_ns = input ? input->duration_ns : 0;
	report.max_queue_depth = input ? input->max_queue_depth : 0;
	report.q_size = input ? input->q_size : 0;
	write_report_sections(&report);
}
#endif

/*
 * write_timing_report - snapshot aggregates and write the timing report.
 * @config: active daemon configuration.
 * Returns nothing.
 */
static void write_timing_report(const conf_t *config)
{
	struct decision_timing_stage_snapshot totals[DECISION_TIMING_STAGE_COUNT];
	struct decision_timing_stage_order order;
	struct decision_timing_report_ctx report;
	FILE *f;
	unsigned int worker, stage, worker_count;
	char decisions[32], duration[32], start_time[64], stop_time[64];
	const char *mode = decision_timing_mode_name(
		config_timing_mode(config));
	unsigned long long duration_ns = 0;
	unsigned long long decision_count;
	unsigned long long start_mono, stop_mono;
	unsigned int max_queue_depth;
	long stopped = atomic_load_explicit(&last_stop_time,
					    memory_order_relaxed);
	long started = atomic_load_explicit(&run_start_time,
					    memory_order_relaxed);
	int tfd;

	memset(totals, 0, sizeof(totals));
	worker_count = atomic_load_explicit(&active_workers,
					    memory_order_relaxed);
	if (worker_count > DECISION_TIMING_MAX_WORKERS)
		worker_count = DECISION_TIMING_MAX_WORKERS;

	for (worker = 0; worker < worker_count; worker++) {
		for (stage = 0; stage < DECISION_TIMING_STAGE_COUNT; stage++)
			snapshot_stage(&totals[stage],
				&workers[worker].stages[stage]);
	}
	sort_stages_by_total(totals, &order);

	tfd = open_timing_report();
	if (tfd < 0) {
		msg(LOG_WARNING, "cannot open %s: %s",
			TIMING_REPORT, strerror(errno));
		return;
	}

	f = fdopen(tfd, "w");
	if (!f) {
		msg(LOG_WARNING, "cannot fdopen %s: %s",
			TIMING_REPORT, strerror(errno));
		close(tfd);
		return;
	}

	start_mono = atomic_load_explicit(&run_start_mono_ns,
					  memory_order_relaxed);
	stop_mono = atomic_load_explicit(&run_stop_mono_ns,
					 memory_order_relaxed);
	if (start_mono && stop_mono >= start_mono)
		duration_ns = stop_mono - start_mono;
	else if (stopped >= started)
		duration_ns = (unsigned long long)(stopped - started) *
			      NSEC_PER_SEC;

	decision_count = totals[DECISION_TIMING_STAGE_TOTAL].count;
	max_queue_depth = atomic_load_explicit(&run_max_queue_depth,
					       memory_order_relaxed);
	report.f = f;
	report.totals = totals;
	report.order = &order;
	report.decisions = decision_count;
	report.duration_ns = duration_ns;
	report.max_queue_depth = max_queue_depth;
	report.q_size = config->q_size;

	format_count(decision_count, decisions, sizeof(decisions));
	format_hms_duration(duration_ns, duration, sizeof(duration));

	fprintf(f, "Mode: %s\n", mode);
	fprintf(f, "Timing run: %s to %s\n",
		format_report_time(started, start_time, sizeof(start_time)),
		format_report_time(stopped, stop_time, sizeof(stop_time)));
	fprintf(f, "Duration: %s\n", duration);
	fprintf(f, "Workers: %u\n", worker_count);
	fprintf(f, "Max queue depth: %u\n", max_queue_depth);
	fprintf(f, "Decisions: %s\n", decisions);
	if (duration_ns)
		fprintf(f, "Throughput: %.1f decisions/sec (wall clock)\n",
			(double)decision_count /
			((double)duration_ns / (double)NSEC_PER_SEC));
	else
		fprintf(f, "Throughput: n/a\n");
	if (totals[DECISION_TIMING_STAGE_TOTAL].total_ns)
		fprintf(f, "Active decision rate: %.1f decisions/sec\n",
			(double)decision_count /
			((double)totals[DECISION_TIMING_STAGE_TOTAL].total_ns /
				(double)NSEC_PER_SEC));
	else
		fprintf(f, "Active decision rate: n/a\n");
	if (atomic_load_explicit(&stop_reason, memory_order_relaxed) ==
			DECISION_TIMING_STOP_OVERFLOW) {
		int overflow_stage = atomic_load_explicit(&stop_reason_stage,
					memory_order_relaxed);

		if (overflow_stage >= 0 &&
		    overflow_stage < DECISION_TIMING_STAGE_COUNT)
			fprintf(f, "Stop reason: counter overflow at %s\n",
				stage_names[overflow_stage]);
		else
			fprintf(f, "Stop reason: counter overflow\n");
	}

	write_report_sections(&report);

	fclose(f);
	msg(LOG_INFO, "Wrote decision timing report to %s", TIMING_REPORT);
}

/*
 * write_unarmed_report - write a report for an unarmed stop request.
 * @config: active daemon configuration.
 * Returns nothing.
 */
static void write_unarmed_report(const conf_t *config)
{
	const char *mode = decision_timing_mode_name(
		config_timing_mode(config));
	FILE *f;
	int tfd;

	tfd = open_timing_report();
	if (tfd < 0) {
		msg(LOG_WARNING, "cannot open %s: %s",
			TIMING_REPORT, strerror(errno));
		return;
	}

	f = fdopen(tfd, "w");
	if (!f) {
		msg(LOG_WARNING, "cannot fdopen %s: %s",
			TIMING_REPORT, strerror(errno));
		close(tfd);
		return;
	}

	fprintf(f, "Mode: %s\n", mode);
	fprintf(f, "Status: timing_collection is not armed\n");
	fclose(f);
	msg(LOG_INFO, "Wrote decision timing report to %s", TIMING_REPORT);
}

/*
 * decision_timing_apply_config - apply a timing mode change.
 * @mode: configured timing mode.
 * Returns nothing.
 */
void decision_timing_apply_config(timing_collection_t mode)
{
	if (mode == TIMING_COLLECTION_OFF &&
	    atomic_exchange_explicit(&timing_armed, false,
				     memory_order_acq_rel)) {
		atomic_store_explicit(&queue_depth_restore_requests, true,
				      memory_order_relaxed);
		msg(LOG_INFO, "Decision timing disarmed because mode is off");
	}
}

/*
 * decision_timing_set_queue_depth_hooks - install queue depth callbacks.
 * @reset: callback that resets max queue depth and returns the saved value.
 * @restore: callback that returns run max depth and restores saved if larger.
 * @ctx: callback context.
 * Returns nothing.
 */
void decision_timing_set_queue_depth_hooks(
		decision_timing_queue_depth_reset_fn reset,
		decision_timing_queue_depth_restore_fn restore,
		void *ctx)
{
	queue_depth_reset = reset;
	queue_depth_restore = restore;
	queue_depth_ctx = ctx;
}

/*
 * decision_timing_signal_request - record SIGUSR1 timing intent.
 * @intent: SIGUSR1 intent value.
 * @pid: sender pid, or -1 when unavailable.
 * @uid: sender uid, or -1 when unavailable.
 * Returns nothing.
 */
void decision_timing_signal_request(report_intent_t intent, pid_t pid,
		uid_t uid)
{
	if (intent == REPORT_INTENT_TIMING_ARM) {
		atomic_store_explicit(&arm_request_pid, (int)pid,
				      memory_order_relaxed);
		atomic_store_explicit(&arm_request_uid, (int)uid,
				      memory_order_relaxed);
		atomic_fetch_add_explicit(&arm_requests, 1,
					  memory_order_relaxed);
	} else if (intent == REPORT_INTENT_TIMING_STOP) {
		atomic_store_explicit(&stop_request_pid, (int)pid,
				      memory_order_relaxed);
		atomic_store_explicit(&stop_request_uid, (int)uid,
				      memory_order_relaxed);
		atomic_fetch_add_explicit(&stop_requests, 1,
					  memory_order_relaxed);
	}
}

/*
 * decision_timing_queue_depth_start - save and reset run queue depth.
 * Returns nothing.
 */
static void decision_timing_queue_depth_start(void)
{
	unsigned int saved = 0;

	if (queue_depth_reset)
		saved = queue_depth_reset(queue_depth_ctx);
	if (atomic_load_explicit(&queue_depth_active, memory_order_relaxed)) {
		unsigned int previous = atomic_load_explicit(
			&saved_max_queue_depth, memory_order_relaxed);

		if (previous > saved)
			saved = previous;
	}

	atomic_store_explicit(&saved_max_queue_depth, saved,
			      memory_order_relaxed);
	atomic_store_explicit(&run_max_queue_depth, 0, memory_order_relaxed);
	atomic_store_explicit(&queue_depth_active, true, memory_order_relaxed);
}

/*
 * decision_timing_queue_depth_stop - snapshot run queue depth and restore.
 * Returns nothing.
 */
static void decision_timing_queue_depth_stop(void)
{
	unsigned int current = 0;
	unsigned int saved;

	if (!atomic_exchange_explicit(&queue_depth_active, false,
				      memory_order_relaxed))
		return;

	saved = atomic_load_explicit(&saved_max_queue_depth,
				     memory_order_relaxed);
	if (queue_depth_restore)
		current = queue_depth_restore(queue_depth_ctx, saved);

	atomic_store_explicit(&run_max_queue_depth, current,
			      memory_order_relaxed);
}

/*
 * decision_timing_arm - start a manual timing run.
 * @pid: requester pid.
 * @uid: requester uid.
 * Returns nothing.
 */
static void decision_timing_arm(int pid, int uid)
{
	if (atomic_load_explicit(&timing_armed, memory_order_acquire)) {
		msg(LOG_INFO,
		    "Decision timing start requested by pid=%d uid=%d "
		    "but timing is already armed",
		    pid, uid);
		return;
	}

	reset_worker_blocks();
	decision_timing_queue_depth_start();
	atomic_store_explicit(&last_arm_time, (long)time(NULL),
			      memory_order_relaxed);
	atomic_store_explicit(&run_start_time,
			      atomic_load_explicit(&last_arm_time,
				memory_order_relaxed), memory_order_relaxed);
	atomic_store_explicit(&run_start_mono_ns, ns_now(),
			      memory_order_relaxed);
	atomic_store_explicit(&run_stop_mono_ns, 0, memory_order_relaxed);
	atomic_store_explicit(&stop_reason, DECISION_TIMING_STOP_MANUAL,
			      memory_order_relaxed);
	atomic_store_explicit(&stop_reason_stage, -1, memory_order_relaxed);
	atomic_store_explicit(&overflow_stop_requests, 0,
			      memory_order_relaxed);
	atomic_store_explicit(&timing_armed, true, memory_order_release);
	msg(LOG_INFO, "Decision timing started by pid=%d uid=%d", pid, uid);
}

/*
 * decision_timing_stop - stop a manual timing run and write a report.
 * @config: active daemon configuration.
 * @pid: requester pid.
 * @uid: requester uid.
 * Returns nothing.
 */
static void decision_timing_stop(const conf_t *config, int pid, int uid)
{
	bool was_armed;

	was_armed = atomic_exchange_explicit(&timing_armed, false,
					     memory_order_acq_rel);
	if (!was_armed) {
		msg(LOG_INFO,
		    "Decision timing stop requested by pid=%d uid=%d but timing is not armed",
		    pid, uid);
		write_unarmed_report(config);
		return;
	}

	atomic_store_explicit(&last_stop_time, (long)time(NULL),
			      memory_order_relaxed);
	atomic_store_explicit(&run_stop_mono_ns, ns_now(),
			      memory_order_relaxed);
	atomic_store_explicit(&stop_reason, DECISION_TIMING_STOP_MANUAL,
			      memory_order_relaxed);
	atomic_store_explicit(&stop_reason_stage, -1, memory_order_relaxed);
	decision_timing_queue_depth_stop();
	msg(LOG_INFO, "Decision timing stopped by pid=%d uid=%d", pid, uid);
	write_timing_report(config);
}

/*
 * decision_timing_process_requests - apply pending timing control requests.
 * @config: active daemon configuration.
 *
 * Signal handlers and overflow detection do not mutate timing state directly.
 * They update the static atomic request flags above: arm_requests,
 * stop_requests, overflow_stop_requests, and queue_depth_restore_requests.
 * The decision thread calls this function from normal process context to drain
 * those flags, start or stop manual timing, restore queue-depth accounting, and
 * write reports when a timing run ends.
 *
 * Returns nothing.
 */
void decision_timing_process_requests(const conf_t *config)
{
	unsigned int arms, stops;
	int pid, uid;

	if (atomic_exchange_explicit(&queue_depth_restore_requests, false,
			memory_order_relaxed))
		decision_timing_queue_depth_stop();

	if (atomic_exchange_explicit(&overflow_stop_requests, 0,
			memory_order_relaxed)) {
		decision_timing_queue_depth_stop();
		write_timing_report(config);
	}

	arms = atomic_exchange_explicit(&arm_requests, 0,
					memory_order_relaxed);
	if (arms) {
		pid = atomic_load_explicit(&arm_request_pid,
					   memory_order_relaxed);
		uid = atomic_load_explicit(&arm_request_uid,
					   memory_order_relaxed);
		if (config_timing_mode(config) != TIMING_COLLECTION_MANUAL) {
			msg(LOG_INFO,
			    "Decision timing start ignored because timing_collection is not manual");
		} else if (uid != 0) {
			msg(LOG_INFO,
			    "Decision timing start ignored because uid=%d is not privileged",
			    uid);
		} else
			decision_timing_arm(pid, uid);
	}

	stops = atomic_exchange_explicit(&stop_requests, 0,
					 memory_order_relaxed);
	if (stops) {
		pid = atomic_load_explicit(&stop_request_pid,
					   memory_order_relaxed);
		uid = atomic_load_explicit(&stop_request_uid,
					   memory_order_relaxed);
		if (config_timing_mode(config) != TIMING_COLLECTION_MANUAL) {
			msg(LOG_INFO,
			    "Decision timing stop ignored because timing_collection is not manual");
		} else if (uid != 0) {
			msg(LOG_INFO,
			    "Decision timing stop ignored because uid=%d is not privileged",
			    uid);
		} else
			decision_timing_stop(config, pid, uid);
	}
}

/*
 * decision_timing_control_report - write timing control state to state report.
 * @f: output stream.
 * @config: active daemon configuration.
 * Returns nothing.
 */
void decision_timing_control_report(FILE *f, const conf_t *config)
{
	const char *mode;

	if (f == NULL || config == NULL)
		return;

	mode = decision_timing_mode_name(config_timing_mode(config));
	fprintf(f, "Timing collection mode: %s\n", mode);
	fprintf(f, "Timing collection armed: %s\n",
		atomic_load_explicit(&timing_armed, memory_order_relaxed) ?
		"true" : "false");
}

/*
 * decision_timing_history_report - write timing history to state report.
 * @f: output stream.
 * Returns nothing.
 */
void decision_timing_history_report(FILE *f)
{
	char arm_time[64], stop_time[64];

	if (f == NULL)
		return;

	fprintf(f, "Timing collection last start time: %s\n",
		format_report_time(atomic_load_explicit(&last_arm_time,
			memory_order_relaxed), arm_time, sizeof(arm_time)));
	fprintf(f, "Timing collection last stop time: %s\n",
		format_report_time(atomic_load_explicit(&last_stop_time,
			memory_order_relaxed), stop_time, sizeof(stop_time)));
}

/*
 * decision_timing_decision_begin - begin timing one dequeued event.
 * @worker_id: decision worker that owns the event.
 * Returns nothing.
 */
void decision_timing_decision_begin(unsigned int worker_id)
{
	bool armed;

	decision_timing_tls.armed = false;
	decision_timing_tls.worker_id = worker_id;
	decision_timing_tls.driver = DECISION_TIMING_DRIVER_COUNT;
	decision_timing_tls.total_start_ns = 0;

	if (worker_id >= DECISION_TIMING_MAX_WORKERS)
		return;

	armed = atomic_load_explicit(&timing_armed, memory_order_acquire);
	if (DECISION_TIMING_UNLIKELY(armed)) {
		decision_timing_tls.total_start_ns = ns_now();
		if (decision_timing_tls.total_start_ns == 0)
			return;
		decision_timing_tls.armed = true;
	}
}

/*
 * decision_timing_decision_end - finish timing one dequeued event.
 * Returns nothing.
 */
void decision_timing_decision_end(void)
{
	uint64_t end;

	if (DECISION_TIMING_UNLIKELY(decision_timing_tls.armed)) {
		end = ns_now();
		if (end >= decision_timing_tls.total_start_ns)
			record_stage(DECISION_TIMING_STAGE_TOTAL,
				     end - decision_timing_tls.total_start_ns);
		decision_timing_tls.armed = false;
	}
}

/*
 * decision_timing_queue_enqueue_time - capture an enqueue timestamp if armed.
 * Returns monotonic nanoseconds for queue timing, or zero when unarmed.
 *
 * This is called by the event producer, before the decision worker has copied
 * the armed state into thread-local storage. Keep it limited to one armed-flag
 * load and only call clock_gettime() while a manual timing run is active.
 */
uint64_t decision_timing_queue_enqueue_time(void)
{
	if (DECISION_TIMING_UNLIKELY(atomic_load_explicit(&timing_armed,
			memory_order_acquire)))
		return ns_now();

	return 0;
}

/*
 * decision_timing_queue_dequeued - record time spent in the userspace queue.
 * @enqueue_ns: timestamp captured when the event was queued.
 * Returns nothing.
 */
void decision_timing_queue_dequeued(uint64_t enqueue_ns)
{
	uint64_t dequeue_ns;

	if (DECISION_TIMING_UNLIKELY(decision_timing_tls.armed &&
			enqueue_ns != 0)) {
		dequeue_ns = decision_timing_tls.total_start_ns;
		if (dequeue_ns >= enqueue_ns)
			record_stage(DECISION_TIMING_STAGE_QUEUE_WAIT,
				     dequeue_ns - enqueue_ns);
	}
}

/*
 * report_missing_helper_driver - report helper timing outside a driver once.
 * @helper: helper type being timed.
 * Returns nothing.
 */
static void report_missing_helper_driver(const char *helper)
{
	bool expected = false;

	if (!atomic_compare_exchange_strong_explicit(
			&missing_helper_driver_logged, &expected, true,
			memory_order_relaxed, memory_order_relaxed))
		return;

	msg(LOG_WARNING,
	    "Decision timing %s helper called outside evaluation/response",
	    helper);
}

/*
 * mime_stage_for_driver - map MIME helper substage to active driver stage.
 * @stage: MIME helper substage.
 * Returns a concrete timing stage, or DECISION_TIMING_STAGE_COUNT on error.
 */
static decision_timing_stage_t mime_stage_for_driver(
		decision_timing_mime_stage_t stage)
{
	static const decision_timing_stage_t map[][2] = {
		{
			DECISION_TIMING_STAGE_EVAL_MIME_DETECTION,
			DECISION_TIMING_STAGE_RESPONSE_MIME_DETECTION
		},
		{
			DECISION_TIMING_STAGE_EVAL_MIME_FAST_CLASSIFICATION,
			DECISION_TIMING_STAGE_RESPONSE_MIME_FAST_CLASSIFICATION
		},
		{
			DECISION_TIMING_STAGE_EVAL_MIME_GATHER_ELF,
			DECISION_TIMING_STAGE_RESPONSE_MIME_GATHER_ELF
		},
		{
			DECISION_TIMING_STAGE_EVAL_MIME_LIBMAGIC_FALLBACK,
			DECISION_TIMING_STAGE_RESPONSE_MIME_LIBMAGIC_FALLBACK
		}
	};
	decision_timing_driver_t driver = decision_timing_tls.driver;

	if (stage > DECISION_TIMING_MIME_LIBMAGIC_FALLBACK)
		stage = DECISION_TIMING_MIME_TOTAL;
	if (driver >= DECISION_TIMING_DRIVER_COUNT) {
		report_missing_helper_driver("MIME");
		return DECISION_TIMING_STAGE_COUNT;
	}

	return map[stage][driver];
}

/*
 * trust_db_stage_for_driver - map trust DB substage to active driver stage.
 * @stage: trust DB helper substage.
 * Returns a concrete timing stage, or DECISION_TIMING_STAGE_COUNT on error.
 */
static decision_timing_stage_t trust_db_stage_for_driver(
		decision_timing_trust_db_stage_t stage)
{
	static const decision_timing_stage_t map[][2] = {
		{
			DECISION_TIMING_STAGE_EVAL_TRUST_DB_LOOKUP,
			DECISION_TIMING_STAGE_RESPONSE_TRUST_DB_LOOKUP
		},
		{
			DECISION_TIMING_STAGE_EVAL_TRUST_DB_LOCK_WAIT,
			DECISION_TIMING_STAGE_RESPONSE_TRUST_DB_LOCK_WAIT
		},
		{
			DECISION_TIMING_STAGE_EVAL_TRUST_DB_READ,
			DECISION_TIMING_STAGE_RESPONSE_TRUST_DB_READ
		}
	};
	decision_timing_driver_t driver = decision_timing_tls.driver;

	if (stage > DECISION_TIMING_TRUST_DB_READ)
		stage = DECISION_TIMING_TRUST_DB_TOTAL;
	if (driver >= DECISION_TIMING_DRIVER_COUNT) {
		report_missing_helper_driver("trust DB");
		return DECISION_TIMING_STAGE_COUNT;
	}

	return map[stage][driver];
}

/*
 * decision_timing_mime_stage_begin_slow - time a driver-specific MIME stage.
 * @stage: MIME helper substage.
 * @span: caller-owned span storage.
 * Returns nothing.
 */
void decision_timing_mime_stage_begin_slow(decision_timing_mime_stage_t stage,
		struct decision_timing_span *span)
{
	decision_timing_stage_begin_slow(mime_stage_for_driver(stage), span);
}

/*
 * decision_timing_trust_db_stage_begin_slow - time driver-specific trust DB.
 * @stage: trust DB helper substage.
 * @span: caller-owned span storage.
 * Returns nothing.
 */
void decision_timing_trust_db_stage_begin_slow(
		decision_timing_trust_db_stage_t stage,
		struct decision_timing_span *span)
{
	decision_timing_stage_begin_slow(trust_db_stage_for_driver(stage),
					 span);
}

/*
 * decision_timing_stage_begin_slow - record a timed stage start.
 * @stage: stage being measured.
 * @span: caller-owned span storage.
 * Returns nothing.
 */
void decision_timing_stage_begin_slow(decision_timing_stage_t stage,
		struct decision_timing_span *span)
{
	if (stage >= DECISION_TIMING_STAGE_COUNT)
		return;

	span->stage = stage;
	span->start_ns = ns_now();
	if (span->start_ns == 0)
		return;
	span->active = true;
}

/*
 * decision_timing_stage_end_slow - record a timed stage result.
 * @span: span previously started.
 * Returns nothing.
 */
void decision_timing_stage_end_slow(struct decision_timing_span *span)
{
	uint64_t end;

	end = ns_now();
	if (end >= span->start_ns)
		record_stage(span->stage, end - span->start_ns);
	span->active = false;
}
