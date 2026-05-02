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
#define DECISION_TIMING_BUCKETS 10
#define DECISION_TIMING_STAGE_WIDTH 48

struct decision_timing_stage_metrics {
	atomic_ullong count;
	atomic_ullong total_ns;
	atomic_ullong max_ns;
	atomic_ullong buckets[DECISION_TIMING_BUCKETS];
};

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
	10000000ULL
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
	">10ms"
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
	"evaluation:hash_ima:total",
	"evaluation:trust_db_lookup:total",
	"evaluation:trust_db_lookup:lock_wait",
	"evaluation:trust_db_lookup:read",
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

	return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
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
	for (i = 1; i < DECISION_TIMING_STAGE_COUNT; i++) {
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
 * find_rare_expensive_stage - find rare stage with the largest total time.
 * @totals: aggregate stage snapshots.
 * @decisions: number of timed decisions.
 * @stage_out: output stage index.
 * Returns true when a stage was found.
 */
static bool find_rare_expensive_stage(
		const struct decision_timing_stage_snapshot *totals,
		unsigned long long decisions, unsigned int *stage_out)
{
	unsigned int i, stage = 0;
	unsigned long long total = 0;

	if (decisions == 0)
		return false;

	for (i = 1; i < DECISION_TIMING_STAGE_COUNT; i++) {
		if (totals[i].count == 0)
			continue;
		if (totals[i].count * 10 >= decisions)
			continue;
		if (totals[i].total_ns > total) {
			total = totals[i].total_ns;
			stage = i;
		}
	}

	if (stage == 0)
		return false;

	*stage_out = stage;
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
		percent_of_count(total->buckets[DECISION_TIMING_BUCKETS - 1],
				 total->count));
}

/*
 * write_stage_table - write observed stages ranked by total time.
 * @f: output stream.
 * @totals: aggregate stage snapshots.
 * @order: stage order to print.
 * @decisions: number of timed decisions.
 * Returns nothing.
 */
static void write_stage_table(FILE *f,
		const struct decision_timing_stage_snapshot *totals,
		const struct decision_timing_stage_order *order,
		unsigned long long decisions)
{
	unsigned int i;

	fprintf(f, "\nStage timing, sorted by total time:\n");
	fprintf(f, "%-*s %10s %14s %10s %10s %10s %12s\n",
		DECISION_TIMING_STAGE_WIDTH,
		"Stage", "Calls", "Calls/Dec", "Total", "Avg",
		"Max", "p95 bucket");

	for (i = 0; i < order->count; i++) {
		unsigned int stage = order->stages[i];
		char calls[32], total[32], avg[32], max[32];
		unsigned long long avg_ns;
		double calls_per_decision = 0.0;

		if (decisions)
			calls_per_decision =
				(double)totals[stage].count / (double)decisions;
		avg_ns = totals[stage].total_ns / totals[stage].count;
		format_count(totals[stage].count, calls, sizeof(calls));
		format_human_duration(totals[stage].total_ns, total,
				      sizeof(total));
		format_human_duration(avg_ns, avg, sizeof(avg));
		format_human_duration(totals[stage].max_ns, max,
				      sizeof(max));

		fprintf(f, "%-*s %10s %14.2f %10s %10s %10s %12s\n",
			DECISION_TIMING_STAGE_WIDTH, stage_names[stage],
			calls, calls_per_decision, total, avg, max,
			percentile_bucket(&totals[stage], 95));
	}
}

/*
 * write_not_observed - list stages that were not observed.
 * @f: output stream.
 * @totals: aggregate stage snapshots.
 * Returns nothing.
 */
static void write_not_observed(FILE *f,
		const struct decision_timing_stage_snapshot *totals)
{
	unsigned int i;
	bool any = false;

	fprintf(f, "\nNot observed:\n  ");
	for (i = 1; i < DECISION_TIMING_STAGE_COUNT; i++) {
		if (totals[i].count)
			continue;
		fprintf(f, "%s%s", any ? ", " : "", stage_names[i]);
		any = true;
	}
	if (!any)
		fprintf(f, "none");
	fputc('\n', f);
}

/*
 * write_interpretation - write a short human interpretation footer.
 * @f: output stream.
 * @totals: aggregate stage snapshots.
 * @order: stage order sorted by total time.
 * @decisions: number of timed decisions.
 * Returns nothing.
 */
static void write_interpretation(FILE *f,
		const struct decision_timing_stage_snapshot *totals,
		const struct decision_timing_stage_order *order,
		unsigned long long decisions)
{
	unsigned int stage;
	char duration[32];

	fprintf(f, "\nNotes:\n");
	if (order->count) {
		stage = order->stages[0];
		format_human_duration(totals[stage].total_ns, duration,
				      sizeof(duration));
		fprintf(f, "  Hottest stage by total time: %s (%s)\n",
			stage_names[stage], duration);
	}
	if (find_slowest_stage(totals, &stage)) {
		format_human_duration(totals[stage].max_ns, duration,
				      sizeof(duration));
		fprintf(f, "  Slowest observed stage by max: %s (%s)\n",
			stage_names[stage], duration);
	}
	if (find_rare_expensive_stage(totals, decisions, &stage)) {
		char max[32];

		format_human_duration(totals[stage].total_ns, duration,
				      sizeof(duration));
		format_human_duration(totals[stage].max_ns, max,
				      sizeof(max));
		fprintf(f,
			"  Largest rare contributor: %s (%s total, %s max)\n",
			stage_names[stage], duration, max);
	} else
		fprintf(f, "  Largest rare contributor: none observed\n");
	fprintf(f,
		"  Stage timings may be nested and do not sum to total decision latency.\n");
}

/*
 * write_timing_report - snapshot aggregates and write the timing report.
 * @config: active daemon configuration.
 * Returns nothing.
 */
static void write_timing_report(const conf_t *config)
{
	struct decision_timing_stage_snapshot totals[DECISION_TIMING_STAGE_COUNT];
	struct decision_timing_stage_order order;
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
			      1000000000ULL;

	decision_count = totals[DECISION_TIMING_STAGE_TOTAL].count;
	max_queue_depth = atomic_load_explicit(&run_max_queue_depth,
					       memory_order_relaxed);
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
			((double)duration_ns / 1000000000.0));
	else
		fprintf(f, "Throughput: n/a\n");
	if (totals[DECISION_TIMING_STAGE_TOTAL].total_ns)
		fprintf(f, "Active decision rate: %.1f decisions/sec\n",
			(double)decision_count /
			((double)totals[DECISION_TIMING_STAGE_TOTAL].total_ns /
				1000000000.0));
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

	write_overall_latency(f, &totals[DECISION_TIMING_STAGE_TOTAL]);
	write_stage_table(f, totals, &order, decision_count);
	write_not_observed(f, totals);
	write_interpretation(f, totals, &order, decision_count);

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
 * decision_timing_process_requests - consume pending manual timing requests.
 * @config: active daemon configuration.
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
