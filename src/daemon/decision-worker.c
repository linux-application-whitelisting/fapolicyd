/*
 * decision-worker.c - daemon decision worker pool
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
 * decision-worker.c owns the daemon's policy-decision worker pool. Its charter
 * is to create worker slots, route each fanotify permission event to the stable
 * subject owner, run worker threads, manage worker-local decision contexts,
 * drain queued and deferred permission events during shutdown, and assemble
 * queue/defer reports from worker-owned state.
 *
 * The state owned here is the worker array, active worker count, worker queues,
 * worker thread IDs, report timer fd, saved queue metrics, and timing
 * queue-depth hooks. This file must not own the fanotify permission group, the
 * kernel event read loop, mount marks, or FAN_Q_OVERFLOW handling; notify.c
 * owns those boundaries and hands permission metadata to this module only
 * after it decides the record needs a policy decision.
 *
 * The worker pool talks to worker-health.c through a narrow snapshot callback:
 * this file provides queue metrics, worker IDs, and health objects while the
 * health module owns the stall algorithm, watchdog ping decisions, and
 * worker_stall failure action. notify.c passes the fanotify fd and mask as
 * runtime inputs because workers must answer permission events but must not
 * manipulate fanotify marks or read kernel batches themselves.
 */

#include "config.h"
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/fanotify.h>
#include <sys/syscall.h>
#include <sys/timerfd.h>
#include <time.h>
#include <unistd.h>
#include "attr-lookup-metrics.h"
#include "conf.h"
#include "daemon-config.h"
#include "decision-config.h"
#include "decision-context.h"
#include "decision-defer.h"
#include "decision-timing.h"
#include "decision-worker.h"
#include "event.h"
#include "file.h"
#include "message.h"
#include "policy.h"
#include "queue.h"
#include "state-report.h"
#include "worker-health.h"

#define DEFER_RECHECK_INTERVAL_SEC 1
#define DECISION_WORKER_MAX DAEMON_CONFIG_DECISION_THREADS_MAX
#define HEALTH_MONITOR_INTERVAL_SEC 3

extern atomic_bool stop, run_stats;
extern conf_t config;

struct decision_worker {
	unsigned int id;
	struct queue *queue;
	struct decision_context *context;
	pthread_t thread;
	atomic_int tid;
	struct worker_health health;
};

static struct queue_metrics last_queue_metrics[DECISION_WORKER_MAX];
static unsigned int last_queue_metrics_count;
static struct decision_worker decision_workers[DECISION_WORKER_MAX];
static unsigned int active_decision_workers;
static unsigned int timing_saved_queue_depth[DECISION_WORKER_MAX];
static int rpt_timer_fd = -1;
static unsigned int rpt_interval;
static struct decision_worker_runtime worker_runtime = {
	.fanotify_fd = -1,
	.fanotify_mask = NULL,
	.report_interval = 0,
};

static void *decision_worker_main(void *arg);
static void dispatch_decision_event(struct decision_worker *worker,
		decision_event_t *event, int *rpt_is_stale);
static unsigned int release_ready_deferred_events(
		struct decision_worker *worker, int *rpt_is_stale);
static unsigned int shutdown_deferred_events(struct decision_worker *worker);
static unsigned int shutdown_queued_events(struct decision_worker *worker);
static void save_last_queue_metrics(void);
static int setup_decision_worker(const conf_t *conf, unsigned int worker_id);
static void cleanup_worker_setup(unsigned int worker_count);
static int worker_owns_reports(const struct decision_worker *worker);
static unsigned int timing_queue_depth_reset(void *ctx);
static unsigned int timing_queue_depth_restore(void *ctx, unsigned int saved);
static struct decision_worker *dispatcher_worker_for_metadata(
		const struct fanotify_event_metadata *metadata,
		unsigned int *worker_index);

/*
 * decision_worker_pool_active_count - return workers currently receiving
 * events.
 *
 * Returns zero before worker-pool initialization, otherwise the active count.
 */
unsigned int decision_worker_pool_active_count(void)
{
	return active_decision_workers;
}

/*
 * dispatcher_subject_key - choose the stable key used for worker routing.
 * @metadata: fanotify permission metadata.
 *
 * The first worker-pool implementation routes by pid. This deliberately
 * matches the current subject state model; do not replace it with round-robin
 * or queue-depth balancing because that would split one subject's startup
 * sequence across workers.
 *
 * Returns a non-negative key suitable for modulo worker selection.
 */
static unsigned int dispatcher_subject_key(
		const struct fanotify_event_metadata *metadata)
{
	if (metadata == NULL || metadata->pid <= 0)
		return 0;

	return (unsigned int)metadata->pid;
}

/*
 * dispatcher_worker_index_from_key - map one subject key to a worker.
 *
 * NOTE: This is the only way possible to route incoming events to a worker.
 * Rerouting to available workers is impossible because we need the same pid
 * to always land on the same worker so that the pattern detection state
 * machine can see the whole startup in the same cache. Never change this
 * algorithm!
 *
 * @subject_key: stable key from dispatcher_subject_key().
 * @worker_count: active decision workers.
 *
 * Returns the selected worker index. A zero worker count falls back to zero so
 * unit tests can exercise the pure routing calculation without a live daemon.
 */
static unsigned int dispatcher_worker_index_from_key(
		unsigned int subject_key, unsigned int worker_count)
{
	if (worker_count == 0)
		return 0;

	return subject_key % worker_count;
}

/*
 * dispatcher_worker_for_metadata - select the worker for one permission event.
 * @metadata: fanotify permission metadata.
 * @worker_index: optional destination for the selected index.
 *
 * Returns the selected worker, or NULL when the worker pool is not initialized.
 */
static struct decision_worker *dispatcher_worker_for_metadata(
		const struct fanotify_event_metadata *metadata,
		unsigned int *worker_index)
{
	unsigned int index;

	index = dispatcher_worker_index_from_key(
		dispatcher_subject_key(metadata), active_decision_workers);
	if (worker_index)
		*worker_index = index;

	if (index >= active_decision_workers) {
		errno = ENODEV;
		return NULL;
	}

	if (decision_workers[index].queue == NULL) {
		errno = ENODEV;
		return NULL;
	}

	return &decision_workers[index];
}

/*
 * decision_worker_pool_enqueue - hand one permission fd to a worker.
 * @metadata: fanotify metadata read by handle_events().
 * @worker_index: optional destination for the selected index.
 *
 * On success, the selected worker queue owns the copied metadata and therefore
 * owns the permission fd reply/close obligation. On failure, ownership stays
 * with the dispatcher and the caller must answer the fanotify event.
 *
 * Returns 0 on success and -1 on failure with errno set.
 */
int decision_worker_pool_enqueue(
		const struct fanotify_event_metadata *metadata,
		unsigned int *worker_index)
{
	struct decision_worker *worker;
	decision_event_t event;
	unsigned int index;

	worker = dispatcher_worker_for_metadata(metadata, &index);
	if (worker_index)
		*worker_index = index;
	if (worker == NULL)
		return -1;

	decision_event_init(&event, metadata);
	event.worker_index = index;

	return q_enqueue(worker->queue, &event);
}

/*
 * worker_context - return the decision context owned by a worker.
 * @worker: decision worker, or NULL in unit-test helper paths.
 *
 * Unit tests can exercise queue/defer cleanup without full daemon startup. In
 * that case the default thread context is used, matching the older single
 * global-context behavior.
 *
 * Returns the worker context or the current thread context fallback.
 */
static struct decision_context *worker_context(struct decision_worker *worker)
{
	if (worker && worker->context)
		return worker->context;
	return decision_context_current();
}

/*
 * worker_defer_queue - return the worker-local subject defer array.
 * @worker: decision worker whose deferred events should be accessed.
 * Returns the defer queue owned by the worker context.
 */
static struct decision_defer_queue *worker_defer_queue(
		struct decision_worker *worker)
{
	return &worker_context(worker)->defer_queue;
}

/*
 * worker_owns_reports - determine whether a worker owns daemon reports.
 * @worker: decision worker to inspect.
 *
 * Interval and signal-triggered reports use shared report state. Keep that
 * control-plane work on worker 0 while other workers only process decisions.
 *
 * Returns 1 when @worker owns reports, 0 otherwise.
 */
static int worker_owns_reports(const struct decision_worker *worker)
{
	return worker && worker->id == 0;
}

/*
 * setup_decision_worker - initialize one worker slot before threads start.
 * @conf: daemon configuration.
 * @worker_id: slot to initialize.
 *
 * Worker 0 reuses the context created by init_event_system(). Additional
 * workers get private contexts and private file-helper state so libmagic,
 * udev, caches, counters, and defers are not shared across decision threads.
 *
 * Returns 0 on success and -1 on failure with errno set when practical.
 */
static int setup_decision_worker(const conf_t *conf, unsigned int worker_id)
{
	struct decision_context *previous = decision_context_current();
	struct decision_worker *worker = &decision_workers[worker_id];
	int rc;

	worker->id = worker_id;
	worker->queue = NULL;
	worker->context = NULL;
	atomic_store_explicit(&worker->tid, 0, memory_order_relaxed);
	worker_health_init(&worker->health);

	if (worker_id == 0)
		worker->context = previous;
	else {
		worker->context = decision_context_create(conf);
		if (worker->context == NULL)
			return -1;

		decision_context_set_current(worker->context);
		rc = file_init();
		decision_context_set_current(previous);
		if (rc) {
			decision_context_destroy(worker->context);
			worker->context = NULL;
			errno = ENOMEM;
			return -1;
		}
	}

	worker->queue = q_open(conf->q_size);
	if (worker->queue == NULL) {
		if (worker_id != 0) {
			decision_context_destroy(worker->context);
			worker->context = NULL;
		}
		return -1;
	}
	decision_context_set_worker_id(worker->context, worker_id);

	return 0;
}

/*
 * cleanup_worker_setup - release partially initialized worker startup state.
 * @worker_count: number of worker slots that may own resources.
 *
 * Returns nothing.
 */
static void cleanup_worker_setup(unsigned int worker_count)
{
	unsigned int i;

	for (i = 0; i < worker_count; i++) {
		struct decision_worker *worker = &decision_workers[i];

		if (worker->queue) {
			q_close(worker->queue);
			worker->queue = NULL;
		}
		if (i != 0 && worker->context) {
			decision_context_destroy(worker->context);
			worker->context = NULL;
		}
	}
	active_decision_workers = 0;
	decision_timing_set_active_workers(0);
	decision_timing_set_queue_depth_hooks(NULL, NULL, NULL);
}

/*
 * decision_worker_pool_open - initialize worker slots and queues.
 * @conf: daemon configuration.
 *
 * Returns 0 on success and -1 after logging and cleaning up setup failures.
 */
int decision_worker_pool_open(const conf_t *conf)
{
	unsigned int i;

	active_decision_workers = 0;
	decision_timing_set_active_workers(0);
	if (conf->decision_threads == 0 ||
	    conf->decision_threads > DECISION_WORKER_MAX) {
		msg(LOG_ERR, "Invalid decision_threads value %u",
		    conf->decision_threads);
		exit(1);
	}

	for (i = 0; i < conf->decision_threads; i++) {
		if (setup_decision_worker(conf, i)) {
			msg(LOG_ERR, "Failed setting up decision worker %u (%s)",
			    i, strerror(errno));
			cleanup_worker_setup(i + 1);
			return -1;
		}
	}
	active_decision_workers = conf->decision_threads;
	decision_timing_set_active_workers(active_decision_workers);
	save_last_queue_metrics();
	decision_timing_set_queue_depth_hooks(timing_queue_depth_reset,
					      timing_queue_depth_restore,
					      NULL);

	return 0;
}

/*
 * decision_worker_collect_health - snapshot worker inputs for health checks.
 * @ctx: unused callback context.
 * @views: destination array supplied by worker-health.c.
 * @max: maximum number of views available.
 *
 * Returns the number of worker views copied.
 */
static unsigned int decision_worker_collect_health(void *ctx,
		struct worker_health_view *views, unsigned int max)
{
	unsigned int i, count = 0;

	(void)ctx;

	if (views == NULL)
		return 0;

	for (i = 0; i < active_decision_workers && count < max; i++) {
		struct decision_worker *worker = &decision_workers[i];

		if (worker->queue == NULL)
			continue;

		views[count].id = worker->id;
		views[count].tid = atomic_load_explicit(&worker->tid,
							memory_order_relaxed);
		views[count].health = &worker->health;
		q_metrics_snapshot(worker->queue, &views[count].metrics);
		count++;
	}

	return count;
}

/*
 * decision_worker_health_nudge - wake worker queues after health events.
 * @ctx: unused callback context.
 * Returns nothing.
 */
static void decision_worker_health_nudge(void *ctx)
{
	(void)ctx;

	decision_worker_pool_nudge();
}

/*
 * decision_worker_pool_start - start workers and health monitoring.
 * @runtime: fanotify runtime state used by worker-owned replies.
 *
 * Returns zero on success or a pthread_create error code after logging and
 * joining any workers already started.
 */
int decision_worker_pool_start(const struct decision_worker_runtime *runtime)
{
	unsigned int i, started_workers = 0;
	int rc;

	worker_runtime = *runtime;
	rpt_interval = runtime->report_interval;
	for (i = 0; i < active_decision_workers; i++) {
		struct decision_worker *worker = &decision_workers[i];

		rc = pthread_create(&worker->thread, NULL,
				    decision_worker_main, worker);
		if (rc) {
			msg(LOG_ERR,
			    "Failed to create decision worker %u (%s)",
			    worker->id, strerror(rc));
			atomic_store(&stop, true);
			for (i = 0; i < started_workers; i++)
				q_shutdown(decision_workers[i].queue);
			for (i = 0; i < started_workers; i++)
				pthread_join(decision_workers[i].thread, NULL);
			return rc;
		}
		started_workers++;
	}

	msg(LOG_INFO, "Activated %u fanotify decision worker%s",
	    active_decision_workers,
	    active_decision_workers == 1 ? "" : "s");

	rc = worker_health_monitor_start(decision_worker_collect_health,
					 decision_worker_health_nudge, NULL);
	if (rc) {
		msg(LOG_ERR, "Failed to create health monitor thread (%s)",
		    strerror(rc));
		atomic_store(&stop, true);
		for (i = 0; i < active_decision_workers; i++)
			q_shutdown(decision_workers[i].queue);
		for (i = 0; i < active_decision_workers; i++)
			pthread_join(decision_workers[i].thread, NULL);
		if (rpt_timer_fd != -1) {
			close(rpt_timer_fd);
			rpt_timer_fd = -1;
		}
		return rc;
	}

	return 0;
}

/*
 * queue_metrics_merge - fold one worker queue snapshot into an aggregate.
 * @aggregate: aggregate metrics being built.
 * @metrics: worker queue metrics to add.
 * Returns nothing.
 */
static void queue_metrics_merge(struct queue_metrics *aggregate,
		const struct queue_metrics *metrics)
{
	aggregate->current_depth += metrics->current_depth;
	if (metrics->max_depth > aggregate->max_depth)
		aggregate->max_depth = metrics->max_depth;
	aggregate->full_count += metrics->full_count;
	if (metrics->oldest_age_ns > aggregate->oldest_age_ns)
		aggregate->oldest_age_ns = metrics->oldest_age_ns;
}

/*
 * save_last_queue_metrics - retain final queue snapshots for reports.
 * Returns nothing.
 */
static void save_last_queue_metrics(void)
{
	unsigned int i;

	last_queue_metrics_count = 0;
	for (i = 0; i < active_decision_workers; i++) {
		struct decision_worker *worker = &decision_workers[i];

		if (worker->queue == NULL)
			continue;

		q_metrics_snapshot(worker->queue, &last_queue_metrics[i]);
		last_queue_metrics_count = i + 1;
	}
}

/*
 * decision_worker_pool_shutdown - stop worker threads after fanotify unmark.
 * Returns nothing.
 */
void decision_worker_pool_shutdown(void)
{
	unsigned int i;

	for (i = 0; i < active_decision_workers; i++)
		q_shutdown(decision_workers[i].queue);
	for (i = 0; i < active_decision_workers; i++)
		pthread_join(decision_workers[i].thread, NULL);
	worker_health_monitor_join();
}

/*
 * decision_worker_pool_close - release worker queues after normal shutdown.
 * Returns nothing.
 */
void decision_worker_pool_close(void)
{
	unsigned int i;

	save_last_queue_metrics();
	for (i = 0; i < active_decision_workers; i++) {
		struct decision_context *ctx = decision_workers[i].context;

		if (ctx == NULL)
			continue;
		decision_defer_metrics_snapshot_reset(&ctx->defer_queue,
						      &ctx->last_defer_metrics,
						      0);
	}
	decision_timing_set_queue_depth_hooks(NULL, NULL, NULL);
	decision_timing_set_active_workers(0);
	for (i = 0; i < active_decision_workers; i++) {
		if (decision_workers[i].queue == NULL)
			continue;
		q_close(decision_workers[i].queue);
		decision_workers[i].queue = NULL;
		decision_workers[i].context = NULL;
	}
	active_decision_workers = 0;
	if (rpt_timer_fd != -1) {
		close(rpt_timer_fd);
		rpt_timer_fd = -1;
	}
	worker_runtime.fanotify_fd = -1;
	worker_runtime.fanotify_mask = NULL;
	worker_runtime.report_interval = 0;
}

/*
 * decision_worker_pool_discard - release setup state before daemon exit.
 * Returns nothing.
 */
void decision_worker_pool_discard(void)
{
	if (rpt_timer_fd != -1) {
		close(rpt_timer_fd);
		rpt_timer_fd = -1;
	}
	cleanup_worker_setup(active_decision_workers);
	worker_runtime.fanotify_fd = -1;
	worker_runtime.fanotify_mask = NULL;
	worker_runtime.report_interval = 0;
}

/*
 * decision_worker_pool_nudge - wake all worker queues.
 * Returns nothing.
 */
void decision_worker_pool_nudge(void)
{
	unsigned int i;

	for (i = 0; i < active_decision_workers; i++)
		q_shutdown(decision_workers[i].queue);
}

/*
 * timing_queue_depth_reset - reset timing run max queue depth.
 * @ctx: unused.
 *
 * Returns the largest max-depth value saved across worker queues.
 */
static unsigned int timing_queue_depth_reset(void *ctx)
{
	unsigned int i, saved, aggregate = 0;

	(void)ctx;

	for (i = 0; i < active_decision_workers; i++) {
		struct decision_worker *worker = &decision_workers[i];

		if (worker->queue == NULL) {
			timing_saved_queue_depth[i] = 0;
			continue;
		}
		saved = q_max_depth_snapshot_reset(worker->queue);
		timing_saved_queue_depth[i] = saved;
		if (saved > aggregate)
			aggregate = saved;
	}

	return aggregate;
}

/*
 * timing_queue_depth_restore - snapshot timing run queue depth and restore.
 * @ctx: unused.
 * @saved: aggregate value returned by timing_queue_depth_reset().
 *
 * Returns the largest max depth observed across worker queues during the run.
 */
static unsigned int timing_queue_depth_restore(void *ctx, unsigned int saved)
{
	unsigned int i, current, aggregate = 0;

	(void)ctx;
	(void)saved;

	for (i = 0; i < active_decision_workers; i++) {
		struct decision_worker *worker = &decision_workers[i];

		if (worker->queue == NULL)
			continue;
		current = q_max_depth_snapshot_restore(worker->queue,
				timing_saved_queue_depth[i]);
		if (current > aggregate)
			aggregate = current;
		timing_saved_queue_depth[i] = 0;
	}

	return aggregate;
}

struct defer_worker_snapshot {
	unsigned int worker_id;
	struct decision_defer_metrics metrics;
};

struct defer_report_snapshot {
	struct decision_defer_metrics metrics;
	struct defer_worker_snapshot workers[DECISION_WORKER_MAX];
	unsigned int worker_count;
	int reset;
};

/*
 * defer_metrics_merge - fold one worker defer snapshot into an aggregate.
 * @aggregate: aggregate defer metrics reported to operators.
 * @metrics: metrics copied from one worker-owned defer array.
 * Returns nothing.
 */
static void defer_metrics_merge(struct decision_defer_metrics *aggregate,
		const struct decision_defer_metrics *metrics)
{
	aggregate->capacity += metrics->capacity;
	aggregate->current_depth += metrics->current_depth;
	aggregate->deferred_events += metrics->deferred_events;
	aggregate->max_depth += metrics->max_depth;
	aggregate->fallbacks += metrics->fallbacks;
	if (metrics->oldest_age_ns > aggregate->oldest_age_ns)
		aggregate->oldest_age_ns = metrics->oldest_age_ns;
}

/*
 * defer_report_snapshot_context - snapshot one worker defer array.
 * @ctx: worker context being sampled.
 * @data: struct defer_report_snapshot aggregate.
 * Returns nothing.
 */
static void defer_report_snapshot_context(struct decision_context *ctx,
		void *data)
{
	struct defer_report_snapshot *snapshot = data;
	struct decision_defer_metrics metrics;
	unsigned int index;

	if (ctx == NULL || snapshot == NULL)
		return;

	decision_defer_metrics_snapshot_reset(&ctx->defer_queue, &metrics,
					      snapshot->reset);
	ctx->last_defer_metrics = metrics;
	defer_metrics_merge(&snapshot->metrics, &metrics);
	index = snapshot->worker_count;
	if (index < DECISION_WORKER_MAX) {
		snapshot->workers[index].worker_id = ctx->worker_id;
		snapshot->workers[index].metrics = metrics;
		snapshot->worker_count++;
	}
}

/*
 * defer_report_snapshot_reset - snapshot defer counters across workers.
 * @snapshot: destination for aggregate and per-worker defer metrics.
 * @reset: non-zero resets interval counters after copying them.
 * Returns nothing.
 */
static void defer_report_snapshot_reset(struct defer_report_snapshot *snapshot,
		int reset)
{
	if (snapshot == NULL)
		return;

	memset(snapshot, 0, sizeof(*snapshot));
	snapshot->reset = reset;
	decision_context_for_each(defer_report_snapshot_context, snapshot);
}

/*
 * defer_worker_snapshot_sort - order worker defer snapshots by worker id.
 * @snapshot: defer report snapshot to sort.
 * Returns nothing.
 */
static void defer_worker_snapshot_sort(struct defer_report_snapshot *snapshot)
{
	unsigned int i, j;

	if (snapshot == NULL)
		return;

	for (i = 0; i < snapshot->worker_count; i++) {
		for (j = i + 1; j < snapshot->worker_count; j++) {
			unsigned int left = snapshot->workers[i].worker_id;
			unsigned int right = snapshot->workers[j].worker_id;

			if (left <= right)
				continue;
			{
				struct defer_worker_snapshot tmp =
					snapshot->workers[i];
				snapshot->workers[i] = snapshot->workers[j];
				snapshot->workers[j] = tmp;
			}
		}
	}
}

/*
 * decision_worker_pool_queue_report - write worker queue metrics.
 * @f: output stream.
 * Returns nothing.
 */
void decision_worker_pool_queue_report(FILE *f)
{
	decision_worker_pool_queue_report_reset(f, 0);
}

/*
 * decision_worker_pool_queue_report_reset - write worker queue metrics.
 * @f: output stream.
 * @reset: non-zero resets interval counters after copying them.
 * Returns nothing.
 */
void decision_worker_pool_queue_report_reset(FILE *f, int reset)
{
	struct queue_metrics aggregate = { 0 };
	struct queue_metrics metrics[DECISION_WORKER_MAX];
	unsigned int worker_ids[DECISION_WORKER_MAX];
	unsigned int count = 0;
	unsigned int i;

	if (f == NULL)
		return;

	if (active_decision_workers) {
		for (i = 0; i < active_decision_workers; i++) {
			struct decision_worker *worker = &decision_workers[i];

			if (worker->queue == NULL)
				continue;

			q_metrics_snapshot_reset(worker->queue, &metrics[count],
						 reset);
			worker_ids[count] = worker->id;
			queue_metrics_merge(&aggregate, &metrics[count]);
			count++;
		}
	} else {
		for (i = 0; i < last_queue_metrics_count; i++) {
			metrics[count] = last_queue_metrics[i];
			worker_ids[count] = i;
			queue_metrics_merge(&aggregate, &metrics[count]);
			count++;
		}
	}

	q_metrics_report(f, &aggregate);
	for (i = 0; i < count; i++)
		q_metrics_report_worker(f, worker_ids[i], &metrics[i]);

	{
		struct defer_report_snapshot defer_snapshot;

		defer_report_snapshot_reset(&defer_snapshot, reset);
		decision_defer_metrics_report(f, &defer_snapshot.metrics);
		if (defer_snapshot.worker_count) {
			defer_worker_snapshot_sort(&defer_snapshot);
			fprintf(f, "\nPer-worker subject defer activity:\n");
			for (i = 0; i < defer_snapshot.worker_count; i++)
				decision_defer_metrics_report_worker(f,
					defer_snapshot.workers[i].worker_id,
					&defer_snapshot.workers[i].metrics);
		}
	}
}

/*
 * decision_worker_pool_queue_health_report - write per-worker health lines.
 * @f: report stream.
 * Returns nothing.
 */
void decision_worker_pool_queue_health_report(FILE *f)
{
	unsigned int i;

	if (f == NULL)
		return;

	if (active_decision_workers) {
		for (i = 0; i < active_decision_workers; i++) {
			struct queue_metrics metrics;
			struct decision_worker *worker = &decision_workers[i];

			if (worker->queue == NULL)
				continue;

			worker_health_report(f, worker->id, &worker->health);
			q_metrics_snapshot(worker->queue, &metrics);
			q_metrics_report_worker(f, worker->id, &metrics);
		}
		return;
	}

	for (i = 0; i < last_queue_metrics_count; i++)
		q_metrics_report_worker(f, i, &last_queue_metrics[i]);
}

/*
 * decision_worker_pool_defer_config_report - write startup defer capacity.
 * @f: report stream.
 * Returns nothing.
 */
void decision_worker_pool_defer_config_report(FILE *f)
{
	struct defer_report_snapshot snapshot;
	struct decision_defer_metrics metrics;

	if (f == NULL)
		return;

	defer_report_snapshot_reset(&snapshot, 0);
	metrics = snapshot.metrics;
	if (snapshot.worker_count)
		metrics.capacity /= snapshot.worker_count;
	decision_defer_config_report(f, &metrics);
}

/*
 * decision_worker_pool_defer_fallback_report - write defer fallback health.
 * @f: report stream.
 * Returns nothing.
 */
void decision_worker_pool_defer_fallback_report(FILE *f)
{
	struct defer_report_snapshot snapshot;

	if (f == NULL)
		return;

	defer_report_snapshot_reset(&snapshot, 0);
	decision_defer_fallback_report(f, &snapshot.metrics);
}

/*
 * decision_worker_pool_defer_age_report - write oldest deferred event age.
 * @f: report stream.
 * Returns nothing.
 */
void decision_worker_pool_defer_age_report(FILE *f)
{
	struct defer_report_snapshot snapshot;

	if (f == NULL)
		return;

	defer_report_snapshot_reset(&snapshot, 0);
	decision_defer_age_report(f, &snapshot.metrics);
}

/*
 * decision_worker_pool_defer_health_report - write defer health indicators.
 * @f: report stream.
 * Returns nothing.
 */
void decision_worker_pool_defer_health_report(FILE *f)
{
	struct defer_report_snapshot snapshot;

	if (f == NULL)
		return;

	defer_report_snapshot_reset(&snapshot, 0);
	decision_defer_health_report(f, &snapshot.metrics);
}

// disable interval reports, used on unrecoverable errors
static void rpt_disable(const char *why)
{
	rpt_interval = 0;
	close(rpt_timer_fd);
	msg(LOG_INFO, "interval reports disabled; %s", why);
}

// initialize interval reporting
static void rpt_init(struct timespec *t)
{
	rpt_timer_fd = timerfd_create(CLOCK_REALTIME, TFD_NONBLOCK);
	if (rpt_timer_fd == -1) {
		rpt_disable("timer create failure");
	} else {
		t->tv_nsec = t->tv_sec = 0;
		struct itimerspec rpt_deadline = { {rpt_interval, 0},
						 {rpt_interval, 0} };
		if (timerfd_settime(rpt_timer_fd, TFD_TIMER_ABSTIME,
				    &rpt_deadline, NULL) == -1) {
			// settime errors are unrecoverable
			rpt_disable(strerror(errno));
		} else {
			msg(LOG_INFO, "interval reports configured; %us",
			    rpt_interval);
		}
	}
}

/*
 * run_decision_event - execute one policy decision for an event envelope.
 * @worker: decision worker that owns the event and reply fd.
 * @event: event to process.
 *
 * Timing starts only when an event is actually processed. A deferred event
 * keeps its original queue timestamp so queue wait includes time spent parked
 * behind a building subject.
 */
static void run_decision_event(struct decision_worker *worker,
		decision_event_t *event)
{
	attr_lookup_metrics_set_worker(worker->id);
	worker_health_event_begin(&worker->health);
	decision_timing_decision_begin(worker->id);
	decision_timing_queue_dequeued(event->enqueue_ns);
	make_policy_decision(event, worker_runtime.fanotify_fd,
			     *worker_runtime.fanotify_mask);
	decision_timing_decision_end();
	worker_health_event_end(&worker->health);
}

/*
 * dispatch_decision_event - process one worker-owned event and release defers.
 * @worker: decision worker that owns the event and reply fd.
 * @event: event envelope from the inter-thread queue.
 * @rpt_is_stale: interval report dirty flag.
 *
 * If another pid owns the same subject slot while its pattern state is still
 * before STATE_FULL, the event is parked in the bounded defer array. When the
 * array is full, processing falls back to the historical eviction behavior so
 * memory and blocked permission events remain bounded.
 */
static void dispatch_decision_event(struct decision_worker *worker,
		decision_event_t *event, int *rpt_is_stale)
{
	struct decision_defer_queue *defer = worker_defer_queue(worker);

	if (event->worker_index == DECISION_EVENT_NO_WORKER)
		event->worker_index = worker->id;
	else if (event->worker_index != worker->id)
		msg(LOG_WARNING,
		    "Decision event worker ownership mismatch: dispatcher "
		    "assigned worker %u but worker %u dequeued PID %d",
		    event->worker_index, worker->id, event->metadata.pid);

	// The wrapper may already carry a slot when it comes from the defer list.
	if (event->subject_slot == DECISION_EVENT_NO_SLOT)
		event->subject_slot = event_subject_slot(event->metadata.pid);

	/*
	 * Park only when another pid owns this subject slot and still needs
	 * its startup pattern state. If the array is full, continue into
	 * normal processing so new_event() applies the historical eviction
	 * behavior.
	 */
	if (event_subject_slot_is_blocked(event->subject_slot,
					  event->metadata.pid)) {
		if (decision_defer_push(defer, event) == 0) {
			*rpt_is_stale = 1;
			return;
		}
		decision_defer_count_fallback(defer);
	}

	for (;;) {
		unsigned int slot;

		/*
		 * Turn one completed subject slot into a chain of policy
		 * decisions. This lets backed-up events for that slot flow
		 * through immediately instead of waiting for the next fanotify
		 * dequeue cycle.
		 *
		 * Process the current event. This may be the original queue
		 * event or a deferred event popped at the bottom of the loop.
		 */
		*rpt_is_stale = 1;
		run_decision_event(worker, event);

		/*
		 * make_policy_decision() sets completed_subject_slot only when
		 * processing leaves a slot empty, STATE_FULL, or later. Without
		 * that signal there is no deferred work that can be unblocked.
		 */
		slot = event->completed_subject_slot;
		if (slot == DECISION_EVENT_NO_SLOT)
			return;
		/*
		 * A deferred event can start building a fresh subject in this
		 * same slot. Stop if it became blocked again. Otherwise pop
		 * the oldest event waiting for this slot and repeat.
		 *
		 * The loop cannot run forever: every iteration either returns
		 * or removes one entry from the fixed-size defer array.
		 */
		if (!event_subject_slot_is_unblocked(slot))
			return;
		if (!decision_defer_pop_slot(defer, slot, event))
			return;
	}
}

/*
 * deferred_event_is_ready - test whether a parked event can run now.
 * @event: deferred event to inspect.
 * @ctx: unused predicate context.
 *
 * Calling event_subject_slot_is_blocked() intentionally reuses the same
 * traced/stale BUILDING eviction check used by fresh events. Without this
 * recheck, a deferred event can wait forever when no later event collides with
 * the same subject slot.
 *
 * Returns 1 when the event can run, 0 when it must remain deferred.
 */
static int deferred_event_is_ready(const decision_event_t *event, void *ctx)
{
	(void)ctx;

	return !event_subject_slot_is_blocked(event->subject_slot,
					      event->metadata.pid);
}

/*
 * release_ready_deferred_events - run deferred events that are unblocked.
 * @rpt_is_stale: interval report dirty flag.
 *
 * Periodic rechecks keep the 10 second BUILDING stale timeout effective even
 * when no new fanotify event arrives for the same subject slot. Each pass pops
 * the oldest ready event and dispatches it through the normal decision path.
 *
 * Returns the number of deferred events released.
 */
static unsigned int release_ready_deferred_events(
		struct decision_worker *worker, int *rpt_is_stale)
{
	struct decision_defer_queue *defer = worker_defer_queue(worker);
	decision_event_t event;
	unsigned int count = 0;

	while (defer->current &&
	       decision_defer_pop_if(defer, deferred_event_is_ready,
				     NULL, &event)) {
		dispatch_decision_event(worker, &event, rpt_is_stale);
		count++;
	}

	if (count)
		msg(LOG_DEBUG, "Released %u deferred fanotify events", count);
	return count;
}

/*
 * shutdown_fallback_decision - get the shutdown reply decision.
 * Returns FAN_ALLOW in permissive mode and FAN_DENY otherwise.
 */
static int shutdown_fallback_decision(void)
{
	if (decision_config_permissive(NULL))
		return FAN_ALLOW;
	return FAN_DENY;
}

/*
 * shutdown_queued_events - reply to every event left in a worker queue.
 * @worker: decision worker whose queue is being drained.
 *
 * A decision worker exits its main loop as soon as stop is observed. Any
 * permission event that reached the worker queue but was not processed yet
 * still owns a live fd and can leave the requesting task blocked. During
 * shutdown, answer those queued events with the same permissive fallback
 * policy used for other bounded failure paths.
 *
 * Returns the number of events answered.
 */
static unsigned int shutdown_queued_events(struct decision_worker *worker)
{
	decision_event_t event;
	unsigned int count = 0;
	int decision = shutdown_fallback_decision();

	if (worker == NULL || worker->queue == NULL)
		return 0;

	while (q_queue_length(worker->queue) > 0) {
		if (q_dequeue(worker->queue, &event) != 1)
			break;
		reply_event(worker_runtime.fanotify_fd, &event.metadata,
			    decision, NULL);
		count++;
	}

	return count;
}

/*
 * shutdown_deferred_events - reply to every event left in the defer array.
 *
 * Deferred fanotify permission events still own live fds. During shutdown each
 * must be answered exactly once, using the same permissive fallback policy as
 * queue-full handling, so the blocked task and descriptor are released.
 *
 * Returns the number of events answered.
 */
static unsigned int shutdown_deferred_events(struct decision_worker *worker)
{
	struct decision_defer_queue *defer = worker_defer_queue(worker);
	decision_event_t event;
	unsigned int count = 0;
	int decision = shutdown_fallback_decision();

	while (decision_defer_pop_any(defer, &event)) {
		reply_event(worker_runtime.fanotify_fd, &event.metadata,
			    decision, NULL);
		count++;
	}

	return count;
}

#ifdef TEST_SUBJECT_DEFER
void test_notify_worker_pool_destroy(void);

/*
 * test_notify_queue_reset - initialize worker queue state for unit tests.
 * @entries: fixed queue capacity.
 *
 * Returns 0 on success and -1 on allocation failure.
 */
int test_notify_queue_reset(unsigned int entries)
{
	struct decision_worker *worker = &decision_workers[0];

	if (worker->queue != NULL)
		q_close(worker->queue);
	worker->id = 0;
	worker->context = decision_context_current();
	decision_context_set_worker_id(worker->context, 0);
	atomic_store_explicit(&worker->tid, 0, memory_order_relaxed);
	worker_health_init(&worker->health);
	worker->queue = q_open(entries);
	active_decision_workers = worker->queue ? 1 : 0;
	return worker->queue == NULL ? -1 : 0;
}

/*
 * test_notify_queue_destroy - release worker queue state after unit tests.
 * Returns nothing.
 */
void test_notify_queue_destroy(void)
{
	struct decision_worker *worker = &decision_workers[0];

	if (worker->queue == NULL)
		return;
	q_close(worker->queue);
	worker->queue = NULL;
	worker->context = NULL;
	active_decision_workers = 0;
}

/*
 * test_notify_queue_push - enqueue an event in worker queue state.
 * @event: event copied into the queue.
 *
 * Returns 0 on success and -1 when the queue rejects the event.
 */
int test_notify_queue_push(const decision_event_t *event)
{
	return q_enqueue(decision_workers[0].queue, event);
}

/*
 * test_notify_shutdown_queued_events - run production queue cleanup.
 * Returns the number of queued events answered.
 */
unsigned int test_notify_shutdown_queued_events(void)
{
	return shutdown_queued_events(&decision_workers[0]);
}

/*
 * test_notify_defer_reset - initialize worker defer state for unit tests.
 * @subj_cache_size: subject cache size used to derive defer capacity.
 *
 * Returns 0 on success and -1 on allocation failure.
 */
int test_notify_defer_reset(unsigned int subj_cache_size)
{
	struct decision_worker *worker = &decision_workers[0];
	struct decision_defer_queue *defer;

	worker->id = 0;
	worker->context = decision_context_current();
	decision_context_set_worker_id(worker->context, 0);
	defer = worker_defer_queue(worker);
	decision_defer_destroy(defer);
	return decision_defer_init(defer, subj_cache_size);
}

/*
 * test_notify_defer_destroy - release worker defer state after unit tests.
 * Returns nothing.
 */
void test_notify_defer_destroy(void)
{
	struct decision_worker *worker = &decision_workers[0];

	decision_defer_destroy(worker_defer_queue(worker));
	worker->context = NULL;
}

/*
 * test_notify_defer_push - park an event in worker defer state.
 * @event: event copied into the defer queue.
 *
 * Returns 0 on success and -1 when the queue rejects the event.
 */
int test_notify_defer_push(const decision_event_t *event)
{
	return decision_defer_push(worker_defer_queue(&decision_workers[0]),
				   event);
}

/*
 * test_notify_shutdown_deferred_events - run production shutdown cleanup.
 * Returns the number of deferred events answered.
 */
unsigned int test_notify_shutdown_deferred_events(void)
{
	return shutdown_deferred_events(&decision_workers[0]);
}

/*
 * test_notify_worker_index - expose stable subject routing for tests.
 * @pid: synthetic fanotify pid.
 * @workers: synthetic active worker count.
 *
 * Returns the worker index selected by the dispatcher key function.
 */
unsigned int test_notify_worker_index(pid_t pid, unsigned int workers)
{
	struct fanotify_event_metadata metadata = {
		.pid = pid,
	};

	return dispatcher_worker_index_from_key(
		dispatcher_subject_key(&metadata), workers);
}

/*
 * test_notify_worker_pool_reset - initialize multiple worker queues for tests.
 * @workers: number of synthetic active workers.
 * @entries: queue capacity per worker.
 *
 * Returns 0 on success and -1 on allocation failure.
 */
int test_notify_worker_pool_reset(unsigned int workers, unsigned int entries)
{
	unsigned int i;

	if (workers == 0 || workers > DECISION_WORKER_MAX) {
		errno = EINVAL;
		return -1;
	}

	for (i = 0; i < DECISION_WORKER_MAX; i++) {
		if (decision_workers[i].queue) {
			q_close(decision_workers[i].queue);
			decision_workers[i].queue = NULL;
		}
		decision_workers[i].context = NULL;
	}
	active_decision_workers = 0;

	for (i = 0; i < workers; i++) {
		decision_workers[i].id = i;
		decision_workers[i].context = decision_context_current();
		decision_context_set_worker_id(decision_workers[i].context, i);
		atomic_store_explicit(&decision_workers[i].tid, 0,
				      memory_order_relaxed);
		worker_health_init(&decision_workers[i].health);
		decision_workers[i].queue = q_open(entries);
		if (decision_workers[i].queue == NULL) {
			test_notify_worker_pool_destroy();
			return -1;
		}
	}
	active_decision_workers = workers;
	decision_timing_set_active_workers(workers);
	return 0;
}

/*
 * test_notify_worker_pool_destroy - release synthetic worker queues.
 * Returns nothing.
 */
void test_notify_worker_pool_destroy(void)
{
	unsigned int i;

	for (i = 0; i < DECISION_WORKER_MAX; i++) {
		if (decision_workers[i].queue) {
			q_close(decision_workers[i].queue);
			decision_workers[i].queue = NULL;
		}
		decision_workers[i].context = NULL;
	}
	active_decision_workers = 0;
	decision_timing_set_active_workers(0);
}

/*
 * test_notify_enqueue_pid_fd - route one synthetic event through dispatcher.
 * @pid: synthetic fanotify pid.
 * @event_fd: marker stored in metadata.fd for ordering assertions.
 *
 * Returns 0 on successful enqueue and -1 on dispatcher/queue failure.
 */
int test_notify_enqueue_pid_fd(pid_t pid, int event_fd)
{
	struct fanotify_event_metadata metadata = {
		.fd = event_fd,
		.pid = pid,
		.mask = FAN_OPEN_PERM,
	};

	return decision_worker_pool_enqueue(&metadata, NULL);
}

/*
 * test_notify_worker_queue_depth - return synthetic worker queue depth.
 * @worker_id: worker queue to inspect.
 *
 * Returns the current queue depth, or UINT_MAX when @worker_id is invalid.
 */
unsigned int test_notify_worker_queue_depth(unsigned int worker_id)
{
	if (worker_id >= active_decision_workers ||
	    decision_workers[worker_id].queue == NULL)
		return UINT_MAX;

	return q_queue_length(decision_workers[worker_id].queue);
}

/*
 * test_notify_worker_drain - drain one synthetic worker queue.
 * @worker_id: worker queue to drain.
 * @pids: optional destination for dequeued pids.
 * @fds: optional destination for dequeued metadata fd markers.
 * @max: maximum entries available in @pids and @fds.
 *
 * Returns the number of events drained.
 */
unsigned int test_notify_worker_drain(unsigned int worker_id, pid_t *pids,
		int *fds, unsigned int max)
{
	decision_event_t event;
	unsigned int count = 0;
	struct queue *queue;

	if (worker_id >= active_decision_workers)
		return 0;
	queue = decision_workers[worker_id].queue;
	if (queue == NULL)
		return 0;

	while (count < max && q_queue_length(queue) > 0) {
		if (q_dequeue(queue, &event) != 1)
			break;
		if (pids)
			pids[count] = event.metadata.pid;
		if (fds)
			fds[count] = event.metadata.fd;
		count++;
	}

	return count;
}
#endif

/*
 * decision_worker_main - run policy decisions for one worker queue.
 * @arg: struct decision_worker pointer.
 * Returns NULL when the worker exits.
 */
static void *decision_worker_main(void *arg)
{
	struct decision_worker *worker = arg;
	sigset_t sigs;
	int owns_reports = worker_owns_reports(worker);

	/* This is a worker thread. Don't handle external signals. */
	sigemptyset(&sigs);
	sigaddset(&sigs, SIGTERM);
	sigaddset(&sigs, SIGHUP);
	sigaddset(&sigs, SIGUSR1);
	sigaddset(&sigs, SIGINT);
	sigaddset(&sigs, SIGQUIT);
	pthread_sigmask(SIG_SETMASK, &sigs, NULL);

	if (worker == NULL || worker->queue == NULL ||
	    worker->context == NULL)
		return NULL;
	atomic_store_explicit(&worker->tid, (int)syscall(SYS_gettid),
			      memory_order_relaxed);
	worker_health_heartbeat(&worker->health);
	/*
	 * The decision path uses decision_context_current() in cache, file, and
	 * policy helpers. Bind this thread before any event or report work so
	 * all mutable state stays private to this worker.
	 */
	decision_context_set_current(worker->context);

	// interval reporting state
	int rpt_is_stale = 0;
	struct timespec rpt_timeout;

	// if an interval was configured, reports are enabled
	if (owns_reports && rpt_interval)
		rpt_init(&rpt_timeout);

	// start with a fresh report
	if (owns_reports)
		atomic_store_explicit(&run_stats, true, memory_order_relaxed);

	while (!stop) {
		int rc;
		decision_event_t event;

		/*
		 * Apply asynchronous timing-control work on the decision
		 * worker. SIGUSR1 handlers and overflow detection only set
		 * atomic request flags; this call starts/stops manual timing,
		 * restores queue-depth accounting, and writes any required
		 * timing report outside signal context.
		 */
		decision_timing_process_requests(&config);

		// if an interval has been configured
		if (owns_reports && rpt_interval) {
			errno = 0;
			rc = q_timed_dequeue(worker->queue, &event,
					     &rpt_timeout);
			if (rc == 0) {
				uint64_t expired = 0;

				worker_health_heartbeat(&worker->health);
				// check for timer expirations
				if (errno == ETIMEDOUT) {
					if (read(rpt_timer_fd, &expired,
						 sizeof(uint64_t)) == -1) {
						// EAGAIN expected w/nonblocking
						// timer. Any other error is
						// unrecoverable.
						if (errno != EAGAIN) {
							rpt_disable(
							    strerror(errno));
							continue;
						}
					}
				}
				// timer expired or stats explicitly requested
				if (expired || atomic_load_explicit(&run_stats,
							memory_order_relaxed)) {
					bool stats_requested =
						atomic_exchange_explicit(
							&run_stats, false,
							memory_order_relaxed);
					// write a new report only when one of
					// 1. new events seen since last report
					// 2. explicitly requested w/run_stats
					if (rpt_is_stale || stats_requested) {
						state_report_write(
						    state_report_reason_for_triggers(
							expired));
						rpt_is_stale = 0;
					}
					// adjust the timed dequeue timeout to
					// a full interval from now
					if (clock_gettime(CLOCK_REALTIME,
							&rpt_timeout)) {
						// gettime errors are
						// unrecoverable
						rpt_disable("clock failure");
						continue;
					}
					rpt_timeout.tv_sec += rpt_interval;
				}
				continue;
			}
			if (rc < 0)
				continue;
		} else {
			int timed_for_defer = 0;
			struct timespec timeout;
			unsigned int timeout_sec = HEALTH_MONITOR_INTERVAL_SEC;

			if (worker->context->defer_queue.current)
				timeout_sec = DEFER_RECHECK_INTERVAL_SEC;
			if (clock_gettime(CLOCK_REALTIME, &timeout) == 0) {
				timeout.tv_sec += timeout_sec;
				errno = 0;
				rc = q_timed_dequeue(worker->queue, &event,
						     &timeout);
				timed_for_defer =
					worker->context->defer_queue.current != 0;
			} else {
				rc = q_dequeue(worker->queue, &event);
			}
			if (rc == 0) {
				worker_health_heartbeat(&worker->health);
				if (owns_reports &&
				    atomic_exchange_explicit(&run_stats, false,
							    memory_order_relaxed)) {
					state_report_write(STATE_REPORT_SIGNAL);
				}
				if (timed_for_defer && errno == ETIMEDOUT)
					release_ready_deferred_events(
						worker, &rpt_is_stale);
				continue;
			}
			if (rc < 0)
				continue;
			if (owns_reports &&
			    atomic_exchange_explicit(&run_stats, false,
						    memory_order_relaxed)) {
				state_report_write(STATE_REPORT_SIGNAL);
			}
		}

		dispatch_decision_event(worker, &event, &rpt_is_stale);
	}
	unsigned int queued = shutdown_queued_events(worker);
	unsigned int deferred = shutdown_deferred_events(worker);

	if (queued || deferred)
		msg(LOG_INFO,
		    "Replied to %u queued and %u deferred fanotify events during shutdown",
		    queued, deferred);
	msg(LOG_DEBUG,
	    "Decision worker %u shutdown backlog: queued=%u deferred=%u",
	    worker->id, queued, deferred);
	msg(LOG_DEBUG, "Exiting decision worker %u", worker->id);
	decision_context_set_current(NULL);
	return NULL;
}
