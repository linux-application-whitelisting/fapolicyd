/*
 * worker-health.c - decision worker health and watchdog monitor
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
 * worker-health.c owns the health timestamps embedded in each decision worker
 * and the monitor thread that interprets those timestamps. Its charter is to
 * record worker loop progress, distinguish idle workers from workers inside a
 * policy decision, detect the existing queue-backed stall condition, refresh
 * the systemd watchdog when all workers are healthy, and execute the
 * worker_stall failure action when a stall is observed.
 *
 * The state owned here is deliberately small: struct worker_health fields,
 * the monitor thread handle, the monitor callback wiring, and watchdog log
 * rate limiting. This file must not own fanotify descriptors, worker queues,
 * worker routing, decision contexts, or shutdown draining. Those are worker
 * pool responsibilities.
 *
 * The monitor sees neighboring state through worker_health_view snapshots
 * supplied by the worker pool. That keeps queue metrics and thread IDs in the
 * worker module while still letting this module make the same health decision
 * as the former notify.c implementation. systemd-notify.c remains the
 * low-level adapter; this module only calls its public watchdog helpers and
 * never reads systemd environment variables directly.
 */

#include "config.h"
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include "daemon-config.h"
#include "failure-action.h"
#include "message.h"
#include "queue.h"
#include "string-util.h"
#include "systemd-notify.h"
#include "worker-health.h"

#define HEALTH_MONITOR_INTERVAL_SEC 3
#define HEALTH_QUEUE_BACKLOG_THRESHOLD 5
#define NSEC_PER_SEC 1000000000ULL
#define USEC_TO_NSEC 1000ULL
#define SYSTEMD_WATCHDOG_LOG_INTERVAL 60

extern atomic_bool stop, run_stats;

enum worker_health_state {
	WORKER_HEALTH_IDLE,
	WORKER_HEALTH_BUSY,
};

struct worker_health_snapshot {
	enum worker_health_state state;
	uint64_t heartbeat_age_ns;
	uint64_t current_event_age_ns;
};

struct worker_health_monitor {
	pthread_t thread;
	worker_health_collect_fn collect;
	worker_health_nudge_fn nudge;
	void *ctx;
	int running;
};

static struct worker_health_monitor monitor;
static struct message_rate_limit systemd_watchdog_log =
	MESSAGE_RATE_LIMIT_INIT(SYSTEMD_WATCHDOG_LOG_INTERVAL);

static void *health_monitor_thread_main(void *arg);

/*
 * health_now_ns - read monotonic time for worker health checks.
 * Returns monotonic nanoseconds, or zero if the clock cannot be read.
 */
static uint64_t health_now_ns(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts))
		return 0;

	return (uint64_t)ts.tv_sec * NSEC_PER_SEC + (uint64_t)ts.tv_nsec;
}

/*
 * health_age_ns - compute an age from a monotonic timestamp.
 * @now: current monotonic time in nanoseconds.
 * @timestamp: older monotonic timestamp, or zero when unset.
 * Returns age in nanoseconds, or zero when the timestamp is unset or invalid.
 */
static uint64_t health_age_ns(uint64_t now, uint64_t timestamp)
{
	if (timestamp == 0 || now < timestamp)
		return 0;

	return now - timestamp;
}

/*
 * worker_health_state_name - convert a worker health state to report text.
 * @state: health state to describe.
 * Returns a static string for reports and logs.
 */
static const char *worker_health_state_name(enum worker_health_state state)
{
	switch (state) {
	case WORKER_HEALTH_IDLE:
		return "idle";
	case WORKER_HEALTH_BUSY:
		return "busy";
	}

	return "unknown";
}

/*
 * worker_health_init - initialize health timestamps for one worker slot.
 * @health: worker health state being initialized.
 * Returns nothing.
 */
void worker_health_init(struct worker_health *health)
{
	uint64_t now;

	if (health == NULL)
		return;

	now = health_now_ns();
	atomic_store_explicit(&health->heartbeat_ns, now, memory_order_relaxed);
	atomic_store_explicit(&health->current_event_started_ns, 0,
			      memory_order_relaxed);
	atomic_store_explicit(&health->last_completed_event_ns, 0,
			      memory_order_relaxed);
	atomic_store_explicit(&health->stall_reported, false,
			      memory_order_relaxed);
}

/*
 * worker_health_heartbeat - record worker loop progress.
 * @health: worker health state that made progress.
 * Returns nothing.
 */
void worker_health_heartbeat(struct worker_health *health)
{
	if (health == NULL)
		return;

	atomic_store_explicit(&health->heartbeat_ns, health_now_ns(),
			      memory_order_relaxed);
}

/*
 * worker_health_event_begin - mark the start of a policy decision.
 * @health: worker health state processing the event.
 * Returns nothing.
 */
void worker_health_event_begin(struct worker_health *health)
{
	uint64_t now;

	if (health == NULL)
		return;

	now = health_now_ns();
	atomic_store_explicit(&health->current_event_started_ns, now,
			      memory_order_release);
	atomic_store_explicit(&health->heartbeat_ns, now, memory_order_relaxed);
}

/*
 * worker_health_event_end - mark a completed policy decision.
 * @health: worker health state that finished processing.
 * Returns nothing.
 */
void worker_health_event_end(struct worker_health *health)
{
	uint64_t now;

	if (health == NULL)
		return;

	now = health_now_ns();
	atomic_store_explicit(&health->last_completed_event_ns, now,
			      memory_order_relaxed);
	atomic_store_explicit(&health->current_event_started_ns, 0,
			      memory_order_release);
	atomic_store_explicit(&health->heartbeat_ns, now, memory_order_relaxed);
	atomic_store_explicit(&health->stall_reported, false,
			      memory_order_relaxed);
}

/*
 * worker_health_snapshot - copy one worker's health timestamps.
 * @health: worker health state to inspect.
 * @snapshot: destination snapshot.
 * @now: current monotonic time in nanoseconds.
 * Returns nothing.
 */
static void worker_health_snapshot(const struct worker_health *health,
		struct worker_health_snapshot *snapshot, uint64_t now)
{
	uint64_t heartbeat, current;

	if (health == NULL || snapshot == NULL)
		return;

	heartbeat = atomic_load_explicit(&health->heartbeat_ns,
					 memory_order_relaxed);
	current = atomic_load_explicit(&health->current_event_started_ns,
				       memory_order_acquire);

	if (current != 0)
		snapshot->state = WORKER_HEALTH_BUSY;
	else
		snapshot->state = WORKER_HEALTH_IDLE;

	snapshot->heartbeat_age_ns = health_age_ns(now, heartbeat);
	snapshot->current_event_age_ns = health_age_ns(now, current);
}

/*
 * worker_health_report - write one compact decision-worker health line.
 * @f: report stream.
 * @worker_id: worker identifier for report text.
 * @health: worker health state to describe.
 */
void worker_health_report(FILE *f, unsigned int worker_id,
		const struct worker_health *health)
{
	struct worker_health_snapshot snapshot = { 0 };
	char heartbeat[32], current[32];
	const char *state;
	uint64_t now;

	if (f == NULL || health == NULL)
		return;

	now = health_now_ns();
	worker_health_snapshot(health, &snapshot, now);
	fapolicyd_format_ns(snapshot.heartbeat_age_ns, heartbeat,
			    sizeof(heartbeat));
	if (snapshot.state == WORKER_HEALTH_IDLE)
		snprintf(current, sizeof(current), "idle");
	else
		fapolicyd_format_ns(snapshot.current_event_age_ns, current,
				    sizeof(current));
	if (atomic_load_explicit(&health->stall_reported,
				 memory_order_relaxed))
		state = "stalled";
	else
		state = worker_health_state_name(snapshot.state);

	fprintf(f, "  Decision worker %u health: state=%s heartbeat=%s "
		"current_event=%s\n", worker_id, state, heartbeat, current);
}

/*
 * health_monitor_interval_ns - choose the monitor wake interval.
 * Returns half the systemd watchdog interval when enabled, otherwise the
 * legacy three-second monitor cadence.
 */
static uint64_t health_monitor_interval_ns(void)
{
	uint64_t watchdog = systemd_watchdog_interval_usec();

	if (watchdog)
		return (watchdog * USEC_TO_NSEC) / 2;

	return HEALTH_MONITOR_INTERVAL_SEC * NSEC_PER_SEC;
}

/*
 * health_stall_timeout_ns - choose the worker stall deadline.
 * Returns the systemd watchdog interval when enabled, otherwise the legacy
 * three-second stall deadline.
 */
static uint64_t health_stall_timeout_ns(void)
{
	uint64_t watchdog = systemd_watchdog_interval_usec();

	if (watchdog)
		return watchdog * USEC_TO_NSEC;

	return HEALTH_MONITOR_INTERVAL_SEC * NSEC_PER_SEC;
}

/*
 * health_monitor_sleep - sleep in short chunks so shutdown is not delayed.
 * @interval_ns: requested sleep interval in nanoseconds.
 * Returns nothing.
 */
static void health_monitor_sleep(uint64_t interval_ns)
{
	while (!atomic_load_explicit(&stop, memory_order_relaxed) &&
	       interval_ns > 0) {
		struct timespec ts;
		uint64_t chunk = interval_ns;

		if (chunk > NSEC_PER_SEC)
			chunk = NSEC_PER_SEC;
		ts.tv_sec = (time_t)(chunk / NSEC_PER_SEC);
		ts.tv_nsec = (long)(chunk % NSEC_PER_SEC);
		while (nanosleep(&ts, &ts) && errno == EINTR)
			;
		interval_ns -= chunk;
	}
}

/*
 * worker_health_is_stalled - decide whether one worker stopped progressing.
 * @snapshot: worker health timestamp snapshot.
 * @metrics: queue metrics for the worker.
 * @timeout_ns: stall deadline in nanoseconds.
 *
 * A single slow current decision can be legitimate storage latency, so the
 * compatibility action requires visible queued pressure before treating it as
 * a daemon-level stall. If no decision is active, an old queued event plus a
 * stale heartbeat means the worker is not draining its queue.
 *
 * Returns 1 when the worker is stalled, 0 otherwise.
 */
static int worker_health_is_stalled(
		const struct worker_health_snapshot *snapshot,
		const struct queue_metrics *metrics, uint64_t timeout_ns)
{
	if (snapshot == NULL || metrics == NULL || timeout_ns == 0)
		return 0;

	if (snapshot->state != WORKER_HEALTH_IDLE &&
	    snapshot->current_event_age_ns >= timeout_ns &&
	    (metrics->current_depth > HEALTH_QUEUE_BACKLOG_THRESHOLD ||
	     metrics->oldest_age_ns >= timeout_ns))
		return 1;

	if (snapshot->state == WORKER_HEALTH_IDLE &&
	    metrics->current_depth > 0 &&
	    metrics->oldest_age_ns >= timeout_ns &&
	    snapshot->heartbeat_age_ns >= timeout_ns)
		return 1;

	return 0;
}

/*
 * health_monitor_log_stall - record and report one worker stall.
 * @view: snapshot of the stalled worker supplied by the worker pool.
 * @snapshot: worker health snapshot.
 * Returns nothing.
 */
static void health_monitor_log_stall(
		const struct worker_health_view *view,
		const struct worker_health_snapshot *snapshot)
{
	char heartbeat[32], current[32], oldest[32];
	unsigned long total;

	if (view == NULL || snapshot == NULL || view->health == NULL)
		return;

	if (atomic_exchange_explicit(&view->health->stall_reported, true,
				     memory_order_relaxed))
		return;

	total = failure_action_record(FAILURE_REASON_WORKER_STALL);
	fapolicyd_format_ns(snapshot->heartbeat_age_ns, heartbeat,
			    sizeof(heartbeat));
	if (snapshot->state == WORKER_HEALTH_IDLE)
		snprintf(current, sizeof(current), "idle");
	else
		fapolicyd_format_ns(snapshot->current_event_age_ns, current,
				    sizeof(current));
	fapolicyd_format_ns(view->metrics.oldest_age_ns, oldest,
			    sizeof(oldest));

	msg(LOG_ERR,
	    "Health monitor detected stalled decision worker %u: TID=%d "
	    "state=%s heartbeat=%s current_event=%s "
	    "queue_depth=%u oldest_queued=%s action=%s "
	    "worker_stall=%lu",
	    view->id, view->tid, "stalled", heartbeat, current,
	    view->metrics.current_depth, oldest,
	    failure_action_name(failure_reason_action(
		    FAILURE_REASON_WORKER_STALL)),
	    total);
	atomic_store_explicit(&run_stats, true, memory_order_relaxed);
	if (monitor.nudge)
		monitor.nudge(monitor.ctx);
}

/*
 * health_monitor_check_workers - check every worker once.
 * @timeout_ns: stall deadline in nanoseconds.
 * Returns 1 when all workers are healthy, 0 when at least one is stalled.
 */
static int health_monitor_check_workers(uint64_t timeout_ns)
{
	struct worker_health_view views[DAEMON_CONFIG_DECISION_THREADS_MAX];
	unsigned int count, i;
	uint64_t now = health_now_ns();
	int healthy = 1;

	if (monitor.collect == NULL)
		return healthy;

	count = monitor.collect(monitor.ctx, views,
				DAEMON_CONFIG_DECISION_THREADS_MAX);
	for (i = 0; i < count; i++) {
		struct worker_health_snapshot snapshot = { 0 };
		int stalled;

		if (views[i].health == NULL)
			continue;

		worker_health_snapshot(views[i].health, &snapshot, now);
		stalled = worker_health_is_stalled(&snapshot, &views[i].metrics,
						   timeout_ns);
		if (stalled) {
			healthy = 0;
			health_monitor_log_stall(&views[i], &snapshot);
			failure_action_execute(FAILURE_REASON_WORKER_STALL);
		} else {
			atomic_store_explicit(&views[i].health->stall_reported,
					      false, memory_order_relaxed);
		}
	}

	return healthy;
}

/*
 * health_monitor_thread_main - monitor worker progress and watchdog state.
 * @arg: unused pthread argument.
 * Returns NULL when the monitor exits.
 */
static void *health_monitor_thread_main(void *arg)
{
	sigset_t sigs;

	(void)arg;

	/* This is a worker thread. Don't handle external signals. */
	sigemptyset(&sigs);
	sigaddset(&sigs, SIGTERM);
	sigaddset(&sigs, SIGHUP);
	sigaddset(&sigs, SIGUSR1);
	sigaddset(&sigs, SIGINT);
	sigaddset(&sigs, SIGQUIT);
	pthread_sigmask(SIG_SETMASK, &sigs, NULL);

	do {
		uint64_t interval_ns = health_monitor_interval_ns();
		uint64_t timeout_ns = health_stall_timeout_ns();
		int healthy = health_monitor_check_workers(timeout_ns);

		if (healthy && systemd_watchdog_enabled() &&
		    systemd_watchdog_ping()) {
			time_t now = time(NULL);

			if (message_rate_limit_allow(&systemd_watchdog_log, now))
				msg(LOG_WARNING,
				    "Cannot refresh systemd watchdog deadline");
		}
		health_monitor_sleep(interval_ns);
	} while (!stop);
	return NULL;
}

/*
 * worker_health_monitor_start - start decision worker health monitoring.
 * @collect: callback that snapshots worker health inputs.
 * @nudge: callback used to wake worker queues after a stall.
 * @ctx: callback context.
 *
 * Returns zero on success or the pthread_create error code.
 */
int worker_health_monitor_start(worker_health_collect_fn collect,
		worker_health_nudge_fn nudge, void *ctx)
{
	int rc;

	monitor.collect = collect;
	monitor.nudge = nudge;
	monitor.ctx = ctx;
	monitor.running = 0;

	rc = pthread_create(&monitor.thread, NULL,
			    health_monitor_thread_main, NULL);
	if (rc) {
		monitor.collect = NULL;
		monitor.nudge = NULL;
		monitor.ctx = NULL;
		return rc;
	}

	monitor.running = 1;
	return 0;
}

/*
 * worker_health_monitor_join - wait for the monitor thread after shutdown.
 * Returns nothing.
 */
void worker_health_monitor_join(void)
{
	if (!monitor.running)
		return;

	pthread_join(monitor.thread, NULL);
	monitor.running = 0;
	monitor.collect = NULL;
	monitor.nudge = NULL;
	monitor.ctx = NULL;
}
