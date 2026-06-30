/*
 * decision-worker.h - daemon decision worker pool interface
 * Copyright (c) 2026 Red Hat Inc.
 * All Rights Reserved.
 *
 * This software may be freely redistributed and/or modified under the
 * terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2, or (at your option) any
 * later version.
 */

#ifndef DECISION_WORKER_HEADER
#define DECISION_WORKER_HEADER

#include <stdint.h>
#include <stdio.h>
#include <sys/fanotify.h>
#include "conf.h"
#include "decision-event.h"

struct decision_worker_runtime {
	int fanotify_fd;
	const uint64_t *fanotify_mask;
	unsigned int report_interval;
};

int decision_worker_pool_open(const conf_t *conf);
int decision_worker_pool_start(const struct decision_worker_runtime *runtime);
void decision_worker_pool_shutdown(void);
void decision_worker_pool_close(void);
void decision_worker_pool_discard(void);
int decision_worker_pool_enqueue(
		const struct fanotify_event_metadata *metadata,
		unsigned int *worker_index);
unsigned int decision_worker_pool_active_count(void);
void decision_worker_pool_nudge(void);
void decision_worker_pool_queue_report(FILE *f);
void decision_worker_pool_queue_report_reset(FILE *f, int reset);
void decision_worker_pool_queue_health_report(FILE *f);
void decision_worker_pool_defer_config_report(FILE *f);
void decision_worker_pool_defer_fallback_report(FILE *f);
void decision_worker_pool_defer_age_report(FILE *f);
void decision_worker_pool_defer_health_report(FILE *f);

#ifdef TEST_SUBJECT_DEFER
int test_notify_queue_reset(unsigned int entries);
void test_notify_queue_destroy(void);
int test_notify_queue_push(const decision_event_t *event);
uint64_t test_notify_worker_heartbeat_ns(unsigned int worker_id);
void test_notify_worker_set_heartbeat_ns(unsigned int worker_id,
		uint64_t heartbeat_ns);
int test_notify_worker_dequeue_dispatch(unsigned int worker_id);
unsigned int test_notify_shutdown_queued_events(void);
int test_notify_defer_reset(unsigned int subj_cache_size);
void test_notify_defer_destroy(void);
int test_notify_defer_push(const decision_event_t *event);
unsigned int test_notify_shutdown_deferred_events(void);
unsigned int test_notify_worker_index(pid_t pid, unsigned int workers);
int test_notify_worker_pool_reset(unsigned int workers, unsigned int entries);
void test_notify_worker_pool_destroy(void);
int test_notify_enqueue_pid_fd(pid_t pid, int event_fd);
unsigned int test_notify_worker_queue_depth(unsigned int worker_id);
unsigned int test_notify_worker_drain(unsigned int worker_id, pid_t *pids,
		int *fds, unsigned int max);
#endif

#endif
