/*
 * worker-health.h - decision worker health tracking
 * Copyright (c) 2026 Red Hat Inc.
 * All Rights Reserved.
 *
 * This software may be freely redistributed and/or modified under the
 * terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2, or (at your option) any
 * later version.
 */

#ifndef WORKER_HEALTH_HEADER
#define WORKER_HEALTH_HEADER

#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include "queue.h"

struct worker_health {
	atomic_ullong heartbeat_ns;
	atomic_ullong current_event_started_ns;
	atomic_ullong last_completed_event_ns;
	atomic_bool stall_reported;
};

struct worker_health_view {
	unsigned int id;
	int tid;
	struct worker_health *health;
	struct queue_metrics metrics;
};

typedef unsigned int (*worker_health_collect_fn)(void *ctx,
		struct worker_health_view *views, unsigned int max);
typedef void (*worker_health_nudge_fn)(void *ctx);

void worker_health_init(struct worker_health *health);
void worker_health_heartbeat(struct worker_health *health);
void worker_health_event_begin(struct worker_health *health);
void worker_health_event_end(struct worker_health *health);
void worker_health_report(FILE *f, unsigned int worker_id,
		const struct worker_health *health);
int worker_health_monitor_start(worker_health_collect_fn collect,
		worker_health_nudge_fn nudge, void *ctx);
void worker_health_monitor_join(void);

#endif
