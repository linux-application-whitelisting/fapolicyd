/*
 * decision-defer.h - bounded subject-slot deferral for decision events
 *
 * Copyright (c) 2026 Red Hat Inc.
 * All Rights Reserved.
 *
 * This software may be freely redistributed and/or modified under the
 * terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your
 * option) any later version.
 */

#ifndef DECISION_DEFER_HEADER
#define DECISION_DEFER_HEADER

#include <stdint.h>
#include <stdio.h>
#include "decision-event.h"

#define DECISION_DEFER_RATIO 16
#define DECISION_DEFER_MIN 16

struct decision_defer_metrics {
	unsigned int capacity;
	unsigned int current_depth;
	unsigned int max_depth;
	unsigned long fallbacks;
	uint64_t oldest_age_ns;
};

struct decision_defer_entry;

struct decision_defer_queue {
	struct decision_defer_entry *entries;
	unsigned int capacity;
	unsigned int current;
	unsigned int max_depth;
	unsigned long fallbacks;
	uint64_t next_order;
};

int decision_defer_init(struct decision_defer_queue *defer,
		unsigned int subj_cache_size);
void decision_defer_destroy(struct decision_defer_queue *defer);
int decision_defer_push(struct decision_defer_queue *defer,
		const decision_event_t *event);
int decision_defer_pop_slot(struct decision_defer_queue *defer,
		unsigned int slot, decision_event_t *event);
int decision_defer_pop_any(struct decision_defer_queue *defer,
		decision_event_t *event);
void decision_defer_count_fallback(struct decision_defer_queue *defer);
void decision_defer_metrics_snapshot_reset(struct decision_defer_queue *defer,
		struct decision_defer_metrics *metrics, int reset);
void decision_defer_metrics_report(FILE *f,
		const struct decision_defer_metrics *metrics);

#endif
