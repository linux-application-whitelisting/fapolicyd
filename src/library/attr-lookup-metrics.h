/*
 * attr-lookup-metrics.h - subject/object attribute lookup counters
 * Copyright (c) 2026 Red Hat Inc.
 * All Rights Reserved.
 *
 * This software may be freely redistributed and/or modified under the
 * terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2, or (at your option) any
 * later version.
 */

#ifndef ATTR_LOOKUP_METRICS_HEADER
#define ATTR_LOOKUP_METRICS_HEADER

#include <stdio.h>
#include "object-attr.h"
#include "subject-attr.h"

struct attr_lookup_metric_snapshot {
	unsigned long long requests;
	unsigned long long lookups;
};

void attr_lookup_metrics_set_worker(unsigned int worker_id);
void attr_lookup_metrics_count_subject_request(subject_type_t type);
void attr_lookup_metrics_count_subject_lookup(subject_type_t type);
void attr_lookup_metrics_count_object_request(object_type_t type);
void attr_lookup_metrics_count_object_lookup(object_type_t type);
int attr_lookup_metrics_subject_snapshot(subject_type_t type,
		struct attr_lookup_metric_snapshot *snapshot, int reset);
int attr_lookup_metrics_object_snapshot(object_type_t type,
		struct attr_lookup_metric_snapshot *snapshot, int reset);
void attr_lookup_metrics_report(FILE *f, int reset);

#endif
