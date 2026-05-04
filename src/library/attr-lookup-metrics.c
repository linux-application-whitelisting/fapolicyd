/*
 * attr-lookup-metrics.c - subject/object attribute lookup counters
 * Copyright (c) 2026 Red Hat Inc.
 * All Rights Reserved.
 *
 * This software may be freely redistributed and/or modified under the
 * terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2, or (at your option) any
 * later version.
 */

#include "config.h"
#include <stdatomic.h>
#include "attr-lookup-metrics.h"

#define ATTR_LOOKUP_METRICS_MAX_WORKERS 32

struct attr_lookup_counter {
	atomic_ullong requests;
	atomic_ullong lookups;
};

/*
 * Keep counters in worker-local blocks so a future decision worker pool can
 * update attributes without bouncing one shared cache line.
 */
struct attr_lookup_worker_block {
	struct attr_lookup_counter subjects[SUBJ_COUNT];
	struct attr_lookup_counter objects[OBJ_COUNT];
} __attribute__((aligned(64)));

static struct attr_lookup_worker_block
	workers[ATTR_LOOKUP_METRICS_MAX_WORKERS];
static __thread unsigned int attr_lookup_worker;

/*
 * attr_lookup_metrics_set_worker - select the caller's metric block.
 * @worker_id: decision worker identifier.
 * Returns nothing.
 */
void attr_lookup_metrics_set_worker(unsigned int worker_id)
{
	attr_lookup_worker = worker_id;
}

/*
 * subject_index - convert a real subject attribute to a counter index.
 * @type: subject attribute.
 * @index: destination for the array index.
 * Return codes:
 * 0 - index populated.
 * 1 - pseudo attribute or invalid attribute.
 */
static int subject_index(subject_type_t type, unsigned int *index)
{
	if (type <= ALL_SUBJ || type == PATTERN || type > SUBJ_END)
		return 1;

	*index = type - SUBJ_START;
	return 0;
}

/*
 * object_index - convert a real object attribute to a counter index.
 * @type: object attribute.
 * @index: destination for the array index.
 * Return codes:
 * 0 - index populated.
 * 1 - pseudo attribute or invalid attribute.
 */
static int object_index(object_type_t type, unsigned int *index)
{
	if (type <= ALL_OBJ || type > OBJ_END)
		return 1;

	*index = type - OBJ_START;
	return 0;
}

/*
 * counter_increment - add one to a relaxed metric counter.
 * @counter: counter to update.
 * Returns nothing.
 */
static void counter_increment(atomic_ullong *counter)
{
	atomic_fetch_add_explicit(counter, 1, memory_order_relaxed);
}

/*
 * counter_snapshot - read one metric counter and optionally clear it.
 * @counter: counter to read.
 * @reset: non-zero clears the counter after copying.
 * Returns the copied counter value.
 */
static unsigned long long counter_snapshot(atomic_ullong *counter, int reset)
{
	if (reset)
		return atomic_exchange_explicit(counter, 0,
						memory_order_relaxed);

	return atomic_load_explicit(counter, memory_order_relaxed);
}

/*
 * attr_lookup_metrics_count_subject_request - count a subject attr request.
 * @type: requested subject attribute.
 * Returns nothing.
 */
void attr_lookup_metrics_count_subject_request(subject_type_t type)
{
	unsigned int index, worker = attr_lookup_worker;

	if (worker >= ATTR_LOOKUP_METRICS_MAX_WORKERS)
		return;
	if (subject_index(type, &index))
		return;

	counter_increment(&workers[worker].subjects[index].requests);
}

/*
 * attr_lookup_metrics_count_subject_lookup - count a subject attr lookup.
 * @type: requested subject attribute missing from the event cache.
 * Returns nothing.
 */
void attr_lookup_metrics_count_subject_lookup(subject_type_t type)
{
	unsigned int index, worker = attr_lookup_worker;

	if (worker >= ATTR_LOOKUP_METRICS_MAX_WORKERS)
		return;
	if (subject_index(type, &index))
		return;

	counter_increment(&workers[worker].subjects[index].lookups);
}

/*
 * attr_lookup_metrics_count_object_request - count an object attr request.
 * @type: requested object attribute.
 * Returns nothing.
 */
void attr_lookup_metrics_count_object_request(object_type_t type)
{
	unsigned int index, worker = attr_lookup_worker;

	if (worker >= ATTR_LOOKUP_METRICS_MAX_WORKERS)
		return;
	if (object_index(type, &index))
		return;

	counter_increment(&workers[worker].objects[index].requests);
}

/*
 * attr_lookup_metrics_count_object_lookup - count an object attr lookup.
 * @type: requested object attribute missing from the event cache.
 * Returns nothing.
 */
void attr_lookup_metrics_count_object_lookup(object_type_t type)
{
	unsigned int index, worker = attr_lookup_worker;

	if (worker >= ATTR_LOOKUP_METRICS_MAX_WORKERS)
		return;
	if (object_index(type, &index))
		return;

	counter_increment(&workers[worker].objects[index].lookups);
}

/*
 * attr_lookup_metrics_subject_snapshot - copy one subject counter.
 * @type: subject attribute to snapshot.
 * @snapshot: destination for aggregated counters.
 * @reset: non-zero resets counters after copying.
 * Return codes:
 * 0 - snapshot populated.
 * 1 - invalid argument or pseudo attribute.
 */
int attr_lookup_metrics_subject_snapshot(subject_type_t type,
		struct attr_lookup_metric_snapshot *snapshot, int reset)
{
	unsigned int index, worker;

	if (snapshot == NULL || subject_index(type, &index))
		return 1;

	snapshot->requests = 0;
	snapshot->lookups = 0;
	for (worker = 0; worker < ATTR_LOOKUP_METRICS_MAX_WORKERS; worker++) {
		snapshot->requests += counter_snapshot(
			&workers[worker].subjects[index].requests, reset);
		snapshot->lookups += counter_snapshot(
			&workers[worker].subjects[index].lookups, reset);
	}

	return 0;
}

/*
 * attr_lookup_metrics_object_snapshot - copy one object counter.
 * @type: object attribute to snapshot.
 * @snapshot: destination for aggregated counters.
 * @reset: non-zero resets counters after copying.
 * Return codes:
 * 0 - snapshot populated.
 * 1 - invalid argument or pseudo attribute.
 */
int attr_lookup_metrics_object_snapshot(object_type_t type,
		struct attr_lookup_metric_snapshot *snapshot, int reset)
{
	unsigned int index, worker;

	if (snapshot == NULL || object_index(type, &index))
		return 1;

	snapshot->requests = 0;
	snapshot->lookups = 0;
	for (worker = 0; worker < ATTR_LOOKUP_METRICS_MAX_WORKERS; worker++) {
		snapshot->requests += counter_snapshot(
			&workers[worker].objects[index].requests, reset);
		snapshot->lookups += counter_snapshot(
			&workers[worker].objects[index].lookups, reset);
	}

	return 0;
}

/*
 * report_subject_attrs - write all subject attribute lookup counters.
 * @f: output stream.
 * @reset: non-zero resets counters after copying.
 * Returns nothing.
 */
static void report_subject_attrs(FILE *f, int reset)
{
	unsigned int type;

	fprintf(f, "Subject attribute lookups:\n");
	for (type = SUBJ_START; type <= SUBJ_END; type++) {
		const char *name = subj_val_to_name(type, RULE_FMT_COLON);
		struct attr_lookup_metric_snapshot snapshot;

		if (type == ALL_SUBJ)
			continue;
		if (attr_lookup_metrics_subject_snapshot(type, &snapshot,
							 reset))
			continue;

		fprintf(f, "Subject attr: %s requests=%llu lookups=%llu\n",
			name ? name : "unknown",
			snapshot.requests, snapshot.lookups);
	}
}

/*
 * report_object_attrs - write all object attribute lookup counters.
 * @f: output stream.
 * @reset: non-zero resets counters after copying.
 * Returns nothing.
 */
static void report_object_attrs(FILE *f, int reset)
{
	unsigned int type;

	fprintf(f, "\nObject attribute lookups:\n");
	for (type = OBJ_START; type <= OBJ_END; type++) {
		const char *name = obj_val_to_name(type);
		struct attr_lookup_metric_snapshot snapshot;

		if (type == ALL_OBJ)
			continue;
		if (attr_lookup_metrics_object_snapshot(type, &snapshot,
							reset))
			continue;

		fprintf(f, "Object attr: %s requests=%llu lookups=%llu\n",
			name ? name : "unknown",
			snapshot.requests, snapshot.lookups);
	}
}

/*
 * attr_lookup_metrics_report - write subject/object attribute counters.
 * @f: output stream.
 * @reset: non-zero resets counters after copying.
 * Returns nothing.
 */
void attr_lookup_metrics_report(FILE *f, int reset)
{
	if (f == NULL)
		return;

	report_subject_attrs(f, reset);
	report_object_attrs(f, reset);
}
