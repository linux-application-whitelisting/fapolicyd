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
#include <stdint.h>
#include <stdatomic.h>
#include "attr-lookup-metrics.h"

#define ATTR_LOOKUP_METRICS_MAX_WORKERS 32
#define ATTR_LOOKUP_LABEL_WIDTH 13
#define ATTR_LOOKUP_NAME_WIDTH 9
#define ATTR_LOOKUP_REQUEST_NARROW_WIDTH 10
#define ATTR_LOOKUP_REQUEST_WIDE_WIDTH 20
#define ATTR_LOOKUP_REQUEST_NARROW_MAX UINT32_MAX

struct attr_lookup_counter {
	atomic_ullong requests;
	atomic_ullong lookups;
};

struct attr_lookup_report_row {
	const char *label;
	const char *name;
	const struct attr_lookup_metric_snapshot *snapshot;
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
static atomic_int attr_lookup_request_width =
	ATOMIC_VAR_INIT(ATTR_LOOKUP_REQUEST_NARROW_WIDTH);
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
 * write_attr_lookup_metric - write one aligned attribute lookup row.
 * @f: output stream.
 * @row: report row metadata and metric snapshot.
 * @request_width: field width for request counts.
 * Returns nothing.
 */
static void write_attr_lookup_metric(FILE *f,
		const struct attr_lookup_report_row *row, int request_width)
{
	fprintf(f, "%-*s %-*s requests=%-*llu lookups=%llu\n",
		ATTR_LOOKUP_LABEL_WIDTH, row->label,
		ATTR_LOOKUP_NAME_WIDTH, row->name ? row->name : "unknown",
		request_width, row->snapshot->requests,
		row->snapshot->lookups);
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
 * snapshot_subject_attrs - copy all subject attribute counters.
 * @snapshots: destination array indexed by subject attribute offset.
 * @reset: non-zero resets counters after copying.
 * Returns nothing.
 */
static void snapshot_subject_attrs(
		struct attr_lookup_metric_snapshot snapshots[SUBJ_COUNT],
		int reset)
{
	unsigned int type;

	for (type = SUBJ_START; type <= SUBJ_END; type++)
		attr_lookup_metrics_subject_snapshot(type,
			&snapshots[type - SUBJ_START], reset);
}

/*
 * snapshot_object_attrs - copy all object attribute counters.
 * @snapshots: destination array indexed by object attribute offset.
 * @reset: non-zero resets counters after copying.
 * Returns nothing.
 */
static void snapshot_object_attrs(
		struct attr_lookup_metric_snapshot snapshots[OBJ_COUNT],
		int reset)
{
	unsigned int type;

	for (type = OBJ_START; type <= OBJ_END; type++)
		attr_lookup_metrics_object_snapshot(type,
			&snapshots[type - OBJ_START], reset);
}

/*
 * request_width_check_snapshot - widen request column if needed.
 * @snapshot: metric snapshot to inspect.
 * @width: current request column width.
 * Returns the request column width to use.
 */
static int request_width_check_snapshot(
		const struct attr_lookup_metric_snapshot *snapshot, int width)
{
	if (width == ATTR_LOOKUP_REQUEST_WIDE_WIDTH)
		return width;
	if (snapshot->requests > ATTR_LOOKUP_REQUEST_NARROW_MAX)
		return ATTR_LOOKUP_REQUEST_WIDE_WIDTH;
	return width;
}

/*
 * request_width_for_report - choose request field width for this report.
 * @subjects: subject attribute snapshots.
 * @objects: object attribute snapshots.
 *
 * Width 10 keeps normal counters compact and covers UINT32_MAX. Once a wider
 * request counter is seen, future reports stay wide until a reset report.
 *
 * Returns the request column width to use.
 */
static int request_width_for_report(
		const struct attr_lookup_metric_snapshot subjects[SUBJ_COUNT],
		const struct attr_lookup_metric_snapshot objects[OBJ_COUNT])
{
	unsigned int type;
	int width;

	width = atomic_load_explicit(&attr_lookup_request_width,
				     memory_order_relaxed);
	if (width == ATTR_LOOKUP_REQUEST_WIDE_WIDTH)
		return width;

	for (type = SUBJ_START; type <= SUBJ_END; type++) {
		if (type == ALL_SUBJ || type == PATTERN)
			continue;
		width = request_width_check_snapshot(
			&subjects[type - SUBJ_START], width);
		if (width == ATTR_LOOKUP_REQUEST_WIDE_WIDTH)
			goto out;
	}
	for (type = OBJ_START; type <= OBJ_END; type++) {
		if (type == ALL_OBJ)
			continue;
		width = request_width_check_snapshot(
			&objects[type - OBJ_START], width);
		if (width == ATTR_LOOKUP_REQUEST_WIDE_WIDTH)
			goto out;
	}

out:
	if (width == ATTR_LOOKUP_REQUEST_WIDE_WIDTH)
		atomic_store_explicit(&attr_lookup_request_width, width,
				      memory_order_relaxed);
	return width;
}

/*
 * report_subject_attrs - write all subject attribute lookup counters.
 * @f: output stream.
 * @snapshots: subject attribute counter snapshots.
 * @request_width: field width for request counts.
 * Returns nothing.
 */
static void report_subject_attrs(FILE *f,
		const struct attr_lookup_metric_snapshot snapshots[SUBJ_COUNT],
		int request_width)
{
	unsigned int type;

	fprintf(f, "Subject attribute lookups:\n");
	for (type = SUBJ_START; type <= SUBJ_END; type++) {
		const char *name = subj_val_to_name(type, RULE_FMT_COLON);
		const struct attr_lookup_metric_snapshot *snapshot =
			&snapshots[type - SUBJ_START];
		struct attr_lookup_report_row row = {
			.label = "Subject attr:",
			.name = name,
			.snapshot = snapshot,
		};

		if (type == ALL_SUBJ || type == PATTERN)
			continue;

		write_attr_lookup_metric(f, &row, request_width);
	}
}

/*
 * report_object_attrs - write all object attribute lookup counters.
 * @f: output stream.
 * @snapshots: object attribute counter snapshots.
 * @request_width: field width for request counts.
 * Returns nothing.
 */
static void report_object_attrs(FILE *f,
		const struct attr_lookup_metric_snapshot snapshots[OBJ_COUNT],
		int request_width)
{
	unsigned int type;

	fprintf(f, "\nObject attribute lookups:\n");
	for (type = OBJ_START; type <= OBJ_END; type++) {
		const char *name = obj_val_to_name(type);
		const struct attr_lookup_metric_snapshot *snapshot =
			&snapshots[type - OBJ_START];
		struct attr_lookup_report_row row = {
			.label = "Object attr:",
			.name = name,
			.snapshot = snapshot,
		};

		if (type == ALL_OBJ)
			continue;

		write_attr_lookup_metric(f, &row, request_width);
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
	struct attr_lookup_metric_snapshot subjects[SUBJ_COUNT] = { 0 };
	struct attr_lookup_metric_snapshot objects[OBJ_COUNT] = { 0 };
	int request_width;

	if (f == NULL)
		return;

	snapshot_subject_attrs(subjects, reset);
	snapshot_object_attrs(objects, reset);
	request_width = request_width_for_report(subjects, objects);
	report_subject_attrs(f, subjects, request_width);
	report_object_attrs(f, objects, request_width);
	if (reset)
		atomic_store_explicit(&attr_lookup_request_width,
				      ATTR_LOOKUP_REQUEST_NARROW_WIDTH,
				      memory_order_relaxed);
}
