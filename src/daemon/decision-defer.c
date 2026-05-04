/*
 * decision-defer.c - bounded subject-slot deferral for decision events
 *
 * Copyright (c) 2026 Red Hat Inc.
 * All Rights Reserved.
 *
 * This software may be freely redistributed and/or modified under the
 * terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your
 * option) any later version.
 */

/*
 * Overview
 * --------
 *
 * Subject deferral protects a subject cache slot while the process currently
 * occupying that slot is still building startup pattern state. The decision
 * thread computes an incoming event's subject slot before calling new_event().
 * If the same slot already contains a different pid whose subject state is
 * before STATE_FULL, processing the incoming event would make new_event()
 * evict the in-progress subject. Instead, the decision thread copies the
 * incoming decision_event_t into this fixed-size defer array. Traced or stale
 * BUILDING occupants are the exception: event.c evicts those subjects and
 * lets the incoming event process normally because waiting may never
 * release the slot.
 *
 * A slot is the subject cache hash index. An entry is one position in this
 * defer array. Multiple deferred entries can target the same slot. Entries are
 * selected by age: pop_slot() returns the oldest deferred event for one
 * released subject slot, while pop_any() returns the oldest event regardless
 * of slot and is used during shutdown cleanup.
 *
 * The decision thread owns this array. No producer writes to it, and no other
 * thread pops from it. That keeps the implementation simple and makes fd
 * ownership explicit: a deferred entry owns the fanotify permission fd in its
 * embedded decision_event_t until the entry is popped for normal processing or
 * shutdown replies to it.
 *
 * The array is intentionally bounded. If it is full, callers must fall back to
 * the historical eviction behavior so memory use and blocked kernel permission
 * events remain bounded.
 */

#include "config.h"
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "decision-defer.h"

struct decision_defer_entry {
	/* Event envelope and permission fd owned while this entry is used. */
	decision_event_t event;
	/* Monotonic time when the event entered the defer array. */
	uint64_t deferred_ns;
	/* Insertion sequence number used to choose the oldest matching entry. */
	uint64_t order;
	/* Non-zero when this array entry currently owns a deferred event. */
	int used;
};

/*
 * defer_now_ns - read monotonic time for defer age reporting.
 * Returns monotonic nanoseconds, or zero if the clock cannot be read.
 */
static uint64_t defer_now_ns(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts))
		return 0;

	return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/*
 * decision_defer_init - allocate a fixed defer array.
 * @defer: queue state to initialize.
 * @subj_cache_size: configured subject cache size.
 *
 * The defer array is intentionally bounded. It scales from the configured
 * subject cache size and has a small floor so tiny test configurations still
 * exercise deferral without repeated allocation.
 *
 * Returns 0 on success and -1 on allocation or argument failure.
 */
int decision_defer_init(struct decision_defer_queue *defer,
		unsigned int subj_cache_size)
{
	unsigned int capacity;

	if (defer == NULL) {
		errno = EINVAL;
		return -1;
	}

	memset(defer, 0, sizeof(*defer));
	capacity = subj_cache_size / DECISION_DEFER_RATIO;
	if (capacity < DECISION_DEFER_MIN)
		capacity = DECISION_DEFER_MIN;

	defer->entries = calloc(capacity, sizeof(struct decision_defer_entry));
	if (defer->entries == NULL)
		return -1;

	defer->capacity = capacity;
	return 0;
}

/*
 * decision_defer_destroy - release defer array storage.
 * @defer: queue state to destroy.
 * Returns nothing.
 */
void decision_defer_destroy(struct decision_defer_queue *defer)
{
	if (defer == NULL)
		return;

	free(defer->entries);
	memset(defer, 0, sizeof(*defer));
}

/*
 * oldest_entry - find the oldest deferred event matching a slot.
 * @defer: queue state to inspect.
 * @slot: matching subject slot, or DECISION_EVENT_NO_SLOT for any slot.
 *
 * This is a bounded O(capacity) linear scan. The defer array is intentionally
 * small and fixed-size, and callers avoid this scan entirely when current is
 * zero.
 *
 * Returns the oldest matching entry, or NULL when none exists.
 */
static struct decision_defer_entry *oldest_entry(
		struct decision_defer_queue *defer, unsigned int slot)
{
	struct decision_defer_entry *oldest = NULL;
	unsigned int i;

	if (defer == NULL || defer->current == 0)
		return NULL;

	for (i = 0; i < defer->capacity; i++) {
		struct decision_defer_entry *entry = &defer->entries[i];

		// Empty entries are available for reuse and never considered.
		if (!entry->used)
			continue;
		// Slot-specific callers only want events blocked by that slot.
		if (slot != DECISION_EVENT_NO_SLOT &&
		    entry->event.subject_slot != slot)
			continue;
		// Lower insertion order means older deferred request.
		if (oldest == NULL || entry->order < oldest->order)
			oldest = entry;
	}

	return oldest;
}

/*
 * decision_defer_push - store one event in the defer array.
 * @defer: queue state receiving the event.
 * @event: event to copy into the defer array.
 *
 * The deferred copy owns the event fd until it is popped for processing or
 * shutdown cleanup handles it.
 *
 * Returns 0 on success and -1 with ENOSPC when the array is full.
 */
int decision_defer_push(struct decision_defer_queue *defer,
		const decision_event_t *event)
{
	unsigned int i;

	if (defer == NULL || event == NULL) {
		errno = EINVAL;
		return -1;
	}

	if (defer->current == defer->capacity) {
		errno = ENOSPC;
		return -1;
	}

	for (i = 0; i < defer->capacity; i++) {
		struct decision_defer_entry *entry = &defer->entries[i];

		if (entry->used)
			continue;

		// Store by value; the defer entry now owns the event fd.
		entry->event = *event;
		// A parked event has not completed any subject slot yet.
		entry->event.completed_subject_slot = DECISION_EVENT_NO_SLOT;
		entry->deferred_ns = defer_now_ns();
		entry->order = defer->next_order++;
		entry->used = 1;
		defer->current++;
		defer->deferred_events++;
		if (defer->current > defer->max_depth)
			defer->max_depth = defer->current;
		return 0;
	}

	errno = ENOSPC;
	return -1;
}

/*
 * pop_entry - remove one deferred entry.
 * @defer: queue state owning the entry.
 * @entry: entry to remove.
 * @event: destination for the deferred event.
 * Returns 1 when an entry was removed, 0 otherwise.
 */
static int pop_entry(struct decision_defer_queue *defer,
		struct decision_defer_entry *entry, decision_event_t *event)
{
	if (defer == NULL || entry == NULL || event == NULL)
		return 0;

	// Transfer fd ownership back to the caller for processing or shutdown.
	*event = entry->event;
	/*
	 * Marking the entry unused is enough. The next push overwrites every
	 * field before setting used again, and oldest_entry() ignores unused
	 * slots. Avoid clearing the full embedded fanotify metadata on every
	 * pop because high-churn workloads can pop many entries.
	 */
	entry->used = 0;
	defer->current--;
	return 1;
}

/*
 * decision_defer_pop_slot - remove the oldest deferred event for one slot.
 * @defer: queue state to pop from.
 * @slot: subject cache slot that is no longer blocking.
 * @event: destination for the deferred event.
 *
 * Returns 1 when an event was removed, 0 when no matching event exists.
 */
int decision_defer_pop_slot(struct decision_defer_queue *defer,
		unsigned int slot, decision_event_t *event)
{
	return pop_entry(defer, oldest_entry(defer, slot), event);
}

/*
 * decision_defer_pop_any - remove the oldest deferred event.
 * @defer: queue state to pop from.
 * @event: destination for the deferred event.
 *
 * Returns 1 when an event was removed, 0 when the defer array is empty.
 */
int decision_defer_pop_any(struct decision_defer_queue *defer,
		decision_event_t *event)
{
	return pop_entry(defer, oldest_entry(defer, DECISION_EVENT_NO_SLOT),
			 event);
}

/*
 * decision_defer_count_fallback - count one full-array fallback.
 * @defer: queue state whose counter should be incremented.
 * Returns nothing.
 */
void decision_defer_count_fallback(struct decision_defer_queue *defer)
{
	if (defer)
		defer->fallbacks++;
}

/*
 * oldest_age_ns - compute age of the oldest currently deferred event.
 * @defer: queue state to inspect.
 * Returns age in nanoseconds, or zero when there are no deferred events.
 */
static uint64_t oldest_age_ns(struct decision_defer_queue *defer)
{
	struct decision_defer_entry *entry;
	uint64_t now;

	entry = oldest_entry(defer, DECISION_EVENT_NO_SLOT);
	if (entry == NULL || entry->deferred_ns == 0)
		return 0;

	now = defer_now_ns();
	if (now < entry->deferred_ns)
		return 0;

	return now - entry->deferred_ns;
}

/*
 * format_age - convert a nanosecond age into compact human-readable text.
 * @age_ns: age in nanoseconds.
 * @buf: destination buffer.
 * @buf_size: destination size.
 * Returns nothing.
 */
static void format_age(uint64_t age_ns, char *buf, size_t buf_size)
{
	if (buf == NULL || buf_size == 0)
		return;

	if (age_ns == 0)
		snprintf(buf, buf_size, "0ns");
	else if (age_ns < 1000ULL)
		snprintf(buf, buf_size, "%lluns",
			 (unsigned long long)age_ns);
	else if (age_ns < 1000000ULL)
		snprintf(buf, buf_size, "%.3fus", (double)age_ns / 1000.0);
	else if (age_ns < 1000000000ULL)
		snprintf(buf, buf_size, "%.3fms",
			 (double)age_ns / 1000000.0);
	else
		snprintf(buf, buf_size, "%.3fs",
			 (double)age_ns / 1000000000.0);
}

/*
 * decision_defer_metrics_snapshot_reset - copy defer metrics.
 * @defer: queue state to read.
 * @metrics: destination for the snapshot.
 * @reset: non-zero resets interval counters after copying.
 *
 * Current depth and capacity are state. Max depth restarts at the current
 * depth after reset so reports never claim a max below live occupancy.
 */
void decision_defer_metrics_snapshot_reset(struct decision_defer_queue *defer,
		struct decision_defer_metrics *metrics, int reset)
{
	if (metrics == NULL)
		return;

	memset(metrics, 0, sizeof(*metrics));
	if (defer == NULL)
		return;

	metrics->capacity = defer->capacity;
	metrics->current_depth = defer->current;
	metrics->deferred_events = defer->deferred_events;
	metrics->max_depth = defer->max_depth;
	metrics->fallbacks = defer->fallbacks;
	metrics->oldest_age_ns = oldest_age_ns(defer);

	if (reset) {
		defer->deferred_events = 0;
		defer->max_depth = defer->current;
		defer->fallbacks = 0;
	}
}

/*
 * decision_defer_config_report - write defer capacity sized at startup.
 * @f: report stream.
 * @metrics: metrics snapshot to report.
 * Returns nothing.
 */
void decision_defer_config_report(FILE *f,
		const struct decision_defer_metrics *metrics)
{
	if (f == NULL || metrics == NULL)
		return;

	fprintf(f, "Subject defer array size: %u\n", metrics->capacity);
}

/*
 * decision_defer_fallback_report - write defer fallback health indicator.
 * @f: report stream.
 * @metrics: metrics snapshot to report.
 * Returns nothing.
 */
void decision_defer_fallback_report(FILE *f,
		const struct decision_defer_metrics *metrics)
{
	if (f == NULL || metrics == NULL)
		return;

	fprintf(f, "Subject defer fallbacks: %lu\n", metrics->fallbacks);
}

/*
 * decision_defer_age_report - write oldest deferred event age.
 * @f: report stream.
 * @metrics: metrics snapshot to report.
 * Returns nothing.
 */
void decision_defer_age_report(FILE *f,
		const struct decision_defer_metrics *metrics)
{
	char age[32];

	if (f == NULL || metrics == NULL)
		return;

	format_age(metrics->oldest_age_ns, age, sizeof(age));
	fprintf(f, "Subject defer oldest age: %s\n", age);
}

/*
 * decision_defer_health_report - write defer health indicators.
 * @f: report stream.
 * @metrics: metrics snapshot to report.
 * Returns nothing.
 */
void decision_defer_health_report(FILE *f,
		const struct decision_defer_metrics *metrics)
{
	decision_defer_fallback_report(f, metrics);
	decision_defer_age_report(f, metrics);
}

/*
 * decision_defer_metrics_report - write defer activity metrics.
 * @f: output stream.
 * @metrics: metrics snapshot to report.
 * Returns nothing.
 */
void decision_defer_metrics_report(FILE *f,
		const struct decision_defer_metrics *metrics)
{
	if (f == NULL || metrics == NULL)
		return;

	fprintf(f, "Subject deferred events: %lu\n",
		metrics->deferred_events);
	fprintf(f, "Subject defer max depth: %u\n", metrics->max_depth);
	fprintf(f, "Subject defer fallbacks: %lu\n", metrics->fallbacks);
}
