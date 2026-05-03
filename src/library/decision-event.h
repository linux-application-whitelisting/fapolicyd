/*
 * decision-event.h - internal event envelope for policy decisions
 *
 * Copyright (c) 2026 Red Hat Inc.
 * All Rights Reserved.
 *
 * This software may be freely redistributed and/or modified under the
 * terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your
 * option) any later version.
 */

#ifndef DECISION_EVENT_HEADER
#define DECISION_EVENT_HEADER

#include <limits.h>
#include <stdint.h>
#include <sys/fanotify.h>

#define DECISION_EVENT_NO_SLOT UINT_MAX

typedef struct decision_event {
	/*
	 * Original fanotify metadata from the kernel. Permission event fd
	 * ownership stays with this envelope until reply_event() answers it
	 * or shutdown cleanup closes it.
	 */
	struct fanotify_event_metadata metadata;
	/*
	 * Userspace queue timestamp used by decision timing. It is zero when
	 * timing was not armed at enqueue time and must be preserved while an
	 * event is deferred.
	 */
	uint64_t enqueue_ns;
	/*
	 * Subject cache slot computed from metadata.pid using the same key
	 * function as the subject cache. DECISION_EVENT_NO_SLOT means it has
	 * not been computed yet.
	 */
	unsigned int subject_slot;
	/*
	 * Slot that became unblocked while this event was processed.
	 * DECISION_EVENT_NO_SLOT means no deferred event should be released.
	 */
	unsigned int completed_subject_slot;
} decision_event_t;

/*
 * decision_event_init - wrap one fanotify metadata record.
 * @event: decision event to initialize.
 * @metadata: fanotify metadata copied into the wrapper.
 * Returns nothing.
 */
static inline void decision_event_init(decision_event_t *event,
		const struct fanotify_event_metadata *metadata)
{
	event->metadata = *metadata;
	event->enqueue_ns = 0;
	event->subject_slot = DECISION_EVENT_NO_SLOT;
	event->completed_subject_slot = DECISION_EVENT_NO_SLOT;
}

#endif
