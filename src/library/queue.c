/*
 * queue.c - a simple queue implementation
 * Copyright 2016,2018,2022 Red Hat Inc.
 * All Rights Reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor
 * Boston, MA 02110-1335, USA.
 *
 * Authors:
 *      Steve Grubb <sgrubb@redhat.com>
 */

#include "config.h"
#include <stdio.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "queue.h"
#include "message.h"

/*
 * Ring buffer queue
 *
 * The queue is a fixed-size ring of struct fanotify_event_metadata.
 * q_open() allocates the array and sets head/tail counters.
 * q_append() copies a new event into the tail.
 * q_peek() fetches the head without removing it.
 * q_drop_head() advances the head after an event is processed.
 * All queue operations are serialized by decision_lock in notify.c;
 * queue_length is read without the lock by the deadman thread and is
 * therefore atomic. Using a ring buffer avoids per-event malloc/free
 * and keeps memory usage predictable. max_depth records the highest
 * queue_length observed for diagnostics.
 */

/* Queue implementation */
static unsigned int max_depth;

/* Initialize a queue   */
struct queue *q_open(size_t num_entries)
{
	struct queue *q;
	int saved_errno;

	if (num_entries == 0 || num_entries > UINT32_MAX ||
	    num_entries > SIZE_MAX / sizeof(struct fanotify_event_metadata)) {
		errno = EINVAL;
		return NULL;
	}

	q = malloc(sizeof(*q));
	if (q == NULL)
		return NULL;

	q->events = calloc(num_entries, sizeof(struct fanotify_event_metadata));
	if (q->events == NULL)
		goto err;

	q->num_entries = num_entries;
	q->queue_head = 0;
	q->queue_tail = 0;
	q->queue_length = 0;
	max_depth = 0;

	return q;

err:
	saved_errno = errno;
	free(q);
	errno = saved_errno;
	return NULL;
}

void q_close(struct queue *q)
{
	free(q->events);
	msg(LOG_DEBUG, "Inter-thread max queue depth %u", max_depth);
	free(q);
}

void q_report(FILE *f)
{
	fprintf(f, "Inter-thread max queue depth: %u\n", max_depth);
}

/* add DATA to Q */
int q_append(struct queue *q, const struct fanotify_event_metadata *data)
{
	if (q->queue_length == q->num_entries) {
		errno = ENOSPC;
		return -1;
	}

	q->events[q->queue_tail] = *data;
	q->queue_tail++;
	if (q->queue_tail == q->num_entries)
		q->queue_tail = 0;

	q->queue_length++;
	if (q->queue_length > max_depth)
		max_depth = q->queue_length;

	return 0;
}

int q_peek(const struct queue *q, struct fanotify_event_metadata *data)
{
	if (q->queue_length == 0)
		return 0;

	*data = q->events[q->queue_head];
	return 1;
}

/* drop head of Q */
int q_drop_head(struct queue *q)
{
	if (q->queue_length == 0) {
		errno = EINVAL;
		return -1;
	}

	q->queue_head++;
	if (q->queue_head == q->num_entries)
		q->queue_head = 0;

	q->queue_length--;
	return 0;
}

