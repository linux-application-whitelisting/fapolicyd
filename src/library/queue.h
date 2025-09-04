/*
 * queue.h -- a queue abstraction
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

#ifndef QUEUE_HEADER
#define QUEUE_HEADER

#include <stdio.h>
#include <sys/types.h>
#include <sys/fanotify.h>
#include <stdatomic.h>
#include <semaphore.h>
#include <time.h>
#include "gcc-attributes.h"

struct queue
{
	/* Ring buffer of fanotify events */
	struct fanotify_event_metadata *events;
	size_t num_entries;
	atomic_uint q_next;
	atomic_uint q_last;
	atomic_uint queue_length;
        sem_t sem;
};

/* Close Q. */
void q_close(struct queue *q);

/* Open a queue for use */
struct queue *q_open(size_t num_entries) __attribute_malloc__
		     __attr_dealloc (q_close, 1);

/* Write out q_depth */
void q_report(FILE *f);

/* Add DATA to tail of Q. Return 0 on success, -1 on error and set errno. */
int q_enqueue(struct queue *q, const struct fanotify_event_metadata *data);

/* Remove one event from Q, storing it into DATA. Return 1 on success or 0 if
 * the queue is empty. */
int q_dequeue(struct queue *q, struct fanotify_event_metadata *data);

/* Remove one event from Q, blocking until timeout. On success return 1. On
 * timeout return 0 and set errno to ETIMEDOUT. */
 int q_timed_dequeue(struct queue *q, struct fanotify_event_metadata *data,
		     const struct timespec *ts);

/* Wake up anyone waiting on the queue. */
void q_shutdown(struct queue *q);

/* Return the number of entries in Q. */
static inline size_t q_queue_length(const struct queue *q) { return q->queue_length; }

#endif
