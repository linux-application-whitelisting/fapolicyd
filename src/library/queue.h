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
#include <pthread.h>
#include <time.h>
#include "gcc-attributes.h"

struct queue
{
	/* Ring buffer of fanotify events */
	struct fanotify_event_metadata *events;
	size_t num_entries;
	size_t queue_head;
	size_t queue_tail;
	atomic_size_t queue_length;
	pthread_mutex_t lock;
	pthread_cond_t cond;
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

/* Remove up to MAX events from Q, storing them into DATA. Return number of
 * events dequeued. */
int q_dequeue(struct queue *q, struct fanotify_event_metadata *data,
	       size_t max);

/* Remove up to MAX events from Q, blocking until timeout. On success, return
 * number of events dequeued. On timeout, return 0 and set errno to ETIMEDOUT.
 */
int q_timed_dequeue(struct queue *q, struct fanotify_event_metadata *data,
		     size_t max, const struct timespec *ts);

/* Wake up anyone waiting on the queue. */
void q_shutdown(struct queue *q);

/* Return the number of entries in Q. */
static inline size_t q_queue_length(const struct queue *q) { return q->queue_length; }

#endif
