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
#include <stdatomic.h>
#include "queue.h"
#include "message.h"

/*
 * Ring buffer queue
 *
 * The queue is a fixed-size ring of struct fanotify_event_metadata.
 * q_open() allocates the array and sets head/tail counters.
 * q_enqueue() copies a new event into the tail.
 * q_dequeue() fetches events from the head and advances it.
 *
 * queue_length is read without locking by the deadman thread and is
 * therefore atomic. Using a ring buffer avoids per-event malloc/free and
 * keeps memory usage predictable. max_depth records the highest
 * queue_length observed for diagnostics.
 */

/* Queue implementation */
static unsigned int max_depth;
extern atomic_bool stop;

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

	pthread_mutex_init(&q->lock, NULL);
	pthread_condattr_t attr;
	pthread_condattr_init(&attr);
	pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);
	pthread_cond_init(&q->cond, &attr);
	pthread_condattr_destroy(&attr);

	return q;

err:
	saved_errno = errno;
	free(q);
	errno = saved_errno;
	return NULL;
}

void q_close(struct queue *q)
{
	pthread_cond_destroy(&q->cond);
	pthread_mutex_destroy(&q->lock);
	free(q->events);
	msg(LOG_DEBUG, "Inter-thread max queue depth %u", max_depth);
	free(q);
}

void q_report(FILE *f)
{
	fprintf(f, "Inter-thread max queue depth: %u\n", max_depth);
}

/* Internal helpers */
static void q_append(struct queue *q,
		      const struct fanotify_event_metadata *data)
{
	q->events[q->queue_tail] = *data;
	q->queue_tail++;
	if (q->queue_tail == q->num_entries)
	q->queue_tail = 0;
}

static void q_peek(const struct queue *q,
		    struct fanotify_event_metadata *data)
{
	*data = q->events[q->queue_head];
}

static void q_drop_head(struct queue *q)
{
	q->queue_head++;
	if (q->queue_head == q->num_entries)
		q->queue_head = 0;
}

/* add DATA to Q */
int q_enqueue(struct queue *q, const struct fanotify_event_metadata *data)
{
	int rc = 0;

	pthread_mutex_lock(&q->lock);
	if (q->queue_length == q->num_entries) {
		errno = ENOSPC;
		rc = -1;
	} else {
		q_append(q, data);
		q->queue_length++;
		if (q->queue_length > max_depth)
			max_depth = q->queue_length;
		pthread_cond_signal(&q->cond);
	}
	pthread_mutex_unlock(&q->lock);
	return rc;
}

/* remove events from Q */
int q_dequeue(struct queue *q, struct fanotify_event_metadata *data,
	       size_t max)
{
	size_t i = 0;

	pthread_mutex_lock(&q->lock);
	while (q->queue_length == 0 && !stop)
	pthread_cond_wait(&q->cond, &q->lock);
	while (i < max && q->queue_length > 0) {
		q_peek(q, &data[i]);
		q_drop_head(q);
		q->queue_length--;
		i++;
	}
	pthread_mutex_unlock(&q->lock);
	return i;
}

int q_timed_dequeue(struct queue *q, struct fanotify_event_metadata *data,
		     size_t max, const struct timespec *ts)
{
	size_t i = 0;
	int rc = 0;

	pthread_mutex_lock(&q->lock);
	while (q->queue_length == 0 && !stop) {
		rc = pthread_cond_timedwait(&q->cond, &q->lock, ts);
		if (rc)
			break;
	}
	if (rc == ETIMEDOUT) {
		pthread_mutex_unlock(&q->lock);
		errno = ETIMEDOUT;
		return 0;
	} else if (rc) {
		pthread_mutex_unlock(&q->lock);
		errno = rc;
		return -1;
	}
	while (i < max && q->queue_length > 0) {
		q_peek(q, &data[i]);
		q_drop_head(q);
		q->queue_length--;
		i++;
	}
	pthread_mutex_unlock(&q->lock);
	return i;
}

void q_shutdown(struct queue *q)
{
	pthread_mutex_lock(&q->lock);
	pthread_cond_signal(&q->cond);
	pthread_mutex_unlock(&q->lock);
}

