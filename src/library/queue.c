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
 * The queue is a fixed-size ring of struct fanotify_event_metadata.  A
 * semaphore tracks how many events are queued while atomic indices maintain
 * the next slot to use for enqueueing and dequeueing.  This avoids blocking
 * producers and consumers on a mutex which improves latency under load.
 *
 * q_open() allocates the array and initializes the semaphore and indices.
 * q_enqueue() copies a new event into the producer slot, advances it and posts
 * to the semaphore.  q_dequeue() waits on the semaphore, reads from the
 * consumer slot and advances it.
 *
 * queue_length is read without locking by the deadman thread and is
 * therefore atomic. Using a ring buffer avoids per-event malloc/free and
 * keeps memory usage predictable. max_depth records the highest
 * queue_length observed for diagnostics.
 */

/* Queue implementation */
static atomic_uint max_depth;

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
	atomic_store_explicit(&q->q_next, 0, memory_order_relaxed);
	atomic_store_explicit(&q->q_last, 0, memory_order_relaxed);
	atomic_store_explicit(&q->queue_length, 0, memory_order_relaxed);
	max_depth = 0;

	if (sem_init(&q->sem, 0, 0) == -1) {
		free(q->events);
		goto err;
	}

	return q;

err:
	saved_errno = errno;
	free(q);
	errno = saved_errno;
	return NULL;
}

void q_close(struct queue *q)
{
	sem_destroy(&q->sem);
	free(q->events);
	msg(LOG_DEBUG, "Inter-thread max queue depth %u", max_depth);
	free(q);
}

void q_report(FILE *f)
{
	fprintf(f, "Inter-thread max queue depth: %u\n", max_depth);
}

/* add DATA to Q */
int q_enqueue(struct queue *q, const struct fanotify_event_metadata *data)
{
	unsigned int n;

	if (atomic_load_explicit(&q->queue_length, memory_order_relaxed) ==
		q->num_entries) {
		errno = ENOSPC;
		return -1;
	}

	/*
	 * Load the producer index with relaxed ordering.  sem_post() acts as a
	 * release barrier and sem_wait() in q_dequeue() provides the matching
	 * acquire barrier.  Because the threads synchronize on the semaphore,
	 * a relaxed load of q_next is sufficient here.
	 */
	n = atomic_load_explicit(&q->q_next, memory_order_relaxed);
	q->events[n] = *data;

	n++;
	if (n == q->num_entries)
		n = 0;

	/*
	 * Store the updated producer index with release semantics.  The event
	 * was written to q->events above and sem_post() will be issued next.
	 * sem_post() itself is a release barrier and sem_wait() in
	 * q_dequeue() will acquire it, so the combination guarantees the
	 * consumer sees the event before noticing that q_next advanced.
	 */
	atomic_store_explicit(&q->q_next, n, memory_order_release);

	n = atomic_fetch_add_explicit(&q->queue_length, 1,
				      memory_order_relaxed) + 1;
	unsigned int old = atomic_load(&max_depth);
	while (n > old && !atomic_compare_exchange_weak(&max_depth, &old, n))
		;

	sem_post(&q->sem);
	return 0;
}

/* remove one event from Q */
int q_dequeue(struct queue *q, struct fanotify_event_metadata *data)
{
	for (;;) {
		if (sem_wait(&q->sem)) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (atomic_load_explicit(&q->queue_length,
					 memory_order_relaxed) == 0)
			return 0;

		/*
		 * The consumer waits on sem_wait() above which provides an
		 * acquire barrier for the producer's sem_post().  Because of
		 * that synchronization a relaxed load of the consumer index is
		 * safe here.
		 */
		unsigned int n = atomic_load_explicit(&q->q_last,
						      memory_order_relaxed);
		*data = q->events[n];
		n++;
		if (n == q->num_entries)
			n = 0;

		/*
		 * Release ensures the slot is cleared before we advance the
		 * consumer index.  The following sem_post() pairs with the
		 * producer's sem_wait(), so the semaphore again provides the
		 * cross-thread ordering needed for the queue operations.
		 */
		atomic_store_explicit(&q->q_last, n, memory_order_release);
		atomic_fetch_sub_explicit(&q->queue_length, 1,
					  memory_order_relaxed);
		return 1;
	}
}

int q_timed_dequeue(struct queue *q, struct fanotify_event_metadata *data,
		     const struct timespec *ts)
{
	for (;;) {
		if (sem_timedwait(&q->sem, ts)) {
			if (errno == EINTR)
				continue;
			if (errno == ETIMEDOUT)
				return 0;
			return -1;
		}
		break;
	}

	if (atomic_load_explicit(&q->queue_length,
				 memory_order_relaxed) == 0)
		return 0;

	/*
	 * The consumer waits on sem_timedwait() above which provides an
	 * acquire barrier for the producer's sem_post().  Because of that
	 * synchronization a relaxed load of the consumer index is safe here.
	 */
	unsigned int n = atomic_load_explicit(&q->q_last,
			                      memory_order_relaxed);
	*data = q->events[n];
	n++;
	if (n == q->num_entries)
		n = 0;

	/*
	 * Release ensures the slot is cleared before we advance the consumer
	 * index.  The semaphore again provides the cross-thread ordering needed
	 * for the queue operations.
	 */
	atomic_store_explicit(&q->q_last, n, memory_order_release);
	atomic_fetch_sub_explicit(&q->queue_length, 1, memory_order_relaxed);
	return 1;
}

void q_shutdown(struct queue *q)
{
	sem_post(&q->sem);
}

