/* queue.c - a simple queue implementation
 * Copyright 2016 Red Hat Inc., Durham, North Carolina.
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
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


/* Queue implementation */
/* Initialize a queue   */
struct queue *q_open(size_t num_entries)
{
	struct queue *q;
	int saved_errno;
	size_t sz, entry_size = sizeof(struct fanotify_event_metadata);

	if (num_entries == 0 || num_entries > UINT32_MAX
	    || entry_size < 1 /* for trailing NUL */
	    /* to allocate "struct queue" including its buffer*/
	    || entry_size > UINT32_MAX - sizeof(struct queue)) {
		errno = EINVAL;
		return NULL;
	}
	if (entry_size > SIZE_MAX ||
			num_entries > SIZE_MAX / sizeof(*q->memory)) {
		errno = EINVAL;
		return NULL;
	}

	q = malloc(sizeof(*q) + entry_size);
	if (q == NULL)
		return NULL;
	q->memory = NULL;
	q->num_entries = num_entries;
	q->entry_size = entry_size;
	q->queue_head = 0;
	q->queue_length = 0;
	q->max_depth = 0;

	sz = num_entries * sizeof(*q->memory);
	q->memory = malloc(sz);
	if (q->memory == NULL)
		goto err;
	memset(q->memory, 0, sz);

	return q;

err:
	saved_errno = errno;
	free(q);
	errno = saved_errno;
	return NULL;
}

void q_close(struct queue *q)
{
	if (q->memory != NULL) {
		size_t i;

		for (i = 0; i < q->num_entries; i++)
			free(q->memory[i]);
		free(q->memory);
	}
	free(q);
	msg(LOG_DEBUG, "Inter-thread max queue depth %u", q->max_depth);
}

/* add DATA to Q */
int q_append(struct queue *q, const struct fanotify_event_metadata *data)
{
	size_t entry_index;
	unsigned char *copy;

	if (q->queue_length == q->num_entries) {
		errno = ENOSPC;
		return -1;
	}

	entry_index = (q->queue_head + q->queue_length) % q->num_entries;
	if (q->memory != NULL) {
		if (q->memory[entry_index] != NULL) {
			errno = EIO; /* This is _really_ unexpected. */
			return -1;
		}
		copy = malloc(sizeof(struct fanotify_event_metadata));
		if (copy == NULL)
			return -1;
		memcpy(copy, data, sizeof(struct fanotify_event_metadata));
	} else
		copy = NULL;

	if (copy != NULL)
		q->memory[entry_index] = copy;

	q->queue_length++;
	if (q->queue_length > q->max_depth)
		q->max_depth = q->queue_length;

	return 0;
}

int q_peek(struct queue *q, struct fanotify_event_metadata *data)
{
	if (q->queue_length == 0)
		return 0;

	if (q->memory != NULL && q->memory[q->queue_head] != NULL) {
		struct fanotify_event_metadata *d = q->memory[q->queue_head];
		memcpy(data, d, sizeof(struct fanotify_event_metadata));

		return 1;
	}
	return 0;
}

/* drop head of Q */
int q_drop_head(struct queue *q)
{
	if (q->queue_length == 0) {
		errno = EINVAL;
		return -1;
	}

	if (q->memory != NULL) {
		free(q->memory[q->queue_head]);
		q->memory[q->queue_head] = NULL;
	}

	q->queue_head++;
	if (q->queue_head == q->num_entries)
		q->queue_head = 0;
	q->queue_length--;
	return 0;
}

size_t q_queue_length(const struct queue *q)
{
	return q->queue_length;
}

