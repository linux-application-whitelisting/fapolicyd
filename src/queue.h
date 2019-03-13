/*
 * queue.h -- a queue abstraction
 * Copyright 2016,2018 Red Hat Inc., Durham, North Carolina.
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

struct queue
{
	/* NULL if !Q_IN_MEMORY.  [i] contains a memory copy of the queue entry
 	 * "i", if known - it may be NULL even if entry exists. */
	void **memory;
	size_t num_entries;
	size_t entry_size;
	size_t queue_head;
	size_t queue_length;
	unsigned int max_depth;
	unsigned char buffer[]; /* Used only locally within q_peek() */
};

/* Open a queue for use */
struct queue *q_open(size_t num_entries);

/* Close Q. */
void q_close(struct queue *q);

/* Write out q_depth */
void q_report(FILE *f);

/* Add DATA to tail of Q. Return 0 on success, -1 on error and set errno. */
int q_append(struct queue *q, const struct fanotify_event_metadata *data);

/* Peek at head of Q, storing it into BUF of SIZE. Return 1 if an entry
 * exists, 0 if queue is empty. On error, return -1 and set errno. */
int q_peek(const struct queue *q, struct fanotify_event_metadata *data);

/* Drop head of Q and return 0. On error, return -1 and set errno. */
int q_drop_head(struct queue *q);

/* Return the number of entries in Q. */
size_t q_queue_length(const struct queue *q);

#endif
