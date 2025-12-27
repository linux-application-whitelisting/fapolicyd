/*
 * lru.h - Header file for lru.c
 * Copyright (c) 2016 Red Hat Inc., Durham, North Carolina.
 * All Rights Reserved.
 *
 * This software may be freely redistributed and/or modified under the
 * terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; see the file COPYING. If not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor
 * Boston, MA 02110-1335, USA.
 *
 * Authors:
 *   Steve Grubb <sgrubb@redhat.com>
 */

#ifndef LRU_HEADER
#define LRU_HEADER
#include "gcc-attributes.h"

// Queue is implemented using double linked list
typedef struct QNode
{
	struct QNode *prev;
	struct QNode *next;
	unsigned long uses;
	void *item;        // the data in the cache
} QNode;

// Collection of pointers to Queue Nodes
typedef struct Hash
{
	unsigned int size; // how many entries
	QNode **array;     // an array of queue nodes
} Hash;

// FIFO of Queue Nodes
typedef struct Queue
{
	unsigned int count;  // Number of filled slots
	unsigned int total;  // total number of slots
	unsigned long hits;  // Number of times object was in cache
	unsigned long misses;// number of times object was not in cache
	unsigned long evictions;// number of times cached object was not usable
	QNode *front;
	QNode *end;
	Hash *hash;
	const char *name;	// Used for reporting
	void (*cleanup)(void *); // Function to call when releasing memory
	void (*evict_cb)(void *); // Optional callback when evicting item
	QNode *pool;		// Pre-allocated queue nodes
	QNode *free_list;	// Free list for queue nodes
} Queue;

void destroy_lru(Queue *queue);
Queue *init_lru(unsigned int qsize, void (*cleanup)(void *),
		const char *name, void (*evict_cb)(void *)) __attribute_malloc__
		__attr_dealloc (destroy_lru, 1);
void lru_evict(Queue *queue, unsigned int key);
QNode *check_lru_cache(Queue *q, unsigned int key);
unsigned int compute_subject_key(const Queue *queue, unsigned int pid);
unsigned long compute_object_key(const Queue *queue, unsigned long num);

#endif
