/*
 * message.h - Header file for message.c
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

#ifndef MESSAGE_HEADER
#define MESSAGE_HEADER

#include <stdatomic.h>
#include <syslog.h>
#include <time.h>

typedef enum { MSG_STDERR, MSG_SYSLOG, MSG_QUIET } message_t;
typedef enum { DBG_NO, DBG_YES } debug_message_t;

struct message_rate_limit {
	atomic_long last_log;
	long interval;
};

#define MESSAGE_RATE_LIMIT_INIT(seconds) \
	{ .last_log = ATOMIC_VAR_INIT(0), .interval = (seconds) }

/*
 * message_rate_limit_allow - test and update a log throttle.
 * @limit: caller-owned rate limit state.
 * @now: current wall-clock time, or (time_t)-1 when unavailable.
 *
 * Returns 1 when the caller should log, 0 when the message is suppressed.
 */
static inline int message_rate_limit_allow(struct message_rate_limit *limit,
					   time_t now)
{
	long current, last;

	if (limit == NULL || limit->interval <= 0 || now == (time_t)-1)
		return 1;

	current = (long)now;
	last = atomic_load_explicit(&limit->last_log, memory_order_relaxed);
	while (last == 0 || current < last ||
	       current - last >= limit->interval) {
		/*
		 * A wall-clock rollback should emit one message immediately
		 * and reset the stored timestamp to avoid a long silence.
		 */
		if (atomic_compare_exchange_weak_explicit(&limit->last_log,
			    &last, current, memory_order_relaxed,
			    memory_order_relaxed))
			return 1;
	}

	return 0;
}

void set_message_mode(message_t mode, debug_message_t debug);
void msg(int priority, const char *fmt, ...)
#ifdef __GNUC__
	__attribute__ ((format (printf, 2, 3)));
#else
	;
#endif

#endif
