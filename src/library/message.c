/*
 * message.c - function to syslog or write to stderr
 * Copyright (c) 2016 Red Hat Inc.
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

#include "config.h"
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <sched.h>
#include <semaphore.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "message.h"

/* The message mode refers to where informational messages go
	0 - stderr, 1 - syslog, 2 - quiet. The default is quiet. */
static message_t message_mode = MSG_QUIET;
static debug_message_t debug_message = DBG_NO;
static atomic_int stderr_color_state = ATOMIC_VAR_INIT(-1);

/*
 * Async logger. Both output destinations can block on journald: vsyslog()
 * writes to /dev/log, and stderr may be a journald stream socket when the
 * daemon runs under systemd. journald itself generates fanotify events this
 * daemon must answer, so a thread that answers events must never write to
 * either destination directly - that is a circular wait during journal
 * rotation. Instead, producers enqueue formatted messages into this bounded
 * ring without ever blocking (full ring == drop + count) and one drain
 * thread is the only writer. A wedged journald then stalls only the drain
 * thread.
 */
/* Sized for the longest realistic line: a message can embed one or two full
 * paths (e.g. "Consider 'mv %s %s'"), so match the PATH_MAX*2 convention
 * already used for path-carrying buffers elsewhere (fapolicyd.c). */
#define LOG_SLOT_SIZE (PATH_MAX * 2)
#define LOG_QUEUE_DEPTH 256

enum { LOG_ASYNC_OFF, LOG_ASYNC_RUNNING, LOG_ASYNC_STOPPING };

struct log_slot {
	int priority;
	size_t len;		/* text length, so the drain thread copies
				   only what was written, not the whole slot */
	char text[LOG_SLOT_SIZE];
};

static struct log_slot log_ring[LOG_QUEUE_DEPTH];
static unsigned log_head, log_count;		/* guarded by log_lock */
static pthread_mutex_t log_lock = PTHREAD_ERRORCHECK_MUTEX_INITIALIZER_NP;
static sem_t log_sem;
static pthread_t log_thread;
static atomic_int log_state = ATOMIC_VAR_INIT(LOG_ASYNC_OFF);
static atomic_ulong log_dropped = ATOMIC_VAR_INIT(0);
/* Producers currently between registering intent and finishing their call
 * into log_enqueue() - see msg() and message_async_stop(). Always accessed
 * with the default (seq_cst) atomic ops: the ordering this enforces spans
 * two independent atomics (this counter and log_state), which acquire/
 * release pairing on either one alone cannot provide. */
static atomic_uint log_inflight = ATOMIC_VAR_INIT(0);
static struct message_rate_limit log_drop_limit = MESSAGE_RATE_LIMIT_INIT(30);

struct message_level {
	const char *name;
	const char *color;
};

/*
 * message_level_info - return display metadata for one syslog priority.
 * @priority: syslog LOG_* priority value.
 * Returns the printable level name and ANSI color for @priority.
 */
static struct message_level message_level_info(int priority)
{
	switch (priority) {
	case LOG_EMERG:
		return (struct message_level){ "EMERGENCY", "\x1b[31m" };
	case LOG_ALERT:
		return (struct message_level){ "ALERT", "\x1b[35m" };
	case LOG_CRIT:
		return (struct message_level){ "CRITICAL", "\x1b[33m" };
	case LOG_ERR:
		return (struct message_level){ "ERROR", "\x1b[31m" };
	case LOG_WARNING:
		return (struct message_level){ "WARNING", "\x1b[33m" };
	case LOG_NOTICE:
		return (struct message_level){ "NOTICE", "\x1b[32m" };
	case LOG_INFO:
		return (struct message_level){ "INFO", "\x1b[36m" };
	case LOG_DEBUG:
		return (struct message_level){ "DEBUG", "\x1b[34m" };
	default:
		return (struct message_level){ "UNKNOWN", "" };
	}
}

/*
 * detect_stderr_color - determine whether stderr should receive ANSI color.
 * Returns 1 for color-capable interactive stderr, 0 otherwise.
 */
static int detect_stderr_color(void)
{
	const char *no_color = getenv("NO_COLOR");
	const char *term = getenv("TERM");

	if (no_color && no_color[0] != '\0')
		return 0;
	if (term && strcmp(term, "dumb") == 0)
		return 0;
	return isatty(fileno(stderr));
}

/*
 * stderr_color_enabled - return the cached stderr color decision.
 * Returns 1 when color should be used, 0 when plain text should be used.
 */
static int stderr_color_enabled(void)
{
	for (;;) {
		int cached = atomic_load_explicit(&stderr_color_state,
						 memory_order_relaxed);
		int expected = -1;
		int detected;

		if (cached != -1)
			return cached;

		detected = detect_stderr_color();
		if (atomic_compare_exchange_strong_explicit(&stderr_color_state,
			    &expected, detected, memory_order_relaxed,
			    memory_order_relaxed))
			return detected;
	}
}

/*
 * msg_stderr - emit one complete formatted message record to stderr.
 * @priority: syslog LOG_* priority used for level display.
 * @fmt: printf-style format string.
 * @ap: argument list for @fmt.
 *
 * Returns nothing. The shared stderr stream is locked only while writing the
 * record so prefix/body/newline output cannot interleave with other threads.
 */
static void msg_stderr(int priority, const char *fmt, va_list ap)
{
	struct message_level level = message_level_info(priority);
	time_t rawtime = time(NULL);
	struct tm timeinfo;
	char buffer[80];
	const char *time_prefix = "time unavailable [ ";
	const int use_color = stderr_color_enabled();

	if (rawtime != (time_t)-1 &&
	    localtime_r(&rawtime, &timeinfo) != NULL &&
	    strftime(buffer, sizeof(buffer), "%x %T [ ", &timeinfo) != 0)
		time_prefix = buffer;

	flockfile(stderr);
	fputs(time_prefix, stderr);
	if (use_color)
		fputs(level.color, stderr);
	fputs(level.name, stderr);
	if (use_color)
		fputs("\x1b[0m", stderr);
	fputs(" ]: ", stderr);
	vfprintf(stderr, fmt, ap);
	fputc('\n', stderr);
	fflush(stderr);
	funlockfile(stderr);
}

/*
 * msg_stderr_f - variadic convenience wrapper around msg_stderr.
 * @priority: syslog LOG_* priority value.
 * @fmt: printf-style format string.
 */
static void msg_stderr_f(int priority, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	msg_stderr(priority, fmt, ap);
	va_end(ap);
}

/*
 * log_write - write one already-formatted message to the active destination.
 * @priority: syslog LOG_* priority value.
 * @text: complete formatted message body.
 *
 * Returns nothing. Only the drain thread may call this while the async
 * logger is running - it is the single writer to the log destinations.
 */
static void log_write(int priority, const char *text)
{
	if (message_mode == MSG_SYSLOG)
		syslog(priority, "%s", text);
	else
		msg_stderr_f(priority, "%s", text);
}

/*
 * log_enqueue - hand one message to the drain thread without blocking on
 * the log destinations.
 * @priority: syslog LOG_* priority value.
 * @fmt: printf-style format string.
 * @ap: argument list for @fmt.
 *
 * Returns nothing. LOG_SLOT_SIZE fits any reasonable message; a message
 * longer than that is truncated. When the ring is full the message is
 * dropped and counted; the drain thread reports the count once it has a
 * free moment (see log_thread_main()).
 */
static void log_enqueue(int priority, const char *fmt, va_list ap)
{
	/*
	 * A fatal signal can interrupt this thread while it already holds
	 * log_lock (coredump_handler() -> unmark_fanotify() -> msg()).
	 * Relocking a normal mutex there would hang forever. log_lock is
	 * PTHREAD_MUTEX_ERRORCHECK so that specific self-relock case returns
	 * EDEADLK instead of blocking; contention from a genuinely different
	 * thread still just blocks, the same as before this queue existed.
	 */
	if (pthread_mutex_lock(&log_lock) == EDEADLK) {
		atomic_fetch_add_explicit(&log_dropped, 1,
					  memory_order_relaxed);
		return;
	}
	/*
	 * log_sem and log_thread are guaranteed to still be alive past this
	 * point: the caller (msg()) counted itself in log_inflight before it
	 * even looked at log_state, and message_async_stop() will not post
	 * the final wakeup or call sem_destroy() until log_inflight drops
	 * back to zero. No re-check of log_state is needed here.
	 */
	if (log_count == LOG_QUEUE_DEPTH) {
		pthread_mutex_unlock(&log_lock);
		/*
		 * Just count it here. Reporting from this producer thread
		 * would mean calling msg() -> log_enqueue() again while the
		 * ring is still full, which would usually just drop the
		 * report itself - a message about the queue being full is
		 * the one message that can't be trusted to compete for a
		 * slot in that same queue. The drain thread reports this
		 * counter directly instead (see log_thread_main()).
		 */
		atomic_fetch_add_explicit(&log_dropped, 1,
					  memory_order_relaxed);
		return;
	}
	unsigned tail = (log_head + log_count) % LOG_QUEUE_DEPTH;

	log_ring[tail].priority = priority;
	int n = vsnprintf(log_ring[tail].text, LOG_SLOT_SIZE, fmt, ap);
	if (n < 0)
		n = 0;
	else if (n >= LOG_SLOT_SIZE) {
		/* LOG_SLOT_SIZE already fits any reasonable message; only a
		 * pathological one lands here. Mark it rather than stay silent. */
		static const char mark[] = " [truncated]";

		memcpy(log_ring[tail].text +
		       LOG_SLOT_SIZE - sizeof(mark), mark, sizeof(mark));
		n = LOG_SLOT_SIZE - 1;
	}
	log_ring[tail].len = (size_t)n;
	log_count++;
	/* Posted while still holding log_lock: message_async_stop() cannot
	 * reach sem_destroy() until this critical section unlocks, so this
	 * post is guaranteed to land before the semaphore can be destroyed. */
	sem_post(&log_sem);
	pthread_mutex_unlock(&log_lock);
}

/*
 * log_thread_main - drain queued messages to the log destinations.
 * @arg: unused pthread argument.
 * Returns NULL when the drain thread exits.
 */
static void *log_thread_main(void *arg)
{
	sigset_t sigs;

	(void)arg;

	/* This is a worker thread. Don't handle external signals. */
	sigemptyset(&sigs);
	sigaddset(&sigs, SIGTERM);
	sigaddset(&sigs, SIGHUP);
	sigaddset(&sigs, SIGUSR1);
	sigaddset(&sigs, SIGINT);
	sigaddset(&sigs, SIGQUIT);
	pthread_sigmask(SIG_SETMASK, &sigs, NULL);

	for (;;) {
		struct log_slot slot;
		unsigned long dropped;
		int have = 0;

		while (sem_wait(&log_sem) && errno == EINTR)
			;

		pthread_mutex_lock(&log_lock);
		if (log_count) {
			/* Copy only what was written, not the whole
			 * LOG_SLOT_SIZE slot, to keep this critical
			 * section short. */
			slot.priority = log_ring[log_head].priority;
			memcpy(slot.text, log_ring[log_head].text,
			       log_ring[log_head].len + 1);
			log_head = (log_head + 1) % LOG_QUEUE_DEPTH;
			log_count--;
			have = 1;
		}
		pthread_mutex_unlock(&log_lock);

		if (have)
			log_write(slot.priority, slot.text);

		/*
		 * log_dropped doubles as the flag this thread checks for a
		 * pending report: producer threads only ever increment it
		 * (see log_enqueue()), so a nonzero read here means messages
		 * were lost since the last time we looked. Reported directly
		 * via log_write(), not msg(), because this thread is the
		 * sole writer and never competes for a ring slot - unlike a
		 * producer thread, it cannot have its own report swallowed
		 * by the very overflow it is reporting.
		 */
		dropped = atomic_load_explicit(&log_dropped,
					       memory_order_relaxed);
		if (dropped &&
		    message_rate_limit_allow(&log_drop_limit, time(NULL))) {
			char note[64];

			dropped = atomic_exchange_explicit(&log_dropped, 0,
						memory_order_relaxed);
			snprintf(note, sizeof(note),
				 "Dropped %lu messages - log queue full",
				 dropped);
			log_write(LOG_WARNING, note);
		}

		if (!have && atomic_load_explicit(&log_state,
			     memory_order_acquire) == LOG_ASYNC_STOPPING)
			break;
	}
	return NULL;
}

int message_async_start(void)
{
	int rc;

	if (atomic_load_explicit(&log_state,
				 memory_order_relaxed) != LOG_ASYNC_OFF)
		return 0;

	if (sem_init(&log_sem, 0, 0))
		return errno;

	log_head = log_count = 0;
	rc = pthread_create(&log_thread, NULL, log_thread_main, NULL);
	if (rc) {
		sem_destroy(&log_sem);
		return rc;
	}
	atomic_store_explicit(&log_state, LOG_ASYNC_RUNNING,
			      memory_order_release);
	return 0;
}

void message_async_stop(void)
{
	if (atomic_load_explicit(&log_state,
				 memory_order_relaxed) != LOG_ASYNC_RUNNING)
		return;

	/*
	 * Flip to STOPPING while holding log_lock: any producer already past
	 * this lock completed its sem_post() before we could acquire it; any
	 * producer that acquires it after sees STOPPING and never touches
	 * log_sem. That makes sem_destroy() below safe with no producer
	 * thread needing to be joined first.
	 */
	pthread_mutex_lock(&log_lock);
	atomic_store_explicit(&log_state, LOG_ASYNC_STOPPING,
			      memory_order_release);
	pthread_mutex_unlock(&log_lock);

	/*
	 * A producer can have read log_state == RUNNING in msg() - registering
	 * itself in log_inflight first - before the STOPPING store above
	 * became visible to it. Wait here for log_inflight to drain to zero:
	 * that is proof every such producer has finished its log_enqueue()
	 * call (ring push and sem_post included), so it is now safe to post
	 * the final wakeup and destroy log_sem below. The critical sections
	 * inside log_enqueue() are short and never block, so this spins only
	 * briefly.
	 */
	while (atomic_load(&log_inflight) != 0)
		sched_yield();

	sem_post(&log_sem);

	/*
	 * pthread_join() alone can hang forever if the drain thread is stuck
	 * inside log_write() on a wedged journald/syslog - exactly the
	 * blocking hazard this whole design exists to avoid, just moved to
	 * shutdown. Give up after a bounded wait instead of hanging
	 * systemctl stop/restart indefinitely.
	 */
	struct timespec deadline;
	clock_gettime(CLOCK_REALTIME, &deadline);
	deadline.tv_sec += 5;
	if (pthread_timedjoin_np(log_thread, NULL, &deadline) != 0) {
		/* Leak the thread and semaphore rather than risk
		 * sem_destroy() on one a still-running thread may use. */
		atomic_store_explicit(&log_state, LOG_ASYNC_OFF,
				      memory_order_relaxed);
		return;
	}
	sem_destroy(&log_sem);
	atomic_store_explicit(&log_state, LOG_ASYNC_OFF,
			      memory_order_relaxed);
}

void set_message_mode(message_t mode, debug_message_t debug)
{
	message_mode = mode;
	debug_message = debug;
	if (mode == MSG_STDERR)
		atomic_store_explicit(&stderr_color_state, -1,
				      memory_order_relaxed);
}

void msg(int priority, const char *fmt, ...)
{
	va_list ap;

	if (message_mode == MSG_QUIET)
		return;

	if (priority == LOG_DEBUG && debug_message == DBG_NO)
		return;

	va_start(ap, fmt);
	/*
	 * Register in log_inflight before looking at log_state, not after:
	 * this is what lets message_async_stop() treat log_inflight == 0 as
	 * proof that no producer can still be relying on the async queue.
	 * Checking log_state first and registering afterward would leave a
	 * window where stop() samples log_inflight == 0, tears the queue
	 * down, and only then has this thread show up expecting it to still
	 * be there.
	 */
	atomic_fetch_add(&log_inflight, 1);
	if (atomic_load(&log_state) == LOG_ASYNC_RUNNING) {
		log_enqueue(priority, fmt, ap);
		atomic_fetch_sub(&log_inflight, 1);
	} else {
		atomic_fetch_sub(&log_inflight, 1);
		if (message_mode == MSG_SYSLOG)
			vsyslog(priority, fmt, ap);
		else
			msg_stderr(priority, fmt, ap);
	}
	va_end(ap);
}
