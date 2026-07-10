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
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <semaphore.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>
#include "message.h"

/* The message mode refers to where informational messages go
	0 - stderr, 1 - syslog, 2 - quiet. The default is quiet. */
static message_t message_mode = MSG_QUIET;
static debug_message_t debug_message = DBG_NO;
static atomic_int stderr_color_state = ATOMIC_VAR_INIT(-1);

/* journald can deadlock with fanotify events, so no thread that answers
 * events may write to syslog/stderr directly. Producers enqueue here
 * instead (full ring == drop + count) and one drain thread does the writes.
 */
#define LOG_SLOT_SIZE (PATH_MAX * 2)
#define LOG_QUEUE_DEPTH 256

enum { LOG_ASYNC_OFF, LOG_ASYNC_RUNNING, LOG_ASYNC_STOPPING };

struct log_slot {
	int priority;
	size_t len;		/* bytes actually written */
	char text[LOG_SLOT_SIZE];
};

static struct log_slot log_ring[LOG_QUEUE_DEPTH];
static unsigned log_head, log_count;		/* guarded by log_lock */
static pthread_mutex_t log_lock = PTHREAD_ERRORCHECK_MUTEX_INITIALIZER_NP;
static sem_t log_sem;
static pthread_t log_thread;
static atomic_int log_state = ATOMIC_VAR_INIT(LOG_ASYNC_OFF);
static atomic_ulong log_dropped = ATOMIC_VAR_INIT(0);
/* producers currently inside log_enqueue() */
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

static void msg_stderr_f(int priority, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	msg_stderr(priority, fmt, ap);
	va_end(ap);
}

/* only the drain thread calls this; text may contain '%' so it's passed
 * through as a literal "%s" body, never as a format string */
static void log_write(int priority, const char *text)
{
	if (message_mode == MSG_SYSLOG)
		syslog(priority, "%s", text);
	else
		msg_stderr_f(priority, "%s", text);
}

/* deliver to stderr without ever blocking: skip the write entirely rather
 * than risk stalling on a full pipe */
static void nonblocking_stderr(int priority, const char *fmt, va_list ap)
{
	struct pollfd pfd = { .fd = STDERR_FILENO, .events = POLLOUT };

	if (poll(&pfd, 1, 0) > 0 && (pfd.revents & POLLOUT))
		msg_stderr(priority, fmt, ap);
}

/* deliver to syslog without ever blocking. vsyslog() has no non-blocking
 * mode and can stall on a wedged journald - the exact deadlock this whole
 * async design exists to avoid - so a minimal datagram sender is used
 * instead; any failure is silently dropped, never retried/waited on */
static void nonblocking_syslog(int priority, const char *fmt, va_list ap)
{
	static int log_fd = -1;
	static int log_opened;
	char text[LOG_SLOT_SIZE];
	char packet[LOG_SLOT_SIZE + 64];
	int n;

	if (!log_opened) {
		struct sockaddr_un addr;

		log_opened = 1;
		memset(&addr, 0, sizeof(addr));
		addr.sun_family = AF_UNIX;
		strncpy(addr.sun_path, _PATH_LOG, sizeof(addr.sun_path) - 1);

		log_fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK, 0);
		if (log_fd != -1 && connect(log_fd, (struct sockaddr *)&addr,
					    sizeof(addr)) == -1) {
			close(log_fd);
			log_fd = -1;
		}
	}
	if (log_fd == -1)
		return;

	n = vsnprintf(text, sizeof(text), fmt, ap);
	if (n < 0)
		return;
	if ((size_t)n >= sizeof(text))
		n = sizeof(text) - 1;

	n = snprintf(packet, sizeof(packet), "<%d>%s[%d]: %.*s",
		     LOG_DAEMON | priority, program_invocation_short_name,
		     getpid(), n, text);
	if (n < 0)
		return;
	if ((size_t)n >= sizeof(packet))
		n = sizeof(packet) - 1;

	send(log_fd, packet, (size_t)n, MSG_DONTWAIT);
}

/* best-effort, non-blocking delivery shared by msg_direct() and by msg()
 * whenever the async drain thread isn't running */
static void msg_direct_deliver(int priority, const char *fmt, va_list ap)
{
	if (message_mode == MSG_SYSLOG)
		nonblocking_syslog(priority, fmt, ap);
	else
		nonblocking_stderr(priority, fmt, ap);
}

/*
 * msg_direct - log a message immediately, best-effort and non-blocking,
 * bypassing the async queue entirely. For callers that can't rely on (or
 * must not touch) the drain thread - e.g. the crash handler.
 */
void msg_direct(int priority, const char *fmt, ...)
{
	va_list ap;

	if (message_mode == MSG_QUIET)
		return;
	if (priority == LOG_DEBUG && debug_message == DBG_NO)
		return;

	va_start(ap, fmt);
	msg_direct_deliver(priority, fmt, ap);
	va_end(ap);
}

static void log_enqueue(int priority, const char *fmt, va_list ap)
{
	/* log_lock is ERRORCHECK: a fatal-signal handler can call msg() while
	 * this thread already holds it, and relocking must fail, not hang */
	if (pthread_mutex_lock(&log_lock) == EDEADLK) {
		atomic_fetch_add_explicit(&log_dropped, 1,
					  memory_order_relaxed);
		return;
	}
	if (log_count == LOG_QUEUE_DEPTH) {
		pthread_mutex_unlock(&log_lock);
		/* can't report via msg(): that would re-enter this same
		 * full queue and just drop the report too */
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
		static const char mark[] = " [truncated]";

		memcpy(log_ring[tail].text +
		       LOG_SLOT_SIZE - sizeof(mark), mark, sizeof(mark));
		n = LOG_SLOT_SIZE - 1;
	}
	log_ring[tail].len = (size_t)n;
	log_count++;
	/* post while still holding the lock so stop() can't destroy log_sem
	 * before this post lands */
	sem_post(&log_sem);
	pthread_mutex_unlock(&log_lock);
}

static void *log_thread_main(void *arg)
{
	sigset_t sigs;

	(void)arg;

	/* worker thread: don't handle external signals */
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

		/* log_write(), not msg(): this thread never competes for a
		 * ring slot, so its own report can't be dropped */
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

	/* flip to STOPPING under log_lock so no producer can start a fresh
	 * sem_post() after we decide it's safe to tear the queue down */
	pthread_mutex_lock(&log_lock);
	atomic_store_explicit(&log_state, LOG_ASYNC_STOPPING,
			      memory_order_release);
	pthread_mutex_unlock(&log_lock);

	/* wait for any producer already inside log_enqueue() to finish
	 * before destroying log_sem */
	while (atomic_load(&log_inflight) != 0)
		sched_yield();

	sem_post(&log_sem);

	/* bounded wait: don't let a wedged journald/syslog hang shutdown */
	struct timespec deadline;
	clock_gettime(CLOCK_REALTIME, &deadline);
	deadline.tv_sec += 5;
	if (pthread_timedjoin_np(log_thread, NULL, &deadline) != 0) {
		/* leak the thread/semaphore rather than destroy them
		 * out from under a still-running thread */
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
	/* register before checking log_state, so message_async_stop() can
	 * rely on log_inflight == 0 as proof no producer is mid-enqueue */
	atomic_fetch_add(&log_inflight, 1);
	if (atomic_load_explicit(&log_state, memory_order_relaxed) ==
	    LOG_ASYNC_RUNNING) {
		log_enqueue(priority, fmt, ap);
		atomic_fetch_sub(&log_inflight, 1);
	} else {
		atomic_fetch_sub(&log_inflight, 1);
		msg_direct_deliver(priority, fmt, ap);
	}
	va_end(ap);
}
