/*
 * notify.c - functions handle recieving and enqueuing events
 * Copyright (c) 2016-17 Red Hat Inc., Durham, North Carolina.
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
 * Free Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * Authors:
 *   Steve Grubb <sgrubb@redhat.com>
 */

#include "config.h" /* Needed to get O_LARGEFILE definition */
#include <string.h>
#include <errno.h>
#include <sys/fanotify.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <pthread.h>
#include <signal.h>
#include <sys/syscall.h>
#include "file.h"
#include "policy.h"
#include "event.h"
#include "message.h"
#include "queue.h"
#include "mounts.h"

#define FANOTIFY_BUFFER_SIZE 8192

// External variables
extern volatile int stop;
extern int q_size;

// Local variables
static pid_t our_pid;
static struct queue *q = NULL;
static pthread_t decision_thread;
static pthread_t deadmans_switch_thread;
static pthread_mutexattr_t decision_lock_attr;
static pthread_mutex_t decision_lock;
static pthread_cond_t do_decision;
static volatile int events_ready;
static volatile pid_t decision_tid;
static volatile int alive = 1;
static int fd;
static unsigned long allowed = 0, denied = 0;

// Local functions
static void *decision_thread_main(void *arg);
static void *deadmans_switch_thread_main(void *arg);

int init_fanotify(void)
{
	uint64_t mask;
	const char *path;

	// Get inter-thread queue ready
	q = q_open(q_size);
	if (q == NULL) {
		msg(LOG_ERR, "Failed setting up queue (%s)",
			strerror(errno));
		exit(1);
	}
	our_pid = getpid();

	if (load_mounts())
		exit(1);

	fd = fanotify_init(FAN_CLOEXEC | FAN_CLASS_CONTENT |
#ifdef USE_AUDIT
				FAN_ENABLE_AUDIT |
#endif
				FAN_NONBLOCK,
				O_RDONLY | O_LARGEFILE | O_CLOEXEC |
				O_NOATIME);

#ifdef USE_AUDIT
	// We will retry without the ENABLE_AUDIT to see if THAT is supported
	if (fd < 0 && errno == EINVAL) {
		fd = fanotify_init(FAN_CLOEXEC | FAN_CLASS_CONTENT |
				FAN_NONBLOCK,
				O_RDONLY | O_LARGEFILE | O_CLOEXEC |
				O_NOATIME);
		if (fd >= 0)
			policy_no_audit();
	}
#endif

	if (fd < 0) {
		msg(LOG_ERR, "Failed opening fanotify fd (%s)",
			strerror(errno));
		exit(1);
	}

	// Start decision thread so its ready when first event comes
	pthread_mutexattr_init(&decision_lock_attr);
	pthread_mutexattr_settype(&decision_lock_attr,
						PTHREAD_MUTEX_ERRORCHECK);
	pthread_mutex_init(&decision_lock, &decision_lock_attr);
	pthread_cond_init(&do_decision, NULL);
	events_ready = 0;
	pthread_create(&decision_thread, NULL, decision_thread_main, NULL);
	pthread_create(&deadmans_switch_thread, NULL,
			deadmans_switch_thread_main, NULL);

	mask = FAN_OPEN_PERM;

	// Iterate through the mount points and add a mark
	path = first_mounts();
	while (path) {
		if (fanotify_mark(fd, FAN_MARK_ADD | FAN_MARK_MOUNT,
				mask, -1, path) == -1) {
			msg(LOG_ERR, "Failed setting up watches (%s)",
				strerror(errno));
			exit(1);
		}
		msg(LOG_DEBUG, "added %s mount point", path);
		path = next_mounts();
	}

	return fd;
}

void shutdown_fanotify(void)
{
	const char *path = first_mounts();

	// Stop the flow of events
	while (path) {
		if (fanotify_mark(fd, FAN_MARK_FLUSH, 0, -1, path) == -1)
			msg(LOG_ERR, "Failed flushing path %s  (%s)",
				path, strerror(errno));
		path = next_mounts();
	}

	// End the thread
	pthread_cond_signal(&do_decision);
	pthread_join(decision_thread, NULL);
	pthread_join(deadmans_switch_thread, NULL);
	pthread_mutex_destroy(&decision_lock);
	pthread_mutexattr_destroy(&decision_lock_attr);
	pthread_cond_destroy(&do_decision);

	// Clean up
	q_close(q);
	close(fd);
	clear_mounts();

	// Report results
	msg(LOG_DEBUG, "Allowed accesses: %lu", allowed);
	msg(LOG_DEBUG, "Denied accesses: %lu", denied);
}

void decision_report(FILE *f)
{
	if (f == NULL)
		return;

	// Report results
	fprintf(f, "Allowed accesses: %lu\n", allowed);
	fprintf(f, "Denied accesses: %lu\n\n", denied);
}

static int get_ready(void)
{
	return events_ready;
}

static void set_ready(void)
{
	events_ready = 1;
}

static void clear_ready(void)
{
	events_ready = 0;
}

static void make_policy_decision(const struct fanotify_event_metadata *metadata)
{
	struct fanotify_response response;
	event_t e;
	int decision;

	if (new_event(metadata, &e))
		decision = FAN_DENY;
	else
		decision = process_event(&e);

	if ((decision & ~AUDIT) == DENY)
		denied++;
	else
		allowed++;

	// Permissive mode uses open notifications
	// that do not need responses. Only reply
	// to _PERM events.
	if (metadata->mask & FAN_OPEN_PERM) {
		response.fd = metadata->fd;
		if (permissive)
			response.response = FAN_ALLOW;
		else
			response.response = decision;
		write(fd, &response, sizeof(struct fanotify_response));
	}
}

static void *deadmans_switch_thread_main(void *arg)
{
	sigset_t sigs;

	/* This is a worker thread. Don't handle signals. */
	sigemptyset(&sigs);
	sigaddset(&sigs, SIGTERM);
	sigaddset(&sigs, SIGHUP);
	sigaddset(&sigs, SIGINT);
	pthread_sigmask(SIG_SETMASK, &sigs, NULL);

	do {
		// Are you alive decision thread?
		if (alive == 0 && get_ready() && !stop &&
					q_queue_length(q) > 2) {
			msg(LOG_ERR,
				"Deadman's switch activated...killing process");
			raise(SIGKILL);
		}
		// OK, prove it again.
		alive = 0;
		sleep(3);
	} while (!stop);
	return NULL;
}

static void *decision_thread_main(void *arg)
{
	sigset_t sigs;

	/* This is a worker thread. Don't handle signals. */
	sigemptyset(&sigs);
	sigaddset(&sigs, SIGTERM);
	sigaddset(&sigs, SIGHUP);
	sigaddset(&sigs, SIGINT);
	pthread_sigmask(SIG_SETMASK, &sigs, NULL);

	while (!stop) {
		int len;
		struct fanotify_event_metadata metadata;

		pthread_mutex_lock(&decision_lock);
		while (get_ready() == 0) {
			pthread_cond_wait(&do_decision, &decision_lock);
			if (stop) {
				pthread_mutex_unlock(&decision_lock);
				return NULL;
			}
		}
		alive = 1;
		len = q_peek(q, &metadata);
		if (len == 0) {
			// Should never happen
			clear_ready(); // Reset to reality
			pthread_mutex_unlock(&decision_lock);
			msg(LOG_DEBUG, "queue size is 0 but event recieved");
			continue;
		}
		q_drop_head(q);
		if (q_queue_length(q) == 0)
			clear_ready();
		pthread_mutex_unlock(&decision_lock);

		make_policy_decision(&metadata);
		close(metadata.fd);
	}
	msg(LOG_DEBUG, "Exiting decision thread");
	return NULL;
}

static void enqueue_event(const struct fanotify_event_metadata *metadata)
{
	pthread_mutex_lock(&decision_lock);
	if (q_append(q, metadata))
		msg(LOG_DEBUG, "enqueue error");
	else
		set_ready();
	pthread_cond_signal(&do_decision);
	pthread_mutex_unlock(&decision_lock);
}

static void approve_event(const struct fanotify_event_metadata *metadata)
{
	struct fanotify_response response;

	response.fd = metadata->fd;
	response.response = FAN_ALLOW;
	write(fd, &response, sizeof(struct fanotify_response));
	close(metadata->fd);
}

void handle_events(void)
{
	const struct fanotify_event_metadata *metadata;
	struct fanotify_event_metadata buf[FANOTIFY_BUFFER_SIZE];
	ssize_t len = -2;

	while (len < 0) {
		do {
			len = read(fd, (void *) buf, sizeof(buf));
		} while (len == -1 && errno == EINTR && stop == 0);
		if (len == -1 && errno != EAGAIN) {
			msg(LOG_ERR,"Error reading (%s)", strerror(errno));
			exit(1);
		}
		if (stop)
			return;
	}

	metadata = (const struct fanotify_event_metadata *)buf;
	while (FAN_EVENT_OK(metadata, len)) {
		if (metadata->vers != FANOTIFY_METADATA_VERSION) {
			msg(LOG_ERR, "Mismatch of fanotify metadata version");
			exit(1);
		}

		if (metadata->fd >= 0) {
			// We will only handle these 2 events for now
			if (((metadata->mask & FAN_OPEN_PERM))||
			    ((metadata->mask & FAN_OPEN))) {
				if (metadata->pid == our_pid) {
					approve_event(metadata);
				} else
					enqueue_event(metadata);
			}
			// For now, prevent leaking descriptors
			// in the near future we should do processing
			// to update the cache.
			else {
				close(metadata->fd);
				return;
			}
		}
		metadata = FAN_EVENT_NEXT(metadata, len);
	}
}

