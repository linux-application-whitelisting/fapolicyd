/*
 * notify.c - functions handle recieving and enqueuing events
 * Copyright (c) 2016-18,2022-23 Red Hat Inc.
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
 *   Radovan Sroka <rsroka@redhat.com>
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
#include <stdatomic.h>
#include "policy.h"
#include "event.h"
#include "message.h"
#include "queue.h"
#include "mounts.h"
#include "paths.h"

#define FANOTIFY_BUFFER_SIZE 8192
#define MAX_EVENTS 4

// External variables
extern volatile atomic_bool stop, run_stats;
extern unsigned int permissive;

// Local variables
static pid_t our_pid;
static struct queue *q = NULL;
static pthread_t decision_thread;
static pthread_t deadmans_switch_thread;
static pthread_mutexattr_t decision_lock_attr;
static pthread_mutex_t decision_lock;
static pthread_cond_t do_decision;
static volatile atomic_bool events_ready;
static volatile atomic_int alive = 1;
static int fd = -1;
static uint64_t mask;
static unsigned int mark_flag;

// External functions
void do_stat_report(FILE *f, int shutdown);

// Local functions
static void *decision_thread_main(void *arg);
static void *deadmans_switch_thread_main(void *arg);

int init_fanotify(const conf_t *conf, mlist *m)
{
	const char *path;

	// Get inter-thread queue ready
	q = q_open(conf->q_size);
	if (q == NULL) {
		msg(LOG_ERR, "Failed setting up queue (%s)",
			strerror(errno));
		exit(1);
	}
	our_pid = getpid();

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

	mask = FAN_OPEN_PERM | FAN_OPEN_EXEC_PERM;
#if defined HAVE_DECL_FAN_MARK_FILESYSTEM && HAVE_DECL_FAN_MARK_FILESYSTEM != 0
	if (conf->allow_filesystem_mark)
	    mark_flag = FAN_MARK_FILESYSTEM;
	else
	    mark_flag = FAN_MARK_MOUNT;
#else
	if (conf->allow_filesystem_mark)
		msg(LOG_ERR,
	    "allow_filesystem_mark is unsupported for this kernel - ignoring");
	mark_flag = FAN_MARK_MOUNT;
#endif
	// Iterate through the mount points and add a mark
	path = mlist_first(m);
	while (path) {
retry_mark:
		if (fanotify_mark(fd, FAN_MARK_ADD | mark_flag,
				  mask, -1, path) == -1) {
			/*
			 * The FAN_OPEN_EXEC_PERM mask is not supported by
			 * all kernel releases prior to 5.0. Retry setting
			 * up the mark using only the legacy FAN_OPEN_PERM
			 * mask.
			 */
			if (errno == EINVAL && mask & FAN_OPEN_EXEC_PERM) {
				msg(LOG_INFO,
				    "Kernel doesn't support OPEN_EXEC_PERM");
				mask = FAN_OPEN_PERM;
				goto retry_mark;
			}
			msg(LOG_ERR, "Error (%s) adding fanotify mark for %s",
				strerror(errno), path);
			exit(1);
		}
		msg(LOG_DEBUG, "added %s mount point", path);
		path = mlist_next(m);
	}

	return fd;
}

void fanotify_update(mlist *m)
{
	// Make sure fanotify_init has run
	if (fd < 0)
		return;

	mlist_first(m);
	while (m->cur) {
		if (m->cur->status == ADD) {
			// We will trust that the mask was set correctly
			if (fanotify_mark(fd, FAN_MARK_ADD | mark_flag,
					mask, -1, m->cur->path) == -1) {
				msg(LOG_ERR,
				    "Error (%s) adding fanotify mark for %s",
					strerror(errno), m->cur->path);
			} else {
				msg(LOG_DEBUG, "Added %s mount point",
					m->cur->path);
			}
		}

		// Now remove the deleted mount point
		if (m->cur->status == DELETE) {
			msg(LOG_DEBUG, "Deleted %s mount point", m->cur->path);
			mlist_delete_cur(m);
		} else {
			mlist_next(m);
		}
	}
}

void shutdown_fanotify(mlist *m)
{
	const char *path = mlist_first(m);

	// Stop the flow of events
	while (path) {
		if (fanotify_mark(fd, FAN_MARK_FLUSH | mark_flag,
				  0, -1, path) == -1)
			msg(LOG_ERR, "Failed flushing path %s  (%s)",
				path, strerror(errno));
		path = mlist_next(m);
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

	// Report results
	msg(LOG_DEBUG, "Allowed accesses: %lu", getAllowed());
	msg(LOG_DEBUG, "Denied accesses: %lu", getDenied());
}

void decision_report(FILE *f)
{
	if (f == NULL)
		return;

	// Report results
	fprintf(f, "Allowed accesses: %lu\n", getAllowed());
	fprintf(f, "Denied accesses: %lu\n", getDenied());
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

static void *deadmans_switch_thread_main(void *arg)
{
	sigset_t sigs;

	/* This is a worker thread. Don't handle signals. */
	sigemptyset(&sigs);
	sigaddset(&sigs, SIGTERM);
	sigaddset(&sigs, SIGHUP);
	sigaddset(&sigs, SIGUSR1);
	sigaddset(&sigs, SIGINT);
	sigaddset(&sigs, SIGSEGV);
	pthread_sigmask(SIG_SETMASK, &sigs, NULL);

	do {
		// Are you alive decision thread?
		if (alive == 0 && get_ready() && !stop &&
					q_queue_length(q) > 5) {
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
	sigaddset(&sigs, SIGUSR1);
	sigaddset(&sigs, SIGINT);
	sigaddset(&sigs, SIGSEGV);
	pthread_sigmask(SIG_SETMASK, &sigs, NULL);

	while (!stop) {
		int len;
		struct fanotify_event_metadata metadata[MAX_EVENTS];

		pthread_mutex_lock(&decision_lock);
		while (get_ready() == 0) {
			pthread_cond_wait(&do_decision, &decision_lock);
			if (stop) {
				pthread_mutex_unlock(&decision_lock);
				return NULL;
			}
			if (run_stats) {
				FILE *f = fopen(STAT_REPORT, "w");
				if (f) {
					do_stat_report(f, 0);
					fclose(f);
				}
				run_stats = 0;
			}
		}
		alive = 1;

		// Grab up to MAX_EVENTS events while locked
		unsigned i = 0;
		size_t num = q_queue_length(q);
		if (num > MAX_EVENTS)
			num = MAX_EVENTS;
		while (i < num) {
			len = q_peek(q, &metadata[i]);
			if (len == 0) {
				// Should never happen
				clear_ready(); // Reset to reality
				msg(LOG_DEBUG,
					"queue size is 0 but event received");
				// limit processing to what we have
				num = i;
				goto out;
			}
			q_drop_head(q);
			if (q_queue_length(q) == 0)
				clear_ready();
			i++;
		}
out:
		pthread_mutex_unlock(&decision_lock);

		for (i=0; i<num; i++) {
			alive = 1;
			make_policy_decision(&metadata[i], fd, mask);
		}
	}
	msg(LOG_DEBUG, "Exiting decision thread");
	return NULL;
}

static void enqueue_event(const struct fanotify_event_metadata *metadata)
{
	if (q_append(q, metadata)) {
		msg(LOG_ERR, "Failed to enqueue event for PID %d: "
			"queue is full, please consider tuning q_size if issue happens often", metadata->pid);
		// We have to deny. This allows the kernel to free it's
		// memory related to this request. reply_event also closes
		// the descriptor, so we don't need to do it here.
		int decision = FAN_DENY;
		if (permissive)
			decision = FAN_ALLOW;
		reply_event(fd, metadata, decision, NULL);
	} else
		set_ready();
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
			// If we get this, we have no access to the file. We
			// cannot formulate a reply either to deny it because
			// we have nothing to work with.
			msg(LOG_ERR,
			    "Error receiving fanotify_event (%s)",
			    strerror(errno));
			return;
		}
		if (stop)
			return;
	}

	// Do all the locking outside of the loop so that we do
	// not keep reacquiring the locks with each iteration
	pthread_mutex_lock(&decision_lock);
	metadata = (const struct fanotify_event_metadata *)buf;
	while (FAN_EVENT_OK(metadata, len)) {
		if (metadata->vers != FANOTIFY_METADATA_VERSION) {
			msg(LOG_ERR, "Mismatch of fanotify metadata version");
			exit(1);
		}

		if (metadata->fd >= 0) {
			if (metadata->mask & mask) {
				if (metadata->pid == our_pid)
					reply_event(fd, metadata, FAN_ALLOW,
							NULL);
				else
					enqueue_event(metadata);
			} else {
				// This should never happen. Reply with deny
				// which releases the descriptor and kernel
				// memory. Continue processing what was read.
				reply_event(fd, metadata, FAN_DENY, NULL);
			}
		}
		metadata = FAN_EVENT_NEXT(metadata, len);
	}

	pthread_cond_signal(&do_decision);
	pthread_mutex_unlock(&decision_lock);
}

