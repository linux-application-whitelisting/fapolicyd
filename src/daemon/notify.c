/*
 * notify.c - functions handle recieving and enqueuing events
 * Copyright (c) 2016-18,2022-24 Red Hat Inc.
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
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/timerfd.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <ctype.h>
#include <time.h>
#include "conf.h"
#include "policy.h"
#include "event.h"
#include "escape.h"
#include "message.h"
#include "queue.h"
#include "mounts.h"
#include "paths.h"

#define FANOTIFY_BUFFER_SIZE 8192
#define KERNEL_OVERFLOW_LOG_INTERVAL 60

#ifndef FAN_Q_OVERFLOW
#define FAN_Q_OVERFLOW		0x00004000
#endif

// External variables
extern atomic_bool stop, run_stats;
extern conf_t config;

// Local variables
static pid_t our_pid;
static struct queue *q = NULL;
static pthread_t decision_thread;
static pthread_t deadmans_switch_thread;
static atomic_bool alive = true;
static int fd = -1;
static int rpt_timer_fd = -1;
static uint64_t mask;
static unsigned int mark_flag;
static unsigned int rpt_interval;
static atomic_ulong kernel_queue_overflow;
static atomic_long kernel_queue_overflow_last_log;

// External functions
void do_stat_report(FILE *f, int shutdown);

// Local functions
static void *decision_thread_main(void *arg);
static void *deadmans_switch_thread_main(void *arg);
void nudge_queue(void);

/*
 * getKernelQueueOverflow - return kernel fanotify overflow count.
 * Returns the number of FAN_Q_OVERFLOW events reported by the kernel.
 */
unsigned long getKernelQueueOverflow(void)
{
	return atomic_load_explicit(&kernel_queue_overflow,
				    memory_order_relaxed);
}

/*
 * kernel_overflow_should_log - rate limit kernel overflow diagnostics.
 * @now: current wall clock time.
 * Returns 1 if a critical log should be emitted, 0 otherwise.
 */
static int kernel_overflow_should_log(time_t now)
{
	long current = (long)now;
	long last = atomic_load_explicit(&kernel_queue_overflow_last_log,
					 memory_order_relaxed);

	while (last == 0 || current < last ||
	       current - last >= KERNEL_OVERFLOW_LOG_INTERVAL) {
		if (atomic_compare_exchange_weak_explicit(
			    &kernel_queue_overflow_last_log, &last, current,
			    memory_order_relaxed, memory_order_relaxed))
			return 1;
	}

	return 0;
}

/*
 * fanotify_failure_action - run the daemon-local failure response.
 * @why: diagnostic name for the failure condition.
 * Returns nothing.
 */
static void fanotify_failure_action(const char *why)
{
	(void)why;

	/*
	 * This is a placeholder until configurable failure actions are
	 * available, make the failure visible through the regular status
	 * path immediately for now.
	 */
	run_stats = true;
	nudge_queue();
}

/*
 * handle_kernel_event - process fanotify metadata without a file descriptor.
 * @metadata: fanotify event metadata from the kernel.
 * Returns 1 when the event was consumed, 0 when normal event handling should
 * continue.
 */
int handle_kernel_event(const struct fanotify_event_metadata *metadata)
{
	unsigned long total;
	time_t now;

	if ((metadata->mask & FAN_Q_OVERFLOW) == 0)
		return 0;

	total = atomic_fetch_add_explicit(&kernel_queue_overflow, 1,
					  memory_order_relaxed) + 1;
	now = time(NULL);
	if (now == (time_t)-1 || kernel_overflow_should_log(now))
		msg(LOG_CRIT,
		    "Kernel fanotify queue overflow; events were lost "
		    "(kernel_queue_overflow=%lu)", total);

	fanotify_failure_action("kernel_queue_overflow");
	return 1;
}

/*
 * escape_path_for_log - return a shell-escaped path for logging.
 * @path: path that may include control characters.
 * @escaped: optional output pointer to an allocated escaped buffer.
 * Returns escaped @path when needed, original @path when not needed,
 * or "<unavailable>" if escaping is needed but allocation fails.
 */
static const char *escape_path_for_log(const char *path, char **escaped)
{
	size_t escaped_size;

	if (escaped)
		*escaped = NULL;

	escaped_size = check_escape_shell(path);
	if (escaped_size == 0)
		return path;

	if (escaped)
		*escaped = escape_shell(path, escaped_size);
	if (escaped && *escaped)
		return *escaped;

	return "<unavailable>";
}

/*
 * open_stat_report - open status report file for overwrite without symlinks.
 * Return codes:
 * >= 0 - writable file descriptor for STAT_REPORT
 *  -1 - open or validation failed (errno set)
 */
static int open_stat_report(void)
{
	struct stat st;
	int sfd;

	sfd = open(STAT_REPORT,
		O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW,
		0640);
	if (sfd < 0)
		return -1;

	if (fstat(sfd, &st) == -1 || !S_ISREG(st.st_mode)) {
		close(sfd);
		errno = EINVAL;
		return -1;
	}

	return sfd;
}

/*
 * ignore_mounts_configured - determine whether ignore_mounts has entries.
 * @list: configuration string describing ignored mount points.
 * Returns 1 when at least one entry is configured and 0 otherwise.
 */
static int ignore_mounts_configured(const char *list)
{
	if (list == NULL)
		return 0;

	while (*list) {
		if (!isspace(*list) && *list != ',')
			return 1;
		list++;
	}

	return 0;
}

int init_fanotify(const conf_t *conf, mlist *m)
{
	const char *path;
	int ignore_mounts_enabled;

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
	rpt_interval = conf->report_interval;
	int rc = pthread_create(&decision_thread, NULL,
				decision_thread_main, NULL);
	if (rc) {
		msg(LOG_ERR, "Failed to create decision thread (%s)",
			strerror(rc));
		close(fd);
		q_close(q);
		exit(1);
	}

	rc = pthread_create(&deadmans_switch_thread, NULL,
			    deadmans_switch_thread_main, NULL);
	if (rc) {
		msg(LOG_ERR, "Failed to create deadman's switch thread (%s)",
		    strerror(rc));
		atomic_store(&stop, true);
		q_shutdown(q);
		pthread_join(decision_thread, NULL);
		if (rpt_timer_fd != -1)
			close(rpt_timer_fd);
		close(fd);
		q_close(q);
		exit(1);
	}

	mask = FAN_OPEN_PERM | FAN_OPEN_EXEC_PERM;

        ignore_mounts_enabled = ignore_mounts_configured(conf->ignore_mounts);

        if (ignore_mounts_enabled && conf->allow_filesystem_mark) {
                msg(LOG_ERR,
                    "ignore_mounts conflicts with allow_filesystem_mark - disable filesystem marks");
                exit(1);
        }

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
		char *escaped_path = NULL;
		const char *safe_path;

		safe_path = escape_path_for_log(path, &escaped_path);
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
				strerror(errno), safe_path);
			free(escaped_path);
			exit(1);
		}
		msg(LOG_DEBUG, "added %s mount point", safe_path);
		free(escaped_path);
		path = mlist_next(m);
	}

	return fd;
}

void fanotify_update(mlist *m)
{
	// Make sure fanotify_init has run
	if (fd < 0)
		return;

	if (m->head == NULL)
		return;

	mnode *cur = m->head, *prev = NULL, *temp;

	while (cur) {
		char *escaped_path = NULL;
		const char *safe_path = escape_path_for_log(cur->path,
							    &escaped_path);

		if (cur->status == MNT_ADD) {
			// We will trust that the mask was set correctly
			if (fanotify_mark(fd, FAN_MARK_ADD | mark_flag,
					mask, -1, cur->path) == -1) {
				msg(LOG_ERR,
				    "Error (%s) adding fanotify mark for %s",
					strerror(errno), safe_path);
			} else {
				msg(LOG_DEBUG, "Added %s mount point",
					safe_path);
			}
		}

		// Now remove the deleted mount point - NOTE: the kernel
		// cleans up the mark itself when umount ran. All we do
		// here is update the bookkeeping.
		if (cur->status == MNT_DELETE) {
			msg(LOG_DEBUG, "Deleted %s mount point", safe_path);
			temp = cur->next;

			if (cur == m->head)
				m->head = temp;
			else
				prev->next = temp;

			free((void *)cur->path);
			free((void *)cur);

			cur = temp;
		} else {
			prev = cur;
			cur = cur->next;
		}
		free(escaped_path);
	}
	m->cur = m->head;  // Leave cur pointing to something valid
}

void unmark_fanotify(mlist *m)
{
	if (m == NULL)
		return;

	const char *path = mlist_first(m);

	// Stop the flow of events
	while (path) {
		char *escaped_path = NULL;
		const char *safe_path = escape_path_for_log(path, &escaped_path);

		if (fanotify_mark(fd, FAN_MARK_FLUSH | mark_flag,
				  0, -1, path) == -1)
			msg(LOG_ERR, "Failed flushing path %s  (%s)",
				safe_path, strerror(errno));
		free(escaped_path);
		path = mlist_next(m);
	}
}

void shutdown_fanotify(mlist *m)
{
	unmark_fanotify(m);

	// End the thread
	q_shutdown(q);
	pthread_join(decision_thread, NULL);
	pthread_join(deadmans_switch_thread, NULL);

	// Clean up
	q_close(q);
	close(rpt_timer_fd);
	close(fd);

	// Report results
	msg(LOG_DEBUG, "Allowed accesses: %lu", getAllowed());
	msg(LOG_DEBUG, "Denied accesses: %lu", getDenied());
}

void nudge_queue(void)
{
	q_shutdown(q);
}

void decision_report(FILE *f)
{
	decision_metrics_t metrics;

	if (f == NULL)
		return;

	getDecisionMetrics(&metrics);

	// Report results
	fprintf(f, "Kernel Queue Overflow: %lu\n", getKernelQueueOverflow());
	fprintf(f, "Reply Errors: %lu\n", getReplyErrors());
	fprintf(f, "Allowed accesses: %lu\n", getAllowed());
	fprintf(f, "Denied accesses: %lu\n", getDenied());
	fprintf(f, "Allowed by rule: %lu\n", metrics.allowed_by_rule);
	fprintf(f, "Allowed by fallthrough: %lu\n",
		metrics.allowed_by_fallthrough);
	if (metrics.allowed_by_fallthrough) {
		fprintf(f, "Allowed by fallthrough open: %lu\n",
			metrics.fallthrough_open);
		fprintf(f, "Allowed by fallthrough execute: %lu\n",
			metrics.fallthrough_execute);
		fprintf(f, "Allowed by fallthrough trusted: %lu\n",
			metrics.fallthrough_trusted);
		fprintf(f, "Allowed by fallthrough untrusted: %lu\n",
			metrics.fallthrough_untrusted);
		fprintf(f, "Allowed by fallthrough trust unknown: %lu\n",
			metrics.fallthrough_trust_unknown);
		fprintf(f, "Allowed by fallthrough executable: %lu\n",
			metrics.fallthrough_executable);
		fprintf(f, "Allowed by fallthrough programmatic: %lu\n",
			metrics.fallthrough_programmatic);
		fprintf(f, "Allowed by fallthrough sharedlib: %lu\n",
			metrics.fallthrough_sharedlib);
		fprintf(f, "Allowed by fallthrough unknown ftype: %lu\n",
			metrics.fallthrough_unknown_ftype);
		fprintf(f, "Allowed by fallthrough other ftype: %lu\n",
			metrics.fallthrough_other_ftype);
	}
	fprintf(f, "Ruleset generation: %u\n", metrics.ruleset_generation);
}


static void *deadmans_switch_thread_main(void *arg)
{
	sigset_t sigs;

	/* This is a worker thread. Don't handle external signals. */
	sigemptyset(&sigs);
	sigaddset(&sigs, SIGTERM);
	sigaddset(&sigs, SIGHUP);
	sigaddset(&sigs, SIGUSR1);
	sigaddset(&sigs, SIGINT);
	sigaddset(&sigs, SIGQUIT);
	pthread_sigmask(SIG_SETMASK, &sigs, NULL);

	do {
		// Are you alive decision thread? The idea of triggering
		// on 5 is that if it's less than 5 it's still alive and
		// processing, although maybe running behind sometimes.
		// But if we are over 5, we are losing the battle.
		if (!atomic_load_explicit(&alive, memory_order_relaxed) &&
		    !atomic_load_explicit(&stop, memory_order_relaxed) &&
		    q_queue_length(q) > 5) {
			msg(LOG_ERR,
				"Deadman's switch activated...killing process");
			raise(SIGKILL);
		}
		// OK, prove it again.
		atomic_store_explicit(&alive, false, memory_order_relaxed);
		sleep(3);
	} while (!stop);
	return NULL;
}

// disable interval reports, used on unrecoverable errors
static void rpt_disable(const char *why)
{
	rpt_interval = 0;
	close(rpt_timer_fd);
	msg(LOG_INFO, "interval reports disabled; %s", why);
}

// initialize interval reporting
static void rpt_init(struct timespec *t)
{
	rpt_timer_fd = timerfd_create(CLOCK_REALTIME, TFD_NONBLOCK);
	if (rpt_timer_fd == -1) {
		rpt_disable("timer create failure");
	} else {
		t->tv_nsec = t->tv_sec = 0;
		struct itimerspec rpt_deadline = { {rpt_interval, 0},
						 {rpt_interval, 0} };
		if (timerfd_settime(rpt_timer_fd, TFD_TIMER_ABSTIME,
				    &rpt_deadline, NULL) == -1) {
			// settime errors are unrecoverable
			rpt_disable(strerror(errno));
		} else {
			msg(LOG_INFO, "interval reports configured; %us",
			    rpt_interval);
		}
	}
}

// write a stat report to file at the standard location
static void rpt_write(void)
{
	int sr_fd = open_stat_report();
	FILE *f;

	if (sr_fd < 0) {
		msg(LOG_WARNING, "cannot open %s: %s",
			STAT_REPORT, strerror(errno));
		return;
	}

	f = fdopen(sr_fd, "w");
	if (!f) {
		msg(LOG_WARNING, "cannot fdopen %s: %s",
			STAT_REPORT, strerror(errno));
		close(sr_fd);
		return;
	}

	do_stat_report(f, 0);
	fclose(f);
}

static void *decision_thread_main(void *arg)
{
	sigset_t sigs;

	/* This is a worker thread. Don't handle external signals. */
	sigemptyset(&sigs);
	sigaddset(&sigs, SIGTERM);
	sigaddset(&sigs, SIGHUP);
	sigaddset(&sigs, SIGUSR1);
	sigaddset(&sigs, SIGINT);
	sigaddset(&sigs, SIGQUIT);
	pthread_sigmask(SIG_SETMASK, &sigs, NULL);

	// interval reporting state
	int rpt_is_stale = 0;
	struct timespec rpt_timeout;

	// if an interval was configured, reports are enabled
	if (rpt_interval)
		rpt_init(&rpt_timeout);

	// start with a fresh report
	run_stats = 1;

	while (!stop) {
		int rc;
		struct fanotify_event_metadata metadata;

		// if an interval has been configured
		if (rpt_interval) {
			errno = 0;
			rc = q_timed_dequeue(q, &metadata, &rpt_timeout);
			if (rc == 0) {
				// check for timer expirations
				if (errno == ETIMEDOUT) {
					uint64_t expired = 0;
					if (read(rpt_timer_fd, &expired,
						sizeof(uint64_t)) == -1) {
						// EAGAIN expected w/nonblocking
						// timer. Any other error is
						// unrecoverable.
						if (errno != EAGAIN) {
							rpt_disable(
							    strerror(errno));
							continue;
						}
					}
					// timer expired or stats explicitly
					// requested
					if (expired || run_stats) {
					// write a new report only when one of
					// 1. new events seen since last report
					// 2. explicitly requested w/run_stats
						if (rpt_is_stale || run_stats) {
							rpt_write();
							run_stats = 0;
							rpt_is_stale = 0;
						}
						// adjust the timed dequeue timeout to
						// a full interval from now
						if (clock_gettime(CLOCK_REALTIME,
								&rpt_timeout)) {
							// gettime errors are
							// unrecoverable
							rpt_disable(
							    "clock failure");
							continue;
						}
						rpt_timeout.tv_sec +=
							rpt_interval;
					}
				}
				continue;
			}
		} else {
			rc = q_dequeue(q, &metadata);
			if (rc == 0) {
				if (run_stats) {
					rpt_write();
					run_stats = 0;
				}
				continue;
			}
			if (run_stats) {
				rpt_write();
				run_stats = 0;
			}
		}

		atomic_store_explicit(&alive, true, memory_order_relaxed);
		rpt_is_stale = 1;
		make_policy_decision(&metadata, fd, mask);
	}
	msg(LOG_DEBUG, "Exiting decision thread");
	return NULL;
}

void handle_events(void)
{
	const struct fanotify_event_metadata *metadata;
	struct fanotify_event_metadata buf[FANOTIFY_BUFFER_SIZE];
	ssize_t len = -2;

	while (len < 0) {
		do {
			len = read(fd, (void *) buf, sizeof(buf));
		} while (len == -1 && errno == EINTR && stop == false);
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

	metadata = (const struct fanotify_event_metadata *)buf;
	while (FAN_EVENT_OK(metadata, len)) {
		if (metadata->vers != FANOTIFY_METADATA_VERSION) {
			msg(LOG_ERR, "Mismatch of fanotify metadata version");
			exit(1);
		}

		if (handle_kernel_event(metadata)) {
			metadata = FAN_EVENT_NEXT(metadata, len);
			continue;
		}

		if (metadata->fd >= 0) {
			if (metadata->mask & mask) {
				if (metadata->pid == our_pid)
					reply_event(fd, metadata, FAN_ALLOW,
						    NULL);
				else if (q_enqueue(q, metadata)) {
					msg(LOG_ERR,
				"Failed to enqueue event for PID %d: "
				"queue is full, please consider tuning q_size "
				"if issue happens often", metadata->pid);
					int decision = FAN_DENY;
					if (__atomic_load_n(&config.permissive,
							    __ATOMIC_RELAXED))
						decision = FAN_ALLOW;
					reply_event(fd, metadata, decision,
						    NULL);
				}
			} else {
				// This should never happen. Reply with deny
				// which releases the descriptor and kernel
				// memory. Continue processing what was read.
				reply_event(fd, metadata, FAN_DENY, NULL);
			}
		}
		metadata = FAN_EVENT_NEXT(metadata, len);
	}
}
