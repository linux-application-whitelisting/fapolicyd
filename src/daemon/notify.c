/*
 * notify.c - daemon fanotify permission group boundary
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

/*
 * Overview
 * --------
 *
 * notify.c owns the daemon's fanotify permission group and the top-level
 * exported API used by fapolicyd.c: init_fanotify(), handle_events(),
 * shutdown_fanotify(), mark updates, public report entry points, and kernel
 * fanotify event reading. It is the boundary between kernel records and the
 * decision worker subsystem.
 *
 * The state owned here is limited to the permission fanotify fd, current mark
 * mask/mark mode, the daemon pid used for self-event bypass, and the kernel
 * queue-overflow rate limiter. This file must not own decision worker queues,
 * worker health timestamps, worker thread lifecycle, defer arrays, or watchdog
 * decisions. Those belong to decision-worker.c and worker-health.c.
 *
 * The ownership handoff remains explicit:
 *
 *   kernel fanotify fd
 *        -> handle_events() fanotify dispatcher
 *        -> decision_worker_pool_enqueue()
 *        -> decision-worker.c queue/defer/worker processing
 *        -> make_policy_decision()
 *        -> reply_event()
 *
 * Before a successful enqueue, notify.c still owns the permission fd and must
 * answer it on local errors such as invalid masks or queue-full fallback. Once
 * decision_worker_pool_enqueue() succeeds, the worker pool owns the copied
 * metadata fd and is the only path that may answer or close it, including
 * deferred-event and shutdown cleanup.
 */

#include "config.h" /* Needed to get O_LARGEFILE definition */
#include <string.h>
#include <errno.h>
#include <sys/fanotify.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <stdint.h>
#include <ctype.h>
#include <time.h>
#include "conf.h"
#include "decision-config.h"
#include "decision-worker.h"
#include "escape.h"
#include "failure-action.h"
#include "fanotify-fs-error.h"
#include "message.h"
#include "mounts.h"
#include "notify.h"
#include "policy.h"

#define FANOTIFY_BUFFER_SIZE 8192
#define KERNEL_OVERFLOW_LOG_INTERVAL 60

// External variables
extern atomic_bool stop, run_stats;
extern conf_t config;
#ifdef USE_RPM
extern atomic_int rpm_loader_pid;
#endif

// Local variables
static pid_t our_pid;
static int fd = -1;
static uint64_t mask;
static unsigned int mark_flag;
static struct message_rate_limit kernel_queue_overflow_log =
	MESSAGE_RATE_LIMIT_INIT(KERNEL_OVERFLOW_LOG_INTERVAL);

// Local functions
static void fanotify_failure_action(failure_reason_t reason);
static const char *escape_path_for_log(const char *path, char **escaped);
static int ignore_mounts_configured(const char *list);

/*
 * getKernelQueueOverflow - return kernel fanotify overflow count.
 * Returns the number of FAN_Q_OVERFLOW events reported by the kernel.
 */
unsigned long getKernelQueueOverflow(void)
{
	return failure_action_count(FAILURE_REASON_KERNEL_QUEUE_OVERFLOW);
}

/*
 * fanotify_failure_action - run the daemon-local failure response.
 * @reason: failure condition that was already recorded.
 * Returns nothing.
 */
static void fanotify_failure_action(failure_reason_t reason)
{
	(void)reason;

	/*
	 * The current action is observe-only. Wake the report path so serious
	 * reliability failures are visible before the next interval report.
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

	if (metadata->mask & FAN_Q_OVERFLOW) {
		total = failure_action_record(
			FAILURE_REASON_KERNEL_QUEUE_OVERFLOW);
		now = time(NULL);
		if (message_rate_limit_allow(&kernel_queue_overflow_log, now))
			msg(LOG_CRIT,
			    "Kernel fanotify queue overflow; events were lost "
			    "(kernel_queue_overflow=%lu)", total);

		fanotify_failure_action(FAILURE_REASON_KERNEL_QUEUE_OVERFLOW);
		return 1;
	}

	return 0;
}

/*
 * fanotify_active_worker_count - return workers currently receiving events.
 * Returns zero before fanotify initialization, otherwise the active count.
 */
unsigned int fanotify_active_worker_count(void)
{
	return decision_worker_pool_active_count();
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
 * ignore_mounts_configured - determine whether ignore_mounts has entries.
 * @list: configuration string describing ignored mount points.
 * Returns 1 when at least one entry is configured and 0 otherwise.
 */
static int ignore_mounts_configured(const char *list)
{
	if (list == NULL)
		return 0;

	while (*list) {
		if (!isspace((unsigned char)*list) && *list != ',')
			return 1;
		list++;
	}

	return 0;
}

int init_fanotify(const conf_t *conf, mlist *m)
{
	const char *path;
	struct decision_worker_runtime runtime;
	int ignore_mounts_enabled;
	int rc;

	if (decision_worker_pool_open(conf))
		exit(1);

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
		decision_worker_pool_discard();
		exit(1);
	}

	if (reply_event_init(fd)) {
		close(fd);
		decision_worker_pool_discard();
		exit(1);
	}

	runtime.fanotify_fd = fd;
	runtime.fanotify_mask = &mask;
	runtime.report_interval = conf->report_interval;
	rc = decision_worker_pool_start(&runtime);
	if (rc) {
		close(fd);
		decision_worker_pool_discard();
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

	fanotify_fs_error_init(m);
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
			fanotify_fs_error_mark(cur->path);
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
		fanotify_fs_error_unmark(path);
		free(escaped_path);
		path = mlist_next(m);
	}
}

void shutdown_fanotify(mlist *m)
{
	unmark_fanotify(m);
	decision_worker_pool_shutdown();
	decision_worker_pool_close();
	fanotify_fs_error_close();
	close(fd);

	// Report results
	msg(LOG_DEBUG, "Allowed accesses: %lu", getAllowed());
	msg(LOG_DEBUG, "Denied accesses: %lu", getDenied());
}

void nudge_queue(void)
{
	decision_worker_pool_nudge();
}

/*
 * fanotify_queue_report - write fanotify queue metrics.
 * @f: output stream.
 * Returns nothing.
 */
void fanotify_queue_report(FILE *f)
{
	decision_worker_pool_queue_report(f);
}

/*
 * fanotify_queue_report_reset - write fanotify queue metrics.
 * @f: output stream.
 * @reset: non-zero resets interval counters after copying them.
 * Returns nothing.
 */
void fanotify_queue_report_reset(FILE *f, int reset)
{
	decision_worker_pool_queue_report_reset(f, reset);
}

/*
 * fanotify_queue_health_report - write per-worker queue health indicators.
 * @f: report stream.
 * Returns nothing.
 */
void fanotify_queue_health_report(FILE *f)
{
	decision_worker_pool_queue_health_report(f);
}

/*
 * fanotify_defer_config_report - write defer capacity sized at startup.
 * @f: report stream.
 * Returns nothing.
 */
void fanotify_defer_config_report(FILE *f)
{
	decision_worker_pool_defer_config_report(f);
}

/*
 * fanotify_defer_fallback_report - write defer fallback health indicator.
 * @f: report stream.
 * Returns nothing.
 */
void fanotify_defer_fallback_report(FILE *f)
{
	decision_worker_pool_defer_fallback_report(f);
}

/*
 * fanotify_defer_age_report - write oldest deferred event age.
 * @f: report stream.
 * Returns nothing.
 */
void fanotify_defer_age_report(FILE *f)
{
	decision_worker_pool_defer_age_report(f);
}

/*
 * fanotify_defer_health_report - write defer health indicators.
 * @f: report stream.
 * Returns nothing.
 */
void fanotify_defer_health_report(FILE *f)
{
	decision_worker_pool_defer_health_report(f);
}

/*
 * fanotify_metrics_report_reset - write queue and defer activity metrics.
 * @f: report stream.
 * @reset: non-zero resets counters after snapshotting them.
 * Returns nothing.
 */
void fanotify_metrics_report_reset(FILE *f, int reset)
{
	if (f == NULL)
		return;

	fprintf(f, "\nInter-thread queue & defer activity:\n");
	fanotify_queue_report_reset(f, reset);
}

/*
 * handle_events - read policy permission fanotify events.
 * Returns nothing.
 */
void handle_events(void)
{
	const struct fanotify_event_metadata *metadata;
	struct fanotify_event_metadata buf[FANOTIFY_BUFFER_SIZE];
	ssize_t len = -2;

	if (fd < 0)
		return;

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
				if (metadata->pid == our_pid
#ifdef USE_RPM
				    || metadata->pid == atomic_load(&rpm_loader_pid)
#endif
				)
					reply_event(fd, metadata, FAN_ALLOW,
						    NULL);
				else {
					unsigned int worker_index =
						DECISION_EVENT_NO_WORKER;

					if (decision_worker_pool_enqueue(
							metadata,
							&worker_index)) {
						int decision = FAN_DENY;

						failure_action_record(
						    FAILURE_REASON_QUEUE_FULL);
						msg(LOG_ERR,
						    "Failed to enqueue event "
						    "for PID %d to worker %u: "
						    "queue is full, please "
						    "consider tuning q_size if "
						    "issue happens often",
						    metadata->pid, worker_index);
						if (decision_config_permissive(NULL))
							decision = FAN_ALLOW;
						reply_event(fd, metadata,
							    decision, NULL);
					}
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
