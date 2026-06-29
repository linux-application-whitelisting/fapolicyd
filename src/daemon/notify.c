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

/*
 * Overview
 * --------
 *
 * notify.c owns the fanotify permission group and is the boundary between
 * kernel events and policy decisions. The main daemon thread reads fanotify
 * batches in handle_events(); from that point it acts as a dispatcher, not as
 * a policy worker. For each permission record it copies the kernel metadata
 * into a decision_event_t, computes a stable subject routing key, chooses the
 * owning decision worker, and enqueues directly to that worker's queue.
 *
 * The ownership rule is intentionally explicit:
 *
 *   kernel fanotify fd
 *        -> handle_events() dispatcher
 *        -> selected worker queue
 *        -> decision_worker_main()
 *        -> make_policy_decision()
 *        -> reply_event()
 *
 * Before a successful enqueue, the dispatcher still owns the permission event
 * and must reply on errors such as invalid masks or queue-full fallback. After
 * a successful enqueue, the selected worker owns the embedded metadata fd and
 * is the only path that may answer or close it, including deferred and
 * shutdown cleanup.
 *
 * Routing is by stable subject identity rather than queue pressure or round
 * robin. Today the stable key is the fanotify pid and only worker 0 is active;
 * later worker-pool steps can increase the active worker count once each
 * worker has a private decision context. Keeping the routing function here
 * makes that future change visible and protects the subject-cache invariant:
 * all events for one live subject must be serialized by the same decision
 * owner so startup-pattern detection observes a coherent sequence.
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
#include <sys/timerfd.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <stdint.h>
#include <ctype.h>
#include <time.h>
#include "attr-lookup-metrics.h"
#include "conf.h"
#include "daemon-config.h"
#include "decision-config.h"
#include "decision-context.h"
#include "decision-defer.h"
#include "decision-timing.h"
#include "failure-action.h"
#include "fanotify-fs-error.h"
#include "file.h"
#include "policy.h"
#include "event.h"
#include "escape.h"
#include "message.h"
#include "queue.h"
#include "mounts.h"
#include "notify.h"
#include "state-report.h"
#include "string-util.h"
#include "systemd-notify.h"

#define FANOTIFY_BUFFER_SIZE 8192
#define KERNEL_OVERFLOW_LOG_INTERVAL 60
#define SYSTEMD_WATCHDOG_LOG_INTERVAL 60
#define DEFER_RECHECK_INTERVAL_SEC 1
#define DECISION_WORKER_MAX DAEMON_CONFIG_DECISION_THREADS_MAX
#define HEALTH_MONITOR_INTERVAL_SEC 3
#define HEALTH_QUEUE_BACKLOG_THRESHOLD 5
#define NSEC_PER_SEC 1000000000ULL
#define USEC_TO_NSEC 1000ULL

// External variables
extern atomic_bool stop, run_stats;
extern conf_t config;

struct decision_worker {
	unsigned int id;
	struct queue *queue;
	struct decision_context *context;
	pthread_t thread;
	atomic_int tid;
	atomic_ullong heartbeat_ns;
	atomic_ullong current_event_started_ns;
	atomic_ullong last_completed_event_ns;
	atomic_bool stall_reported;
};

// Local variables
static pid_t our_pid;
static struct queue_metrics last_queue_metrics[DECISION_WORKER_MAX];
static unsigned int last_queue_metrics_count;
static struct decision_worker decision_workers[DECISION_WORKER_MAX];
static unsigned int active_decision_workers;
static pthread_t health_monitor_thread;
static int fd = -1;
static int rpt_timer_fd = -1;
static uint64_t mask;
static unsigned int mark_flag;
static unsigned int rpt_interval;
static unsigned int timing_saved_queue_depth[DECISION_WORKER_MAX];
static struct message_rate_limit kernel_queue_overflow_log =
	MESSAGE_RATE_LIMIT_INIT(KERNEL_OVERFLOW_LOG_INTERVAL);
static struct message_rate_limit systemd_watchdog_log =
	MESSAGE_RATE_LIMIT_INIT(SYSTEMD_WATCHDOG_LOG_INTERVAL);

// Local functions
static void *decision_worker_main(void *arg);
static void *health_monitor_thread_main(void *arg);
static void dispatch_decision_event(struct decision_worker *worker,
		decision_event_t *event, int *rpt_is_stale);
static void fanotify_failure_action(failure_reason_t reason);
static unsigned int release_ready_deferred_events(
		struct decision_worker *worker, int *rpt_is_stale);
static unsigned int shutdown_deferred_events(struct decision_worker *worker);
static unsigned int shutdown_queued_events(struct decision_worker *worker);
static void save_last_queue_metrics(void);
static int setup_decision_worker(const conf_t *conf, unsigned int worker_id);
static void cleanup_worker_setup(unsigned int worker_count);
static int worker_owns_reports(const struct decision_worker *worker);
static void worker_health_report(FILE *f, const struct decision_worker *worker);
static unsigned int timing_queue_depth_reset(void *ctx);
static unsigned int timing_queue_depth_restore(void *ctx, unsigned int saved);
static struct decision_worker *dispatcher_worker_for_metadata(
		const struct fanotify_event_metadata *metadata,
		unsigned int *worker_index);
static int dispatcher_enqueue_permission_event(
		const struct fanotify_event_metadata *metadata,
		unsigned int *worker_index);
void fanotify_queue_report_reset(FILE *f, int reset);
void nudge_queue(void);

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
	return active_decision_workers;
}

/*
 * dispatcher_subject_key - choose the stable key used for worker routing.
 * @metadata: fanotify permission metadata.
 *
 * The first worker-pool implementation routes by pid. This deliberately
 * matches the current subject state model; do not replace it with round-robin
 * or queue-depth balancing because that would split one subject's startup
 * sequence across workers.
 *
 * Returns a non-negative key suitable for modulo worker selection.
 */
static unsigned int dispatcher_subject_key(
		const struct fanotify_event_metadata *metadata)
{
	if (metadata == NULL || metadata->pid <= 0)
		return 0;

	return (unsigned int)metadata->pid;
}

/*
 * dispatcher_worker_index_from_key - map one subject key to a worker.
 *
 * NOTE: This is the only way possible to route incoming events to a worker.
 * Rerouting to available workers is impossible because we need the same pid
 * to always land on the same worker so that the pattern detection state
 * machine can see the whole startup in the same cache. Never change this
 * algorithm!
 *
 * @subject_key: stable key from dispatcher_subject_key().
 * @worker_count: active decision workers.
 *
 * Returns the selected worker index. A zero worker count falls back to zero so
 * unit tests can exercise the pure routing calculation without a live daemon.
 */
static unsigned int dispatcher_worker_index_from_key(
		unsigned int subject_key, unsigned int worker_count)
{
	if (worker_count == 0)
		return 0;

	return subject_key % worker_count;
}

/*
 * dispatcher_worker_for_metadata - select the worker for one permission event.
 * @metadata: fanotify permission metadata.
 * @worker_index: optional destination for the selected index.
 *
 * Returns the selected worker, or NULL when fanotify is not initialized.
 */
static struct decision_worker *dispatcher_worker_for_metadata(
		const struct fanotify_event_metadata *metadata,
		unsigned int *worker_index)
{
	unsigned int index;

	index = dispatcher_worker_index_from_key(
		dispatcher_subject_key(metadata), active_decision_workers);
	if (worker_index)
		*worker_index = index;

	if (index >= active_decision_workers) {
		errno = ENODEV;
		return NULL;
	}

	if (decision_workers[index].queue == NULL) {
		errno = ENODEV;
		return NULL;
	}

	return &decision_workers[index];
}

/*
 * dispatcher_enqueue_permission_event - hand one permission fd to a worker.
 * @metadata: fanotify metadata read by handle_events().
 * @worker_index: optional destination for the selected index.
 *
 * On success, the selected worker queue owns the copied metadata and therefore
 * owns the permission fd reply/close obligation. On failure, ownership stays
 * with the dispatcher and the caller must answer the fanotify event.
 *
 * Returns 0 on success and -1 on failure with errno set.
 */
static int dispatcher_enqueue_permission_event(
		const struct fanotify_event_metadata *metadata,
		unsigned int *worker_index)
{
	struct decision_worker *worker;
	decision_event_t event;
	unsigned int index;

	worker = dispatcher_worker_for_metadata(metadata, &index);
	if (worker_index)
		*worker_index = index;
	if (worker == NULL)
		return -1;

	decision_event_init(&event, metadata);
	event.worker_index = index;

	return q_enqueue(worker->queue, &event);
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

/*
 * worker_context - return the decision context owned by a worker.
 * @worker: decision worker, or NULL in unit-test helper paths.
 *
 * Unit tests can exercise queue/defer cleanup without full daemon startup. In
 * that case the default thread context is used, matching the older single
 * global-context behavior.
 *
 * Returns the worker context or the current thread context fallback.
 */
static struct decision_context *worker_context(struct decision_worker *worker)
{
	if (worker && worker->context)
		return worker->context;
	return decision_context_current();
}

/*
 * worker_defer_queue - return the worker-local subject defer array.
 * @worker: decision worker whose deferred events should be accessed.
 * Returns the defer queue owned by the worker context.
 */
static struct decision_defer_queue *worker_defer_queue(
		struct decision_worker *worker)
{
	return &worker_context(worker)->defer_queue;
}

/*
 * worker_owns_reports - determine whether a worker owns daemon reports.
 * @worker: decision worker to inspect.
 *
 * Interval and signal-triggered reports use shared report state. Keep that
 * control-plane work on worker 0 while other workers only process decisions.
 *
 * Returns 1 when @worker owns reports, 0 otherwise.
 */
static int worker_owns_reports(const struct decision_worker *worker)
{
	return worker && worker->id == 0;
}

enum worker_health_state {
	WORKER_HEALTH_IDLE,
	WORKER_HEALTH_BUSY,
};

struct worker_health_snapshot {
	enum worker_health_state state;
	uint64_t heartbeat_age_ns;
	uint64_t current_event_age_ns;
};

/*
 * health_now_ns - read monotonic time for worker health checks.
 * Returns monotonic nanoseconds, or zero if the clock cannot be read.
 */
static uint64_t health_now_ns(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts))
		return 0;

	return (uint64_t)ts.tv_sec * NSEC_PER_SEC + (uint64_t)ts.tv_nsec;
}

/*
 * health_age_ns - compute an age from a monotonic timestamp.
 * @now: current monotonic time in nanoseconds.
 * @timestamp: older monotonic timestamp, or zero when unset.
 * Returns age in nanoseconds, or zero when the timestamp is unset or invalid.
 */
static uint64_t health_age_ns(uint64_t now, uint64_t timestamp)
{
	if (timestamp == 0 || now < timestamp)
		return 0;

	return now - timestamp;
}

/*
 * worker_health_state_name - convert a worker health state to report text.
 * @state: health state to describe.
 * Returns a static string for reports and logs.
 */
static const char *worker_health_state_name(enum worker_health_state state)
{
	switch (state) {
	case WORKER_HEALTH_IDLE:
		return "idle";
	case WORKER_HEALTH_BUSY:
		return "busy";
	}

	return "unknown";
}

/*
 * worker_health_init - initialize health timestamps for one worker slot.
 * @worker: worker slot being initialized.
 * Returns nothing.
 */
static void worker_health_init(struct decision_worker *worker)
{
	uint64_t now;

	if (worker == NULL)
		return;

	now = health_now_ns();
	atomic_store_explicit(&worker->heartbeat_ns, now, memory_order_relaxed);
	atomic_store_explicit(&worker->current_event_started_ns, 0,
			      memory_order_relaxed);
	atomic_store_explicit(&worker->last_completed_event_ns, 0,
			      memory_order_relaxed);
	atomic_store_explicit(&worker->stall_reported, false,
			      memory_order_relaxed);
}

/*
 * worker_health_heartbeat - record worker loop progress.
 * @worker: worker that made progress.
 * Returns nothing.
 */
static void worker_health_heartbeat(struct decision_worker *worker)
{
	if (worker == NULL)
		return;

	atomic_store_explicit(&worker->heartbeat_ns, health_now_ns(),
			      memory_order_relaxed);
}

/*
 * worker_health_event_begin - mark the start of a policy decision.
 * @worker: worker processing the event.
 * Returns nothing.
 */
static void worker_health_event_begin(struct decision_worker *worker)
{
	uint64_t now;

	if (worker == NULL)
		return;

	now = health_now_ns();
	atomic_store_explicit(&worker->current_event_started_ns, now,
			      memory_order_release);
	atomic_store_explicit(&worker->heartbeat_ns, now, memory_order_relaxed);
}

/*
 * worker_health_event_end - mark a completed policy decision.
 * @worker: worker that finished processing.
 * Returns nothing.
 */
static void worker_health_event_end(struct decision_worker *worker)
{
	uint64_t now;

	if (worker == NULL)
		return;

	now = health_now_ns();
	atomic_store_explicit(&worker->last_completed_event_ns, now,
			      memory_order_relaxed);
	atomic_store_explicit(&worker->current_event_started_ns, 0,
			      memory_order_release);
	atomic_store_explicit(&worker->heartbeat_ns, now, memory_order_relaxed);
	atomic_store_explicit(&worker->stall_reported, false,
			      memory_order_relaxed);
}

/*
 * worker_health_snapshot - copy one worker's health timestamps.
 * @worker: worker to inspect.
 * @snapshot: destination snapshot.
 * @now: current monotonic time in nanoseconds.
 * Returns nothing.
 */
static void worker_health_snapshot(const struct decision_worker *worker,
		struct worker_health_snapshot *snapshot, uint64_t now)
{
	uint64_t heartbeat, current;

	if (worker == NULL || snapshot == NULL)
		return;

	heartbeat = atomic_load_explicit(&worker->heartbeat_ns,
					 memory_order_relaxed);
	current = atomic_load_explicit(&worker->current_event_started_ns,
				       memory_order_acquire);

	if (current != 0)
		snapshot->state = WORKER_HEALTH_BUSY;
	else
		snapshot->state = WORKER_HEALTH_IDLE;

	snapshot->heartbeat_age_ns = health_age_ns(now, heartbeat);
	snapshot->current_event_age_ns = health_age_ns(now, current);
}

/*
 * worker_health_report - write one compact decision-worker health line.
 * @f: report stream.
 * @worker: decision worker to describe.
 */
static void worker_health_report(FILE *f, const struct decision_worker *worker)
{
	struct worker_health_snapshot snapshot = { 0 };
	char heartbeat[32], current[32];
	const char *state;
	uint64_t now;

	if (f == NULL || worker == NULL)
		return;

	now = health_now_ns();
	worker_health_snapshot(worker, &snapshot, now);
	fapolicyd_format_ns(snapshot.heartbeat_age_ns, heartbeat,
			    sizeof(heartbeat));
	if (snapshot.state == WORKER_HEALTH_IDLE)
		snprintf(current, sizeof(current), "idle");
	else
		fapolicyd_format_ns(snapshot.current_event_age_ns, current,
				    sizeof(current));
	if (atomic_load_explicit(&worker->stall_reported, memory_order_relaxed))
		state = "stalled";
	else
		state = worker_health_state_name(snapshot.state);

	fprintf(f, "  Decision worker %u health: state=%s heartbeat=%s "
		"current_event=%s\n", worker->id, state, heartbeat, current);
}

/*
 * setup_decision_worker - initialize one worker slot before threads start.
 * @conf: daemon configuration.
 * @worker_id: slot to initialize.
 *
 * Worker 0 reuses the context created by init_event_system(). Additional
 * workers get private contexts and private file-helper state so libmagic,
 * udev, caches, counters, and defers are not shared across decision threads.
 *
 * Returns 0 on success and -1 on failure with errno set when practical.
 */
static int setup_decision_worker(const conf_t *conf, unsigned int worker_id)
{
	struct decision_context *previous = decision_context_current();
	struct decision_worker *worker = &decision_workers[worker_id];
	int rc;

	worker->id = worker_id;
	worker->queue = NULL;
	worker->context = NULL;
	atomic_store_explicit(&worker->tid, 0, memory_order_relaxed);
	worker_health_init(worker);

	if (worker_id == 0)
		worker->context = previous;
	else {
		worker->context = decision_context_create(conf);
		if (worker->context == NULL)
			return -1;

		decision_context_set_current(worker->context);
		rc = file_init();
		decision_context_set_current(previous);
		if (rc) {
			decision_context_destroy(worker->context);
			worker->context = NULL;
			errno = ENOMEM;
			return -1;
		}
	}

	worker->queue = q_open(conf->q_size);
	if (worker->queue == NULL) {
		if (worker_id != 0) {
			decision_context_destroy(worker->context);
			worker->context = NULL;
		}
		return -1;
	}
	decision_context_set_worker_id(worker->context, worker_id);

	return 0;
}

/*
 * cleanup_worker_setup - release partially initialized worker startup state.
 * @worker_count: number of worker slots that may own resources.
 *
 * Returns nothing.
 */
static void cleanup_worker_setup(unsigned int worker_count)
{
	unsigned int i;

	for (i = 0; i < worker_count; i++) {
		struct decision_worker *worker = &decision_workers[i];

		if (worker->queue) {
			q_close(worker->queue);
			worker->queue = NULL;
		}
		if (i != 0 && worker->context) {
			decision_context_destroy(worker->context);
			worker->context = NULL;
		}
	}
	active_decision_workers = 0;
	decision_timing_set_active_workers(0);
	decision_timing_set_queue_depth_hooks(NULL, NULL, NULL);
}

int init_fanotify(const conf_t *conf, mlist *m)
{
	const char *path;
	int ignore_mounts_enabled;
	int rc;
	unsigned int i, started_workers = 0;

	active_decision_workers = 0;
	decision_timing_set_active_workers(0);
	if (conf->decision_threads == 0 ||
	    conf->decision_threads > DECISION_WORKER_MAX) {
		msg(LOG_ERR, "Invalid decision_threads value %u",
		    conf->decision_threads);
		exit(1);
	}

	for (i = 0; i < conf->decision_threads; i++) {
		if (setup_decision_worker(conf, i)) {
			msg(LOG_ERR, "Failed setting up decision worker %u (%s)",
			    i, strerror(errno));
			cleanup_worker_setup(i + 1);
			exit(1);
		}
	}
	active_decision_workers = conf->decision_threads;
	decision_timing_set_active_workers(active_decision_workers);
	save_last_queue_metrics();
	decision_timing_set_queue_depth_hooks(timing_queue_depth_reset,
					      timing_queue_depth_restore,
					      NULL);
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
		cleanup_worker_setup(active_decision_workers);
		exit(1);
	}

	if (reply_event_init(fd)) {
		close(fd);
		cleanup_worker_setup(active_decision_workers);
		exit(1);
	}

	// Start the decision worker so it is ready when first event comes.
	rpt_interval = conf->report_interval;
	for (i = 0; i < active_decision_workers; i++) {
		struct decision_worker *worker = &decision_workers[i];

		rc = pthread_create(&worker->thread, NULL,
				    decision_worker_main, worker);
		if (rc) {
			msg(LOG_ERR,
			    "Failed to create decision worker %u (%s)",
			    worker->id, strerror(rc));
			atomic_store(&stop, true);
			for (i = 0; i < started_workers; i++)
				q_shutdown(decision_workers[i].queue);
			for (i = 0; i < started_workers; i++)
				pthread_join(decision_workers[i].thread, NULL);
			close(fd);
			cleanup_worker_setup(active_decision_workers);
			exit(1);
		}
		started_workers++;
	}

	msg(LOG_INFO, "Activated %u fanotify decision worker%s",
	    active_decision_workers,
	    active_decision_workers == 1 ? "" : "s");

	rc = pthread_create(&health_monitor_thread, NULL,
			    health_monitor_thread_main, NULL);
	if (rc) {
		msg(LOG_ERR, "Failed to create health monitor thread (%s)",
		    strerror(rc));
		atomic_store(&stop, true);
		for (i = 0; i < active_decision_workers; i++)
			q_shutdown(decision_workers[i].queue);
		for (i = 0; i < active_decision_workers; i++)
			pthread_join(decision_workers[i].thread, NULL);
		if (rpt_timer_fd != -1)
			close(rpt_timer_fd);
		close(fd);
		cleanup_worker_setup(active_decision_workers);
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

/*
 * queue_metrics_merge - fold one worker queue snapshot into an aggregate.
 * @aggregate: aggregate metrics being built.
 * @metrics: worker queue metrics to add.
 * Returns nothing.
 */
static void queue_metrics_merge(struct queue_metrics *aggregate,
		const struct queue_metrics *metrics)
{
	aggregate->current_depth += metrics->current_depth;
	if (metrics->max_depth > aggregate->max_depth)
		aggregate->max_depth = metrics->max_depth;
	aggregate->full_count += metrics->full_count;
	if (metrics->oldest_age_ns > aggregate->oldest_age_ns)
		aggregate->oldest_age_ns = metrics->oldest_age_ns;
}

/*
 * save_last_queue_metrics - retain final queue snapshots for reports.
 * Returns nothing.
 */
static void save_last_queue_metrics(void)
{
	unsigned int i;

	last_queue_metrics_count = 0;
	for (i = 0; i < active_decision_workers; i++) {
		struct decision_worker *worker = &decision_workers[i];

		if (worker->queue == NULL)
			continue;

		q_metrics_snapshot(worker->queue, &last_queue_metrics[i]);
		last_queue_metrics_count = i + 1;
	}
}

void shutdown_fanotify(mlist *m)
{
	unsigned int i;

	unmark_fanotify(m);

	// End the worker threads.
	for (i = 0; i < active_decision_workers; i++)
		q_shutdown(decision_workers[i].queue);
	for (i = 0; i < active_decision_workers; i++)
		pthread_join(decision_workers[i].thread, NULL);
	pthread_join(health_monitor_thread, NULL);

	// Clean up
	save_last_queue_metrics();
	for (i = 0; i < active_decision_workers; i++) {
		struct decision_context *ctx = decision_workers[i].context;

		if (ctx == NULL)
			continue;
		decision_defer_metrics_snapshot_reset(&ctx->defer_queue,
						      &ctx->last_defer_metrics,
						      0);
	}
	decision_timing_set_queue_depth_hooks(NULL, NULL, NULL);
	decision_timing_set_active_workers(0);
	for (i = 0; i < active_decision_workers; i++) {
		if (decision_workers[i].queue == NULL)
			continue;
		q_close(decision_workers[i].queue);
		decision_workers[i].queue = NULL;
		decision_workers[i].context = NULL;
	}
	active_decision_workers = 0;
	if (rpt_timer_fd != -1) {
		close(rpt_timer_fd);
		rpt_timer_fd = -1;
	}
	fanotify_fs_error_close();
	close(fd);

	// Report results
	msg(LOG_DEBUG, "Allowed accesses: %lu", getAllowed());
	msg(LOG_DEBUG, "Denied accesses: %lu", getDenied());
}

void nudge_queue(void)
{
	unsigned int i;

	for (i = 0; i < active_decision_workers; i++)
		q_shutdown(decision_workers[i].queue);
}

/*
 * timing_queue_depth_reset - reset timing run max queue depth.
 * @ctx: unused.
 *
 * Returns the largest max-depth value saved across worker queues.
 */
static unsigned int timing_queue_depth_reset(void *ctx)
{
	unsigned int i, saved, aggregate = 0;

	(void)ctx;

	for (i = 0; i < active_decision_workers; i++) {
		struct decision_worker *worker = &decision_workers[i];

		if (worker->queue == NULL) {
			timing_saved_queue_depth[i] = 0;
			continue;
		}
		saved = q_max_depth_snapshot_reset(worker->queue);
		timing_saved_queue_depth[i] = saved;
		if (saved > aggregate)
			aggregate = saved;
	}

	return aggregate;
}

/*
 * timing_queue_depth_restore - snapshot timing run queue depth and restore.
 * @ctx: unused.
 * @saved: aggregate value returned by timing_queue_depth_reset().
 *
 * Returns the largest max depth observed across worker queues during the run.
 */
static unsigned int timing_queue_depth_restore(void *ctx, unsigned int saved)
{
	unsigned int i, current, aggregate = 0;

	(void)ctx;
	(void)saved;

	for (i = 0; i < active_decision_workers; i++) {
		struct decision_worker *worker = &decision_workers[i];

		if (worker->queue == NULL)
			continue;
		current = q_max_depth_snapshot_restore(worker->queue,
				timing_saved_queue_depth[i]);
		if (current > aggregate)
			aggregate = current;
		timing_saved_queue_depth[i] = 0;
	}

	return aggregate;
}

struct defer_worker_snapshot {
	unsigned int worker_id;
	struct decision_defer_metrics metrics;
};

struct defer_report_snapshot {
	struct decision_defer_metrics metrics;
	struct defer_worker_snapshot workers[DECISION_WORKER_MAX];
	unsigned int worker_count;
	int reset;
};

/*
 * defer_metrics_merge - fold one worker defer snapshot into an aggregate.
 * @aggregate: aggregate defer metrics reported to operators.
 * @metrics: metrics copied from one worker-owned defer array.
 * Returns nothing.
 */
static void defer_metrics_merge(struct decision_defer_metrics *aggregate,
		const struct decision_defer_metrics *metrics)
{
	aggregate->capacity += metrics->capacity;
	aggregate->current_depth += metrics->current_depth;
	aggregate->deferred_events += metrics->deferred_events;
	aggregate->max_depth += metrics->max_depth;
	aggregate->fallbacks += metrics->fallbacks;
	if (metrics->oldest_age_ns > aggregate->oldest_age_ns)
		aggregate->oldest_age_ns = metrics->oldest_age_ns;
}

/*
 * defer_report_snapshot_context - snapshot one worker defer array.
 * @ctx: worker context being sampled.
 * @data: struct defer_report_snapshot aggregate.
 * Returns nothing.
 */
static void defer_report_snapshot_context(struct decision_context *ctx,
		void *data)
{
	struct defer_report_snapshot *snapshot = data;
	struct decision_defer_metrics metrics;
	unsigned int index;

	if (ctx == NULL || snapshot == NULL)
		return;

	decision_defer_metrics_snapshot_reset(&ctx->defer_queue, &metrics,
					      snapshot->reset);
	ctx->last_defer_metrics = metrics;
	defer_metrics_merge(&snapshot->metrics, &metrics);
	index = snapshot->worker_count;
	if (index < DECISION_WORKER_MAX) {
		snapshot->workers[index].worker_id = ctx->worker_id;
		snapshot->workers[index].metrics = metrics;
		snapshot->worker_count++;
	}
}

/*
 * defer_report_snapshot_reset - snapshot defer counters across workers.
 * @snapshot: destination for aggregate and per-worker defer metrics.
 * @reset: non-zero resets interval counters after copying them.
 * Returns nothing.
 */
static void defer_report_snapshot_reset(struct defer_report_snapshot *snapshot,
		int reset)
{
	if (snapshot == NULL)
		return;

	memset(snapshot, 0, sizeof(*snapshot));
	snapshot->reset = reset;
	decision_context_for_each(defer_report_snapshot_context, snapshot);
}

/*
 * defer_worker_snapshot_sort - order worker defer snapshots by worker id.
 * @snapshot: defer report snapshot to sort.
 * Returns nothing.
 */
static void defer_worker_snapshot_sort(struct defer_report_snapshot *snapshot)
{
	unsigned int i, j;

	if (snapshot == NULL)
		return;

	for (i = 0; i < snapshot->worker_count; i++) {
		for (j = i + 1; j < snapshot->worker_count; j++) {
			unsigned int left = snapshot->workers[i].worker_id;
			unsigned int right = snapshot->workers[j].worker_id;

			if (left <= right)
				continue;
			{
				struct defer_worker_snapshot tmp =
					snapshot->workers[i];
				snapshot->workers[i] = snapshot->workers[j];
				snapshot->workers[j] = tmp;
			}
		}
	}
}

/*
 * fanotify_queue_report - write fanotify queue metrics.
 * @f: output stream.
 * Returns nothing.
 */
void fanotify_queue_report(FILE *f)
{
	fanotify_queue_report_reset(f, 0);
}

/*
 * fanotify_queue_report_reset - write fanotify queue metrics.
 * @f: output stream.
 * @reset: non-zero resets interval counters after copying them.
 * Returns nothing.
 */
void fanotify_queue_report_reset(FILE *f, int reset)
{
	struct queue_metrics aggregate = { 0 };
	struct queue_metrics metrics[DECISION_WORKER_MAX];
	unsigned int worker_ids[DECISION_WORKER_MAX];
	unsigned int count = 0;
	unsigned int i;

	if (f == NULL)
		return;

	if (active_decision_workers) {
		for (i = 0; i < active_decision_workers; i++) {
			struct decision_worker *worker = &decision_workers[i];

			if (worker->queue == NULL)
				continue;

			q_metrics_snapshot_reset(worker->queue, &metrics[count],
						 reset);
			worker_ids[count] = worker->id;
			queue_metrics_merge(&aggregate, &metrics[count]);
			count++;
		}
	} else {
		for (i = 0; i < last_queue_metrics_count; i++) {
			metrics[count] = last_queue_metrics[i];
			worker_ids[count] = i;
			queue_metrics_merge(&aggregate, &metrics[count]);
			count++;
		}
	}

	q_metrics_report(f, &aggregate);
	for (i = 0; i < count; i++)
		q_metrics_report_worker(f, worker_ids[i], &metrics[i]);

	{
		struct defer_report_snapshot defer_snapshot;

		defer_report_snapshot_reset(&defer_snapshot, reset);
		decision_defer_metrics_report(f, &defer_snapshot.metrics);
		if (defer_snapshot.worker_count) {
			defer_worker_snapshot_sort(&defer_snapshot);
			fprintf(f, "\nPer-worker subject defer activity:\n");
			for (i = 0; i < defer_snapshot.worker_count; i++)
				decision_defer_metrics_report_worker(f,
					defer_snapshot.workers[i].worker_id,
					&defer_snapshot.workers[i].metrics);
		}
	}
}

/*
 * fanotify_queue_health_report - write per-worker queue health indicators.
 * @f: report stream.
 * Returns nothing.
 */
void fanotify_queue_health_report(FILE *f)
{
	unsigned int i;

	if (f == NULL)
		return;

	if (active_decision_workers) {
		for (i = 0; i < active_decision_workers; i++) {
			struct queue_metrics metrics;
			struct decision_worker *worker = &decision_workers[i];

			if (worker->queue == NULL)
				continue;

			worker_health_report(f, worker);
			q_metrics_snapshot(worker->queue, &metrics);
			q_metrics_report_worker(f, worker->id, &metrics);
		}
		return;
	}

	for (i = 0; i < last_queue_metrics_count; i++)
		q_metrics_report_worker(f, i, &last_queue_metrics[i]);
}

/*
 * fanotify_defer_config_report - write defer capacity sized at startup.
 * @f: report stream.
 * Returns nothing.
 */
void fanotify_defer_config_report(FILE *f)
{
	struct defer_report_snapshot snapshot;
	struct decision_defer_metrics metrics;

	if (f == NULL)
		return;

	defer_report_snapshot_reset(&snapshot, 0);
	metrics = snapshot.metrics;
	if (snapshot.worker_count)
		metrics.capacity /= snapshot.worker_count;
	decision_defer_config_report(f, &metrics);
}

/*
 * fanotify_defer_fallback_report - write defer fallback health indicator.
 * @f: report stream.
 * Returns nothing.
 */
void fanotify_defer_fallback_report(FILE *f)
{
	struct defer_report_snapshot snapshot;

	if (f == NULL)
		return;

	defer_report_snapshot_reset(&snapshot, 0);
	decision_defer_fallback_report(f, &snapshot.metrics);
}

/*
 * fanotify_defer_age_report - write oldest deferred event age.
 * @f: report stream.
 * Returns nothing.
 */
void fanotify_defer_age_report(FILE *f)
{
	struct defer_report_snapshot snapshot;

	if (f == NULL)
		return;

	defer_report_snapshot_reset(&snapshot, 0);
	decision_defer_age_report(f, &snapshot.metrics);
}

/*
 * fanotify_defer_health_report - write defer health indicators.
 * @f: report stream.
 * Returns nothing.
 */
void fanotify_defer_health_report(FILE *f)
{
	struct defer_report_snapshot snapshot;

	if (f == NULL)
		return;

	defer_report_snapshot_reset(&snapshot, 0);
	decision_defer_health_report(f, &snapshot.metrics);
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
 * health_monitor_interval_ns - choose the monitor wake interval.
 * Returns half the systemd watchdog interval when enabled, otherwise the legacy
 * three-second monitor cadence.
 */
static uint64_t health_monitor_interval_ns(void)
{
	uint64_t watchdog = systemd_watchdog_interval_usec();

	if (watchdog)
		return (watchdog * USEC_TO_NSEC) / 2;

	return HEALTH_MONITOR_INTERVAL_SEC * NSEC_PER_SEC;
}

/*
 * health_stall_timeout_ns - choose the worker stall deadline.
 * Returns the systemd watchdog interval when enabled, otherwise the legacy
 * three-second stall deadline.
 */
static uint64_t health_stall_timeout_ns(void)
{
	uint64_t watchdog = systemd_watchdog_interval_usec();

	if (watchdog)
		return watchdog * USEC_TO_NSEC;

	return HEALTH_MONITOR_INTERVAL_SEC * NSEC_PER_SEC;
}

/*
 * health_monitor_sleep - sleep in short chunks so shutdown is not delayed.
 * @interval_ns: requested sleep interval in nanoseconds.
 * Returns nothing.
 */
static void health_monitor_sleep(uint64_t interval_ns)
{
	while (!atomic_load_explicit(&stop, memory_order_relaxed) &&
	       interval_ns > 0) {
		struct timespec ts;
		uint64_t chunk = interval_ns;

		if (chunk > NSEC_PER_SEC)
			chunk = NSEC_PER_SEC;
		ts.tv_sec = (time_t)(chunk / NSEC_PER_SEC);
		ts.tv_nsec = (long)(chunk % NSEC_PER_SEC);
		while (nanosleep(&ts, &ts) && errno == EINTR)
			;
		interval_ns -= chunk;
	}
}

/*
 * worker_health_is_stalled - decide whether one worker stopped progressing.
 * @snapshot: worker health timestamp snapshot.
 * @metrics: queue metrics for the worker.
 * @timeout_ns: stall deadline in nanoseconds.
 *
 * A single slow current decision can be legitimate storage latency, so the
 * compatibility action requires visible queued pressure before treating it as
 * a daemon-level stall. If no decision is active, an old queued event plus a
 * stale heartbeat means the worker is not draining its queue.
 *
 * Returns 1 when the worker is stalled, 0 otherwise.
 */
static int worker_health_is_stalled(
		const struct worker_health_snapshot *snapshot,
		const struct queue_metrics *metrics, uint64_t timeout_ns)
{
	if (snapshot == NULL || metrics == NULL || timeout_ns == 0)
		return 0;

	if (snapshot->state != WORKER_HEALTH_IDLE &&
	    snapshot->current_event_age_ns >= timeout_ns &&
	    (metrics->current_depth > HEALTH_QUEUE_BACKLOG_THRESHOLD ||
	     metrics->oldest_age_ns >= timeout_ns))
		return 1;

	if (snapshot->state == WORKER_HEALTH_IDLE &&
	    metrics->current_depth > 0 &&
	    metrics->oldest_age_ns >= timeout_ns &&
	    snapshot->heartbeat_age_ns >= timeout_ns)
		return 1;

	return 0;
}

/*
 * health_monitor_log_stall - record and report one worker stall.
 * @worker: stalled worker.
 * @snapshot: worker health snapshot.
 * @metrics: queue metrics for the worker.
 * Returns nothing.
 */
static void health_monitor_log_stall(struct decision_worker *worker,
		const struct worker_health_snapshot *snapshot,
		const struct queue_metrics *metrics)
{
	char heartbeat[32], current[32], oldest[32];
	unsigned long total;
	int tid;

	if (worker == NULL || snapshot == NULL || metrics == NULL)
		return;

	if (atomic_exchange_explicit(&worker->stall_reported, true,
				     memory_order_relaxed))
		return;

	total = failure_action_record(FAILURE_REASON_WORKER_STALL);
	tid = atomic_load_explicit(&worker->tid, memory_order_relaxed);
	fapolicyd_format_ns(snapshot->heartbeat_age_ns, heartbeat,
			    sizeof(heartbeat));
	if (snapshot->state == WORKER_HEALTH_IDLE)
		snprintf(current, sizeof(current), "idle");
	else
		fapolicyd_format_ns(snapshot->current_event_age_ns, current,
				    sizeof(current));
	fapolicyd_format_ns(metrics->oldest_age_ns, oldest, sizeof(oldest));

	msg(LOG_ERR,
	    "Health monitor detected stalled decision worker %u: TID=%d "
	    "state=%s heartbeat=%s current_event=%s "
	    "queue_depth=%u oldest_queued=%s action=%s "
	    "worker_stall=%lu",
	    worker->id, tid, "stalled", heartbeat, current,
	    metrics->current_depth, oldest,
	    failure_action_name(failure_reason_action(
		    FAILURE_REASON_WORKER_STALL)),
	    total);
	atomic_store_explicit(&run_stats, true, memory_order_relaxed);
	nudge_queue();
}

/*
 * health_monitor_check_workers - check every worker once.
 * @timeout_ns: stall deadline in nanoseconds.
 * Returns 1 when all workers are healthy, 0 when at least one is stalled.
 */
static int health_monitor_check_workers(uint64_t timeout_ns)
{
	unsigned int i;
	uint64_t now = health_now_ns();
	int healthy = 1;

	for (i = 0; i < active_decision_workers; i++) {
		struct decision_worker *worker = &decision_workers[i];
		struct worker_health_snapshot snapshot = { 0 };
		struct queue_metrics metrics;
		int stalled;

		if (worker->queue == NULL)
			continue;

		worker_health_snapshot(worker, &snapshot, now);
		q_metrics_snapshot(worker->queue, &metrics);
		stalled = worker_health_is_stalled(&snapshot, &metrics,
						   timeout_ns);
		if (stalled) {
			healthy = 0;
			health_monitor_log_stall(worker, &snapshot, &metrics);
			failure_action_execute(FAILURE_REASON_WORKER_STALL);
		} else {
			atomic_store_explicit(&worker->stall_reported, false,
					      memory_order_relaxed);
		}
	}

	return healthy;
}

static void *health_monitor_thread_main(void *arg)
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
		uint64_t interval_ns = health_monitor_interval_ns();
		uint64_t timeout_ns = health_stall_timeout_ns();
		int healthy = health_monitor_check_workers(timeout_ns);

		if (healthy && systemd_watchdog_enabled() &&
		    systemd_watchdog_ping()) {
			time_t now = time(NULL);

			if (message_rate_limit_allow(&systemd_watchdog_log, now))
				msg(LOG_WARNING,
				    "Cannot refresh systemd watchdog deadline");
		}
		health_monitor_sleep(interval_ns);
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

/*
 * run_decision_event - execute one policy decision for an event envelope.
 * @worker: decision worker that owns the event and reply fd.
 * @event: event to process.
 *
 * Timing starts only when an event is actually processed. A deferred event
 * keeps its original queue timestamp so queue wait includes time spent parked
 * behind a building subject.
 */
static void run_decision_event(struct decision_worker *worker,
		decision_event_t *event)
{
	attr_lookup_metrics_set_worker(worker->id);
	worker_health_event_begin(worker);
	decision_timing_decision_begin(worker->id);
	decision_timing_queue_dequeued(event->enqueue_ns);
	make_policy_decision(event, fd, mask);
	decision_timing_decision_end();
	worker_health_event_end(worker);
}

/*
 * dispatch_decision_event - process one worker-owned event and release defers.
 * @worker: decision worker that owns the event and reply fd.
 * @event: event envelope from the inter-thread queue.
 * @rpt_is_stale: interval report dirty flag.
 *
 * If another pid owns the same subject slot while its pattern state is still
 * before STATE_FULL, the event is parked in the bounded defer array. When the
 * array is full, processing falls back to the historical eviction behavior so
 * memory and blocked permission events remain bounded.
 */
static void dispatch_decision_event(struct decision_worker *worker,
		decision_event_t *event, int *rpt_is_stale)
{
	struct decision_defer_queue *defer = worker_defer_queue(worker);

	if (event->worker_index == DECISION_EVENT_NO_WORKER)
		event->worker_index = worker->id;
	else if (event->worker_index != worker->id)
		msg(LOG_WARNING,
		    "Decision event worker ownership mismatch: dispatcher "
		    "assigned worker %u but worker %u dequeued PID %d",
		    event->worker_index, worker->id, event->metadata.pid);

	// The wrapper may already carry a slot when it comes from the defer list.
	if (event->subject_slot == DECISION_EVENT_NO_SLOT)
		event->subject_slot = event_subject_slot(event->metadata.pid);

	/*
	 * Park only when another pid owns this subject slot and still needs
	 * its startup pattern state. If the array is full, continue into
	 * normal processing so new_event() applies the historical eviction
	 * behavior.
	 */
	if (event_subject_slot_is_blocked(event->subject_slot,
					  event->metadata.pid)) {
		if (decision_defer_push(defer, event) == 0) {
			*rpt_is_stale = 1;
			return;
		}
		decision_defer_count_fallback(defer);
	}

	for (;;) {
		unsigned int slot;

		/*
		 * Turn one completed subject slot into a chain of policy
		 * decisions. This lets backed-up events for that slot flow
		 * through immediately instead of waiting for the next fanotify
		 * dequeue cycle.
		 *
		 * Process the current event. This may be the original queue
		 * event or a deferred event popped at the bottom of the loop.
		 */
		*rpt_is_stale = 1;
		run_decision_event(worker, event);

		/*
		 * make_policy_decision() sets completed_subject_slot only when
		 * processing leaves a slot empty, STATE_FULL, or later. Without
		 * that signal there is no deferred work that can be unblocked.
		 */
		slot = event->completed_subject_slot;
		if (slot == DECISION_EVENT_NO_SLOT)
			return;
		/*
		 * A deferred event can start building a fresh subject in this
		 * same slot. Stop if it became blocked again. Otherwise pop
		 * the oldest event waiting for this slot and repeat.
		 *
		 * The loop cannot run forever: every iteration either returns
		 * or removes one entry from the fixed-size defer array.
		 */
		if (!event_subject_slot_is_unblocked(slot))
			return;
		if (!decision_defer_pop_slot(defer, slot, event))
			return;
	}
}

/*
 * deferred_event_is_ready - test whether a parked event can run now.
 * @event: deferred event to inspect.
 * @ctx: unused predicate context.
 *
 * Calling event_subject_slot_is_blocked() intentionally reuses the same
 * traced/stale BUILDING eviction check used by fresh events. Without this
 * recheck, a deferred event can wait forever when no later event collides with
 * the same subject slot.
 *
 * Returns 1 when the event can run, 0 when it must remain deferred.
 */
static int deferred_event_is_ready(const decision_event_t *event, void *ctx)
{
	(void)ctx;

	return !event_subject_slot_is_blocked(event->subject_slot,
					      event->metadata.pid);
}

/*
 * release_ready_deferred_events - run deferred events that are unblocked.
 * @rpt_is_stale: interval report dirty flag.
 *
 * Periodic rechecks keep the 10 second BUILDING stale timeout effective even
 * when no new fanotify event arrives for the same subject slot. Each pass pops
 * the oldest ready event and dispatches it through the normal decision path.
 *
 * Returns the number of deferred events released.
 */
static unsigned int release_ready_deferred_events(
		struct decision_worker *worker, int *rpt_is_stale)
{
	struct decision_defer_queue *defer = worker_defer_queue(worker);
	decision_event_t event;
	unsigned int count = 0;

	while (defer->current &&
	       decision_defer_pop_if(defer, deferred_event_is_ready,
				     NULL, &event)) {
		dispatch_decision_event(worker, &event, rpt_is_stale);
		count++;
	}

	if (count)
		msg(LOG_DEBUG, "Released %u deferred fanotify events", count);
	return count;
}

/*
 * shutdown_fallback_decision - get the shutdown reply decision.
 * Returns FAN_ALLOW in permissive mode and FAN_DENY otherwise.
 */
static int shutdown_fallback_decision(void)
{
	if (decision_config_permissive(NULL))
		return FAN_ALLOW;
	return FAN_DENY;
}

/*
 * shutdown_queued_events - reply to every event left in a worker queue.
 * @worker: decision worker whose queue is being drained.
 *
 * A decision worker exits its main loop as soon as stop is observed. Any
 * permission event that reached the worker queue but was not processed yet
 * still owns a live fd and can leave the requesting task blocked. During
 * shutdown, answer those queued events with the same permissive fallback
 * policy used for other bounded failure paths.
 *
 * Returns the number of events answered.
 */
static unsigned int shutdown_queued_events(struct decision_worker *worker)
{
	decision_event_t event;
	unsigned int count = 0;
	int decision = shutdown_fallback_decision();

	if (worker == NULL || worker->queue == NULL)
		return 0;

	while (q_queue_length(worker->queue) > 0) {
		if (q_dequeue(worker->queue, &event) != 1)
			break;
		reply_event(fd, &event.metadata, decision, NULL);
		count++;
	}

	return count;
}

/*
 * shutdown_deferred_events - reply to every event left in the defer array.
 *
 * Deferred fanotify permission events still own live fds. During shutdown each
 * must be answered exactly once, using the same permissive fallback policy as
 * queue-full handling, so the blocked task and descriptor are released.
 *
 * Returns the number of events answered.
 */
static unsigned int shutdown_deferred_events(struct decision_worker *worker)
{
	struct decision_defer_queue *defer = worker_defer_queue(worker);
	decision_event_t event;
	unsigned int count = 0;
	int decision = shutdown_fallback_decision();

	while (decision_defer_pop_any(defer, &event)) {
		reply_event(fd, &event.metadata, decision, NULL);
		count++;
	}

	return count;
}

#ifdef TEST_SUBJECT_DEFER
void test_notify_worker_pool_destroy(void);

/*
 * test_notify_queue_reset - initialize notify.c queue state for unit tests.
 * @entries: fixed queue capacity.
 *
 * Returns 0 on success and -1 on allocation failure.
 */
int test_notify_queue_reset(unsigned int entries)
{
	struct decision_worker *worker = &decision_workers[0];

	if (worker->queue != NULL)
		q_close(worker->queue);
	worker->id = 0;
	worker->context = decision_context_current();
	decision_context_set_worker_id(worker->context, 0);
	atomic_store_explicit(&worker->tid, 0, memory_order_relaxed);
	worker_health_init(worker);
	worker->queue = q_open(entries);
	active_decision_workers = worker->queue ? 1 : 0;
	return worker->queue == NULL ? -1 : 0;
}

/*
 * test_notify_queue_destroy - release notify.c queue state after unit tests.
 * Returns nothing.
 */
void test_notify_queue_destroy(void)
{
	struct decision_worker *worker = &decision_workers[0];

	if (worker->queue == NULL)
		return;
	q_close(worker->queue);
	worker->queue = NULL;
	worker->context = NULL;
	active_decision_workers = 0;
}

/*
 * test_notify_queue_push - enqueue an event in notify.c queue state.
 * @event: event copied into the queue.
 *
 * Returns 0 on success and -1 when the queue rejects the event.
 */
int test_notify_queue_push(const decision_event_t *event)
{
	return q_enqueue(decision_workers[0].queue, event);
}

/*
 * test_notify_shutdown_queued_events - run production queue cleanup.
 * Returns the number of queued events answered.
 */
unsigned int test_notify_shutdown_queued_events(void)
{
	return shutdown_queued_events(&decision_workers[0]);
}

/*
 * test_notify_defer_reset - initialize notify.c defer state for unit tests.
 * @subj_cache_size: subject cache size used to derive defer capacity.
 *
 * Returns 0 on success and -1 on allocation failure.
 */
int test_notify_defer_reset(unsigned int subj_cache_size)
{
	struct decision_worker *worker = &decision_workers[0];
	struct decision_defer_queue *defer;

	worker->id = 0;
	worker->context = decision_context_current();
	decision_context_set_worker_id(worker->context, 0);
	defer = worker_defer_queue(worker);
	decision_defer_destroy(defer);
	return decision_defer_init(defer, subj_cache_size);
}

/*
 * test_notify_defer_destroy - release notify.c defer state after unit tests.
 * Returns nothing.
 */
void test_notify_defer_destroy(void)
{
	struct decision_worker *worker = &decision_workers[0];

	decision_defer_destroy(worker_defer_queue(worker));
	worker->context = NULL;
}

/*
 * test_notify_defer_push - park an event in notify.c defer state.
 * @event: event copied into the defer queue.
 *
 * Returns 0 on success and -1 when the queue rejects the event.
 */
int test_notify_defer_push(const decision_event_t *event)
{
	return decision_defer_push(worker_defer_queue(&decision_workers[0]),
				   event);
}

/*
 * test_notify_shutdown_deferred_events - run production shutdown cleanup.
 * Returns the number of deferred events answered.
 */
unsigned int test_notify_shutdown_deferred_events(void)
{
	return shutdown_deferred_events(&decision_workers[0]);
}

/*
 * test_notify_worker_index - expose stable subject routing for tests.
 * @pid: synthetic fanotify pid.
 * @workers: synthetic active worker count.
 *
 * Returns the worker index selected by the dispatcher key function.
 */
unsigned int test_notify_worker_index(pid_t pid, unsigned int workers)
{
	struct fanotify_event_metadata metadata = {
		.pid = pid,
	};

	return dispatcher_worker_index_from_key(
		dispatcher_subject_key(&metadata), workers);
}

/*
 * test_notify_worker_pool_reset - initialize multiple worker queues for tests.
 * @workers: number of synthetic active workers.
 * @entries: queue capacity per worker.
 *
 * Returns 0 on success and -1 on allocation failure.
 */
int test_notify_worker_pool_reset(unsigned int workers, unsigned int entries)
{
	unsigned int i;

	if (workers == 0 || workers > DECISION_WORKER_MAX) {
		errno = EINVAL;
		return -1;
	}

	for (i = 0; i < DECISION_WORKER_MAX; i++) {
		if (decision_workers[i].queue) {
			q_close(decision_workers[i].queue);
			decision_workers[i].queue = NULL;
		}
		decision_workers[i].context = NULL;
	}
	active_decision_workers = 0;

	for (i = 0; i < workers; i++) {
		decision_workers[i].id = i;
		decision_workers[i].context = decision_context_current();
		decision_context_set_worker_id(decision_workers[i].context, i);
		atomic_store_explicit(&decision_workers[i].tid, 0,
				      memory_order_relaxed);
		worker_health_init(&decision_workers[i]);
		decision_workers[i].queue = q_open(entries);
		if (decision_workers[i].queue == NULL) {
			test_notify_worker_pool_destroy();
			return -1;
		}
	}
	active_decision_workers = workers;
	decision_timing_set_active_workers(workers);
	return 0;
}

/*
 * test_notify_worker_pool_destroy - release synthetic worker queues.
 * Returns nothing.
 */
void test_notify_worker_pool_destroy(void)
{
	unsigned int i;

	for (i = 0; i < DECISION_WORKER_MAX; i++) {
		if (decision_workers[i].queue) {
			q_close(decision_workers[i].queue);
			decision_workers[i].queue = NULL;
		}
		decision_workers[i].context = NULL;
	}
	active_decision_workers = 0;
	decision_timing_set_active_workers(0);
}

/*
 * test_notify_enqueue_pid_fd - route one synthetic event through dispatcher.
 * @pid: synthetic fanotify pid.
 * @event_fd: marker stored in metadata.fd for ordering assertions.
 *
 * Returns 0 on successful enqueue and -1 on dispatcher/queue failure.
 */
int test_notify_enqueue_pid_fd(pid_t pid, int event_fd)
{
	struct fanotify_event_metadata metadata = {
		.fd = event_fd,
		.pid = pid,
		.mask = FAN_OPEN_PERM,
	};

	return dispatcher_enqueue_permission_event(&metadata, NULL);
}

/*
 * test_notify_worker_queue_depth - return synthetic worker queue depth.
 * @worker_id: worker queue to inspect.
 *
 * Returns the current queue depth, or UINT_MAX when @worker_id is invalid.
 */
unsigned int test_notify_worker_queue_depth(unsigned int worker_id)
{
	if (worker_id >= active_decision_workers ||
	    decision_workers[worker_id].queue == NULL)
		return UINT_MAX;

	return q_queue_length(decision_workers[worker_id].queue);
}

/*
 * test_notify_worker_drain - drain one synthetic worker queue.
 * @worker_id: worker queue to drain.
 * @pids: optional destination for dequeued pids.
 * @fds: optional destination for dequeued metadata fd markers.
 * @max: maximum entries available in @pids and @fds.
 *
 * Returns the number of events drained.
 */
unsigned int test_notify_worker_drain(unsigned int worker_id, pid_t *pids,
		int *fds, unsigned int max)
{
	decision_event_t event;
	unsigned int count = 0;
	struct queue *queue;

	if (worker_id >= active_decision_workers)
		return 0;
	queue = decision_workers[worker_id].queue;
	if (queue == NULL)
		return 0;

	while (count < max && q_queue_length(queue) > 0) {
		if (q_dequeue(queue, &event) != 1)
			break;
		if (pids)
			pids[count] = event.metadata.pid;
		if (fds)
			fds[count] = event.metadata.fd;
		count++;
	}

	return count;
}
#endif

static void *decision_worker_main(void *arg)
{
	struct decision_worker *worker = arg;
	sigset_t sigs;
	int owns_reports = worker_owns_reports(worker);

	/* This is a worker thread. Don't handle external signals. */
	sigemptyset(&sigs);
	sigaddset(&sigs, SIGTERM);
	sigaddset(&sigs, SIGHUP);
	sigaddset(&sigs, SIGUSR1);
	sigaddset(&sigs, SIGINT);
	sigaddset(&sigs, SIGQUIT);
	pthread_sigmask(SIG_SETMASK, &sigs, NULL);

	if (worker == NULL || worker->queue == NULL ||
	    worker->context == NULL)
		return NULL;
	atomic_store_explicit(&worker->tid, (int)syscall(SYS_gettid),
			      memory_order_relaxed);
	worker_health_heartbeat(worker);
	/*
	 * The decision path uses decision_context_current() in cache, file, and
	 * policy helpers. Bind this thread before any event or report work so
	 * all mutable state stays private to this worker.
	 */
	decision_context_set_current(worker->context);

	// interval reporting state
	int rpt_is_stale = 0;
	struct timespec rpt_timeout;

	// if an interval was configured, reports are enabled
	if (owns_reports && rpt_interval)
		rpt_init(&rpt_timeout);

	// start with a fresh report
	if (owns_reports)
		atomic_store_explicit(&run_stats, true, memory_order_relaxed);

	while (!stop) {
		int rc;
		decision_event_t event;

		/*
		 * Apply asynchronous timing-control work on the decision
		 * worker. SIGUSR1 handlers and overflow detection only set
		 * atomic request flags; this call starts/stops manual timing,
		 * restores queue-depth accounting, and writes any required
		 * timing report outside signal context.
		 */
		decision_timing_process_requests(&config);

		// if an interval has been configured
			if (owns_reports && rpt_interval) {
				errno = 0;
				rc = q_timed_dequeue(worker->queue, &event,
						     &rpt_timeout);
				if (rc == 0) {
					uint64_t expired = 0;

					worker_health_heartbeat(worker);
					// check for timer expirations
					if (errno == ETIMEDOUT) {
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
				}
				// timer expired or stats explicitly requested
				if (expired || atomic_load_explicit(&run_stats,
							memory_order_relaxed)) {
					bool stats_requested =
						atomic_exchange_explicit(
							&run_stats, false,
							memory_order_relaxed);
					// write a new report only when one of
					// 1. new events seen since last report
					// 2. explicitly requested w/run_stats
					if (rpt_is_stale || stats_requested) {
						state_report_write(
						    state_report_reason_for_triggers(
							expired));
						rpt_is_stale = 0;
					}
					// adjust the timed dequeue timeout to
					// a full interval from now
					if (clock_gettime(CLOCK_REALTIME,
							&rpt_timeout)) {
						// gettime errors are
						// unrecoverable
						rpt_disable("clock failure");
						continue;
					}
					rpt_timeout.tv_sec += rpt_interval;
				}
				continue;
			}
			if (rc < 0)
				continue;
			} else {
				int timed_for_defer = 0;
				struct timespec timeout;
				unsigned int timeout_sec =
					HEALTH_MONITOR_INTERVAL_SEC;

				if (worker->context->defer_queue.current)
					timeout_sec = DEFER_RECHECK_INTERVAL_SEC;
				if (clock_gettime(CLOCK_REALTIME, &timeout) == 0) {
					timeout.tv_sec += timeout_sec;
					errno = 0;
					rc = q_timed_dequeue(worker->queue, &event,
							     &timeout);
					timed_for_defer =
						worker->context->defer_queue.current != 0;
				} else {
					rc = q_dequeue(worker->queue, &event);
				}
				if (rc == 0) {
					worker_health_heartbeat(worker);
					if (owns_reports &&
					    atomic_exchange_explicit(&run_stats, false,
								    memory_order_relaxed)) {
					state_report_write(STATE_REPORT_SIGNAL);
				}
				if (timed_for_defer && errno == ETIMEDOUT)
					release_ready_deferred_events(
						worker, &rpt_is_stale);
				continue;
			}
			if (rc < 0)
				continue;
			if (owns_reports &&
			    atomic_exchange_explicit(&run_stats, false,
						    memory_order_relaxed)) {
				state_report_write(STATE_REPORT_SIGNAL);
			}
		}

		dispatch_decision_event(worker, &event, &rpt_is_stale);
	}
	unsigned int queued = shutdown_queued_events(worker);
	unsigned int deferred = shutdown_deferred_events(worker);

	if (queued || deferred)
		msg(LOG_INFO,
		    "Replied to %u queued and %u deferred fanotify events during shutdown",
		    queued, deferred);
	msg(LOG_DEBUG,
	    "Decision worker %u shutdown backlog: queued=%u deferred=%u",
	    worker->id, queued, deferred);
	msg(LOG_DEBUG, "Exiting decision worker %u", worker->id);
	decision_context_set_current(NULL);
	return NULL;
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
				if (metadata->pid == our_pid)
					reply_event(fd, metadata, FAN_ALLOW,
						    NULL);
				else {
					unsigned int worker_index =
						DECISION_EVENT_NO_WORKER;

					if (dispatcher_enqueue_permission_event(
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
