/*
 * notify_test.c - unit tests for daemon fanotify metadata handling
 */
#include "config.h"
#include <error.h>
#include <errno.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/fanotify.h>
#include <unistd.h>

#include "failure-action.h"
#include "fanotify-fs-error.h"
#include "notify.h"
#include "policy.h"
#include "decision-config.h"
#include "decision-defer.h"
#include "decision-timing.h"
#include "state-report.h"

#ifndef FAN_Q_OVERFLOW
#define FAN_Q_OVERFLOW		0x00004000
#endif

#if defined(FAPOLICYD_ENABLE_FANOTIFY_FS_ERROR) && \
	defined(FAN_FS_ERROR) && defined(FAN_REPORT_FID) && \
	defined(FAN_MARK_FILESYSTEM) && \
	defined(FAN_EVENT_INFO_TYPE_ERROR) && \
	defined(FAN_EVENT_INFO_TYPE_FID)
#define TEST_HAVE_FAN_FS_ERROR 1

struct test_fanotify_fs_error_info {
	struct fanotify_event_info_header hdr;
	int32_t error;
	uint32_t error_count;
};
#else
#define TEST_HAVE_FAN_FS_ERROR 0
#endif

extern atomic_bool run_stats;
extern atomic_uint signal_report_requests;
extern conf_t config;

int test_notify_queue_reset(unsigned int entries);
void test_notify_queue_destroy(void);
int test_notify_queue_push(const decision_event_t *event);
unsigned int test_notify_shutdown_queued_events(void);
int test_notify_defer_reset(unsigned int subj_cache_size);
void test_notify_defer_destroy(void);
int test_notify_defer_push(const decision_event_t *event);
unsigned int test_notify_shutdown_deferred_events(void);
unsigned int test_notify_worker_index(pid_t pid, unsigned int workers);
int test_notify_worker_pool_reset(unsigned int workers, unsigned int entries);
void test_notify_worker_pool_destroy(void);
int test_notify_enqueue_pid_fd(pid_t pid, int event_fd);
unsigned int test_notify_worker_queue_depth(unsigned int worker_id);
unsigned int test_notify_worker_drain(unsigned int worker_id, pid_t *pids,
		int *fds, unsigned int max);

#define CHECK(expr, code, msg) \
	do { \
		if (!(expr)) \
			error(1, 0, "%s", msg); \
	} while (0)

void do_stat_report_reset(FILE *f, int shutdown, int reset)
{
	(void)f;
	(void)shutdown;
	(void)reset;
}

void do_state_report(FILE *f, int shutdown)
{
	(void)f;
	(void)shutdown;
}

void do_metrics_report_reset(FILE *f, int reset)
{
	(void)f;
	(void)reset;
}

/*
 * read_decision_report - capture decision_report output for assertions.
 * @buf: destination buffer.
 * @size: size of @buf.
 * Returns nothing. Exits if the temporary stream cannot be used.
 */
static void read_decision_report(char *buf, size_t size, int reset)
{
	FILE *f = tmpfile();
	size_t used;

	if (f == NULL)
		error(1, 0, "tmpfile failed");

	decision_report_reset(f, reset);
	fflush(f);
	rewind(f);
	used = fread(buf, 1, size - 1, f);
	buf[used] = 0;
	fclose(f);
}

/*
 * read_decision_metrics_report - capture metrics decision header output.
 * @buf: destination buffer.
 * @size: size of @buf.
 * Returns nothing. Exits if the temporary stream cannot be used.
 */
static void read_decision_metrics_report(char *buf, size_t size)
{
	FILE *f = tmpfile();
	size_t used;

	if (f == NULL)
		error(1, 0, "tmpfile failed");

	decision_report_metrics_reset(f, 0);
	fflush(f);
	rewind(f);
	used = fread(buf, 1, size - 1, f);
	buf[used] = 0;
	fclose(f);
}

/*
 * read_fanotify_queue_report - capture fanotify queue metrics output.
 * @buf: destination buffer.
 * @size: size of @buf.
 * @reset: non-zero resets interval queue counters.
 * Returns nothing. Exits if the temporary stream cannot be used.
 */
static void read_fanotify_queue_report(char *buf, size_t size, int reset)
{
	FILE *f = tmpfile();
	size_t used;

	if (f == NULL)
		error(1, 0, "tmpfile failed");

	fanotify_queue_report_reset(f, reset);
	fflush(f);
	rewind(f);
	used = fread(buf, 1, size - 1, f);
	buf[used] = 0;
	fclose(f);
}

/*
 * read_operating_mode_report - capture the state operating mode section.
 * @buf: destination buffer.
 * @size: size of @buf.
 * Returns nothing. Exits if the temporary stream cannot be used.
 */
static void read_operating_mode_report(char *buf, size_t size)
{
	struct state_report_operating_mode mode = {
		.permissive = false,
		.integrity = "sha256",
		.reset_strategy = "manual",
		.config_generation = 5,
		.ruleset_generation = 7,
		.config_effective_since = 1,
		.ruleset_effective_since = 1,
		.trust_db = {
			.generation = 9,
			.entries = 11,
			.publish_time = 1,
			.lmdb_generation = 3,
			.lmdb_publish_time = 1,
		},
		.config = &config,
	};
	FILE *f = tmpfile();
	size_t used;

	if (f == NULL)
		error(1, 0, "tmpfile failed");

	config.timing_collection = TIMING_COLLECTION_MANUAL;
	state_report_operating_mode(f, &mode);
	fflush(f);
	rewind(f);
	used = fread(buf, 1, size - 1, f);
	buf[used] = 0;
	fclose(f);
}

#if TEST_HAVE_FAN_FS_ERROR
/*
 * read_fs_error_report - capture recent FAN_FS_ERROR detail output.
 * @buf: destination buffer.
 * @size: size of @buf.
 * Returns nothing. Exits if the temporary stream cannot be used.
 */
static void read_fs_error_report(char *buf, size_t size)
{
	FILE *f = tmpfile();
	size_t used;

	if (f == NULL)
		error(1, 0, "tmpfile failed");

	fanotify_fs_error_report(f);
	fflush(f);
	rewind(f);
	used = fread(buf, 1, size - 1, f);
	buf[used] = 0;
	fclose(f);
}
#endif

/*
 * test_operating_mode_report_order - verify state field order.
 *
 * Config generation and ruleset generation are adjacent so readers can see the
 * decision configuration identity beside the active policy identity.
 *
 * Returns nothing. Exits on test failure.
 */
static void test_operating_mode_report_order(void)
{
	const char *config_generation, *ruleset, *trust_db, *lmdb_env;
	const char *timing_mode;
	char report[1024];

	read_operating_mode_report(report, sizeof(report));
	config_generation = strstr(report,
				   "Config generation: 5 "
				   "(effective since ");
	ruleset = strstr(report,
			 "Ruleset generation: 7 "
			 "(effective since ");
	trust_db = strstr(report,
			  "Trust database generation: 9 "
			  "(effective since ");
	lmdb_env = strstr(report,
			  "LMDB environment generation: 3 "
			  "(effective since ");
	timing_mode = strstr(report, "Timing collection mode: manual\n");
	CHECK(config_generation != NULL, 68,
	      "[ERROR:68] operating mode report missing config generation");
	CHECK(ruleset != NULL, 59,
	      "[ERROR:59] operating mode report missing ruleset field");
	CHECK(trust_db != NULL, 69,
	      "[ERROR:69] operating mode report missing trust DB generation");
	CHECK(lmdb_env != NULL, 71,
	      "[ERROR:71] operating mode report missing LMDB generation");
	CHECK(strstr(report, "Trust database entries: 11\n") != NULL, 70,
	      "[ERROR:70] operating mode report missing trust DB entries");
	CHECK(timing_mode != NULL, 58,
	      "[ERROR:58] operating mode report missing timing mode field");
	CHECK(config_generation < ruleset && ruleset < trust_db &&
	      trust_db < lmdb_env && lmdb_env < timing_mode, 60,
	      "[ERROR:60] generation fields were not grouped");
}

/*
 * test_shutdown_deferred_events - verify notify shutdown replies once.
 *
 * Deferred permission events own their metadata fd until shutdown cleanup
 * replies and closes it. Use pipe read ends as stand-ins for fanotify fds so
 * the test can prove the production cleanup path closes each one exactly once.
 *
 * Returns nothing. Exits on test failure.
 */
static void test_shutdown_deferred_events(void)
{
	decision_event_t event;
	int pipes[3][2];
	unsigned int i;

	CHECK(test_notify_defer_reset(1) == 0, 40,
	      "[ERROR:40] notify defer reset failed");

	for (i = 0; i < 3; i++) {
		CHECK(pipe(pipes[i]) == 0, 41,
		      "[ERROR:41] pipe setup failed");
		memset(&event, 0, sizeof(event));
		event.metadata.fd = pipes[i][0];
		event.metadata.pid = 500 + i;
		event.metadata.mask = FAN_OPEN_PERM;
		event.subject_slot = i;
		event.completed_subject_slot = DECISION_EVENT_NO_SLOT;
		CHECK(test_notify_defer_push(&event) == 0, 42,
		      "[ERROR:42] notify defer push failed");
	}

	__atomic_store_n(&config.permissive, true, __ATOMIC_RELAXED);
	CHECK(decision_config_publish(&config) == 0, 66,
	      "[ERROR:66] decision config publish failed");
	CHECK(test_notify_shutdown_deferred_events() == 3, 61,
	      "[ERROR:61] deferred shutdown count mismatch");
	__atomic_store_n(&config.permissive, false, __ATOMIC_RELAXED);
	CHECK(decision_config_publish(&config) == 0, 69,
	      "[ERROR:69] decision config reset failed");
	decision_config_destroy();

	for (i = 0; i < 3; i++) {
		errno = 0;
		CHECK(close(pipes[i][0]) == -1 && errno == EBADF, 43,
		      "[ERROR:43] deferred fd was not closed exactly once");
		close(pipes[i][1]);
	}

	test_notify_defer_destroy();
}

/*
 * test_shutdown_queued_events - verify notify shutdown drains queue fds.
 *
 * The decision worker can observe stop before it processes every event already
 * accepted from fanotify. Those queued permission events must still be answered
 * during shutdown or their requesting tasks can remain blocked.
 *
 * Returns nothing. Exits on test failure.
 */
static void test_shutdown_queued_events(void)
{
	decision_event_t event;
	int pipes[3][2];
	unsigned int i;

	CHECK(test_notify_queue_reset(4) == 0, 62,
	      "[ERROR:62] notify queue reset failed");

	for (i = 0; i < 3; i++) {
		CHECK(pipe(pipes[i]) == 0, 63,
		      "[ERROR:63] queue pipe setup failed");
		memset(&event, 0, sizeof(event));
		event.metadata.fd = pipes[i][0];
		event.metadata.pid = 600 + i;
		event.metadata.mask = FAN_OPEN_PERM;
		event.subject_slot = i;
		event.completed_subject_slot = DECISION_EVENT_NO_SLOT;
		CHECK(test_notify_queue_push(&event) == 0, 64,
		      "[ERROR:64] notify queue push failed");
	}

	__atomic_store_n(&config.permissive, true, __ATOMIC_RELAXED);
	CHECK(decision_config_publish(&config) == 0, 67,
	      "[ERROR:67] decision config publish failed");
	CHECK(test_notify_shutdown_queued_events() == 3, 65,
	      "[ERROR:65] queued shutdown count mismatch");
	__atomic_store_n(&config.permissive, false, __ATOMIC_RELAXED);
	CHECK(decision_config_publish(&config) == 0, 70,
	      "[ERROR:70] decision config reset failed");
	decision_config_destroy();

	for (i = 0; i < 3; i++) {
		errno = 0;
		CHECK(close(pipes[i][0]) == -1 && errno == EBADF, 71,
		      "[ERROR:71] queued fd was not closed exactly once");
		close(pipes[i][1]);
	}

	test_notify_queue_destroy();
}

/*
 * test_dispatcher_worker_routing - verify stable subject worker selection.
 *
 * The dispatcher must not choose workers by queue pressure or round-robin:
 * all events with the same subject key need the same decision owner so the
 * subject cache sees an ordered startup sequence.
 *
 * Returns nothing. Exits on test failure.
 */
static void test_dispatcher_worker_routing(void)
{
	CHECK(test_notify_worker_index(1001, 4) == 1, 77,
	      "[ERROR:77] pid routing did not use stable modulo key");
	CHECK(test_notify_worker_index(1001, 4) ==
	      test_notify_worker_index(1001, 4), 78,
	      "[ERROR:78] same pid did not route to same worker");
	CHECK(test_notify_worker_index(1002, 4) == 2, 79,
	      "[ERROR:79] adjacent pid routing mismatch");
	CHECK(test_notify_worker_index(-1, 4) == 0, 80,
	      "[ERROR:80] invalid pid did not use fallback key");
	CHECK(test_notify_worker_index(1001, 0) == 0, 81,
	      "[ERROR:81] zero worker fallback changed");
}

/*
 * test_dispatcher_same_pid_ordering - verify FIFO ownership for one pid.
 *
 * Same-pid fanotify events must enter the same worker queue in arrival order
 * so the subject startup state machine sees a coherent sequence.
 *
 * Returns nothing. Exits on test failure.
 */
static void test_dispatcher_same_pid_ordering(void)
{
	pid_t pids[4];
	int fds[4];
	unsigned int worker;

	CHECK(test_notify_worker_pool_reset(4, 8) == 0, 91,
	      "[ERROR:91] worker pool reset failed");
	CHECK(fanotify_active_worker_count() == 4, 92,
	      "[ERROR:92] active worker count mismatch");

	worker = test_notify_worker_index(1001, 4);
	CHECK(test_notify_enqueue_pid_fd(1001, 10) == 0, 93,
	      "[ERROR:93] first same-pid enqueue failed");
	CHECK(test_notify_enqueue_pid_fd(1001, 11) == 0, 94,
	      "[ERROR:94] second same-pid enqueue failed");
	CHECK(test_notify_enqueue_pid_fd(1001, 12) == 0, 95,
	      "[ERROR:95] third same-pid enqueue failed");
	CHECK(test_notify_worker_queue_depth(worker) == 3, 96,
	      "[ERROR:96] same-pid events did not share one queue");
	CHECK(test_notify_worker_drain(worker, pids, fds, 4) == 3, 97,
	      "[ERROR:97] same-pid drain count mismatch");
	CHECK(pids[0] == 1001 && pids[1] == 1001 && pids[2] == 1001,
	      98, "[ERROR:98] drained pid changed");
	CHECK(fds[0] == 10 && fds[1] == 11 && fds[2] == 12, 99,
	      "[ERROR:99] same-pid queue order changed");

	test_notify_worker_pool_destroy();
}

/*
 * test_dispatcher_pid_reuse_stability - verify reused pid routing stability.
 *
 * Numeric PID reuse is still handled by the subject fingerprint inside the
 * owning worker. Routing must not send the reused numeric PID to a different
 * worker, or stale/startup state could be split across caches.
 *
 * Returns nothing. Exits on test failure.
 */
static void test_dispatcher_pid_reuse_stability(void)
{
	pid_t pids[4];
	int fds[4];
	unsigned int worker;

	CHECK(test_notify_worker_pool_reset(4, 8) == 0, 100,
	      "[ERROR:100] worker pool reset failed for pid reuse");
	worker = test_notify_worker_index(2209, 4);
	CHECK(test_notify_enqueue_pid_fd(2209, 20) == 0, 101,
	      "[ERROR:101] first reused-pid enqueue failed");
	CHECK(test_notify_enqueue_pid_fd(2210, 30) == 0, 102,
	      "[ERROR:102] adjacent pid enqueue failed");
	CHECK(test_notify_enqueue_pid_fd(2209, 21) == 0, 103,
	      "[ERROR:103] second reused-pid enqueue failed");

	CHECK(test_notify_worker_drain(worker, pids, fds, 4) == 2, 104,
	      "[ERROR:104] reused-pid owner queue count mismatch");
	CHECK(pids[0] == 2209 && pids[1] == 2209, 105,
	      "[ERROR:105] reused pid did not stay on owner queue");
	CHECK(fds[0] == 20 && fds[1] == 21, 106,
	      "[ERROR:106] reused-pid queue order changed");

	test_notify_worker_pool_destroy();
}

/*
 * test_dispatcher_worker_skew - verify hot PID buckets remain observable.
 *
 * Stable pid modulo routing can skew traffic. The dispatcher must expose that
 * pressure through per-worker queue metrics instead of rebalancing same-pid
 * events onto other workers.
 *
 * Returns nothing. Exits on test failure.
 */
static void test_dispatcher_worker_skew(void)
{
	char report[4096];

	CHECK(test_notify_worker_pool_reset(4, 8) == 0, 107,
	      "[ERROR:107] worker pool reset failed for skew");
	CHECK(test_notify_enqueue_pid_fd(1000, 40) == 0, 108,
	      "[ERROR:108] skew enqueue 1 failed");
	CHECK(test_notify_enqueue_pid_fd(1004, 41) == 0, 109,
	      "[ERROR:109] skew enqueue 2 failed");
	CHECK(test_notify_enqueue_pid_fd(1008, 42) == 0, 110,
	      "[ERROR:110] skew enqueue 3 failed");
	CHECK(test_notify_enqueue_pid_fd(1012, 43) == 0, 111,
	      "[ERROR:111] skew enqueue 4 failed");

	CHECK(test_notify_worker_queue_depth(0) == 4, 112,
	      "[ERROR:112] hot pid bucket did not stay on worker 0");
	CHECK(test_notify_worker_queue_depth(1) == 0 &&
	      test_notify_worker_queue_depth(2) == 0 &&
	      test_notify_worker_queue_depth(3) == 0, 113,
	      "[ERROR:113] skew was rebalanced across workers");

	read_fanotify_queue_report(report, sizeof(report), 0);
	CHECK(strstr(report,
		     "Decision worker 0 current queue depth: 4\n") != NULL,
	      114, "[ERROR:114] skew report missing hot worker depth");
	CHECK(strstr(report,
		     "Decision worker 1 current queue depth: 0\n") != NULL,
	      115, "[ERROR:115] skew report missing idle worker depth");

	test_notify_worker_pool_destroy();
}

/*
 * test_notify_queue_report_reset - verify per-worker queue metrics reset.
 *
 * Worker queues own their metrics independently. A metrics reset must clear
 * the full counter for the queue that reported it while preserving the live
 * depth state for future reports.
 *
 * Returns nothing. Exits on test failure.
 */
static void test_notify_queue_report_reset(void)
{
	decision_event_t event = { 0 };
	char report[2048];

	CHECK(test_notify_queue_reset(1) == 0, 82,
	      "[ERROR:82] notify queue reset failed for metrics");
	CHECK(test_notify_queue_push(&event) == 0, 83,
	      "[ERROR:83] queue metrics push failed");
	errno = 0;
	CHECK(test_notify_queue_push(&event) == -1 && errno == ENOSPC, 84,
	      "[ERROR:84] full queue did not reject metrics push");

	read_fanotify_queue_report(report, sizeof(report), 1);
	CHECK(strstr(report, "Inter-thread current queue depth: 1\n") != NULL,
	      85, "[ERROR:85] aggregate queue depth missing");
	CHECK(strstr(report,
		     "Decision worker 0 current queue depth: 1\n") != NULL,
	      86, "[ERROR:86] worker current depth missing");
	CHECK(strstr(report,
		     "Decision worker 0 max queue depth: 1\n") != NULL,
	      87, "[ERROR:87] worker max depth missing");
	CHECK(strstr(report,
		     "Decision worker 0 queue full count: 1\n") != NULL,
	      88, "[ERROR:88] worker full count missing before reset");
	CHECK(strstr(report,
		     "Decision worker 0 oldest queued age: ") != NULL,
	      89, "[ERROR:89] worker oldest age missing");

	read_fanotify_queue_report(report, sizeof(report), 0);
	CHECK(strstr(report,
		     "Decision worker 0 queue full count: 0\n") != NULL,
	      90, "[ERROR:90] worker full count did not reset");

	test_notify_queue_destroy();
}

/*
 * main - exercise synthetic FAN_NOFD kernel metadata.
 * Returns 0 on success. Exits with error() on test failure.
 */
int main(void)
{
	struct fanotify_event_metadata metadata = {
		.event_len = sizeof(metadata),
		.vers = FANOTIFY_METADATA_VERSION,
		.fd = FAN_NOFD,
		.pid = 0,
	};
	unsigned long before, after;
	unsigned long overflow_after, reply_after;
#if TEST_HAVE_FAN_FS_ERROR
	unsigned long fs_error_after = 0;
#endif
	char report[4096], expected[128];
	int event_pipe[2];

	test_operating_mode_report_order();
	test_dispatcher_worker_routing();
	test_dispatcher_same_pid_ordering();
	test_dispatcher_pid_reuse_stability();
	test_dispatcher_worker_skew();
	test_notify_queue_report_reset();

	before = getKernelQueueOverflow();
	metadata.mask = 0;
	// A FAN_NOFD event without FAN_Q_OVERFLOW is not a kernel event.
	CHECK(handle_kernel_event(&metadata) == 0, 1,
	      "[ERROR:1] non-overflow FAN_NOFD event was consumed");
	// Ignoring a non-overflow FAN_NOFD event must not change metrics.
	CHECK(getKernelQueueOverflow() == before, 2,
	      "[ERROR:2] non-overflow event changed overflow count");
	CHECK(failure_action_count(FAILURE_REASON_KERNEL_QUEUE_OVERFLOW) ==
	      before, 3, "[ERROR:3] non-overflow event changed failure count");

	atomic_store(&run_stats, false);
	metadata.mask = FAN_Q_OVERFLOW;
	// FAN_Q_OVERFLOW should be consumed as a kernel queue failure.
	CHECK(handle_kernel_event(&metadata) == 1, 4,
	      "[ERROR:4] FAN_Q_OVERFLOW event was not consumed");

	after = getKernelQueueOverflow();
	overflow_after = after;
	// Consuming FAN_Q_OVERFLOW should increment the overflow counter once.
	CHECK(after == before + 1, 5,
	      "[ERROR:5] FAN_Q_OVERFLOW did not increment count");
	CHECK(failure_action_count(FAILURE_REASON_KERNEL_QUEUE_OVERFLOW) ==
	      after, 6, "[ERROR:6] FAN_Q_OVERFLOW failure count mismatch");
	// Queue overflow should request the configured failure action.
	CHECK(atomic_load(&run_stats), 7,
	      "[ERROR:7] FAN_Q_OVERFLOW did not trigger failure action");

	read_decision_report(report, sizeof(report), 0);
	snprintf(expected, sizeof(expected), "Kernel Queue Overflow: %lu",
		 after);
	// The status report should expose the overflow counter value.
	CHECK(strstr(report, expected) != NULL, 8,
	      "[ERROR:8] status report missing Kernel Queue Overflow");
	snprintf(expected, sizeof(expected),
		 "Failure action kernel_queue_overflow (observe): %lu", after);
	CHECK(strstr(report, expected) != NULL, 9,
	      "[ERROR:9] status report missing kernel overflow failure count");

#if TEST_HAVE_FAN_FS_ERROR
	{
		struct {
			struct fanotify_event_metadata metadata;
			struct test_fanotify_fs_error_info error;
		} fs_error_event;

		memset(&fs_error_event, 0, sizeof(fs_error_event));
		fs_error_event.metadata.event_len =
			sizeof(fs_error_event.metadata) +
			sizeof(fs_error_event.error);
		fs_error_event.metadata.vers = FANOTIFY_METADATA_VERSION;
		fs_error_event.metadata.metadata_len =
			sizeof(fs_error_event.metadata);
		fs_error_event.metadata.fd = FAN_NOFD;
		fs_error_event.metadata.pid = 5678;
		fs_error_event.metadata.mask = FAN_FS_ERROR;
		fs_error_event.error.hdr.info_type =
			FAN_EVENT_INFO_TYPE_ERROR;
		fs_error_event.error.hdr.len = sizeof(fs_error_event.error);
		fs_error_event.error.error = EIO;
		fs_error_event.error.error_count = 3;

		before = getFanotifyFilesystemErrors();
		atomic_store(&run_stats, false);
		CHECK(fanotify_fs_error_handle_event(
		      &fs_error_event.metadata) == 1, 46,
		      "[ERROR:46] FAN_FS_ERROR event was not consumed");
		after = getFanotifyFilesystemErrors();
		fs_error_after = after;
		CHECK(after == before + 1, 47,
		      "[ERROR:47] FAN_FS_ERROR did not increment count");
		CHECK(failure_action_count(
		      FAILURE_REASON_FANOTIFY_FS_ERROR) == after, 48,
		      "[ERROR:48] FAN_FS_ERROR failure count mismatch");
		CHECK(atomic_load(&run_stats), 49,
		      "[ERROR:49] FAN_FS_ERROR did not trigger failure action");

		read_decision_report(report, sizeof(report), 0);
		snprintf(expected, sizeof(expected),
			 "Filesystem Errors: %lu", after);
		CHECK(strstr(report, expected) != NULL, 50,
		      "[ERROR:50] status report missing Filesystem Errors");
		snprintf(expected, sizeof(expected),
			 "Failure action fanotify_filesystem_error "
			 "(observe): %lu", after);
		CHECK(strstr(report, expected) != NULL, 51,
		      "[ERROR:51] status report missing FS error failure");

		read_fs_error_report(report, sizeof(report));
		CHECK(strstr(report, "Filesystem error last status: ok") != NULL,
		      52, "[ERROR:52] FS error status missing");
		CHECK(strstr(report, "Filesystem error last errno: 5") != NULL,
		      53, "[ERROR:53] FS error errno missing");
		CHECK(strstr(report,
			     "Filesystem error last suppressed count: 3")
		      != NULL, 54,
		      "[ERROR:54] FS error suppressed count missing");
	}
#endif

	// Use a real event fd so reply_event can prove it still closes once.
	CHECK(pipe(event_pipe) == 0, 10, "[ERROR:10] pipe failed");
	metadata.fd = event_pipe[0];
	metadata.pid = 1234;
	metadata.mask = FAN_OPEN_PERM;
	before = getReplyErrors();

	reply_event(-1, &metadata, FAN_ALLOW, NULL);
	after = getReplyErrors();
	reply_after = after;
	// A failed fanotify response write should increment reply_errors once.
	CHECK(after == before + 1, 11,
	      "[ERROR:11] reply_event did not count EBADF write failure");
	CHECK(failure_action_count(FAILURE_REASON_RESPONSE_WRITE_FAILURE) ==
	      after, 12, "[ERROR:12] response failure count mismatch");

	errno = 0;
	// reply_event should close the event fd even when the response fails.
	CHECK(close(event_pipe[0]) == -1 && errno == EBADF, 13,
	      "[ERROR:13] reply_event did not close event fd");
	close(event_pipe[1]);

	read_decision_report(report, sizeof(report), 0);
	snprintf(expected, sizeof(expected), "Reply Errors: %lu", after);
	// The status report should expose the aggregate reply_errors value.
	CHECK(strstr(report, expected) != NULL, 14,
	      "[ERROR:14] status report missing Reply Errors count");
	snprintf(expected, sizeof(expected),
		 "Failure action response_write_failure (observe): %lu", after);
	CHECK(strstr(report, expected) != NULL, 15,
	      "[ERROR:15] status report missing response failure count");
	CHECK(strstr(report, "Failure action queue_full (observe): ") != NULL,
	      16, "[ERROR:16] status report missing queue full failure count");
	CHECK(strstr(report, "Failure action worker_stall (observe): ") != NULL,
	      17, "[ERROR:17] status report missing worker stall failure count");
	CHECK(strstr(report, "Failure action rule_reload_failure (observe): ")
	      != NULL, 18,
	      "[ERROR:18] status report missing rule reload failure count");
	CHECK(strstr(report, "Failure action trust_reload_failure (observe): ")
	      != NULL, 19,
	      "[ERROR:19] status report missing trust reload failure count");
	CHECK(strstr(report,
		     "Failure action fanotify_filesystem_error (observe): ")
	      != NULL, 55,
	      "[ERROR:55] status report missing fs error failure count");
	CHECK(strstr(report, "Allowed by rule: ") != NULL, 20,
	      "[ERROR:20] status report missing rule allow count");
	CHECK(strstr(report, "Allowed by fallthrough: ") != NULL, 21,
	      "[ERROR:21] status report missing fallthrough allow count");
	CHECK(strstr(report, "Allowed by fallthrough executable: ") == NULL, 22,
	      "[ERROR:22] zero fallthrough report included ftype detail");
	CHECK(strstr(report, "Ruleset generation: ") != NULL, 23,
	      "[ERROR:23] status report missing ruleset generation");

	read_decision_metrics_report(report, sizeof(report));
	const char *metrics_reset = strstr(report, "Last metrics reset: never\n");
	const char *metrics_config = strstr(report,
					    "Config generation: 0 "
					    "(effective since ");
	const char *metrics_ruleset = strstr(report, "Ruleset generation: ");

	CHECK(metrics_reset != NULL, 44,
	      "[ERROR:44] metrics report missing last reset header");
	CHECK(metrics_config != NULL, 72,
	      "[ERROR:72] metrics report missing config generation header");
	CHECK(metrics_ruleset != NULL, 45,
	      "[ERROR:45] metrics report missing ruleset generation header");
	CHECK(metrics_reset < metrics_config && metrics_config < metrics_ruleset,
	      73, "[ERROR:73] metrics identity headers out of order");

	atomic_store(&run_stats, false);
	atomic_store(&signal_report_requests, 0);
	siginfo_t info;

	memset(&info, 0, sizeof(info));
	info.si_code = SI_QUEUE;
	info.si_pid = 4321;
	info.si_uid = 0;
	info.si_value.sival_int = REPORT_INTENT_TIMING_ARM;
	usr1_handler(SIGUSR1, &info, NULL);
	CHECK(!atomic_load(&run_stats), 24,
	      "[ERROR:24] timing start incorrectly requested state report");
	CHECK(atomic_load(&signal_report_requests) == 0, 25,
	      "[ERROR:25] timing start incremented state report requests");

	config.timing_collection = TIMING_COLLECTION_OFF;
	decision_timing_process_requests(&config);
	FILE *timing = tmpfile();
	CHECK(timing != NULL, 26, "[ERROR:26] tmpfile failed");
	decision_timing_control_report(timing, &config);
	fflush(timing);
	rewind(timing);
	size_t used = fread(report, 1, sizeof(report) - 1, timing);
	report[used] = 0;
	fclose(timing);
	CHECK(strstr(report, "Timing collection mode: off") != NULL, 27,
	      "[ERROR:27] timing mode missing from state report");
	CHECK(strstr(report, "Timing collection armed: false") != NULL, 28,
	      "[ERROR:28] timing unexpectedly armed while configured off");

	config.timing_collection = TIMING_COLLECTION_MANUAL;
	usr1_handler(SIGUSR1, &info, NULL);
	decision_timing_process_requests(&config);
	timing = tmpfile();
	CHECK(timing != NULL, 29, "[ERROR:29] tmpfile failed");
	decision_timing_control_report(timing, &config);
	fflush(timing);
	rewind(timing);
	used = fread(report, 1, sizeof(report) - 1, timing);
	report[used] = 0;
	fclose(timing);
	CHECK(strstr(report, "Timing collection mode: manual") != NULL, 30,
	      "[ERROR:30] manual timing mode missing from state report");
	CHECK(strstr(report, "Timing collection armed: true") != NULL, 31,
	      "[ERROR:31] privileged manual timing start was not applied");
	CHECK(strstr(report, "Timing collection last start requester") == NULL,
	      32, "[ERROR:32] timing start requester still in state report");

	info.si_value.sival_int = REPORT_INTENT_TIMING_STOP;
	usr1_handler(SIGUSR1, &info, NULL);
	decision_timing_process_requests(&config);
	timing = tmpfile();
	CHECK(timing != NULL, 33, "[ERROR:33] tmpfile failed");
	decision_timing_control_report(timing, &config);
	fflush(timing);
	rewind(timing);
	used = fread(report, 1, sizeof(report) - 1, timing);
	report[used] = 0;
	fclose(timing);
	CHECK(strstr(report, "Timing collection armed: false") != NULL, 34,
	      "[ERROR:34] timing stop did not disarm");
	CHECK(strstr(report, "Timing collection last stop requester") == NULL,
	      35, "[ERROR:35] timing stop requester still in state report");

	read_decision_report(report, sizeof(report), 1);
	snprintf(expected, sizeof(expected), "Kernel Queue Overflow: %lu",
		 overflow_after);
	CHECK(strstr(report, expected) != NULL, 36,
	      "[ERROR:36] reset report lost pre-reset overflow count");
	snprintf(expected, sizeof(expected), "Reply Errors: %lu", reply_after);
	CHECK(strstr(report, expected) != NULL, 37,
	      "[ERROR:37] reset report lost pre-reset reply count");
#if TEST_HAVE_FAN_FS_ERROR
	snprintf(expected, sizeof(expected), "Filesystem Errors: %lu",
		 fs_error_after);
	CHECK(strstr(report, expected) != NULL, 56,
	      "[ERROR:56] reset report lost pre-reset fs error count");
#endif
	CHECK(getKernelQueueOverflow() == 0, 38,
	      "[ERROR:38] reset report did not clear overflow count");
	CHECK(getReplyErrors() == 0, 39,
	      "[ERROR:39] reset report did not clear reply count");
#if TEST_HAVE_FAN_FS_ERROR
	CHECK(getFanotifyFilesystemErrors() == 0, 57,
	      "[ERROR:57] reset report did not clear fs error count");
#endif

	test_shutdown_deferred_events();
	test_shutdown_queued_events();

	return 0;
}
