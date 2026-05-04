/*
 * notify_test.c - unit tests for daemon fanotify metadata handling
 */
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
#include "notify.h"
#include "policy.h"
#include "decision-defer.h"
#include "decision-timing.h"
#include "state-report.h"

#ifndef FAN_Q_OVERFLOW
#define FAN_Q_OVERFLOW		0x00004000
#endif

#if defined(FAN_FS_ERROR) && defined(FAN_REPORT_FID) && \
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

int test_notify_defer_reset(unsigned int subj_cache_size);
void test_notify_defer_destroy(void);
int test_notify_defer_push(const decision_event_t *event);
void test_notify_shutdown_deferred_events(void);

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
		.ruleset_generation = 7,
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

/*
 * test_operating_mode_report_order - verify state field order.
 *
 * The operating mode group keeps the timing control fields together. Ruleset
 * generation is last so readers see the active policy after all control
 * state in the same group.
 *
 * Returns nothing. Exits on test failure.
 */
static void test_operating_mode_report_order(void)
{
	const char *ruleset, *last_stop;
	char report[1024];

	read_operating_mode_report(report, sizeof(report));
	last_stop = strstr(report, "Timing collection last stop time: never\n");
	ruleset = strstr(report, "Ruleset generation: 7\n");
	CHECK(last_stop != NULL, 58,
	      "[ERROR:58] operating mode report missing timing stop field");
	CHECK(ruleset != NULL, 59,
	      "[ERROR:59] operating mode report missing ruleset field");
	CHECK(last_stop < ruleset, 60,
	      "[ERROR:60] ruleset generation was not last in group");
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
	test_notify_shutdown_deferred_events();

	for (i = 0; i < 3; i++) {
		errno = 0;
		CHECK(close(pipes[i][0]) == -1 && errno == EBADF, 43,
		      "[ERROR:43] deferred fd was not closed exactly once");
		close(pipes[i][1]);
	}

	test_notify_defer_destroy();
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
	unsigned long fs_error_after = 0;
	char report[4096], expected[128];
	int event_pipe[2];

	test_operating_mode_report_order();

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
		CHECK(handle_kernel_event(&fs_error_event.metadata) == 1, 46,
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
	CHECK(strstr(report, "Last metrics reset: never") != NULL, 44,
	      "[ERROR:44] metrics report missing last reset header");
	CHECK(strstr(report, "Ruleset generation: ") != NULL, 45,
	      "[ERROR:45] metrics report missing ruleset generation header");

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

	return 0;
}
