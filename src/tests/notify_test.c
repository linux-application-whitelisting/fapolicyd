/*
 * notify_test.c - unit tests for daemon fanotify metadata handling
 */
#include <error.h>
#include <errno.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <sys/fanotify.h>
#include <unistd.h>

#include "failure-action.h"
#include "notify.h"
#include "policy.h"
#include "state-report.h"

#ifndef FAN_Q_OVERFLOW
#define FAN_Q_OVERFLOW		0x00004000
#endif

extern atomic_bool run_stats;

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
	char report[2048], expected[64];
	int event_pipe[2];

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
	CHECK(strstr(report, "Allowed by rule: ") != NULL, 20,
	      "[ERROR:20] status report missing rule allow count");
	CHECK(strstr(report, "Allowed by fallthrough: ") != NULL, 21,
	      "[ERROR:21] status report missing fallthrough allow count");
	CHECK(strstr(report, "Allowed by fallthrough executable: ") == NULL, 22,
	      "[ERROR:22] zero fallthrough report included ftype detail");
	CHECK(strstr(report, "Ruleset generation: ") != NULL, 23,
	      "[ERROR:23] status report missing ruleset generation");

	read_decision_report(report, sizeof(report), 1);
	snprintf(expected, sizeof(expected), "Kernel Queue Overflow: %lu",
		 overflow_after);
	CHECK(strstr(report, expected) != NULL, 24,
	      "[ERROR:24] reset report lost pre-reset overflow count");
	snprintf(expected, sizeof(expected), "Reply Errors: %lu", reply_after);
	CHECK(strstr(report, expected) != NULL, 25,
	      "[ERROR:25] reset report lost pre-reset reply count");
	CHECK(getKernelQueueOverflow() == 0, 26,
	      "[ERROR:26] reset report did not clear overflow count");
	CHECK(getReplyErrors() == 0, 27,
	      "[ERROR:27] reset report did not clear reply count");

	return 0;
}
