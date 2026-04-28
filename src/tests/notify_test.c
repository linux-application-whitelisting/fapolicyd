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

#include "notify.h"
#include "policy.h"

#ifndef FAN_Q_OVERFLOW
#define FAN_Q_OVERFLOW		0x00004000
#endif

extern atomic_bool run_stats;

#define CHECK(expr, code, msg) \
	do { \
		if (!(expr)) \
			error(1, 0, "%s", msg); \
	} while (0)

void do_stat_report(FILE *f, int shutdown)
{
	(void)f;
	(void)shutdown;
}

/*
 * read_decision_report - capture decision_report output for assertions.
 * @buf: destination buffer.
 * @size: size of @buf.
 * Returns nothing. Exits if the temporary stream cannot be used.
 */
static void read_decision_report(char *buf, size_t size)
{
	FILE *f = tmpfile();
	size_t used;

	if (f == NULL)
		error(1, 0, "tmpfile failed");

	decision_report(f);
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

	atomic_store(&run_stats, false);
	metadata.mask = FAN_Q_OVERFLOW;
	// FAN_Q_OVERFLOW should be consumed as a kernel queue failure.
	CHECK(handle_kernel_event(&metadata) == 1, 3,
	      "[ERROR:3] FAN_Q_OVERFLOW event was not consumed");

	after = getKernelQueueOverflow();
	// Consuming FAN_Q_OVERFLOW should increment the overflow counter once.
	CHECK(after == before + 1, 4,
	      "[ERROR:4] FAN_Q_OVERFLOW did not increment count");
	// Queue overflow should request the configured failure action.
	CHECK(atomic_load(&run_stats), 5,
	      "[ERROR:5] FAN_Q_OVERFLOW did not trigger failure action");

	read_decision_report(report, sizeof(report));
	snprintf(expected, sizeof(expected), "Kernel Queue Overflow: %lu",
		 after);
	// The status report should expose the overflow counter value.
	CHECK(strstr(report, expected) != NULL, 6,
	      "[ERROR:6] status report missing Kernel Queue Overflow");

	// Use a real event fd so reply_event can prove it still closes once.
	CHECK(pipe(event_pipe) == 0, 7, "[ERROR:7] pipe failed");
	metadata.fd = event_pipe[0];
	metadata.pid = 1234;
	metadata.mask = FAN_OPEN_PERM;
	before = getReplyErrors();

	reply_event(-1, &metadata, FAN_ALLOW, NULL);
	after = getReplyErrors();
	// A failed fanotify response write should increment reply_errors once.
	CHECK(after == before + 1, 8,
	      "[ERROR:8] reply_event did not count EBADF write failure");

	errno = 0;
	// reply_event should close the event fd even when the response fails.
	CHECK(close(event_pipe[0]) == -1 && errno == EBADF, 9,
	      "[ERROR:9] reply_event did not close event fd");
	close(event_pipe[1]);

	read_decision_report(report, sizeof(report));
	snprintf(expected, sizeof(expected), "Reply Errors: %lu", after);
	// The status report should expose the aggregate reply_errors value.
	CHECK(strstr(report, expected) != NULL, 10,
	      "[ERROR:10] status report missing Reply Errors count");
	CHECK(strstr(report, "Allowed by rule: ") != NULL, 11,
	      "[ERROR:11] status report missing rule allow count");
	CHECK(strstr(report, "Allowed by fallthrough: ") != NULL, 12,
	      "[ERROR:12] status report missing fallthrough allow count");
	CHECK(strstr(report, "Allowed by fallthrough executable: ") == NULL, 13,
	      "[ERROR:13] zero fallthrough report included ftype detail");
	CHECK(strstr(report, "Ruleset generation: ") != NULL, 14,
	      "[ERROR:14] status report missing ruleset generation");

	return 0;
}
