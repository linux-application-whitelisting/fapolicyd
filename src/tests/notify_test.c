/*
 * notify_test.c - unit tests for daemon fanotify metadata handling
 */
#include <error.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <sys/fanotify.h>

#include "notify.h"

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
	char report[512], expected[64];

	before = getKernelQueueOverflow();
	metadata.mask = 0;
	CHECK(handle_kernel_event(&metadata) == 0, 1,
	      "[ERROR:1] non-overflow FAN_NOFD event was consumed");
	CHECK(getKernelQueueOverflow() == before, 2,
	      "[ERROR:2] non-overflow event changed overflow count");

	atomic_store(&run_stats, false);
	metadata.mask = FAN_Q_OVERFLOW;
	CHECK(handle_kernel_event(&metadata) == 1, 3,
	      "[ERROR:3] FAN_Q_OVERFLOW event was not consumed");

	after = getKernelQueueOverflow();
	CHECK(after == before + 1, 4,
	      "[ERROR:4] FAN_Q_OVERFLOW did not increment count");
	CHECK(atomic_load(&run_stats), 5,
	      "[ERROR:5] FAN_Q_OVERFLOW did not trigger failure action");

	read_decision_report(report, sizeof(report));
	snprintf(expected, sizeof(expected), "kernel_queue_overflow: %lu",
		 after);
	CHECK(strstr(report, expected) != NULL, 6,
	      "[ERROR:6] status report missing kernel_queue_overflow");

	return 0;
}
