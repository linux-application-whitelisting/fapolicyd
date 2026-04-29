/*
 * failure_action_test.c - verify internal failure action accounting
 */
#include <error.h>
#include <stdio.h>
#include <string.h>

#include "failure-action.h"

#define CHECK(expr, code, msg) \
	do { \
		if (!(expr)) \
			error(1, 0, "%s", msg); \
	} while (0)

/*
 * read_failure_report - capture failure action report output.
 * @buf: destination buffer.
 * @size: size of @buf.
 * Returns nothing. Exits if the temporary stream cannot be used.
 */
static void read_failure_report(char *buf, size_t size)
{
	FILE *f = tmpfile();
	size_t used;

	if (f == NULL)
		error(1, 0, "tmpfile failed");

	failure_action_report(f);
	fflush(f);
	rewind(f);
	used = fread(buf, 1, size - 1, f);
	buf[used] = 0;
	fclose(f);
}

/*
 * main - exercise failure action names, actions, counters, and reporting.
 * Returns 0 on success. Exits with error() on test failure.
 */
int main(void)
{
	failure_action_metrics_t metrics;
	char report[1024];
	char expected[128];
	unsigned long before, after;

	CHECK(strcmp(failure_reason_name(FAILURE_REASON_QUEUE_FULL),
		     "queue_full") == 0, 1,
	      "[ERROR:1] queue_full reason name changed");
	CHECK(failure_reason_action(FAILURE_REASON_QUEUE_FULL) ==
	      FAILURE_ACTION_OBSERVE, 2,
	      "[ERROR:2] queue_full default action changed");
	CHECK(strcmp(failure_action_name(FAILURE_ACTION_OBSERVE),
		     "observe") == 0, 3,
	      "[ERROR:3] observe action name changed");

	CHECK(strcmp(failure_reason_name((failure_reason_t)-1),
		     "unknown") == 0, 4,
	      "[ERROR:4] invalid reason name not unknown");
	CHECK(failure_action_record((failure_reason_t)-1) == 0, 5,
	      "[ERROR:5] invalid reason changed counters");

	before = failure_action_count(FAILURE_REASON_QUEUE_FULL);
	after = failure_action_record(FAILURE_REASON_QUEUE_FULL);
	CHECK(after == before + 1, 6,
	      "[ERROR:6] queue_full counter did not increment");
	CHECK(failure_action_count(FAILURE_REASON_QUEUE_FULL) == after, 7,
	      "[ERROR:7] queue_full counter read mismatch");

	read_failure_report(report, sizeof(report));
	snprintf(expected, sizeof(expected),
		 "Failure action queue_full (observe): %lu", after);
	CHECK(strstr(report, expected) != NULL, 8,
	      "[ERROR:8] report missing queue_full counter");
	CHECK(strstr(report,
		     "Failure action trust_reload_failure (observe): ") != NULL,
	      9, "[ERROR:9] report missing trust reload counter");

	failure_action_snapshot(&metrics, 1);
	CHECK(failure_action_metrics_count(&metrics,
	      FAILURE_REASON_QUEUE_FULL) == after, 10,
	      "[ERROR:10] reset snapshot lost queue_full count");
	CHECK(failure_action_count(FAILURE_REASON_QUEUE_FULL) == 0, 11,
	      "[ERROR:11] reset snapshot did not clear queue_full count");

	return 0;
}
