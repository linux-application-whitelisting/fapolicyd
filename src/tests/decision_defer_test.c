/*
 * decision_defer_test.c - unit tests for subject-slot decision deferral
 */
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "decision-defer.h"

#define CHECK(cond, code, msg) \
	do { \
		if (!(cond)) { \
			fprintf(stderr, "%s\n", msg); \
			return code; \
		} \
	} while (0)

/*
 * make_event - build a synthetic decision event for queue tests.
 * @pid: event subject pid.
 * @fd: synthetic fanotify permission fd.
 * @slot: subject cache slot that blocks the event.
 *
 * Returns an initialized decision event. completed_subject_slot is set to a
 * non-default value so tests can prove deferral clears stale release state.
 */
static decision_event_t make_event(pid_t pid, int fd, unsigned int slot)
{
	decision_event_t event;

	memset(&event, 0, sizeof(event));
	event.metadata.pid = pid;
	event.metadata.fd = fd;
	event.metadata.mask = FAN_OPEN_PERM;
	event.subject_slot = slot;
	event.completed_subject_slot = slot + 100;
	return event;
}

/*
 * test_slot_release_chain - pop deferred events for one released slot.
 *
 * Multiple events can wait on the same subject slot. Releasing that slot must
 * return the oldest matching event first, then the next matching event, while
 * leaving unrelated slots parked until their own release.
 *
 * Returns 0 on success, or a distinct failure code.
 */
static int test_slot_release_chain(void)
{
	struct decision_defer_queue defer;
	decision_event_t event, out;

	CHECK(decision_defer_init(&defer, 1) == 0, 1,
	      "[ERROR:1] decision_defer_init failed");

	event = make_event(100, 10, 3);
	CHECK(decision_defer_push(&defer, &event) == 0, 2,
	      "[ERROR:2] first defer push failed");
	event = make_event(101, 11, 4);
	CHECK(decision_defer_push(&defer, &event) == 0, 3,
	      "[ERROR:3] unrelated defer push failed");
	event = make_event(102, 12, 3);
	CHECK(decision_defer_push(&defer, &event) == 0, 4,
	      "[ERROR:4] chained defer push failed");
	CHECK(defer.current == 3 && defer.max_depth == 3, 5,
	      "[ERROR:5] defer depth not tracked");

	CHECK(decision_defer_pop_slot(&defer, 3, &out) == 1, 6,
	      "[ERROR:6] released slot did not pop");
	CHECK(out.metadata.pid == 100 && out.metadata.fd == 10, 7,
	      "[ERROR:7] released slot did not pop oldest event");
	CHECK(out.completed_subject_slot == DECISION_EVENT_NO_SLOT, 8,
	      "[ERROR:8] deferred event kept stale completion slot");

	CHECK(decision_defer_pop_slot(&defer, 3, &out) == 1, 9,
	      "[ERROR:9] chained release did not pop second event");
	CHECK(out.metadata.pid == 102 && out.metadata.fd == 12, 10,
	      "[ERROR:10] chained release popped wrong event");

	CHECK(decision_defer_pop_slot(&defer, 3, &out) == 0, 11,
	      "[ERROR:11] released slot popped unrelated event");
	CHECK(decision_defer_pop_slot(&defer, 4, &out) == 1, 12,
	      "[ERROR:12] unrelated slot did not remain deferred");
	CHECK(out.metadata.pid == 101 && defer.current == 0, 13,
	      "[ERROR:13] unrelated release or depth mismatch");

	decision_defer_destroy(&defer);
	return 0;
}

/*
 * report_contains - test whether defer metrics report contains expected text.
 * @metrics: metrics snapshot to render.
 * @needle: expected substring.
 *
 * Returns 1 when the rendered report contains @needle, 0 otherwise.
 */
static int report_contains(const struct decision_defer_metrics *metrics,
		const char *needle)
{
	FILE *report;
	char buf[512];
	size_t used;
	int found;

	report = tmpfile();
	if (report == NULL)
		return 0;

	decision_defer_metrics_report(report, metrics);
	fflush(report);
	rewind(report);
	used = fread(buf, 1, sizeof(buf) - 1, report);
	buf[used] = 0;
	found = strstr(buf, needle) != NULL;
	fclose(report);
	return found;
}

/*
 * test_full_array_fallback_metrics - verify bounded capacity accounting.
 *
 * A full defer array must reject another event so the caller can fall back to
 * historical eviction behavior. The fallback counter and reset semantics must
 * remain observable in the metrics snapshot and report.
 *
 * Returns 0 on success, or a distinct failure code.
 */
static int test_full_array_fallback_metrics(void)
{
	struct decision_defer_queue defer;
	struct decision_defer_metrics metrics;
	decision_event_t event;
	char expected[64];
	unsigned int i;

	CHECK(decision_defer_init(&defer, 1) == 0, 20,
	      "[ERROR:20] decision_defer_init failed");
	CHECK(defer.capacity == DECISION_DEFER_MIN, 21,
	      "[ERROR:21] tiny cache did not use defer floor");

	for (i = 0; i < defer.capacity; i++) {
		event = make_event(200 + i, 20 + i, i % 2);
		CHECK(decision_defer_push(&defer, &event) == 0, 22,
		      "[ERROR:22] filling defer array failed");
	}

	event = make_event(999, 99, 1);
	errno = 0;
	CHECK(decision_defer_push(&defer, &event) == -1, 23,
	      "[ERROR:23] full defer array accepted an event");
	CHECK(errno == ENOSPC, 24,
	      "[ERROR:24] full defer array did not set ENOSPC");

	decision_defer_count_fallback(&defer);
	decision_defer_metrics_snapshot_reset(&defer, &metrics, 0);
	CHECK(metrics.capacity == defer.capacity, 25,
	      "[ERROR:25] metrics capacity mismatch");
	CHECK(metrics.current_depth == defer.capacity, 26,
	      "[ERROR:26] metrics current depth mismatch");
	CHECK(metrics.deferred_events == defer.capacity, 27,
	      "[ERROR:27] metrics deferred events mismatch");
	CHECK(metrics.max_depth == defer.capacity, 28,
	      "[ERROR:28] metrics max depth mismatch");
	CHECK(metrics.fallbacks == 1, 29,
	      "[ERROR:29] metrics fallback count mismatch");
	snprintf(expected, sizeof(expected), "Subject deferred events: %u",
		 defer.capacity);
	CHECK(report_contains(&metrics, expected), 30,
	      "[ERROR:30] metrics report missing deferred event count");
	CHECK(report_contains(&metrics, "Subject defer fallbacks: 1"), 31,
	      "[ERROR:31] metrics report missing fallback count");

	decision_defer_metrics_snapshot_reset(&defer, &metrics, 1);
	CHECK(metrics.deferred_events == defer.capacity, 32,
	      "[ERROR:32] reset snapshot lost deferred event count");
	CHECK(metrics.fallbacks == 1, 33,
	      "[ERROR:33] reset snapshot lost fallback count");
	CHECK(defer.deferred_events == 0, 34,
	      "[ERROR:34] reset did not clear deferred event counter");
	CHECK(defer.fallbacks == 0, 35,
	      "[ERROR:35] reset did not clear fallback counter");
	CHECK(defer.max_depth == defer.current, 36,
	      "[ERROR:36] reset did not leave max depth at live depth");

	while (decision_defer_pop_any(&defer, &event))
		;
	CHECK(defer.current == 0, 37,
	      "[ERROR:37] defer array did not drain");

	decision_defer_destroy(&defer);
	return 0;
}

/*
 * test_shutdown_pop_any_cleanup - drain deferred fds in shutdown order.
 *
 * Shutdown cleanup uses pop_any() to take ownership of every still-deferred
 * event. This test closes each popped permission fd and verifies each one is
 * released exactly once.
 *
 * Returns 0 on success, or a distinct failure code.
 */
static int test_shutdown_pop_any_cleanup(void)
{
	struct decision_defer_queue defer;
	decision_event_t event;
	int pipes[3][2];
	unsigned int i;

	CHECK(decision_defer_init(&defer, 1) == 0, 40,
	      "[ERROR:40] decision_defer_init failed");

	for (i = 0; i < 3; i++) {
		CHECK(pipe(pipes[i]) == 0, 41,
		      "[ERROR:41] pipe setup failed");
		event = make_event(300 + i, pipes[i][0], 7 - i);
		CHECK(decision_defer_push(&defer, &event) == 0, 42,
		      "[ERROR:42] shutdown defer push failed");
	}

	for (i = 0; i < 3; i++) {
		CHECK(decision_defer_pop_any(&defer, &event) == 1, 43,
		      "[ERROR:43] shutdown pop_any missed event");
		CHECK(event.metadata.pid == 300 + i, 44,
		      "[ERROR:44] shutdown pop_any order mismatch");
		CHECK(close(event.metadata.fd) == 0, 45,
		      "[ERROR:45] shutdown fd close failed");
	}

	CHECK(decision_defer_pop_any(&defer, &event) == 0, 46,
	      "[ERROR:46] shutdown pop_any returned extra event");
	for (i = 0; i < 3; i++) {
		errno = 0;
		CHECK(close(pipes[i][0]) == -1 && errno == EBADF, 47,
		      "[ERROR:47] deferred fd was not closed exactly once");
		close(pipes[i][1]);
	}

	decision_defer_destroy(&defer);
	return 0;
}

/* main - run defer queue unit tests. */
int main(void)
{
	int rc;

	rc = test_slot_release_chain();
	if (rc)
		return rc;

	rc = test_full_array_fallback_metrics();
	if (rc)
		return rc;

	rc = test_shutdown_pop_any_cleanup();
	if (rc)
		return rc;

	return 0;
}
