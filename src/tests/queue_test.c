/*
 * queue_test.c - verify queue metric accounting
 */
#include <errno.h>
#include <error.h>
#include <stdio.h>
#include <string.h>

#include "queue.h"

#define CHECK(expr, code, msg) \
	do { \
		if (!(expr)) \
			error(1, 0, "%s", msg); \
	} while (0)

/*
 * read_queue_report - capture queue text report output.
 * @metrics: metrics to write.
 * @buf: destination buffer.
 * @size: size of @buf.
 * Returns nothing. Exits if the temporary stream cannot be used.
 */
static void read_queue_report(const struct queue_metrics *metrics, char *buf,
			      size_t size)
{
	FILE *f = tmpfile();
	size_t used;

	if (f == NULL)
		error(1, 0, "tmpfile failed");

	q_metrics_report(f, metrics);
	fflush(f);
	rewind(f);
	used = fread(buf, 1, size - 1, f);
	buf[used] = 0;
	fclose(f);
}

/*
 * main - exercise queue current depth, max depth, full count, and reporting.
 * Returns 0 on success. Exits with error() on test failure.
 */
int main(void)
{
	decision_event_t event = { 0 };
	decision_event_t out = { 0 };
	struct queue_metrics metrics;
	struct queue *q;
	char report[128];
	unsigned int run_max, saved;

	q = q_open(2);
	CHECK(q != NULL, 1, "[ERROR:1] q_open failed");

	q_metrics_snapshot(q, &metrics);
	CHECK(metrics.current_depth == 0, 2,
	      "[ERROR:2] initial current depth not zero");
	CHECK(metrics.max_depth == 0, 3,
	      "[ERROR:3] initial max depth not zero");
	CHECK(metrics.full_count == 0, 4,
	      "[ERROR:4] initial full count not zero");

	CHECK(q_enqueue(q, &event) == 0, 5,
	      "[ERROR:5] first enqueue failed");
	CHECK(q_enqueue(q, &event) == 0, 6,
	      "[ERROR:6] second enqueue failed");

	errno = 0;
	CHECK(q_enqueue(q, &event) == -1 && errno == ENOSPC, 7,
	      "[ERROR:7] full queue did not return ENOSPC");

	q_metrics_snapshot(q, &metrics);
	CHECK(metrics.current_depth == 2, 8,
	      "[ERROR:8] full current depth incorrect");
	CHECK(metrics.max_depth == 2, 9,
	      "[ERROR:9] max depth incorrect");
	CHECK(metrics.full_count == 1, 10,
	      "[ERROR:10] full count incorrect");

	CHECK(q_dequeue(q, &out) == 1, 11,
	      "[ERROR:11] dequeue failed");
	q_metrics_snapshot(q, &metrics);
	CHECK(metrics.current_depth == 1, 12,
	      "[ERROR:12] dequeue current depth incorrect");
	CHECK(metrics.max_depth == 2, 13,
	      "[ERROR:13] dequeue changed max depth");
	CHECK(metrics.full_count == 1, 14,
	      "[ERROR:14] dequeue changed full count");

	read_queue_report(&metrics, report, sizeof(report));
	CHECK(strcmp(report, "Inter-thread max queue depth: 2\n") == 0, 15,
	      "[ERROR:15] legacy queue report format changed");

	q_metrics_snapshot_reset(q, &metrics, 1);
	CHECK(metrics.current_depth == 1, 16,
	      "[ERROR:16] reset snapshot changed current depth");
	CHECK(metrics.max_depth == 2, 17,
	      "[ERROR:17] reset snapshot lost previous max depth");
	CHECK(metrics.full_count == 1, 18,
	      "[ERROR:18] reset snapshot lost previous full count");

	q_metrics_snapshot(q, &metrics);
	CHECK(metrics.current_depth == 1, 19,
	      "[ERROR:19] reset changed current depth state");
	CHECK(metrics.max_depth == 1, 20,
	      "[ERROR:20] reset did not restart max depth at current depth");
	CHECK(metrics.full_count == 0, 21,
	      "[ERROR:21] reset did not clear full count");

	saved = q_max_depth_snapshot_reset(q);
	CHECK(saved == 1, 22,
	      "[ERROR:22] max depth reset returned wrong saved value");
	CHECK(q_enqueue(q, &event) == 0, 23,
	      "[ERROR:23] enqueue after max depth reset failed");
	run_max = q_max_depth_snapshot_restore(q, saved);
	CHECK(run_max == 2, 24,
	      "[ERROR:24] max depth restore returned wrong run value");
	q_metrics_snapshot(q, &metrics);
	CHECK(metrics.max_depth == 2, 25,
	      "[ERROR:25] restore changed larger run max depth");

	CHECK(q_dequeue(q, &out) == 1, 26,
	      "[ERROR:26] second dequeue failed");
	saved = q_max_depth_snapshot_reset(q);
	CHECK(saved == 2, 27,
	      "[ERROR:27] second max depth reset lost saved high water");
	q_metrics_snapshot(q, &metrics);
	CHECK(metrics.max_depth == 1, 28,
	      "[ERROR:28] max depth reset did not restart at current depth");
	run_max = q_max_depth_snapshot_restore(q, saved);
	CHECK(run_max == 1, 29,
	      "[ERROR:29] restore did not return timing run max depth");
	q_metrics_snapshot(q, &metrics);
	CHECK(metrics.max_depth == 2, 30,
	      "[ERROR:30] restore did not preserve pre-run max depth");

	q_close(q);
	return 0;
}
