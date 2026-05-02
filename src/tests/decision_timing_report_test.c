/*
 * decision_timing_report_test.c - timing report formatting tests
 */
#include <error.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "decision-timing.h"

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

#define CHECK(expr, code, msg) \
	do { \
		if (!(expr)) \
			error(1, 0, "%s", msg); \
	} while (0)

struct report_case {
	const struct decision_timing_test_stage_sample *samples;
	unsigned int sample_count;
	const struct decision_timing_test_report_input *input;
};

void msg(int priority, const char *fmt, ...)
{
	(void)priority;
	(void)fmt;
}

/*
 * read_test_report - capture synthetic timing report output.
 * @test: report inputs.
 * @buf: destination buffer.
 * @size: size of @buf.
 * Returns nothing. Exits if the temporary stream cannot be used.
 */
static void read_test_report(const struct report_case *test, char *buf,
			     size_t size)
{
	FILE *f = tmpfile();
	size_t used;

	if (f == NULL)
		error(1, 0, "tmpfile failed");

	decision_timing_test_write_report(f, test->samples,
					  test->sample_count, test->input);
	fflush(f);
	rewind(f);
	used = fread(buf, 1, size - 1, f);
	buf[used] = 0;
	fclose(f);
}

/*
 * require_text - find required report text.
 * @report: report buffer.
 * @needle: required text.
 * @code: failure code.
 * Returns the first occurrence of @needle.
 */
static const char *require_text(const char *report, const char *needle,
				int code)
{
	const char *found = strstr(report, needle);

	CHECK(found != NULL, code, needle);
	return found;
}

/*
 * reject_text - assert that report text is absent.
 * @report: report buffer.
 * @needle: text that must be absent.
 * @code: failure code.
 * Returns nothing.
 */
static void reject_text(const char *report, const char *needle, int code)
{
	CHECK(strstr(report, needle) == NULL, code, needle);
}

static const struct decision_timing_test_stage_sample full_samples[] = {
	{ DECISION_TIMING_STAGE_TOTAL, 99, 99000000ULL, 5000000ULL, 5 },
	{ DECISION_TIMING_STAGE_TOTAL, 1, 260000000ULL, 260000000ULL, 13 },
	{ DECISION_TIMING_STAGE_QUEUE_WAIT, 100, 17400000ULL,
	  314000000ULL, 4 },
	{ DECISION_TIMING_STAGE_EVENT_BUILD, 100, 20000000ULL,
	  1000000ULL, 3 },
	{ DECISION_TIMING_STAGE_CACHE_FLUSH, 1, 1000000ULL,
	  1000000ULL, 5 },
	{ DECISION_TIMING_STAGE_PROC_FINGERPRINT, 100, 5000000ULL,
	  100000ULL, 3 },
	{ DECISION_TIMING_STAGE_PROC_STATUS_EXE_LOOKUP, 3, 1200000ULL,
	  500000ULL, 5 },
	{ DECISION_TIMING_STAGE_FD_STAT, 100, 3000000ULL, 100000ULL, 3 },
	{ DECISION_TIMING_STAGE_FD_PATH_RESOLUTION, 50, 4000000ULL,
	  200000ULL, 4 },
	{ DECISION_TIMING_STAGE_EVAL_MIME_DETECTION, 10, 10000000ULL,
	  1000000ULL, 6 },
	{ DECISION_TIMING_STAGE_RESPONSE_MIME_DETECTION, 10, 12000000ULL,
	  5000000ULL, 7 },
	{ DECISION_TIMING_STAGE_EVAL_MIME_FAST_CLASSIFICATION, 10,
	  4000000ULL, 1000000ULL, 5 },
	{ DECISION_TIMING_STAGE_RESPONSE_MIME_FAST_CLASSIFICATION, 10,
	  3690000ULL, 1000000ULL, 5 },
	{ DECISION_TIMING_STAGE_EVAL_MIME_GATHER_ELF, 5, 5000000ULL,
	  1200000ULL, 5 },
	{ DECISION_TIMING_STAGE_RESPONSE_MIME_GATHER_ELF, 5, 4220000ULL,
	  1200000ULL, 5 },
	{ DECISION_TIMING_STAGE_EVAL_MIME_LIBMAGIC_FALLBACK, 5,
	  4300000ULL, 2000000ULL, 6 },
	{ DECISION_TIMING_STAGE_RESPONSE_MIME_LIBMAGIC_FALLBACK, 10,
	  12000000ULL, 4000000ULL, 7 },
	{ DECISION_TIMING_STAGE_HASH_IMA, 2, 7500000ULL, 3000000ULL, 7 },
	{ DECISION_TIMING_STAGE_HASH_SHA, 3, 4500000ULL, 2000000ULL, 6 },
	{ DECISION_TIMING_STAGE_EVAL_TRUST_DB_LOOKUP, 10, 4000000ULL,
	  2000000ULL, 5 },
	{ DECISION_TIMING_STAGE_RESPONSE_TRUST_DB_LOOKUP, 5, 2000000ULL,
	  1000000ULL, 5 },
	{ DECISION_TIMING_STAGE_EVAL_TRUST_DB_LOCK_WAIT, 10, 1000ULL,
	  500ULL, 0 },
	{ DECISION_TIMING_STAGE_RESPONSE_TRUST_DB_LOCK_WAIT, 5, 500ULL,
	  200ULL, 0 },
	{ DECISION_TIMING_STAGE_EVAL_TRUST_DB_READ, 10, 3999000ULL,
	  1999000ULL, 5 },
	{ DECISION_TIMING_STAGE_RESPONSE_TRUST_DB_READ, 5, 1999500ULL,
	  1000000ULL, 5 },
	{ DECISION_TIMING_STAGE_RULE_LOCK_WAIT, 100, 100000ULL,
	  5000ULL, 1 },
	{ DECISION_TIMING_STAGE_RULE_EVALUATION, 100, 30000000ULL,
	  2000000ULL, 5 },
	{ DECISION_TIMING_STAGE_RESPONSE_TOTAL, 99, 140000000ULL,
	  3000000ULL, 5 },
	{ DECISION_TIMING_STAGE_RESPONSE_TOTAL, 1, 260000000ULL,
	  260000000ULL, 13 },
	{ DECISION_TIMING_STAGE_SYSLOG_DEBUG_FORMAT, 100, 300000000ULL,
	  260000000ULL, 13 },
	{ DECISION_TIMING_STAGE_AUDIT_RESPONSE_PREP, 100, 500000ULL,
	  10000ULL, 2 },
	{ DECISION_TIMING_STAGE_FANOTIFY_RESPONSE_WRITE, 100,
	  1000000ULL, 50000ULL, 3 },
};

static const struct decision_timing_test_stage_sample sparse_samples[] = {
	{ DECISION_TIMING_STAGE_TOTAL, 4, 4000000ULL, 1000000ULL, 6 },
	{ DECISION_TIMING_STAGE_EVENT_BUILD, 4, 1000000ULL, 250000ULL, 4 },
	{ DECISION_TIMING_STAGE_RULE_EVALUATION, 4, 2000000ULL,
	  500000ULL, 5 },
	{ DECISION_TIMING_STAGE_RESPONSE_TOTAL, 4, 1000000ULL,
	  250000ULL, 4 },
};

static const struct decision_timing_test_report_input full_input = {
	.duration_ns = 10000000000ULL,
	.max_queue_depth = 7,
	.q_size = 40,
};

static const struct decision_timing_test_report_input sparse_input = {
	.duration_ns = 1000000000ULL,
	.max_queue_depth = 0,
	.q_size = 40,
};

/*
 * test_full_report - verify the insight sections with all major stages.
 * Returns nothing.
 */
static void test_full_report(void)
{
	const struct report_case test = {
		.samples = full_samples,
		.sample_count = ARRAY_SIZE(full_samples),
		.input = &full_input,
	};
	const char *overall, *queueing, *phases, *helper_intro, *helpers;
	const char *observations, *drivers, *detailed, *tail;
	const char *not_observed, *notes;
	char report[16384];

	read_test_report(&test, report, sizeof(report));

	overall = require_text(report, "\nOverall decision latency:", 1);
	queueing = require_text(report, "\nQueueing:", 2);
	phases = require_text(report, "\nDecision phase timing:", 3);
	helper_intro = require_text(report, "\nLazy helper attribution:", 4);
	drivers = require_text(report,
		"\nLazy helper attribution by driver:", 5);
	helpers = require_text(report,
		"\nCombined lazy helper attribution:", 6);
	observations = require_text(report, "\nDerived observations:", 35);
	detailed = require_text(report,
		"\nDetailed stage timing, sorted by total time:", 7);
	tail = require_text(report, "\nStage tail summary:", 8);
	not_observed = require_text(report, "\nNot observed:", 9);
	notes = require_text(report, "\nNotes:", 10);

	CHECK(overall < queueing && queueing < phases &&
	      phases < helper_intro && helper_intro < drivers &&
	      drivers < helpers &&
	      helpers < observations && observations < detailed &&
	      detailed < tail && tail < not_observed &&
	      not_observed < notes, 11,
	      "[ERROR:11] report sections are out of order");
	require_text(report, "max queue depth: 7", 12);
	require_text(detailed, "decision:total", 30);
	require_text(report, "event_build", 13);
	require_text(report, "evaluation", 14);
	require_text(report, "response", 15);
	require_text(report, "syslog/debug-heavy", 16);
	require_text(report, "mime_detection:libmagic_fallback", 17);
	require_text(report, "mime_detection:fast_classification    4.00 ms",
		     40);
	require_text(report, "trust_db_lookup:lock_wait", 18);
	reject_text(report, "metrics:", 19);
	require_text(report, "tail: >10ms", 20);
	require_text(report, "hash_ima is rare but expensive", 21);
	require_text(report, "hash_sha is rare but expensive", 41);
	require_text(report, "evaluation:hash_sha:total", 42);
	require_text(report, "trust DB lock wait is negligible", 22);
	require_text(report, "active logical driver: evaluation or response",
		     23);
	require_text(report,
		     "Queueing was low with small bursts: max queue "
		     "depth 7 of 40 (17.5%), p95 wait <=100us, max wait "
		     "314 ms.",
		     36);
	require_text(report,
		     "Largest manual/debug phase contributor: response",
		     37);
	require_text(report,
		     "Largest daemon-relevant decision phase contributor: evaluation",
		     38);
	reject_text(report, "other:", 31);
	reject_text(report, "Other total", 32);
	reject_text(report, ">100ms 0/", 33);
	reject_text(report, ">250ms 0/", 34);
	reject_text(report, "Stage timings may be nested", 39);
}

/*
 * test_sparse_report - verify missing queue and helper rows are stable.
 * Returns nothing.
 */
static void test_sparse_report(void)
{
	const struct report_case test = {
		.samples = sparse_samples,
		.sample_count = ARRAY_SIZE(sparse_samples),
		.input = &sparse_input,
	};
	char report[8192];

	read_test_report(&test, report, sizeof(report));
	require_text(report, "\nQueueing:\n  not observed\n  max queue depth: 0",
		     24);
	require_text(report, "\nLazy helper attribution by driver:", 25);
	require_text(report, "\nCombined lazy helper attribution:", 26);
	require_text(report, "  not observed", 27);
	reject_text(report, "Response note:", 28);
	reject_text(report, "syslog/debug-heavy", 29);
}

/*
 * test_missing_input - verify unavailable run-level input is deterministic.
 * Returns nothing.
 */
static void test_missing_input(void)
{
	const struct report_case test = {
		.samples = sparse_samples,
		.sample_count = ARRAY_SIZE(sparse_samples),
		.input = NULL,
	};
	char report[8192];

	read_test_report(&test, report, sizeof(report));
	require_text(report, "max queue depth: 0", 30);
}

/*
 * main - run timing report formatting tests.
 * Returns 0 on success. Exits with error() on test failure.
 */
int main(void)
{
	test_full_report();
	test_sparse_report();
	test_missing_input();
	return 0;
}
