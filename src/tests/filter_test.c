/*
 * filter_test.c - comprehensive tests for filter configuration
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <time.h>
#include <pthread.h>
#include <sys/stat.h>
#include <unistd.h>

#include "filter.h"

/*
 * Test strategy summary
 * ---------------------
 * This harness validates filter.c against both a minimal example
 * configuration and the full production filter.  Path/verdict pairs
 * are defined in src/tests/fixtures/filter-cases.txt; for each entry the
 * test:
 *   1. re‑initializes the filter,
 *   2. loads the designated filter file,
 *   3. checks that filter_check() returns the expected allow/deny
 *      result.
 * Coverage includes wildcard patterns, nested overrides, directory
 * versus file semantics, duplicate slashes, “..” traversal, UTF‑8
 * path segments, and other edge cases.
 *
 * Negative parsing: src/tests/fixtures/broken-filter.conf contains mixed
 * whitespace indentation, a missing leading ‘+’/‘-’, and an unescaped
 * ‘#’ to ensure filter_load_file() fails on malformed syntax.
 *
 * Performance guardrail: the production filter is parsed 1000 times,
 * measuring mean parse time via clock_gettime(). A warning is issued if
 * the average exceeds twice BASE_NS, allowing detection of significant
 * regressions.
 *
 * Additional safeguards: explicit checks ensure all fixture files are
 * present, filter_init() succeeds, and error messages provide unique
 * exit codes for CI triage.
 */


#define BASE_NS 7400

#ifndef TEST_BASE
#define TEST_BASE "."
#endif

#define CASES_FILE TEST_BASE "/src/tests/fixtures/filter-cases.txt"
#define MIN_CONF  TEST_BASE "/src/tests/fixtures/filter-minimal.conf"
#define BROKEN_CONF TEST_BASE "/src/tests/fixtures/broken-filter.conf"
#define PROD_CONF TEST_BASE "/init/fapolicyd-filter.conf"
#define CONCURRENT_FILTER_RULES 2048
#define CONCURRENT_FILTER_WORKERS 4
#define CONCURRENT_FILTER_ITERATIONS 200

extern filter_t *global_filter;

/* check_tree_reset - ensure processed and matched flags are cleared */
static int check_tree_reset(filter_t *f)
{
	if (!f)
		return 1;

	if (f->processed || f->matched)
		return 0;

	list_item_t *item = list_get_first(&f->list);
	for (; item; item = item->next) {
			if (!check_tree_reset((filter_t *)item->data))
				return 0;
	}

	return 1;
}

static int file_exists(const char *path)
{
	struct stat st;
	return stat(path, &st) == 0;
}

/* replace escape sequences like '\ ' */
static void unescape(char *s)
{
	char *src = s, *dst = s;
	while (*src) {
		if (*src == '\\' && src[1]) {
			++src;
			*dst++ = *src++;
		} else {
			*dst++ = *src++;
		}
	}
	*dst = '\0';
}

static int run_cases(const char *cfg, const char *path)
{
	FILE *f = fopen(CASES_FILE, "r");
	char col[32];
	char p[1024];
	int exp;
	int rc = 0;

	if (f == NULL) {
		fprintf(stderr, "[ERROR:6] missing %s\n", CASES_FILE);
		return 6;
	}

	while (fscanf(f, "%31s %1023s %d", col, p, &exp) == 3) {
		if (strcmp(col, cfg) != 0)
			continue;
		unescape(p);
		if (filter_init()) {
			fprintf(stderr, "[ERROR:2] filter_init failed\n");
			rc = 2;
			break;
		}
		if (filter_load_file(path)) {
			fprintf(stderr,
				"[ERROR:3] loading a valid fixture failed\n");
			filter_destroy();
			rc = 3;
			break;
		}
		int res = filter_check(p);
		if (!check_tree_reset(global_filter)) {
			fprintf(stderr,
			"[ERROR:7] filter flags not reset after filter_check\n");
			rc = 7;
			filter_destroy();
			break;
		}
		if (res != exp) {
			fprintf(stderr,
				"[ERROR:4] %s:%s expected %s got %s\n",
				cfg, p, exp ? "ALLOW" : "DENY",
				res ? "ALLOW" : "DENY");
			rc = 4;
			filter_destroy();
			break;
		}
		filter_destroy();
	}

	fclose(f);
	return rc;
}

/*
 * run_wide_tree_case - verify wide root trees do not hit depth errors
 * Returns 0 on success and a unique non-zero test code on failure.
 */
static int run_wide_tree_case(void)
{
	char tmpl[] = "/tmp/fapolicyd-filter-wide-XXXXXX";
	int fd = mkstemp(tmpl);
	if (fd < 0) {
		fprintf(stderr, "[ERROR:8] cannot create temp file\n");
		return 8;
	}

	FILE *f = fdopen(fd, "w");
	if (!f) {
		close(fd);
		unlink(tmpl);
		fprintf(stderr, "[ERROR:9] cannot open temp file stream\n");
		return 9;
	}

	/*
	 * Create more than MAX_FILTER_DEPTH sibling rules at the root level.
	 * The checker pushes root descendants before matching, so this used to
	 * fail with FILTER_ERR_DEPTH when backed by a fixed-size stack.
	 */
	for (int i = 0; i < 80; i++) {
		if (fprintf(f, "+ /wide-%d\n", i) < 0) {
			fclose(f);
			unlink(tmpl);
			fprintf(stderr, "[ERROR:10] cannot write temp config\n");
			return 10;
		}
	}

	if (fprintf(f, "+ /target\n") < 0) {
		fclose(f);
		unlink(tmpl);
		fprintf(stderr, "[ERROR:10] cannot write temp config\n");
		return 10;
	}

	if (fclose(f) != 0) {
		unlink(tmpl);
		fprintf(stderr, "[ERROR:11] cannot close temp config\n");
		return 11;
	}

	if (filter_init()) {
		unlink(tmpl);
		fprintf(stderr, "[ERROR:2] filter_init failed\n");
		return 2;
	}
	if (filter_load_file(tmpl)) {
		filter_destroy();
		unlink(tmpl);
		fprintf(stderr, "[ERROR:3] loading wide fixture failed\n");
		return 3;
	}

	filter_rc_t res = filter_check("/target");
	if (!check_tree_reset(global_filter)) {
		filter_destroy();
		unlink(tmpl);
		fprintf(stderr,
			"[ERROR:7] filter flags not reset after filter_check\n");
		return 7;
	}

	filter_destroy();
	unlink(tmpl);

	if (res != FILTER_ALLOW) {
		fprintf(stderr,
			"[ERROR:12] wide tree expected ALLOW got %d\n", res);
		return 12;
	}

	return 0;
}

struct concurrent_filter_worker {
	const char *path;
	filter_rc_t expected;
	int failed;
};

struct concurrent_filter_observer {
	atomic_bool done;
	atomic_bool saw_mutation;
};

/*
 * concurrent_filter_worker - repeatedly check one path from a shared tree.
 * @arg: concurrent_filter_worker pointer describing the expected verdict.
 * Returns NULL.
 */
static void *concurrent_filter_worker(void *arg)
{
	struct concurrent_filter_worker *worker = arg;

	for (int i = 0; i < CONCURRENT_FILTER_ITERATIONS; i++) {
		if (filter_check(worker->path) != worker->expected) {
			worker->failed = 1;
			break;
		}
	}

	return NULL;
}

/*
 * concurrent_filter_observer - detect check-time mutations in the filter tree.
 * @arg: concurrent_filter_observer pointer.
 * Returns NULL.
 */
static void *concurrent_filter_observer(void *arg)
{
	struct concurrent_filter_observer *observer = arg;

	while (!atomic_load_explicit(&observer->done, memory_order_relaxed)) {
		if (!check_tree_reset(global_filter)) {
			atomic_store_explicit(&observer->saw_mutation, true,
					      memory_order_relaxed);
			break;
		}
	}

	return NULL;
}

/*
 * run_concurrent_check_case - verify filter checks are read-only tree walks.
 *
 * Trust-source imports are normally serialized today, but the compiled filter
 * is shared library state. Future import backends can safely share one loaded
 * filter generation only if checking a path does not write traversal state
 * into the tree itself.
 *
 * Returns 0 on success and a unique non-zero test code on failure.
 */
static int run_concurrent_check_case(void)
{
	struct concurrent_filter_worker worker[CONCURRENT_FILTER_WORKERS] = {
		{ "/target", FILTER_ALLOW, 0 },
		{ "/wide-9999", FILTER_DENY, 0 },
		{ "/wide-0100", FILTER_ALLOW, 0 },
		{ "/wide-2047", FILTER_ALLOW, 0 },
	};
	struct concurrent_filter_observer observer = { 0 };
	pthread_t workers[CONCURRENT_FILTER_WORKERS];
	pthread_t observer_thread;
	char tmpl[] = "/tmp/fapolicyd-filter-concurrent-XXXXXX";
	int fd = mkstemp(tmpl);
	int rc = 0;

	if (fd < 0) {
		fprintf(stderr, "[ERROR:13] cannot create temp file\n");
		return 13;
	}

	FILE *f = fdopen(fd, "w");
	if (!f) {
		close(fd);
		unlink(tmpl);
		fprintf(stderr, "[ERROR:14] cannot open temp file stream\n");
		return 14;
	}

	for (int i = 0; i < CONCURRENT_FILTER_RULES; i++) {
		if (fprintf(f, "+ /wide-%04d\n", i) < 0) {
			fclose(f);
			unlink(tmpl);
			fprintf(stderr, "[ERROR:15] cannot write temp config\n");
			return 15;
		}
	}

	if (fprintf(f, "+ /target\n") < 0) {
		fclose(f);
		unlink(tmpl);
		fprintf(stderr, "[ERROR:15] cannot write temp config\n");
		return 15;
	}

	if (fclose(f) != 0) {
		unlink(tmpl);
		fprintf(stderr, "[ERROR:16] cannot close temp config\n");
		return 16;
	}

	if (filter_init()) {
		unlink(tmpl);
		fprintf(stderr, "[ERROR:2] filter_init failed\n");
		return 2;
	}

	if (filter_load_file(tmpl)) {
		filter_destroy();
		unlink(tmpl);
		fprintf(stderr,
			"[ERROR:3] loading concurrent fixture failed\n");
		return 3;
	}

	if (pthread_create(&observer_thread, NULL,
			   concurrent_filter_observer, &observer)) {
		filter_destroy();
		unlink(tmpl);
		fprintf(stderr, "[ERROR:17] cannot create observer thread\n");
		return 17;
	}

	for (int i = 0; i < CONCURRENT_FILTER_WORKERS; i++) {
		if (pthread_create(&workers[i], NULL,
				   concurrent_filter_worker, &worker[i])) {
			atomic_store_explicit(&observer.done, true,
					      memory_order_relaxed);
			pthread_join(observer_thread, NULL);
			filter_destroy();
			unlink(tmpl);
			fprintf(stderr, "[ERROR:18] cannot create worker\n");
			return 18;
		}
	}

	for (int i = 0; i < CONCURRENT_FILTER_WORKERS; i++)
		pthread_join(workers[i], NULL);
	atomic_store_explicit(&observer.done, true, memory_order_relaxed);
	pthread_join(observer_thread, NULL);

	for (int i = 0; i < CONCURRENT_FILTER_WORKERS; i++) {
		if (worker[i].failed) {
			fprintf(stderr,
				"[ERROR:19] concurrent filter verdict changed\n");
			rc = 19;
			break;
		}
	}

	if (rc == 0 &&
	    atomic_load_explicit(&observer.saw_mutation,
				 memory_order_relaxed)) {
		fprintf(stderr,
			"[ERROR:20] filter_check mutated shared tree state\n");
		rc = 20;
	}

	filter_destroy();
	unlink(tmpl);

	return rc;
}

int main(void)
{
	if (!file_exists(MIN_CONF)) {
		fprintf(stderr, "[ERROR:6] missing %s\n", MIN_CONF);
		return 6;
	}
	if (!file_exists(PROD_CONF)) {
		fprintf(stderr, "[ERROR:6] missing %s\n", PROD_CONF);
		return 6;
	}
	if (!file_exists(CASES_FILE)) {
		fprintf(stderr, "[ERROR:6] missing %s\n", CASES_FILE);
		return 6;
	}
	if (!file_exists(BROKEN_CONF)) {
		fprintf(stderr, "[ERROR:6] missing %s\n", BROKEN_CONF);
		return 6;
	}

	if (filter_init()) {
		fprintf(stderr, "[ERROR:2] filter_init failed\n");
		return 2;
	}
	if (!filter_load_file(BROKEN_CONF)) {
		fprintf(stderr,
		    "[ERROR:5] malformed filter did not fail as expected\n");
		filter_destroy();
		return 5;
	}
	filter_destroy();

	int rc = run_cases("minimal", MIN_CONF);
	if (rc)
		return rc;
	rc = run_cases("prod", PROD_CONF);
	if (rc)
		return rc;
	rc = run_wide_tree_case();
	if (rc)
		return rc;
	rc = run_concurrent_check_case();
	if (rc)
		return rc;

	struct timespec s, e;
	clock_gettime(CLOCK_MONOTONIC, &s);
	for (int i = 0; i < 1000; i++) {
		if (filter_init()) {
			fprintf(stderr, "[ERROR:2] filter_init failed\n");
			return 2;
		}
		if (filter_load_file(PROD_CONF)) {
			fprintf(stderr,
				"[ERROR:3] loading a valid fixture failed\n");
			filter_destroy();
			return 3;
		}
		filter_destroy();
	}
	clock_gettime(CLOCK_MONOTONIC, &e);
	long avg = ((e.tv_sec - s.tv_sec) * 1000000000L +
			(e.tv_nsec - s.tv_nsec)) / 1000;
	// The point of this test is to spot something wrong in the
	// parser that might loop way too long. Calling it a warning
	// since build systems vary in speed.
	if (avg > 2 * BASE_NS) {
		fprintf(stderr, "[WARNING:4] prod parse %ldns exceeds %dns\n",
			avg, 2 * BASE_NS);
	}

	return 0;
}
