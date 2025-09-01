/*
 * filter_test.c - comprehensive tests for filter configuration
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>

#include "filter.h"

/*
 * Test strategy summary
 * ---------------------
 * This harness validates filter.c against both a minimal example
 * configuration and the full production filter.  Path/verdict pairs
 * are defined in tests/fixtures/filter-cases.txt; for each entry the
 * test:
 *   1. re‑initializes the filter,
 *   2. loads the designated filter file,
 *   3. checks that filter_check() returns the expected allow/deny
 *      result.
 * Coverage includes wildcard patterns, nested overrides, directory
 * versus file semantics, duplicate slashes, “..” traversal, UTF‑8
 * path segments, and other edge cases.
 *
 * Negative parsing: tests/fixtures/broken-filter.conf contains mixed
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

#define CASES_FILE TEST_BASE "/tests/fixtures/filter-cases.txt"
#define MIN_CONF  TEST_BASE "/tests/fixtures/filter-minimal.conf"
#define BROKEN_CONF TEST_BASE "/tests/fixtures/broken-filter.conf"
#define PROD_CONF TEST_BASE "/init/fapolicyd-filter.conf"

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

