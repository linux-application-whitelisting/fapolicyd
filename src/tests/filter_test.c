/*
 * filter_test.c - comprehensive tests for filter configuration
 */
#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <time.h>
#include <pthread.h>
#include <sys/stat.h>
#include <unistd.h>
#include <ctype.h>

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
 * Kernel script/tool exceptions require a version directory; .c/.h source
 * files under those exceptions remain excluded by the production filter.
 *
 * Fixture rows are read one line at a time so escaped spaces in paths cannot
 * silently truncate the suite. Malformed rows fail with a line number.
 *
 * Additional configurations exercise conflicting sibling rules, ancestor
 * changes, parent fallback and literal/glob leaves, with exact trace checks.
 * Invalid indentation and missing rule signs are tested independently so an
 * earlier error cannot hide a later case in a malformed configuration.
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

/*
 * parse_case - split one fixture row in place, preserving escaped whitespace.
 * Outputs the configuration name, decoded path and expected 0/1 verdict.
 * Returns 0 for a complete valid row and 1 for malformed test input.
 */
static int parse_case(char *line, char **cfg, char **path, int *expected)
{
	char *end;

	*cfg = line + strspn(line, " \t");
	end = strpbrk(*cfg, " \t");
	if (end == NULL)
		return 1;
	*end++ = '\0';
	if (strcmp(*cfg, "minimal") && strcmp(*cfg, "prod"))
		return 1;
	*path = end + strspn(end, " \t");
	for (end = *path; *end && !isspace((unsigned char)*end); end++) {
		if (*end == '\\') {
			if (!end[1] || end[1] == '\n')
				return 1;
			end++;
		}
	}
	if (end == *path || *end == '\0')
		return 1;
	*end++ = '\0';
	end += strspn(end, " \t");
	if ((*end != '0' && *end != '1') ||
	    end[1 + strspn(end + 1, " \t\r\n")] != '\0')
		return 1;
	*expected = *end - '0';
	unescape(*path);
	return 0;
}

/* Check fixture parsing against valid and malformed rows; return 0 or 23. */
static int run_fixture_reader_cases(void)
{
	static const struct {
		const char *row;
		const char *cfg;
		const char *path;
		int expected;
	} cases[] = {
		{ "minimal /etc/hosts 1\n", "minimal", "/etc/hosts", 1 },
		{ "prod /usr/share/space\\ file.py 1\n",
		  "prod", "/usr/share/space file.py", 1 },
		{ "\tprod\t/usr/share/手稿.lua\t0\r\n",
		  "prod", "/usr/share/手稿.lua", 0 },
		{ "prod /trailing\\  0", "prod", "/trailing ", 0 },
		{ "prod /missing-verdict\n", NULL, NULL, 0 },
		{ "prod /invalid 2\n", NULL, NULL, 0 },
		{ "prod /invalid 1 extra\n", NULL, NULL, 0 },
		{ "prod /unescaped space 1\n", NULL, NULL, 0 },
		{ "unknown /file 1\n", NULL, NULL, 0 },
		{ "prod /dangling\\\n", NULL, NULL, 0 },
		{ "\n", NULL, NULL, 0 },
	};

	for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		char *row = strdup(cases[i].row);
		char *cfg, *path;
		int expected, rc;

		if (row == NULL)
			return 23;
		rc = parse_case(row, &cfg, &path, &expected);
		if ((rc == 0) != (cases[i].cfg != NULL) ||
		    (rc == 0 && (strcmp(cfg, cases[i].cfg) ||
				 strcmp(path, cases[i].path) ||
				 expected != cases[i].expected))) {
			fprintf(stderr, "[ERROR:23] fixture reader case %zu\n", i);
			free(row);
			return 23;
		}
		free(row);
	}
	return 0;
}

/* Run every row for cfg from the fixture file; return 0 or a test error. */
static int run_cases(const char *cfg, const char *path)
{
	FILE *f = fopen(CASES_FILE, "r");
	char *line = NULL;
	size_t capacity = 0, lineno = 0, count = 0;
	int exp;
	int rc = 0;

	if (f == NULL) {
		fprintf(stderr, "[ERROR:6] missing %s\n", CASES_FILE);
		return 6;
	}

	while (getline(&line, &capacity, f) != -1) {
		char *col, *p;

		lineno++;
		if (parse_case(line, &col, &p, &exp)) {
			fprintf(stderr, "[ERROR:22] malformed fixture %s:%zu\n",
				CASES_FILE, lineno);
			rc = 22;
			break;
		}
		if (strcmp(col, cfg) != 0)
			continue;
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
		count++;
	}

	if (rc == 0 && (!feof(f) || count == 0)) {
		fprintf(stderr, "[ERROR:22] incomplete or empty %s cases\n", cfg);
		rc = 22;
	}
	if (rc == 0)
		printf("%s: %zu fixture cases passed\n", cfg, count);
	free(line);
	fclose(f);
	return rc;
}

struct filter_case {
	const char *path;
	filter_rc_t expected;
	const char *trace;
};

/* Load an isolated configuration; return -1 for setup errors or loader status. */
static int load_filter_text(const char *rules)
{
	char tmpl[] = "/tmp/fapolicyd-filter-case-XXXXXX";
	int fd = mkstemp(tmpl);
	FILE *f;
	int rc;

	if (fd < 0)
		return -1;
	f = fdopen(fd, "w");
	if (f == NULL) {
		close(fd);
		unlink(tmpl);
		return -1;
	}
	rc = fputs(rules, f) == EOF;
	if (fclose(f) != 0)
		rc = 1;
	if (rc || filter_init()) {
		unlink(tmpl);
		return -1;
	}
	rc = filter_load_file(tmpl);
	unlink(tmpl);
	return rc;
}

/* Check a verdict, optional exact trace and tree flags; return 0 or 24. */
static int check_filter_case(const char *name, const struct filter_case *test)
{
	char *trace = NULL;
	size_t size = 0;
	FILE *f = NULL;
	int rc = 0;
	filter_rc_t result;

	if (test->trace) {
		f = open_memstream(&trace, &size);
		if (f == NULL)
			return 24;
	}
	filter_set_trace(f);
	result = filter_check(test->path);
	filter_set_trace(NULL);
	if (f && fclose(f) != 0)
		rc = 24;
	if (result != test->expected || !check_tree_reset(global_filter)) {
		fprintf(stderr, "[ERROR:24] %s:%s expected %d got %d\n",
			name, test->path, test->expected, result);
		rc = 24;
	}
	if (rc == 0 && test->trace && strcmp(trace, test->trace)) {
		fprintf(stderr,
			"[ERROR:24] %s:%s trace mismatch\nExpected:\n%sGot:\n%s",
			name, test->path, test->trace, trace);
		rc = 24;
	}
	free(trace);
	return rc;
}

/*
 * run_traversal_cases - check import decisions independently of tree layout.
 * Conflicting rules make reversed order observable. Mixed ancestor changes
 * expose stale parents, offsets or matched flags. Repeat paths in reverse
 * order on the same tree to check that earlier queries leave no state behind.
 * Returns 0 on success or 24 on a setup, verdict, trace or tree-state error.
 */
static int run_traversal_cases(void)
{
	const struct {
		const char *name;
		const char *rules;
		const struct filter_case *cases;
	} scenarios[] = {
		{ "top-level precedence",
		  "- /usr/share/cache/*\n+ /usr/share/*\n"
		  "+ /usr/bin/tool\n- /usr/bin/*\n",
		  (const struct filter_case[]) {
			{ "/usr/share/cache/keep.py", FILTER_DENY,
			  "deny /usr/share/cache/* match\n"
			  "deciding rule: deny /usr/share/cache/* (leaf match)\n"
			  "decision exclude\n" },
			{ "/usr/share/script.py", FILTER_ALLOW,
			  "deny /usr/share/cache/* no match\n"
			  "allow /usr/share/* match\n"
			  "deciding rule: allow /usr/share/* (leaf match)\n"
			  "decision include\n" },
			{ "/usr/bin/tool", FILTER_ALLOW, NULL },
			{ "/usr/bin/tool-extra", FILTER_DENY, NULL },
			{ "/opt/unknown", FILTER_DENY, NULL },
			{ NULL, 0, NULL }
		  } },
		{ "nested precedence",
		  "- /\n + usr/\n  - share/cache/*\n  + share/*\n"
		  "  + bin/tool\n  - bin/*\n",
		  (const struct filter_case[]) {
			{ "/usr/share/cache/keep.py", FILTER_DENY, NULL },
			{ "/usr/share/script.py", FILTER_ALLOW,
			  "deny / match\nallow usr/ match\n"
			  "deny share/cache/* no match\n"
			  "allow share/* match\n"
			  "deciding rule: allow share/* (leaf match)\n"
			  "decision include\n" },
			{ "/usr/bin/tool", FILTER_ALLOW, NULL },
			{ "/usr/bin/tool-extra", FILTER_DENY, NULL },
			{ "/usr/other", FILTER_ALLOW, NULL },
			{ "/opt/unknown", FILTER_DENY, NULL },
			{ NULL, 0, NULL }
		  } },
		{ "ancestor changes and parent fallback",
		  "- /\n + usr/\n  - share/\n   + scripts/\n"
		  "    - private/\n   + public/\n  - lib/\n"
		  "   + plugins/\n    - *.debug\n   + scripts/\n"
		  " + opt/\n  - cache/\n   + keep\n",
		  (const struct filter_case[]) {
			{ "/usr/share/scripts/tool", FILTER_ALLOW, NULL },
			{ "/usr/share/scripts/private/secret", FILTER_DENY, NULL },
			{ "/usr/share/public/info", FILTER_ALLOW, NULL },
			{ "/usr/share/other", FILTER_DENY, NULL },
			{ "/usr/lib/plugins/module.so", FILTER_ALLOW, NULL },
			{ "/usr/lib/plugins/module.debug", FILTER_DENY,
			  "deny / match\nallow usr/ match\ndeny share/ no match\n"
			  "deny lib/ match\nallow plugins/ match\n"
			  "deny *.debug match\n"
			  "deciding rule: deny *.debug (leaf match)\n"
			  "decision exclude\n" },
			{ "/usr/lib/scripts/tool", FILTER_ALLOW,
			  "deny / match\nallow usr/ match\ndeny share/ no match\n"
			  "deny lib/ match\nallow plugins/ no match\n"
			  "allow scripts/ match\n"
			  "deciding rule: allow scripts/ (directory fallback)\n"
			  "decision include\n" },
			{ "/usr/lib/other", FILTER_DENY, NULL },
			{ "/usr/bin/tool", FILTER_ALLOW, NULL },
			{ "/opt/cache/keep", FILTER_ALLOW, NULL },
			{ "/opt/cache/keep-extra", FILTER_DENY, NULL },
			{ "/opt/cache/temp", FILTER_DENY, NULL },
			{ "/opt/tool", FILTER_ALLOW, NULL },
			{ "/other", FILTER_DENY, NULL },
			{ NULL, 0, NULL }
		  } },
		{ "literal, glob and directory leaves",
		  "+ /opt/tool\n+ /opt/plugins/*.so\n+ /srv/data/\n",
		  (const struct filter_case[]) {
			{ "/opt/tool", FILTER_ALLOW,
			  "allow /opt/tool match\n"
			  "deciding rule: allow /opt/tool (leaf match)\n"
			  "decision include\n" },
			{ "/opt/tool-extra", FILTER_DENY, NULL },
			{ "/opt/tool/child", FILTER_DENY, NULL },
			{ "/opt/plugins/module.so", FILTER_ALLOW,
			  "allow /opt/tool no match\nallow /opt/plugins/*.so match\n"
			  "deciding rule: allow /opt/plugins/*.so (leaf match)\n"
			  "decision include\n" },
			{ "/opt/plugins/module.so.debug", FILTER_DENY, NULL },
			{ "/srv/data", FILTER_DENY, NULL },
			{ "/srv/data/", FILTER_ALLOW, NULL },
			{ "/srv/data/item", FILTER_ALLOW, NULL },
			{ "/srv/database/item", FILTER_DENY, NULL },
			{ "", FILTER_DENY, NULL },
			{ NULL, 0, NULL }
		  } },
		{ "non-directory parent has no fallback",
		  "- /\n + opt\n  + /keep\n",
		  (const struct filter_case[]) {
			{ "/opt/keep", FILTER_ALLOW, NULL },
			{ "/opt/other", FILTER_DENY,
			  "deny / match\nallow opt match\nallow /keep no match\n"
			  "deciding rule: deny / (directory fallback)\n"
			  "decision exclude\n" },
			{ "/opt", FILTER_DENY, NULL },
			{ NULL, 0, NULL }
		  } },
		{ "empty tree", "",
		  (const struct filter_case[]) {
			{ "/anything", FILTER_DENY, "default: exclude\ndecision exclude\n" },
			{ NULL, 0, NULL }
		  } },
	};

	for (size_t i = 0; i < sizeof(scenarios) / sizeof(scenarios[0]); i++) {
		const struct filter_case *cases = scenarios[i].cases;
		size_t count = 0;
		int rc = 0;

		if (load_filter_text(scenarios[i].rules)) {
			fprintf(stderr, "[ERROR:24] loading %s\n", scenarios[i].name);
			filter_destroy();
			return 24;
		}
		while (cases[count].path)
			count++;
		for (size_t n = 0; n < 2 * count; n++) {
			size_t index = n < count ? n : 2 * count - n - 1;

			rc = check_filter_case(scenarios[i].name, &cases[index]);
			if (rc)
				break;
		}
		filter_destroy();
		if (rc)
			return rc;
	}
	return 0;
}

/* Reject each malformed configuration independently; return 0 or 25. */
static int run_invalid_indentation_cases(void)
{
	static const struct {
		const char *name;
		const char *rules;
	} cases[] = {
		{ "indented first rule", " + /usr/\n" },
		{ "skipped child level", "+ /\n  - usr/\n" },
		{ "jump after dedent",
		  "+ /\n + usr/\n  - share/\n + opt/\n   + cache/\n" },
		{ "missing sign", "+ /\nusr/share/\n" },
		{ "tab indentation", "+ /\n\t- usr/\n" },
	};

	for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		int rc = load_filter_text(cases[i].rules);

		/* Failed loads still own a partial tree which must be safe to free. */
		filter_destroy();
		if (rc != 1) {
			fprintf(stderr, "[ERROR:25] %s: load returned %d\n",
				cases[i].name, rc);
			return 25;
		}
	}
	return 0;
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

	int rc = run_fixture_reader_cases();
	if (rc)
		return rc;
	rc = run_traversal_cases();
	if (rc)
		return rc;
	rc = run_invalid_indentation_cases();
	if (rc)
		return rc;
	rc = run_cases("minimal", MIN_CONF);
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
