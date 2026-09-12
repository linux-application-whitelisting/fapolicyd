/* Verify load-time filter warnings independently of per-path tracing. */
#include "config.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "filter.h"
#include "message.h"

#ifndef TEST_BASE
#define TEST_BASE "."
#endif

static FILE *messages;
static unsigned int warnings;

/* Capture warning delivery through the logger used by both daemon and CLI. */
void __wrap_msg(int priority, const char *fmt, ...)
{
	va_list ap;

	if (priority != LOG_WARNING || messages == NULL)
		return;
	warnings++;
	va_start(ap, fmt);
	vfprintf(messages, fmt, ap);
	va_end(ap);
	fputc('\n', messages);
}

struct diagnostic_case {
	const char *name;
	const char *rules;
	const char *warning;
	unsigned int count;
	int load_result;
};

/* Load a case, check warnings before matching, then check tracing isolation.
 * A NULL rules string selects the shipped configuration. Return 0 or 1.
 */
static int run_case(const struct diagnostic_case *test)
{
	char name[] = "/tmp/fapolicyd-filter-diagnostics-XXXXXX";
	const char *path = TEST_BASE "/init/fapolicyd-filter.conf";
	char *output = NULL;
	size_t size = 0;
	int rc = 1;

	if (test->rules) {
		int fd = mkstemp(name);
		FILE *f;

		if (fd == -1)
			return 1;
		f = fdopen(fd, "w");
		if (f == NULL) {
			close(fd);
			unlink(name);
			return 1;
		}
		int failed = fputs(test->rules, f) == EOF;
		if (fclose(f) != 0 || failed) {
			unlink(name);
			return 1;
		}
		path = name;
	}

	messages = open_memstream(&output, &size);
	if (messages == NULL)
		goto out;
	warnings = 0;
	filter_set_trace(NULL);
	if (filter_init())
		goto close;
	if (filter_load_file(path) != test->load_result)
		goto destroy;
	fflush(messages);
	/* No tracing has been enabled: daemon loads must also warn. */
	if (warnings != test->count ||
	    (test->count && (!strstr(output, path) ||
			    !strstr(output, test->warning) ||
			    !strstr(output, "If no child matches"))))
		goto destroy;
	if (!test->load_result) {
		/* This path never enters the suspicious scripts branch. */
		size_t before = size;
		filter_set_trace(messages);
		filter_rc_t result = filter_check("/elsewhere/file.conf");
		filter_set_trace(NULL);
		fflush(messages);
		if (result != FILTER_DENY || warnings != test->count ||
		    !strstr(output + before, "decision exclude\n"))
			goto destroy;
	}
	rc = 0;
destroy:
	filter_destroy();
close:
	fclose(messages);
	messages = NULL;
out:
	if (test->rules)
		unlink(name);
	if (rc)
		fprintf(stderr, "%s failed: %u warnings, output:\n%s\n",
			test->name, warnings, output ? output : "");
	free(output);
	return rc;
}

int main(void)
{
	static const struct diagnostic_case cases[] = {
		{ "scripts parent with source exceptions",
		  "# count comments and blank lines\n\n+ /\n - usr/src/*/\n"
		  "  + */scripts/*\n   - *.c\n   - *.h\n - *.conf\n",
		  ":5: rule '+ */scripts/*'", 1, 0 },
		{ "literal parent and multiple children",
		  "- /foo\n + bar\n + baz\n",
		  ":1: rule '- /foo'", 1, 0 },
		{ "multiple suspicious branches",
		  "+ /foo*\n - *.c\n- /bar*\n + *.py\n",
		  "has child rules but is not a directory rule", 2, 0 },
		{ "directory refinements including wildcard directories",
		  "- /\n + usr/src/*/\n  - scripts/\n   + *.py\n",
		  NULL, 0, 0 },
		{ "file and glob leaves",
		  "+ /usr/bin/tool\n+ /usr/share/*.py\n", NULL, 0, 0 },
		{ "invalid configuration is not validated as a complete tree",
		  "+ /foo*\n - *.c\n   + broken\n", NULL, 0, 1 },
		{ "shipped configuration", NULL, NULL, 0, 0 },
	};

	for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		if (run_case(&cases[i]))
			return 1;
	}
	return 0;
}
