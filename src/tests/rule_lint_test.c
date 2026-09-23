/* Verify policy linter diagnostics for misleading rule fields. */
#include "config.h"

#include <error.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "message.h"

#include "../cli/rule-lint.c"

struct lint_case {
	const char *name;
	const char *rule;
	const char *warning;
};

/*
 * append_rule - add an immutable test rule to a parsed rule list.
 * @rules: rule list under construction.
 * @text: rule or set definition to parse.
 * @lineno: source line assigned to the parsed rule.
 * Returns nothing; exits the test on parse or allocation failure.
 */
static void append_rule(llist *rules, const char *text, unsigned int lineno)
{
	char *copy = strdup(text);

	if (!copy)
		error(1, errno, "strdup failed");
	if (rules_append(rules, copy, lineno)) {
		free(copy);
		error(1, 0, "rule parse failed at line %u", lineno);
	}
	free(copy);
}

/*
 * capture_lint - run the policy linter and capture its stderr diagnostics.
 * @rules: parsed rule list to lint.
 * @output: destination for a heap-allocated diagnostic string.
 * Returns the linter result. Exits the test when capture setup fails.
 */
static int capture_lint(const llist *rules, char **output)
{
	FILE *capture;
	long length;
	int rc, saved_stderr;

	*output = NULL;
	capture = tmpfile();
	if (!capture)
		error(1, errno, "tmpfile failed");
	saved_stderr = dup(STDERR_FILENO);
	if (saved_stderr == -1)
		error(1, errno, "dup failed");
	fflush(stderr);
	if (dup2(fileno(capture), STDERR_FILENO) == -1)
		error(1, errno, "dup2 failed");

	rc = lint_rules_policy(rules, "/tmp/test.rules", 0);

	fflush(stderr);
	if (dup2(saved_stderr, STDERR_FILENO) == -1)
		error(1, errno, "dup2 restore failed");
	close(saved_stderr);
	if (fseek(capture, 0, SEEK_END))
		error(1, errno, "fseek failed");
	length = ftell(capture);
	if (length < 0)
		error(1, errno, "ftell failed");
	if (fseek(capture, 0, SEEK_SET))
		error(1, errno, "fseek failed");
	*output = calloc((size_t)length + 1, 1);
	if (!*output)
		error(1, errno, "calloc failed");
	if (length && fread(*output, 1, (size_t)length, capture) !=
			(size_t)length)
		error(1, errno, "capture read failed");
	fclose(capture);
	return rc;
}

/*
 * run_case - lint one rule inside an otherwise complete policy.
 * @test: rule and expected warning substring.
 * Returns 0 on success and 1 on a mismatched diagnostic.
 */
static int run_case(const struct lint_case *test)
{
	char *output;
	llist rules;
	int rc, failed = 0;

	if (rules_create(&rules))
		error(1, 0, "rules_create failed");
	append_rule(&rules, "%languages=text/x-python", 1);
	append_rule(&rules, test->rule, 2);
	append_rule(&rules,
		"deny_syslog perm=open all : ftype=%languages", 3);
	append_rule(&rules, "deny_syslog perm=execute all : all", 4);
	append_rule(&rules, "allow perm=open all : all", 5);

	rc = capture_lint(&rules, &output);
	if (test->warning) {
		if (rc == 0 || !strstr(output, test->warning))
			failed = 1;
	} else if (rc != 0 || output[0] != '\0')
		failed = 1;

	if (failed)
		fprintf(stderr, "%s failed (rc=%d):\n%s\n", test->name, rc,
			output);
	free(output);
	rules_clear(&rules);
	return failed;
}

int main(void)
{
	static const struct lint_case cases[] = {
		{ "object all with constraints",
		  "allow perm=any all : dir=/opt/tool/ all",
		  "object all in rule 1 at /tmp/test.rules:2 is redundant" },
		{ "subject all with constraints",
		  "allow perm=any exe=/usr/bin/git all : ftype=text/x-perl",
		  "subject all in rule 1 at /tmp/test.rules:2 is redundant" },
		{ "untrusted object allow",
		  "allow perm=open all : path=/tmp/plugin trust=0",
		  "object trust=0 in allow rule 1 at /tmp/test.rules:2" },
		{ "untrusted subject allow",
		  "allow perm=open uid=1000 trust=0 : all",
		  "subject trust=0 in allow rule 1 at /tmp/test.rules:2" },
		{ "object directory prefix",
		  "deny perm=open all : dir=/tmp/ansible",
		  "object dir prefix '/tmp/ansible'" },
		{ "subject directory prefix",
		  "deny perm=open dir=/tmp/ansible : all",
		  "subject dir prefix '/tmp/ansible'" },
		{ "intentional constrained allow",
		  "allow perm=open all : dir=/opt/tool/ trust=1", NULL },
	};

	set_message_mode(MSG_STDERR, DBG_NO);
	for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
		if (run_case(&cases[i]))
			return 1;

	return 0;
}
