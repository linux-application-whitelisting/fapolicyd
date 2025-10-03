/*
* rules_test.c - verify parsing and evaluation of policy rules
*
* Test strategy summary
* ---------------------
* This harness exercises the rule parser and evaluator for:
*   1. direct values and %set references
*   2. rule_evaluate() subject/object matching
*   3. error paths: undefined sets and type mismatches
*
* Valid rules live in src/tests/fixtures/rules-valid.rules.  Each line is
* fed through rules_append() to mimic fagenrules processing.  Negative
* cases are described in the err_cases array below; QE can extend
* coverage by appending new entries.
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <error.h>
#include <stdatomic.h>

#include "attr-sets.h"
#include "conf.h"
#include "rules.h"
#include "subject.h"
#include "object.h"
#include "event.h"
#include "message.h"

#define ERRBUF 4096

#ifndef TEST_BASE
#define TEST_BASE "."
#endif

#define VALID_RULES TEST_BASE "/src/tests/fixtures/rules-valid.rules"

/* globals expected by library code */
conf_t config;
int debug_mode;
atomic_bool stop;

/* definition of a negative parsing test */
struct err_case {
	const char *lines[3];
	const char *expect;
};

static const struct err_case errors[] = {
	{
	{ "allow perm=any auid=%missing : path=/bin/ls", NULL },
	"set 'missing' was not defined before"
	},
	{
	{ "%strs=foo,bar",
	  "allow perm=any auid=%strs : path=/bin/ls",
	  NULL },
	"cannot assign %strs which has STRING type to auid (UNSIGNED expected)"
	},
	{
	{ "%nums=1,2",
	  "allow perm=any all : path=%nums",
	  NULL },
	"SIGNED set nums to the STRING attribute"
	}
};

/*
* append_capture - invoke rules_append() while capturing stderr
*
* l:	rule list
* line: rule text
* ln:	line number for error reporting
* buf: destination buffer for any message emitted
*/
static int append_capture(llist *l, const char *line, unsigned ln,
						char *buf, size_t buflen)
{
	int p[2];
	if (pipe(p))
		error(1, errno, "pipe failed");

	fflush(stderr);
	int save = dup(STDERR_FILENO);
	if (save == -1)
		error(1, errno, "dup failed");
	if (dup2(p[1], STDERR_FILENO) == -1)
		error(1, errno, "dup2 failed");
	close(p[1]);

	char *tmp = strdup(line);
	if (!tmp)
		error(1, errno, "strdup failed");
	int rc = rules_append(l, tmp, ln);
	free(tmp);

	fflush(stderr);
	if (dup2(save, STDERR_FILENO) == -1)
		error(1, errno, "dup2 restore failed");
	close(save);

	ssize_t r = read(p[0], buf, buflen - 1);
	if (r < 0)
		r = 0;
	buf[r] = '\0';
	close(p[0]);
	return rc;
}

/*
* prep_event - allocate and populate an event for evaluation
*/
static void prep_event(event_t *e, unsigned int auid, const char *path)
{
	e->s = malloc(sizeof(s_array));
	e->o = malloc(sizeof(o_array));
	if (!e->s || !e->o)
		error(1, errno, "malloc failed");

	subject_create(e->s);
	object_create(e->o);

	e->s->info = calloc(1, sizeof(struct proc_info));
	if (!e->s->info)
		error(1, errno, "calloc failed");

	subject_attr_t sattr = { .type = AUID, .uval = auid };
	if (subject_add(e->s, &sattr))
		error(1, 0, "subject_add failed");

	object_attr_t oattr = { .type = PATH, .o = strdup(path) };
	if (!oattr.o)
		error(1, errno, "strdup failed");
	if (object_add(e->o, &oattr))
		error(1, 0, "object_add failed");
	e->type = 0;
}

/*
* free_event - release memory from prep_event()
*/
static void free_event(event_t *e)
{
	subject_clear(e->s);
	object_clear(e->o);
	free(e->s);
	free(e->o);
}

/*
* load_fixture - parse rule lines from a fixture file
*/
static void load_fixture(const char *path, llist *l)
{
	char err[ERRBUF];
	FILE *f = fopen(path, "r");
	char line[256];
	unsigned ln = 1;

	if (!f)
		error(1, errno, "open %s", path);

	while (fgets(line, sizeof(line), f)) {
		line[strcspn(line, "\n")] = '\0';
		if (append_capture(l, line, ln, err, sizeof(err)))
			error(1, 0, "fixture parse failed line %u: %s", ln, err);
		ln++;
	}
	fclose(f);
}

/*
* evaluate - walk the rule list until a decision is reached
*/
static decision_t evaluate(const llist *l, event_t *e)
{
	lnode *cur;

	for (cur = l->head; cur; cur = cur->next) {
		decision_t d = rule_evaluate(cur, e);
		if (d != NO_OPINION)
			return d;
	}
	return NO_OPINION;
}

int main(void)
{
	char err[ERRBUF];
	llist l;
	event_t e;
	unsigned i, j;
	int rc;

	set_message_mode(MSG_STDERR, DBG_NO);

	/* positive path using fixture file */
	if (init_attr_sets())
		error(1, 0, "init_attr_sets failed");
	rules_create(&l);
	load_fixture(VALID_RULES, &l);
	rules_regen_sets(&l);

	prep_event(&e, 1000, "/bin/ls");
	if (evaluate(&l, &e) != ALLOW)
		error(1, 0, "direct rule evaluation failed");
	free_event(&e);

	prep_event(&e, 1001, "/bin/ls");
	if (evaluate(&l, &e) != ALLOW)
		error(1, 0, "set rule evaluation failed");
	free_event(&e);

	prep_event(&e, 2000, "/bin/ls");
	if (evaluate(&l, &e) != NO_OPINION)
		error(1, 0, "subject mismatch unexpected result");
	free_event(&e);

	prep_event(&e, 1001, "/tmp/xx");
	if (evaluate(&l, &e) != NO_OPINION)
		error(1, 0, "object mismatch unexpected result");
	free_event(&e);

	rules_clear(&l);
	destroy_attr_sets();

	/* negative parsing scenarios */
	for (i = 0; i < sizeof(errors)/sizeof(errors[0]); i++) {
		const struct err_case *c = &errors[i];

		if (init_attr_sets())
			error(1, 0, "init_attr_sets failed");
		rules_create(&l);

		for (j = 0; c->lines[j]; j++) {
			rc = append_capture(&l, c->lines[j], j + 1,
				err, sizeof(err));
			if (c->lines[j + 1] == NULL) {
				if (rc == 0)
					error(1, 0, "error case %u accepted", i);
			if (strstr(err, c->expect) == NULL)
				error(1, 0, "case %u message: %s", i, err);
			} else if (rc) {
				error(1, 0, "setup line %u failed: %s", j, err);
			}
		}

		rules_clear(&l);
		destroy_attr_sets();
	}

	return 0;
}

