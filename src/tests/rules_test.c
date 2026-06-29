/*
* rules_test.c - verify parsing and evaluation of policy rules
*
* Test strategy summary
* ---------------------
* This harness exercises the rule parser and evaluator for:
*   1. direct values and %set references
*   2. rule_evaluate() subject/object matching
*   3. error paths: undefined sets, type mismatches, and mixed
*      valid/invalid same-side attributes
*
* Valid rules live in src/tests/fixtures/rules-valid.rules.  Each line is
* fed through rules_append() to mimic fagenrules processing.  Negative
* cases are described in the err_cases array below; QE can extend
* coverage by appending new entries.
*/
#include "config.h"
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
	{ "allow perm=any all : path=%missing", NULL },
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
	},
	{
	{ "%strs=wheel,staff",
	  "allow perm=any gid=%strs : path=/bin/ls",
	  NULL },
	"cannot assign %strs which has STRING type to gid (UNSIGNED expected)"
	},
	{
	{ "%dupe=1,2",
	  "%dupe=3,4",
	  NULL },
	"set dupe was already defined!"
	},
	{
	{ "allow auid=1000 uid=-1 path=/bin/ls", NULL },
	"negative value -1 not allowed for uid"
	},
	{
	{ "allow auid=1000 path=/bin/ls trust=2", NULL },
	"trust can be set to 1 or 0"
	},
	{
	{ "allow perm=any auid=1000 uid=-1 : path=/bin/ls", NULL },
	"negative value -1 not allowed for uid"
	},
	{
	{ "allow perm=any auid=1000 : path=/bin/ls trust=2", NULL },
	"trust can be set to 1 or 0"
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

	if (subject_create(e->s) || object_create(e->o))
		error(1, errno, "event array allocation failed");

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
* prep_macro_event - build an event with explicit subject/object paths
*
* e:   event to populate
* exe: subject executable path
* obj: object path
*
* Returns: none
*/
static void prep_macro_event(event_t *e, const char *exe, const char *obj)
{
	e->s = malloc(sizeof(s_array));
	e->o = malloc(sizeof(o_array));
	if (!e->s || !e->o)
		error(1, errno, "malloc failed");

	if (subject_create(e->s) || object_create(e->o))
		error(1, errno, "event array allocation failed");

	e->s->info = calloc(1, sizeof(struct proc_info));
	if (!e->s->info)
		error(1, errno, "calloc failed");

	subject_attr_t exe_attr = { .type = EXE, .str = strdup(exe) };
	if (!exe_attr.str)
		error(1, errno, "strdup failed");
	if (subject_add(e->s, &exe_attr))
		error(1, 0, "subject_add failed");

	object_attr_t path_attr = { .type = PATH, .o = strdup(obj) };
	if (!path_attr.o)
		error(1, errno, "strdup failed");
	if (object_add(e->o, &path_attr))
		error(1, 0, "object_add failed");

	e->type = 0;
}

/*
* add_trust_attrs - add cached subject and object trust values
*
* e: event to update
* subj_trusted: subject trust value to cache
* obj_trusted: object trust value to cache
*
* Returns: none
*/
static void add_trust_attrs(event_t *e, unsigned int subj_trusted,
			    int obj_trusted)
{
	subject_attr_t subj_trust = {
		.type = SUBJ_TRUST,
		.uval = subj_trusted
	};
	object_attr_t obj_trust = {
		.type = OBJ_TRUST,
		.val = obj_trusted
	};

	if (subject_add(e->s, &subj_trust))
		error(1, 0, "subject_add trust failed");
	if (object_add(e->o, &obj_trust))
		error(1, 0, "object_add trust failed");
}

/*
* prep_pattern_event - build an event with explicit pattern state
*
* e: event to populate
* state: startup-pattern state to expose to rule evaluation
* elf_info: ELF classification flags to expose to rule evaluation
* path1: first startup path recorded for the subject
*
* Returns: none
*/
static void prep_pattern_event(event_t *e, state_t state, uint32_t elf_info,
			       const char *path1)
{
	memset(e, 0, sizeof(*e));
	e->s = malloc(sizeof(s_array));
	e->o = malloc(sizeof(o_array));
	if (!e->s || !e->o)
		error(1, errno, "malloc failed");

	if (subject_create(e->s) || object_create(e->o))
		error(1, errno, "event array allocation failed");

	e->s->info = calloc(1, sizeof(struct proc_info));
	if (!e->s->info)
		error(1, errno, "calloc failed");

	e->s->info->pid = getpid();
	e->s->info->state = state;
	e->s->info->elf_info = elf_info;
	e->s->info->path1 = strdup(path1);
	if (!e->s->info->path1)
		error(1, errno, "strdup failed");

	e->type = FAN_OPEN_EXEC_PERM;
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

/*
* evaluate_pattern_rule - parse and evaluate one pattern rule
*
* rule: policy rule text to parse
* state: startup-pattern state for the synthetic event
* elf_info: ELF classification flags for the synthetic event
* path1: first startup path recorded for the synthetic event
*
* Returns: the decision produced by the parsed rule.
*/
static decision_t evaluate_pattern_rule(const char *rule, state_t state,
					uint32_t elf_info, const char *path1)
{
	char err[ERRBUF];
	llist l;
	event_t e;
	decision_t decision;

	if (rules_create(&l))
		error(1, 0, "rules_create failed");
	if (append_capture(&l, rule, 1, err, sizeof(err)))
		error(1, 0, "pattern rule parse failed: %s", err);

	prep_pattern_event(&e, state, elf_info, path1);
	decision = evaluate(&l, &e);
	free_event(&e);
	rules_clear(&l);
	return decision;
}

/*
* test_pattern_outcome_rules - verify policy-visible pattern outcomes
*
* Pattern rules mutate and then clear startup path state after evaluation.
* Exercise each pattern in isolation so the test pins the policy-visible
* outcome without depending on rule ordering side effects.
*
* Returns: none. Exits on test failure.
*/
static void test_pattern_outcome_rules(void)
{
	if (evaluate_pattern_rule("allow perm=any pattern=normal : all",
				  STATE_FULL, IS_ELF|HAS_DYNAMIC,
				  "/usr/bin/dynamic-app") != ALLOW)
		error(1, 0, "normal pattern rule did not allow");

	if (evaluate_pattern_rule("deny perm=any pattern=ld_so : all",
				  STATE_FULL, IS_ELF|HAS_DYNAMIC,
				  SYSTEM_LD_SO) != DENY)
		error(1, 0, "ld_so pattern rule did not deny");

	if (evaluate_pattern_rule("deny perm=any pattern=static : all",
				  STATE_COLLECTING, IS_ELF,
				  "/usr/bin/static-app") != DENY)
		error(1, 0, "static pattern rule did not deny");

	if (evaluate_pattern_rule("deny perm=any pattern=ld_so : all",
				  STATE_FULL, IS_ELF|HAS_DYNAMIC,
				  "/usr/bin/dynamic-app") != NO_OPINION)
		error(1, 0, "ld_so pattern matched normal startup");
}

int main(void)
{
	char err[ERRBUF];
	llist l;
	event_t e;
	unsigned i, j;
	int rc;

	set_message_mode(MSG_STDERR, DBG_NO);

	test_pattern_outcome_rules();

	/* positive path using fixture file */
	if (rules_create(&l))
		error(1, 0, "rules_create failed");
	load_fixture(VALID_RULES, &l);

	prep_event(&e, 1000, "/bin/ls");
	if (evaluate(&l, &e) != ALLOW)
		error(1, 0, "direct rule evaluation failed");
	free_event(&e);

	prep_event(&e, 1001, "/bin/ls");
	if (evaluate(&l, &e) != ALLOW)
		error(1, 0, "set rule evaluation failed");
	free_event(&e);

	prep_event(&e, 1001, "/usr/bin/id");
	if (evaluate(&l, &e) != ALLOW)
		error(1, 0, "object set evaluation failed");
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

	/* macro keyword matching on dir attributes */
	if (rules_create(&l))
		error(1, 0, "rules_create failed");

	rc = append_capture(&l, "allow perm=any dir=execdirs : all", 1,
		err, sizeof(err));
	if (rc)
		error(1, 0, "execdirs subject rule parse failed: %s", err);

	rc = append_capture(&l, "allow perm=any all : dir=systemdirs", 2,
		err, sizeof(err));
	if (rc)
		error(1, 0, "systemdirs object rule parse failed: %s", err);

	prep_macro_event(&e, "/usr/bin/bash", "/tmp/xx");
	if (evaluate(&l, &e) != ALLOW)
		error(1, 0, "execdirs macro subject match failed");
	free_event(&e);

	prep_macro_event(&e, "/opt/my-tool", "/etc/hosts");
	if (evaluate(&l, &e) != ALLOW)
		error(1, 0, "systemdirs macro object match failed");
	free_event(&e);

	prep_macro_event(&e, "/opt/my-tool", "/var/tmp/xx");
	if (evaluate(&l, &e) != NO_OPINION)
		error(1, 0, "unexpected macro match");
	free_event(&e);

	rules_clear(&l);

	/* deprecated dir=untrusted warnings and compatibility */
	if (rules_create(&l))
		error(1, 0, "rules_create failed");

	rc = append_capture(&l,
		"allow perm=any dir=untrusted : path=/tmp/payload", 1,
		err, sizeof(err));
	if (rc)
		error(1, 0, "subject untrusted dir parse failed: %s", err);
	if (strstr(err, "subject dir=untrusted is deprecated") == NULL)
		error(1, 0, "subject untrusted dir warning missing: %s", err);

	prep_macro_event(&e, "/opt/untrusted-tool", "/tmp/payload");
	add_trust_attrs(&e, 0, 0);
	if (evaluate(&l, &e) != ALLOW)
		error(1, 0, "subject untrusted dir compatibility failed");
	free_event(&e);

	prep_macro_event(&e, "/opt/untrusted-tool", "/tmp/payload");
	add_trust_attrs(&e, 0, 1);
	if (evaluate(&l, &e) != NO_OPINION)
		error(1, 0, "trusted object matched legacy exception");
	free_event(&e);

	rules_clear(&l);

	if (rules_create(&l))
		error(1, 0, "rules_create failed");

	rc = append_capture(&l,
		"allow perm=any all : dir=untrusted", 1,
		err, sizeof(err));
	if (rc)
		error(1, 0, "object untrusted dir parse failed: %s", err);
	if (strstr(err, "object dir=untrusted is deprecated") == NULL)
		error(1, 0, "object untrusted dir warning missing: %s", err);

	prep_macro_event(&e, "/usr/bin/bash", "/tmp/payload");
	add_trust_attrs(&e, 1, 0);
	if (evaluate(&l, &e) != ALLOW)
		error(1, 0, "object untrusted dir compatibility failed");
	free_event(&e);

	prep_macro_event(&e, "/usr/bin/bash", "/tmp/payload");
	add_trust_attrs(&e, 1, 1);
	if (evaluate(&l, &e) != NO_OPINION)
		error(1, 0, "trusted object matched object untrusted dir");
	free_event(&e);

	rules_clear(&l);

	if (rules_create(&l))
		error(1, 0, "rules_create failed");

	rc = append_capture(&l, "%legacy=untrusted", 1, err, sizeof(err));
	if (rc)
		error(1, 0, "legacy set parse failed: %s", err);
	if (strstr(err, "dir=untrusted is deprecated") != NULL)
		error(1, 0, "set definition emitted dir warning: %s", err);

	rc = append_capture(&l,
		"allow perm=any all : dir=%legacy", 2, err, sizeof(err));
	if (rc)
		error(1, 0, "object untrusted dir set parse failed: %s", err);
	if (strstr(err, "object dir=untrusted is deprecated") == NULL)
		error(1, 0, "set-based untrusted dir warning missing: %s",
		      err);

	rules_clear(&l);

	if (rules_create(&l))
		error(1, 0, "rules_create failed");

	rc = append_capture(&l,
		"allow perm=any exe=untrusted : all", 1, err, sizeof(err));
	if (rc)
		error(1, 0, "exe untrusted rule parse failed: %s", err);
	if (strstr(err, "dir=untrusted is deprecated") != NULL)
		error(1, 0, "exe untrusted emitted dir warning: %s", err);

	rules_clear(&l);

	/* duplicate inline string values should remain harmless */
	if (rules_create(&l))
		error(1, 0, "rules_create failed");

	rc = append_capture(&l,
		"allow perm=any all : path=/bin/ls,/bin/ls", 1,
		err, sizeof(err));
	if (rc)
		error(1, 0, "inline duplicate string rejected: %s", err);

	rules_clear(&l);

	/* negative parsing scenarios */
	for (i = 0; i < sizeof(errors)/sizeof(errors[0]); i++) {
		const struct err_case *c = &errors[i];

		if (rules_create(&l))
			error(1, 0, "rules_create failed");

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
	}

	return 0;
}
