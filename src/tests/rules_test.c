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

static decision_t evaluate(const llist *l, event_t *e);

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
	{ "%languages+=application/x-vendor-script", NULL },
	"set languages must be defined before it can be extended"
	},
	{
	{ "%custom=one",
	  "%custom+=two",
	  NULL },
	"set append is only supported for %languages"
	},
	{
	{ "%languages=1",
	  "%languages+=application/x-vendor-script",
	  NULL },
	"set languages must have STRING type"
	},
	{
	{ "%languages=text/x-python",
	  "%languages+=",
	  NULL },
	"%languages+= requires at least one MIME type"
	},
	{
	{ "%languages=text/x-python",
	  "%languages+=glob:application/*",
	  NULL },
	"glob values are not valid in %languages"
	},
	{
	{ "allow auid=1000 uid=-1 path=/bin/ls", NULL },
	"negative value -1 not allowed for uid"
	},
	{
	{ "allow perm=any auid=-1 : path=/bin/ls", NULL },
	"negative value -1 not allowed for auid"
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
	},
	{
	{ "allow perm=any dir=glob:/home/*/bin/ : all", NULL },
	"subject dir does not support glob patterns; glob: is valid only with exe and path"
	},
	{
	{ "allow perm=any all : dir=glob:/home/*/bin/", NULL },
	"object dir does not support glob patterns; glob: is valid only with exe and path"
	},
	{
	{ "%dirs=glob:/home/*/bin/",
	  "allow perm=any dir=%dirs : all",
	  NULL },
	"subject dir does not support glob patterns; glob: is valid only with exe and path"
	},
	{
	{ "%dirs=glob:/home/*/bin/",
	  "allow perm=any all : dir=%dirs",
	  NULL },
	"object dir does not support glob patterns; glob: is valid only with exe and path"
	},
	{
	{ "allow perm=any comm=glob:python* : all", NULL },
	"subject comm does not support glob patterns; glob: is valid only with exe and path"
	},
	{
	{ "allow perm=any all : ftype=glob:application/*", NULL },
	"object ftype does not support glob patterns; glob: is valid only with exe and path"
	},
	{
	{ "allow perm=any all : path=glob:", NULL },
	"object path glob pattern must be an absolute path"
	},
	{
	{ "allow perm=any exe=glob:opt/app-* : all", NULL },
	"subject exe glob pattern must be an absolute path"
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
 * prep_nfsd_event - build a kernel NFS server open event for policy tests.
 * @e: event to initialize.
 * @comm: kernel thread comm value.
 * @ppid: parent process ID reported by procfs.
 * @event_type: fanotify permission event mask.
 *
 * The object is a language file so a following language denial verifies that
 * an nfsd exception must match before the ordinary language policy.
 */
static void prep_nfsd_event(event_t *e, const char *comm, pid_t ppid,
			    uint64_t event_type)
{
	subject_attr_t comm_attr = { .type = COMM, .str = strdup(comm) };
	subject_attr_t ppid_attr = { .type = PPID, .pid = ppid };
	object_attr_t path_attr = {
		.type = PATH,
		.o = strdup("/srv/export/module.py")
	};
	object_attr_t ftype_attr = {
		.type = FTYPE,
		.o = strdup("text/x-python")
	};

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
	if (!comm_attr.str || !path_attr.o || !ftype_attr.o)
		error(1, errno, "strdup failed");
	if (subject_add(e->s, &comm_attr) ||
	    subject_add(e->s, &ppid_attr) ||
	    object_add(e->o, &path_attr) ||
	    object_add(e->o, &ftype_attr))
		error(1, 0, "attribute setup failed");

	e->type = event_type;
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
 * test_language_set_extension - verify package MIME additions to %languages.
 *
 * The extension is a set union, so a duplicate MIME remains harmless while a
 * new MIME becomes visible to ftype rules that use the built-in macro.
 * Returns nothing. Exits on test failure.
 */
static void test_language_set_extension(void)
{
	char err[ERRBUF];
	llist l;
	event_t e;
	object_attr_t ftype = {
		.type = FTYPE,
		.o = strdup("application/x-vendor-script"),
	};
	attr_sets_entry_t *languages;
	int rc;

	if (!ftype.o)
		error(1, errno, "strdup failed");
	if (rules_create(&l))
		error(1, 0, "rules_create failed");

	rc = append_capture(&l, "%languages=text/x-python", 1,
			    err, sizeof(err));
	if (rc)
		error(1, 0, "language set parse failed: %s", err);
	rc = append_capture(&l,
		"%languages+=application/x-vendor-script,text/x-python", 2,
		err, sizeof(err));
	if (rc)
		error(1, 0, "language set extension parse failed: %s", err);
	rc = append_capture(&l,
		"allow perm=open all : ftype=%languages", 3,
		err, sizeof(err));
	if (rc)
		error(1, 0, "language ftype rule parse failed: %s", err);

	languages = attr_sets_find(l.sets, "languages");
	if (!languages || !attr_set_check_str(languages,
			"application/x-vendor-script"))
		error(1, 0, "language extension MIME was not added");

	prep_event(&e, 1000, "/tmp/vendor-script");
	if (object_add(e.o, &ftype))
		error(1, 0, "language ftype setup failed");
	e.type = FAN_OPEN_PERM;
	if (evaluate(&l, &e) != ALLOW)
		error(1, 0, "extended language MIME did not match ftype rule");
	free_event(&e);
	rules_clear(&l);
}

/*
 * test_explicit_untrusted_match - verify that trust=0 is a real constraint.
 *
 * A zero trust value matches only an untrusted subject or object. Omitting
 * trust is what accepts either state, so keep these behaviors distinct.
 * Returns nothing. Exits on test failure.
 */
static void test_explicit_untrusted_match(void)
{
	char err[ERRBUF];
	llist l;
	event_t e;
	int rc;

	if (rules_create(&l))
		error(1, 0, "rules_create failed");
	rc = append_capture(&l,
		"allow perm=any trust=0 : trust=0", 1, err, sizeof(err));
	if (rc)
		error(1, 0, "trust=0 rule parse failed: %s", err);

	prep_macro_event(&e, "/opt/untrusted-tool", "/tmp/untrusted-data");
	add_trust_attrs(&e, 0, 0);
	if (evaluate(&l, &e) != ALLOW)
		error(1, 0, "trust=0 did not match untrusted attributes");
	free_event(&e);

	prep_macro_event(&e, "/opt/trusted-tool", "/tmp/untrusted-data");
	add_trust_attrs(&e, 1, 0);
	if (evaluate(&l, &e) != NO_OPINION)
		error(1, 0, "subject trust=0 matched a trusted subject");
	free_event(&e);

	prep_macro_event(&e, "/opt/untrusted-tool", "/tmp/trusted-data");
	add_trust_attrs(&e, 0, 1);
	if (evaluate(&l, &e) != NO_OPINION)
		error(1, 0, "object trust=0 matched a trusted object");
	free_event(&e);
	rules_clear(&l);
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
 * evaluate_glob_rule - parse and evaluate one path-oriented rule
 * @rule: policy rule text to parse.
 * @exe: concrete subject executable path.
 * @path: concrete object path.
 *
 * Returns: the decision produced by the parsed rule.
 */
static decision_t evaluate_glob_rule(const char *rule, const char *exe,
				     const char *path)
{
	char err[ERRBUF];
	llist l;
	event_t e;
	decision_t decision;

	if (rules_create(&l))
		error(1, 0, "rules_create failed");
	if (append_capture(&l, rule, 1, err, sizeof(err)))
		error(1, 0, "glob rule parse failed: %s", err);

	prep_macro_event(&e, exe, path);
	decision = evaluate(&l, &e);
	free_event(&e);
	rules_clear(&l);
	return decision;
}

/*
 * test_glob_rules - verify exe and path glob semantics
 *
 * Explicitly marked globs match whole paths without crossing directory
 * components or matching a leading period implicitly. Unmarked
 * metacharacters remain exact for compatibility. Escapes, named sets,
 * immutable event paths, literal dir prefixes, and first-match ordering are
 * covered alongside the positive cases.
 *
 * Returns: none. Exits on test failure.
 */
static void test_glob_rules(void)
{
	static const struct {
		const char *rule;
		const char *exe;
		const char *path;
		decision_t expected;
		const char *name;
	} cases[] = {
		{
			"allow perm=any all : path=glob:/home/*/bin/tool",
			"/usr/bin/bash", "/home/alice/bin/tool", ALLOW,
			"object component wildcard"
		},
		{
			"allow perm=any all : path=glob:/home/*/bin/tool",
			"/usr/bin/bash", "/home/alice/project/bin/tool",
			NO_OPINION, "object wildcard crossed slash"
		},
		{
			"allow perm=any all : path=glob:/opt/app-?/bin/tool",
			"/usr/bin/bash", "/opt/app-7/bin/tool", ALLOW,
			"question wildcard"
		},
		{
			"allow perm=any all : path=glob:/opt/app-?/bin/tool",
			"/usr/bin/bash", "/opt/app-77/bin/tool", NO_OPINION,
			"question wildcard width"
		},
		{
			"allow perm=any all : path=glob:/srv/app-[0-9]/tool",
			"/usr/bin/bash", "/srv/app-4/tool", ALLOW,
			"bracket wildcard"
		},
		{
			"allow perm=any all : path=glob:/home/*/bin/tool",
			"/usr/bin/bash", "/home/.admin/bin/tool", NO_OPINION,
			"implicit leading period"
		},
		{
			"allow perm=any all : path=glob:/home/.*/bin/tool",
			"/usr/bin/bash", "/home/.admin/bin/tool", ALLOW,
			"explicit leading period"
		},
		{
			"allow perm=any all : path=glob:/home/alice/bin/*",
			"/usr/bin/bash", "/home/alice/bin/.tool", NO_OPINION,
			"implicit basename period"
		},
		{
			"allow perm=any all : path=glob:/home/alice/bin/.*",
			"/usr/bin/bash", "/home/alice/bin/.tool", ALLOW,
			"explicit basename period"
		},
		{
			"allow perm=any all : path=glob:/opt/app-*/bin/tool",
			"/usr/bin/bash", "/opt/app-2/bin/tool.bak", NO_OPINION,
			"whole path matching"
		},
		{
			"allow perm=any exe=glob:/opt/vendor/app-*/bin/app : all",
			"/opt/vendor/app-2/bin/app", "/tmp/input", ALLOW,
			"subject executable wildcard"
		},
		{
			"allow perm=any exe=glob:/opt/*/bin/app : all",
			"/opt/vendor/release/bin/app", "/tmp/input",
			NO_OPINION, "subject wildcard crossed slash"
		},
		{
			"allow perm=any all : path=/tmp/name[1]",
			"/usr/bin/bash", "/tmp/name[1]", ALLOW,
			"literal bracket path"
		},
		{
			"allow perm=any all : path=/tmp/name[1]",
			"/usr/bin/bash", "/tmp/name1", NO_OPINION,
			"literal bracket does not broaden"
		},
		{
			"allow perm=any all : path=/tmp/name*",
			"/usr/bin/bash", "/tmp/name*", ALLOW,
			"literal star path"
		},
		{
			"allow perm=any all : path=/tmp/name*",
			"/usr/bin/bash", "/tmp/name1", NO_OPINION,
			"literal star does not broaden"
		},
		{
			"allow perm=any all : path=/tmp/name?",
			"/usr/bin/bash", "/tmp/name1", NO_OPINION,
			"literal question mark does not broaden"
		},
		{
			"allow perm=any all : path=glob:/tmp/name[1]",
			"/usr/bin/bash", "/tmp/name1", ALLOW,
			"marked bracket expression"
		},
		{
			"allow perm=any all : path=glob:/tmp/name\\*",
			"/usr/bin/bash", "/tmp/name*", ALLOW,
			"escaped wildcard in pattern"
		},
		{
			"allow perm=any all : path=/no/match,glob:/home/*/bin/tool",
			"/usr/bin/bash", "/home/alice/bin/tool", ALLOW,
			"inline path alternatives"
		},
		{
			"allow perm=any all : dir=/home/*/bin/",
			"/usr/bin/bash", "/home/*/bin/tool", ALLOW,
			"literal directory metacharacter"
		},
	};
	char err[ERRBUF];
	llist l;
	event_t e;
	object_attr_t *path_attr;

	for (size_t i = 0; i < sizeof(cases)/sizeof(cases[0]); i++) {
		decision_t decision = evaluate_glob_rule(cases[i].rule,
			cases[i].exe, cases[i].path);

		if (decision != cases[i].expected)
			error(1, 0, "%s produced decision %d, expected %d",
			      cases[i].name, decision, cases[i].expected);
	}

	if (rules_create(&l))
		error(1, 0, "rules_create failed");
	if (append_capture(&l,
		"%wine=glob:/home/*/.wine/drive_c/windows/notepad.exe,/opt/wine/notepad.exe",
		1, err, sizeof(err)))
		error(1, 0, "glob set parse failed: %s", err);
	if (append_capture(&l,
		"allow perm=any all : path=%wine", 2, err, sizeof(err)))
		error(1, 0, "glob set rule parse failed: %s", err);

	prep_macro_event(&e, "/usr/bin/bash",
			 "/home/alice/.wine/drive_c/windows/notepad.exe");
	if (evaluate(&l, &e) != ALLOW)
		error(1, 0, "named glob set did not match");
	path_attr = object_access(e.o, PATH);
	if (!path_attr || strcmp(path_attr->o,
		    "/home/alice/.wine/drive_c/windows/notepad.exe"))
		error(1, 0, "glob evaluation changed the concrete object path");
	free_event(&e);
	rules_clear(&l);

	if (rules_create(&l))
		error(1, 0, "rules_create failed");
	if (append_capture(&l,
		"deny perm=any all : path=glob:/home/*/bin/tool",
		1, err, sizeof(err)))
		error(1, 0, "ordered glob rule parse failed: %s", err);
	if (append_capture(&l,
		"allow perm=any all : path=/home/alice/bin/tool",
		2, err, sizeof(err)))
		error(1, 0, "ordered exact rule parse failed: %s", err);

	prep_macro_event(&e, "/usr/bin/bash", "/home/alice/bin/tool");
	if (evaluate(&l, &e) != DENY)
		error(1, 0, "glob rules did not preserve first-match ordering");
	free_event(&e);
	rules_clear(&l);
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

/*
 * test_nfsd_kernel_thread_rule - verify the optional NFS server exception.
 *
 * nfsd has no executable to place in the trust database. The policy must
 * identify its kernel worker by comm and PPID, permit only open events, and
 * precede the normal language-file denial.
 */
static void test_nfsd_kernel_thread_rule(void)
{
	char err[ERRBUF];
	llist l;
	event_t e;
	int rc;

	if (rules_create(&l))
		error(1, 0, "rules_create failed");

	rc = append_capture(&l,
		"allow perm=open ppid=2 comm=nfsd : all", 1,
		err, sizeof(err));
	if (rc)
		error(1, 0, "nfsd rule parse failed: %s", err);
	rc = append_capture(&l,
		"deny perm=any all : ftype=text/x-python", 2,
		err, sizeof(err));
	if (rc)
		error(1, 0, "language deny rule parse failed: %s", err);

	prep_nfsd_event(&e, "nfsd", 2, FAN_OPEN_PERM);
	if (evaluate(&l, &e) != ALLOW)
		error(1, 0, "nfsd open did not bypass language denial");
	free_event(&e);

	prep_nfsd_event(&e, "nfsd", 2, FAN_OPEN_EXEC_PERM);
	if (evaluate(&l, &e) != DENY)
		error(1, 0, "nfsd rule unexpectedly allowed execute event");
	free_event(&e);

	prep_nfsd_event(&e, "nfsd", 1, FAN_OPEN_PERM);
	if (evaluate(&l, &e) != DENY)
		error(1, 0, "non-kernel nfsd process matched exception");
	free_event(&e);

	prep_nfsd_event(&e, "kworker", 2, FAN_OPEN_PERM);
	if (evaluate(&l, &e) != DENY)
		error(1, 0, "unrelated kernel thread matched nfsd exception");
	free_event(&e);

	rules_clear(&l);
}

/*
 * test_unset_auid_rule - verify the unsigned representation of an unset auid.
 *
 * Audit uses -1 internally for an unset login uid, but fapolicyd rule values
 * are unsigned. The parser must reject -1 and a rule using 4294967295 must
 * match the value reported for an unset audit uid.
 */
static void test_unset_auid_rule(void)
{
	char err[ERRBUF];
	llist l;
	event_t e;
	int rc;

	if (rules_create(&l))
		error(1, 0, "rules_create failed");

	rc = append_capture(&l,
		"allow perm=open auid=4294967295 : all", 1,
		err, sizeof(err));
	if (rc)
		error(1, 0, "unset auid rule parse failed: %s", err);

	prep_event(&e, 4294967295U, "/bin/ls");
	e.type = FAN_OPEN_PERM;
	if (evaluate(&l, &e) != ALLOW)
		error(1, 0, "unset auid did not match unsigned rule value");
	free_event(&e);
	rules_clear(&l);
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
	test_glob_rules();
	test_nfsd_kernel_thread_rule();
	test_unset_auid_rule();
	test_language_set_extension();
	test_explicit_untrusted_match();

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
