/*
 * rule-lint.c - CLI rule validation and lint checks
 * Copyright (c) 2026 Red Hat Inc.
 * All Rights Reserved.
 *
 * This software may be freely redistributed and/or modified under the
 * terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2, or (at your option) any
 * later version.
 */

#include "config.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "file-cli.h"
#include "message.h"
#include "paths.h"
#include "rules.h"
#include "rule-lint.h"

/*
 * get_rule_line - read one rule file line without its trailing newline.
 * @f: rule file stream.
 * Returns a heap-allocated line or NULL at end of file.
 */
static char *get_rule_line(FILE *f)
{
	char *line = NULL;
	size_t len = 0;

	if (getline(&line, &len, f) != -1) {
		char *ptr = strchr(line, 0x0a);

		if (ptr)
			*ptr = 0;
		return line;
	}
	free(line);
	return NULL;
}

/*
 * rule_is_broad_subject - check if a rule has an unrestricted subject side.
 * @rule: parsed rule to inspect.
 * Returns 1 when the subject side is all, 0 otherwise.
 */
static int rule_is_broad_subject(const lnode *rule)
{
	for (unsigned int i = 0; i < rule->s_count; i++)
		if (rule->s[i].type == ALL_SUBJ)
			return 1;

	return 0;
}

/*
 * rule_is_broad_object - check if a rule has an unrestricted object side.
 * @rule: parsed rule to inspect.
 * Returns 1 when the object side is all, 0 otherwise.
 */
static int rule_is_broad_object(const lnode *rule)
{
	for (unsigned int i = 0; i < rule->o_count; i++)
		if (rule->o[i].type == ALL_OBJ)
			return 1;

	return 0;
}

/*
 * rule_is_deny - check if a rule denies access.
 * @rule: parsed rule to inspect.
 * Returns 1 for deny-family decisions, 0 otherwise.
 */
static int rule_is_deny(const lnode *rule)
{
	return (rule->d & DENY) == DENY;
}

/*
 * rule_is_allow - check if a rule allows access.
 * @rule: parsed rule to inspect.
 * Returns 1 for allow-family decisions, 0 otherwise.
 */
static int rule_is_allow(const lnode *rule)
{
	return (rule->d & ALLOW) == ALLOW;
}

/*
 * rule_matches_execute - check if a rule can match execute events.
 * @rule: parsed rule to inspect.
 * Returns 1 when perm=execute or perm=any, 0 otherwise.
 */
static int rule_matches_execute(const lnode *rule)
{
	return rule->a == EXEC_ACC || rule->a == ANY_ACC;
}

/*
 * rule_matches_open - check if a rule can match open events.
 * @rule: parsed rule to inspect.
 * Returns 1 when perm=open or perm=any, 0 otherwise.
 */
static int rule_matches_open(const lnode *rule)
{
	return rule->a == OPEN_ACC || rule->a == ANY_ACC;
}

/*
 * rule_has_language_ftype - check if a rule matches the %languages set.
 * @rule: parsed rule to inspect.
 * Returns 1 when an object ftype attribute references %languages.
 */
static int rule_has_language_ftype(const lnode *rule)
{
	for (unsigned int i = 0; i < rule->o_count; i++) {
		if (rule->o[i].type != FTYPE || rule->o[i].set == NULL)
			continue;
		if (rule->o[i].set->name &&
				strcmp(rule->o[i].set->name, "languages") == 0)
			return 1;
	}

	return 0;
}

/*
 * lint_rules_policy - emit policy-shape warnings for default-allow gaps.
 * @rules: parsed rule list to inspect.
 * Returns CLI_EXIT_GENERIC when warnings were emitted, CLI_EXIT_SUCCESS
 * otherwise. Syntax validation is handled before this function runs.
 */
static int lint_rules_policy(const llist *rules)
{
	const lnode *rule;
	const lnode *last_exec_rule = NULL;
	const lnode *first_lang_deny = NULL;
	const lnode *first_open_allow = NULL;
	int warnings = 0;
	int has_languages;

	has_languages = attr_sets_find(rules->sets, "languages") != NULL;

	for (rule = rules_first_node(rules); rule;
	     rule = rules_next_node(rule)) {
		if (rule_matches_execute(rule))
			last_exec_rule = rule;

		if (!first_lang_deny && rule_is_deny(rule) &&
		    rule_matches_open(rule) && rule_is_broad_subject(rule) &&
		    rule_has_language_ftype(rule))
			first_lang_deny = rule;

		if (!first_open_allow && rule_is_allow(rule) &&
		    rule_matches_open(rule) && rule_is_broad_subject(rule) &&
		    rule_is_broad_object(rule))
			first_open_allow = rule;
	}

	if (!last_exec_rule || !rule_is_deny(last_exec_rule) ||
	    !rule_is_broad_subject(last_exec_rule) ||
	    !rule_is_broad_object(last_exec_rule)) {
		fprintf(stderr, "Policy lint warning: executable events can "
			"fall through; no terminal broad execute deny found\n");
		warnings = 1;
	}

	if (!has_languages) {
		fprintf(stderr, "Policy lint warning: %%languages is not "
			"defined; programmatic ftype coverage cannot be checked\n");
		warnings = 1;
	} else if (!first_lang_deny) {
		fprintf(stderr, "Policy lint warning: programmatic opens can "
			"fall through; no broad %%languages open deny found\n");
		warnings = 1;
	}

	if (first_open_allow &&
	    (!first_lang_deny || first_open_allow->num < first_lang_deny->num)) {
		fprintf(stderr, "Policy lint warning: broad open allow on rule "
			"%u can shadow programmatic-content denies\n",
			first_open_allow->num + 1);
		warnings = 1;
	}

	if (warnings == 0)
		printf("Policy lint found no warnings\n");

	return warnings ? CLI_EXIT_GENERIC : CLI_EXIT_SUCCESS;
}

/*
 * default_rules_path - select the rules file used when no path is supplied.
 * @path: selected path is returned here.
 * Returns CLI_EXIT_SUCCESS when a single candidate was selected.
 */
static int default_rules_path(const char **path)
{
	int old_rules = access(OLD_RULES_FILE, F_OK) == 0;
	int compiled_rules = access(RULES_FILE, F_OK) == 0;

	if (old_rules && compiled_rules) {
		fprintf(stderr, "Error - old and new rules file detected. "
			"Delete one or the other.\n");
		return CLI_EXIT_PATH_CONFIG;
	}

	if (old_rules)
		*path = OLD_RULES_FILE;
	else
		*path = RULES_FILE;

	return CLI_EXIT_SUCCESS;
}

/*
 * check_rules_file - parse a rules file and optionally lint policy shape.
 * @path: rule file path to inspect, or NULL for the active rules file.
 * @lint_rules: non-zero enables policy lint warnings after syntax checks.
 * Returns CLI_EXIT_SUCCESS when validation passes and lint finds no warnings.
 */
int check_rules_file(const char *path, int lint_rules)
{
	FILE *f;
	int rc, lineno = 1, invalid = 0;
	char *line = NULL;
	llist temp_rules;
	unsigned int cnt;

	set_message_mode(MSG_STDERR, DBG_NO);

	if (path == NULL) {
		rc = default_rules_path(&path);
		if (rc)
			return rc;
	}

	f = fopen(path, "r");
	if (f == NULL) {
		fprintf(stderr, "Cannot open rules file %s (%s)\n",
				path, strerror(errno));
		return CLI_EXIT_IO;
	}

	if (rules_create(&temp_rules)) {
		fprintf(stderr, "Failed to create rules list\n");
		fclose(f);
		return CLI_EXIT_INTERNAL;
	}

	while ((line = get_rule_line(f))) {
		rc = rules_append(&temp_rules, line, lineno);
		if (rc) {
			fprintf(stderr, "Rule validation failed at line %d\n",
					lineno);
			invalid = 1;
		}
		free(line);
		lineno++;
	}

	cnt = temp_rules.cnt;
	fclose(f);

	if (invalid) {
		rules_clear(&temp_rules);
		return CLI_EXIT_RULE_FILTER;
	}

	if (cnt == 0) {
		fprintf(stderr, "No rules found in file\n");
		rules_clear(&temp_rules);
		return CLI_EXIT_RULE_FILTER;
	}

	printf("Rules file is valid (%u rules)\n", cnt);

	if (lint_rules) {
		fflush(stdout);
		rc = lint_rules_policy(&temp_rules);
	} else
		rc = CLI_EXIT_SUCCESS;

	rules_clear(&temp_rules);
	return rc;
}
