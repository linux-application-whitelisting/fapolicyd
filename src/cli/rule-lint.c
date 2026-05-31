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

struct lint_path_status {
	const char *path;
	int old_rules;
	int compiled_rules;
	int stale_old_rules;
};

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
 * rule_has_only_language_ftype - check for a broad language object match.
 * @rule: parsed rule to inspect.
 * Returns 1 when the object side is exactly ftype=%languages.
 */
static int rule_has_only_language_ftype(const lnode *rule)
{
	return rule->o_count == 1 && rule_has_language_ftype(rule);
}

/*
 * print_rule_location - print the rule number and source file location.
 * @path: rule file path used for parsing.
 * @rule: parsed rule to locate.
 */
static void print_rule_location(const char *path, const lnode *rule)
{
	fprintf(stderr, "rule %u at %s:%u", rule->num + 1, path,
		rule->lineno);
}

/*
 * lint_rules_policy - emit policy-shape warnings for default-allow gaps.
 * @rules: parsed rule list to inspect.
 * @path: rule file path used for parsing.
 * @stale_old_rules: non-zero when old rules shadow compiled.rules.
 * Returns CLI_EXIT_GENERIC when warnings were emitted, CLI_EXIT_SUCCESS
 * otherwise. Syntax validation is handled before this function runs.
 */
static int lint_rules_policy(const llist *rules, const char *path,
			     int stale_old_rules)
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
		    rule_has_only_language_ftype(rule))
			first_lang_deny = rule;

		if (!first_open_allow && rule_is_allow(rule) &&
		    rule_matches_open(rule) && rule_is_broad_subject(rule) &&
		    rule_is_broad_object(rule))
			first_open_allow = rule;
	}

	if (stale_old_rules) {
		fprintf(stderr, "Policy lint warning: %s exists alongside "
			"%s; fapolicyd loads the old rules file first and "
			"ignores compiled.rules\n", OLD_RULES_FILE, RULES_FILE);
		fprintf(stderr, "Policy lint hint: remove %s or migrate it "
			"into rules.d and rerun fagenrules\n", OLD_RULES_FILE);
		warnings = 1;
	}

	if (!last_exec_rule || !rule_is_deny(last_exec_rule) ||
	    !rule_is_broad_subject(last_exec_rule) ||
	    !rule_is_broad_object(last_exec_rule)) {
		fprintf(stderr, "Policy lint warning: executable events can "
			"fall through; no terminal broad execute deny found");
		if (last_exec_rule) {
			fprintf(stderr, " after ");
			print_rule_location(path, last_exec_rule);
		} else
			fprintf(stderr, " in %s", path);
		fprintf(stderr, "\nPolicy lint hint: add a final "
			"\"deny_audit perm=execute all : all\" rule\n");
		warnings = 1;
	}

	if (!has_languages) {
		fprintf(stderr, "Policy lint warning: %%languages is not "
			"defined in %s; programmatic ftype coverage cannot "
			"be checked\n", path);
		warnings = 1;
	} else if (!first_lang_deny) {
		fprintf(stderr, "Policy lint warning: programmatic opens can "
			"fall through; no broad %%languages open deny found");
		if (first_open_allow) {
			fprintf(stderr, " before ");
			print_rule_location(path, first_open_allow);
		} else
			fprintf(stderr, " in %s", path);
		fprintf(stderr, "\nPolicy lint hint: add "
			"\"deny_audit perm=open all : ftype=%%languages\" "
			"before broad open allows\n");
		warnings = 1;
	}

	if (first_open_allow &&
	    (!first_lang_deny || first_open_allow->num < first_lang_deny->num)) {
		fprintf(stderr, "Policy lint warning: broad open allow ");
		print_rule_location(path, first_open_allow);
		if (first_lang_deny) {
			fprintf(stderr, " appears before programmatic-content "
				"deny ");
			print_rule_location(path, first_lang_deny);
		} else
			fprintf(stderr, " can shadow programmatic-content "
				"denies");
		fprintf(stderr, "\n");
		warnings = 1;
	}

	if (warnings == 0)
		printf("Policy lint found no warnings\n");

	return warnings ? CLI_EXIT_GENERIC : CLI_EXIT_SUCCESS;
}

/*
 * is_active_rules_path - check if a path names an installed rules file.
 * @path: path supplied by the caller.
 * Returns 1 when @path names the old or compiled rules file.
 */
static int is_active_rules_path(const char *path)
{
	return path && (strcmp(path, OLD_RULES_FILE) == 0 ||
			strcmp(path, RULES_FILE) == 0);
}

/*
 * select_rules_path - select the rules file and record lint path state.
 * @requested_path: caller supplied path, or NULL for the active rules file.
 * @lint_rules: non-zero when policy lint warnings are enabled.
 * @status: selected path and old/new rule-file state.
 * Returns CLI_EXIT_SUCCESS when a single candidate was selected.
 */
static int select_rules_path(const char *requested_path, int lint_rules,
			     struct lint_path_status *status)
{
	memset(status, 0, sizeof(*status));
	status->path = requested_path;
	status->old_rules = access(OLD_RULES_FILE, F_OK) == 0;
	status->compiled_rules = access(RULES_FILE, F_OK) == 0;

	if (status->old_rules && status->compiled_rules &&
	    (requested_path == NULL || is_active_rules_path(requested_path)))
		status->stale_old_rules = lint_rules;

	if (requested_path)
		return CLI_EXIT_SUCCESS;

	if (status->old_rules && status->compiled_rules && !lint_rules) {
		fprintf(stderr, "Error - old and new rules file detected. "
			"Delete one or the other.\n");
		return CLI_EXIT_PATH_CONFIG;
	}

	if (status->old_rules)
		status->path = OLD_RULES_FILE;
	else
		status->path = RULES_FILE;

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
	struct lint_path_status path_status;
	unsigned int cnt;

	set_message_mode(MSG_STDERR, DBG_NO);

	rc = select_rules_path(path, lint_rules, &path_status);
	if (rc)
		return rc;
	path = path_status.path;

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
		rc = lint_rules_policy(&temp_rules, path,
				       path_status.stale_old_rules);
	} else
		rc = CLI_EXIT_SUCCESS;

	rules_clear(&temp_rules);
	return rc;
}
