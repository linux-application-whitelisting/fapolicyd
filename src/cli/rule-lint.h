/*
 * rule-lint.h - CLI rule validation and lint checks
 * Copyright (c) 2026 Red Hat Inc.
 * All Rights Reserved.
 *
 * This software may be freely redistributed and/or modified under the
 * terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2, or (at your option) any
 * later version.
 */

#ifndef RULE_LINT_HEADER
#define RULE_LINT_HEADER

int check_rules_file(const char *path, int lint_rules);

#endif
