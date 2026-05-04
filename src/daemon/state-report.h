/*
 * state-report.h - daemon state report coordination
 * Copyright (c) 2026 Red Hat Inc.
 * All Rights Reserved.
 *
 * This software may be freely redistributed and/or modified under the
 * terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2, or (at your option) any
 * later version.
 */

#ifndef STATE_REPORT_HEADER
#define STATE_REPORT_HEADER

#include "conf.h"
#include "failure-action.h"
#include <stdbool.h>
#include <signal.h>
#include <stdio.h>

enum state_report_reason {
	STATE_REPORT_SIGNAL,
	STATE_REPORT_INTERVAL,
};

struct state_report_operating_mode {
	bool permissive;
	const char *integrity;
	const char *reset_strategy;
	unsigned int ruleset_generation;
	const conf_t *config;
};

void usr1_handler(int sig, siginfo_t *info, void *context);
void state_report_log_reset_strategy(reset_strategy_t strategy);
enum state_report_reason state_report_reason_for_triggers(int expired);
void state_report_write(enum state_report_reason reason);
void state_report_operating_mode(FILE *f,
		const struct state_report_operating_mode *mode);
void do_state_report(FILE *f, int shutdown);
void do_stat_report(FILE *f, int shutdown);
void do_metrics_report_reset(FILE *f, int reset);
void do_stat_report_reset(FILE *f, int shutdown, int reset);
void decision_report(FILE *f);
void decision_report_reset(FILE *f, int reset);
void decision_report_metrics_reset(FILE *f, int reset);
void decision_report_reset_with_failures(FILE *f, int reset,
		const failure_action_metrics_t *failures);
void decision_failure_action_report(FILE *f,
		const failure_action_metrics_t *failures);

#endif
