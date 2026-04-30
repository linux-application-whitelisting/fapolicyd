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
#include <signal.h>
#include <stdio.h>

enum state_report_reason {
	STATE_REPORT_SIGNAL,
	STATE_REPORT_INTERVAL,
};

void state_report_signal_handler(int sig, siginfo_t *info, void *context);
void state_report_log_reset_strategy(reset_strategy_t strategy);
enum state_report_reason state_report_reason_for_triggers(int expired);
void state_report_write(enum state_report_reason reason);
void do_stat_report(FILE *f, int shutdown);
void do_stat_report_reset(FILE *f, int shutdown, int reset);
void decision_report(FILE *f);
void decision_report_reset(FILE *f, int reset);

#endif
