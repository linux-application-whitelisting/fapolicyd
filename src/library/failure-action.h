/*
 * failure-action.h - internal failure action model
 * Copyright (c) 2026 Red Hat Inc.
 * All Rights Reserved.
 *
 * This software may be freely redistributed and/or modified under the
 * terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2, or (at your option) any
 * later version.
 */

#ifndef FAILURE_ACTION_HEADER
#define FAILURE_ACTION_HEADER

#include <stdio.h>

typedef enum {
	FAILURE_REASON_QUEUE_FULL,
	FAILURE_REASON_KERNEL_QUEUE_OVERFLOW,
	FAILURE_REASON_WORKER_STALL,
	FAILURE_REASON_RULE_RELOAD_FAILURE,
	FAILURE_REASON_TRUST_RELOAD_FAILURE,
	FAILURE_REASON_RESPONSE_WRITE_FAILURE,
	FAILURE_REASON_MAX
} failure_reason_t;

typedef enum {
	FAILURE_ACTION_OBSERVE
} failure_action_t;

typedef struct {
	unsigned long counts[FAILURE_REASON_MAX];
} failure_action_metrics_t;

const char *failure_reason_name(failure_reason_t reason);
failure_action_t failure_reason_action(failure_reason_t reason);
const char *failure_action_name(failure_action_t action);
unsigned long failure_action_record(failure_reason_t reason);
unsigned long failure_action_count(failure_reason_t reason);
void failure_action_snapshot(failure_action_metrics_t *metrics, int reset);
unsigned long failure_action_metrics_count(
		const failure_action_metrics_t *metrics,
		failure_reason_t reason);
void failure_action_metrics_report(FILE *f,
		const failure_action_metrics_t *metrics);
void failure_action_report(FILE *f);

#endif
