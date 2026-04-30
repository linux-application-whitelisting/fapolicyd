/*
 * policy-metrics.h - internal policy decision metrics
 * Copyright (c) 2026 Red Hat Inc.
 * All Rights Reserved.
 *
 * This software may be freely redistributed and/or modified under the
 * terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2, or (at your option) any
 * later version.
 */

#ifndef POLICY_METRICS_HEADER
#define POLICY_METRICS_HEADER

#include "policy.h"

/*
 * policy_metrics_record_ruleset_update - count a published policy generation.
 * Returns nothing.
 */
void policy_metrics_record_ruleset_update(void);

/*
 * policy_metrics_record_decision - count a policy decision.
 * @decision: decision returned by policy evaluation.
 * @e: event used for allow detail bucketing, or NULL when unavailable.
 * @source: whether the allow came from a rule or default fallthrough.
 * Returns nothing.
 */
void policy_metrics_record_decision(decision_t decision, event_t *e,
		decision_source_t source);

#endif
