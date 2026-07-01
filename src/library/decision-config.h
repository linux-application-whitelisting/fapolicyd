/*
 * decision-config.h - immutable decision configuration generations
 *
 * Copyright (c) 2026 Red Hat Inc.
 * All Rights Reserved.
 *
 * This software may be freely redistributed and/or modified under the
 * terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2, or (at your option) any
 * later version.
 */

#ifndef DECISION_CONFIG_HEADER
#define DECISION_CONFIG_HEADER

#include <time.h>
#include "conf.h"

struct decision_config;

int decision_config_publish(const conf_t *config);
const struct decision_config *decision_config_pin(void);
void decision_config_unpin(const struct decision_config *config);
const struct decision_config *decision_config_current(void);
unsigned int decision_config_generation(const struct decision_config *config);
time_t decision_config_effective_since(const struct decision_config *config);
unsigned int decision_config_permissive(const struct decision_config *config);
integrity_t decision_config_integrity(const struct decision_config *config);
unsigned int decision_config_rpm_sha256_only(
	const struct decision_config *config);
unsigned int decision_config_active_generation(void);
time_t decision_config_active_effective_since(void);
void decision_config_destroy(void);

#endif
