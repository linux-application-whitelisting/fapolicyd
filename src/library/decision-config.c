/*
 * decision-config.c - immutable decision configuration generations
 *
 * Copyright (c) 2026 Red Hat Inc.
 * All Rights Reserved.
 *
 * This software may be freely redistributed and/or modified under the
 * terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2, or (at your option) any
 * later version.
 */

#include "config.h"
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <time.h>
#include "decision-config.h"
#include "message.h"

/*
 * decision_config - immutable fields that can change a decision result.
 *
 * A permission event pins one generation before event construction and keeps
 * using it through trust checks and the final fanotify response. Reloads
 * publish a new object instead of mutating the active one, so a decision never
 * observes permissive mode from one reload and digest policy from another.
 */
struct decision_config {
	unsigned int permissive;
	integrity_t integrity;
	unsigned int rpm_sha256_only;
	unsigned int generation;
	time_t effective_since;
	struct decision_config *previous;
};

static struct decision_config default_decision_config = {
	.permissive = 0,
	.integrity = IN_NONE,
	.rpm_sha256_only = 0,
	.generation = 0,
	.effective_since = 0,
	.previous = NULL,
};
static _Atomic(struct decision_config *) active_decision_config =
	&default_decision_config;
static atomic_uint next_generation;
static pthread_mutex_t publish_lock = PTHREAD_MUTEX_INITIALIZER;
static __thread const struct decision_config *pinned_decision_config;

static const struct decision_config *decision_config_active(void)
{
	struct decision_config *config;

	config = atomic_load_explicit(&active_decision_config,
				      memory_order_acquire);
	if (config == NULL)
		return &default_decision_config;
	return config;
}

/*
 * decision_config_publish - publish a new immutable decision config.
 * @config: parsed daemon configuration to snapshot.
 * Returns 0 on success and 1 on allocation or argument failure.
 */
int decision_config_publish(const conf_t *config)
{
	struct decision_config *snapshot;
	time_t now;

	if (config == NULL)
		return 1;

	snapshot = calloc(1, sizeof(*snapshot));
	if (snapshot == NULL) {
		msg(LOG_ERR, "Cannot allocate decision config generation");
		return 1;
	}

	snapshot->permissive = config->permissive ? 1 : 0;
	snapshot->integrity = config->integrity;
	snapshot->rpm_sha256_only = config->rpm_sha256_only ? 1 : 0;
	now = time(NULL);
	snapshot->effective_since = now == (time_t)-1 ? 0 : now;

	pthread_mutex_lock(&publish_lock);
	snapshot->generation = atomic_fetch_add_explicit(&next_generation, 1,
							 memory_order_relaxed) + 1;
	snapshot->previous = atomic_load_explicit(&active_decision_config,
						  memory_order_relaxed);
	atomic_store_explicit(&active_decision_config, snapshot,
			      memory_order_release);
	pthread_mutex_unlock(&publish_lock);

	msg(LOG_INFO, "Decision config generation %u published",
	    snapshot->generation);
	return 0;
}

/*
 * decision_config_pin - pin the active config for the current decision.
 * Returns the config generation that the current thread will use.
 */
const struct decision_config *decision_config_pin(void)
{
	const struct decision_config *config = decision_config_active();

	pinned_decision_config = config;
	return config;
}

/*
 * decision_config_unpin - clear a pinned config for the current thread.
 * @config: generation previously returned by decision_config_pin().
 * Returns nothing.
 */
void decision_config_unpin(const struct decision_config *config)
{
	if (pinned_decision_config == config)
		pinned_decision_config = NULL;
}

/*
 * decision_config_current - return pinned generation or active generation.
 * Returns a valid decision config object.
 */
const struct decision_config *decision_config_current(void)
{
	if (pinned_decision_config)
		return pinned_decision_config;
	return decision_config_active();
}

unsigned int decision_config_generation(const struct decision_config *config)
{
	if (config == NULL)
		config = decision_config_current();
	return config->generation;
}

/*
 * decision_config_effective_since - return the config activation time.
 * @config: config generation to inspect, or NULL for the current generation.
 * Returns the time @config became active, or zero if it is unknown.
 */
time_t decision_config_effective_since(const struct decision_config *config)
{
	if (config == NULL)
		config = decision_config_current();
	return config->effective_since;
}

unsigned int decision_config_permissive(const struct decision_config *config)
{
	if (config == NULL)
		config = decision_config_current();
	return config->permissive;
}

integrity_t decision_config_integrity(const struct decision_config *config)
{
	if (config == NULL)
		config = decision_config_current();
	return config->integrity;
}

/*
 * decision_config_rpm_sha256_only - return the active RPM digest floor flag.
 * @config: config generation to inspect, or NULL for the current generation.
 * Returns 1 when RPM trust records must be SHA256 or stronger, otherwise 0.
 */
unsigned int decision_config_rpm_sha256_only(
	const struct decision_config *config)
{
	if (config == NULL)
		config = decision_config_current();
	return config->rpm_sha256_only;
}

unsigned int decision_config_active_generation(void)
{
	return decision_config_generation(decision_config_active());
}

/*
 * decision_config_active_effective_since - return active activation time.
 * Returns the time the active config became effective, or zero if unknown.
 */
time_t decision_config_active_effective_since(void)
{
	return decision_config_effective_since(decision_config_active());
}

/*
 * decision_config_destroy - free published config generations during shutdown.
 *
 * Generations are not reclaimed on reload because a future worker may still
 * have pinned the old one. Shutdown is the only point where all decision users
 * are gone and the list can be released without an epoch scheme.
 */
void decision_config_destroy(void)
{
	struct decision_config *config, *previous;

	pthread_mutex_lock(&publish_lock);
	config = atomic_exchange_explicit(&active_decision_config,
					  &default_decision_config,
					  memory_order_acq_rel);
	while (config && config != &default_decision_config) {
		previous = config->previous;
		free(config);
		config = previous;
	}
	atomic_store_explicit(&next_generation, 0, memory_order_relaxed);
	pthread_mutex_unlock(&publish_lock);

	pinned_decision_config = NULL;
}
