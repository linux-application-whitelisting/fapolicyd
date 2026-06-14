/*
 * database-internal.h - private boundary between trust DB modules
 * Copyright (c) 2026 Red Hat Inc.
 * All Rights Reserved.
 *
 * This software may be freely redistributed and/or modified under the
 * terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2, or (at your option) any
 * later version.
 */

#ifndef DATABASE_INTERNAL_HEADER
#define DATABASE_INTERNAL_HEADER

#include <stddef.h>
#include "conf.h"
#include "gcc-attributes.h"

int database_update_controls_init(void) __wur;
void database_update_controls_destroy(void);
int database_update_thread_start(conf_t *config) __nonnull ((1)) __wur;
void database_update_thread_stop(void);
void database_update_read_lock(void);
void database_update_read_unlock(void);

int database_reload_from_backends(conf_t *config) __nonnull ((1)) __wur;
void database_compact_from_backends(conf_t *config) __nonnull ((1));
int database_store_update_record(const char *path, size_t size,
	const char *hash)
	__nonnull ((1, 3))
	__attr_access ((__read_only__, 1))
	__attr_access ((__read_only__, 3)) __wur;

#endif
