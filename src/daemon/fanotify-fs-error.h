/*
 * fanotify-fs-error.h - FAN_FS_ERROR health monitoring
 * Copyright (c) 2026 Red Hat Inc.
 * All Rights Reserved.
 *
 * This software may be freely redistributed and/or modified under the
 * terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2, or (at your option) any
 * later version.
 */

#ifndef FANOTIFY_FS_ERROR_HEADER
#define FANOTIFY_FS_ERROR_HEADER

#include <stdio.h>
#include <sys/fanotify.h>
#include "mounts.h"

int fanotify_fs_error_init(mlist *m);
int fanotify_fs_error_mark(const char *path);
void fanotify_fs_error_unmark(const char *path);
void fanotify_fs_error_close(void);
int fanotify_fs_error_fd(void);
void fanotify_fs_error_handle_events(void);
int fanotify_fs_error_handle_event(
		const struct fanotify_event_metadata *metadata);
unsigned long getFanotifyFilesystemErrors(void);
void fanotify_fs_error_report(FILE *f);

#endif
