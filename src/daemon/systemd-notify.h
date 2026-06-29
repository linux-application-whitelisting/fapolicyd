/*
 * systemd-notify.h - minimal systemd notify/watchdog integration
 * Copyright (c) 2026 Red Hat Inc.
 * All Rights Reserved.
 */

#ifndef SYSTEMD_NOTIFY_HEADER
#define SYSTEMD_NOTIFY_HEADER

#include <stdint.h>

void systemd_notify_set_enabled(int enabled);
int systemd_notify_ready(void);
int systemd_notify_stopping(void);
int systemd_watchdog_ping(void);
uint64_t systemd_watchdog_interval_usec(void);
int systemd_watchdog_enabled(void);

#endif
