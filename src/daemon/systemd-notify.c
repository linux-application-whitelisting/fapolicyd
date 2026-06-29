/*
 * systemd-notify.c - minimal systemd notify/watchdog integration
 * Copyright (c) 2026 Red Hat Inc.
 * All Rights Reserved.
 *
 * This software may be freely redistributed and/or modified under the
 * terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2, or (at your option) any
 * later version.
 */

#include "config.h"
#include <errno.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include "systemd-notify.h"

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

#ifndef SOCK_CLOEXEC
#define SOCK_CLOEXEC 0
#endif

#ifdef FAPOLICYD_ENABLE_SYSTEMD_WATCHDOG
static atomic_int notify_enabled = ATOMIC_VAR_INIT(1);

/*
 * notify_runtime_enabled - check whether runtime mode allows notification.
 * Returns non-zero when sd_notify/watchdog environment may be consumed.
 */
static int notify_runtime_enabled(void)
{
	return atomic_load_explicit(&notify_enabled, memory_order_relaxed) != 0;
}

/*
 * notify_address - build the AF_UNIX destination from NOTIFY_SOCKET.
 * @path: NOTIFY_SOCKET value from systemd.
 * @addr: destination socket address.
 * @addr_len: destination address length.
 *
 * Systemd accepts either filesystem paths or abstract namespace sockets where
 * the environment value starts with '@'. Returns 0 on success and -1 with errno
 * set on invalid input.
 */
static int notify_address(const char *path, struct sockaddr_un *addr,
		socklen_t *addr_len)
{
	size_t len;

	if (path == NULL || *path == 0 || addr == NULL || addr_len == NULL) {
		errno = EINVAL;
		return -1;
	}

	memset(addr, 0, sizeof(*addr));
	addr->sun_family = AF_UNIX;
	if (path[0] == '@') {
		len = strlen(path + 1);
		if (len + 1 > sizeof(addr->sun_path)) {
			errno = ENAMETOOLONG;
			return -1;
		}
		addr->sun_path[0] = 0;
		memcpy(addr->sun_path + 1, path + 1, len);
		*addr_len = offsetof(struct sockaddr_un, sun_path) + 1 + len;
		return 0;
	}

	len = strlen(path);
	if (len >= sizeof(addr->sun_path)) {
		errno = ENAMETOOLONG;
		return -1;
	}
	memcpy(addr->sun_path, path, len + 1);
	*addr_len = offsetof(struct sockaddr_un, sun_path) + len + 1;
	return 0;
}

/*
 * notify_send - send one systemd notification datagram.
 * @state: newline-separated sd_notify state fields.
 * Returns 0 when notification is disabled or the datagram was sent, -1 on
 * local socket/send failure.
 */
static int notify_send(const char *state)
{
	const char *path;
	struct sockaddr_un addr;
	socklen_t addr_len;
	int fd, saved_errno;

	if (!notify_runtime_enabled() || state == NULL)
		return 0;

	path = getenv("NOTIFY_SOCKET");
	if (path == NULL || *path == 0)
		return 0;
	if (notify_address(path, &addr, &addr_len))
		return -1;

	fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -1;
	if (sendto(fd, state, strlen(state), MSG_NOSIGNAL,
		   (const struct sockaddr *)&addr, addr_len) < 0) {
		saved_errno = errno;
		close(fd);
		errno = saved_errno;
		return -1;
	}
	close(fd);
	return 0;
}

/*
 * watchdog_pid_matches - check whether systemd targeted this process.
 * Returns 1 when WATCHDOG_PID is unset or matches getpid(), 0 otherwise.
 */
static int watchdog_pid_matches(void)
{
	const char *pid_env = getenv("WATCHDOG_PID");
	char *end = NULL;
	unsigned long pid;

	if (pid_env == NULL || *pid_env == 0)
		return 1;

	errno = 0;
	pid = strtoul(pid_env, &end, 10);
	if (errno || end == pid_env || *end != 0)
		return 0;

	return pid == (unsigned long)getpid();
}
#endif

/*
 * systemd_notify_set_enabled - enable or disable systemd notification.
 * @enabled: non-zero enables notify/watchdog environment consumption.
 * Returns nothing.
 */
void systemd_notify_set_enabled(int enabled)
{
#ifdef FAPOLICYD_ENABLE_SYSTEMD_WATCHDOG
	atomic_store_explicit(&notify_enabled, enabled ? 1 : 0,
			      memory_order_relaxed);
#else
	(void)enabled;
#endif
}

/*
 * systemd_notify_ready - tell systemd startup completed.
 * Returns 0 when disabled or sent, -1 on local notification failure.
 */
int systemd_notify_ready(void)
{
#ifdef FAPOLICYD_ENABLE_SYSTEMD_WATCHDOG
	return notify_send("READY=1\nSTATUS=Ready");
#else
	return 0;
#endif
}

/*
 * systemd_notify_stopping - tell systemd shutdown started.
 * Returns 0 when disabled or sent, -1 on local notification failure.
 */
int systemd_notify_stopping(void)
{
#ifdef FAPOLICYD_ENABLE_SYSTEMD_WATCHDOG
	return notify_send("STOPPING=1\nSTATUS=Stopping");
#else
	return 0;
#endif
}

/*
 * systemd_watchdog_ping - refresh the systemd watchdog deadline.
 * Returns 0 when disabled or sent, -1 on local notification failure.
 */
int systemd_watchdog_ping(void)
{
#ifdef FAPOLICYD_ENABLE_SYSTEMD_WATCHDOG
	return notify_send("WATCHDOG=1");
#else
	return 0;
#endif
}

/*
 * systemd_watchdog_interval_usec - return configured watchdog interval.
 * Returns WATCHDOG_USEC when systemd enabled the watchdog for this process, or
 * zero when notification/watchdog support is disabled.
 */
uint64_t systemd_watchdog_interval_usec(void)
{
#ifdef FAPOLICYD_ENABLE_SYSTEMD_WATCHDOG
	const char *usec_env;
	char *end = NULL;
	unsigned long long usec;

	if (!notify_runtime_enabled())
		return 0;

	if (getenv("NOTIFY_SOCKET") == NULL || !watchdog_pid_matches())
		return 0;

	usec_env = getenv("WATCHDOG_USEC");
	if (usec_env == NULL || *usec_env == 0)
		return 0;

	errno = 0;
	usec = strtoull(usec_env, &end, 10);
	if (errno || end == usec_env || *end != 0 || usec == 0)
		return 0;

	return (uint64_t)usec;
#else
	return 0;
#endif
}

/*
 * systemd_watchdog_enabled - check whether systemd watchdog pings are active.
 * Returns 1 when systemd supplied a usable watchdog interval, 0 otherwise.
 */
int systemd_watchdog_enabled(void)
{
	return systemd_watchdog_interval_usec() != 0;
}
