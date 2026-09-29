/* fapolicyd-rpm-plugin.c - report RPM transaction changes to fapolicyd
 *
 * Copyright 2020,2022,2026 Red Hat Inc.
 * All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Authors:
 *   Radovan Sroka <rsroka@redhat.com>
 *   Panu Matilainen <pmatilai@redhat.com>
 *   Steve Grubb <sgrubb@redhat.com>
 */

#include "config.h"

#include <rpm/rpmfi.h>
#include <rpm/rpmlog.h>
#include <rpm/rpmplugin.h>
#include <rpm/rpmstring.h>
#include <rpm/rpmts.h>

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "paths.h"

#ifndef RPM_SYMBOL_EXPORT
#define RPM_SYMBOL_EXPORT __attribute__((visibility("default")))
#endif

struct fapolicyd_data {
	int fd;
	long changed_files;
	const char *connected_path;
	const char *primary_fifo_path;
	const char *legacy_fifo_path;
};

static struct fapolicyd_data fapolicyd_state = {
	.fd = -1,
	.changed_files = 0,
	.connected_path = UPDATE_FIFO_PATH,
	.primary_fifo_path = UPDATE_FIFO_PATH,
	.legacy_fifo_path = LEGACY_UPDATE_FIFO_PATH,
};

/*
 * open_fifo - open and validate one daemon update FIFO.
 * @state: plugin connection state to update on success.
 * @path: FIFO pathname to open.
 *
 * Returns zero on success or an errno value describing the failure.
 */
static int open_fifo(struct fapolicyd_data *state, const char *path)
{
	struct stat s;
	int fd;
	int rc;

	fd = open(path, O_WRONLY | O_NONBLOCK | O_CLOEXEC);
	if (fd == -1) {
		rc = errno;
		rpmlog(RPMLOG_DEBUG, "Open: %s -> %s\n", path,
		       strerror(rc));
		return rc;
	}

	if (fstat(fd, &s) == -1) {
		rc = errno;
		rpmlog(RPMLOG_DEBUG, "Stat: %s -> %s\n", path,
		       strerror(rc));
		goto bad;
	}

	if (!S_ISFIFO(s.st_mode)) {
		rc = ENOTSUP;
		rpmlog(RPMLOG_DEBUG, "File: %s exists but it is not a pipe!\n",
		       path);
		goto bad;
	}

	if ((s.st_mode & 07777) != 0660) {
		rc = EACCES;
		rpmlog(RPMLOG_ERR, "File: %s has %o instead of 0660\n", path,
		       s.st_mode & 07777);
		goto bad;
	}

	state->fd = fd;
	state->connected_path = path;
	return 0;

bad:
	close(fd);
	state->fd = -1;
	return rc;
}

/*
 * connect_fifo - connect to the current daemon or its migration predecessor.
 * @state: plugin connection state and endpoint paths.
 *
 * The legacy endpoint is considered only when the new endpoint is absent.
 * Returns zero on success or an errno value describing the failure.
 */
static int connect_fifo(struct fapolicyd_data *state)
{
	int rc;

	rc = open_fifo(state, state->primary_fifo_path);
	if (rc == ENOENT)
		rc = open_fifo(state, state->legacy_fifo_path);

	return rc;
}

/*
 * close_fifo - close the current daemon connection.
 * @state: plugin connection state to reset.
 *
 * Returns nothing.
 */
static void close_fifo(struct fapolicyd_data *state)
{
	if (state->fd >= 0)
		(void)close(state->fd);

	state->fd = -1;
}

/*
 * write_fifo - write one complete protocol record without spinning.
 * @state: connected plugin state.
 * @str: NUL-terminated record to write.
 *
 * Returns RPMRC_OK on success and RPMRC_FAIL when the nonblocking FIFO cannot
 * accept the record. EAGAIN is handled by the bounded reconnect loop instead
 * of a CPU-consuming retry here.
 */
static rpmRC write_fifo(struct fapolicyd_data *state, const char *str)
{
	size_t len = strlen(str);
	size_t written = 0;

	while (written < len) {
		ssize_t n = write(state->fd, str + written, len - written);

		if (n < 0) {
			if (errno == EINTR)
				continue;
			rpmlog(RPMLOG_DEBUG, "Write: %s -> %s\n",
			       state->connected_path, strerror(errno));
			return RPMRC_FAIL;
		}
		if (n == 0) {
			errno = EIO;
			return RPMRC_FAIL;
		}
		written += (size_t)n;
	}

	return RPMRC_OK;
}

/*
 * try_to_write_to_fifo - write with bounded service-restart recovery.
 * @state: plugin connection state.
 * @str: protocol record to write.
 *
 * Returns RPMRC_OK on success and RPMRC_FAIL after the retry period expires.
 */
static rpmRC try_to_write_to_fifo(struct fapolicyd_data *state,
		const char *str)
{
	const int timeout = 60;
	int reload = 0;
	int printed = 0;

	for (int i = 0; i < timeout; i++) {
		if (reload) {
			if (!printed) {
				rpmlog(RPMLOG_WARNING,
				       "fapolicyd-rpm-plugin: waiting for the service "
				       "connection to resume, it can take up to %d "
				       "seconds\n", timeout);
				printed = 1;
			}

			close_fifo(state);
			(void)connect_fifo(state);
		}

		if (state->fd >= 0 && write_fifo(state, str) == RPMRC_OK) {
			if (reload)
				rpmlog(RPMLOG_WARNING,
				       "fapolicyd-rpm-plugin: the service connection "
				       "has resumed\n");
			return RPMRC_OK;
		}

		reload = 1;
		sleep(1);
	}

	rpmlog(RPMLOG_WARNING,
	       "fapolicyd-rpm-plugin: the service connection has not resumed\n");
	rpmlog(RPMLOG_WARNING,
	       "fapolicyd-rpm-plugin: continuing without the service\n");
	return RPMRC_FAIL;
}

/* Initialize the plugin connection for a real host transaction. */
static rpmRC fapolicyd_rpm_init(rpmPlugin plugin, rpmts ts)
{
	if (rpmtsFlags(ts) & (RPMTRANS_FLAG_TEST | RPMTRANS_FLAG_BUILD_PROBS))
		return RPMRC_OK;

	if (rstreq(rpmtsRootDir(ts), "/"))
		(void)connect_fifo(&fapolicyd_state);

	return RPMRC_OK;
}

/* Release the plugin connection after the RPM transaction. */
static void fapolicyd_rpm_cleanup(rpmPlugin plugin)
{
	close_fifo(&fapolicyd_state);
}

/* Notify fapolicyd that RPM has completed the transaction. */
static rpmRC fapolicyd_rpm_tsm_post(rpmPlugin plugin, rpmts ts, int res)
{
	if (rpmtsFlags(ts) & (RPMTRANS_FLAG_TEST | RPMTRANS_FLAG_BUILD_PROBS))
		return RPMRC_OK;

	if (fapolicyd_state.fd >= 0 &&
	    try_to_write_to_fifo(&fapolicyd_state, "1\n") == RPMRC_OK &&
	    fapolicyd_state.fd >= 0)
		(void)try_to_write_to_fifo(&fapolicyd_state, "2\n");

	return RPMRC_OK;
}

/* Flush cached decisions before a scriptlet observes installed files. */
static rpmRC fapolicyd_rpm_scriptlet_pre(rpmPlugin plugin,
		const char *s_name, int type)
{
	if (fapolicyd_state.fd >= 0 && fapolicyd_state.changed_files > 0) {
		(void)try_to_write_to_fifo(&fapolicyd_state, "2\n");
		fapolicyd_state.changed_files = 0;
	}

	return RPMRC_OK;
}

/* Send metadata for one regular file RPM is about to install. */
static rpmRC fapolicyd_rpm_fsm_file_prepare(rpmPlugin plugin, rpmfi fi,
		int fd, const char *path, const char *dest, mode_t file_mode,
		rpmFsmOp op)
{
	char buffer[4096];
	rpmFileAction action;
	rpm_loff_t size;
	char *sha;

	if (fapolicyd_state.fd < 0)
		return RPMRC_OK;

	action = XFO_ACTION(op);
	if (XFA_SKIPPING(action) || (op & FAF_UNOWNED))
		return RPMRC_OK;

	if (!S_ISREG(rpmfiFMode(fi)))
		return RPMRC_OK;

	fapolicyd_state.changed_files++;
	size = rpmfiFSize(fi);
	sha = rpmfiFDigestHex(fi, NULL);
	if (sha != NULL) {
		snprintf(buffer, sizeof(buffer), "%s %" PRIu64 " %64s\n",
			 dest, size, sha);
		(void)try_to_write_to_fifo(&fapolicyd_state, buffer);
		free(sha);
	}

	return RPMRC_OK;
}

RPM_SYMBOL_EXPORT
struct rpmPluginHooks_s fapolicyd_rpm_hooks = {
	.init = fapolicyd_rpm_init,
	.cleanup = fapolicyd_rpm_cleanup,
	.tsm_post = fapolicyd_rpm_tsm_post,
	.scriptlet_pre = fapolicyd_rpm_scriptlet_pre,
	.fsm_file_prepare = fapolicyd_rpm_fsm_file_prepare,
};
