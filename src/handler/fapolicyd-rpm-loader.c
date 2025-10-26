/*
 * fapolicy-rpm-loader.c - loader tool for fapolicyd
 * Copyright (c) 2025-2025 Red Hat Inc.
 * All Rights Reserved.
 *
 * This software may be freely redistributed and/or modified under the
 * terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; see the file COPYING. If not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor
 * Boston, MA 02110-1335, USA.
 *
 * Authors:
 *   Radovan Sroka <rsroka@redhat.com>
 */

#include "config.h"
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syslog.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#include <magic.h>
#include <stdlib.h>
#include <getopt.h>
#include <stdatomic.h>
#include <lmdb.h>
#include <limits.h>
#include <signal.h>

#include "backend-manager.h"
#include "daemon-config.h"
#include "message.h"
#include "fd-fgets.h"
#include "paths.h"

atomic_bool stop = 0;  // Library needs this
unsigned int debug_mode = 0;			// Library needs this
conf_t config;				// Library needs this


int do_rpm_init_backend(void);
int do_rpm_load_list(conf_t * conf, int memfd);
int do_rpm_destroy_backend(void);

extern backend rpm_backend;

// fetch the socket FD number – defaults to 3 if env not set
int sock_fd = 3; // same number dup2’ed by parent

int main(int argc, char * const argv[])
{

	set_message_mode(MSG_STDERR, DBG_YES);

	if (load_daemon_config(&config)) {
		free_daemon_config(&config);
		msg(LOG_ERR, "Exiting due to bad configuration");
		return 1;
	}

	int memfd = memfd_create("rpm_snapshot", MFD_CLOEXEC|MFD_ALLOW_SEALING);
	if (memfd < 0) {
		msg(LOG_ERR, "memfd_create failed");
		exit(1);
	}

	do_rpm_init_backend();
	if (do_rpm_load_list(&config, memfd)) {
		msg(LOG_ERR, "Failed to populate rpm backend snapshot");
		exit(1);
	}

	msg(LOG_INFO, "Loaded files %ld", rpm_backend.entries);

	fcntl(memfd, F_ADD_SEALS, F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE);
	lseek(memfd, 0, SEEK_SET);            /* rewind – not strictly needed */

	// send the FD
	struct msghdr  _msg = {0};
	struct iovec   iov = { .iov_base = (char[1]){0}, .iov_len = 1 };
	union { struct cmsghdr align; char buf[CMSG_SPACE(sizeof(int))]; } cmsgbuf;

	_msg.msg_iov = &iov;
	_msg.msg_iovlen = 1;
	_msg.msg_control = cmsgbuf.buf;
	_msg.msg_controllen = sizeof cmsgbuf.buf;

	struct cmsghdr *c = CMSG_FIRSTHDR(&_msg);

	c->cmsg_level = SOL_SOCKET;
	c->cmsg_type  = SCM_RIGHTS;
	c->cmsg_len   = CMSG_LEN(sizeof(int));
	memcpy(CMSG_DATA(c), &memfd, sizeof(int));

	if (sendmsg(sock_fd, &_msg, 0) < 0) {
		msg(LOG_ERR, "sendmsg failed");
		exit(1);
	}

	close(sock_fd);       // closes the channel; parent gets EOF
	close(memfd);         // parent has its own refcount

	do_rpm_destroy_backend();

	free_daemon_config(&config);
	return 0;
}

