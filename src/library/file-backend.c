/*
 * file-backend.c - file backend
 * Copyright (c) 2020 Red Hat Inc.
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
 *   Steve Grubb <sgrubb@redhat.com>
 *   Zoltan Fridrich <zfridric@redhat.com>
 */

#include "config.h"

#include <errno.h>
#include <stddef.h>
#include <string.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>

#include "fapolicyd-backend.h"
#include "llist.h"
#include "message.h"
#include "trust-file.h"



static int file_init_backend(void);
static int file_load_list(const conf_t *conf);
static int file_destroy_backend(void);

backend file_backend =
{
	"file",
	file_init_backend,
	file_load_list,
	file_destroy_backend,
	{ 0, 0, NULL },
	-1,
	-1,
};



static int file_load_list(const conf_t *conf)
{
	msg(LOG_DEBUG, "Loading file backend");
	list_empty(&file_backend.list);

	/* Close any previous snapshot before rebuilding the backend view. */
	if (file_backend.memfd != -1) {
		close(file_backend.memfd);
		file_backend.memfd = -1;
		file_backend.entries = -1;
	}

	int memfd = memfd_create("file_snapshot",
				 MFD_CLOEXEC | MFD_ALLOW_SEALING);
	if (memfd < 0) {
		msg(LOG_WARNING, "memfd_create failed for file backend (%s)",
		    strerror(errno));
		return 1;
	}

	trust_file_load_all(&file_backend.list, memfd);

	/* Seal the snapshot so readers see a stable view. */
	if (fcntl(memfd, F_ADD_SEALS, F_SEAL_SHRINK |
		  F_SEAL_GROW | F_SEAL_WRITE) == -1)
		msg(LOG_WARNING, "Failed to seal file backend memfd (%s)",
		    strerror(errno));
	file_backend.memfd = memfd;

	return 0;
}

static int file_init_backend(void)
{
	list_init(&file_backend.list);
	return 0;
}

static int file_destroy_backend(void)
{
	list_empty(&file_backend.list);
	return 0;
}
