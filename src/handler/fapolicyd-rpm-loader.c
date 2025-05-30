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
#include "llist.h"
#include "fd-fgets.h"
#include "paths.h"

volatile atomic_bool stop = 0;  // Library needs this
unsigned int debug_mode = 0;			// Library needs this
unsigned int permissive = 0;			// Library needs this


int do_rpm_init_backend(void);
int do_rpm_load_list(conf_t * conf);
int do_rpm_destroy_backend(void);

extern backend rpm_backend;

int main(int argc, char * const argv[])
{

	set_message_mode(MSG_STDERR, DBG_YES);

	conf_t config;

	load_daemon_config(&config);

	do_rpm_init_backend();
	do_rpm_load_list(&config);

	msg(LOG_INFO, "Loaded files %ld", rpm_backend.list.count);

	list_item_t *item = list_get_first(&rpm_backend.list);
	for (; item != NULL; item = item->next) {
		printf("%s %s\n", (const char*)item->index, (const char*)item->data);
	}

	do_rpm_destroy_backend();

	free_daemon_config(&config);
	return 0;
}

