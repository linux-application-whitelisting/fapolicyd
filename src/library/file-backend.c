/*
 * file-backend.c - file backend
 * Copyright (c) 2020 Red Hat Inc., Durham, North Carolina.
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
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include "message.h"

#include "fapolicyd-backend.h"
#include "llist.h"

#define FILE_PATH "/etc/fapolicyd/fapolicyd.trust"
#define BUFFER_SIZE 4096

static int file_init_backend(void);
static int file_load_list(void);
static int file_destroy_backend(void);

backend file_backend =
{
	"file",
	file_init_backend,
	file_load_list,
	file_destroy_backend,
	{ 0, 0, NULL },
};


enum _states {
	NAME = 0,
	SIZE,
	SHA,
};

#define DELIMITER " "

static int file_load_list(void)
{
	char buffer[BUFFER_SIZE];
	msg(LOG_INFO, "Loading file backend");

	list_empty(&file_backend.list);
	memset(buffer, 0, BUFFER_SIZE);

	FILE *file = fopen(FILE_PATH, "r");
	if (!file) {
		msg(LOG_ERR, "Cannot open %s", FILE_PATH);
		return 1;
	}

	long line = 1;
	while(fgets(buffer, BUFFER_SIZE, file)) {
		char *ptr, *saved;
		int state = NAME;
		char name = NULL;
		char *size = NULL;
		char *sha = NULL;

		if(iscntrl(buffer[0]) || buffer[0] == '#') {
			memset(buffer, 0, BUFFER_SIZE);
			continue;
		}

		ptr = strtok_r(buffer, DELIMITER, &saved);
		while (ptr) {
			if(strlen(ptr) == 0)
				continue;
			switch (state)
			{
				case NAME:
					name = ptr;
					break;
				case SIZE:
					size = ptr;
					break;
				case SHA:
					sha = ptr;
					break;
				default:
					fclose(file);
					msg(LOG_ERR,
					    "%s:%ld : Too many columns",
						FILE_PATH, line);
					return 1;
			}
			state++;
			ptr = strtok_r(NULL, DELIMITER, &saved);
		}

		errno = 0;
		unsigned long sz = strtoul(size, NULL, 10);
		if (errno) {
			msg(LOG_ERR, "%s:%ld Cannot convert size to number.",
				FILE_PATH, line);
			fclose(file);
			return 1;
		}

		char *index = NULL;
		char *data = NULL;
		int verified = 0;

		// TODO: create proper trim function
		sha[64] = '\0';

		if (asprintf(&data, DATA_FORMAT, verified, sz, sha) == -1)
			data = NULL;

		index = strdup(name);

		//msg(LOG_INFO, "GGG: %s, %s", index, data);
		if (index && data)
			list_append(&file_backend.list, index, data);

		//free(data);
		memset(buffer, 0, BUFFER_SIZE);
		line++;
	}

	fclose(file);
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

