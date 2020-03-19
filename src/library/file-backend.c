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
 *    Steve Grubb <sgrubb@redhat.com>
 */

#include "config.h"

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include "message.h"
#include "file.h"

#include "fapolicyd-backend.h"
#include "llist.h"
#include "file-backend.h"

#define FILE_PATH "/etc/fapolicyd/fapolicyd.trust"
#define BUFFER_SIZE 4096+1+10+86
#define FILE_READ_FORMAT  "%4096s %lu %86s"	// path size SHA256
#define FILE_WRITE_FORMAT "%s %lu %s\n"		// path size SHA256

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
	FILE *file;
	char buffer[BUFFER_SIZE];
	long line = 1;

	msg(LOG_INFO, "Loading file backend");
	list_empty(&file_backend.list);

	file = fopen(FILE_PATH, "r");
	if (!file) {
		msg(LOG_ERR, "Cannot open %s", FILE_PATH);
		return 1;
	}

	while (fgets(buffer, BUFFER_SIZE, file)) {
		char *ptr, *saved;
		int state = NAME;
		char *name = NULL;
		char *size = NULL;
		char *sha = NULL;

		if (iscntrl(buffer[0]) || buffer[0] == '#')
			continue;

		ptr = strtok_r(buffer, DELIMITER, &saved);
		while (ptr) {
			if (*ptr == 0)
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


/*
 * This function will append a path string to the file trust database.
 * it returns 0 on success, -1 on error, and 1 if a duplicate is found.
 */
int file_append(const char *path)
{
	FILE *f;
	int fd, count, count2;
	char *hash, *line, buffer[BUFFER_SIZE];
	struct stat sb;

	set_message_mode(MSG_STDERR, DBG_NO);
	f = fopen(FILE_PATH, "r+");
	if (f == NULL) {
		msg(LOG_ERR, "Cannot open %s", FILE_PATH);
		return -1;
	}

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		msg(LOG_ERR, "Cannot open %s", path);
		goto err_out2;
	}

	// Scan the file and look for a duplicate
	while (fgets(buffer, BUFFER_SIZE, f)) {
		char thash[87], tpath[4097];
		long unsigned size;

		sscanf(buffer, FILE_READ_FORMAT, tpath, &size, thash);
		if (strcmp(tpath, path) == 0) {
			msg(LOG_ERR, "%s is already in the database", path);
			close(fd);
			fclose(f);
			return 1;
		}
	}

	// No duplicate, make sure we are at the end
	if (!feof(f))
		fseek(f, 0, SEEK_END);

	// Get the size
	if (fstat(fd, &sb)) {
		msg(LOG_ERR, "Cannot stat %s", path);
		goto err_out;
	}

	// Get the hash
	hash = get_hash_from_fd(fd);

	// Format the output
	count = asprintf(&line, FILE_WRITE_FORMAT, path, sb.st_size, hash);
	if (count < 0) {
		msg(LOG_ERR, "Cannot format entry for %s", path);
		free(hash);
		goto err_out;
	}

	// Write it to disk
	if (fwrite(line, count, 1, f) != 1) {
		msg(LOG_ERR, "failed writing to %s\n", FILE_PATH);
		free(line);
		free(hash);
		goto err_out;
	}
	free(line);
	free(hash);
	close(fd);
	fclose(f);

	return 0;
err_out:
	close(fd);
err_out2:
	fclose(f);

	return -1;
}

