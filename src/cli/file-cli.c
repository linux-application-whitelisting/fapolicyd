/*
 * file-cli.c - implementation of CLI option file
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
 *   Zoltan Fridrich <zfridric@redhat.com>
 */

#include "config.h"

#include <fcntl.h>
#include <ftw.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "llist.h"
#include "message.h"
#include "string-util.h"
#include "trust-file.h"



#define FTW_NOPENFD 1024
#define FTW_FLAGS (FTW_ACTIONRETVAL | FTW_PHYS)



list_t add_list;



static int ftw_add_list_append(const char *fpath,
		const struct stat *sb __attribute__ ((unused)),
		int typeflag,
		struct FTW *ftwbuf __attribute__ ((unused)))
{
	if (typeflag == FTW_F)
		list_append(&add_list, strdup(fpath), NULL);
	return FTW_CONTINUE;
}

/**
 * Load path into add_list. If path is a directory,
 * loads all regular files within the directory tree
 *
 * @param path Path to load into add_list
 * @return 0 on success, 1 on error
 */
static int add_list_load_path(const char *path)
{
	int fd = open(path, O_RDONLY);
	if (fd < 0) {
		msg(LOG_ERR, "Cannot open %s", path);
		return 1;
	}

	struct stat sb;
	if (fstat(fd, &sb)) {
		msg(LOG_ERR, "Cannot stat %s", path);
		close(fd);
		return 1;
	}
	close(fd);

	if (S_ISDIR(sb.st_mode))
		nftw(path, &ftw_add_list_append, FTW_NOPENFD, FTW_FLAGS);
	else
		list_append(&add_list, strdup(path), NULL);

	return 0;
}




int file_append(const char *path, const char *fname)
{
	set_message_mode(MSG_STDERR, DBG_NO);

	list_init(&add_list);
	if (add_list_load_path(path))
		return -1;
	
	trust_file_rm_duplicates_all(&add_list);

	if (add_list.count == 0) {
		msg(LOG_ERR, "After removing duplicates, there is nothing to add");
		return 1;
	}

	char *dest = fname ? fapolicyd_strcat(TRUST_DIR_PATH, fname) : TRUST_FILE_PATH;
	int rc = trust_file_append(dest, &add_list);

	if (fname)
		free(dest);
	list_empty(&add_list);
	return rc ? -1 : 0;
}

int file_delete(const char *path, const char *fname)
{
	set_message_mode(MSG_STDERR, DBG_NO);
	int count;

	if (fname) {
		char *file = fapolicyd_strcat(TRUST_DIR_PATH, fname);
		count = trust_file_delete_path(file, path);
		free(file);
	} else {
		count = trust_file_delete_path_all(path);
	}

	if (count == 0)
		msg(LOG_ERR, "%s is not in the trust database", path);

	return !count;
}

int file_update(const char *path, const char *fname)
{
	set_message_mode(MSG_STDERR, DBG_NO);
	int count;

	if (fname) {
		char *file = fapolicyd_strcat(TRUST_DIR_PATH, fname);
		count = trust_file_update_path(file, path);
		free(file);
	} else {
		count = trust_file_update_path_all(path);
	}

	if (count == 0)
		msg(LOG_ERR, "%s is not in the trust database", path);

	return !count;
}
