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
#include <stdbool.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "llist.h"
#include "message.h"
#include "string-util.h"
#include "trust-file.h"
#include "filter.h"
#include "file-cli.h"



#define FTW_NOPENFD 1024
#define FTW_FLAGS (FTW_ACTIONRETVAL | FTW_PHYS)



list_t add_list;



static int ftw_add_list_append(const char *fpath,
		const struct stat *sb __attribute__ ((unused)),
		int typeflag,
		struct FTW *ftwbuf __attribute__ ((unused)))
{
	if (typeflag == FTW_F) {
		if (S_ISREG(sb->st_mode)) {
			char *tmp = strdup(fpath);
			if (!tmp) {
				errno = ENOMEM;
				return FTW_STOP;
			}
			if (list_append(&add_list, tmp, NULL)) {
				free(tmp);
				errno = ENOMEM;
				return FTW_STOP;
			}
		} else {
			msg(LOG_INFO, "Skipping non regular file: %s", fpath);
		}
	}
	return FTW_CONTINUE;
}

/**
 * Load path into add_list. If path is a directory,
 * loads all regular files within the directory tree
 *
 * @param path Path to load into add_list
 * @return CLI_EXIT_SUCCESS on success, CLI_EXIT_IO for filesystem problems,
 *     and CLI_EXIT_INTERNAL on allocation failures
 */
static int add_list_load_path(const char *path)
{
	int fd = open(path, O_RDONLY|O_NONBLOCK);
	if (fd < 0) {
		msg(LOG_ERR, "Cannot open %s", path);
		return CLI_EXIT_IO;
	}

	struct stat sb;
	if (fstat(fd, &sb)) {
		msg(LOG_ERR, "Cannot stat %s", path);
		close(fd);
		return CLI_EXIT_IO;
	}
	close(fd);

	int rc;

	if (S_ISDIR(sb.st_mode))
		rc = nftw(path, &ftw_add_list_append, FTW_NOPENFD, FTW_FLAGS);
	else {
		char *tmp = strdup(path);
		if (!tmp)
			return CLI_EXIT_INTERNAL;
		rc = list_append(&add_list, tmp, NULL);
		if (rc)
			free(tmp);
	}

	if (rc) {
		if (errno == ENOMEM)
			return CLI_EXIT_INTERNAL;
		return CLI_EXIT_IO;
	}

	return CLI_EXIT_SUCCESS;
}

int file_append(const char *path, const char *fname, bool use_filter)
{
	int rc;

	set_message_mode(MSG_STDERR, DBG_NO);

	list_init(&add_list);
	rc = add_list_load_path(path);
	if (rc) {
		list_empty(&add_list); // could be partially populated by nftw
		return rc;
	}

	if (use_filter && filter_prune_list(&add_list, NULL)) {
		list_empty(&add_list);
		return CLI_EXIT_RULE_FILTER;
	}

	trust_file_rm_duplicates_all(&add_list);

	if (add_list.count == 0) {
		msg(LOG_ERR,
		    "After removing duplicates, there is nothing to add");
		return CLI_EXIT_NOOP;
	}

	char *dest = fname ? fapolicyd_strcat(TRUST_DIR_PATH, fname) :
							TRUST_FILE_PATH;
	if (dest == NULL)
		return CLI_EXIT_INTERNAL;

	rc = trust_file_append(dest, &add_list);

	list_empty(&add_list);

	if (fname)
		free(dest);

	return rc ? CLI_EXIT_IO : CLI_EXIT_SUCCESS;
}

int file_delete(const char *path, const char *fname)
{
	int count = 0, rc;

	set_message_mode(MSG_STDERR, DBG_NO);

	if (fname) {
		char *file = fapolicyd_strcat(TRUST_DIR_PATH, fname);
		if (file) {
			count = trust_file_delete_path(file, path);
			free(file);
		} else
			return CLI_EXIT_INTERNAL;
	} else {
		count = trust_file_delete_path_all(path);
	}

	if (count < 0)
		rc = CLI_EXIT_PATH_CONFIG;
	else if (count == 0) {
		msg(LOG_ERR, "%s is not in the trust database", path);
		rc = CLI_EXIT_NOOP;
	} else
		rc = CLI_EXIT_SUCCESS;

	return rc;
}

int file_update(const char *path, const char *fname, bool use_filter)
{
	set_message_mode(MSG_STDERR, DBG_NO);
	int count = 0, rc = CLI_EXIT_SUCCESS;
	bool filter_ready = false;

	if (use_filter) {
		if (filter_init())
			return CLI_EXIT_RULE_FILTER;
		if (filter_load_file(NULL)) {
			filter_destroy();
			return CLI_EXIT_RULE_FILTER;
		}
		filter_ready = true;
	}

	if (fname) {
		char *file = fapolicyd_strcat(TRUST_DIR_PATH, fname);
		if (file) {
			count = trust_file_update_path(file, path, use_filter);
			free(file);
		} else
			count = -1;
	} else {
		count = trust_file_update_path_all(path, use_filter);
	}

	if (filter_ready)
		filter_destroy();

	if (count < 0)
		rc = CLI_EXIT_PATH_CONFIG;
	else if (count == 0) {
		msg(LOG_ERR, "%s is not in the trust database", path);
		rc = CLI_EXIT_NOOP;
	}

	return rc;
}
