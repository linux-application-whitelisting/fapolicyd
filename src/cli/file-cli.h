/*
 * file-backend.h - Header file for CLI option file
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
 *   Steve Grubb <sgrubb@redhat.com>
 *   Radovan Sroka <rsroka@redhat.com>
 *   Zoltan Fridrich <zfridric@redhat.com>
 */

#ifndef FILE_CLI_H
#define FILE_CLI_H

#include <stdbool.h>

enum cli_exit_status {
	CLI_EXIT_SUCCESS = 0,
	CLI_EXIT_GENERIC = 1,
	CLI_EXIT_USAGE = 2,
	CLI_EXIT_PATH_CONFIG = 3,
	CLI_EXIT_DB_ERROR = 4,
	CLI_EXIT_RULE_FILTER = 5,
	CLI_EXIT_DAEMON_IPC = 6,
	CLI_EXIT_IO = 7,
	CLI_EXIT_INTERNAL = 8,
	CLI_EXIT_NOOP = 9,
};

/**
 * Append a path into the file trust database
 *
 * @param path Path to append into the file trust database
 * @param fname Filename where \p path should be written. If NULL, then
 *     \p path is written into fapolicyd.trust file. Otherwise,
 *     write \p path into file \p fname within the trust.d directory
 * @param use_filter When true, apply the filter configuration to the list of
 *     files gathered from \p path before writing anything
 * @return CLI_EXIT_SUCCESS on success, CLI_EXIT_NOOP when no new entries are
 *     added, CLI_EXIT_RULE_FILTER for filter failures, CLI_EXIT_INTERNAL on
 *     allocation failures, and CLI_EXIT_IO for filesystem errors.
 */
int file_append(const char *path, const char *fname, bool use_filter);

/**
 * Delete a path from the file trust database.
 * It matches all occurrances so that a directory may be passed and
 * all parts of it get deleted
 *
 * @param path Path to delete from the file trust database
 * @param fname Filename from which \p path should be deleted. If NULL, then
 *     \p path is deleted from fapolicyd.trust file. Otherwise,
 *     deletes \p path from file \p fname within the trust.d directory
 * @return CLI_EXIT_SUCCESS on success, CLI_EXIT_NOOP when nothing is removed,
 *     CLI_EXIT_IO for filesystem errors, and CLI_EXIT_PATH_CONFIG when trust
 *     files cannot be parsed.
 */
int file_delete(const char *path, const char *fname);

/**
 * Update a path in the file trust database.
 * It matches all occurrances so that a directory may be passed and
 * all parts of it get updated
 *
 * @param path Path to update in the file trust database
 * @param fname Filename in which \p path should be updated. If NULL, then
 *     \p path is updated in fapolicyd.trust file. Otherwise,
 *     updates \p path in file \p fname within the trust.d directory
 * @param use_filter When true, apply the filter configuration to the list of
 *     files being updated so that filtered paths are skipped
 * @return CLI_EXIT_SUCCESS on success, CLI_EXIT_NOOP when nothing is updated,
 *     CLI_EXIT_RULE_FILTER for filter parsing errors, CLI_EXIT_IO for
 *     filesystem errors, and CLI_EXIT_PATH_CONFIG when trust files cannot be
 *     parsed.
 */
int file_update(const char *path, const char *fname, bool use_filter);

#endif
