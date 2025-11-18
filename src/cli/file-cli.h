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

/**
 * Append a path into the file trust database
 *
 * @param path Path to append into the file trust database
 * @param fname Filename where \p path should be written. If NULL, then
 *     \p path is written into fapolicyd.trust file. Otherwise,
 *     write \p path into file \p fname within the trust.d directory
 * @param use_filter When true, apply the filter configuration to the list of
 *     files gathered from \p path before writing anything
 * @return 0 on success, -1 on error and 1 if \p path already exists in
 *     the file trust database
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
 * @return 0 on success, non-zero if nothing got deleted
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
 * @return 0 on success, non-zero if nothing got updated
 */
int file_update(const char *path, const char *fname, bool use_filter);

#endif
