/*
 * trust-file.h - Header for managing trust files
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

#ifndef TRUST_FILE_H
#define TRUST_FILE_H

#include "llist.h"

#define TRUST_FILE_PATH "/etc/fapolicyd/fapolicyd.trust"
#define TRUST_DIR_PATH "/etc/fapolicyd/trust.d/"

int trust_file_append(const char *fpath, list_t *list);
int trust_file_load(const char *fpath, list_t *list, int memfd);
int trust_file_update_path(const char *fpath, const char *path);
int trust_file_delete_path(const char *fpath, const char *path);
int trust_file_rm_duplicates(const char *fpath, list_t *list);

void trust_file_load_all(list_t *list, int memfd);
int trust_file_update_path_all(const char *path);
int trust_file_delete_path_all(const char *path);
void trust_file_rm_duplicates_all(list_t *list);

#endif
