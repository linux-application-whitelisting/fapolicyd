/*
 * fapolicyd-backend.h - Header file for database backend interface
 * Copyright (c) 2020-23 Red Hat Inc.
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

#ifndef FAPOLICYD_BACKEND_HEADER
#define FAPOLICYD_BACKEND_HEADER

#include "conf.h"
#include "llist.h"

// If this gets extended, please put the new items at the end.
typedef enum { SRC_UNKNOWN, SRC_RPM, SRC_FILE_DB, SRC_DEB, SRC_EBUILD } trust_src_t;

// source, size, sha
#define DATA_FORMAT "%u %lu %64s"

typedef struct _backend
{
	const char * name;
	int (*init)(void);
	int (*load)(const conf_t *);
	int (*close)(void);
	list_t list;
} backend;

#endif
