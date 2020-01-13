/*
 * backend-manager.h - Header file for backend manager
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
 */

#ifndef BACKEND_MANAGER_H
#define BACKEND_MANAGER_H

#include <stdbool.h>

#include "conf.h"
#include "fapolicyd-backend.h"

typedef struct _backend_entry {
	backend * backend;
	struct _backend_entry * next;
} backend_entry;


int backend_init(const conf_t * conf);
int backend_load(void);
void backend_close(void);
backend_entry* backend_get_first(void);

#endif
