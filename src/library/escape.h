/*
 * escape.h - Header file for escaping capability
 * Copyright (c) 2021,23 Red Hat Inc.
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

#ifndef ESCAPE_H
#define ESCAPE_H

#include "gcc-attributes.h"

char *escape_shell(const char *, const size_t) __attr_access ((__read_only__, 1, 2)) MALLOCLIKE;
size_t check_escape_shell(const char *);
void unescape_shell(char *s, const size_t len) __attr_access ((__read_write__, 1, 2));

char *unescape(const char *input) MALLOCLIKE;

#endif

