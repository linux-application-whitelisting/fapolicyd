/*
 * string-util.h - Header file for string-util
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
 *   Zoltan Fridrich <zfridric@redhat.com>
 */

#ifndef STRING_UTIL_H
#define STRING_UTIL_H

#include "gcc-attributes.h"

char *fapolicyd_strtrim(char *s);

/**
 * Concatenates two NULL terminated strings
 *
 * @param s1 First NULL terminated string
 * @param s2 Second NULL terminated string
 * @return Dynamically allocated NULL terminated string s1||s2
 */
char *fapolicyd_strcat(const char *s1, const char *s2) MALLOCLIKE;

#endif
