/*
 * string-util.c - useful string functions
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

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "string-util.h"

#pragma GCC optimize("O3")

char *fapolicyd_strtrim(char *s)
{
	if (!s)
		return NULL;

	// skip leading spaces
	char *start = s;
	while (*start && isspace((unsigned char)*start)) start++;

	// shift left (no-op if start == s)
	size_t len = strlen(start);
	memmove(s, start, len + 1);	// includes the '\0'

	// all spaces?
	if (*s == '\0')
		return s;

	// trim trailing
	char *end = s + len - 1;
	while (end >= s && isspace((unsigned char)*end))
		*end-- = '\0';

	return s;
}

char *fapolicyd_strcat(const char *s1, const char *s2)
{
	size_t s1_len = strlen(s1);
	size_t s2_len = strlen(s2);
	char *r = malloc(s1_len + s2_len + 1);
	if (r == NULL)
		return NULL;
	strcpy(r, s1);
	strcat(r, s2);
	return r;
}

char *fapolicyd_strnchr(const char *s, int c, size_t len)
{
	unsigned char uc = (unsigned char)c;

	for (; len--; ++s) {
		if ((unsigned char)*s == uc)
			return (char *)s;
		if (*s == '\0')
			break;
	}
	return NULL;
}
