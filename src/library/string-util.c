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

char *fapolicyd_strtrim(char *s)
{
	char *cp1;
	char *cp2;

	if (!s) return NULL;

	// skip leading spaces, via cp1
	for (cp1=s; isspace(*cp1); cp1++ );

	// shift left remaining chars, via cp2
	for (cp2=s; *cp1; cp1++, cp2++)
		*cp2 = *cp1;

	// mark new end of string for s
	*cp2-- = 0;

	// replace trailing spaces with '\0'
	while ( cp2 > s && isspace(*cp2) )
		*cp2-- = 0;

	return s;
}

char *fapolicyd_strcat(const char *s1, const char *s2)
{
	size_t s1_len = strlen(s1);
	size_t s2_len = strlen(s2);
	char *r = malloc(s1_len + s2_len + 1);
	strcpy(r, s1);
	strcat(r, s2);
	return r;
}
