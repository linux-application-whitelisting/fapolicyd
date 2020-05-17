/*
 * string-util.c - useful string functions
 * Copyright (c) 2020 Red Hat Inc., Durham, North Carolina.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "string-util.h"

char * fapolicyd_strtrim(char * s)
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

char * fapolicyd_get_line(FILE *f, char *buf)
{
	if (fgets_unlocked(buf, BUFFER_MAX-1, f)) {

		/* remove newline */
		char *ptr = strchr(buf, 0x0a);
		if (ptr)
			*ptr = 0;
		return buf;
	}

	return NULL;
}
