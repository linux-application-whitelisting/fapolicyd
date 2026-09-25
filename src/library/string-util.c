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

#include "config.h"

/*
 * Keep this feature selection before every system header. fapolicyd enables
 * _GNU_SOURCE globally, which makes glibc expose its non-portable, char *
 * strerror_r(). This translation unit deliberately selects POSIX.1-2008 so
 * glibc and musl both expose the XSI, int-returning interface. Do not remove
 * or move this override without changing fapolicyd_strerror() with it.
 */
#undef _GNU_SOURCE
#undef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "string-util.h"

#pragma GCC optimize("O3")

_Static_assert(_Generic(&strerror_r,
	int (*)(int, char *, size_t): 1, default: 0),
	"fapolicyd requires the XSI strerror_r interface");

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
	memcpy(r, s1, s1_len);
	memcpy(r + s1_len, s2, s2_len + 1);  // includes null terminator
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

/*
 * fapolicyd_strerror - provide one strerror_r interface across C libraries.
 * @errnum: error number to describe.
 * @buf: caller-owned output buffer.
 * @buf_size: size of @buf.
 *
 * Returns @buf containing the error description, or a fixed string when no
 * writable buffer was supplied. This translation unit forces and verifies the
 * portable XSI strerror_r interface above.
 */
const char *fapolicyd_strerror(int errnum, char *buf, size_t buf_size)
{
	if (buf == NULL || buf_size == 0)
		return "Unknown error";

	if (strerror_r(errnum, buf, buf_size) != 0)
		snprintf(buf, buf_size, "Unknown error %d", errnum);
	return buf;
}

/*
 * fapolicyd_format_ns - format nanoseconds for compact reports.
 * @ns: duration or age in nanoseconds.
 * @buf: destination buffer.
 * @buf_size: destination size.
 *
 * Returns nothing.
 */
void fapolicyd_format_ns(uint64_t ns, char *buf, size_t buf_size)
{
	if (buf == NULL || buf_size == 0)
		return;

	if (ns == 0)
		snprintf(buf, buf_size, "0 ns");
	else if (ns < 1000ULL)
		snprintf(buf, buf_size, "%llu ns", (unsigned long long)ns);
	else if (ns < 1000000ULL)
		snprintf(buf, buf_size, "%.3fus", (double)ns / 1000.0);
	else if (ns < 1000000000ULL)
		snprintf(buf, buf_size, "%.3fms", (double)ns / 1000000.0);
	else
		snprintf(buf, buf_size, "%.3fs", (double)ns / 1000000000.0);
}
