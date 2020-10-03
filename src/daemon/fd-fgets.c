/* fd-fgets.c --
 * Copyright 2019,2020 Red Hat Inc.
 * All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Authors:
 *   Steve Grubb <sgrubb@redhat.com>
 */

#include "config.h"
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include "fd-fgets.h"

#define BUF_SIZE 8192
static char buffer[2*BUF_SIZE+1] = { 0 };
static char *current = buffer;
static const char *eptr = buffer+(2*BUF_SIZE);
static int eof = 0;

int fd_fgets_eof(void)
{
	return eof;
}

void fd_fgets_rewind(void)
{
	eof = 0;
}

int fd_fgets(char *buf, size_t blen, int fd)
{
	int complete = 0;
	size_t line_len = 0;
	char *line_end = NULL;

	assert(blen != 0);
	/* See if we have more in the buffer first */
	if (current != buffer) {
		line_end = strchr(buffer, '\n');
		if (line_end == NULL && (size_t)(current - buffer) >= blen-1)
			line_end = current-1; //enough to fill blen,point to end
	}

	/* Otherwise get some new bytes */
	if (line_end == NULL && current != eptr && !eof) {
		ssize_t len;

		/* Use current since we may be adding more */
		do {
			len = read(fd, current, eptr - current);
		} while (len < 0 && errno == EINTR);
		if (len < 0)
			return -1;
		if (len == 0)
			eof = 1;
		else
			current[len] = 0;
		current += len;

		/* Start from beginning to see if we have one */
		line_end = strchr(buffer, '\n');
	}

	/* See what we have */
	if (line_end) {
		/* Include the last character (usually newline) */
		line_len = (line_end+1) - buffer;
		/* Make sure we are within the right size */
		if (line_len > blen-1)
			line_len = blen-1;
		complete = 1;
	} else if (current == eptr) {
		/* We are full but no newline */
		line_len = blen-1;
		complete = 1;
	} else if (current >= buffer+blen-1) {
		/* Not completely full, no newline, but enough to fill buf */
		line_len = blen-1;
		complete = 1;
	}
	if (complete) {
		size_t remainder_len;

		/* Move to external buf and terminate it */
		memcpy(buf, buffer, line_len);
		buf[line_len] = 0;
		remainder_len = current - (buffer + line_len);
		if (remainder_len > 0) {
			/* We have a few leftover bytes to move */
			memmove(buffer, buffer+line_len, remainder_len);
			current = buffer+remainder_len;
		} else {
			/* Got the whole thing, just reset */
			current = buffer;
		}
		*current = 0;
	}
	return complete;
}
