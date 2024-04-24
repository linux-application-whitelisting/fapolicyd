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
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include "fd-fgets.h"


fd_fgets_context_t * fd_fgets_init(void)
{
	fd_fgets_context_t *ctx = malloc(sizeof(fd_fgets_context_t));
	if (!ctx)
		return NULL;

	memset(ctx->buffer, 0, sizeof(ctx->buffer));
	ctx->current = ctx->buffer;
	ctx->eptr = ctx->buffer+(2*FD_FGETS_BUF_SIZE);
	ctx->eof = 0;
	return ctx;
}

void fd_fgets_destroy(fd_fgets_context_t *ctx)
{
	free(ctx);
}

int fd_fgets_eof(fd_fgets_context_t *ctx)
{
	return ctx->eof;
}

void fd_fgets_rewind(fd_fgets_context_t *ctx)
{
	ctx->eof = 0;
}

int fd_fgets(fd_fgets_context_t *ctx, char *buf, size_t blen, int fd)
{
	int complete = 0;
	size_t line_len = 0;
	char *line_end = NULL;

	assert(blen != 0);
	/* See if we have more in the buffer first */
	if (ctx->current != ctx->buffer) {
		line_end = strchr(ctx->buffer, '\n');
		if (line_end == NULL && (size_t)(ctx->current - ctx->buffer) >= blen-1)
			line_end = ctx->current-1; //enough to fill blen,point to end
	}

	/* Otherwise get some new bytes */
	if (line_end == NULL && ctx->current != ctx->eptr && !ctx->eof) {
		ssize_t len;

		/* Use current since we may be adding more */
		do {
			len = read(fd, ctx->current, ctx->eptr - ctx->current);
		} while (len < 0 && errno == EINTR);
		if (len < 0)
			return -1;
		if (len == 0)
			ctx->eof = 1;
		else
			ctx->current[len] = 0;
		ctx->current += len;

		/* Start from beginning to see if we have one */
		line_end = strchr(ctx->buffer, '\n');
	}

	/* See what we have */
	if (line_end) {
		/* Include the last character (usually newline) */
		line_len = (line_end+1) - ctx->buffer;
		/* Make sure we are within the right size */
		if (line_len > blen-1)
			line_len = blen-1;
		complete = 1;
	} else if (ctx->current == ctx->eptr) {
		/* We are full but no newline */
		line_len = blen-1;
		complete = 1;
	} else if (ctx->current >= ctx->buffer+blen-1) {
		/* Not completely full, no newline, but enough to fill buf */
		line_len = blen-1;
		complete = 1;
	}
	if (complete) {
		size_t remainder_len;

		/* Move to external buf and terminate it */
		memcpy(buf, ctx->buffer, line_len);
		buf[line_len] = 0;
		remainder_len = ctx->current - (ctx->buffer + line_len);
		if (remainder_len > 0) {
			/* We have a few leftover bytes to move */
			memmove(ctx->buffer, ctx->buffer+line_len, remainder_len);
			ctx->current = ctx->buffer+remainder_len;
		} else {
			/* Got the whole thing, just reset */
			ctx->current = ctx->buffer;
		}
		*(ctx->current) = 0;
	}
	return complete;
}
