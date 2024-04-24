/* fd-fgets.h -- a replacement for glibc's fgets
 * Copyright 2019,2020,2022 Red Hat Inc.
 * All Rights Reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Authors:
 *      Steve Grubb <sgrubb@redhat.com>
 */

#ifndef FD_FGETS_HEADER
#define FD_FGETS_HEADER

#include <sys/types.h>
#include "gcc-attributes.h"

#ifndef __attr_access
#  define __attr_access(x)
#endif

#ifndef FD_FGETS_BUF_SIZE
#  define FD_FGETS_BUF_SIZE 8192
#endif

typedef struct fd_fgets_context {
    char buffer[2*FD_FGETS_BUF_SIZE+1];
    char *current;
    char *eptr;
    int eof;
} fd_fgets_context_t;

void fd_fgets_destroy(fd_fgets_context_t *ctx);
fd_fgets_context_t * fd_fgets_init(void) __attribute_malloc__
     __attr_dealloc (fd_fgets_destroy, 1);

int fd_fgets_eof(fd_fgets_context_t *ctx);
void fd_fgets_rewind(fd_fgets_context_t *ctx);
int fd_fgets(fd_fgets_context_t *ctx, char *buf, size_t blen, int fd)
	__attr_access ((__write_only__, 2, 3));

#endif

