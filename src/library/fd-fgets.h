/* fd-fgets.h -- a replacement for glibc's fgets
 * Copyright 2019,2020,2022,2025 Red Hat Inc.
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

typedef struct fd_fgets_state fd_fgets_state_t;

enum fd_mem {
	MEM_SELF_MANAGED,
        MEM_MALLOC,
        MEM_MMAP,
        MEM_MMAP_FILE
};

void fd_fgets_clear(void);
int fd_fgets_eof(void);
int fd_fgets_more(size_t blen);
int fd_fgets(char *buf, size_t blen, int fd)
	__attr_access ((__write_only__, 1, 2)) __wur;
int fd_setvbuf(void *buf, size_t buff_size, enum fd_mem how)
	__attr_access ((__read_only__, 1, 2));

void fd_fgets_destroy(fd_fgets_state_t *st);
fd_fgets_state_t *fd_fgets_init(void)
	__attribute_malloc__ __attr_dealloc (fd_fgets_destroy, 1);
void fd_fgets_clear_r(fd_fgets_state_t *st);
int fd_fgets_eof_r(fd_fgets_state_t *st);
int fd_fgets_more_r(fd_fgets_state_t *st, size_t blen);
int fd_fgets_r(fd_fgets_state_t *st, char *buf, size_t blen, int fd)
	__attr_access ((__write_only__, 2, 3)) __wur;
int fd_setvbuf_r(fd_fgets_state_t *st, void *buf, size_t buff_size,
		enum fd_mem how)
		__attr_access ((__read_only__, 2, 3));

#endif

