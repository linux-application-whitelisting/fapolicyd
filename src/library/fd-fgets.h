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

#ifndef __attr_access
#  define __attr_access(x)
#endif

int fd_fgets_eof(void);
void fd_fgets_rewind(void);
int fd_fgets(char *buf, size_t blen, int fd)
	__attr_access ((__write_only__, 1, 2));

#endif

