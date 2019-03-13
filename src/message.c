/*
 * message.c - function to syslog or write to stderr
 * Copyright (c) 2016 Red Hat Inc., Durham, North Carolina.
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
 *   Steve Grubb <sgrubb@redhat.com>
 */

#include "config.h"
#include <stdio.h>
#include <stdarg.h>
#include "message.h"

/* The message mode refers to where informational messages go
   0 - stderr, 1 - syslog, 2 - quiet. The default is quiet. */
static message_t message_mode = MSG_QUIET;
static debug_message_t debug_message = DBG_NO;

void set_message_mode(message_t mode, debug_message_t debug)
{
        message_mode = mode;
	debug_message = debug;
}

void msg(int priority, const char *fmt, ...)
{
        va_list   ap;

	if (message_mode == MSG_QUIET)
		return;

	if (priority == LOG_DEBUG && debug_message == DBG_NO)
		return;

        va_start(ap, fmt);
        if (message_mode == MSG_SYSLOG)
                vsyslog(priority, fmt, ap);
        else {
                vfprintf(stderr, fmt, ap);
		fputc('\n', stderr);
		fflush(stderr);
	}
        va_end( ap );
}
