/*
 * message.c - function to syslog or write to stderr
 * Copyright (c) 2016 Red Hat Inc.
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
#include <pthread.h>  // for pthread_mutex_lock, pthread_mutex_unlock, PTHREAD_MUTEX_INITIALIZER, pthread_mutex_t
#include <stdarg.h>   // for va_end, va_list, va_start
#include <stdio.h>    // for fputs, stderr, fflush, fileno, fputc, vfprintf
#include <stdlib.h>   // for getenv
#include <syslog.h>   // for LOG_DEBUG, LOG_ALERT, LOG_CRIT, LOG_EMERG, LOG_ERR, LOG_INFO, LOG_NOTICE, LOG_WARNING, vsyslog
#include <time.h>     // for localtime_r, strftime, time, time_t, tm
#include <unistd.h>   // for isatty
#include "message.h"

/* The message mode refers to where informational messages go
	0 - stderr, 1 - syslog, 2 - quiet. The default is quiet. */
static message_t message_mode = MSG_QUIET;
static debug_message_t debug_message = DBG_NO;
static pthread_mutex_t msg_lock = PTHREAD_MUTEX_INITIALIZER;
static int use_color = -1;

void set_message_mode(message_t mode, debug_message_t debug)
{
	message_mode = mode;
	debug_message = debug;
}

void msg(int priority, const char *fmt, ...)
{
	va_list ap;

	if (message_mode == MSG_QUIET)
		return;

	if (priority == LOG_DEBUG && debug_message == DBG_NO)
		return;

	if (use_color == -1) {
		const char *nc = getenv("NO_COLOR");
		if (nc && nc[0] != '\0')
			use_color = 0;
		else if (!isatty(fileno(stderr)))
			use_color = 0;
		else
			use_color = 1;
	}

	pthread_mutex_lock(&msg_lock);
	va_start(ap, fmt);
	if (message_mode == MSG_SYSLOG)
		vsyslog(priority, fmt, ap);
	else {
		// For stderr we'll include the log level, use ANSI escape
		// codes to colourise the it, and prefix lines with the time
		// and date.
		const char *color = "";
		const char *reset = "";
		const char *level;

		if (use_color) {
			reset = "\x1b[0m";
			switch (priority) {
			case LOG_EMERG:	   color = "\x1b[31m"; break; /* Red */
			case LOG_ALERT:	   color = "\x1b[35m"; break; /* Magenta */
			case LOG_CRIT:	   color = "\x1b[33m"; break; /* Yellow */
			case LOG_ERR:	   color = "\x1b[31m"; break; /* Red */
			case LOG_WARNING:  color = "\x1b[33m"; break; /* Yellow */
			case LOG_NOTICE:   color = "\x1b[32m"; break; /* Green */
			case LOG_INFO:	   color = "\x1b[36m"; break; /* Cyan */
			case LOG_DEBUG:	   color = "\x1b[34m"; break; /* Blue */
			default:	   color = "\x1b[0m";  break; /* Reset */
			}
		}

		switch (priority) {
		case LOG_EMERG:	   level = "EMERGENCY"; break;
		case LOG_ALERT:	   level = "ALERT"; break;
		case LOG_CRIT:	   level = "CRITICAL"; break;
		case LOG_ERR:	   level = "ERROR"; break;
		case LOG_WARNING:  level = "WARNING"; break;
		case LOG_NOTICE:   level = "NOTICE"; break;
		case LOG_INFO:	   level = "INFO"; break;
		case LOG_DEBUG:	   level = "DEBUG"; break;
		default:	   level = "UNKNOWN"; break;
		}

		time_t rawtime;
		struct tm timeinfo;
		char buffer[80];

		time(&rawtime);
		// localtime is not threadsafe, use _r version for safety
		(void) localtime_r(&rawtime, &timeinfo);

		strftime(buffer, sizeof(buffer), "%x %T [ ", &timeinfo);
		fputs(buffer, stderr);

		fputs(color, stderr);
		fputs(level, stderr);
		fputs(reset, stderr);
		fputs(" ]: ", stderr);

		vfprintf(stderr, fmt, ap);
		fputc('\n', stderr);

		fflush(stderr);
	}
	va_end(ap);
	pthread_mutex_unlock(&msg_lock);
}
