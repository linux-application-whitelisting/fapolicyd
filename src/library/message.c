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
#include <stdatomic.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "message.h"

/* The message mode refers to where informational messages go
	0 - stderr, 1 - syslog, 2 - quiet. The default is quiet. */
static message_t message_mode = MSG_QUIET;
static debug_message_t debug_message = DBG_NO;
static atomic_int stderr_color_state = ATOMIC_VAR_INIT(-1);

struct message_level {
	const char *name;
	const char *color;
};

/*
 * message_level_info - return display metadata for one syslog priority.
 * @priority: syslog LOG_* priority value.
 * Returns the printable level name and ANSI color for @priority.
 */
static struct message_level message_level_info(int priority)
{
	switch (priority) {
	case LOG_EMERG:
		return (struct message_level){ "EMERGENCY", "\x1b[31m" };
	case LOG_ALERT:
		return (struct message_level){ "ALERT", "\x1b[35m" };
	case LOG_CRIT:
		return (struct message_level){ "CRITICAL", "\x1b[33m" };
	case LOG_ERR:
		return (struct message_level){ "ERROR", "\x1b[31m" };
	case LOG_WARNING:
		return (struct message_level){ "WARNING", "\x1b[33m" };
	case LOG_NOTICE:
		return (struct message_level){ "NOTICE", "\x1b[32m" };
	case LOG_INFO:
		return (struct message_level){ "INFO", "\x1b[36m" };
	case LOG_DEBUG:
		return (struct message_level){ "DEBUG", "\x1b[34m" };
	default:
		return (struct message_level){ "UNKNOWN", "" };
	}
}

/*
 * detect_stderr_color - determine whether stderr should receive ANSI color.
 * Returns 1 for color-capable interactive stderr, 0 otherwise.
 */
static int detect_stderr_color(void)
{
	const char *no_color = getenv("NO_COLOR");
	const char *term = getenv("TERM");

	if (no_color && no_color[0] != '\0')
		return 0;
	if (term && strcmp(term, "dumb") == 0)
		return 0;
	return isatty(fileno(stderr));
}

/*
 * stderr_color_enabled - return the cached stderr color decision.
 * Returns 1 when color should be used, 0 when plain text should be used.
 */
static int stderr_color_enabled(void)
{
	for (;;) {
		int cached = atomic_load_explicit(&stderr_color_state,
						 memory_order_relaxed);
		int expected = -1;
		int detected;

		if (cached != -1)
			return cached;

		detected = detect_stderr_color();
		if (atomic_compare_exchange_strong_explicit(&stderr_color_state,
			    &expected, detected, memory_order_relaxed,
			    memory_order_relaxed))
			return detected;
	}
}

/*
 * msg_stderr - emit one complete formatted message record to stderr.
 * @priority: syslog LOG_* priority used for level display.
 * @fmt: printf-style format string.
 * @ap: argument list for @fmt.
 *
 * Returns nothing. The shared stderr stream is locked only while writing the
 * record so prefix/body/newline output cannot interleave with other threads.
 */
static void msg_stderr(int priority, const char *fmt, va_list ap)
{
	struct message_level level = message_level_info(priority);
	time_t rawtime = time(NULL);
	struct tm timeinfo;
	char buffer[80];
	const char *time_prefix = "time unavailable [ ";
	const int use_color = stderr_color_enabled();

	if (rawtime != (time_t)-1 &&
	    localtime_r(&rawtime, &timeinfo) != NULL &&
	    strftime(buffer, sizeof(buffer), "%x %T [ ", &timeinfo) != 0)
		time_prefix = buffer;

	flockfile(stderr);
	fputs(time_prefix, stderr);
	if (use_color)
		fputs(level.color, stderr);
	fputs(level.name, stderr);
	if (use_color)
		fputs("\x1b[0m", stderr);
	fputs(" ]: ", stderr);
	vfprintf(stderr, fmt, ap);
	fputc('\n', stderr);
	fflush(stderr);
	funlockfile(stderr);
}

void set_message_mode(message_t mode, debug_message_t debug)
{
	message_mode = mode;
	debug_message = debug;
	if (mode == MSG_STDERR)
		atomic_store_explicit(&stderr_color_state, -1,
				      memory_order_relaxed);
}

void msg(int priority, const char *fmt, ...)
{
	va_list ap;

	if (message_mode == MSG_QUIET)
		return;

	if (priority == LOG_DEBUG && debug_message == DBG_NO)
		return;

	va_start(ap, fmt);
	if (message_mode == MSG_SYSLOG)
		vsyslog(priority, fmt, ap);
	else
		msg_stderr(priority, fmt, ap);
	va_end(ap);
}
