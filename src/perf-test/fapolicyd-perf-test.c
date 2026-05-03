/*
 * fapolicyd-perf-test.c - fapolicyd performance testing tool
 * Copyright (c) 2025-2026 Red Hat Inc.
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
 *   Ondrej Mosnacek <omosnace@redhat.com>
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdatomic.h>

#include <fcntl.h>
#include <unistd.h>
#include <sys/time.h>

#include "config.h"

#include "daemon-config.h"
#include "message.h"
#include "policy.h"
#include "database.h"

/* These need to be defined for the library */
atomic_bool stop = 0;
unsigned int debug_mode = 0;
conf_t config = {};

static char *get_line(FILE *f)
{
	char *line = NULL;
	size_t len = 0;

	while (getline(&line, &len, f) != -1) {
		/* remove newline */
		char *ptr = strchr(line, 0x0a);
		if (ptr)
			*ptr = 0;
		return line;
	}
	free(line);
	return NULL;
}

static int do_perf_test(FILE *input)
{
	int rc = 0, resp_fd;
	pid_t our_pid;
	struct timeval t0, t1;
	char *path;

	set_message_mode(MSG_STDERR, DBG_NO);
	if (load_daemon_config(&config)) {
		rc = 1;
		goto out_reset_config;
	}
	if (load_rules(&config)) {
		rc = 1;
		goto out_reset_config;
	}
	// Setup lru caches
	if (init_event_system(&config)) {
		rc = 1;
		goto out_rules;
	}
	if (init_database(&config)) {
		rc = 1;
		goto out_event_system;
	}
	// Init the file test libraries
	file_init();
	// Don't let it accidently emit audit events
	policy_no_audit();

	resp_fd = open("/dev/null", O_WRONLY|O_CLOEXEC);
	if (resp_fd < 0) {
		fprintf(stderr, "Can't open dev null\n");
		rc = 1;
		goto out_file;
	}

	our_pid = getpid();
	printf("Starting scan...\n");

	gettimeofday(&t0, NULL);
	while ((path = get_line(input))) {
		int fd = open(path, O_RDONLY|O_CLOEXEC);
		free(path);
		if (fd < 0)
			continue;
		// Build an "event" to exercise fapolicyd's decision making
		struct fanotify_event_metadata metadata;
		decision_event_t event;

		metadata.fd = fd; // listener closes after reply
		metadata.pid = our_pid;
		metadata.mask = FAN_OPEN_PERM;

		decision_event_init(&event, &metadata);
		make_policy_decision(&event, resp_fd,
				     FAN_OPEN_PERM | FAN_OPEN_EXEC_PERM);
	}
	stop = 1;
	gettimeofday(&t1, NULL);

	long sec  = t1.tv_sec  - t0.tv_sec;
	long usec = t1.tv_usec - t0.tv_usec;
	if (usec < 0) {
		usec += 1000000;
		sec--;
	}
	long msec = usec / 1000;
	printf("Elapsed: %ld seconds, %ld milliseconds\n", sec, msec);

	close(resp_fd);
out_file:
	file_close();
	close_database();
out_event_system:
	destroy_event_system();
	unlink_fifo();
out_rules:
	destroy_rules();
out_reset_config:
	free_daemon_config(&config);
	return rc;
}

static const char *USAGE =
"Fapolicyd Performace Test\n\n"
"Usage: %s [INPUT_FILE]\n\n"
"Runs a dummy fapolicyd policy decision on each file from newline-separated\n"
"list read from INPUT_FILE (or stdin if not specified) and prints the total"
"time it took.\n"
;

int main(int argc, char * const argv[])
{
	FILE *input = stdin;
	int rc;

	if (argc > 2) {
		printf(USAGE, argv[0]);
		return 2;
	}

	if (argc > 1) {
		input = fopen(argv[1], "r");
		if (input == NULL) {
			fprintf(stderr, "Error opening input file\n");
			return 1;
		}
	}

	rc = do_perf_test(input);
	if (input != stdin)
		fclose(input);
	return rc;
}
