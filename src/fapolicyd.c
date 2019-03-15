/*
 * fapolicyd.c - Main file for the program
 * Copyright (c) 2016,2018 Red Hat Inc., Durham, North Carolina.
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
 *   Radovan Sroka <rsroka@redhat.com>
 */

#include "config.h"
#include <stdio.h>
#include <poll.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/resource.h>
#include <stdio.h>
#include <ctype.h>
#include <grp.h>
#include <cap-ng.h>
#include <sys/prctl.h>
#include <linux/unistd.h>  /* syscall numbers */
#include <sys/stat.h>	/* umask */
#include <seccomp.h>
#include <stdatomic.h>

#include "notify.h"
#include "policy.h"
#include "event.h"
#include "file.h"
#include "database.h"
#include "message.h"
#include "daemon-config.h"
#include "queue.h"


// Global program variables
int debug = 0, permissive = 0;

// Signal handler notifications
volatile atomic_bool stop = 0;

// Local variables
static const char *pidfile = "/run/fapolicyd.pid";
#define REPORT "/var/log/fapolicyd-access.log"
static struct daemon_conf config;


static void install_syscall_filter(void)
{
	scmp_filter_ctx ctx;
	int rc = -1;

	ctx = seccomp_init(SCMP_ACT_ALLOW);
	if (ctx == NULL)
		goto err_out;

	rc = seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EACCES),
				SCMP_SYS(execve), 0);
	if (rc < 0)
		goto err_out;
#ifdef HAVE_FEXECVE
# ifdef __NR_fexecve
	rc = seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EACCES),
				SCMP_SYS(fexecve), 0);
	if (rc < 0)
		goto err_out;
# endif
#endif
	rc = seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EIO),
				SCMP_SYS(sendfile), 0);
	if (rc < 0)
		goto err_out;

	rc = seccomp_load(ctx);
err_out:
	if (rc < 0)
		msg(LOG_ERR, "Failed installing seccomp filter");
	seccomp_release(ctx);
}

static void term_handler(int sig)
{
	stop = 1 + sig; // Just so its used...
}

// This is a workaround for https://bugzilla.redhat.com/show_bug.cgi?id=643031
#define UNUSED(x) (void)(x)
extern int rpmsqEnable (int signum, void *handler);
int rpmsqEnable (int signum, void *handler)
{
	UNUSED(signum);
	UNUSED(handler);
	return 0;
}

static int write_pid_file(void)
{
	int pidfd, len;
	char val[16];

	len = snprintf(val, sizeof(val), "%u\n", getpid());
	if (len <= 0) {
		msg(LOG_ERR, "Pid error (%s)", strerror(errno));
		pidfile = NULL;
		return 1;
	}
	pidfd = open(pidfile, O_CREAT | O_TRUNC | O_NOFOLLOW | O_WRONLY, 0644);
	if (pidfd < 0) {
		msg(LOG_ERR, "Unable to set pidfile (%s)",
			strerror(errno));
		pidfile = NULL;
		return 1;
	}
	if (write(pidfd, val, (unsigned int)len) != len) {
		msg(LOG_ERR, "Unable to write pidfile (%s)",
			strerror(errno));
		close(pidfd);
		pidfile = NULL;
		return 1;
	}
	close(pidfd);
	return 0;
}

static int become_daemon(void)
{
	int fd;
	pid_t pid;

	pid = fork();
	switch (pid)
	{
		case 0: // Child
			fd = open("/dev/null", O_RDWR);
			if (fd < 0) return -1;
			if (dup2(fd, 0) < 0) {
				close(fd);
				return -1;
			}
			if (dup2(fd, 1) < 0) {
				close(fd);
				return -1;
			}
			if (dup2(fd, 2) < 0) {
				close(fd);
				return -1;
			}
			close(fd);
			chdir("/");
			if (setsid() < 0)
				return -1;
			break;
		case -1:
			return -1;
			break;
		default:	// Parent
			_exit(0);
			break;
	}
	return 0;
}

static void usage(void)
{
	fprintf(stderr,
		"Usage: fapolicyd [--debug|--debug-deny] [--permissive] "
		"[--boost xxx]\n\t\t[--queue xxx] [--user xx] [--group xx]"
		"[--no-details]\n");
	exit(1);
}

int main(int argc, char *argv[])
{
	struct pollfd pfd[1];
	struct sigaction sa;
	struct rlimit limit;
	int rc, i;

	if (argc > 1 && strcmp(argv[1], "--help") == 0)
		usage();
	set_message_mode(MSG_STDERR, debug);
	if (load_daemon_config(&config)) {
		msg(LOG_ERR, "Exiting due to bad configuration");
		return 1;
	}
	permissive = config.permissive;
	for (i=1; i < argc; i++) {
		if (strcmp(argv[i], "--debug") == 0) {
			debug = 1;
			set_message_mode(MSG_STDERR, DBG_YES);
		} else if (strcmp(argv[i], "--debug-deny") == 0) {
			debug = 2;
			set_message_mode(MSG_STDERR, DBG_YES);
		} else if (strcmp(argv[i], "--permissive") == 0) {
			permissive = 1;
		} else if (strcmp(argv[i], "--boost") == 0) {
			i++;
			if (i == argc || !isdigit(*argv[i])) {
				msg(LOG_ERR, "boost takes a numeric argument");
				exit(1);
			}
			errno = 0;
			config.nice_val = strtoul(argv[i], NULL, 10);
			if (errno) {
				msg(LOG_ERR, "Error converting boost value");
				exit(1);
			}
			if (config.nice_val > 20) {
				msg(LOG_ERR,
					"boost value must be less than or"
					" equal to 20");
				exit(1);
			}
		} else if (strcmp(argv[i], "--queue") == 0) {
			i++;
			if (i == argc || !isdigit(*argv[i])) {
				msg(LOG_ERR, "queue takes a numeric argument");
				exit(1);
			}
			errno = 0;
			config.q_size = strtoul(argv[i], NULL, 10);
			if (errno) {
				msg(LOG_ERR, "Error converting queue value");
				exit(1);
			}
			if (config.q_size >= 10480) {
				msg(LOG_WARNING,
					"q_size might be unnecessarily large");
			}
		} else if (strcmp(argv[i], "--user") == 0) {
			i++;
			if (i == argc || *argv[i] == '-') {
				msg(LOG_ERR, "user takes an argument");
				exit(1);
			}
			if (isdigit(*argv[i])) {
				errno = 0;
				struct passwd *pw;

				config.uid = strtoul(argv[i], NULL, 10);

				if (errno) {
					msg(LOG_ERR,
						"Error converting user value");
					exit(1);
				}

				pw = getpwuid(config.uid);

				if (pw == NULL) {
					msg(LOG_ERR, "user entry with uid %d"
						" not found", config.uid);
					exit(1);
				}

				config.gid = pw->pw_gid;
				endpwent();
			} else {
				struct passwd *pw = getpwnam(argv[i]);
				if (pw == NULL) {
					msg(LOG_ERR, "user %s is unknown",
							argv[i]);
					exit(1);
				}
				config.uid = pw->pw_uid;
				config.gid = pw->pw_gid;
				endpwent();
			}
		} else if (strcmp(argv[i], "--group") == 0) {
			i++;
			if (i == argc || *argv[i] == '-') {
				msg(LOG_ERR, "group takes an argument");
				exit(1);
			}
			if (isdigit(*argv[i])) {
				errno = 0;
				config.gid = strtoul(argv[i], NULL, 10);
				if (errno) {
					msg(LOG_ERR,
						"Error converting group value");
					exit(1);
				}
			} else {
				struct group *gr = getgrnam(argv[i]);
				if (gr == NULL) {
					msg(LOG_ERR, "group %s is unknown",
							argv[i]);
					exit(1);
				}
				config.gid = gr->gr_gid;
				endgrent();
			}
		} else if (strcmp(argv[i], "--no-details") == 0) {
			config.detailed_report = 0;
		} else {
			msg(LOG_ERR, "unknown command option:%s\n", argv[i]);
			usage();
		}
	}

	// Set a couple signal handlers
	sa.sa_flags = 0;
	sigemptyset(&sa.sa_mask);
	sa.sa_handler = term_handler;
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGINT, &sa, NULL);

	// Bump up resources
	limit.rlim_cur = RLIM_INFINITY;
	limit.rlim_max = RLIM_INFINITY;
	setrlimit(RLIMIT_FSIZE, &limit);
	setrlimit(RLIMIT_NOFILE, &limit);

	// Set strict umask
	(void) umask( 0117 );

	// get more time slices because everything is waiting on us
	rc = nice(-config.nice_val);
	if (rc == -1)
		msg(LOG_WARNING, "Couldn't adjust priority (%s)",
				strerror(errno));

	// Load the rule configuration
	if (load_config())
		exit(1);
	if (!debug) {
		if (become_daemon() < 0) {
			msg(LOG_ERR, "Exiting due to failure daemonizing");
			exit(1);
		}
		set_message_mode(MSG_SYSLOG, DBG_NO);
		openlog("fapolicyd", LOG_PID, LOG_DAEMON);
	}

	// Write the pid file for the init system
	write_pid_file();

	// If we are not going to be root, then setup necessary capabilities
	if (config.uid != 0) {
		if (preconstruct_fifo(&config))
			exit(1);
		capng_clear(CAPNG_SELECT_BOTH);
		capng_updatev(CAPNG_ADD, CAPNG_EFFECTIVE|CAPNG_PERMITTED,
			CAP_DAC_OVERRIDE, CAP_SYS_ADMIN, CAP_SYS_PTRACE,
			CAP_SYS_NICE, CAP_SYS_RESOURCE, CAP_AUDIT_WRITE, -1);
		if (capng_change_id(config.uid, config.gid,
							CAPNG_DROP_SUPP_GRP)) {
			msg(LOG_ERR, "Cannot change to uid %d", config.uid);
			exit(1);
		} else
			msg(LOG_DEBUG, "Changed to uid %d", config.uid);
	}

	// Install seccomp filter to prevent escalation
	install_syscall_filter();

	// Setup lru caches
	init_event_system(&config);

	// Init the database
	init_database(&config);

	// Init the file test libraries
	file_init();

	// Initialize the file watch system
	pfd[0].fd = init_fanotify(&config);
	pfd[0].events = POLLIN;

	msg(LOG_DEBUG, "Starting to listen for events");
	while (!stop) {
		rc = poll(pfd, 1, -1);

#ifdef DEBUG
		msg(LOG_DEBUG, "Main poll interrupted");
#endif
		if (rc < 0) {
			if (errno == EINTR)
				continue;
			else {
				msg(LOG_ERR, "Poll error (%s)\n",
						strerror(errno));
				exit(1);
			}
		} else if (rc > 0) {
			if (pfd[0].revents & POLLIN) {
				lock_update_thread();
				handle_events();
				unlock_update_thread();
			}

			// This will always need to be here as long as we
			// link against librpm. Turns out that librpm masks
			// signals to prevent corrupted databases during an
			// update. Since we only do read access, we can turn
			// them back on.
			sigaction(SIGTERM, &sa, NULL);
			sigaction(SIGINT, &sa, NULL);
		}
	}
	msg(LOG_DEBUG, "shutting down...");
	shutdown_fanotify();
	file_close();
	close_database();
	if (pidfile)
		unlink(pidfile);
	// Reinstate the strict umask in case rpm messed with it
	(void) umask( 0237 );
	if (config.do_stat_report) {
		FILE *f = fopen(REPORT, "w");
		if (f == NULL)
			msg(LOG_WARNING, "Cannot create usage report");
		else {
			fprintf(f, "Permissive: %s\n",
					config.permissive ? "true" : "false");
			fprintf(f, "q_size: %u\n", config.q_size);
			q_report(f);
			decision_report(f);
			run_usage_report(&config, f);
			fclose(f);
		}
	}
	destroy_event_system();
	destroy_config();
	free_daemon_config(&config);

	return 0;
}
