/*
 * fapolicyd.c - Main file for the program
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
 * Free Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * Authors:
 *   Steve Grubb <sgrubb@redhat.com>
 */

#include "config.h"
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
#include <pwd.h>
#include <cap-ng.h>
#include <stddef.h>        /* offsetof */
#include <sys/prctl.h>
#include <linux/audit.h>   /* Arch definitions */
#include <linux/filter.h>  /* BPF */
#include <linux/seccomp.h>
#include <linux/unistd.h>  /* syscall numbers */
#include "notify.h"
#include "policy.h"
#include "event.h"
#include "file.h"
#include "message.h"

// Seccomp macros
#define syscall_nr (offsetof(struct seccomp_data, nr))
#define arch_nr (offsetof(struct seccomp_data, arch))

#if defined(__i386__)
# define ARCH_NR        AUDIT_ARCH_I386
#elif defined(__x86_64__)
# define ARCH_NR        AUDIT_ARCH_X86_64
#else
# warning "Platform does not support seccomp filter yet"
# define ARCH_NR        0
#endif

#define VALIDATE_ARCHITECTURE \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, arch_nr), \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ARCH_NR, 0, 2)

#define EXAMINE_SYSCALL \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, syscall_nr)

#define DENY_SYSCALL(name) \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_##name, 0, 1), \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL)

#define OTHERWISE_OK \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW)


// Global program variables
int debug = 0, permissive = 0;
int q_size = 2048;

// Signal handler notifications
volatile int stop = 0;

// Local variables
static int nice_val = 10;
static int uid = 0;
static const char *pidfile = "/var/run/fapolicyd.pid";
static struct sock_filter filter[] = {
	VALIDATE_ARCHITECTURE,
	EXAMINE_SYSCALL,
	DENY_SYSCALL(execve),
#ifdef HAVE_FEXECVE
# ifdef __NR_fexecve
	DENY_SYSCALL(fexecve),
# endif
#endif
	OTHERWISE_OK
};

static struct sock_fprog prog = {
	.len = (unsigned short)(sizeof(filter)/sizeof(filter[0])),
	.filter = filter,
};


static int install_syscall_filter(void)
{
	int rc = 0;
#ifdef HAVE_DECL_PR_SET_NO_NEW_PRIVS
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
		msg(LOG_ERR, "Setting NO_NEW_PRIVS failed");
		rc = 1;
	}
#endif
#if ARCH_NR
# ifdef HAVE_DECL_SECCOMP_MODE_FILTER
	if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)) {
		if (errno == EINVAL)
			msg(LOG_WARNING, "SECCOMP_FILTER is not available");
		rc = 1;
	}
	if (rc == 0)
		msg(LOG_DEBUG, "Syscall filter installed");
# endif
#endif
	return rc;
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
			if (dup2(fd, 0) < 0)
				return -1;
			if (dup2(fd, 1) < 0)
				return -1;
			if (dup2(fd, 2) < 0)
				return -1;
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
		"[--boost xxx] [--queue xxx] [--user xx]\n");
	exit(1);
}

int main(int argc, char *argv[])
{
	struct pollfd pfd[1];
	struct sigaction sa;
	struct rlimit limit;
	int rc, i;

	set_message_mode(MSG_STDERR, debug);
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
			if (i == argc || !isdigit(argv[i])) {
				msg(LOG_ERR, "boost takes a numeric argument");
				exit(1);
			}
			errno = 0;
			nice_val = strtoul(argv[i], NULL, 10);
			if (errno) {
				msg(LOG_ERR, "Error converting boost value");
				exit(1);
			}
			if (nice_val >= 20) {
				msg(LOG_ERR,
					"boost value must be less that 20");
				exit(1);
			}
		} else if (strcmp(argv[i], "--queue") == 0) {
			i++;
			if (i == argc || !isdigit(argv[i])) {
				msg(LOG_ERR, "queue takes a numeric argument");
				exit(1);
			}
			errno = 0;
			q_size = strtol(argv[i], NULL, 10);
			if (errno) {
				msg(LOG_ERR, "Error converting queue value");
				exit(1);
			}
			if (q_size >= 10480) {
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
				uid = strtol(argv[i], NULL, 10);
				if (errno) {
					msg(LOG_ERR,
						"Error converting user value");
					exit(1);
				}
			} else {
				struct passwd *pw = getpwnam(argv[i]);
				if (pw == NULL) {
					msg(LOG_ERR, "user %s is unknown",
							argv[i]);
					exit(1);
				}
				uid = pw->pw_uid;
				endpwent();
			}
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

	// get more time slices because everything is waiting on us
	rc = nice(-nice_val);
	if (rc == -1)
		msg(LOG_WARNING, "Couldn't adjust priority (%s)",
				strerror(errno));

	// Load the rule configuration
	if (load_config())
		exit(1);
	file_init();
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
	if (uid != 0) {
		capng_clear(CAPNG_SELECT_BOTH);
		capng_updatev(CAPNG_ADD, CAPNG_EFFECTIVE|CAPNG_PERMITTED,
			CAP_DAC_OVERRIDE, CAP_SYS_ADMIN, CAP_SYS_PTRACE,
			CAP_SYS_NICE, CAP_SYS_RESOURCE, -1);
		if (capng_change_id(uid, uid, CAPNG_DROP_SUPP_GRP)) {
			msg(LOG_ERR, "Cannot change to uid %d", uid);
			exit(1);
		} else
			msg(LOG_DEBUG, "Changed to uid %d", uid);
	}

	// Install seccomp filter to prevent escalation
	install_syscall_filter();

	// Initialize the file watch system
	pfd[0].fd = init_fanotify();
	pfd[0].events = POLLIN;

	msg(LOG_DEBUG, "Starting to listen for events");
	while (!stop) {
		rc = poll(pfd, 1, -1);
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
				handle_events();
			}
		}
	}
	msg(LOG_DEBUG, "shutting down...");
	shutdown_fanotify();
	file_close();
	if (pidfile)
		unlink(pidfile);
	destroy_config();

	return 0;
}

