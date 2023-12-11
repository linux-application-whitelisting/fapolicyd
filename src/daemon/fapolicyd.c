/*
 * fapolicyd.c - Main file for the program
 * Copyright (c) 2016,2018-22 Red Hat Inc.
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

#define _GNU_SOURCE	   /* gettid() in unistd.h */

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
#include <ctype.h>
#include <cap-ng.h>
#include <sys/prctl.h>
#include <linux/unistd.h>  /* syscall numbers */
#include <sys/stat.h>	   /* umask */
#include <seccomp.h>
#include <stdatomic.h>
#include <limits.h>        /* PATH_MAX */
#include <locale.h>
#include "notify.h"
#include "policy.h"
#include "event.h"
#include "escape.h"
#include "fd-fgets.h"
#include "file.h"
#include "database.h"
#include "message.h"
#include "daemon-config.h"
#include "conf.h"
#include "queue.h"
#include "gcc-attributes.h"
#include "avl.h"
#include "paths.h"


// Global program variables
unsigned int debug_mode = 0, permissive = 0;

// Signal handler notifications
volatile atomic_bool stop = 0, hup = 0, run_stats = 0;

// Local variables
static conf_t config;
// This holds info about all file systems to watch
struct fs_avl {
	avl_tree_t index;
};
// This is the data about a specific file system to watch
typedef struct fs_data {
        avl_t avl;        // This has to be first
        const char *fs_name;
} fs_data_t;
static struct fs_avl filesystems;

// List of mounts being watched
static mlist *m = NULL;

static void usage(void) NORETURN;


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


static int cmp_fs(void *a, void *b)
{
	return strcmp(((fs_data_t *)a)->fs_name, ((fs_data_t *)b)->fs_name);
}


static void free_filesystem(fs_data_t *s)
{
	free((void *)s->fs_name);
	free((void *)s);
}


static void destroy_filesystem(void)
{
	avl_t *cur = filesystems.index.root;

	fs_data_t *tmp =(fs_data_t *)avl_remove(&filesystems.index, cur);
	if ((avl_t *)tmp != cur)
		msg(LOG_DEBUG, "filesystem: removal of invalid node");
	free_filesystem(tmp);
}


static void destroy_fs_list(void)
{
	while (filesystems.index.root)
		destroy_filesystem();
}


static int add_filesystem(fs_data_t *f)
{
	fs_data_t *tmp=(fs_data_t *)avl_insert(&filesystems.index,(avl_t *)(f));
	if (tmp) {
		if (tmp != f) {
			msg(LOG_DEBUG, "fs_list: duplicate filesystem found");
			free_filesystem(f);
		}
		return 1;
	}
	return 0;
}


static fs_data_t *new_filesystem(const char *fs)
{
	fs_data_t *tmp = malloc(sizeof(fs_data_t));
	if (tmp) {
		tmp->fs_name = fs ? strdup(fs) : strdup("");
		if (add_filesystem(tmp) != 0)
			return NULL;
	}
	return tmp;
}


static fs_data_t *find_filesystem(const char *f)
{
	fs_data_t tmp;

	tmp.fs_name = f;
	return (fs_data_t *)avl_search(&filesystems.index, (avl_t *) &tmp);
}


static void init_fs_list(const char *watch_fs)
{
	if (watch_fs == NULL) {
		msg(LOG_ERR, "File systems to watch is empty");
		exit(1);
	}
	avl_init(&filesystems.index, cmp_fs);

	// Now parse up list and push into avl
	char *ptr, *saved, *tmp = strdup(watch_fs);
	ptr = strtok_r(tmp, ",", &saved);
	while (ptr) {
		new_filesystem(ptr);
		ptr = strtok_r(NULL, ",", &saved);
	}
	free(tmp);
}


static void term_handler(int sig)
{
	stop = 1 + sig; // Just so its used...
}


static void coredump_handler(int sig)
{
	if (getpid() == gettid()) {
		unmark_fanotify_and_close_fd(m);
		unlink_fifo();
		signal(sig, SIG_DFL);
		kill(getpid(), sig);
	} else {
		/*
		 * Fatal signals are usually delivered to the thread generating
		 * them, if this is not main thread, raised the signal again to
		 * handle it there, then wait forever to die.
		 */
		kill(getpid(), sig);
		for (;;) pause();
	}
}


static void hup_handler(int sig)
{
	hup = 1 + sig; // Just so its used...
}

static void usr1_handler(int sig __attribute__((unused)))
{
	run_stats = 1;
}

/*
 * This function handles the reconfiguration of the daemon
 * after receiving a SIGHUP signal.
 */
static void reconfigure(void)
{
	set_reload_rules();

	set_reload_trust_database();

	// TODO: Update configuration
}

// This is a workaround for https://bugzilla.redhat.com/show_bug.cgi?id=643031
#define UNUSED(x) (void)(x)
#ifdef USE_RPM
extern int rpmsqEnable (int signum, void *handler);
int rpmsqEnable (int signum, void *handler)
{
	UNUSED(signum);
	UNUSED(handler);
	return 0;
}
#endif


static int write_pid_file(void)
{
	int pidfd, len;
	char val[16];

	len = snprintf(val, sizeof(val), "%u\n", getpid());
	if (len <= 0) {
		msg(LOG_ERR, "Pid error (%s)", strerror(errno));
		return 1;
	}
	pidfd = open(pidfile, O_CREAT | O_TRUNC | O_NOFOLLOW | O_WRONLY, 0644);
	if (pidfd < 0) {
		msg(LOG_ERR, "Unable to create pidfile (%s)",
			strerror(errno));
		return 1;
	}
	if (write(pidfd, val, (unsigned int)len) != len) {
		msg(LOG_ERR, "Unable to write pidfile (%s)",
			strerror(errno));
		close(pidfd);
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
			if (fd < 0)
				return -1;
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


// Returns 1 if we care about the entry and 0 if we do not
static int check_mount_entry(const char *point, const char *type)
{
	// Some we know we don't want
	if (strcmp(point, "/run") == 0)
		return 0;
	if (strncmp(point, "/sys", 4) == 0)
		return 0;

	if (find_filesystem(type))
		return 1;
	else
		return 0;
}


static void handle_mounts(int fd)
{
	char buf[PATH_MAX * 2], device[1025], point[4097];
	char type[32], mntops[128];
	int fs_req, fs_passno;

	if (m == NULL) {
		m = malloc(sizeof(mlist));
		mlist_create(m);
	}

	// Rewind the descriptor
	lseek(fd, 0, SEEK_SET);
	fd_fgets_rewind();
	mlist_mark_all_deleted(m);
	do {
		int rc = fd_fgets(buf, sizeof(buf), fd);
		// Get a line
		if (rc > 0) {
			// Parse it
			sscanf(buf, "%1024s %4096s %31s %127s %d %d\n",
			    device, point, type, mntops, &fs_req, &fs_passno);
			unescape_shell(device, strlen(device));
			unescape_shell(point, strlen(point));
			// Is this one that we care about?
			if (check_mount_entry(point, type)) {
				// Can we find it in the old list?
				if (mlist_find(m, point)) {
					// Mark no change
					m->cur->status = NO_CHANGE;
				} else
					mlist_append(m, point);
			}
		} else if (rc < 0) // Some kind of error - stop
			break;
	} while (!fd_fgets_eof());

	// update marks
	fanotify_update(m);
}


static void usage(void)
{
	fprintf(stderr,
		"Usage: fapolicyd [--debug|--debug-deny] [--permissive] "
		"[--no-details]\n");
	exit(1);
}

void do_stat_report(FILE *f, int shutdown)
{
	fprintf(f, "Permissive: %s\n", config.permissive ? "true" : "false");
	fprintf(f, "q_size: %u\n", config.q_size);
	q_report(f);
	decision_report(f);
	database_report(f);
	if (shutdown)
		fputs("\n", f);
	else
		do_cache_reports(f);
}

int already_running(void)
{
	int pidfd = open(pidfile, O_RDONLY);
	if (pidfd >= 0) {
		char pid_buf[16];

		if (fd_fgets(pid_buf, sizeof(pid_buf), pidfd)) {
			int pid;
			char exe_buf[80], my_path[80];

			// Get our path
			if (get_program_from_pid(getpid(),
					sizeof(exe_buf), my_path) == NULL)
				goto err_out; // shouldn't happen, but be safe

			// convert pidfile to integer
			errno = 0;
			pid = strtoul(pid_buf, NULL, 10);
			if (errno)
				goto err_out; // shouldn't happen, but be safe

			// verify it really is fapolicyd
			if (get_program_from_pid(pid,
					sizeof(exe_buf), exe_buf) == NULL)
				goto good; //if pid doesn't exist, we're OK

			// If the path doesn't have fapolicyd in it, we're OK
			if (strstr(exe_buf, "fapolicyd") == NULL)
				goto good;

			if (strcmp(exe_buf, my_path) == 0)
				goto err_out; // if the same, we need to exit

			// one last sanity check in case path is unexpected
			// for example: /sbin/fapolicyd & /home/test/fapolicyd
			if (pid != getpid())
				goto err_out;
good:
			close(pidfd);
			unlink(pidfile);
			return 0;
		} else
		    msg(LOG_ERR, "fapolicyd pid file found but unreadable");
err_out: // At this point, we have a pid file, let's just assume it's alive
	 // because if 2 are running, it deadlocks the machine
		close(pidfd);
		return 1;
	}
	return 0; // pid file doesn't exist, we're good to go
}

int main(int argc, const char *argv[])
{
	struct pollfd pfd[2];
	struct sigaction sa;
	struct rlimit limit;

	char *locale = setlocale(LC_TIME, "");

	if (argc > 1 && strcmp(argv[1], "--help") == 0)
		usage();
	set_message_mode(MSG_STDERR, debug_mode);
	if (load_daemon_config(&config)) {
		free_daemon_config(&config);
		msg(LOG_ERR, "Exiting due to bad configuration");
		return 1;
	}
	permissive = config.permissive;
	for (int i=1; i < argc; i++) {
		if (strcmp(argv[i], "--debug") == 0) {
			debug_mode = 1;
			set_message_mode(MSG_STDERR, DBG_YES);
		} else if (strcmp(argv[i], "--debug-deny") == 0) {
			debug_mode = 2;
			set_message_mode(MSG_STDERR, DBG_YES);
		} else if (strcmp(argv[i], "--permissive") == 0) {
			permissive = 1;
		} else if (strcmp(argv[i], "--boost") == 0) {
			i++;
			msg(LOG_ERR, "boost value on the command line is"
				" deprecated - ignoring");
		} else if (strcmp(argv[i], "--queue") == 0) {
			i++;
			msg(LOG_ERR, "queue value on the command line is"
				" deprecated - ignoring");
		} else if (strcmp(argv[i], "--user") == 0) {
			i++;
			msg(LOG_ERR, "user value on the command line is"
				" deprecated - ignoring");
		} else if (strcmp(argv[i], "--group") == 0) {
			i++;
			msg(LOG_ERR, "group value on the command line is"
				" deprecated - ignoring");
		} else if (strcmp(argv[i], "--no-details") == 0) {
			config.detailed_report = 0;
		} else {
			msg(LOG_ERR, "unknown command option:%s\n", argv[i]);
			free_daemon_config(&config);
			usage();
		}
	}

	if (already_running()) {
		msg(LOG_ERR, "fapolicyd is already running");
		exit(1);
	}

	// Set a couple signal handlers
	sa.sa_flags = 0;
	sigemptyset(&sa.sa_mask);
	sa.sa_handler = hup_handler;
	sigaction(SIGHUP, &sa, NULL);
	sa.sa_handler = coredump_handler;
	sigaction(SIGSEGV, &sa, NULL);
	sigaction(SIGABRT, &sa, NULL);
	sigaction(SIGBUS, &sa, NULL);
	sigaction(SIGFPE, &sa, NULL);
	sigaction(SIGILL, &sa, NULL);
	sigaction(SIGSYS, &sa, NULL);
	sigaction(SIGTRAP, &sa, NULL);
	sigaction(SIGXCPU, &sa, NULL);
	sigaction(SIGXFSZ, &sa, NULL);
	sigaction(SIGQUIT, &sa, NULL);

	sa.sa_handler = usr1_handler;
	sigaction(SIGUSR1, &sa, NULL);
	/* These need to be last since they are used later */
	sa.sa_handler = term_handler;
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGINT, &sa, NULL);

	// Bump up resources
	limit.rlim_cur = RLIM_INFINITY;
	limit.rlim_max = RLIM_INFINITY;
	setrlimit(RLIMIT_FSIZE, &limit);
	getrlimit(RLIMIT_NOFILE, &limit);
	if (limit.rlim_max >= 16384)
		limit.rlim_cur = limit.rlim_max;
	else
		limit.rlim_max = limit.rlim_cur = 16834;

	if (setrlimit(RLIMIT_NOFILE, &limit))
		msg(LOG_WARNING, "Can't increase file number rlimit - %s",
		    strerror(errno));
	else
		msg(LOG_INFO,"Can handle %lu file descriptors", limit.rlim_cur);

	// get more time slices because everything is waiting on us
	errno = 0;
	nice(-config.nice_val);
	if (errno)
		msg(LOG_WARNING, "Couldn't adjust priority (%s)",
				strerror(errno));

	// Load the rule configuration
	if (load_rules(&config))
		exit(1);
	if (!debug_mode) {
		if (become_daemon() < 0) {
			msg(LOG_ERR, "Exiting due to failure daemonizing");
			exit(1);
		}
		set_message_mode(MSG_SYSLOG, DBG_NO);
		openlog("fapolicyd", LOG_PID, LOG_DAEMON);
	}

	// Set the exit function so there is always a fifo cleanup
	if (atexit(unlink_fifo)) {
		msg(LOG_ERR, "Cannot set exit function");
		exit(1);
	}

	// Setup filesystem to watch list
	init_fs_list(config.watch_fs);

	// Write the pid file for the init system
	write_pid_file();

	// Set strict umask
	(void) umask( 0117 );

	if (preconstruct_fifo(&config)) {
		unlink(pidfile);
		msg(LOG_ERR, "Cannot construct a pipe");
		exit(1);
	}

	// If we are not going to be root, then setup necessary capabilities
	if (config.uid != 0) {
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
	if (init_database(&config)) {
		destroy_event_system();
		destroy_rules();
		destroy_fs_list();
		free_daemon_config(&config);
		unlink(pidfile);
		exit(1);
	}

	// Init the file test libraries
	file_init();

	// Initialize the file watch system
	pfd[0].fd = open("/proc/mounts", O_RDONLY);
	pfd[0].events = POLLPRI;
	handle_mounts(pfd[0].fd);
	pfd[1].fd = init_fanotify(&config, m);
	pfd[1].events = POLLIN;

	msg(LOG_INFO, "Starting to listen for events");
	while (!stop) {
		int rc;
		if (hup) {
			hup = 0;
			msg(LOG_DEBUG, "Got SIGHUP");
			reconfigure();
		}
		rc = poll(pfd, 2, -1);

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
			if (pfd[1].revents & POLLIN) {
				handle_events();
			}
			if (pfd[0].revents & POLLPRI) {
				msg(LOG_DEBUG, "Mount change detected");
				handle_mounts(pfd[0].fd);
			}

			// This will always need to be here as long as we
			// link against librpm. Turns out that librpm masks
			// signals to prevent corrupted databases during an
			// update. Since we only do read access, we can turn
			// them back on.
#ifdef USE_RPM
			sigaction(SIGTERM, &sa, NULL);
			sigaction(SIGINT, &sa, NULL);
#endif
		}
	}
	msg(LOG_INFO, "shutting down...");
	shutdown_fanotify(m);
	close(pfd[0].fd);
	mlist_clear(m);
	free(m);
	file_close();
	close_database();
	unlink(pidfile);
	// Reinstate the strict umask in case rpm messed with it
	(void) umask( 0237 );
	if (config.do_stat_report) {
		FILE *f = fopen(REPORT, "w");
		if (f == NULL)
			msg(LOG_WARNING, "Cannot create usage report");
		else {
			do_stat_report(f, 1);
			run_usage_report(&config, f);
			fclose(f);
		}
	}
	destroy_event_system();
	destroy_rules();
	destroy_fs_list();
	free_daemon_config(&config);

	return 0;
}
