/*
 * fapolicyd-stress.c - fanotify decision stress helper
 * Copyright (c) 2026 Red Hat Inc.
 * All Rights Reserved.
 *
 * This software may be freely redistributed and/or modified under the
 * terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2, or (at your option) any
 * later version.
 */

#include "config.h"
#include "paths.h"
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define DEFAULT_ROOTS 4
#define DEFAULT_FANOUT 1
#define DEFAULT_DEPTH 0
#define DEFAULT_ITERATIONS 100
#define DEFAULT_SECONDS 0
#define DEFAULT_HASH_MB 16
#define DEFAULT_CHURN_FILES 2048
#define GRACEFUL_STOP_NS 5000000000ULL
#define TERM_STOP_NS 250000000ULL
#define MAX_COMMANDS 64
#define CAPTURE_LIMIT (1024 * 1024)
#define HASH_BLOCK_SIZE 65536
#define NORETURN __attribute__((noreturn))

#ifndef STRESS_SCRIPT_DIR
#define STRESS_SCRIPT_DIR "scripts"
#endif

enum workload_type {
	WORKLOAD_EXEC_OPEN,
	WORKLOAD_FORK_EXEC,
	WORKLOAD_INTERPRETER,
	WORKLOAD_NOSHEBANG,
	WORKLOAD_HASH,
	WORKLOAD_CHURN,
	WORKLOAD_ALL,
};

struct command_set {
	const char *paths[MAX_COMMANDS];
	unsigned int count;
};

struct stress_options {
	enum workload_type workload;
	unsigned int roots;
	unsigned int fanout;
	unsigned int depth;
	unsigned int iterations;
	unsigned int seconds;
	unsigned int hash_mb;
	unsigned int churn_files;
	int collect_status;
	int collect_timing;
	int keep_workdir;
	int verbose;
	const char *workdir_base;
	const char *cli_path;
	const char *shell_path;
	struct command_set commands;
};

struct stress_paths {
	char workdir[PATH_MAX];
	char churn_dir[PATH_MAX];
	char hash_file[PATH_MAX];
	char small_file[PATH_MAX];
	char shebang_script[PATH_MAX];
	char no_shebang_script[PATH_MAX];
	int created_workdir;
};

struct stress_shared {
	volatile sig_atomic_t stop;
	unsigned long long operations;
	unsigned long long errors;
};

struct leaf_stats {
	unsigned long long operations;
	unsigned long long errors;
};

struct capture {
	char *data;
	size_t len;
	int status;
};

struct daemon_metrics {
	int present;
	unsigned long long queue_max_depth;
	unsigned long long subject_defer_current;
	unsigned long long subject_defer_max_depth;
	unsigned long long subject_defer_fallbacks;
	char subject_defer_oldest_age[32];
	unsigned long long early_subject_evictions;
	unsigned long long subject_tracer_evictions;
	unsigned long long subject_stale_evictions;
	unsigned long long subject_collisions;
	unsigned long long subject_evictions;
	unsigned long long object_collisions;
	unsigned long long object_evictions;
	unsigned long long allowed;
	unsigned long long denied;
	unsigned long long kernel_overflow;
	unsigned long long reply_errors;
	int have_timing_mode;
	char timing_mode[32];
	int have_reset_strategy;
	char reset_strategy[32];
};

struct timing_metrics {
	int present;
	unsigned long long decisions;
	unsigned long long max_queue_depth;
	double throughput;
	double active_rate;
	char avg_latency[32];
	char max_latency[32];
	char p95_latency[32];
};

struct daemon_config_snapshot {
	unsigned int report_interval;
	int have_report_interval;
	int have_reset_strategy;
	char reset_strategy[32];
};

static struct stress_shared *signal_shared;

/*
 * usage - print command line help.
 * @prog: executable name.
 * Returns nothing.
 */
static void usage(const char *prog)
{
	printf("Usage: %s [options]\n\n", prog);
	printf("Workloads:\n");
	printf("  -w, --workload exec-open Open command paths and exec them\n");
	printf("  -w, --workload fork-exec Tight fork/exec loops\n");
	printf("  -w, --workload interpreter Shell interpreter script workload\n");
	printf("  -w, --workload noshebang Direct no-shebang exec plus shell run\n");
	printf("  -w, --workload hash      Read and hash a large file\n");
	printf("  -w, --workload churn     Open many distinct files\n");
	printf("  -w, --workload all       Run every workload in each loop\n\n");
	printf("Tree and run controls:\n");
	printf("  -r, --roots N            Root process count (default %u)\n",
	       DEFAULT_ROOTS);
	printf("  -f, --fanout N           Children per non-leaf node (default %u)\n",
	       DEFAULT_FANOUT);
	printf("  -d, --depth N            Tree depth below roots (default %u)\n",
	       DEFAULT_DEPTH);
	printf("  -i, --iterations N       Iterations per leaf, 0 for timed-only\n");
	printf("  -s, --seconds N          Timed run length, 0 disables timer\n");
	printf("      --preset early-evict Aggressive collision workload\n");
	printf("      --preset ld-so-regression Fork/exec false ld_so pressure\n\n");
	printf("Workload inputs:\n");
	printf("  -c, --command PATH       Add one exec target; repeat as needed\n");
	printf("      --hash-mb N          Hash file size in MiB (default %u)\n",
	       DEFAULT_HASH_MB);
	printf("      --churn-files N      Cache churn file count (default %u)\n",
	       DEFAULT_CHURN_FILES);
	printf("      --workdir DIR        Base directory for generated files\n");
	printf("      --keep-workdir       Keep generated files after the run\n");
	printf("      --shell PATH         Shell path for interpreter workloads\n\n");
	printf("Daemon reporting:\n");
	printf("      --status             Capture daemon status (default)\n");
	printf("      --no-status          Do not capture daemon status\n");
	printf("      --timing             Wrap run in decision timing; "
	       "requires root\n");
	printf("      --cli PATH           fapolicyd-cli path\n");
	printf("  -v, --verbose            Print helper command failures\n");
	printf("  -h, --help               Show this help\n");
}

/*
 * parse_uint - parse a non-negative unsigned integer option.
 * @text: option value.
 * @out: parsed destination.
 * Returns 0 on success, 1 on parse error.
 */
static int parse_uint(const char *text, unsigned int *out)
{
	char *end = NULL;
	unsigned long value;

	if (text == NULL || *text == 0)
		return 1;

	errno = 0;
	value = strtoul(text, &end, 10);
	if (errno || end == text || *end || value > UINT_MAX)
		return 1;

	*out = (unsigned int)value;
	return 0;
}

/*
 * parse_workload - convert a workload name to an enum.
 * @name: workload name.
 * @workload: parsed destination.
 * Returns 0 on success, 1 on unknown workload.
 */
static int parse_workload(const char *name, enum workload_type *workload)
{
	if (strcmp(name, "exec-open") == 0)
		*workload = WORKLOAD_EXEC_OPEN;
	else if (strcmp(name, "fork-exec") == 0)
		*workload = WORKLOAD_FORK_EXEC;
	else if (strcmp(name, "interpreter") == 0)
		*workload = WORKLOAD_INTERPRETER;
	else if (strcmp(name, "noshebang") == 0)
		*workload = WORKLOAD_NOSHEBANG;
	else if (strcmp(name, "hash") == 0)
		*workload = WORKLOAD_HASH;
	else if (strcmp(name, "churn") == 0)
		*workload = WORKLOAD_CHURN;
	else if (strcmp(name, "all") == 0)
		*workload = WORKLOAD_ALL;
	else
		return 1;

	return 0;
}

/*
 * workload_name - return a printable workload name.
 * @workload: workload enum.
 * Returns a stable string.
 */
static const char *workload_name(enum workload_type workload)
{
	switch (workload) {
	case WORKLOAD_EXEC_OPEN:
		return "exec-open";
	case WORKLOAD_FORK_EXEC:
		return "fork-exec";
	case WORKLOAD_INTERPRETER:
		return "interpreter";
	case WORKLOAD_NOSHEBANG:
		return "noshebang";
	case WORKLOAD_HASH:
		return "hash";
	case WORKLOAD_CHURN:
		return "churn";
	case WORKLOAD_ALL:
		return "all";
	}

	return "unknown";
}

/*
 * command_set_add - append a command path.
 * @commands: command set to update.
 * @path: command path to add.
 * Returns 0 on success, 1 when the set is full.
 */
static int command_set_add(struct command_set *commands, const char *path)
{
	if (commands->count >= MAX_COMMANDS)
		return 1;
	commands->paths[commands->count++] = path;
	return 0;
}

/*
 * add_first_existing - add the first executable path from a candidate list.
 * @commands: command set to update.
 * @candidates: NULL-terminated executable candidates.
 * Returns 0 when a candidate was added, 1 otherwise.
 */
static int add_first_existing(struct command_set *commands,
		const char * const *candidates)
{
	unsigned int idx;

	for (idx = 0; candidates[idx]; idx++) {
		if (access(candidates[idx], X_OK) == 0)
			return command_set_add(commands, candidates[idx]);
	}

	return 1;
}

/*
 * add_default_commands - populate harmless installed exec targets.
 * @commands: command set to update.
 * Returns 0 when at least one target is available, 1 otherwise.
 */
static int add_default_commands(struct command_set *commands)
{
	static const char * const arch_cmds[] = {
		"/usr/bin/arch", "/bin/arch", NULL
	};
	static const char * const date_cmds[] = {
		"/usr/bin/date", "/bin/date", NULL
	};
	static const char * const dir_cmds[] = {
		"/usr/bin/dir", "/bin/dir", NULL
	};
	static const char * const env_cmds[] = {
		"/usr/bin/env", "/bin/env", NULL
	};
	static const char * const groups_cmds[] = {
		"/usr/bin/groups", "/bin/groups", NULL
	};
	static const char * const hostname_cmds[] = {
		"/usr/bin/hostname", "/bin/hostname", NULL
	};
	static const char * const hostid_cmds[] = {
		"/usr/bin/hostid", "/bin/hostid", NULL
	};
	static const char * const id_cmds[] = {
		"/usr/bin/id", "/bin/id", NULL
	};
	static const char * const ls_cmds[] = {
		"/usr/bin/ls", "/bin/ls", NULL
	};
	static const char * const nproc_cmds[] = {
		"/usr/bin/nproc", "/bin/nproc", NULL
	};
	static const char * const printenv_cmds[] = {
		"/usr/bin/printenv", "/bin/printenv", NULL
	};
	static const char * const pwd_cmds[] = {
		"/usr/bin/pwd", "/bin/pwd", NULL
	};
	static const char * const whoami_cmds[] = {
		"/usr/bin/whoami", "/bin/whoami", NULL
	};
	static const char * const uname_cmds[] = {
		"/usr/bin/uname", "/bin/uname", NULL
	};
	static const char * const users_cmds[] = {
		"/usr/bin/users", "/bin/users", NULL
	};
	static const char * const who_cmds[] = {
		"/usr/bin/who", "/bin/who", NULL
	};
	static const char * const true_cmds[] = {
		"/usr/bin/true", "/bin/true", NULL
	};
	unsigned int before = commands->count;

	add_first_existing(commands, who_cmds);
	add_first_existing(commands, users_cmds);
	add_first_existing(commands, uname_cmds);
	add_first_existing(commands, pwd_cmds);
	add_first_existing(commands, printenv_cmds);
	add_first_existing(commands, nproc_cmds);
	add_first_existing(commands, ls_cmds);
	add_first_existing(commands, hostid_cmds);
	add_first_existing(commands, env_cmds);
	add_first_existing(commands, dir_cmds);
	add_first_existing(commands, date_cmds);
	add_first_existing(commands, arch_cmds);
	add_first_existing(commands, groups_cmds);
	add_first_existing(commands, hostname_cmds);
	add_first_existing(commands, id_cmds);
	add_first_existing(commands, whoami_cmds);

	if (commands->count == before)
		add_first_existing(commands, true_cmds);

	return commands->count == before ? 1 : 0;
}

/*
 * find_shell - choose a shell for interpreter workloads.
 * @opts: stress options to update.
 * Returns 0 on success, 1 when no shell is executable.
 */
static int find_shell(struct stress_options *opts)
{
	if (opts->shell_path)
		return access(opts->shell_path, X_OK) == 0 ? 0 : 1;

	if (access("/bin/sh", X_OK) == 0) {
		opts->shell_path = "/bin/sh";
		return 0;
	}
	if (access("/usr/bin/sh", X_OK) == 0) {
		opts->shell_path = "/usr/bin/sh";
		return 0;
	}

	return 1;
}

/*
 * set_defaults - initialize stress options.
 * @opts: options object to initialize.
 * Returns nothing.
 */
static void set_defaults(struct stress_options *opts)
{
	memset(opts, 0, sizeof(*opts));
	opts->workload = WORKLOAD_FORK_EXEC;
	opts->roots = DEFAULT_ROOTS;
	opts->fanout = DEFAULT_FANOUT;
	opts->depth = DEFAULT_DEPTH;
	opts->iterations = DEFAULT_ITERATIONS;
	opts->seconds = DEFAULT_SECONDS;
	opts->hash_mb = DEFAULT_HASH_MB;
	opts->churn_files = DEFAULT_CHURN_FILES;
	opts->collect_status = 1;
}

/*
 * apply_preset - apply a named preset to options.
 * @opts: options object to update.
 * @name: preset name.
 * Returns 0 on success, 1 on unknown preset.
 */
static int apply_preset(struct stress_options *opts, const char *name)
{
	if (strcmp(name, "early-evict") != 0 &&
	    strcmp(name, "ld-so-regression") != 0)
		return 1;

	opts->workload = WORKLOAD_FORK_EXEC;
	opts->roots = 32;
	opts->fanout = 8;
	opts->depth = 1;
	opts->iterations = 0;
	opts->seconds = 60;
	return 0;
}

/*
 * parse_args - parse command line options.
 * @opts: options object to fill.
 * @argc: argument count.
 * @argv: argument vector.
 * Returns 0 on success, 1 on invalid arguments, 2 after help.
 */
static int parse_args(struct stress_options *opts, int argc, char **argv)
{
	enum {
		OPT_HASH_MB = 256,
		OPT_CHURN_FILES,
		OPT_WORKDIR,
		OPT_KEEP_WORKDIR,
		OPT_STATUS,
		OPT_NO_STATUS,
		OPT_TIMING,
		OPT_CLI,
		OPT_SHELL,
		OPT_PRESET,
	};
	static const struct option long_opts[] = {
		{"workload", required_argument, NULL, 'w'},
		{"roots", required_argument, NULL, 'r'},
		{"fanout", required_argument, NULL, 'f'},
		{"depth", required_argument, NULL, 'd'},
		{"iterations", required_argument, NULL, 'i'},
		{"seconds", required_argument, NULL, 's'},
		{"command", required_argument, NULL, 'c'},
		{"hash-mb", required_argument, NULL, OPT_HASH_MB},
		{"churn-files", required_argument, NULL, OPT_CHURN_FILES},
		{"workdir", required_argument, NULL, OPT_WORKDIR},
		{"keep-workdir", no_argument, NULL, OPT_KEEP_WORKDIR},
		{"status", no_argument, NULL, OPT_STATUS},
		{"no-status", no_argument, NULL, OPT_NO_STATUS},
		{"timing", no_argument, NULL, OPT_TIMING},
		{"cli", required_argument, NULL, OPT_CLI},
		{"shell", required_argument, NULL, OPT_SHELL},
		{"preset", required_argument, NULL, OPT_PRESET},
		{"verbose", no_argument, NULL, 'v'},
		{"help", no_argument, NULL, 'h'},
		{NULL, 0, NULL, 0}
	};
	int opt;

	while ((opt = getopt_long(argc, argv, "w:r:f:d:i:s:c:vh",
				  long_opts, NULL)) != -1) {
		switch (opt) {
		case 'w':
			if (parse_workload(optarg, &opts->workload))
				return 1;
			break;
		case 'r':
			if (parse_uint(optarg, &opts->roots))
				return 1;
			break;
		case 'f':
			if (parse_uint(optarg, &opts->fanout))
				return 1;
			break;
		case 'd':
			if (parse_uint(optarg, &opts->depth))
				return 1;
			break;
		case 'i':
			if (parse_uint(optarg, &opts->iterations))
				return 1;
			break;
		case 's':
			if (parse_uint(optarg, &opts->seconds))
				return 1;
			break;
		case 'c':
			if (command_set_add(&opts->commands, optarg))
				return 1;
			break;
		case 'v':
			opts->verbose = 1;
			break;
		case 'h':
			usage(argv[0]);
			return 2;
		case OPT_HASH_MB:
			if (parse_uint(optarg, &opts->hash_mb))
				return 1;
			break;
		case OPT_CHURN_FILES:
			if (parse_uint(optarg, &opts->churn_files))
				return 1;
			break;
		case OPT_WORKDIR:
			opts->workdir_base = optarg;
			break;
		case OPT_KEEP_WORKDIR:
			opts->keep_workdir = 1;
			break;
		case OPT_STATUS:
			opts->collect_status = 1;
			break;
		case OPT_NO_STATUS:
			opts->collect_status = 0;
			break;
		case OPT_TIMING:
			opts->collect_timing = 1;
			break;
		case OPT_CLI:
			opts->cli_path = optarg;
			break;
		case OPT_SHELL:
			opts->shell_path = optarg;
			break;
		case OPT_PRESET:
			if (apply_preset(opts, optarg))
				return 1;
			break;
		default:
			return 1;
		}
	}

	if (optind != argc)
		return 1;
	if (opts->roots == 0)
		return 1;
	if (opts->depth && opts->fanout == 0)
		return 1;
	if (opts->iterations == 0 && opts->seconds == 0)
		return 1;

	return 0;
}

/*
 * monotonic_ns - read monotonic time in nanoseconds.
 * Returns a best-effort monotonic timestamp.
 */
static unsigned long long monotonic_ns(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts))
		return 0;
	return (unsigned long long)ts.tv_sec * 1000000000ULL +
	       (unsigned long long)ts.tv_nsec;
}

/*
 * signal_stop - request workload stop from a signal handler.
 * @sig: received signal.
 * Returns nothing.
 */
static void signal_stop(int sig __attribute__((unused)))
{
	if (signal_shared)
		signal_shared->stop = 1;
}

/*
 * install_signal_handlers - arrange graceful parent interruption.
 * @shared: shared run state to mark on interruption.
 * Returns 0 on success, 1 on failure.
 */
static int install_signal_handlers(struct stress_shared *shared)
{
	struct sigaction act;

	signal_shared = shared;
	memset(&act, 0, sizeof(act));
	act.sa_handler = signal_stop;
	sigemptyset(&act.sa_mask);
	if (sigaction(SIGINT, &act, NULL))
		return 1;
	if (sigaction(SIGTERM, &act, NULL))
		return 1;

	return 0;
}

/*
 * shared_add - add leaf-local counters to shared totals.
 * @shared: shared counter block.
 * @stats: local counters to flush.
 * Returns nothing.
 */
static void shared_add(struct stress_shared *shared, struct leaf_stats *stats)
{
	if (stats->operations)
		__sync_fetch_and_add(&shared->operations, stats->operations);
	if (stats->errors)
		__sync_fetch_and_add(&shared->errors, stats->errors);
	stats->operations = 0;
	stats->errors = 0;
}

/*
 * join_path - join a directory and file name.
 * @dst: destination buffer.
 * @dir: directory path.
 * @name: final component.
 * Returns 0 on success, 1 on truncation.
 */
static int join_path(char *dst, const char *dir, const char *name)
{
	int rc = snprintf(dst, PATH_MAX, "%s/%s", dir, name);

	return rc < 0 || rc >= PATH_MAX;
}

/*
 * make_workdir - create the generated file directory.
 * @opts: run options.
 * @paths: path object to fill.
 * Returns 0 on success, 1 on failure.
 */
static int make_workdir(const struct stress_options *opts,
		struct stress_paths *paths)
{
	const char *base = opts->workdir_base ? opts->workdir_base : "/tmp";

	memset(paths, 0, sizeof(*paths));
	if (snprintf(paths->workdir, sizeof(paths->workdir),
		     "%s/fapolicyd-stress.XXXXXX", base) >=
			(int)sizeof(paths->workdir))
		return 1;

	if (mkdtemp(paths->workdir) == NULL)
		return 1;
	paths->created_workdir = 1;

	return 0;
}

/*
 * write_file_data - create a file with exact contents and mode.
 * @path: destination path.
 * @buf: bytes to write.
 * @len: byte count.
 * @mode: file mode to set.
 * Returns 0 on success, 1 on failure.
 */
static int write_file_data(const char *path, const void *buf, size_t len,
		mode_t mode)
{
	const char *ptr = buf;
	size_t done = 0;
	int fd;

	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, mode);
	if (fd < 0)
		return 1;

	while (done < len) {
		ssize_t rc = write(fd, ptr + done, len - done);

		if (rc < 0) {
			if (errno == EINTR)
				continue;
			close(fd);
			return 1;
		}
		done += (size_t)rc;
	}

	if (fchmod(fd, mode)) {
		close(fd);
		return 1;
	}

	close(fd);
	return 0;
}

/*
 * create_large_file - create the file used by the hash workload.
 * @path: destination path.
 * @size_mb: size in MiB.
 * Returns 0 on success, 1 on failure.
 */
static int create_large_file(const char *path, unsigned int size_mb)
{
	unsigned char buf[HASH_BLOCK_SIZE];
	unsigned long long total = (unsigned long long)size_mb * 1024ULL *
				   1024ULL;
	unsigned long long written = 0;
	size_t idx;
	int fd;

	for (idx = 0; idx < sizeof(buf); idx++)
		buf[idx] = (unsigned char)(idx * 31U + 17U);

	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	if (fd < 0)
		return 1;

	while (written < total) {
		size_t want = sizeof(buf);
		ssize_t rc;

		if (total - written < want)
			want = (size_t)(total - written);
		rc = write(fd, buf, want);
		if (rc < 0) {
			if (errno == EINTR)
				continue;
			close(fd);
			return 1;
		}
		written += (unsigned long long)rc;
	}

	close(fd);
	return 0;
}

/*
 * create_churn_files - create many small files for object-cache churn.
 * @paths: generated path object.
 * @count: number of files to create.
 * Returns 0 on success, 1 on failure.
 */
static int create_churn_files(struct stress_paths *paths, unsigned int count)
{
	char file_path[PATH_MAX];
	unsigned int idx;

	if (join_path(paths->churn_dir, paths->workdir, "churn"))
		return 1;
	if (mkdir(paths->churn_dir, 0700) && errno != EEXIST)
		return 1;

	for (idx = 0; idx < count; idx++) {
		char data[64];
		int len;

		if (snprintf(file_path, sizeof(file_path), "%s/file-%06u.dat",
			     paths->churn_dir, idx) >= (int)sizeof(file_path))
			return 1;
		len = snprintf(data, sizeof(data), "fapolicyd-stress %u\n",
			       idx);
		if (len < 0 || len >= (int)sizeof(data))
			return 1;
		if (write_file_data(file_path, data, (size_t)len, 0600))
			return 1;
	}

	return 0;
}

/*
 * workload_needs_scripts - decide whether script inputs are needed.
 * @workload: selected workload.
 * Returns true when script files are needed.
 */
static bool workload_needs_scripts(enum workload_type workload)
{
	return workload == WORKLOAD_INTERPRETER ||
	       workload == WORKLOAD_NOSHEBANG ||
	       workload == WORKLOAD_ALL;
}

/*
 * setup_script_inputs - locate committed scripts and create their data file.
 * @paths: generated path object.
 * Returns 0 on success, 1 on failure.
 */
static int setup_script_inputs(struct stress_paths *paths)
{
	if (join_path(paths->small_file, paths->workdir, "script-data.txt"))
		return 1;
	if (write_file_data(paths->small_file, "script data\n", 12, 0600))
		return 1;

	if (join_path(paths->shebang_script, STRESS_SCRIPT_DIR,
		      "with-shebang.sh"))
		return 1;
	if (join_path(paths->no_shebang_script, STRESS_SCRIPT_DIR,
		      "without-shebang"))
		return 1;

	if (access(paths->shebang_script, X_OK) ||
	    access(paths->no_shebang_script, X_OK))
		return 1;

	return 0;
}

/*
 * setup_paths - create all generated inputs for the selected workload.
 * @opts: run options.
 * @paths: generated path object to fill.
 * Returns 0 on success, 1 on failure.
 */
static int setup_paths(const struct stress_options *opts,
		struct stress_paths *paths)
{
	if (make_workdir(opts, paths))
		return 1;

	if (workload_needs_scripts(opts->workload) &&
	    setup_script_inputs(paths))
		return 1;

	if (opts->workload == WORKLOAD_HASH ||
	    opts->workload == WORKLOAD_ALL) {
		if (join_path(paths->hash_file, paths->workdir,
			      "large-hash-file.dat"))
			return 1;
		if (create_large_file(paths->hash_file, opts->hash_mb))
			return 1;
	}

	if (opts->workload == WORKLOAD_CHURN ||
	    opts->workload == WORKLOAD_ALL) {
		if (create_churn_files(paths, opts->churn_files))
			return 1;
	}

	return 0;
}

/*
 * remove_churn_files - remove generated churn files.
 * @paths: generated path object.
 * @count: number of churn files.
 * Returns nothing.
 */
static void remove_churn_files(const struct stress_paths *paths,
		unsigned int count)
{
	char file_path[PATH_MAX];
	unsigned int idx;

	for (idx = 0; idx < count; idx++) {
		if (snprintf(file_path, sizeof(file_path), "%s/file-%06u.dat",
			     paths->churn_dir, idx) < (int)sizeof(file_path))
			unlink(file_path);
	}
	rmdir(paths->churn_dir);
}

/*
 * cleanup_paths - remove generated inputs unless retention was requested.
 * @opts: run options.
 * @paths: generated path object.
 * Returns nothing.
 */
static void cleanup_paths(const struct stress_options *opts,
		const struct stress_paths *paths)
{
	if (opts->keep_workdir || !paths->created_workdir)
		return;

	if (opts->workload == WORKLOAD_CHURN ||
	    opts->workload == WORKLOAD_ALL)
		remove_churn_files(paths, opts->churn_files);

	if (paths->hash_file[0])
		unlink(paths->hash_file);
	if (paths->small_file[0])
		unlink(paths->small_file);
	rmdir(paths->workdir);
}

/*
 * redirect_child_output - send child stdout and stderr to /dev/null.
 * Returns nothing.
 */
static void redirect_child_output(void)
{
	int fd = open("/dev/null", O_WRONLY | O_CLOEXEC);

	if (fd < 0)
		return;
	dup2(fd, STDOUT_FILENO);
	dup2(fd, STDERR_FILENO);
	close(fd);
}

/*
 * child_exec - execute a target from a forked child.
 * @path: executable path.
 * @argv: argument vector.
 * @enoexec_ok: non-zero treats ENOEXEC as success.
 * Returns only on exec failure by exiting the child.
 */
static NORETURN void child_exec(const char *path,
		char *const argv[], int enoexec_ok)
{
	redirect_child_output();
	execvp(path, argv);
	if (enoexec_ok && errno == ENOEXEC)
		_exit(0);
	_exit(errno == EACCES ? 126 : 127);
}

/*
 * wait_exec - wait for a forked exec child.
 * @pid: child pid.
 * Returns 0 when the child succeeded, 1 otherwise.
 */
static int wait_exec(pid_t pid)
{
	int status;

	for (;;) {
		if (waitpid(pid, &status, 0) >= 0)
			break;
		if (errno != EINTR)
			return 1;
	}

	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
		return 1;
	return 0;
}

/*
 * run_exec_argv - fork and execute one command.
 * @path: executable path.
 * @argv: argument vector.
 * @enoexec_ok: non-zero treats ENOEXEC as success.
 * Returns 0 on success, 1 on failure.
 */
static int run_exec_argv(const char *path, char *const argv[], int enoexec_ok)
{
	pid_t pid = fork();

	if (pid < 0)
		return 1;
	if (pid == 0)
		child_exec(path, argv, enoexec_ok);

	return wait_exec(pid);
}

/*
 * run_simple_exec - fork and execute a single-argument command.
 * @path: executable path.
 * @enoexec_ok: non-zero treats ENOEXEC as success.
 * Returns 0 on success, 1 on failure.
 */
static int run_simple_exec(const char *path, int enoexec_ok)
{
	char *const argv[] = {(char *)path, NULL};

	return run_exec_argv(path, argv, enoexec_ok);
}

/*
 * stat_add_exec_result - account for one exec attempt.
 * @stats: leaf-local counters.
 * @rc: operation return code.
 * Returns nothing.
 */
static void stat_add_exec_result(struct leaf_stats *stats, int rc)
{
	stats->operations++;
	if (rc)
		stats->errors++;
}

/*
 * do_fork_exec - run one harmless installed command.
 * @opts: run options.
 * @stats: leaf-local counters.
 * @iteration: loop iteration used to rotate targets.
 * Returns nothing.
 */
static void do_fork_exec(const struct stress_options *opts,
		struct leaf_stats *stats, unsigned int iteration)
{
	const char *cmd = opts->commands.paths[iteration % opts->commands.count];

	stat_add_exec_result(stats, run_simple_exec(cmd, 0));
}

/*
 * do_exec_open - open all configured command paths and exec one target.
 * @opts: run options.
 * @stats: leaf-local counters.
 * @iteration: loop iteration used to rotate targets.
 * Returns nothing.
 */
static void do_exec_open(const struct stress_options *opts,
		struct leaf_stats *stats, unsigned int iteration)
{
	unsigned int idx;

	for (idx = 0; idx < opts->commands.count; idx++) {
		const char *cmd = opts->commands.paths[idx];
		int fd;

		if (strchr(cmd, '/') == NULL)
			continue;
		stats->operations++;
		fd = open(cmd, O_RDONLY | O_CLOEXEC);
		if (fd < 0)
			stats->errors++;
		else
			close(fd);
	}

	do_fork_exec(opts, stats, iteration);
}

/*
 * do_interpreter - run a shebang script directly and through the shell.
 * @opts: run options.
 * @paths: generated input paths.
 * @stats: leaf-local counters.
 * Returns nothing.
 */
static void do_interpreter(const struct stress_options *opts,
		const struct stress_paths *paths, struct leaf_stats *stats)
{
	char *const direct_argv[] = {
		(char *)paths->shebang_script,
		(char *)paths->small_file,
		NULL
	};
	char *const shell_argv[] = {
		(char *)opts->shell_path,
		(char *)paths->shebang_script,
		(char *)paths->small_file,
		NULL
	};

	stat_add_exec_result(stats, run_exec_argv(paths->shebang_script,
						  direct_argv, 0));
	stat_add_exec_result(stats, run_exec_argv(opts->shell_path,
						  shell_argv, 0));
}

/*
 * do_noshebang - run a no-shebang script directly and through the shell.
 * @opts: run options.
 * @paths: generated input paths.
 * @stats: leaf-local counters.
 * Returns nothing.
 */
static void do_noshebang(const struct stress_options *opts,
		const struct stress_paths *paths, struct leaf_stats *stats)
{
	char *const direct_argv[] = {
		(char *)paths->no_shebang_script,
		(char *)paths->small_file,
		NULL
	};
	char *const shell_argv[] = {
		(char *)opts->shell_path,
		(char *)paths->no_shebang_script,
		(char *)paths->small_file,
		NULL
	};

	stat_add_exec_result(stats, run_exec_argv(paths->no_shebang_script,
						  direct_argv, 1));
	stat_add_exec_result(stats, run_exec_argv(opts->shell_path,
						  shell_argv, 0));
}

/*
 * do_hash_file - read and hash the generated large file.
 * @paths: generated input paths.
 * @stats: leaf-local counters.
 * Returns nothing.
 */
static void do_hash_file(const struct stress_paths *paths,
		struct leaf_stats *stats)
{
	unsigned char buf[HASH_BLOCK_SIZE];
	uint64_t hash = 1469598103934665603ULL;
	int fd;

	fd = open(paths->hash_file, O_RDONLY | O_CLOEXEC);
	stats->operations++;
	if (fd < 0) {
		stats->errors++;
		return;
	}

	for (;;) {
		ssize_t len = read(fd, buf, sizeof(buf));
		ssize_t pos;

		if (len < 0) {
			if (errno == EINTR)
				continue;
			stats->errors++;
			break;
		}
		if (len == 0)
			break;
		for (pos = 0; pos < len; pos++) {
			hash ^= buf[pos];
			hash *= 1099511628211ULL;
		}
	}

	if (hash == 0)
		stats->errors++;
	close(fd);
}

/*
 * do_cache_churn - open one generated churn file.
 * @opts: run options.
 * @paths: generated input paths.
 * @stats: leaf-local counters.
 * @iteration: loop iteration used to rotate files.
 * Returns nothing.
 */
static void do_cache_churn(const struct stress_options *opts,
		const struct stress_paths *paths, struct leaf_stats *stats,
		unsigned int iteration)
{
	char file_path[PATH_MAX];
	char byte;
	int fd;

	if (opts->churn_files == 0)
		return;
	if (snprintf(file_path, sizeof(file_path), "%s/file-%06u.dat",
		     paths->churn_dir, iteration % opts->churn_files) >=
			(int)sizeof(file_path)) {
		stats->errors++;
		return;
	}

	stats->operations++;
	fd = open(file_path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		stats->errors++;
		return;
	}
	if (read(fd, &byte, sizeof(byte)) < 0)
		stats->errors++;
	close(fd);
}

/*
 * run_one_iteration - run the selected workload once.
 * @opts: run options.
 * @paths: generated input paths.
 * @stats: leaf-local counters.
 * @iteration: loop iteration.
 * Returns nothing.
 */
static void run_one_iteration(const struct stress_options *opts,
		const struct stress_paths *paths, struct leaf_stats *stats,
		unsigned int iteration)
{
	switch (opts->workload) {
	case WORKLOAD_EXEC_OPEN:
		do_exec_open(opts, stats, iteration);
		break;
	case WORKLOAD_FORK_EXEC:
		do_fork_exec(opts, stats, iteration);
		break;
	case WORKLOAD_INTERPRETER:
		do_interpreter(opts, paths, stats);
		break;
	case WORKLOAD_NOSHEBANG:
		do_noshebang(opts, paths, stats);
		break;
	case WORKLOAD_HASH:
		do_hash_file(paths, stats);
		break;
	case WORKLOAD_CHURN:
		do_cache_churn(opts, paths, stats, iteration);
		break;
	case WORKLOAD_ALL:
		do_exec_open(opts, stats, iteration);
		do_fork_exec(opts, stats, iteration);
		do_interpreter(opts, paths, stats);
		do_noshebang(opts, paths, stats);
		do_hash_file(paths, stats);
		do_cache_churn(opts, paths, stats, iteration);
		break;
	}
}

/*
 * leaf_loop - execute workload iterations in a leaf process.
 * @opts: run options.
 * @paths: generated input paths.
 * @shared: shared run state.
 * Returns only by exiting the leaf process.
 */
static NORETURN void leaf_loop(const struct stress_options *opts,
		const struct stress_paths *paths, struct stress_shared *shared)
{
	struct leaf_stats stats = {0, 0};
	unsigned int iteration = 0;

	while (!shared->stop) {
		if (opts->iterations && iteration >= opts->iterations)
			break;

		run_one_iteration(opts, paths, &stats, iteration);
		iteration++;

		if ((iteration & 0x3F) == 0)
			shared_add(shared, &stats);
	}

	shared_add(shared, &stats);
	_exit(0);
}

/*
 * wait_for_children - wait for branch children.
 * @children: child pid array.
 * @count: number of pids in the array.
 * Returns 0 if all children succeeded, 1 otherwise.
 */
static int wait_for_children(pid_t *children, unsigned int count)
{
	unsigned int idx;
	int failed = 0;

	for (idx = 0; idx < count; idx++) {
		int status = 0;
		int waited = 0;

		for (;;) {
			if (waitpid(children[idx], &status, 0) >= 0) {
				waited = 1;
				break;
			}
			if (errno != EINTR) {
				failed = 1;
				break;
			}
		}
		if (!waited || !WIFEXITED(status) || WEXITSTATUS(status) != 0)
			failed = 1;
	}

	return failed;
}

/*
 * spawn_branch - recursively create a process subtree.
 * @opts: run options.
 * @paths: generated input paths.
 * @shared: shared run state.
 * @depth: remaining depth below this process.
 * Returns only by exiting the branch process.
 */
static NORETURN void spawn_branch(
		const struct stress_options *opts,
		const struct stress_paths *paths, struct stress_shared *shared,
		unsigned int depth)
{
	pid_t *children;
	unsigned int idx;
	int failed;

	if (depth == 0)
		leaf_loop(opts, paths, shared);

	children = calloc(opts->fanout, sizeof(*children));
	if (children == NULL)
		_exit(1);

	for (idx = 0; idx < opts->fanout; idx++) {
		children[idx] = fork();
		if (children[idx] < 0) {
			shared->stop = 1;
			free(children);
			_exit(1);
		}
		if (children[idx] == 0)
			spawn_branch(opts, paths, shared, depth - 1);
	}

	failed = wait_for_children(children, opts->fanout);
	free(children);
	_exit(failed ? 1 : 0);
}

/*
 * estimate_leaf_count - calculate expected leaf process count.
 * @opts: run options.
 * @out: destination for estimated leaves.
 * Returns 0 on success, 1 on overflow.
 */
static int estimate_leaf_count(const struct stress_options *opts,
		unsigned long long *out)
{
	unsigned long long leaves = opts->roots;
	unsigned int idx;

	for (idx = 0; idx < opts->depth; idx++) {
		if (opts->fanout &&
		    leaves > ULLONG_MAX / opts->fanout)
			return 1;
		leaves *= opts->fanout;
	}

	*out = leaves;
	return 0;
}

/*
 * start_roots - fork root processes for the stress tree.
 * @opts: run options.
 * @paths: generated input paths.
 * @shared: shared run state.
 * Returns a pid array on success, NULL on failure.
 */
static pid_t *start_roots(const struct stress_options *opts,
		const struct stress_paths *paths, struct stress_shared *shared)
{
	pid_t *roots;
	unsigned int idx;

	roots = calloc(opts->roots, sizeof(*roots));
	if (roots == NULL)
		return NULL;

	for (idx = 0; idx < opts->roots; idx++) {
		roots[idx] = fork();
		if (roots[idx] < 0) {
			shared->stop = 1;
			return roots;
		}
		if (roots[idx] == 0) {
			setpgid(0, 0);
			spawn_branch(opts, paths, shared, opts->depth);
		}
		setpgid(roots[idx], roots[idx]);
	}

	return roots;
}

/*
 * roots_done - reap any finished roots.
 * @roots: pid array.
 * @count: number of roots.
 * Returns non-zero when every root has exited.
 */
static int roots_done(pid_t *roots, unsigned int count)
{
	unsigned int idx;
	int all_done = 1;

	for (idx = 0; idx < count; idx++) {
		int status;

		if (roots[idx] == 0)
			continue;
		if (waitpid(roots[idx], &status, WNOHANG) == roots[idx])
			roots[idx] = 0;
		else if (errno == ECHILD)
			roots[idx] = 0;
		else
			all_done = 0;
	}

	return all_done;
}

/*
 * wait_roots_until - wait for root processes until a deadline.
 * @roots: pid array.
 * @count: number of roots.
 * @deadline: monotonic nanosecond deadline.
 *
 * The shared stop flag tells leaf loops to stop starting new work. Waiting
 * here gives in-flight exec/open operations time to finish naturally before
 * the harness has to terminate remaining process groups.
 *
 * Returns non-zero when every root has exited.
 */
static int wait_roots_until(pid_t *roots, unsigned int count,
		unsigned long long deadline)
{
	while (monotonic_ns() < deadline) {
		if (roots_done(roots, count))
			return 1;
		usleep(10000);
	}

	return roots_done(roots, count);
}

/*
 * stop_roots - terminate unfinished root process groups.
 * @roots: pid array.
 * @count: number of roots.
 * @sig: signal to send.
 * Returns nothing.
 */
static void stop_roots(pid_t *roots, unsigned int count, int sig)
{
	unsigned int idx;

	for (idx = 0; idx < count; idx++) {
		if (roots[idx] > 0)
			kill(-roots[idx], sig);
	}
}

/*
 * wait_remaining_roots - wait for all remaining root processes.
 * @roots: pid array.
 * @count: number of roots.
 * Returns nothing.
 */
static void wait_remaining_roots(pid_t *roots, unsigned int count)
{
	unsigned int idx;

	for (idx = 0; idx < count; idx++) {
		if (roots[idx] <= 0)
			continue;
		while (waitpid(roots[idx], NULL, 0) < 0 && errno == EINTR)
			;
		roots[idx] = 0;
	}
}

/*
 * run_stress_tree - run the configured process tree to completion.
 * @opts: run options.
 * @paths: generated input paths.
 * @shared: shared run state.
 * Returns 0 when the tree was started, 1 on setup failure.
 */
static int run_stress_tree(const struct stress_options *opts,
		const struct stress_paths *paths, struct stress_shared *shared)
{
	unsigned long long start = monotonic_ns();
	unsigned long long deadline = 0;
	pid_t *roots;

	if (opts->seconds)
		deadline = start + (unsigned long long)opts->seconds *
			   1000000000ULL;

	roots = start_roots(opts, paths, shared);
	if (roots == NULL)
		return 1;

	while (!shared->stop) {
		if (roots_done(roots, opts->roots))
			break;
		if (deadline && monotonic_ns() >= deadline) {
			shared->stop = 1;
			break;
		}
		usleep(10000);
	}

	if (shared->stop) {
		if (!wait_roots_until(roots, opts->roots,
				      monotonic_ns() + GRACEFUL_STOP_NS)) {
			stop_roots(roots, opts->roots, SIGTERM);
			if (!wait_roots_until(roots, opts->roots,
					      monotonic_ns() + TERM_STOP_NS))
				stop_roots(roots, opts->roots, SIGKILL);
		}
	}
	wait_remaining_roots(roots, opts->roots);
	free(roots);
	return 0;
}

/*
 * capture_free - release captured command output.
 * @capture: capture object to clear.
 * Returns nothing.
 */
static void capture_free(struct capture *capture)
{
	free(capture->data);
	capture->data = NULL;
	capture->len = 0;
	capture->status = 0;
}

/*
 * run_capture - run a helper command and capture stdout/stderr.
 * @path: executable path.
 * @argv: argument vector.
 * @capture: captured output destination.
 * Returns 0 when the command ran and exited successfully, 1 otherwise.
 */
static int run_capture(const char *path, char *const argv[],
		struct capture *capture)
{
	char *buf = NULL;
	size_t len = 0;
	int pipefd[2];
	pid_t pid;
	int status = 0;

	memset(capture, 0, sizeof(*capture));
	if (pipe(pipefd))
		return 1;

	pid = fork();
	if (pid < 0) {
		close(pipefd[0]);
		close(pipefd[1]);
		return 1;
	}
	if (pid == 0) {
		close(pipefd[0]);
		dup2(pipefd[1], STDOUT_FILENO);
		dup2(pipefd[1], STDERR_FILENO);
		close(pipefd[1]);
		execvp(path, argv);
		_exit(127);
	}

	close(pipefd[1]);
	for (;;) {
		char tmp[4096];
		ssize_t rc = read(pipefd[0], tmp, sizeof(tmp));

		if (rc < 0) {
			if (errno == EINTR)
				continue;
			break;
		}
		if (rc == 0)
			break;
		if (len + (size_t)rc + 1 <= CAPTURE_LIMIT) {
			char *next = realloc(buf, len + (size_t)rc + 1);

			if (next == NULL)
				break;
			buf = next;
			memcpy(buf + len, tmp, (size_t)rc);
			len += (size_t)rc;
			buf[len] = 0;
		}
	}
	close(pipefd[0]);

	while (waitpid(pid, &status, 0) < 0 && errno == EINTR)
		;

	if (buf == NULL) {
		buf = calloc(1, 1);
		if (buf == NULL)
			return 1;
	}
	capture->data = buf;
	capture->len = len;
	capture->status = status;

	return !WIFEXITED(status) || WEXITSTATUS(status) != 0;
}

/*
 * file_executable - test whether a path is executable.
 * @path: candidate path.
 * Returns true when it can be executed.
 */
static bool file_executable(const char *path)
{
	return path && access(path, X_OK) == 0;
}

/*
 * find_cli_from_exe - locate fapolicyd-cli relative to this helper.
 * @dst: destination path buffer.
 * Returns 0 when an executable candidate is found, 1 otherwise.
 */
static int find_cli_from_exe(char *dst)
{
	char exe[PATH_MAX];
	char *slash;
	ssize_t len;

	len = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
	if (len < 0)
		return 1;
	exe[len] = 0;
	slash = strrchr(exe, '/');
	if (slash == NULL)
		return 1;
	*slash = 0;
	if (snprintf(dst, PATH_MAX, "%s/../../fapolicyd-cli", exe) >=
			PATH_MAX)
		return 1;
	return file_executable(dst) ? 0 : 1;
}

/*
 * find_cli - locate fapolicyd-cli for report collection.
 * @opts: run options.
 * @dst: destination path buffer.
 * Returns 0 when an executable candidate is found, 1 otherwise.
 */
static int find_cli(const struct stress_options *opts, char *dst)
{
	const char *env = getenv("FAPOLICYD_CLI");
	static const char * const candidates[] = {
		"src/fapolicyd-cli",
		"./fapolicyd-cli",
		"../../fapolicyd-cli",
		"/usr/sbin/fapolicyd-cli",
		"/sbin/fapolicyd-cli",
		"/usr/bin/fapolicyd-cli",
		"/bin/fapolicyd-cli",
		NULL
	};
	unsigned int idx;

	if (opts->cli_path) {
		if (!file_executable(opts->cli_path))
			return 1;
		snprintf(dst, PATH_MAX, "%s", opts->cli_path);
		return 0;
	}

	if (env && file_executable(env)) {
		snprintf(dst, PATH_MAX, "%s", env);
		return 0;
	}

	if (find_cli_from_exe(dst) == 0)
		return 0;

	for (idx = 0; candidates[idx]; idx++) {
		if (file_executable(candidates[idx])) {
			snprintf(dst, PATH_MAX, "%s", candidates[idx]);
			return 0;
		}
	}

	return 1;
}

/*
 * parse_human_u64 - parse an unsigned integer allowing commas.
 * @text: text to parse.
 * @out: parsed destination.
 * Returns 0 on success, 1 on parse error.
 */
static int parse_human_u64(const char *text, unsigned long long *out)
{
	unsigned long long value = 0;
	int saw_digit = 0;

	while (*text && isspace((unsigned char)*text))
		text++;
	while (*text) {
		if (*text == ',') {
			text++;
			continue;
		}
		if (!isdigit((unsigned char)*text))
			break;
		value = value * 10ULL + (unsigned long long)(*text - '0');
		saw_digit = 1;
		text++;
	}

	if (!saw_digit)
		return 1;
	*out = value;
	return 0;
}

/*
 * parse_u64_line - parse a numeric "name: value" line.
 * @data: report text.
 * @name: metric name with trailing colon.
 * @out: parsed destination.
 * Returns 0 on success, 1 when not found or invalid.
 */
static int parse_u64_line(const char *data, const char *name,
		unsigned long long *out)
{
	size_t name_len = strlen(name);
	const char *pos = data;

	while ((pos = strstr(pos, name)) != NULL) {
		if ((pos == data || pos[-1] == '\n') &&
		    parse_human_u64(pos + name_len, out) == 0)
			return 0;
		pos += name_len;
	}

	return 1;
}

/*
 * parse_word_line - parse the first word after a "name: value" line.
 * @data: report text.
 * @name: metric name with trailing colon.
 * @out: destination buffer.
 * @out_len: destination buffer size.
 * Returns 0 on success, 1 when not found or invalid.
 */
static int parse_word_line(const char *data, const char *name,
		char *out, size_t out_len)
{
	size_t name_len = strlen(name);
	const char *pos = data;
	size_t idx = 0;

	while ((pos = strstr(pos, name)) != NULL) {
		if (pos != data && pos[-1] != '\n') {
			pos += name_len;
			continue;
		}
		pos += name_len;
		while (*pos && isspace((unsigned char)*pos))
			pos++;
		while (*pos && !isspace((unsigned char)*pos) &&
		       idx + 1 < out_len)
			out[idx++] = *pos++;
		out[idx] = 0;
		return idx ? 0 : 1;
	}

	return 1;
}

/*
 * parse_double_line - parse a floating point "name: value" line.
 * @data: report text.
 * @name: metric name with trailing colon.
 * @out: parsed destination.
 * Returns 0 on success, 1 when not found or invalid.
 */
static int parse_double_line(const char *data, const char *name, double *out)
{
	size_t name_len = strlen(name);
	const char *pos = data;
	char *end = NULL;

	pos = strstr(data, name);
	if (pos == NULL)
		return 1;
	pos += name_len;
	while (*pos && isspace((unsigned char)*pos))
		pos++;
	errno = 0;
	*out = strtod(pos, &end);
	if (errno || end == pos)
		return 1;
	return 0;
}

/*
 * trim_space - remove leading and trailing whitespace in a line field.
 * @text: field text.
 * Returns the first non-space character in the trimmed field.
 */
static char *trim_space(char *text)
{
	char *end;

	while (isspace((unsigned char)*text))
		text++;
	if (*text == 0)
		return text;

	end = text + strlen(text) - 1;
	while (end > text && isspace((unsigned char)*end)) {
		*end = 0;
		end--;
	}

	return text;
}

/*
 * parse_config_assignment - split one fapolicyd.conf assignment.
 * @line: mutable configuration line.
 * @name: destination for the trimmed option name.
 * @value: destination for the trimmed option value.
 * Returns 0 when an assignment was found, 1 for blank or non-assignment lines.
 */
static int parse_config_assignment(char *line, char **name, char **value)
{
	char *comment;
	char *equals;

	comment = strchr(line, '#');
	if (comment)
		*comment = 0;

	equals = strchr(line, '=');
	if (equals == NULL)
		return 1;

	*equals = 0;
	*name = trim_space(line);
	*value = trim_space(equals + 1);
	return **name && **value ? 0 : 1;
}

/*
 * copy_config_word - copy the first whitespace-delimited config value.
 * @dst: destination buffer.
 * @src: source value.
 * @dst_len: destination buffer size.
 * Returns nothing.
 */
static void copy_config_word(char *dst, const char *src, size_t dst_len)
{
	size_t idx = 0;

	while (*src && !isspace((unsigned char)*src) && idx + 1 < dst_len)
		dst[idx++] = *src++;
	dst[idx] = 0;
}

/*
 * parse_config_snapshot - extract reset-sensitive fapolicyd.conf settings.
 * @config: destination config snapshot.
 * @line: mutable configuration line.
 * Returns nothing.
 */
static void parse_config_snapshot(struct daemon_config_snapshot *config,
		char *line)
{
	unsigned int value;
	char *name;
	char *setting;

	if (parse_config_assignment(line, &name, &setting))
		return;

	if (strcmp(name, "report_interval") == 0) {
		if (parse_uint(setting, &value) == 0) {
			config->report_interval = value;
			config->have_report_interval = 1;
		}
	} else if (strcmp(name, "reset_strategy") == 0) {
		copy_config_word(config->reset_strategy, setting,
				 sizeof(config->reset_strategy));
		config->have_reset_strategy = config->reset_strategy[0] != 0;
	}
}

/*
 * read_daemon_config_snapshot - read config settings that affect counters.
 * @config: destination config snapshot.
 * @verbose: non-zero prints config read failures.
 * Returns 0 when the config was read, 1 otherwise.
 */
static int read_daemon_config_snapshot(struct daemon_config_snapshot *config,
		int verbose)
{
	char line[8192];
	FILE *file;
	int fd;

	memset(config, 0, sizeof(*config));

	fd = open(CONFIG_FILE, O_RDONLY | O_NOFOLLOW);
	if (fd < 0) {
		if (verbose && errno != ENOENT)
			fprintf(stderr, "cannot read %s: %s\n",
				CONFIG_FILE, strerror(errno));
		return 1;
	}

	file = fdopen(fd, "r");
	if (file == NULL) {
		if (verbose)
			fprintf(stderr, "cannot read %s: %s\n",
				CONFIG_FILE, strerror(errno));
		close(fd);
		return 1;
	}

	while (fgets(line, sizeof(line), file))
		parse_config_snapshot(config, line);

	fclose(file);
	return 0;
}

/*
 * copy_token_until - copy text until a delimiter or line end.
 * @dst: destination buffer.
 * @src: source pointer.
 * @delim: delimiter to stop at.
 * Returns nothing.
 */
static void copy_token_until(char *dst, const char *src, char delim)
{
	size_t idx = 0;

	while (*src && *src != delim && *src != '\n' &&
	       idx + 1 < 32) {
		dst[idx++] = *src++;
	}
	dst[idx] = 0;
}

/*
 * parse_daemon_metrics - merge daemon report metrics used by this harness.
 * @data: fapolicyd state and metrics report text.
 * @metrics: metric snapshot to update.
 * Returns nothing.
 */
static void parse_daemon_metrics(const char *data,
		struct daemon_metrics *metrics)
{
	metrics->present = 1;
	parse_u64_line(data, "Inter-thread max queue depth:",
		       &metrics->queue_max_depth);
	parse_u64_line(data, "Subject deferred events:",
		       &metrics->subject_defer_current);
	parse_u64_line(data, "Subject defer max depth:",
		       &metrics->subject_defer_max_depth);
	parse_u64_line(data, "Subject defer fallbacks:",
		       &metrics->subject_defer_fallbacks);
	parse_word_line(data, "Subject defer oldest age:",
			metrics->subject_defer_oldest_age,
			sizeof(metrics->subject_defer_oldest_age));
	parse_u64_line(data, "Early subject cache evictions:",
		       &metrics->early_subject_evictions);
	parse_u64_line(data, "Subject BUILDING tracer evictions:",
		       &metrics->subject_tracer_evictions);
	parse_u64_line(data, "Subject BUILDING stale evictions:",
		       &metrics->subject_stale_evictions);
	parse_u64_line(data, "Subject collisions:",
		       &metrics->subject_collisions);
	parse_u64_line(data, "Subject evictions:",
		       &metrics->subject_evictions);
	parse_u64_line(data, "Object collisions:",
		       &metrics->object_collisions);
	parse_u64_line(data, "Object evictions:",
		       &metrics->object_evictions);
	parse_u64_line(data, "Allowed accesses:", &metrics->allowed);
	parse_u64_line(data, "Denied accesses:", &metrics->denied);
	parse_u64_line(data, "Kernel queue overflow:",
		       &metrics->kernel_overflow);
	parse_u64_line(data, "Reply errors:", &metrics->reply_errors);

	if (parse_word_line(data, "Timing collection mode:",
			    metrics->timing_mode,
			    sizeof(metrics->timing_mode)) == 0)
		metrics->have_timing_mode = 1;
	if (parse_word_line(data, "reset_strategy:",
			    metrics->reset_strategy,
			    sizeof(metrics->reset_strategy)) == 0)
		metrics->have_reset_strategy = 1;
}

/*
 * parse_timing_metrics - extract timing metrics used by this harness.
 * @data: fapolicyd timing report text.
 * @metrics: metric snapshot to fill.
 * Returns nothing.
 */
static void parse_timing_metrics(const char *data,
		struct timing_metrics *metrics)
{
	const char *pos;

	memset(metrics, 0, sizeof(*metrics));
	metrics->present = 1;
	parse_u64_line(data, "Max queue depth:", &metrics->max_queue_depth);
	parse_u64_line(data, "Decisions:", &metrics->decisions);
	parse_double_line(data, "Throughput:", &metrics->throughput);
	parse_double_line(data, "Active decision rate:", &metrics->active_rate);

	pos = strstr(data, "Overall decision latency:");
	if (pos) {
		const char *avg = strstr(pos, "  avg ");
		const char *p95 = strstr(pos, "p95 bucket ");

		if (avg) {
			avg += strlen("  avg ");
			copy_token_until(metrics->avg_latency, avg, ',');
			pos = strstr(avg, "max ");
			if (pos) {
				pos += strlen("max ");
				copy_token_until(metrics->max_latency, pos, '\n');
			}
		}
		if (p95) {
			p95 += strlen("p95 bucket ");
			copy_token_until(metrics->p95_latency, p95, ',');
		}
	}
}

/*
 * collect_status - ask fapolicyd-cli for state and metrics and parse them.
 * @cli_path: fapolicyd-cli executable.
 * @metrics: destination metrics.
 * @verbose: non-zero prints failures.
 * Returns 0 on success, 1 on failure.
 */
static int collect_status(const char *cli_path, struct daemon_metrics *metrics,
		int verbose)
{
	struct capture capture;
	char *const state_argv[] = {(char *)cli_path, "--check-status", NULL};
	char *const metrics_argv[] = {(char *)cli_path, "--check-metrics", NULL};
	int rc;

	memset(metrics, 0, sizeof(*metrics));

	rc = run_capture(cli_path, state_argv, &capture);
	if (rc) {
		if (verbose)
			fprintf(stderr, "status capture failed: %s\n",
				capture.data ? capture.data : "no output");
		capture_free(&capture);
		return 1;
	}
	parse_daemon_metrics(capture.data, metrics);
	capture_free(&capture);

	rc = run_capture(cli_path, metrics_argv, &capture);
	if (rc) {
		if (verbose)
			fprintf(stderr, "metrics capture failed: %s\n",
				capture.data ? capture.data : "no output");
		capture_free(&capture);
		return 1;
	}
	parse_daemon_metrics(capture.data, metrics);
	capture_free(&capture);
	return 0;
}

/*
 * validate_privileged_options - report options that need elevated privilege.
 * @opts: run options.
 * Returns 0 when the run may continue, 1 for a hard privilege error.
 */
static int validate_privileged_options(const struct stress_options *opts)
{
	if (geteuid() == 0)
		return 0;

	if (opts->collect_timing) {
		fprintf(stderr,
			"--timing requires root or equivalent privilege\n");
		return 1;
	}
	if (opts->collect_status)
		fprintf(stderr,
			"--status may require root; use --no-status for an "
			"unprivileged workload-only run\n");

	return 0;
}

/*
 * ensure_timing_ready - verify active daemon timing configuration.
 * @cli_path: fapolicyd-cli executable.
 * @status: existing status snapshot, or NULL.
 * @verbose: non-zero prints status capture failures.
 * Returns 0 when manual timing can be requested, 1 otherwise.
 */
static int ensure_timing_ready(const char *cli_path,
		const struct daemon_metrics *status, int verbose)
{
	struct daemon_metrics tmp;

	if (status == NULL || !status->present) {
		if (collect_status(cli_path, &tmp, verbose)) {
			fprintf(stderr,
				"--timing requires an active daemon status "
				"report to verify timing_collection=manual\n");
			return 1;
		}
		status = &tmp;
	}

	if (!status->have_timing_mode) {
		fprintf(stderr,
			"--timing requires a daemon status report with "
			"Timing collection mode\n");
		return 1;
	}
	if (strcmp(status->timing_mode, "manual") != 0) {
		fprintf(stderr,
			"--timing requires timing_collection=manual in the "
			"active daemon configuration; current mode is %s\n",
			status->timing_mode);
		return 1;
	}

	return 0;
}

/*
 * warn_interval_reset_hazard - warn when interval reports may reset counters.
 * @opts: run options.
 * @status: active daemon status snapshot, or NULL.
 * Returns nothing.
 */
static void warn_interval_reset_hazard(const struct stress_options *opts,
		const struct daemon_metrics *status)
{
	struct daemon_config_snapshot config;
	const char *reset_strategy = NULL;

	if (read_daemon_config_snapshot(&config, opts->verbose))
		return;
	if (!config.have_report_interval || config.report_interval == 0)
		return;

	if (status && status->have_reset_strategy)
		reset_strategy = status->reset_strategy;
	else if (config.have_reset_strategy)
		reset_strategy = config.reset_strategy;

	if (reset_strategy == NULL || strcmp(reset_strategy, "auto") != 0)
		return;

	fprintf(stderr,
		"warning: reset_strategy=auto with report_interval=%u can "
		"reset daemon counters during this run; stress deltas and "
		"post-run state reports may undercount workload activity\n",
		config.report_interval);
}

/*
 * timing_start - request manual decision timing start.
 * @cli_path: fapolicyd-cli executable.
 * @verbose: non-zero prints failures.
 * Returns 0 on success, 1 on failure.
 */
static int timing_start(const char *cli_path, int verbose)
{
	struct capture capture;
	char *const argv[] = {(char *)cli_path, "--timing-start", NULL};
	int rc = run_capture(cli_path, argv, &capture);

	if (rc && verbose)
		fprintf(stderr, "timing start failed: %s\n",
			capture.data ? capture.data : "no output");
	capture_free(&capture);
	return rc;
}

/*
 * timing_stop - request manual decision timing stop and parse report.
 * @cli_path: fapolicyd-cli executable.
 * @metrics: destination timing metrics.
 * @verbose: non-zero prints failures.
 * Returns 0 on success, 1 on failure.
 */
static int timing_stop(const char *cli_path, struct timing_metrics *metrics,
		int verbose)
{
	struct capture capture;
	char *const argv[] = {(char *)cli_path, "--timing-stop", NULL};
	int rc = run_capture(cli_path, argv, &capture);

	if (rc) {
		if (verbose)
			fprintf(stderr, "timing stop failed: %s\n",
				capture.data ? capture.data : "no output");
		capture_free(&capture);
		return 1;
	}
	parse_timing_metrics(capture.data, metrics);
	capture_free(&capture);
	return 0;
}

/*
 * metric_delta - calculate an unsigned monotonic metric delta.
 * @after: value after the run.
 * @before: value before the run.
 * Returns after-before when monotonic, otherwise after.
 */
static unsigned long long metric_delta(unsigned long long after,
		unsigned long long before)
{
	return after >= before ? after - before : after;
}

/*
 * print_metric_delta - print one before/after metric line.
 * @name: printable metric name.
 * @before: value before the run.
 * @after: value after the run.
 * Returns nothing.
 */
static void print_metric_delta(const char *name, unsigned long long before,
		unsigned long long after)
{
	printf("%s: before=%llu after=%llu delta=%llu\n", name, before, after,
	       metric_delta(after, before));
}

/*
 * print_status_summary - print daemon status metrics for the run.
 * @before: metrics before the run.
 * @after: metrics after the run.
 * Returns nothing.
 */
static void print_status_summary(const struct daemon_metrics *before,
		const struct daemon_metrics *after)
{
	if (!before->present || !after->present) {
		printf("Daemon status: not observed\n");
		return;
	}

	printf("\nDaemon status deltas:\n");
	printf("Inter-thread max queue depth: before=%llu after=%llu\n",
	       before->queue_max_depth, after->queue_max_depth);
	printf("Subject deferred events: before=%llu after=%llu\n",
	       before->subject_defer_current,
	       after->subject_defer_current);
	printf("Subject defer max depth: before=%llu after=%llu\n",
	       before->subject_defer_max_depth,
	       after->subject_defer_max_depth);
	print_metric_delta("Subject defer fallbacks",
			   before->subject_defer_fallbacks,
			   after->subject_defer_fallbacks);
	printf("Subject defer oldest age: before=%s after=%s\n",
	       before->subject_defer_oldest_age[0] ?
			before->subject_defer_oldest_age : "0ns",
	       after->subject_defer_oldest_age[0] ?
			after->subject_defer_oldest_age : "0ns");
	print_metric_delta("Early subject cache evictions",
			   before->early_subject_evictions,
			   after->early_subject_evictions);
	print_metric_delta("Subject BUILDING tracer evictions",
			   before->subject_tracer_evictions,
			   after->subject_tracer_evictions);
	print_metric_delta("Subject BUILDING stale evictions",
			   before->subject_stale_evictions,
			   after->subject_stale_evictions);
	print_metric_delta("Subject collisions", before->subject_collisions,
			   after->subject_collisions);
	print_metric_delta("Subject evictions", before->subject_evictions,
			   after->subject_evictions);
	print_metric_delta("Object collisions", before->object_collisions,
			   after->object_collisions);
	print_metric_delta("Object evictions", before->object_evictions,
			   after->object_evictions);
	print_metric_delta("Allowed accesses", before->allowed,
			   after->allowed);
	print_metric_delta("Denied accesses", before->denied, after->denied);
	print_metric_delta("Kernel queue overflows", before->kernel_overflow,
			   after->kernel_overflow);
	print_metric_delta("Reply errors", before->reply_errors,
			   after->reply_errors);
}

/*
 * print_timing_summary - print parsed decision timing metrics.
 * @timing: timing metrics to print.
 * Returns nothing.
 */
static void print_timing_summary(const struct timing_metrics *timing)
{
	if (!timing->present) {
		printf("\nDecision timing: not observed\n");
		return;
	}

	printf("\nDecision timing:\n");
	printf("Full report: %s\n", TIMING_REPORT);
	printf("Decisions: %llu\n", timing->decisions);
	printf("Max queue depth during timing: %llu\n",
	       timing->max_queue_depth);
	if (timing->throughput)
		printf("Timed throughput: %.1f decisions/sec\n",
		       timing->throughput);
	if (timing->active_rate)
		printf("Active decision rate: %.1f decisions/sec\n",
		       timing->active_rate);
	if (timing->avg_latency[0] || timing->max_latency[0] ||
	    timing->p95_latency[0])
		printf("Decision latency: avg=%s max=%s p95_bucket=%s\n",
		       timing->avg_latency[0] ? timing->avg_latency : "n/a",
		       timing->max_latency[0] ? timing->max_latency : "n/a",
		       timing->p95_latency[0] ? timing->p95_latency : "n/a");
}

/*
 * print_run_header - print selected workload configuration.
 * @opts: run options.
 * @leaves: estimated leaf process count.
 * @paths: generated path object.
 * Returns nothing.
 */
static void print_run_header(const struct stress_options *opts,
		unsigned long long leaves, const struct stress_paths *paths)
{
	printf("fapolicyd stress harness\n");
	printf("workload: %s\n", workload_name(opts->workload));
	printf("roots: %u\n", opts->roots);
	printf("fanout: %u\n", opts->fanout);
	printf("depth: %u\n", opts->depth);
	printf("estimated leaf processes: %llu\n", leaves);
	printf("iterations per leaf: %u\n", opts->iterations);
	printf("seconds: %u\n", opts->seconds);
	printf("workdir: %s\n", paths->workdir);
}

/*
 * print_run_summary - print local workload throughput.
 * @shared: shared run counters.
 * @elapsed_ns: elapsed wall-clock nanoseconds.
 * Returns nothing.
 */
static void print_run_summary(const struct stress_shared *shared,
		unsigned long long elapsed_ns)
{
	double seconds = elapsed_ns ? (double)elapsed_ns / 1000000000.0 : 0.0;
	double throughput = seconds ? (double)shared->operations / seconds : 0.0;

	printf("\nWorkload summary:\n");
	printf("wall_seconds: %.3f\n", seconds);
	printf("operations: %llu\n", shared->operations);
	printf("errors: %llu\n", shared->errors);
	printf("throughput_ops_per_sec: %.1f\n", throughput);
}

/*
 * main - program entry point.
 * @argc: argument count.
 * @argv: argument vector.
 * Returns 0 when the run completed without workload errors, non-zero on
 * setup or workload failure.
 */
int main(int argc, char **argv)
{
	struct stress_options opts;
	struct stress_paths paths;
	struct stress_shared *shared;
	struct daemon_metrics before_status;
	struct daemon_metrics after_status;
	struct timing_metrics timing;
	unsigned long long leaves = 0;
	unsigned long long start_ns;
	unsigned long long end_ns;
	char cli_path[PATH_MAX] = "";
	int cli_available = 0;
	int arg_rc;
	int rc = 0;

	set_defaults(&opts);
	arg_rc = parse_args(&opts, argc, argv);
	if (arg_rc == 2)
		return 0;
	if (arg_rc) {
		usage(argv[0]);
		return 2;
	}
	if (validate_privileged_options(&opts))
		return 2;

	if (opts.commands.count == 0 && add_default_commands(&opts.commands)) {
		fprintf(stderr, "no executable command targets found\n");
		return 1;
	}
	if (find_shell(&opts)) {
		fprintf(stderr, "no executable shell found\n");
		return 1;
	}
	if (estimate_leaf_count(&opts, &leaves)) {
		fprintf(stderr, "process tree size overflow\n");
		return 1;
	}
	if (setup_paths(&opts, &paths)) {
		fprintf(stderr, "failed to create stress inputs: %s\n",
			strerror(errno));
		cleanup_paths(&opts, &paths);
		return 1;
	}

	shared = mmap(NULL, sizeof(*shared), PROT_READ | PROT_WRITE,
		      MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (shared == MAP_FAILED) {
		fprintf(stderr, "failed to create shared counters: %s\n",
			strerror(errno));
		cleanup_paths(&opts, &paths);
		return 1;
	}
	memset(shared, 0, sizeof(*shared));

	memset(&before_status, 0, sizeof(before_status));
	memset(&after_status, 0, sizeof(after_status));
	memset(&timing, 0, sizeof(timing));

	cli_available = find_cli(&opts, cli_path) == 0;
	if (opts.collect_timing && !cli_available) {
		fprintf(stderr, "--timing requires fapolicyd-cli\n");
		rc = 1;
		goto out;
	}
	if (opts.collect_status && cli_available)
		collect_status(cli_path, &before_status, opts.verbose);
	warn_interval_reset_hazard(&opts, &before_status);
	if (opts.collect_timing &&
	    ensure_timing_ready(cli_path, &before_status, opts.verbose)) {
		rc = 1;
		goto out;
	}
	if (opts.collect_timing && timing_start(cli_path, opts.verbose)) {
		fprintf(stderr, "failed to start daemon decision timing\n");
		rc = 1;
		goto out;
	} else if (opts.collect_status && !cli_available)
		fprintf(stderr, "fapolicyd-cli not found; daemon metrics disabled\n");

	if (install_signal_handlers(shared)) {
		fprintf(stderr, "failed to install signal handlers\n");
		rc = 1;
		goto out;
	}

	print_run_header(&opts, leaves, &paths);
	start_ns = monotonic_ns();
	if (run_stress_tree(&opts, &paths, shared)) {
		fprintf(stderr, "failed to start stress tree\n");
		rc = 1;
	}
	end_ns = monotonic_ns();

	if (opts.collect_timing && cli_available)
		timing_stop(cli_path, &timing, opts.verbose);
	if (opts.collect_status && cli_available)
		collect_status(cli_path, &after_status, opts.verbose);

	print_run_summary(shared, end_ns - start_ns);
	if (opts.collect_status)
		print_status_summary(&before_status, &after_status);
	if (opts.collect_timing)
		print_timing_summary(&timing);

	if (shared->errors)
		rc = 1;

out:
	munmap(shared, sizeof(*shared));
	cleanup_paths(&opts, &paths);
	return rc;
}
