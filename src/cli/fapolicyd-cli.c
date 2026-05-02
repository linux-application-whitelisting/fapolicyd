/*
 * fapolicy-cli.c - CLI tool for fapolicyd
 * Copyright (c) 2019-2022 Red Hat Inc.
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
 *   Radovan Sroka <rsroka@redhat.com>
 *   Steve Grubb <sgrubb@redhat.com>
 *   Zoltan Fridrich <zfridric@redhat.com>
 */

#include "config.h"
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#include <magic.h>
#include <stdbool.h>
#include <stdlib.h>
#include <getopt.h>
#include <stdatomic.h>
#include <lmdb.h>
#include <limits.h>
#include <signal.h>
#include <ftw.h>
#include <libgen.h>	// basename
#include "policy.h"
#include "rules.h"
#include "database.h"
#include "file-cli.h"
#include "file.h"
#include "fapolicyd-backend.h"
#include "string-util.h"
#include "daemon-config.h"
#include "message.h"
#include "llist.h"
#include "avl.h"
#include "fd-fgets.h"
#include "paths.h"
#include "filter.h"
#include "file.h"
#include "ignore-mounts.h"
#include "rule-lint.h"

bool verbose = false;
static bool lint_rules = false;
static bool assume_yes = false;

static const char *usage =
"Fapolicyd CLI Tool\n\n"
"--check-config        Check the daemon config for syntax errors\n"
"--check-path          Check files in $PATH against the trustdb for problems\n"
"--check-status        Dump the deamon's internal performance statistics\n"
"--check-trustdb       Check the trustdb against files on disk for problems\n"
"--check-watch_fs      Check watch_fs against currently mounted file systems\n"
"--check-ignore_mounts [path] Scan ignored mounts for executable content\n"
"--check-rules [path]  Validate rules file syntax without loading\n"
"--lint                Enable policy lint warnings with --check-rules\n"
"--reset-metrics       Dump status and reset metrics when daemon allows it\n"
"--timing-start        Start a manual decision timing run\n"
"--timing-stop         Stop manual decision timing and dump timing report\n"
"--verbose             Enable verbose output for select commands\n"
"-d, --delete-db       Delete the trust database\n"
"-D, --dump-db         Dump the trust database contents\n"
"-f, --file cmd path   Manage the file trust database\n"
"-h, --help            Prints this help message\n"
"-t, --ftype file-path Prints out the mime type of a file\n"
"-l, --list            Prints a list of the daemon's rules with numbers\n"
"-r, --reload-rules    Notifies fapolicyd to perform reload of rules\n"
"-y, --yes             Do not prompt before a manual metrics reset\n"
#ifdef HAVE_LIBRPM
"--test-filter path    Test FILTER_FILE against path and trace to stdout\n"
#endif
"--filter              Use FILTER_FILE for --file add or update\n"
"--trust-file file     Use after --file to specify trust file\n"
"-u, --update          Notifies fapolicyd to perform update of database\n"
;

static struct option long_opts[] =
{
	{"check-config",0, NULL,  1 },
	{"check-watch_fs",0, NULL, 2 },
	{"check-ignore_mounts", 2, NULL, 7 },
	{"verbose",     0, NULL, 8 },
	{"check-trustdb",0, NULL,  3 },
	{"check-status",0, NULL,  4 },
	{"check-path",  0, NULL,  5 },
	{"check-rules",  2, NULL, 9 },
	{"lint",	0, NULL, 10 },
	{"reset-metrics", 0, NULL, 11 },
	{"timing-start",	0, NULL, 12 },
	{"timing-stop",	0, NULL, 13 },
	{"yes",		0, NULL, 'y'},
	{"delete-db",	0, NULL, 'd'},
	{"dump-db",	0, NULL, 'D'},
	{"file",	1, NULL, 'f'},
	{"help",	0, NULL, 'h'},
	{"ftype",	1, NULL, 't'},
	{"list",	0, NULL, 'l'},
	{"update",	0, NULL, 'u'},
	{"reload-rules",	0, NULL, 'r'},
#ifdef HAVE_LIBRPM
	{"test-filter", 1, NULL, 6 },
#endif
	{ NULL,		0, NULL, 0 }
};

atomic_bool stop = 0;  // Library needs this
unsigned int debug_mode = 0;			// Library needs this
conf_t config;				// Library needs this

static void reset_config(void)
{
	free_daemon_config(&config);
	memset(&config, 0, sizeof(config));
}

typedef enum _reload_code { DB, RULES} reload_code;

static char *get_line(FILE *f)
{
	char *line = NULL;
	size_t len = 0;

	if (getline(&line, &len, f) != -1) {
		/* remove newline */
		char *ptr = strchr(line, 0x0a);
		if (ptr)
			*ptr = 0;
		return line;
	}
	free(line);
	return NULL;
}


static int do_delete_db(void)
{
	if (unlink_db())
		return CLI_EXIT_DB_ERROR;
	return CLI_EXIT_SUCCESS;
}


// This function opens the trust db and iterates over the entries.
// It returns CLI_EXIT_SUCCESS on success and CLI_EXIT_DB_ERROR on failure
static int verify_file(const char *path, off_t size, const char *sha,
		        unsigned int tsource);
static int do_dump_db(void)
{
	int rc, exit_rc = CLI_EXIT_SUCCESS;
	MDB_env *env;
	MDB_txn *txn;
	MDB_dbi dbi;
	MDB_stat status;
	MDB_cursor *cursor;
	MDB_val key, val;

	rc = mdb_env_create(&env);
	if (rc) {
		fprintf(stderr, "mdb_env_create failed, error %d %s\n", rc,
							mdb_strerror(rc));
		return CLI_EXIT_DB_ERROR;
	}
	mdb_env_set_maxdbs(env, 2);
	rc = mdb_env_open(env, DB_DIR, MDB_RDONLY|MDB_NOLOCK, 0660);
	if (rc) {
		fprintf(stderr, "mdb_env_open failed, error %d %s\n", rc,
							mdb_strerror(rc));
		exit_rc = CLI_EXIT_DB_ERROR;
		goto env_close;
	}
	rc = mdb_env_stat(env, &status);
	if (rc) {
		fprintf(stderr, "mdb_env_stat failed, error %d %s\n", rc,
							mdb_strerror(rc));
		exit_rc = CLI_EXIT_DB_ERROR;
		goto env_close;
	}
	if (status.ms_entries == 0) {
		printf("Trust database is empty\n");
		goto env_close; // Note: rc is 0 to get here
	}
	rc = mdb_txn_begin(env, NULL, MDB_RDONLY, &txn);
	if (rc) {
		fprintf(stderr, "mdb_txn_begin failed, error %d %s\n", rc,
							mdb_strerror(rc));
		exit_rc = CLI_EXIT_DB_ERROR;
		goto env_close;
	}
	rc = mdb_dbi_open(txn, DB_NAME, MDB_DUPSORT, &dbi);
	if (rc) {
		fprintf(stderr, "mdb_open failed, error %d %s\n", rc,
							mdb_strerror(rc));
		exit_rc = CLI_EXIT_DB_ERROR;
		goto txn_abort;
	}
	rc = mdb_cursor_open(txn, dbi, &cursor);
	if (rc) {
		fprintf(stderr, "mdb_cursor_open failed, error %d %s\n", rc,
							mdb_strerror(rc));
		exit_rc = CLI_EXIT_DB_ERROR;
		goto txn_abort;
	}
	rc = mdb_cursor_get(cursor, &key, &val, MDB_FIRST);
	if (rc) {
		fprintf(stderr, "mdb_cursor_get failed, error %d %s\n", rc,
							mdb_strerror(rc));
		exit_rc = CLI_EXIT_DB_ERROR;
		goto txn_abort;
	}
	do {
		char *path = NULL, *data = NULL, sha[FILE_DIGEST_STRING_MAX];
		unsigned int tsource;
		size_t size;
		const char *source;

		path = malloc(key.mv_size + 1);
		if (!path)
			goto next_record;

		memcpy(path, key.mv_data, key.mv_size);
		path[key.mv_size] = 0;
		data = malloc(val.mv_size + 1);

		if (!data)
			goto next_record;

		memcpy(data, val.mv_data, val.mv_size);
		data[val.mv_size] = 0;

		if (sscanf(data, DATA_FORMAT_IN, &tsource, &size, sha) != 3)
			goto next_record;

		source = lookup_tsource(tsource);
		printf("%s %s %zu %s\n", source, path, size, sha);

next_record:
		free(data);
		free(path);
		// Try to get the duplicate. If it doesn't exist, get the next one
		rc = mdb_cursor_get(cursor, &key, &val, MDB_NEXT_DUP);
		if (rc == MDB_NOTFOUND)
			rc = mdb_cursor_get(cursor, &key, &val, MDB_NEXT_NODUP);
	} while (rc == 0);

	if (rc != MDB_NOTFOUND)
		exit_rc = CLI_EXIT_DB_ERROR;
	mdb_cursor_close(cursor);
	mdb_close(env, dbi);
txn_abort:
	mdb_txn_abort(txn);
env_close:
	mdb_env_close(env);

	return exit_rc;
}

static int parse_file_args(int argc, char * const argv[],
			    const char **path, const char **trust_file,
			    bool *use_filter, bool path_optional)
{
	*path = NULL;
	*trust_file = NULL;
	*use_filter = false;

	for (int i = 0; i < argc; i++) {
		if (!strcmp(argv[i], "--filter")) {
			if (*use_filter)
				return CLI_EXIT_USAGE;
			*use_filter = true;
			continue;
		}
		if (!strcmp(argv[i], "--trust-file")) {
			if (*trust_file || i + 1 >= argc)
				return CLI_EXIT_USAGE;
			*trust_file = argv[++i];
			continue;
		}
		if (*path == NULL) {
			*path = argv[i];
			continue;
		}
		return CLI_EXIT_USAGE;
	}

	if (!path_optional && *path == NULL)
		return CLI_EXIT_USAGE;

	return CLI_EXIT_SUCCESS;
}

static int do_file_add(int argc, char * const argv[])
{
	char full_path[PATH_MAX] = { 0 };
	const char *path = NULL;
	const char *trust_file = NULL;
	bool use_filter = false;

	int rc = parse_file_args(argc, argv, &path, &trust_file,
				 &use_filter, false);
	if (rc)
		return rc;

	if (!realpath(path, full_path))
		return CLI_EXIT_PATH_CONFIG;

	return file_append(full_path, trust_file, use_filter);
}

static int do_file_delete(int argc, char * const argv[])
{
	char full_path[PATH_MAX] = { 0 };

	if (argc == 1) {
		if (!realpath(argv[0], full_path))
			return CLI_EXIT_PATH_CONFIG;
		return file_delete(full_path, NULL);
	}
	if (argc == 3) {
		if (!realpath(argv[0], full_path))
			return CLI_EXIT_PATH_CONFIG;
		if (strcmp("--trust-file", argv[1]))
			return CLI_EXIT_USAGE;
		return file_delete(full_path, argv[2]);
	}
	return CLI_EXIT_USAGE;
}

static int do_file_update(int argc, char * const argv[])
{
	char full_path[PATH_MAX] = { 0 };
	const char *path = NULL;
	const char *trust_file = NULL;
	bool use_filter = false;

	int rc = parse_file_args(argc, argv, &path, &trust_file,
				 &use_filter, true);
	if (rc)
		return rc;

	if (path) {
		if (!realpath(path, full_path))
			return CLI_EXIT_PATH_CONFIG;
		path = full_path;
	} else {
		path = "/";
	}

	return file_update(path, trust_file, use_filter);
}

static int do_manage_files(int argc, char * const argv[])
{
	int rc = CLI_EXIT_SUCCESS;

	if (argc < 1 || argc > 5) {
		fprintf(stderr, "Wrong number of arguments\n");
		fprintf(stderr, "\n%s", usage);
		return CLI_EXIT_USAGE;
	}

	if (!strcmp("add", argv[0]))
		rc = do_file_add(argc - 1, argv + 1);
	else if (!strcmp("delete", argv[0]))
		rc = do_file_delete(argc - 1, argv + 1);
	else if (!strcmp("update", argv[0]))
		rc = do_file_update(argc - 1, argv + 1);
	else {
		fprintf(stderr, "%s is not a valid option, choose one of add|delete|update\n", argv[0]);
		fprintf(stderr, "\n%s", usage);
		return CLI_EXIT_USAGE;
	}

	switch (rc) {
	case CLI_EXIT_SUCCESS: // no error
		return CLI_EXIT_SUCCESS;
	case CLI_EXIT_USAGE: // args error
		fprintf(stderr, "Wrong number of arguments\n");
                fprintf(stderr, "\n%s", usage);
                return rc;
	case CLI_EXIT_PATH_CONFIG: // realpath error
		fprintf(stderr, "Can't obtain realpath from: %s\n", argv[1]);
		fprintf(stderr, "\n%s", usage);
		return rc;
	default: // file function errors
		break;
	}
	return rc;
}


static int do_ftype(const char *path)
{
	int fd;
	const char *ptr = NULL;
	char buf[80];
	struct stat sb;
	struct file_info i;

	// We need to open in non-blocking mode because if its a
	// fifo, it will hang the program.
	fd = open(path, O_RDONLY|O_NONBLOCK);
	if (fd < 0) {
		fprintf(stderr, "Cannot open %s - %s\n", path, strerror(errno));
		return CLI_EXIT_IO;
	}
	if (fstat(fd, &sb) != 0) {
		fprintf(stderr, "Cannot stat %s - %s\n", path, strerror(errno));
		close(fd);
		return CLI_EXIT_IO;
	}

	// Setup file info with bare essentials
	i.device = sb.st_dev;
	i.mode = sb.st_mode;
	i.size = sb.st_size;

	if (file_init()) {
		fprintf(stderr, "Cannot initialize file helper libraries\n");
		close(fd);
		return CLI_EXIT_INTERNAL;
	}
	ptr = get_file_type_from_fd(fd, &i, path, sizeof(buf), buf);
	file_close();
	close(fd);

	if (ptr)
		printf("%s\n", ptr);
	else
		printf("unknown\n");

	return CLI_EXIT_SUCCESS;
}

static int do_list(void)
{
	unsigned count = 1;
	FILE *f = fopen(OLD_RULES_FILE, "rm");
	char *buf;

	if (f == NULL) {
		f = fopen(RULES_FILE, "rm");
		if (f == NULL) {
			fprintf(stderr, "Cannot open rules file (%s)\n",
						strerror(errno));
			return CLI_EXIT_IO;
		}
	} else {
		FILE *t = fopen(RULES_FILE, "rm");
		if (t) {
			fclose(t);
			fclose(f);
			fprintf(stderr,
				"Error - old and new rules file detected. "
				"Delete one or the other.\n");
			return CLI_EXIT_PATH_CONFIG;
		}
	}

	while ((buf = get_line(f))) {
		char *str = buf;
		while (*str) {
			if (!isblank(*str))
				break;
			str++;
		}
		if (*str == 0) // blank line
			goto next_iteration;
		if (*str == '#') //comment line
			goto next_iteration;
		if (*str == '%') {
			printf("-> %s\n", buf);
			goto next_iteration;
		}

		printf("%u. %s\n", count, buf);
		count++;
next_iteration:
		free(buf);
	}
	fclose(f);
	return CLI_EXIT_SUCCESS;
}


static int do_reload(int code)
{
	int fd = -1;
	struct stat s;

	fd = open(fifo_path, O_WRONLY);
	if (fd == -1) {
		fprintf(stderr, "Open: %s -> %s\n", fifo_path, strerror(errno));
		return CLI_EXIT_DAEMON_IPC;
	}

	if (fstat(fd, &s) == -1) {
		fprintf(stderr, "Stat: %s -> %s\n", fifo_path, strerror(errno));
		close(fd);
		return CLI_EXIT_DAEMON_IPC;
	} else {
		if (!S_ISFIFO(s.st_mode)) {
			fprintf(stderr,
				"File: %s exists but it is not a pipe!\n",
				fifo_path);
			close(fd);
			return CLI_EXIT_DAEMON_IPC;
		}
		// we will require pipe to have 0660 permissions
		mode_t mode = s.st_mode & ~S_IFMT;
		if (mode != 0660) {
			fprintf(stderr,
				"File: %s has 0%o instead of 0660 \n",
				fifo_path,
				mode);
			close(fd);
			return CLI_EXIT_DAEMON_IPC;
		}
	}

	ssize_t ret = 0;
	char str[32] = {0};

	if (code == DB) {
		snprintf(str, 32, "%c\n", RELOAD_TRUSTDB_COMMAND);
		ret = write(fd, "1\n", strlen(str));
	} else if (code == RULES) {
		snprintf(str, 32, "%c\n", RELOAD_RULES_COMMAND);
		ret = write(fd, "3\n", strlen(str));
	}

	if (ret == -1) {
		fprintf(stderr,"Write: %s -> %s\n", fifo_path, strerror(errno));
		close(fd);
		return CLI_EXIT_DAEMON_IPC;
	}

	if (close(fd)) {
		fprintf(stderr,"Close: %s -> %s\n", fifo_path, strerror(errno));
		return CLI_EXIT_DAEMON_IPC;
	}

	printf("Fapolicyd was notified\n");
	return CLI_EXIT_SUCCESS;
}

static const char *bad_filesystems[] = {
	"autofs",
	"bdev",
	"binder",
	"binfmt_misc",
	"bpf",
	"cgroup",
	"cgroup2",
	"configfs",
	"cpuset",
	"debugfs",
	"devpts",
	"devtmpfs",
	"efivarfs",
	"fusectl",
	"fuse.gvfsd-fuse",
	"fuse.portal",
	"hugetlbfs",
	"mqueue",
	"nsfs",
	"overlay", // No source of trust for what's in this
	"pipefs",
	"proc",
	"pstore",
	"resctrl",
	"rpc_pipefs",
	"securityfs",
	"selinuxfs",
	"sockfs",
	"sysfs",
	"tracefs"
};
#define FS_NAMES (sizeof(bad_filesystems)/sizeof(bad_filesystems[0]))

// Returns 1 if not a real file system and 0 if its a file system we can watch
static int not_watchable(const char *type)
{
	unsigned int i;

	for (i = 0; i < FS_NAMES; i++)
		if (strcmp(bad_filesystems[i], type) == 0)
			return 1;

	return 0;
}

// Returns CLI_EXIT_SUCCESS on success or other CLI_EXIT_* codes on failure.
// Finding unwatched file systems is not considered an error
static int check_watch_fs(void)
{
	char buf[PATH_MAX * 2], device[1025], point[4097];
	char type[32], mntops[128];
	int fs_req, fs_passno, fd, found = 0, alloc_err = 0;
	list_t fs, mnt;
	char *ptr, *saved, *tmp;

	set_message_mode(MSG_STDERR, DBG_YES);
	reset_config();
	if (load_daemon_config(&config)) {
		reset_config();
		return CLI_EXIT_PATH_CONFIG;
	}
	if (config.watch_fs == NULL) {
		fprintf(stderr, "File systems to watch is empty");
		reset_config();
		return CLI_EXIT_PATH_CONFIG;
	}
	tmp = strdup(config.watch_fs);
	if (tmp == NULL) {
		reset_config();
		return CLI_EXIT_INTERNAL;
	}

	list_init(&fs);
	ptr = strtok_r(tmp, ",", &saved);
	while (ptr) {
		char *index = strdup(ptr);
		char *data = strdup("0");
		if (!index || !data || list_append(&fs, index, data)) {
			free(index);
			free(data);
			alloc_err = 1;
		}
		ptr = strtok_r(NULL, ",", &saved);
	}
	free(tmp);

	fd = open("/proc/mounts", O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "Unable to open mounts\n");
		reset_config();
		list_empty(&fs);
		return CLI_EXIT_IO;
	}

	fd_fgets_state_t *st = fd_fgets_init();
	if (!st) {
		fprintf(stderr, "Failed fd_fgets_init\n");
		reset_config();
		list_empty(&fs);
		close(fd);
		return CLI_EXIT_INTERNAL;
	}

	// Build the list of mount point types
	list_init(&mnt);
	do {
		if (fd_fgets_r(st, buf, sizeof(buf), fd)) {
			sscanf(buf, "%1024s %4096s %31s %127s %d %d\n",
			       device,point, type, mntops, &fs_req, &fs_passno);
			// Some file systems are not watchable
			if (not_watchable(type))
				continue;
			char *index = strdup(type);
			char *data = strdup("0");
			if (!index || !data || list_append(&mnt, index, data)) {
				free(index);
				free(data);
				alloc_err = 1;
			}
		}
	} while (!fd_fgets_eof_r(st));
	fd_fgets_destroy(st);
	close(fd);


	// Now search the list we just built
	for (list_item_t *lptr = mnt.first; lptr; ) {
		// See if the file system is watched
		if (list_contains(&fs, lptr->index) == 0) {
			found = 1;
			printf("%s not watched\n", (char *)lptr->index);

			// Remove the file system so that we get 1 report
			char *tmpfs = strdup(lptr->index);
			while (list_remove(&mnt, tmpfs))
                                ;
			free(tmpfs);

			// Start from the beginning
			lptr = mnt.first;
			continue;
		}
		lptr = lptr->next;
	}

	reset_config();
	list_empty(&fs);
	list_empty(&mnt);
	if (found == 0)
		printf("Nothing appears missing\n");

	if (alloc_err)
		return CLI_EXIT_INTERNAL;
	return CLI_EXIT_SUCCESS;
}

// Returns 0 = everything is OK, 1 = there is a problem
static int verify_file(const char *path, off_t size, const char *sha,
		        unsigned int tsource)
{
	int fd, warn_sha = 0;
	struct stat sb;
	file_hash_alg_t alg;
	size_t digest_len, expected_len;
	const char *alg_name;

	digest_len = strlen(sha);
	alg = file_hash_alg(digest_len);
	expected_len = file_hash_length(alg) * 2;

	/*
	 * Non-RPM trust fragments historically used SHA256, but newer stores
	 * may contain longer digests (for example SHA512).  Fall back to
	 * SHA256 only when the digest length cannot be mapped to a known
	 * algorithm so legacy entries keep working.
	 */
	if (expected_len == 0)
		expected_len = file_hash_length(FILE_HASH_ALG_SHA256) * 2;
	if (alg == FILE_HASH_ALG_NONE)
		alg = FILE_HASH_ALG_SHA256;

	if (digest_len != expected_len) {
		printf("%s miscompares: cannot infer digest algorithm\n", path);
		return 1;
	}

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		printf("Can't open %s (%s)\n", path, strerror(errno));
		return 1;
	}
	if (fstat(fd, &sb)) {
		printf("Can't stat %s (%s)\n", path, strerror(errno));
		close(fd);
		return 1;
	}
	if (sb.st_size != size) {
		printf("%s miscompares: file size\n", path);
		close(fd);
		return 1;
	}

	char *sha_buf = get_hash_from_fd2(fd, sb.st_size, alg);
	close(fd);

	if (sha_buf == NULL || strcmp(sha, sha_buf))
		warn_sha = 1;
	free(sha_buf);

	if (warn_sha) {
		alg_name = file_hash_alg_name(alg);
		printf("%s miscompares: %s\n", path,
		       alg_name ? alg_name : "digest");
		return 1;
	}
	return 0;
}

static int check_trustdb(void)
{
	int found = 0;

	set_message_mode(MSG_STDERR, DBG_NO);
	reset_config();
	if (load_daemon_config(&config)) {
		reset_config();
		return CLI_EXIT_PATH_CONFIG;
	}
	set_message_mode(MSG_QUIET, DBG_NO);
	int rc = walk_database_start(&config);
	reset_config();
	if (rc)
		return CLI_EXIT_DB_ERROR;

	do {
		unsigned int tsource;
		off_t size;
		char sha[FILE_DIGEST_STRING_MAX];
		char path[448];
		char data[TRUSTDB_DATA_BUFSZ];

		// Get the entry and format it for use.
		walkdb_entry_t *entry = walk_database_get_entry();
		snprintf(path, sizeof(path), "%.*s", (int) entry->path.mv_size,
			(char *) entry->path.mv_data);
		snprintf(data, sizeof(data), "%.*s", (int) entry->data.mv_size,
			(char *) entry->data.mv_data);
		if (sscanf(data, DATA_FORMAT_IN, &tsource, &size, sha) != 3) {
			fprintf(stderr, "%s data entry is corrupted\n", path);
			continue;
		}
		if (verify_file(path, size, sha, tsource))
			found = 1;
	} while (walk_database_next());

	walk_database_finish();

	if (found == 0)
		puts("No problems found");

	return CLI_EXIT_SUCCESS;
}

static int is_link(const char *path)
{
	struct stat sb;

	if (lstat(path, &sb)) {
		fprintf(stderr, "Can't stat %s\n", path);
		return -1;
	}
	if (S_ISLNK(sb.st_mode))
		return 1;

	return 0;
}

// Check that the file is in the trust db
static int path_found = 0;
static int check_file(const char *fpath,
		const struct stat *sb,
		int typeflag_unused __attribute__ ((unused)),
		struct FTW *s_unused __attribute__ ((unused)))
{
	int ret = FTW_CONTINUE;

	if (S_ISREG(sb->st_mode) == 0)
		return ret;

	int fd = open(fpath, O_RDONLY|O_CLOEXEC);
	if (fd >= 0) {
		struct file_info info;
		info.size = sb->st_size;

		if (check_trust_database(fpath, &info, fd) != 1) {
			path_found = 1;
			fprintf(stderr, "%s is not trusted\n", fpath);
		}

		close(fd);
	}
	return ret;
}

static int check_path(void)
{
	char *ptr, *saved;
	const char *env_path = getenv("PATH");
	if (env_path == NULL) {
		puts("PATH not found");
		return CLI_EXIT_PATH_CONFIG;
	}

	set_message_mode(MSG_STDERR, DBG_NO);
	reset_config();
	if (load_daemon_config(&config)) {
		reset_config();
		return CLI_EXIT_PATH_CONFIG;
	}
	set_message_mode(MSG_QUIET, DBG_NO);
	init_database(&config);
	char *path = strdup(env_path);
	ptr = strtok_r(path, ":", &saved);
	while (ptr) {
		if (is_link(ptr))
			goto next;

		nftw(ptr, check_file, 1024, FTW_PHYS);
next:
		ptr = strtok_r(NULL, ":", &saved);
	}
	stop = 1; // Need this to terminate update thread
	free(path);
	close_database();
	reset_config();

	if (path_found == 0)
		puts("No problems found");

	return CLI_EXIT_SUCCESS;
}

/*
 * confirm_metric_reset - ask before sending a SIGUSR1 reset intent.
 * Returns 1 when the caller confirms, 0 otherwise.
 */
static int confirm_metric_reset(void)
{
	char answer[8];

	fprintf(stderr,
		"Request runtime metrics reset with this state report? [y/N] ");
	fflush(stderr);
	if (fgets(answer, sizeof(answer), stdin) == NULL)
		return 0;

	return answer[0] == 'y' || answer[0] == 'Y';
}

/*
 * check_metric_reset_strategy - verify reset intent against on-disk config.
 * @reset_metrics: reset intent flag to clear when manual reset is unlikely.
 * Returns nothing.
 */
static void check_metric_reset_strategy(int *reset_metrics)
{
	conf_t disk_config;
	const char *strategy;

	if (!*reset_metrics)
		return;

	memset(&disk_config, 0, sizeof(disk_config));
	set_message_mode(MSG_STDERR, DBG_NO);
	if (load_daemon_config(&disk_config)) {
		fprintf(stderr,
			"Unable to verify reset_strategy in %s; sending a "
			"plain --check-status request.\n", CONFIG_FILE);
		fprintf(stderr,
			"The daemon's active setting may differ from the "
			"on-disk configuration.\n");
		*reset_metrics = 0;
		free_daemon_config(&disk_config);
		set_message_mode(MSG_QUIET, DBG_NO);
		return;
	}
	strategy = lookup_reset_strategy(disk_config.reset_strategy);

	if (disk_config.reset_strategy != RESET_MANUAL) {
		fprintf(stderr,
			"On-disk reset_strategy is %s, not manual; "
			"--reset-metrics appears unable to reset metrics.\n",
			strategy ? strategy : "unknown");
		fprintf(stderr,
			"Sending a plain --check-status request. The daemon's "
			"active setting may differ until config is reloaded.\n");
		*reset_metrics = 0;
	}

	free_daemon_config(&disk_config);
	set_message_mode(MSG_QUIET, DBG_NO);
}

/*
 * send_state_report_signal - request a state report from fapolicyd.
 * @pid: daemon PID to signal.
 * @reset_metrics: non-zero adds reset intent to the signal.
 * @reason: error text buffer.
 * @reason_len: size of @reason.
 * Returns 0 on success, non-zero on failure.
 */
static int send_state_report_signal(unsigned int pid, int reset_metrics,
		char *reason, size_t reason_len)
{
	union sigval value;

	value.sival_int = reset_metrics ? REPORT_INTENT_RESET_METRICS :
					  REPORT_INTENT_STATUS;
	if (sigqueue(pid, SIGUSR1, value)) {
		snprintf(reason, reason_len, "signal failed: %s",
			 strerror(errno));
		return 1;
	}
	return 0;
}

/*
 * send_timing_signal - send a SIGUSR1 timing intent to fapolicyd.
 * @pid: daemon PID to signal.
 * @intent: timing intent to send.
 * @reason: error text buffer.
 * @reason_len: size of @reason.
 * Returns 0 on success, non-zero on failure.
 */
static int send_timing_signal(unsigned int pid, report_intent_t intent,
		char *reason, size_t reason_len)
{
	union sigval value;

	value.sival_int = intent;
	if (sigqueue(pid, SIGUSR1, value)) {
		snprintf(reason, reason_len, "signal failed: %s",
			 strerror(errno));
		return 1;
	}
	return 0;
}

/*
 * get_daemon_pid - read and validate the fapolicyd pid file.
 * @pid: output pid on success.
 * @reason: error text buffer.
 * @reason_len: size of @reason.
 * Returns 0 on success, non-zero on failure.
 */
static int get_daemon_pid(unsigned int *pid, char *reason, size_t reason_len)
{
	fd_fgets_state_t *st;
	int pidfd;

	st = fd_fgets_init();
	if (!st) {
		snprintf(reason, reason_len, "internal allocation failure");
		return 1;
	}

	pidfd = open(pidfile, O_RDONLY);
	if (pidfd >= 0) {
		char pid_buf[16];

		if (fd_fgets_r(st, pid_buf, sizeof(pid_buf), pidfd)) {
			char exe_buf[64];

			errno = 0;
			*pid = strtoul(pid_buf, NULL, 10);
			if (errno) {
				snprintf(reason, reason_len,
					 "bad pid in pid file");
				goto err_out;
			}
			if (get_program_from_pid(*pid, sizeof(exe_buf),
					exe_buf) == NULL) {
				snprintf(reason, reason_len,
					 "can't read proc file");
				goto err_out;
			}
			if (strcmp(basename(exe_buf), "fapolicyd")) {
				snprintf(reason, reason_len,
					 "pid file doesn't point to fapolicyd");
				goto err_out;
			}
			close(pidfd);
			fd_fgets_destroy(st);
			return 0;
		}
		snprintf(reason, reason_len, "unreadable pid file");
	} else
		snprintf(reason, reason_len, "no pid file");

err_out:
	if (pidfd >= 0)
		close(pidfd);
	fd_fgets_destroy(st);
	return 1;
}

/*
 * display_report_file - wait for a daemon report and write it to stdout.
 * @path: report path to read.
 * @reason: output error reason on failure.
 * Returns 0 on success, non-zero on timeout or I/O failure.
 */
static int display_report_file(const char *path, const char **reason)
{
	fd_fgets_state_t *st;
	unsigned int tries = 0;
	int rpt_fd;

	st = fd_fgets_init();
	if (!st) {
		*reason = "internal allocation failure";
		return 1;
	}

retry:
	sleep(1);

	rpt_fd = open(path, O_RDONLY);
	if (rpt_fd < 0) {
		if (tries < 25) {
			tries++;
			goto retry;
		}
		*reason = "timed out waiting for report";
		fd_fgets_destroy(st);
		return 1;
	}

	fd_fgets_clear_r(st);
	do {
		char buf[80];

		if (fd_fgets_r(st, buf, sizeof(buf), rpt_fd))
			write(1, buf, strlen(buf));
	} while (!fd_fgets_eof_r(st));

	close(rpt_fd);
	fd_fgets_destroy(st);
	return 0;
}

/*
 * do_timing_control - request a manual decision timing control action.
 * @intent: timing intent to send.
 * Returns a CLI_EXIT_* value.
 */
static int do_timing_control(report_intent_t intent)
{
	const char *reason;
	unsigned int pid;
	char signal_reason[80];

	if (get_daemon_pid(&pid, signal_reason, sizeof(signal_reason))) {
		printf("Can't find fapolicyd: %s\n", signal_reason);
		return CLI_EXIT_DAEMON_IPC;
	}

	if (intent == REPORT_INTENT_TIMING_STOP)
		unlink(TIMING_REPORT);

	if (send_timing_signal(pid, intent, signal_reason,
			       sizeof(signal_reason))) {
		printf("Can't signal fapolicyd: %s\n", signal_reason);
		return CLI_EXIT_DAEMON_IPC;
	}

	if (intent == REPORT_INTENT_TIMING_ARM)
		printf("Decision timing start requested\n");
	else if (display_report_file(TIMING_REPORT, &reason)) {
		printf("Can't read decision timing report: %s\n", reason);
		return CLI_EXIT_DAEMON_IPC;
	}

	return CLI_EXIT_SUCCESS;
}

/*
 * do_status_report - request and display a daemon state report.
 * @reset_metrics: non-zero when the user requested --reset-metrics.
 * Returns a CLI_EXIT_* value.
 */
static int do_status_report(int reset_metrics)
{
	const char *reason = "no pid file";
	char signal_reason[80];

	fd_fgets_state_t *st = fd_fgets_init();
	if (!st)
		return CLI_EXIT_INTERNAL;

	// open pid file
	int pidfd = open(pidfile, O_RDONLY);
	if (pidfd >= 0) {
		char pid_buf[16];

		// read contents
		if (fd_fgets_r(st, pid_buf, sizeof(pid_buf), pidfd)) {
			int rpt_fd;
			unsigned int pid, tries = 0;
			char exe_buf[64];

			// convert to integer
			errno = 0;
			pid = strtoul(pid_buf, NULL, 10);
			if (errno) {
				reason = "bad pid in pid file";
				goto err_out;
			}

			// verify it really is fapolicyd
			if (get_program_from_pid(pid,
					sizeof(exe_buf), exe_buf) == NULL) {
				reason = "can't read proc file";
				goto err_out;
			}
			if (strcmp(basename(exe_buf), "fapolicyd")) {
				reason = "pid file doesn't point to fapolicyd";
				goto err_out;
			}

			check_metric_reset_strategy(&reset_metrics);
			if (reset_metrics && !assume_yes &&
			    !confirm_metric_reset()) {
				close(pidfd);
				fd_fgets_destroy(st);
				return CLI_EXIT_NOOP;
			}

			// delete the old report
			unlink(STAT_REPORT);

			// send the signal for the report
			if (send_state_report_signal(pid, reset_metrics,
						     signal_reason,
						     sizeof(signal_reason))) {
				reason = signal_reason;
				goto err_out;
			}

			// Access a file to provoke a response
			int fd = open(CONFIG_FILE, O_RDONLY);
			if (fd >= 0)
				close(fd);

retry:
			// wait for it
			sleep(1);

			// display the report
			rpt_fd = open(STAT_REPORT, O_RDONLY);
			if (rpt_fd < 0) {
				if (tries < 25) {
					tries++;
					goto retry;
				} else {
					reason = "timed out waiting for report";
					goto err_out;
				}
			}
			fd_fgets_clear_r(st);
			do {
				char buf[80];
				if (fd_fgets_r(st, buf, sizeof(buf), rpt_fd))
					write(1, buf, strlen(buf));
			} while (!fd_fgets_eof_r(st));
			close(rpt_fd);
		}
		close(pidfd);
		fd_fgets_destroy(st);
		return CLI_EXIT_SUCCESS;
	}
err_out:
	fd_fgets_destroy(st);
	if (pidfd >= 0)
		close(pidfd);
	printf("Can't find fapolicyd: %s\n", reason);
	return CLI_EXIT_DAEMON_IPC;
}

#ifdef HAVE_LIBRPM
static int do_test_filter(const char *path)
{
	set_message_mode(MSG_STDERR, DBG_NO);
	filter_set_trace(stdout);

	if (filter_init()) {
		fprintf(stderr, "filter_init failed\n");
		return CLI_EXIT_RULE_FILTER;
	}
	if (filter_load_file(FILTER_FILE)) {
		filter_destroy();
		fprintf(stderr, "filter_load_file failed\n");
		return CLI_EXIT_RULE_FILTER;
	}
	filter_check(path);
	filter_destroy();
	return CLI_EXIT_SUCCESS;
}
#endif

int main(int argc, char * const argv[])
{
	int opt, option_index, rc = CLI_EXIT_GENERIC;
	int orig_argc = argc, arg_count = 0;
	char *args[orig_argc+1];

	for (int i = 0; i < orig_argc; i++) {
		if (strcmp(argv[i], "--verbose") == 0) {
			verbose = true;
			continue;
		}
		if (strcmp(argv[i], "--lint") == 0) {
			lint_rules = true;
			continue;
		}
		if (strcmp(argv[i], "--yes") == 0 ||
		    strcmp(argv[i], "-y") == 0) {
			assume_yes = true;
			continue;
		}
		args[arg_count++] = argv[i];
	}
	args[arg_count] = NULL;

	if (arg_count == 1) {
		fprintf(stderr, "Too few arguments\n\n");
		fprintf(stderr, "%s", usage);
		return CLI_EXIT_USAGE;
	}

	optind = 1;

	/* Run getopt_long on the sanitized copy so command parsing behaves
	 * exactly as before --verbose was introduced. */
	opt = getopt_long(arg_count, (char * const *)args, "Ddf:ht:lury",
				 long_opts, &option_index);

	if (assume_yes && opt != 11)
		goto args_err;

	switch (opt) {
	case 'd':
		if (lint_rules)
			goto args_err;
		if (arg_count > 2)
			goto args_err;
		rc = do_delete_db();
		break;
	case 'D':
		if (lint_rules)
			goto args_err;
		if (arg_count > 2)
			goto args_err;
		rc = do_dump_db();
		break;
	case 'f':
		if (lint_rules)
			goto args_err;
		if (arg_count > 7)
			goto args_err;
		// fapolicyd-cli, -f, | operation, path ...
		// skip the first two args
		rc = do_manage_files(arg_count-2, args+2);
		break;
	case 'h':
		if (lint_rules)
			goto args_err;
		printf("%s", usage);
		rc = CLI_EXIT_SUCCESS;
		break;
	case 't':
		if (lint_rules)
			goto args_err;
		if (arg_count > 3)
			goto args_err;
		rc = do_ftype(optarg);
		break;
	case 'l':
		if (lint_rules)
			goto args_err;
		if (arg_count > 2)
			goto args_err;
		rc = do_list();
		break;
	case 'u':
		if (lint_rules)
			goto args_err;
		if (arg_count > 2)
			goto args_err;
		rc = do_reload(DB);
		break;
	case 'r':
		if (lint_rules)
			goto args_err;
		if (arg_count > 2)
			goto args_err;
		rc = do_reload(RULES);
		break;

	// Now the pure long options
	case 1: { // --check-config

		if (lint_rules)
			goto args_err;
		if (arg_count > 2)
			goto args_err;
		set_message_mode(MSG_STDERR, DBG_YES);
		reset_config();
		if (load_daemon_config(&config)) {
			reset_config();
			fprintf(stderr, "Configuration errors reported\n");
			return CLI_EXIT_PATH_CONFIG;
		} else {
			printf("Daemon config is OK\n");
			reset_config();
			return CLI_EXIT_SUCCESS;
		} }
		break;
	case 2: // --check-watch_fs
		if (lint_rules)
			goto args_err;
		if (arg_count > 2)
			goto args_err;
		return check_watch_fs();
		break;
	case 3: // --check-trustdb
		if (lint_rules)
			goto args_err;
		if (arg_count > 2)
			goto args_err;
		return check_trustdb();
		break;
	case 4: // --check-status
		if (lint_rules)
			goto args_err;
		if (arg_count > 2)
			goto args_err;
		return do_status_report(0);
		break;
	case 5: // --check-path
		if (lint_rules)
			goto args_err;
		if (arg_count > 2)
			goto args_err;
		return check_path();
		break;

	case 7: { // --check-ignore_mounts
		const char *override = optarg;

		if (lint_rules)
			goto args_err;
		if (override == NULL && optind < arg_count &&
						args[optind][0] != '-')
			override = args[optind++];
		if (optind < arg_count)
			goto args_err;
		return check_ignore_mounts(override);
		}
		break;

	case 9: { // --check-rules
		const char *path = optarg;

		if (path == NULL && optind < arg_count &&
						args[optind][0] != '-')
			path = args[optind++];
		if (optind < arg_count)
			goto args_err;
		return check_rules_file(path, lint_rules);
		}
		break;

	case 10:
		goto args_err;

	case 11: // --reset-metrics
		if (lint_rules)
			goto args_err;
		if (arg_count > 2)
			goto args_err;
		return do_status_report(1);

	case 12: // --timing-start
		if (lint_rules)
			goto args_err;
		if (arg_count > 2)
			goto args_err;
		return do_timing_control(REPORT_INTENT_TIMING_ARM);

	case 13: // --timing-stop
		if (lint_rules)
			goto args_err;
		if (arg_count > 2)
			goto args_err;
		return do_timing_control(REPORT_INTENT_TIMING_STOP);

	case 'y':
		goto args_err;

#ifdef HAVE_LIBRPM
	case 6: { // --test-filter
		if (lint_rules)
			goto args_err;
		if (arg_count > 3)
			goto args_err;
		return do_test_filter(optarg);
		}
		break;
#endif
	default:
		printf("%s", usage);
		rc = CLI_EXIT_USAGE;
	}
	return rc;

args_err:
	fprintf(stderr, "Too many arguments\n\n");
	fprintf(stderr, "%s", usage);
	return CLI_EXIT_USAGE;
}
