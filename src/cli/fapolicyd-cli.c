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
#include <stdlib.h>
#include <getopt.h>
#include <stdatomic.h>
#include <lmdb.h>
#include <limits.h>
#include <signal.h>
#include <ftw.h>
#include "policy.h"
#include "database.h"
#include "file-cli.h"
#include "fapolicyd-backend.h"
#include "string-util.h"
#include "daemon-config.h"
#include "message.h"
#include "llist.h"
#include "fd-fgets.h"
#include "paths.h"

static const char *usage =
"Fapolicyd CLI Tool\n\n"
"--check-config        Check the daemon config for syntax errors\n"
"--check-path          Check files in $PATH against the trustdb for problems\n"
"--check-status        Dump the deamon's internal performance statistics\n"
"--check-trustdb       Check the trustdb against files on disk for problems\n"
"--check-watch_fs      Check watch_fs against currently mounted file systems\n"
"-d, --delete-db       Delete the trust database\n"
"-D, --dump-db         Dump the trust database contents\n"
"-f, --file cmd path   Manage the file trust database\n"
"--trust-file file     Use after --file to specify trust file\n"
"-h, --help            Prints this help message\n"
"-t, --ftype file-path Prints out the mime type of a file\n"
"-l, --list            Prints a list of the daemon's rules with numbers\n"
"-u, --update          Notifies fapolicyd to perform update of database\n"
"-r, --reload-rules    Notifies fapolicyd to perform reload of rules\n"
;

static struct option long_opts[] =
{
	{"check-config",0, NULL,  1 },
	{"check-watch_fs",0, NULL, 2 },
	{"check-trustdb",0, NULL,  3 },
	{"check-status",0, NULL,  4 },
	{"check-path",  0, NULL,  5 },
	{"delete-db",	0, NULL, 'd'},
	{"dump-db",	0, NULL, 'D'},
	{"file",	1, NULL, 'f'},
	{"help",	0, NULL, 'h'},
	{"ftype",	1, NULL, 't'},
	{"list",	0, NULL, 'l'},
	{"update",	0, NULL, 'u'},
	{"reload-rules",	0, NULL, 'r'},
	{ NULL,		0, NULL, 0 }
};

volatile atomic_bool stop = 0;  // Library needs this
unsigned int debug_mode = 0;			// Library needs this
unsigned int permissive = 0;			// Library needs this

typedef enum _reload_code { DB, RULES} reload_code;

static char *get_line(FILE *f, unsigned *lineno)
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


static int do_delete_db(void)
{
	if (unlink_db())
		return 1;
	return 0;
}


// This function opens the trust db and iterates over the entries.
// It returns a 0 on success and non-zero on failure
static int do_dump_db(void)
{
	int rc;
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
		return 1;
	}
	mdb_env_set_maxdbs(env, 2);
	rc = mdb_env_open(env, DB_DIR, MDB_RDONLY|MDB_NOLOCK, 0660);
	if (rc) {
		fprintf(stderr, "mdb_env_open failed, error %d %s\n", rc,
							mdb_strerror(rc));
		rc = 1;
		goto env_close;
	}
	rc = mdb_env_stat(env, &status);
	if (rc) {
		fprintf(stderr, "mdb_env_stat failed, error %d %s\n", rc,
							mdb_strerror(rc));
		rc = 1;
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
		rc = 1;
		goto env_close;
	}
	rc = mdb_dbi_open(txn, DB_NAME, MDB_DUPSORT, &dbi);
	if (rc) {
		fprintf(stderr, "mdb_open failed, error %d %s\n", rc,
							mdb_strerror(rc));
		rc = 1;
		goto txn_abort;
	}
	rc = mdb_cursor_open(txn, dbi, &cursor);
	if (rc) {
		fprintf(stderr, "mdb_cursor_open failed, error %d %s\n", rc,
							mdb_strerror(rc));
		rc = 1;
		goto txn_abort;
	}
	rc = mdb_cursor_get(cursor, &key, &val, MDB_FIRST);
	if (rc) {
		fprintf(stderr, "mdb_cursor_get failed, error %d %s\n", rc,
							mdb_strerror(rc));
		rc = 1;
		goto txn_abort;
	}
	do {
		char *path = NULL, *data = NULL, sha[65];
		unsigned int tsource;
		off_t size;
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

		if (sscanf(data, DATA_FORMAT, &tsource, &size, sha) != 3)
			goto next_record;

		source = lookup_tsource(tsource);
		printf("%s %s %lu %s\n", source, path, size, sha);

next_record:
		free(data);
		free(path);
		// Try to get the duplicate. If it doesn't exist, get the next one
		rc = mdb_cursor_get(cursor, &key, &val, MDB_NEXT_DUP);
		if (rc == MDB_NOTFOUND)
			rc = mdb_cursor_get(cursor, &key, &val, MDB_NEXT_NODUP);
	} while (rc == 0);

	rc = 0;
	mdb_cursor_close(cursor);
	mdb_close(env, dbi);
txn_abort:
	mdb_txn_abort(txn);
env_close:
	mdb_env_close(env);

	return rc;
}

static int do_file_add(int argc, char * const argv[])
{
	char full_path[PATH_MAX] = { 0 };

	if (argc == 1) {
		if (!realpath(argv[0], full_path))
			return 3;
		return file_append(full_path, NULL);
	}
	if (argc == 3) {
		if (!realpath(argv[0], full_path))
			return 3;
		if (strcmp("--trust-file", argv[1]))
			return 2;
		return file_append(full_path, argv[2]);
	}
	return 2;
}

static int do_file_delete(int argc, char * const argv[])
{
	char full_path[PATH_MAX] = { 0 };

	if (argc == 1) {
		if (!realpath(argv[0], full_path))
			return 3;
		return file_delete(full_path, NULL);
	}
	if (argc == 3) {
		if (!realpath(argv[0], full_path))
			return 3;
		if (strcmp("--trust-file", argv[1]))
			return 2;
		return file_delete(full_path, argv[2]);
	}
	return 2;
}

static int do_file_update(int argc, char * const argv[])
{
	char full_path[PATH_MAX] = { 0 };

	if (argc == 0)
		return file_update("/", NULL);
	if (argc == 1) {
		if (!realpath(argv[0], full_path))
			return 3;
		return file_update(full_path, NULL);
	}
	if (argc == 2) {
		if (strcmp("--trust-file", argv[0]))
			return 2;
		return file_update("/", argv[1]);
	}
	if (argc == 3) {
		if (!realpath(argv[0], full_path))
			return 3;
		if (strcmp("--trust-file", argv[1]))
			return 2;
		return file_update(full_path, argv[2]);
	}
	return 2;
}

static int do_manage_files(int argc, char * const argv[])
{
	int rc = 0;

	if (argc < 1 || argc > 4) {
		fprintf(stderr, "Wrong number of arguments\n");
		fprintf(stderr, "\n%s", usage);
		return 1;
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
		return 1;
	}

	switch (rc) {
	case 0: // no error
		return 0;
	case 2: // args error
		fprintf(stderr, "Wrong number of arguments\n");
		fprintf(stderr, "\n%s", usage);
		break;
	case 3: // realpath error
		fprintf(stderr, "Can't obtain realpath from: %s\n", argv[1]);
		fprintf(stderr, "\n%s", usage);
		break;
	default: // file function errors
		break;
	}
	return 1;
}


static int do_ftype(const char *path)
{
	int fd;
	magic_t magic_cookie;
	const char *ptr = NULL;
	struct stat sb;

	// We need to open in non-blocking mode because if its a
	// fifo, it will hang the program.
	fd = open(path, O_RDONLY|O_NONBLOCK);
	if (fd < 0) {
		fprintf(stderr, "Cannot open %s - %s\n", path, strerror(errno));
		exit(1);
	}

	unsetenv("MAGIC");
	magic_cookie = magic_open(MAGIC_MIME|MAGIC_ERROR|MAGIC_NO_CHECK_CDF|
						  MAGIC_NO_CHECK_ELF);
	if (magic_cookie == NULL) {
		fprintf(stderr, "Unable to init libmagic");
		close(fd);
		return 1;
	}
	if (magic_load(magic_cookie,
			"/usr/share/fapolicyd/fapolicyd-magic.mgc:"
			"/usr/share/misc/magic.mgc") != 0) {
		fprintf(stderr, "Unable to load magic database");
		close(fd);
		magic_close(magic_cookie);
		return 1;
	}

	// Change it back to blocking
	if (fcntl(fd, F_SETFL, 0)) {
		fprintf(stderr, "Unable to make fd blocking");
		close(fd);
		magic_close(magic_cookie);
		return 1;
	}

	if (fstat(fd, &sb) == 0) {
		uint32_t elf = 0;

		// Only classify if a regular file
		if (sb.st_mode & S_IFREG)
			elf = gather_elf(fd, sb.st_size);
		if (elf)
			ptr = classify_elf_info(elf, path);
		else {
			ptr = classify_device(sb.st_mode);
			if (ptr == NULL)
				ptr = magic_descriptor(magic_cookie, fd);
		}
	} else
		fprintf(stderr, "Failed fstat (%s)", strerror(errno));

	if (ptr) {
		char buf[80], *str;
		strncpy(buf, ptr, 79);
		buf[79] = 0;
		str = strchr(buf, ';');
		if (str)
			*str = 0;
		printf("%s\n", buf);
	} else
		printf("unknown\n");

	close(fd);
	magic_close(magic_cookie);

	return 0;
}

static int do_list(void)
{
	unsigned count = 1, lineno = 0;
	FILE *f = fopen(OLD_RULES_FILE, "rm");
	char *buf;

	if (f == NULL) {
		f = fopen(RULES_FILE, "rm");
		if (f == NULL) {
			fprintf(stderr, "Cannot open rules file (%s)\n",
						strerror(errno));
			return 1;
		}
	} else {
		FILE *t = fopen(RULES_FILE, "rm");
		if (t) {
			fclose(t);
			fclose(f);
			fprintf(stderr,
				"Error - old and new rules file detected. "
				"Delete one or the other.\n");
			return 1;
		}
	}

	while ((buf = get_line(f, &lineno))) {
		char *str = buf;
		lineno++;
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
	return 0;
}


static int do_reload(int code)
{
	int fd = -1;
	struct stat s;

	fd = open(fifo_path, O_WRONLY);
	if (fd == -1) {
		fprintf(stderr, "Open: %s -> %s\n", fifo_path, strerror(errno));
		return 1;
	}

	if (fstat(fd, &s) == -1) {
		fprintf(stderr, "Stat: %s -> %s\n", fifo_path, strerror(errno));
		close(fd);
		return 1;
	} else {
		if (!S_ISFIFO(s.st_mode)) {
			fprintf(stderr,
				"File: %s exists but it is not a pipe!\n",
				 fifo_path);
			close(fd);
			return 1;
		}
		// we will require pipe to have 0660 permissions
		mode_t mode = s.st_mode & ~S_IFMT;
		if (mode != 0660) {
			fprintf(stderr,
				"File: %s has 0%o instead of 0660 \n",
				fifo_path,
				mode);
			close(fd);
			return 1;
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
		return 1;
	}

	if (close(fd)) {
		fprintf(stderr,"Close: %s -> %s\n", fifo_path, strerror(errno));
		return 1;
	}

	printf("Fapolicyd was notified\n");
	return 0;
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
	"overlayfs", // No source of trust for what's in this
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

// Returns 1 on error and 0 on success.
// Finding unwatched file systems is not considered an error
static int check_watch_fs(void)
{
	conf_t config;
	char buf[PATH_MAX * 2], device[1025], point[4097];
	char type[32], mntops[128];
	int fs_req, fs_passno, fd, found = 0;
	list_t fs, mnt;
	char *ptr, *saved, *tmp;

	set_message_mode(MSG_STDERR, DBG_YES);
	if (load_daemon_config(&config)) {
		free_daemon_config(&config);
		return 1;
	}
	if (config.watch_fs == NULL) {
		fprintf(stderr, "File systems to watch is empty");
		return 1;
	}
	tmp = strdup(config.watch_fs);

	list_init(&fs);
	ptr = strtok_r(tmp, ",", &saved);
	while (ptr) {
		// we do not care about the data
		list_append(&fs, strdup(ptr), strdup("0"));
		ptr = strtok_r(NULL, ",", &saved);
	}
	free(tmp);

	fd = open("/proc/mounts", O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "Unable to open mounts\n");
		free_daemon_config(&config);
		list_empty(&fs);
		return 1;
	}

	fd_fgets_context_t *fd_fgets_context = fd_fgets_init();
	if (!fd_fgets_context) {
		fprintf(stderr, "Failed fd_fgets_init\n");
		free_daemon_config(&config);
		list_empty(&fs);
		close(fd);
		return 1;
	}

	// Build the list of mount point types
	list_init(&mnt);
	do {
		if (fd_fgets(fd_fgets_context, buf, sizeof(buf), fd)) {
			sscanf(buf, "%1024s %4096s %31s %127s %d %d\n",
			       device,point, type, mntops, &fs_req, &fs_passno);
			// Some file systems are not watchable
			if (not_watchable(type))
				continue;
			list_append(&mnt, strdup(type), strdup("0"));
		}
	} while (!fd_fgets_eof(fd_fgets_context));
	fd_fgets_destroy(fd_fgets_context);
	close(fd);


	// Now search the list we just built
	for (list_item_t *lptr = mnt.first; lptr; lptr = lptr->next) {
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
		}
	}

	free_daemon_config(&config);
	list_empty(&fs);
	list_empty(&mnt);
	if (found == 0)
		printf("Nothing appears missing\n");

	return 0;
}

// Returns 0 = everything is OK, 1 = there is a problem
static int verify_file(const char *path, off_t size, const char *sha)
{
	int fd, warn_size = 0, warn_sha = 0;
	struct stat sb;

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
	if (sb.st_size != size)
		warn_size = 1;

	char *sha_buf = get_hash_from_fd2(fd, sb.st_size, 1);
	close(fd);

	if (sha_buf == NULL || strcmp(sha, sha_buf))
		warn_sha = 1;
	free(sha_buf);

	if (warn_size || warn_sha) {
		printf("%s miscompares: %s %s\n", path,
		   warn_size ? "size" : "",
		   warn_sha ? (strlen(sha) < 64 ? "is a sha1" : "sha256") : "");
		return 1;
	}
	return 0;
}

static int check_trustdb(void)
{
	conf_t config;
	int found = 0;

	set_message_mode(MSG_STDERR, DBG_NO);
	if (load_daemon_config(&config)) {
		free_daemon_config(&config);
		return 1;
	}
	set_message_mode(MSG_QUIET, DBG_NO);
	int rc = walk_database_start(&config);
	free_daemon_config(&config);
	if (rc)
		return 1;

	do {
		unsigned int tsource; // unused
		off_t size;
		char sha[65];
		char path[448];
		char data[80];

		// Get the entry and format it for use.
		walkdb_entry_t *entry = walk_database_get_entry();
		snprintf(path, sizeof(path), "%.*s", (int) entry->path.mv_size,
			(char *) entry->path.mv_data);
		snprintf(data, sizeof(data), "%.*s", (int) entry->data.mv_size,
			(char *) entry->data.mv_data);
		if (sscanf(data, DATA_FORMAT, &tsource, &size, sha) != 3) {
			fprintf(stderr, "%s data entry is corrupted\n", path);
			continue;
		}
		if (verify_file(path, size, sha))
			found =1 ;
	} while (walk_database_next());

	walk_database_finish();

	if (found == 0)
		puts("No problems found");

	return 0;
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
	conf_t config;
	char *ptr, *saved;
	const char *env_path = getenv("PATH");
	if (env_path == NULL) {
		puts("PATH not found");
		return 1;
	}

	set_message_mode(MSG_STDERR, DBG_NO);
	if (load_daemon_config(&config)) {
		free_daemon_config(&config);
		return 1;
	}
	set_message_mode(MSG_QUIET, DBG_NO);
	init_database(&config);
	char *path = strdup(env_path);
	ptr = strtok_r(path, ":", &saved);
	while (ptr) {
		if (is_link(path))
			goto next;

		nftw(ptr, check_file, 1024, FTW_PHYS);
next:
		ptr = strtok_r(NULL, ":", &saved);
	}
	stop = 1; // Need this to terminate update thread
	free(path);
	close_database();
	free_daemon_config(&config);

	if (path_found == 0)
		puts("No problems found");

	return 0;
}

static int do_status_report(void)
{
	const char *reason = "no pid file";

	fd_fgets_context_t *fd_fgets_context = fd_fgets_init();
	if (!fd_fgets_context)
		return 1;

	// open pid file
	int pidfd = open(pidfile, O_RDONLY);
	if (pidfd >= 0) {
		char pid_buf[16];

		// read contents
		if (fd_fgets(fd_fgets_context, pid_buf, sizeof(pid_buf), pidfd)) {
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
			if (strcmp(exe_buf, DAEMON_PATH)) {
				reason = "pid file doesn't point to fapolicyd";
				goto err_out;
			}

			// delete the old report
			unlink(STAT_REPORT);

			// send the signal for the report
			kill(pid, SIGUSR1);

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
			fd_fgets_rewind(fd_fgets_context);
			do {
				char buf[80];
				if (fd_fgets(fd_fgets_context, buf, sizeof(buf), rpt_fd))
					write(1, buf, strlen(buf));
			} while (!fd_fgets_eof(fd_fgets_context));
			close(rpt_fd);
		} else
			reason = "can't read pid file";
		close(pidfd);
		fd_fgets_destroy(fd_fgets_context);
		return 0;
	}
err_out:
	fd_fgets_destroy(fd_fgets_context);
	if (pidfd >= 0)
		close(pidfd);
	printf("Can't find fapolicyd: %s\n", reason);
	return 1;
}

int main(int argc, char * const argv[])
{
	int opt, option_index, rc = 1;

	if (argc == 1) {
		fprintf(stderr, "Too few arguments\n\n");
		fprintf(stderr, "%s", usage);
		return rc;
	}

	opt = getopt_long(argc, argv, "Ddf:ht:lur",
				 long_opts, &option_index);
	switch (opt) {
	case 'd':
		if (argc > 2)
			goto args_err;
		rc = do_delete_db();
		break;
	case 'D':
		if (argc > 2)
			goto args_err;
		rc = do_dump_db();
		break;
	case 'f':
		if (argc > 6)
			goto args_err;
		// fapolicyd-cli, -f, | operation, path ...
		// skip the first two args
		rc = do_manage_files(argc-2, argv+2);
		break;
	case 'h':
		printf("%s", usage);
		rc = 0;
		break;
	case 't':
		if (argc > 3)
			goto args_err;
		rc = do_ftype(optarg);
		break;
	case 'l':
		if (argc > 2)
			goto args_err;
		rc = do_list();
		break;
	case 'u':
		if (argc > 2)
			goto args_err;
		rc = do_reload(DB);
		break;
	case 'r':
		if (argc > 2)
			goto args_err;
		rc = do_reload(RULES);
		break;

	// Now the pure long options
	case 1: { // --check-config
		conf_t config;

		if (argc > 2)
			goto args_err;
		set_message_mode(MSG_STDERR, DBG_YES);
		if (load_daemon_config(&config)) {
			free_daemon_config(&config);
			fprintf(stderr, "Configuration errors reported\n");
			return 1;
		} else {
			printf("Daemon config is OK\n");
			free_daemon_config(&config);
			return 0;
		} }
		break;
	case 2: // --check-watch_fs
		if (argc > 2)
			goto args_err;
		return check_watch_fs();
		break;
	case 3: // --check-trustdb
		if (argc > 2)
			goto args_err;
		return check_trustdb();
		break;
	case 4: // --check-status
		if (argc > 2)
			goto args_err;
		return do_status_report();
		break;
	case 5: // --check-path
		if (argc > 2)
			goto args_err;
		return check_path();
		break;
	default:
		printf("%s", usage);
		rc = 1;
	}
	return rc;

args_err:
	fprintf(stderr, "Too many arguments\n\n");
	fprintf(stderr, "%s", usage);
	return rc;
}

