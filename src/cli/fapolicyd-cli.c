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
#include <mntent.h>
#include "policy.h"
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
#ifdef HAVE_LIBRPM
#include "filter.h"
#endif

bool verbose = false;

static const char *usage =
"Fapolicyd CLI Tool\n\n"
"--check-config        Check the daemon config for syntax errors\n"
"--check-path          Check files in $PATH against the trustdb for problems\n"
"--check-status        Dump the deamon's internal performance statistics\n"
"--check-trustdb       Check the trustdb against files on disk for problems\n"
"--check-watch_fs      Check watch_fs against currently mounted file systems\n"
"--check-ignore_mounts [path] Scan ignored mounts for executable content\n"
"--verbose             Enable verbose output for select commands\n"
"-d, --delete-db       Delete the trust database\n"
"-D, --dump-db         Dump the trust database contents\n"
"-f, --file cmd path   Manage the file trust database\n"
"-h, --help            Prints this help message\n"
"-t, --ftype file-path Prints out the mime type of a file\n"
"-l, --list            Prints a list of the daemon's rules with numbers\n"
"-r, --reload-rules    Notifies fapolicyd to perform reload of rules\n"
#ifdef HAVE_LIBRPM
"--test-filter path    Test FILTER_FILE against path and trace to stdout\n"
#endif
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

struct mount_scan_state {
	const avl_tree_t *languages;
	unsigned long *count;
	int had_error;
};

static struct mount_scan_state scan_state;

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
		if (elf & IS_ELF)
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

// Returns 1 on error and 0 on success.
// Finding unwatched file systems is not considered an error
static int check_watch_fs(void)
{
	char buf[PATH_MAX * 2], device[1025], point[4097];
	char type[32], mntops[128];
	int fs_req, fs_passno, fd, found = 0;
	list_t fs, mnt;
	char *ptr, *saved, *tmp;

	set_message_mode(MSG_STDERR, DBG_YES);
	reset_config();
	if (load_daemon_config(&config)) {
		reset_config();
		return 1;
	}
	if (config.watch_fs == NULL) {
		fprintf(stderr, "File systems to watch is empty");
		reset_config();
		return 1;
	}
	tmp = strdup(config.watch_fs);

	list_init(&fs);
	ptr = strtok_r(tmp, ",", &saved);
	while (ptr) {
		char *index = strdup(ptr);
		char *data = strdup("0");
		if (!index || !data || list_append(&fs, index, data)) {
			free(index);
			free(data);
		}
		ptr = strtok_r(NULL, ",", &saved);
	}
	free(tmp);

	fd = open("/proc/mounts", O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "Unable to open mounts\n");
		reset_config();
		list_empty(&fs);
		return 1;
	}

	fd_fgets_state_t *st = fd_fgets_init();
	if (!st) {
		fprintf(stderr, "Failed fd_fgets_init\n");
		reset_config();
		list_empty(&fs);
		close(fd);
		return 1;
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
			}
		}
	} while (!fd_fgets_eof_r(st));
	fd_fgets_destroy(st);
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

	reset_config();
	list_empty(&fs);
	list_empty(&mnt);
	if (found == 0)
		printf("Nothing appears missing\n");

	return 0;
}

/*
 * append_mount_entry - duplicate an ignore_mounts entry into a list.
 * @mount: trimmed ignore_mounts entry.
 * @data: list receiving duplicated entries.
 * Returns 0 on success and 1 on allocation failure.
 */
static int append_mount_entry(const char *mount, void *data)
{
	list_t *mounts = data;
	char *copy = strdup(mount);

	if (copy == NULL)
		return 1;

	if (list_append(mounts, copy, NULL)) {
		free(copy);
		return 1;
	}

	return 0;
}

/*
 * populate_mount_list - split ignore_mounts string into individual entries.
 * @ignore_list: comma separated mount list from the configuration.
 * @mounts: list that receives duplicated mount paths.
 * Returns 0 on success and 1 on allocation failure.
 */
static int populate_mount_list(const char *ignore_list, list_t *mounts)
{
	int rc;

	if (ignore_list == NULL)
		return 0;

	rc = iterate_ignore_mounts(ignore_list, append_mount_entry, mounts);
	if (rc) {
		list_empty(mounts);
		return 1;
	}

	return 0;
}

struct language_entry {
	avl_t avl;
	char *mime;
};

/*
 * compare_language_entry - compare two MIME tree nodes alphabetically.
 * @a: first tree entry for comparison.
 * @b: second tree entry for comparison.
 * Returns <0 when @a sorts before @b, >0 when it sorts after, and 0 when they
 * match.
 */
static int compare_language_entry(void *a, void *b)
{
	const struct language_entry *la = a;
	const struct language_entry *lb = b;

	return strcmp(la->mime, lb->mime);
}

/*
 * insert_language_mime - add a MIME string to the %languages tree.
 * @languages: AVL tree tracking the known MIME values.
 * @mime: MIME string trimmed from the rules file.
 * Returns 0 on success and 1 on allocation failure.
 */
static int insert_language_mime(avl_tree_t *languages, const char *mime)
{
	struct language_entry *entry;
	avl_t *ret;

	entry = malloc(sizeof(*entry));
	if (entry == NULL)
		return 1;

	entry->mime = strdup(mime);
	if (entry->mime == NULL) {
		free(entry);
		return 1;
	}

	ret = avl_insert(languages, &entry->avl);
	if (ret != &entry->avl) {
		free(entry->mime);
		free(entry);
	}

	return 0;
}

/*
 * free_language_mimes - release all nodes stored in the MIME AVL tree.
 * @languages: AVL tree previously filled by load_language_mimes().
 */
static void free_language_mimes(avl_tree_t *languages)
{
	while (languages->root) {
		struct language_entry *entry =
			(struct language_entry *)languages->root;

		avl_remove(languages, &entry->avl);
		free(entry->mime);
		free(entry);
	}
}

/*
 * load_language_mimes - gather MIME types belonging to %languages.
 * @languages: AVL tree populated with MIME type strings.
 * @source_path: returns the path used while loading definitions.
 * Returns 0 on success and 1 on failure.
 */
static int load_language_mimes(avl_tree_t *languages, const char **source_path)
{
	FILE *fp;
	char *line = NULL;
	size_t len = 0;
	int rc = 1, found = 0;

	*source_path = LANGUAGE_RULES_FILE;
	fp = fopen(*source_path, "rm");
	if (fp == NULL) {
		*source_path = RULES_FILE;
		fp = fopen(*source_path, "rm");
		if (fp == NULL)
			return 1;
	}

	while (getline(&line, &len, fp) != -1) {
		char *entry = fapolicyd_strtrim(line);

		if (strncmp(entry, "%languages=", 11) == 0) {
			char *value = entry + 11;
			char *tmp = strdup(value);
			char *ptr, *saved;

			if (tmp == NULL)
				goto done;

			ptr = strtok_r(tmp, ",", &saved);
			while (ptr) {
				char *mime = fapolicyd_strtrim(ptr);

				if (*mime) {
					if (insert_language_mime(languages, mime)) {
						free(tmp);
						free_language_mimes(languages);
						goto done;
					}
				}
				ptr = strtok_r(NULL, ",", &saved);
			}
			free(tmp);
			found = 1;
			break;
		}
	}

	if (found)
		rc = 0;

done:
	free(line);
	fclose(fp);
	return rc;
}

/*
 * is_mount_point - determine whether the supplied path is a mount point.
 * @path: directory to inspect.
 * Returns 1 when the path is mounted, 0 when it is not, and -1 when the
 * mount table cannot be read.
 */
static int is_mount_point(const char *path)
{
	FILE *fp;
	struct mntent *ent;

	fp = setmntent(MOUNTS_FILE, "r");
	if (fp == NULL)
		return -1;

	while ((ent = getmntent(fp))) {
		if (strcmp(ent->mnt_dir, path) == 0) {
			endmntent(fp);
			return 1;
		}
	}

	endmntent(fp);
	return 0;
}

/*
 * validate_override_mount - verify CLI override path and copy it to config.
 * @override: path supplied by the administrator.
 * Returns 0 on success and 1 on failure.
 */
static int validate_override_mount(const char *override)
{
	char resolved[PATH_MAX];
	char *rpath;
	struct stat sb;
	int mount_rc;

	rpath = realpath(override, resolved);
	if (rpath == NULL) {
		fprintf(stderr, "Cannot resolve %s (%s)\n", override, strerror(errno));
		return 1;
	}
	if (stat(rpath, &sb) || S_ISDIR(sb.st_mode) == 0) {
		fprintf(stderr, "%s is not a directory\n", rpath);
		return 1;
	}

	mount_rc = is_mount_point(rpath);
	if (mount_rc <= 0) {
		if (mount_rc == 0)
			fprintf(stderr, "%s is not a mount point\n", rpath);
		else
			fprintf(stderr, "Unable to read %s (%s)\n", MOUNTS_FILE,
				strerror(errno));
		return 1;
	}

	free((void *)config.ignore_mounts);
	config.ignore_mounts = strdup(rpath);
	if (config.ignore_mounts == NULL) {
		fprintf(stderr, "Out of memory\n");
		return 1;
	}

	return 0;
}

/*
 * load_ignore_mounts_config - populate ignore_mounts field for scanning.
 * @override: optional CLI path override.
 * Returns 0 on success and 1 on failure.
 */
static int load_ignore_mounts_config(const char *override)
{
	if (override)
		return validate_override_mount(override);

	set_message_mode(MSG_STDERR, DBG_YES);
	if (load_daemon_config(&config))
		return 1;

	return 0;
}

/*
 * inspect_mount_file - nftw callback that records suspicious files.
 * @fpath: path of the file being inspected.
 * @sb: stat buffer describing the file.
 * @typeflag_unused: unused nftw type flag.
 * @ftwbuf_unused: unused nftw traversal metadata.
 * Returns FTW_CONTINUE so the walk keeps running.
 */
static int inspect_mount_file(const char *fpath, const struct stat *sb,
	int typeflag_unused __attribute__ ((unused)),
	struct FTW *ftwbuf_unused __attribute__ ((unused)))
{
	int fd;
	struct file_info info;
	char buf[128];
	char *mime;

	/* Only evaluate regular files discovered during the walk. */
	if (S_ISREG(sb->st_mode) == 0)
		return FTW_CONTINUE;

	/* Open the file and collect metadata for libmagic. */
	fd = open(fpath, O_RDONLY|O_CLOEXEC);
	if (fd < 0) {
		fprintf(stderr, "Unable to open %s (%s)\n", fpath, strerror(errno));
		scan_state.had_error = 1;
		return FTW_CONTINUE;
	}

	memset(&info, 0, sizeof(info));
	info.device = sb->st_dev;
	info.inode = sb->st_ino;
	info.mode = sb->st_mode;
	info.size = sb->st_size;
	info.time = sb->st_mtim;

	mime = get_file_type_from_fd(fd, &info, fpath, sizeof(buf), buf);
	close(fd);
	if (mime == NULL) {
		fprintf(stderr, "Unable to determine mime for %s\n", fpath);
		scan_state.had_error = 1;
		return FTW_CONTINUE;
	}

	/* Look up the MIME in the %languages tree and report matches. */
	struct language_entry key = {
		.mime = buf,
	};

	if (avl_search(scan_state.languages, &key.avl)) {
		if (verbose)
			printf("%s: %s\n", fpath, buf);
		if (scan_state.count)
			(*scan_state.count)++;
	}

	return FTW_CONTINUE;
}

/*
 * scan_mount_entry - scan a single ignore_mounts entry for suspicious files.
 * @mount: entry from config.ignore_mounts.
 * @suspicious_total: aggregate counter updated with matches.
 * @override: 0 ignore_mounts list, 1 command line override
 * Returns 0 when the mount was scanned successfully and 1 when errors
 * prevent a full scan.
 */
static int scan_mount_entry(const char *mount, unsigned long *suspicious_total,
			    int override)
{
	char resolved[PATH_MAX];
	char *rpath;
	unsigned long mount_count = 0;
	struct stat sb;
	int rc = 0;
	int scanned = 0;

	rpath = realpath(mount, resolved);
	if (rpath == NULL) {
		fprintf(stderr, "Cannot resolve %s (%s)\n", mount,
			strerror(errno));
		printf("Summary for %s: 0 suspicious file(s) (scan skipped)\n",
		       mount);
		return 1;
	}

	if (stat(rpath, &sb)) {
		fprintf(stderr, "%s does not exist\n", rpath);
		printf("Summary for %s: 0 suspicious file(s) (scan skipped)\n",
		       rpath);
		return 1;
	}
	if (S_ISDIR(sb.st_mode) == 0) {
		fprintf(stderr, "%s is not a directory\n", rpath);
		printf("Summary for %s: 0 suspicious file(s) (scan skipped)\n",
		       rpath);
		return 1;
	}

	const char *warning = NULL;
	int mount_rc = check_ignore_mount_warning(MOUNTS_FILE, rpath, &warning);

	if (warning) {
		if (override && warning[0] == 'i')
			warning += 20; // skip the ignore_mount part
		fprintf(stderr, warning, rpath, MOUNTS_FILE);
		fputc('\n', stderr);
	}

	// A warning was already printed -  just return
	if (mount_rc != 1)
		return 1;

	scan_state.count = &mount_count;
	scan_state.had_error = 0;
	if (nftw(rpath, inspect_mount_file, 1024, FTW_PHYS)) {
		fprintf(stderr, "Unable to scan %s (%s)\n", rpath,
			strerror(errno));
		printf("Summary for %s: 0 suspicious file(s) (scan skipped)\n",
		       rpath);
		rc = 1;
	} else
		scanned = 1;

	if (scan_state.had_error)
		rc = 1;

	if (scanned) {
		printf("Summary for %s: %lu suspicious file(s)\n", rpath,
		       mount_count);
		*suspicious_total += mount_count;
	}

	scan_state.count = NULL;

	if (!scanned)
		return 1;

	return rc;
}


/*
 * check_ignore_mounts - validate ignore_mounts entries and scan for matches.
 * @override: optional mount path provided on the command line.
 * Returns 0 when no suspicious files are found and 1 otherwise.
 */
static int check_ignore_mounts(const char *override)
{
	list_t mounts;
	avl_tree_t languages;
	int rc = 1;
	unsigned long suspicious_total = 0;
	int errors = 0;
	int file_ready = 0;
	const char *languages_path;

	reset_config();
	list_init(&mounts);
	avl_init(&languages, compare_language_entry);

	/* Load ignore_mounts either from the override path or daemon config. */
	if (load_ignore_mounts_config(override))
		goto finish;

	if (config.ignore_mounts == NULL) {
		printf("No ignore_mounts entries configured\n");
		rc = 0;
		goto finish;
	}

	if (populate_mount_list(config.ignore_mounts, &mounts)) {
		fprintf(stderr, "Failed to parse ignore_mounts entries\n");
		goto finish;
	}

	if (mounts.first == NULL) {
		printf("No ignore_mounts entries configured\n");
		rc = 0;
		goto finish;
	}

	/* Build a fast lookup tree of MIME types associated with %languages. */
	if (load_language_mimes(&languages, &languages_path)) {
		fprintf(stderr,
			"Unable to load %%languages definitions from %s\n",
			languages_path);
		goto finish;
	}

	/* Initialize libmagic once so nftw() callbacks can reuse it. */
	file_init();
	file_ready = 1;
	scan_state.languages = &languages;

	/* Walk each ignore_mounts entry and flag suspicious MIME matches. */
	for (list_item_t *lptr = mounts.first; lptr; lptr = lptr->next) {
		if (scan_mount_entry(lptr->index, &suspicious_total,
				     override ? 1 : 0))
			errors = 1;
	}

	if (errors == 0 && suspicious_total == 0)
		rc = 0;

finish:
	if (file_ready)
		file_close();
	list_empty(&mounts);
	free_language_mimes(&languages);
	scan_state.languages = NULL;
	scan_state.count = NULL;
	scan_state.had_error = 0;
	reset_config();
	return (suspicious_total > 0) ? 1 : (errors ? 1 : rc);
}

// Returns 0 = everything is OK, 1 = there is a problem
static int verify_file(const char *path, off_t size, const char *sha)
{
	int fd, warn_sha = 0;
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
	if (sb.st_size != size) {
		printf("%s miscompares: file size\n", path);
		close(fd);
		return 1;
	}

	char *sha_buf = get_hash_from_fd2(fd, sb.st_size, 1);
	close(fd);

	if (sha_buf == NULL || strcmp(sha, sha_buf))
		warn_sha = 1;
	free(sha_buf);

	if (warn_sha) {
		const char *sha_desc;
		size_t sha_len = strlen(sha);

		// For now, only sha256 is supported
		if (sha_len < 64)
			sha_desc = "is a sha1";
		else if (sha_len > 64)
			sha_desc = "is a sha512";
		else
			sha_desc = "sha256";

		printf("%s miscompares: %s\n", path, sha_desc);
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
		return 1;
	}
	set_message_mode(MSG_QUIET, DBG_NO);
	int rc = walk_database_start(&config);
	reset_config();
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
	char *ptr, *saved;
	const char *env_path = getenv("PATH");
	if (env_path == NULL) {
		puts("PATH not found");
		return 1;
	}

	set_message_mode(MSG_STDERR, DBG_NO);
	reset_config();
	if (load_daemon_config(&config)) {
		reset_config();
		return 1;
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

	return 0;
}

static int do_status_report(void)
{
	const char *reason = "no pid file";

	fd_fgets_state_t *st = fd_fgets_init();
	if (!st)
		return 1;

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
			fd_fgets_clear_r(st);
			do {
				char buf[80];
				if (fd_fgets_r(st, buf, sizeof(buf), rpt_fd))
					write(1, buf, strlen(buf));
			} while (!fd_fgets_eof_r(st));
			close(rpt_fd);
		} else
			reason = "can't read pid file";
		close(pidfd);
		fd_fgets_destroy(st);
		return 0;
	}
err_out:
	fd_fgets_destroy(st);
	if (pidfd >= 0)
		close(pidfd);
	printf("Can't find fapolicyd: %s\n", reason);
	return 1;
}

#ifdef HAVE_LIBRPM
static int do_test_filter(const char *path)
{
	set_message_mode(MSG_STDERR, DBG_NO);
	filter_set_trace(stdout);

	if (filter_init()) {
		fprintf(stderr, "filter_init failed\n");
		return 1;
	}
	if (filter_load_file(FILTER_FILE)) {
		filter_destroy();
		fprintf(stderr, "filter_load_file failed\n");
		return 1;
	}
	filter_check(path);
	filter_destroy();
	return 0;
}
#endif

int main(int argc, char * const argv[])
{
	int opt, option_index, rc = 1;
	int orig_argc = argc, arg_count = 0;
	char *args[orig_argc+1];

	for (int i = 0; i < orig_argc; i++) {
		if (strcmp(argv[i], "--verbose") == 0) {
			verbose = true;
			continue;
		}
		args[arg_count++] = argv[i];
	}
	args[arg_count] = NULL;

	if (arg_count == 1) {
		fprintf(stderr, "Too few arguments\n\n");
		fprintf(stderr, "%s", usage);
		return rc;
	}

	optind = 1;

	/* Run getopt_long on the sanitized copy so command parsing behaves
	 * exactly as before --verbose was introduced. */
	opt = getopt_long(arg_count, (char * const *)args, "Ddf:ht:lur",
				 long_opts, &option_index);

	switch (opt) {
	case 'd':
		if (arg_count > 2)
			goto args_err;
		rc = do_delete_db();
		break;
	case 'D':
		if (arg_count > 2)
			goto args_err;
		rc = do_dump_db();
		break;
	case 'f':
		if (arg_count > 6)
			goto args_err;
		// fapolicyd-cli, -f, | operation, path ...
		// skip the first two args
		rc = do_manage_files(arg_count-2, args+2);
		break;
	case 'h':
		printf("%s", usage);
		rc = 0;
		break;
	case 't':
		if (arg_count > 3)
			goto args_err;
		rc = do_ftype(optarg);
		break;
	case 'l':
		if (arg_count > 2)
			goto args_err;
		rc = do_list();
		break;
	case 'u':
		if (arg_count > 2)
			goto args_err;
		rc = do_reload(DB);
		break;
	case 'r':
		if (arg_count > 2)
			goto args_err;
		rc = do_reload(RULES);
		break;

	// Now the pure long options
	case 1: { // --check-config

		if (arg_count > 2)
			goto args_err;
		set_message_mode(MSG_STDERR, DBG_YES);
		reset_config();
		if (load_daemon_config(&config)) {
			reset_config();
			fprintf(stderr, "Configuration errors reported\n");
			return 1;
		} else {
			printf("Daemon config is OK\n");
			reset_config();
			return 0;
		} }
		break;
	case 2: // --check-watch_fs
		if (arg_count > 2)
			goto args_err;
		return check_watch_fs();
		break;
	case 3: // --check-trustdb
		if (arg_count > 2)
			goto args_err;
		return check_trustdb();
		break;
	case 4: // --check-status
		if (arg_count > 2)
			goto args_err;
		return do_status_report();
		break;
	case 5: // --check-path
		if (arg_count > 2)
			goto args_err;
		return check_path();
		break;

	case 7: { // --check-ignore_mounts
		const char *override = optarg;

		if (override == NULL && optind < arg_count &&
						argv[optind][0] != '-')
			override = args[optind++];
		if (optind < arg_count)
			goto args_err;
		return check_ignore_mounts(override);
		}
		break;

#ifdef HAVE_LIBRPM
	case 6: { // --test-filter
		if (arg_count > 3)
			goto args_err;
		return do_test_filter(optarg);
		}
		break;
#endif
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

