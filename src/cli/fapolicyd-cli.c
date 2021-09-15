/*
 * fapolicy-cli.c - CLI tool for fapolicyd
 * Copyright (c) 2019-2021 Red Hat Inc.
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
#include "policy.h"
#include "database.h"
#include "file-cli.h"
#include "fapolicyd-backend.h"
#include "string-util.h"


static const char *usage =
"Fapolicyd CLI Tool\n\n"
"-d, --delete-db       Delete the trust database\n"
"-D, --dump-db         Dump the trust database contents\n"
"-f, --file cmd path   Manage the file trust database\n"
"--trust-file file     Use after --file to specify trust file\n"
"-h, --help            Prints this help message\n"
"-t, --ftype file-path Prints out the mime type of a file\n"
"-l, --list            Prints a list of the daemon's rules with numbers\n"
"-u, --update          Notifies fapolicyd to perform update of database\n"
;

static struct option long_opts[] =
{
	{"delete-db",	0, NULL, 'd'},
	{"dump-db",	0, NULL, 'D'},
	{"file",	1, NULL, 'f'},
	{"help",	0, NULL, 'h'},
	{"ftype",	1, NULL, 't'},
	{"list",	0, NULL, 'l'},
	{"update",	0, NULL, 'u'},
};

static const char *_pipe = "/run/fapolicyd/fapolicyd.fifo";
volatile atomic_bool stop = 0;  // Library needs this
int debug = 0;			// Library needs this

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
		char *path, *data, sha[65];
		unsigned int tsource;
		off_t size;
		const char *source;

		path = malloc(key.mv_size+1);
		if (!path)
			continue;
		memcpy(path, key.mv_data, key.mv_size);
		path[key.mv_size] = 0;
		data = malloc(val.mv_size+1);
		if (!data) {
			free(path);
			continue;
		}
		memcpy(data, val.mv_data, val.mv_size);
		data[val.mv_size] = 0;
		if (sscanf(data, DATA_FORMAT, &tsource, &size, sha) != 3) {
			free(data);
			free(path);
			continue;
		}
		source = lookup_tsource(tsource);
		printf("%s %s %lu %s\n", source, path, size, sha);
		free(data);
		free(path);
		// Try to get the duplicate. If doesn't exist, get the next one
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


/*
 * This function always requires at least one option, the command. We can
 * guarantee that argv[2] is the command because getopt_long would have
 * printed an error otherwise. argv[3] would be an optional parameter based
 * on which command is being run. If argv[4] == "--trust-file" then argv[5]
 * specifies a trust file to operate on.
 *
 * The function returns 0 on success and 1 on failure
 */
static int do_manage_files(int argc, char * const argv[])
{
	int rc = 0;

	if (argc > 0) {
		if ( (strcmp("add", argv[0]) != 0)
			 && (strcmp("delete", argv[0]) != 0)
			 && (strcmp("update", argv[0]) != 0) ) {
			fprintf(stderr, "%s is not valid option, choose from add|delete|update\n", argv[0]);
			goto args_err;
		}
	}

	if (argc < 2)
		goto args_err;

	char full_path[PATH_MAX] = {0};

	if (realpath(argv[1], full_path) == NULL) {
		fprintf(stderr, "Cannot get realpath from: %s\n", argv[1]);
		perror("realpath");
		goto args_err;
	}

	if (strcmp("add", argv[0]) == 0) {
		switch (argc) {
		case 2:
			rc = file_append(full_path, NULL);
			break;
		case 4:
			if (strcmp("--trust-file", argv[2]))
				goto args_err;
			rc = file_append(full_path, argv[3]);
			break;
		default:
			goto args_err;
		}
	} else if (strcmp("delete", argv[0]) == 0) {
		switch (argc) {
		case 2:
			rc = file_delete(full_path, NULL);
			break;
		case 4:
			if (strcmp("--trust-file", argv[2]))
				goto args_err;
			rc = file_delete(full_path, argv[3]);
			break;
		default:
			goto args_err;
		}
	} else if (strcmp("update", argv[0]) == 0) {
		switch (argc) {
		case 2:
			rc = file_update(full_path, NULL);
			break;
		case 4:
			if (strcmp("--trust-file", argv[2]))
				goto args_err;
			rc = file_update(full_path, argv[3]);
			break;
		default:
			goto args_err;
		}
	}

	return rc ? 1 : 0;

args_err:
	fprintf(stderr, "Wrong number of arguments\n\n");
	fprintf(stderr, "%s", usage);

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
	fcntl(fd, F_SETFL, 0);

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
	FILE *f = fopen(RULES_FILE, "rm");
	char *buf;

	if (f == NULL) {
		fprintf(stderr, "Cannot open rules file (%s)\n",
						strerror(errno));
		return 1;
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


static int do_update(void)
{
	int fd = -1;
	struct stat s;

	fd = open(_pipe, O_WRONLY);
	if (fd == -1) {
		fprintf(stderr, "Open: %s -> %s\n", _pipe, strerror(errno));
		return 1;
	}

	if (stat(_pipe, &s) == -1) {
		fprintf(stderr, "Stat: %s -> %s\n", _pipe, strerror(errno));
		close(fd);
		return 1;
	} else {
		if (!S_ISFIFO(s.st_mode)) {
			fprintf(stderr,
				"File: %s exists but it is not a pipe!\n",
				 _pipe);
			close(fd);
			return 1;
		}
		// we will require pipe to have 0660 permissions
		if (!(
		      (s.st_mode & S_IRUSR) &&
		      (s.st_mode & S_IWUSR) &&
		      !(s.st_mode & S_IXUSR) &&

		      (s.st_mode & S_IRGRP) &&
		      (s.st_mode & S_IWGRP) &&
		      !(s.st_mode & S_IXGRP) &&

		      !(s.st_mode & S_IROTH) &&
		      !(s.st_mode & S_IWOTH) &&
		      !(s.st_mode & S_IXOTH)
		     )) {
			fprintf(stderr,
				"File: %s has 0%d%d%d instead of 0660 \n",
				_pipe,
				((s.st_mode & S_IRUSR) ? 4 : 0) +
				((s.st_mode & S_IWUSR) ? 2 : 0) +
				((s.st_mode & S_IXUSR) ? 1 : 0)
				,
				((s.st_mode & S_IRGRP) ? 4 : 0) +
				((s.st_mode & S_IWGRP) ? 2 : 0) +
				((s.st_mode & S_IXGRP) ? 1 : 0)
				,
				((s.st_mode & S_IROTH) ? 4 : 0) +
				((s.st_mode & S_IWOTH) ? 2 : 0) +
				((s.st_mode & S_IXOTH) ? 1 : 0) );
			close(fd);
			return 1;
		}
	}

	ssize_t ret = write(fd, "1", 2);

	if (ret == -1) {
		fprintf(stderr, "Write: %s -> %s\n", _pipe, strerror(errno));
		close(fd);
		return 1;
	}

	if (close(fd)) {
		fprintf(stderr, "Close: %s -> %s\n", _pipe, strerror(errno));
		return 1;
	}

	printf("Fapolicyd was notified\n");
	return 0;
}


int main(int argc, char * const argv[])
{
	int opt, option_index, rc = 1;

	if (argc == 1) {
		fprintf(stderr, "Too few arguments\n\n");
		fprintf(stderr, "%s", usage);
		return rc;
	}

	opt = getopt_long(argc, argv, "Ddf:ht:lu",
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
		rc = do_update();
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

