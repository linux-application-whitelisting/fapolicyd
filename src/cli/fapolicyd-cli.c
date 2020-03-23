/*
 * fapolicy-cli.c - CLI tool for fapolicyd
 * Copyright (c) 2019,2020 Red Hat Inc.
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
#include "policy.h"
#include "database.h"
#include "file-backend.h"

const char *usage =
"Fapolicyd CLI Tool\n\n"
"-d, --delete-db\t\tDelete the trust database\n"
"-f, --file option path\tManage the file trust database\n"
"-h, --help\t\tPrints this help message\n"
"-t, --ftype file-path\tPrints out the mime type of a file\n"
"-l, --list\t\tPrints a list of the daemon's rules with numbers\n"
"-u, --update\t\tNotifies fapolicyd to perform update of database\n"
;

struct option long_opts[] =
{
	{"delete-db",	0, NULL, 'd'},
	{"file",	1, NULL, 'f'},
	{"help",	0, NULL, 'h'},
	{"ftype",	1, NULL, 't'},
	{"list",	0, NULL, 'l'},
	{"update",	0, NULL, 'u'},
};

const char *_pipe = "/run/fapolicyd/fapolicyd.fifo";
volatile atomic_bool stop = 0;  // Library needs this


static char *get_line(FILE *f, char *buf, unsigned size, unsigned *lineno)
{
	int too_long = 0;

	while (fgets_unlocked(buf, size, f)) {
		/* remove newline */
		char *ptr = strchr(buf, 0x0a);
		if (ptr) {
			if (!too_long) {
				*ptr = 0;
				return buf;
			}
			// Reset and start with the next line
			too_long = 0;
			*lineno = *lineno + 1;
		} else {
			// If a line is too long skip it.
			// Only output 1 warning
			if (!too_long)
				fprintf(stderr, "Skipping line %u: too long\n",
								*lineno);
			too_long = 1;
		}
	}
	return NULL;
}


int do_delete_db(void)
{
	unlink_db();
	return 0;
}

/*
 * This function always requires at least one option, the command. We can
 * guarantee that argv[2] is the command because getopt_long would have
 * printed an error otherwise. argv[3] would be an optional parameter based
 * on which command is being run.
 *
 * The function returns 0 on success and -1 on failure
 */
int do_manage_files(int argc, char * const argv[])
{
	int rc = 0;

	if (strcmp("add", argv[2]) == 0) {
		if (argc != 4)
			goto args_err;

		rc = file_append(argv[3]);
		if (rc)
			rc = 1; // simplify return code
	} else if (strcmp("delete", argv[2]) == 0) {
		if (argc != 4)
			goto args_err;

		rc = file_delete(argv[3]);
	} else if (strcmp("update", argv[2]) == 0) {
		if (argc == 4)
			rc = file_update(argv[3]);
		 else
			rc = file_update("/");

	}

	return rc;

args_err:
	fprintf(stderr, "Wrong number of arguments\n\n");
	fprintf(stderr, "%s", usage);

	return 1;
}


int do_ftype(const char *path)
{
	int fd;
	magic_t magic_cookie;
	const char *ptr;
	struct stat sb;

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		printf("Cannot open %s - %s\n", path, strerror(errno));
		exit(1);
	}

	unsetenv("MAGIC");
	magic_cookie = magic_open(MAGIC_MIME|MAGIC_ERROR|MAGIC_NO_CHECK_CDF|
						  MAGIC_NO_CHECK_ELF);
	if (magic_cookie == NULL) {
		printf("Unable to init libmagic");
		close(fd);
		return 1;
	}
	if (magic_load(magic_cookie,
			"/usr/share/fapolicyd/fapolicyd-magic.mgc:"
			"/usr/share/misc/magic.mgc") != 0) {
		printf("Unable to load magic database");
		close(fd);
		magic_close(magic_cookie);
		return 1;
	}
	fstat(fd, &sb);
	uint32_t elf = gather_elf(fd, sb.st_size);
	if (elf)
		ptr = classify_elf_info(elf, path);
	else
		ptr = magic_descriptor(magic_cookie, fd);
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


int do_list(void)
{
	unsigned count = 1, lineno = 0;
	char buf[160];
	FILE *f = fopen(RULES_FILE, "rm");
	if (f == NULL) {
		fprintf(stderr, "Cannot open rules file (%s)\n",
						strerror(errno));
		return 1;
	}
	while (get_line(f, buf, sizeof(buf), &lineno)) {
		char *str = buf;
		lineno++;
		while (*str) {
			if (!isblank(*str))
				break;
			str++;
		}
		if (*str == 0) // blank line
			continue;
		if (*str == '#') //comment line
			continue;
		printf("%u. %s\n", count, buf);
		count++;
	}
	fclose(f);
	return 0;
}


int do_update(void)
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

	if (argc > 5)
		goto args_err;

	opt = getopt_long(argc, argv, "df:ht:lu",
				 long_opts, &option_index);
	switch (opt) {
	case 'd':
		if (argc > 2)
			goto args_err;
		rc = do_delete_db();
		break;
	case 'f':
		if (argc > 4)
			goto args_err;
		rc = do_manage_files(argc, argv);
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

