/*
 * rpm-backend.c - rpm backend
 * Copyright (c) 2020 Red Hat Inc.
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
 */

#include "config.h"
#include <stdio.h>
#include <stdatomic.h>
#include <stddef.h>
#include <string.h>
#include <sys/syslog.h>
#include <sys/syslog.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <unistd.h>
#include <fcntl.h>
#include <rpm/rpmlib.h>
#include <rpm/rpmts.h>
#include <rpm/rpmmacro.h>
#include <rpm/rpmlog.h>
#include <rpm/rpmdb.h>
#include <rpm/rpmpgp.h>
#include <fnmatch.h>

#include <uthash.h>

#include "message.h"
#include "gcc-attributes.h"
#include "fapolicyd-backend.h"
#include "llist.h"

#include "filter.h"

static int rpm_init_backend(void);
static int rpm_load_list(const conf_t *);
static int rpm_destroy_backend(void);

volatile atomic_bool ongoing_rpm_operation = 0;

backend rpm_backend =
{
	"rpmdb",
	rpm_init_backend,
	rpm_load_list,
	rpm_destroy_backend,
	/* list initialization */
	{ 0, 0, NULL },
};

#ifdef RPM_DB_PATH
const char *rpm_dir_path = RPM_DB_PATH;
#else
const char *rpm_dir_path = "/usr/lib/sysimage/rpm";
#endif
ssize_t rpm_dir_path_len = -1;


static size_t fd_buffer_size = 0;
static size_t fd_buffer_pos = 0;
static int *fd_buffer = NULL;

#define MIN_BUFFER_SIZE 512
static int init_fd_buffer(void) {
	struct rlimit limit;
	getrlimit(RLIMIT_NOFILE, &limit);

	fd_buffer_size = limit.rlim_cur / 4;
	if (fd_buffer_size < MIN_BUFFER_SIZE)
		fd_buffer_size = MIN_BUFFER_SIZE;

	fd_buffer = malloc(fd_buffer_size * sizeof(int));
	if (!fd_buffer)
		return 1;

	for(size_t i = 0 ; i < fd_buffer_size; i++)
		fd_buffer[i] = -1;

	msg(LOG_DEBUG, "FD buffer size set to: %ld",  fd_buffer_size);
	return 0;
}

int push_fd_to_buffer(int fd) {

	if (!fd_buffer) {
		msg(LOG_ERR, "FD buffer already freed!");
		return 1;
	}
	if (fd_buffer_pos < fd_buffer_size) {
		msg(LOG_DEBUG, "Pushing to FD buffer(%ld), ocupancy: %ld", fd_buffer_size,  fd_buffer_pos);
		fd_buffer[fd_buffer_pos++] = fd;
		return 0;
	}

	msg(LOG_ERR, "FD buffer full");
	return 1;
}

static void close_fds_in_buffer(void) {
	if (fd_buffer_pos)
		msg(LOG_DEBUG, "Closing FDs from buffer, size: %ld",  fd_buffer_pos);
	for (size_t i = 0 ; i < fd_buffer_pos ; i++) {
		close(fd_buffer[i]);
		fd_buffer[i] = -1;
	}

	fd_buffer_pos = 0;
}

static void destroy_fd_buffer(void) {

	if (!fd_buffer)
		return;

	free(fd_buffer);
	fd_buffer = NULL;
	fd_buffer_size = -1;
}

static rpmts ts = NULL;
static rpmtxn txn = NULL;
static rpmdbMatchIterator mi = NULL;

static int init_rpm(void)
{
	return rpmReadConfigFiles ((const char *)NULL, (const char *)NULL);
}

static Header h = NULL;
#define MAX_RETRIES 3
static int get_next_package_rpm(int *error)
{
	// If this is the first time, create a package iterator
	if (mi == NULL) {
		ts = rpmtsCreate();

		int stderr_fd = dup(fileno(stderr)); // Duplicate stderr
		int stdin_fd = dup(fileno(stdin)); // Duplicate stdin

		int devnull = open("/dev/null", O_WRONLY);
		int devnontty = open("/dev/null", O_RDONLY);

		if (devnull == -1 || stderr_fd == -1 || devnontty == -1 || stdin_fd == -1 )
			return 0;

		// supress messages from rpmdb in stderr
		dup2(devnull, fileno(stderr)); // Redirect stderr to /dev/null

		// force rpm lib to use nonblocking waiting
		// it checks for isatty(STDIN_FILENO) == 0
		dup2(devnontty, fileno(stdin)); // Redirect stdin to non pty device /dev/null

		close(devnull);
		close(devnontty);

		int i = 0;
		while (1) {
			txn = rpmtxnBegin(ts, 0);

			msg(LOG_DEBUG, "Waiting for RPM transaction lock");

			if (txn == NULL) {
				if (i < MAX_RETRIES)
					sleep(1);
			} else {
				break;
			}

			if (i >= MAX_RETRIES)
				break;
			i++;
		}

		dup2(stderr_fd, fileno(stderr)); // Restore stderr
		dup2(stdin_fd, fileno(stdin)); // Restore stdin
		close(stderr_fd);
		close(stdin_fd);

		if (txn == NULL) {
			*error = 1;
			return 0;
		}

		msg(LOG_DEBUG, "Got rpmdb lock on %d iterations", i);

		mi = rpmtsInitIterator(ts, RPMDBI_PACKAGES, NULL, 0);
		if (mi == NULL)
			return 0;
	}

	if (h)	// Decrement reference count, and free memory
		headerFree(h);

	h = rpmdbNextIterator(mi);
	if (h == NULL)
		return 0;	// No more packages, done

	// Increment reference count
	headerLink(h);

	return 1;
}

static rpmfi fi = NULL;
static int get_next_file_rpm(void)
{
	// If its the first time, make file iterator
	if (fi == NULL)
		fi = rpmfiNew(NULL, h, RPMTAG_BASENAMES, RPMFI_KEEPHEADER);

	if (fi) {
		if (rpmfiNext(fi) == -1) {
			// No more files, cleanup iterator
			rpmfiFree(fi);
			fi = NULL;
			return 0;
		}
        }
	return 1;
}

// Like strdup, but sets a minimum size for safety
static inline char *strmdup(const char *s, size_t min) __attr_dealloc_free;
static inline char *strmdup(const char *s, size_t min)
{
	char *new;
	size_t len = strlen(s) + 1;

	new = malloc(len < min ? min : len);
	if (new == NULL)
		return NULL;

	return (char *)memcpy(new, s, len);
}

static const char *get_file_name_rpm(void)
{
	return strmdup(rpmfiFN(fi), 7);
}

static rpm_loff_t get_file_size_rpm(void)
{
	return rpmfiFSize(fi);
}

static char *get_sha256_rpm(void)
{
	return rpmfiFDigestHex(fi, NULL);
}

static int is_dir_link_rpm(void)
{
	mode_t mode = rpmfiFMode(fi);
	if (S_ISDIR(mode) || S_ISLNK(mode))
		return 1;
	return 0;
}

/* We don't want doc files in the database */
static int is_doc_rpm(void)
{
	if (rpmfiFFlags(fi) & (RPMFILE_DOC|RPMFILE_README|
				RPMFILE_GHOST|RPMFILE_LICENSE|RPMFILE_PUBKEY))
		return 1;
	return 0;
}

/* Config files can have a changed hash. We want them in the db since
 * they are trusted. */
static int is_config_rpm(void)
{
	if (rpmfiFFlags(fi) &
		(RPMFILE_CONFIG|RPMFILE_MISSINGOK|RPMFILE_NOREPLACE))
		return 1;
	return 0;
}

static void close_rpm(void)
{
	rpmfiFree(fi);
	fi = NULL;
	headerFree(h);
	h = NULL;
	rpmdbFreeIterator(mi);
	mi = NULL;
	rpmtxnEnd(txn);
	txn = NULL;
	rpmtsFree(ts);
	ts = NULL;
	rpmFreeCrypto();
	rpmFreeRpmrc();
	rpmFreeMacros(NULL);
	rpmlogClose();
}

struct _hash_record {
	const char * key;
	UT_hash_handle hh;
};

extern unsigned int debug_mode;
static int rpm_load_list(const conf_t *conf)
{
	int rc;
	int error = 0;
	unsigned int msg_count = 0;
	unsigned int tsource = SRC_RPM;

	// empty list before loading
	list_empty(&rpm_backend.list);

	// hash table
	struct _hash_record *hashtable = NULL;

	ongoing_rpm_operation = 1;

	msg(LOG_INFO, "Loading rpmdb backend");
	if ((rc = init_rpm())) {
		msg(LOG_ERR, "init_rpm() failed (%d)", rc);
		return rc;
	}

	// Loop across the rpm database
	while (get_next_package_rpm(&error)) {
		// Loop across the packages
		while (get_next_file_rpm()) {
			// We do not want directories or symlinks in the
			// database. Multiple packages can own the same
			// directory and that causes problems in the size info.
			if (is_dir_link_rpm())
				continue;

			// We do not want any documentation in the database
			if (is_doc_rpm())
				continue;

			// We do not want any configuration files in database
			if (is_config_rpm())
				continue;

			// Get specific file information
			const char *file_name = get_file_name_rpm();
			rpm_loff_t sz = get_file_size_rpm();
			const char *sha = get_sha256_rpm();
			char *data;

			if (file_name == NULL)
				continue;

			// should we drop a path?
			if (!filter_check(file_name)) {
				free((void *)file_name);
				free((void *)sha);
				continue;
			}

			if (strlen(sha) != 64) {
				// Limit this to 5 if production
				if (debug_mode || msg_count++ < 5) {
					msg(LOG_WARNING, "No SHA256 for %s",
							    file_name);
				}

				// skip the entry if there is no sha256
				if (conf && conf->rpm_sha256_only) {
					free((void *)file_name);
					free((void *)sha);
					continue;
				}
			}

			if (asprintf(	&data,
					DATA_FORMAT,
					tsource,
					sz,
					sha) == -1) {
				data = NULL;
			}

			if (data) {
				// getting rid of the duplicates
				struct _hash_record *rcd = NULL;
				char key[4096];
				snprintf(key, 4095, "%s %s", file_name, data);

				HASH_FIND_STR( hashtable, key, rcd );

				if (!rcd) {
					rcd = (struct _hash_record*) malloc(sizeof(struct _hash_record));
					rcd->key = strdup(key);
					HASH_ADD_KEYPTR( hh, hashtable, rcd->key, strlen(rcd->key), rcd );
					list_append(&rpm_backend.list, file_name, data);
				} else {
					free((void*)file_name);
					free((void*)data);
				}
			} else {
				free((void*)file_name);
			}
			free((void *)sha);
		}
	}

	close_rpm();

	ongoing_rpm_operation = 0;
	close_fds_in_buffer();

	// cleaning up
	struct _hash_record *item, *tmp;
	HASH_ITER( hh, hashtable, item, tmp) {
		HASH_DEL( hashtable, item );
		free((void*)item->key);
		free((void*)item);
	}

	if (error) {
		msg(LOG_INFO, "Could not acquire lock for rpmdb, staying with old db");
		return 1;
	}

	return 0;
}

static int rpm_init_backend(void)
{
	// first time initialization
	// we need to be sure following is not called when reloading backend
	if (rpm_dir_path_len == -1) {
		rpm_dir_path_len = strlen(rpm_dir_path);

		if(init_fd_buffer()) {
			return 1;
		}

		if (filter_init()) {
			destroy_fd_buffer();
			return 1;
		}

		if (filter_load_file()) {
			filter_destroy();
			destroy_fd_buffer();
			return 1;
		}
	}

	list_init(&rpm_backend.list);

	return 0;
}


extern volatile atomic_bool stop;
static int rpm_destroy_backend(void)
{
	list_empty(&rpm_backend.list);
	// for sure
	close_fds_in_buffer();

	// just in case fapolicyd is going down
	if (stop) {
		filter_destroy();
		destroy_fd_buffer();
	}
	return 0;
}
