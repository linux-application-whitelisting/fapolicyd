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
#include <ctype.h>
#include <stdio.h>
#include <stdatomic.h>
#include <stddef.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syslog.h>
#include <sys/syslog.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>
#include <spawn.h>
#include <fcntl.h>
#include <errno.h>
#include <rpm/rpmlib.h>
#include <rpm/rpmts.h>
#include <rpm/rpmmacro.h>
#include <rpm/rpmlog.h>
#include <rpm/rpmdb.h>
#include <rpm/rpmpgp.h>
#include <fnmatch.h>
#include <sys/mman.h>

#include <uthash.h>

#include "message.h"
#include "gcc-attributes.h"
#include "fd-fgets.h"
#include "fapolicyd-backend.h"

#include "filter.h"
#include "file.h"


extern atomic_bool stop;

int do_rpm_init_backend(void);
int do_rpm_load_list(const conf_t *, int memfd);
int do_rpm_destroy_backend(void);

static int rpm_init_backend(void);
static int rpm_load_list(const conf_t *);
static int rpm_destroy_backend(void);

backend rpm_backend =
{
	"rpmdb",
	rpm_init_backend,
	rpm_load_list,
	rpm_destroy_backend,
	-1,
	-1,
};

static rpmts ts = NULL;
static rpmdbMatchIterator mi = NULL;

static int init_rpm(void)
{
	return rpmReadConfigFiles ((const char *)NULL, (const char *)NULL);
}

static Header h = NULL;
static int get_next_package_rpm(void)
{
	// If this is the first time, create a package iterator
	if (mi == NULL) {
		ts = rpmtsCreate();
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

static const char *get_file_name_rpm(void)
{	// Copy is made because the linked list takes custody of it
	// FIXME: if the linked list ever goes away, remove strdup
	return strdup(rpmfiFN(fi));
}

static rpm_loff_t get_file_size_rpm(void)
{
	return rpmfiFSize(fi);
}

static char *get_sha256_rpm(int *len)
{
	// The rpm database has SHA512, SHA26, and SHA1 hashes. This uses
	// a static buffer to avoid a short lived malloc/free cycle.
	static char sha[SHA512_LEN * 2 + 1];
	const unsigned char *digest;
	size_t tlen = 0;

	// This gets the binary form of the hash.
	digest = rpmfiFDigest(fi, NULL, &tlen);
	if (digest && tlen) // clip to sha512 size.
		bytes2hex(sha, digest, tlen > SHA512_LEN ? SHA512_LEN : tlen);
	else
		sha[0] = 0;

	// Return the length to avoid a strlen call later.
	*len = 2*tlen;
	return sha;
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

#define BUFFER_SIZE 4096
#define MAX_DELIMS 3
static int rpm_load_list(const conf_t *conf)
{
	// before the spawn
	int sv[2];
	if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv) < 0) {
		msg(LOG_ERR, "socketpair failed");
		exit(1);
	}

	posix_spawn_file_actions_t actions;
	posix_spawn_file_actions_init(&actions);

	// child sees sv[1] as FD 3 (arbitrary but fixed)
	posix_spawn_file_actions_adddup2(&actions, sv[1], 3);
	posix_spawn_file_actions_addclose(&actions, sv[0]);
	posix_spawn_file_actions_addclose(&actions, sv[1]);

	char *argv[] = { "fapolicyd-rpm-loader", NULL };
	char *custom_env[] = { "FAPO_SOCK_FD=3", NULL };

	pid_t pid = -1;
	int status = posix_spawn(&pid, "/usr/bin/fapolicyd-rpm-loader",
					 &actions, NULL, argv, custom_env);
	close(sv[1]);  // Parent doesn't write

	if (status == 0) {
		msg(LOG_DEBUG, "fapolicyd-rpm-loader spawned with pid: %d",pid);

		struct msghdr  _msg  = {0};
		struct iovec   iov = { .iov_base = (char[1]){0}, .iov_len = 1 };
		union {
			struct cmsghdr align;
			char buf[CMSG_SPACE(sizeof(int))];
		} cmsgbuf;

		_msg.msg_iov    = &iov;
		_msg.msg_iovlen = 1;
		_msg.msg_control = cmsgbuf.buf;
		_msg.msg_controllen = sizeof cmsgbuf.buf;

		if (recvmsg(sv[0], &_msg, 0) < 0) {
			msg(LOG_ERR, "recvmesg failed");
			exit(1);
		}
		close(sv[0]);

		struct cmsghdr *c = CMSG_FIRSTHDR(&_msg);
		if (!c || c->cmsg_type != SCM_RIGHTS) {
			msg(LOG_ERR, "missing fd");
			exit(1);
		}

		int memfd;
		memcpy(&memfd, CMSG_DATA(c), sizeof memfd);

		// Mark entries unknown until a fresh snapshot is available.
		rpm_backend.entries = -1;

		if (fcntl(memfd, F_SETFD, FD_CLOEXEC) == -1) {
			char err_buff[BUFFER_SIZE];
			msg(LOG_WARNING,
			    "Failed to set CLOEXEC on rpm memfd (%s)",
			    strerror_r(errno, err_buff, BUFFER_SIZE));
		}

		// Pass the memfd to the backend representation
		rpm_backend.memfd = memfd;

		waitpid(pid, NULL, 0);
	} else
		msg(LOG_ERR, "posix_spawn failed: %s\n", strerror(status));

	posix_spawn_file_actions_destroy(&actions);

	return 0;
}

// this function is used in fapolicyd-rpm-loader
extern unsigned int debug_mode;
int do_rpm_load_list(const conf_t *conf, int memfd)
{
	int rc;
	unsigned int msg_count = 0;
	unsigned int tsource = SRC_RPM;

	// hash table
	struct _hash_record *hashtable = NULL;
	long entries = 0;

	if (memfd < 0) {
		msg(LOG_ERR, "Invalid memfd supplied to rpm loader");
		return 1;
	}

	msg(LOG_INFO, "Loading rpmdb backend");
	if ((rc = init_rpm())) {
		msg(LOG_ERR, "init_rpm() failed (%d)", rc);
		return rc;
	}

	// Loop across the rpm database
	while (!stop && get_next_package_rpm()) {
		// Loop across the packages
		while (!stop && get_next_file_rpm()) {
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
			if (file_name == NULL)
				continue;

			// should we drop a path?
			filter_rc_t f_res = filter_check(file_name);
			if (f_res != FILTER_ALLOW) {
				free((void *)file_name);
				if (f_res == FILTER_ERR_DEPTH)
					return FILTER_ERR_DEPTH;
				continue;
			}

			rpm_loff_t sz = get_file_size_rpm();
			int len;
			const char *sha = get_sha256_rpm(&len);
			char *data;

			// RPMs may use SHA256 or stronger digests. Filter out
			// short digests (including SHA1) while accepting
			// anything 64 characters or longer.
			if (len < 64) {
				// Limit this to 5 if production
				if (debug_mode || msg_count++ < 5) {
					msg(LOG_WARNING,
					    "No acceptable digest for %s",
					    file_name);
				}

				// skip the entry if there is no acceptable hash
				if (conf && conf->rpm_sha256_only) {
					free((void *)file_name);
					continue;
				}
			}

			// We use asprintf here so that we can reuse existing
			// cleanup paths and avoid manual buffer management.
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
					rcd = (struct _hash_record*)
					     malloc(sizeof(struct _hash_record));
					rcd->key = strdup(key);
					HASH_ADD_KEYPTR( hh, hashtable,
							 rcd->key,
							 strlen(rcd->key),
							  rcd );
					if (dprintf(memfd, "%s %s\n",
						    file_name, data) < 0) {
						msg(LOG_ERR,
						    "dprintf failed writing %s to memfd (%s)",
						    file_name,
						    strerror(errno));
						free((void*)file_name);
						free((void*)data);
						rc = 1;
						goto out;
					}
					entries++;
					free((void*)file_name);
					free((void*)data);
				} else {
					free((void*)file_name);
					free((void*)data);
				}
			} else {
				free((void*)file_name);
			}
		}
	}

	rc = 0;
out:
	close_rpm();

	// cleaning up
	struct _hash_record *item, *tmp;
	HASH_ITER( hh, hashtable, item, tmp) {
		   HASH_DEL( hashtable, item );
		free((void*)item->key);
		free((void*)item);
	}

	if (rc == 0)
		rpm_backend.entries = entries;

	return rc;
}

static int rpm_init_backend(void)
{
	return 0;
}

// this function is used in fapolicyd-rpm-loader
int do_rpm_init_backend(void)
{

	if (filter_init())
		return 1;

	if (filter_load_file(NULL)) {
		filter_destroy();
		return 1;
	}

	return 0;
}

static int rpm_destroy_backend(void)
{
	return 0;
}

// this function is used in fapolicyd-rpm-loader
int do_rpm_destroy_backend(void)
{
	filter_destroy();
	return 0;
}
