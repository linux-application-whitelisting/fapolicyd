/*
 * md5-backend.c - functions for adding files to the trust database
 * based on MD5 hashes.
 * Copyright (c) 2023-26 Red Hat Inc.
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
 *   Stephen Tridgell
 *   Matt Jolly <Matt.Jolly@footclan.ninja>
 */
#include "config.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <sys/stat.h>
#include <sys/syslog.h>
#include <sys/types.h>

#include "file.h"
#include "fapolicyd-backend.h"
#include "message.h"
#include "md5-backend.h"

/*
 * Given a path to a file with an expected MD5 digest, add
 * the file to the trust database if it matches.
 *
 * Dpkg does not provide sha256 sums or file sizes to verify against.
 * The only source for verification is MD5. The logic implemented is:
 * 1) Calculate the MD5 sum and compare to the expected hash. If it does
 *    not match, skip the file.
 * 2) Calculate the SHA256 and file size on the local files.
 * 3) Add to database.
 *
 * Security considerations:
 * An attacker would need to craft a file with a MD5 hash collision.
 * While MD5 is considered broken, this is still some effort.
 * This function would compute a sha256 and file size on the attackers
 * crafted file so they do not secure this backend.
 *
 * Returns MD5_BACKEND_ADDED when the file was recorded or already present,
 * MD5_BACKEND_SKIPPED for per-file conditions expected from dpkg state drift,
 * and MD5_BACKEND_FATAL when the backend snapshot is unsafe to use.
 */
md5_backend_result_t add_file_to_backend_by_md5(const char *path,
			       const char *expected_md5,
			       struct _hash_record **hashtable,
			       trust_src_t trust_src, backend *dstbackend)
{

	if (path == NULL || expected_md5 == NULL || hashtable == NULL ||
	    dstbackend == NULL || dstbackend->memfd < 0) {
		msg(LOG_ERR, "Invalid MD5 backend destination for %s",
		    path ? path : "(null)");
		return MD5_BACKEND_FATAL;
	}

	#ifdef DEBUG
	msg(LOG_DEBUG, "Adding %s", path);
	msg(LOG_DEBUG, "\tExpected MD5: %s", expected_md5);
	#endif

	int fd = open(path, O_RDONLY|O_NOFOLLOW);
	struct stat path_stat;
	if (fd < 0) {
		if (errno != ELOOP) // Don't report symlinks as a warning
			msg(LOG_WARNING, "Could not open %s, %s", path,
			    strerror(errno));
		return MD5_BACKEND_SKIPPED;
	}

	if (fstat(fd, &path_stat)) {
		close(fd);
		msg(LOG_WARNING, "fstat file %s failed %s", path,
		    strerror(errno));
		return MD5_BACKEND_SKIPPED;
	}

	// If its not a regular file, skip.
	if (!S_ISREG(path_stat.st_mode)) {
		close(fd);
		msg(LOG_DEBUG, "Not regular file %s", path);
		return MD5_BACKEND_SKIPPED;
	}

	off_t file_size = path_stat.st_size;
	trustdb_size_t stored_size;

	if (trustdb_size_from_signed((intmax_t)file_size, &stored_size)) {
		close(fd);
		msg(LOG_ERR, "File size for %s exceeds trust DB format", path);
		return MD5_BACKEND_FATAL;
	}

	#ifdef DEBUG
	msg(LOG_DEBUG, "\tFile size: %jd", (intmax_t)file_size);
	#endif

	char *md5_digest = get_hash_from_fd2(fd, file_size,
		FILE_HASH_ALG_MD5);
	if (md5_digest == NULL) {
		close(fd);
		msg(LOG_ERR, "MD5 digest returned NULL");
		return MD5_BACKEND_FATAL;
	}
	if (strcmp(md5_digest, expected_md5) != 0) {
		msg(LOG_WARNING, "Skipping %s: hash mismatch. Got %s, expected %s",
				path, md5_digest, expected_md5);
		close(fd);
		free(md5_digest);
		return MD5_BACKEND_SKIPPED;
	}
	free(md5_digest);

	// It's OK so create a sha256 of the file
	char *sha_digest = get_hash_from_fd2(fd, file_size,
		FILE_HASH_ALG_SHA256);
	close(fd);

	if (sha_digest == NULL) {
		msg(LOG_ERR, "Sha digest returned NULL");
		return MD5_BACKEND_FATAL;
	}

	char *data;
	if (asprintf(&data, DATA_FORMAT, trust_src, stored_size,
		    sha_digest) == -1) {
		msg(LOG_ERR, "Out of memory formatting trust data for %s", path);
		free(sha_digest);
		return MD5_BACKEND_FATAL;
	}
	free(sha_digest);

	// Getting rid of the duplicates.
	struct _hash_record *rcd = NULL;
	char *key = NULL;

	if (asprintf(&key, "%s %s", path, data) == -1) {
		msg(LOG_ERR, "Out of memory tracking %s", path);
		free((void *)data);
		return MD5_BACKEND_FATAL;
	}

	HASH_FIND_STR(*hashtable, key, rcd);

	if (!rcd) {
		rcd = (struct _hash_record *)malloc(
					sizeof(struct _hash_record));
		if (rcd == NULL) {
			msg(LOG_ERR, "Out of memory tracking %s", path);
			free(key);
			free((void *)data);
			return MD5_BACKEND_FATAL;
		}
		rcd->key = key;
		if (dprintf(dstbackend->memfd, "%s %s\n",
			    path, data) < 0) {
			msg(LOG_ERR,
			    "dprintf failed writing %s to memfd (%s)",
			    path, strerror(errno));
			free(key);
			free(rcd);
			free((void *)data);
			return MD5_BACKEND_FATAL;
		}
		HASH_ADD_KEYPTR(hh, *hashtable, rcd->key,
				strlen(rcd->key), rcd);
	} else {
		free(key);
	}
	free((void *)data);
	return MD5_BACKEND_ADDED;
}
