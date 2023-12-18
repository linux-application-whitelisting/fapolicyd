/*
 * md5-backend.c - functions for adding files to the trust database
 * based on MD5 hashes.
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
 *    not match, abort.
 * 2) Calculate the SHA256 and file size on the local files.
 * 3) Add to database.
 *
 * Security considerations:
 * An attacker would need to craft a file with a MD5 hash collision.
 * While MD5 is considered broken, this is still some effort.
 * This function would compute a sha256 and file size on the attackers
 * crafted file so they do not secure this backend.
 */
int add_file_to_backend_by_md5(const char *path,
							const char *expected_md5,
							struct _hash_record **hashtable,
							trust_src_t trust_src,
							backend *dstbackend)
{

	#ifdef DEBUG
	msg(LOG_DEBUG, "Adding %s", path);
	msg(LOG_DEBUG, "\tExpected MD5: %s", expected_md5);
	#endif

	int fd = open(path, O_RDONLY|O_NOFOLLOW);
	struct stat path_stat;
	if (fd < 0) {
		if (errno != ELOOP) // Don't report symlinks as a warning
			msg(LOG_WARNING, "Could not open %si, %s", path, strerror(errno));
		return 1;
	}

	if (fstat(fd, &path_stat)) {
		close(fd);
		msg(LOG_WARNING, "fstat file %s failed %s", path, strerror(errno));
		return 1;
	}

	// If its not a regular file, skip.
	if (!S_ISREG(path_stat.st_mode)) {
		close(fd);
		msg(LOG_DEBUG, "Not regular file %s", path);
		return 1;
	}

	size_t file_size = path_stat.st_size;

	#ifdef DEBUG
	msg(LOG_DEBUG, "\tFile size: %zu", file_size);
	#endif

	char *md5_digest = get_hash_from_fd2(fd, file_size, 0);
	if (md5_digest == NULL) {
		close(fd);
		msg(LOG_ERR, "MD5 digest returned NULL");
		return 1;
	}
	if (strcmp(md5_digest, expected_md5) != 0) {
		msg(LOG_WARNING, "Skipping %s: hash mismatch. Got %s, expected %s",
				path, md5_digest, expected_md5);
		close(fd);
		free(md5_digest);
		return 1;
	}
	free(md5_digest);

	// It's OK so create a sha256 of the file
	char *sha_digest = get_hash_from_fd2(fd, file_size, 1);
	close(fd);

	if (sha_digest == NULL) {
		msg(LOG_ERR, "Sha digest returned NULL");
		return 1;
	}

	char *data;
	if (asprintf(&data, DATA_FORMAT, trust_src, file_size, sha_digest) == -1) {
		data = NULL;
	}
	free(sha_digest);

	if (data) {
		// Getting rid of the duplicates.
		struct _hash_record *rcd = NULL;
		char key[kMaxKeyLength];
		snprintf(key, kMaxKeyLength - 1, "%s %s", path, data);

		HASH_FIND_STR(*hashtable, key, rcd);

		if (!rcd) {
			rcd = (struct _hash_record *)malloc(sizeof(struct _hash_record));
			rcd->key = strdup(key);
			HASH_ADD_KEYPTR(hh, *hashtable, rcd->key, strlen(rcd->key), rcd);
			list_append(&dstbackend->list, strdup(path), data);
		} else {
			free((void *)data);
		}
		return 0;
	}
	return 1;
}
