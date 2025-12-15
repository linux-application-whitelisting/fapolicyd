/*
 * file.c - functions for accessing attributes of files
 * Copyright (c) 2016,2018-23 Red Hat Inc.
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
 *   Steve Grubb <sgrubb@redhat.com>
 */

#include "config.h"
#include <stdio.h>
#include <limits.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <magic.h>
#include <libudev.h>
#include <elf.h>
#include <sys/xattr.h>
#include <linux/hash_info.h>
#include <sys/mman.h>
#include <mntent.h>

#include "file.h"
#include "message.h"
#include "process.h" // For elf info bit mask
#include "string-util.h"

// Local defines
#define IMA_XATTR_DIGEST_NG 0x04	// security/integrity/integrity.h

// Local variables
static struct udev *udev;
magic_t magic_fast, magic_full;
struct cache { dev_t device; const char *devname; };
static struct cache c = { 0, NULL };

// Local declarations
static ssize_t safe_read(int fd, char *buf, size_t size)
				__attr_access ((__write_only__, 2, 3));
static char *get_program_cwd_from_pid(pid_t pid, size_t blen, char *buf)
				__attr_access ((__write_only__, 3, 2));
static void resolve_path(const char *pcwd, char *path, size_t len)
				__attr_access ((__write_only__, 2, 3));

// readelf -l path-to-app | grep 'Requesting' | cut -d':' -f2 | tr -d ' ]';
static const char *interpreters[] = {
	"/lib64/ld-linux-x86-64.so.2",
	"/lib/ld-linux.so.2",			// i686
	"/usr/lib64/ld-linux-x86-64.so.2",
	"/usr/lib/ld-linux.so.2",		// i686
	"/lib/ld.so.2",
	"/lib/ld-linux-armhf.so.3",		// fedora armv7hl
	"/lib/ld-linux-aarch64.so.1",		// fedora aarch64
	"/lib/ld64.so.1",			// rhel8 s390x
	"/lib64/ld64.so.2",			// rhel8 ppc64le
};
#define MAX_INTERPS (sizeof(interpreters)/sizeof(interpreters[0]))


// Define a convience function to rewind a descriptor to the beginning
static inline void rewind_fd(int fd)
{
	lseek(fd, 0, SEEK_SET);
}


// Initialize what we can now so that its not done each call
void file_init(void)
{
	// Setup udev
	udev = udev_new();

	// Setup libmagic
	unsetenv("MAGIC");
	// Fast magic: minimal rules, all expensive checks disabled
	magic_fast = magic_open(
		MAGIC_MIME |
		MAGIC_ERROR |
		MAGIC_NO_CHECK_CDF |
		MAGIC_NO_CHECK_ELF |
		MAGIC_NO_CHECK_COMPRESS |  /* Don't decompress */
		MAGIC_NO_CHECK_TAR |
		MAGIC_NO_CHECK_SOFT |      /* Skip soft magic (text analysis) */
		MAGIC_NO_CHECK_APPTYPE |
		MAGIC_NO_CHECK_ENCODING |  /* Skip charset detection */
		MAGIC_NO_CHECK_TOKENS |    /* Skip text tokens */
		MAGIC_NO_CHECK_JSON        /* Skip JSON validation */
		);
	if (magic_fast == NULL) {
		msg(LOG_ERR, "Unable to init libmagic");
		exit(1);
	}

	// Load only essential magic rules
	if (magic_load(magic_fast, MAGIC_PATH) != 0) {
		msg(LOG_ERR, "Unable to load fast magic database");
		exit(1);
	}

	// Full magic: normal operation
	magic_full = magic_open(MAGIC_MIME|MAGIC_ERROR|MAGIC_NO_CHECK_CDF|
			MAGIC_NO_CHECK_ELF);
	if (magic_full == NULL) {
		msg(LOG_ERR, "Unable to init libmagic");
		exit(1);
	}
	// System default
	if (magic_load(magic_full, NULL) != 0) {
		msg(LOG_ERR, "Unable to load default magic database");
		exit(1);
	}
}


// Release memory during shutdown
void file_close(void)
{
	udev_unref(udev);
	magic_close(magic_fast);
	magic_close(magic_full);
	free((void *)c.devname);
}


/*
 * file_hash_length - return the binary digest size for the algorithm.
 * @alg: file digest algorithm to query.
 * Returns the digest length in bytes, or 0 when the algorithm is unknown.
 */
size_t file_hash_length(file_hash_alg_t alg)
{
	switch (alg) {
	case FILE_HASH_ALG_MD5:
		return MD5_LEN;
	case FILE_HASH_ALG_SHA1:
		return SHA1_LEN;
	case FILE_HASH_ALG_SHA256:
		return SHA256_LEN;
	case FILE_HASH_ALG_SHA512:
		return SHA512_LEN;
	default:
		break;
	}
	return 0;
}


/*
 * file_hash_alg - return the algorith for the digest size.
 * @len: the digest length to query.
 * Returns the digest algorithm.
 */
file_hash_alg_t file_hash_alg(unsigned len)
{
	// Ordered most probable to least likely
	switch (len) {
	case SHA256_LEN * 2:
		return FILE_HASH_ALG_SHA256;
	case SHA512_LEN * 2:
		return FILE_HASH_ALG_SHA512;
	case MD5_LEN * 2:
		return FILE_HASH_ALG_MD5;
	case SHA1_LEN * 2:
		return FILE_HASH_ALG_SHA1;
	}
	return FILE_HASH_ALG_NONE;
}

/*
 * file_hash_alg_fast - return the algorith for the digest size
 * O(1) – no strlen, no scanning
 * @digest: the digest to query.
 * Returns the digest algorithm.
 */
file_hash_alg_t file_hash_alg_fast(const char *digest)
{
    /* cautious access: check shorter offsets first */
    if (!digest)
	return FILE_HASH_ALG_NONE;

    /* MD5 is 32 hex chars */
    if (!digest[MD5_LEN*2])
	return FILE_HASH_ALG_MD5;

    /* SHA1 is 40 hex chars */
    if (!digest[SHA1_LEN*2])
	return FILE_HASH_ALG_SHA1;

    /* SHA-256 is 64 hex chars */
    if (!digest[SHA256_LEN*2])
	return FILE_HASH_ALG_SHA256;

    /* SHA-512 is 128 hex chars */
    if (!digest[SHA512_LEN*2])
	return FILE_HASH_ALG_SHA512;

    return FILE_HASH_ALG_NONE;
}

/*
 * file_info_reset_digest - clear cached digest metadata for a file record.
 * @info: cached file entry to sanitize.
 */
void file_info_reset_digest(struct file_info *info)
{
	if (info == NULL)
		return;

	info->digest_alg = FILE_HASH_ALG_NONE;
	info->digest[0] = 0;
}


/*
 * file_info_cache_digest - persist digest metadata alongside cached files.
 * @info: cached file entry to update.
 * @alg: algorithm used to generate the cached digest.
 * The binary digest length can be derived from file_hash_length(@alg) on
 * demand, so it is not cached alongside the algorithm selection.
 */
void file_info_cache_digest(struct file_info *info, file_hash_alg_t alg)
{
	if (info == NULL)
		return;

	info->digest_alg = alg;
}

static const char *hash_prefixes[] =
{
	NULL,		// FILE_HASH_ALG_NONE
	"md5",
	"sha1",
	"sha256",
	"sha512",
};

/*
 * ima_algo_desc - Associate kernel IMA identifiers with local hashing enums.
 * @ima_alg: Algorithm identifier stored in the IMA digest-ng header.
 * @alg:     Local file hashing algorithm used when recomputing the digest.
 * @digest_len: Binary digest length for @alg.
 */
struct ima_algo_desc {
	uint8_t ima_alg;
	file_hash_alg_t alg;
	size_t digest_len;
};

static const struct ima_algo_desc ima_algo_map[] = {
	{ HASH_ALGO_MD5, FILE_HASH_ALG_MD5, MD5_LEN },
	{ HASH_ALGO_SHA1, FILE_HASH_ALG_SHA1, SHA1_LEN },
	{ HASH_ALGO_SHA256, FILE_HASH_ALG_SHA256, SHA256_LEN },
	{ HASH_ALGO_SHA512, FILE_HASH_ALG_SHA512, SHA512_LEN },
};

/*
 * ima_lookup_algo - Translate an IMA digest-ng algorithm id to local metadata.
 * @ima_id: Numeric algorithm encoded in the xattr header.
 * Returns a pointer to the mapped description, or NULL when unsupported.
 */
static const struct ima_algo_desc *ima_lookup_algo(uint8_t ima_id)
{
	unsigned int i;

	for (i = 0; i < (sizeof(ima_algo_map)/sizeof(ima_algo_map[0])); i++) {
		if (ima_algo_map[i].ima_alg == ima_id)
			return &ima_algo_map[i];
	}

	return NULL;
}

const char *file_hash_alg_name(file_hash_alg_t alg)
{
	unsigned value = alg;
	if (alg > FILE_HASH_ALG_SHA512)
		return NULL;
	return hash_prefixes[value];
}

file_hash_alg_t file_hash_name_alg(const char *name)
{
	if (name == NULL || name[0] == 0)
		return FILE_HASH_ALG_NONE;

	if (name[0] == 'm')
	    return FILE_HASH_ALG_MD5;
	if (name[3] == '1')
		return FILE_HASH_ALG_SHA1;
	if (name[3] == '2')
		return FILE_HASH_ALG_SHA256;
	if (name[3] == '5')
		return FILE_HASH_ALG_SHA512;
	return FILE_HASH_ALG_NONE;
}


/*
 * stat_file_entry - populate a cached description of an open descriptor.
 * @fd: descriptor to stat for cache metadata.
 * Returns an allocated struct file_info on success, otherwise NULL.
 */
struct file_info *stat_file_entry(int fd)
{
	struct stat sb;

	if (fstat(fd, &sb) == 0) {
		struct file_info *info = malloc(sizeof(struct file_info));
		if (info == NULL)
			return info;

		info->device = sb.st_dev;
		info->inode = sb.st_ino;
		info->mode = sb.st_mode;
		info->size = sb.st_size;

		// Try to get the modified time. If its zero, then it
		// hasn't been modified. Revert to create time if no
		// modifications have been done.
		if (sb.st_mtim.tv_sec)
			info->time.tv_sec = sb.st_mtim.tv_sec;
		else
			info->time.tv_sec = sb.st_ctim.tv_sec;
		if (sb.st_mtim.tv_nsec)
			info->time.tv_nsec = sb.st_mtim.tv_nsec;
		else
			info->time.tv_nsec = sb.st_ctim.tv_nsec;
		file_info_reset_digest(info);
		return info;
	}
	return NULL;
}


// Returns 0 if equal and 1 if not equal
int compare_file_infos(const struct file_info *p1, const struct file_info *p2)
{
	if (p1 == NULL || p2 == NULL)
		return 1;

	/* Digest metadata is advisory and excluded from equality checks. */
	// Compare in the order to find likely mismatch first
//msg(LOG_DEBUG, "inode %ld %ld", p1->inode, p2->inode);
	if (p1->inode != p2->inode) {
//msg(LOG_DEBUG, "mismatch INODE");
		return 1;
	}
	if (p1->time.tv_nsec != p2->time.tv_nsec) {
//msg(LOG_DEBUG, "mismatch NANO");
		return 1;
	}
	if (p1->time.tv_sec != p2->time.tv_sec) {
//msg(LOG_DEBUG, "mismatch SEC");
		return 1;
	}
	if (p1->size != p2->size) {
//msg(LOG_DEBUG, "mismatch BLOCKS");
		return 1;
	}
	if (p1->device != p2->device) {
//msg(LOG_DEBUG, "mismatch DEV");
		return 1;
	}

	return 0;
}


/*
 * check_ignore_mount_noexec - ensure an ignored mount has the noexec flag.
 * @mounts_file: path to the mount table used to validate the entry.
 * @point: mount point path to examine.
 * Returns 1 when the mount exists and has noexec, 0 when the mount is present
 * but missing the flag, -1 when the mount point is not found, and -2 if the
 * mount table cannot be read.
 */
int check_ignore_mount_noexec(const char *mounts_file, const char *point)
{
	FILE *fp;
	struct mntent *ent;
	int found = 0;

	fp = setmntent(mounts_file, "r");
	if (fp == NULL) {
		msg(LOG_ERR, "Cannot read %s (%s)", mounts_file, strerror(errno));
		return -2;
	}

	while ((ent = getmntent(fp))) {
		if (strcmp(ent->mnt_dir, point) == 0) {
			found = 1;
			if (hasmntopt(ent, "noexec")) {
				endmntent(fp);
				return 1;
			}
			break;
		}
	}

	endmntent(fp);

	if (!found)
		return -1;

	return 0;
}

/*
 * iterate_ignore_mounts - walk through ignore_mounts entries and invoke a callback.
 * @ignore_list: comma separated list of mount points to process.
 * @callback: function invoked for each trimmed entry.
 * @user_data: opaque pointer passed to the callback on each invocation.
 * Returns 0 on success, 1 when memory allocation fails, or the first non-zero
 * value returned by the callback.
 */
int iterate_ignore_mounts(const char *ignore_list,
	int (*callback)(const char *mount, void *user_data), void *user_data)
{
	char *ptr, *saved, *tmp;

	if (ignore_list == NULL || callback == NULL)
		return 0;

	tmp = strdup(ignore_list);
	if (tmp == NULL)
		return 1;

	ptr = strtok_r(tmp, ",", &saved);
	while (ptr) {
		char *mount = fapolicyd_strtrim(ptr);

		if (*mount) {
			int rc = callback(mount, user_data);
			if (rc) {
				free(tmp);
				return rc;
			}
		}
		ptr = strtok_r(NULL, ",", &saved);
	}

	free(tmp);
	return 0;
}

/*
 * check_ignore_mount_warning - obtain shared warning text for ignore_mounts.
 * @mounts_file: path to the mount table used to validate entries.
 * @point: mount point path to examine.
 * @warning: updated with standardized warning text or NULL when not needed.
 * Returns the same codes as check_ignore_mount_noexec.
 */
int check_ignore_mount_warning(const char *mounts_file, const char *point,
	const char **warning)
{
	int rc;
	static const char warn_noexec[] =
		"ignore_mounts entry %1$s must be mounted noexec - it will be watched";
	static const char warn_missing[] =
		"ignore_mounts entry %1$s is not present in %2$s - it will be watched";
	static const char warn_unknown[] =
		"Cannot determine mount options for %1$s - it will be watched";

	rc = check_ignore_mount_noexec(mounts_file, point);
	if (warning)
		*warning = NULL;

	if (warning && rc != 1) {
		if (rc == 0)
			*warning = warn_noexec;
		else if (rc == -1)
			*warning = warn_missing;
		else if (rc < -1)
			*warning = warn_unknown;
	}

	return rc;
}


static char *get_program_cwd_from_pid(pid_t pid, size_t blen, char *buf)
{
	char path[32];
	ssize_t path_len;

	snprintf(path, sizeof(path), "/proc/%d/cwd", pid);
	path_len = readlink(path, buf, blen - 1);
	if (path_len < 0)
		return NULL;

	if ((size_t)path_len < blen)
		buf[path_len] = 0;
	else
		buf[blen-1] = 0;
	return buf;
}


// If we had to build a path because it started out relative,
// then put the pieces together and get the conanical name
static void resolve_path(const char *pcwd, char *path, size_t len)
{
	char tpath[PATH_MAX+1];
	int tlen = strlen(pcwd);

	// Start with current working directory
	strncpy(tpath, pcwd, PATH_MAX);
	if (tlen >= PATH_MAX) {
		tlen=PATH_MAX-1;
		tpath[PATH_MAX] = 0;
	}

	// Add the relative path
	strncat(tpath, path, (PATH_MAX-1) - tlen);
	tpath[PATH_MAX] = 0;

	// Ask for it to be resolved
	if (realpath(tpath, path) == NULL) {
		strncpy(path, tpath, len);
		path[len - 1] = 0;
	}
}


char *get_file_from_fd(int fd, pid_t pid, size_t blen, char *buf)
{
	char procfd_path[32];
	ssize_t path_len;

	if (blen == 0)
		return NULL;

	snprintf(procfd_path, sizeof(procfd_path)-1,
		"/proc/self/fd/%d", fd);
	path_len = readlink(procfd_path, buf, blen - 1);
	if (path_len < 0)
		return NULL;

	if ((size_t)path_len < blen)
		buf[path_len] = 0;
	else
		buf[blen-1] = 0;

	// If this does not start with a '/' we have a relative path
	if (buf[0] != '/') {
		char pcwd[PATH_MAX+1];

		pcwd[0] = 0;
		get_program_cwd_from_pid(pid, sizeof(pcwd), pcwd);
		resolve_path(pcwd, buf, blen);
	}
	return buf;
}


char *get_device_from_stat(unsigned int device, size_t blen, char *buf)
{
	struct udev_device *dev;
	const char *node;

	if (c.device) {
		if (c.device == device) {
			strncpy(buf, c.devname, blen-1);
			buf[blen-1] = 0;
			return buf;
		}
	}

	// Create udev_device from the dev_t obtained from stat
	dev = udev_device_new_from_devnum(udev, 'b', device);
	node = udev_device_get_devnode(dev);
	if (node == NULL) {
		udev_device_unref(dev);
		return NULL;
	}
	strncpy(buf, node, blen-1);
	buf[blen-1] = 0;
	udev_device_unref(dev);

	// Update saved values
	free((void *)c.devname);
	c.device = device;
	c.devname = strdup(buf);

	return buf;
}


const char *classify_elf_info(uint32_t elf, const char *path)
{
	const char *ptr;

	if (elf & HAS_ERROR)
		ptr = "application/x-bad-elf";
	else if (elf & HAS_EXEC)
		ptr = "application/x-executable";
	else if (elf & HAS_REL)
		ptr = "application/x-object";
	else if (elf & HAS_CORE)
		ptr = "application/x-coredump";
	else if (elf & HAS_INTERP) { // dynamic app
		ptr = "application/x-executable";
		// libc and pthread actually have an interpreter?!?
		// Need to carve out an exception to reclassify them.
		const char *p = path;
		if (!strncmp(p, "/usr", 4))
			p += 4;
		if (!strncmp(p, "/lib", 4)) {
			p += 4;
			if (!strncmp(p, "64", 2))
				p += 2;
			if (!strncmp(p, "/libc-2", 7) ||
				!strncmp(p, "/libc.so", 8) ||
				!strncmp(p, "/libpthread-2", 13))
				ptr = "application/x-sharedlib";
		}
	} else {
		if (elf & HAS_DYNAMIC) { // shared obj
			if (elf & HAS_DEBUG)
				ptr = "application/x-executable";
			else
				ptr = "application/x-sharedlib";
		} else
			return NULL;
	}
	// TODO: add HAS_BAD_INTERP, HAS_EXE_STACK, HAS_RWE_LOAD to
	// classify BAD_ELF based on system policy
	return ptr;
}


/*
 * This function classifies the descriptor if it's not a regular file.
 * This is needed because libmagic tries to read it and comes up with
 * application/x-empty instead. This function will return NULL if the
 * file is not a device. Otherwise a pointer to its mime type.
 */
const char *classify_device(mode_t mode)
{
	const char *ptr = NULL;

	switch (mode & S_IFMT) {
	case S_IFCHR:
		ptr = "inode/chardevice";
		break;
	case S_IFBLK:
		ptr = "inode/blockdevice";
		break;
	case S_IFIFO:
		ptr = "inode/fifo";
		break;
	case S_IFSOCK:
		ptr = "inode/socket";
		break;
	}

	return ptr;
}


/*
 * Mime Type Detection Overview
 * ----------------------------
 *
 * Determining a file's mime type is expensive when relying solely on libmagic.
 * Profiling showed libmagic spending ~43% of its time on text encoding
 * analysis even for files whose type could be determined from their first
 * few bytes.
 *
 * This code implements a tiered detection strategy that tries fast O(1) checks
 * before falling back to libmagic.  A single pread() loads the file header
 * once; this buffer is reused across all detection stages:
 *
 *  1. Empty files        - size == 0 returns application/x-empty immediately.
 *  2. ELF detection      - gather_elf() classifies executables and libraries.
 *  3. Shebang scripts    - extract_shebang_interpreter() + mime_from_shebang()
 *                          identify shell, python, perl, etc. by interpreter.
 *  4. Magic numbers      - detect_by_magic_number() matches PNG, JPEG, gzip.
 *  5. Text formats       - detect_text_format() catches HTML, XML, JSON.
 *  6. Two-tier libmagic  - magic_fast (minimal rules) then magic_full if needed
 *
 * Shebang detection extracts the interpreter basename regardless of path
 * (/bin/sh, /usr/bin/env bash, /nix/store/.../python3 all work).  Interpreter
 * matching uses suffix patterns (*sh catches bash/dash/zsh/fish/ksh) rather
 * than exact names to handle variants across distributions.
 *
 * Based on a Fedora system scan, this approach resolves ~98% of files without
 * a full libmagic lookup: ELF ~75%, shebang scripts ~16%, magic/text ~7%.
 */


// Hot function could benefit from aggressive optimization
#pragma GCC push_options
#pragma GCC optimize ("O3")
/*
 * extract_shebang_interpreter - parse a shebang line to find interpreter
 * @data: pointer to file header data
 * @len: number of bytes available in @data
 * @buf: storage for the interpreter basename
 * @buflen: size of @buf
 *
 * Handles variations like:
 *   #!/bin/sh
 *   #!/usr/bin/bash
 *   #!/usr/local/bin/python3
 *   #!/nix/store/abc123-python-3.11/bin/python3
 *   #!/usr/bin/env python3
 *   #!/bin/env -S python3 -u
 * Returns pointer to @buf with the interpreter basename (e.g., "bash",
 * "python3"), or NULL when no interpreter can be parsed.
 */
const char *extract_shebang_interpreter(const char *data, size_t len,
	char *buf, size_t buflen)
{
	char line[256];
	size_t n;
	char *p, *end, *slash;
	size_t basename_len;

	if (len == 0)
		return NULL;

	if (len > sizeof(line) - 1)
		len = sizeof(line) - 1;

	n = len;
	memcpy(line, data, n);
	if (n < 4 || line[0] != '#' || line[1] != '!')
		return NULL;
	line[n] = '\0';

	/* Skip #! and whitespace */
	p = line + 2;
	while (*p == ' ' || *p == '\t')
		p++;

	/* Find end of first token (the path) */
	end = p;
	while (*end && *end != ' ' && *end != '\t' &&
				      *end != '\n' && *end != '\r')
		end++;

	/* Get basename - works for any path format */
	slash = end - 1;
	while (slash > p && *slash != '/')
		slash--;
	if (*slash == '/')
		slash++;

	basename_len = end - slash;

	/* Check if this is 'env' (handles /any/path/env) */
	if (basename_len == 3 && strncmp(slash, "env", 3) == 0) {
		/* Skip to next token */
		p = end;
		while (*p == ' ' || *p == '\t')
			p++;

		/* Skip env flags like -S, -i, --split-string */
		while (*p == '-') {
			while (*p && *p != ' ' && *p != '\t')
				p++;
			while (*p == ' ' || *p == '\t')
				p++;
		}

		/* Now p points to the interpreter */
		end = p;
		while (*end && *end != ' ' && *end != '\t' &&
					      *end != '\n' && *end != '\r')
			end++;

		/* Get basename again (env arg might have a path too) */
		slash = end - 1;
		while (slash > p && *slash != '/')
			slash--;
		if (*slash == '/')
			slash++;

		basename_len = end - slash;
	}

	if (basename_len == 0 || basename_len >= buflen)
		return NULL;

	/* Copy basename, keeping version number but stripping sub-versions
	 * python3.11.2 -> python3, perl5.32 -> perl5 */
	size_t i;
	for (i = 0; i < basename_len && i < buflen - 1; i++) {
		char ch = slash[i];
		/* Stop at '.' or second consecutive digit */
		if (ch == '.')
			break;
		if (ch >= '0' && ch <= '9' && i > 0 &&
			slash[i-1] >= '0' && slash[i-1] <= '9')
			break;
		buf[i] = ch;
	}

	if (i == 0)
		return NULL;
	buf[i] = '\0';

	return buf;
}
#pragma GCC pop_options


/*
 * mime_from_shebang - map a shebang interpreter to a mime type
 * @interp: interpreter basename extracted from the shebang line
 *
 * Uses suffix and prefix matching to classify interpreters without
 * relying on their absolute path. Returns the mime type string for
 * recognized interpreters or NULL to let libmagic handle unknown ones.
 */
const char *mime_from_shebang(const char *interp)
{
	const char *p;
	size_t len;

	if (!interp || !*interp)
		return NULL;

	/* Find end of string - we need the pointer for suffix check */
	for (p = interp; *p; p++)
		;
	len = p - interp;

	/*
	 * Shell detection - match *sh suffix
	 * Covers: sh, ash, bash, dash, fish, ksh, mksh, pdksh, zsh, csh, tcsh
	 * Mirrors magic rule: (a|ba|da|fi|k|mk|pdk|z|c|tc)?sh
	 * Avoid: wish,tclsh,jimsh - which are tcl
	 */
	if (len >= 2 && p[-2] == 's' && p[-1] == 'h') {
		if (len >= 4 && p[-4] == 'w')
			return "text/x-tcl";
		if (len >= 5 &&
		    ((p[-5] == 't' && p[-4] == 'c' && p[-3] == 'l') ||
		     (p[-5] == 'j' && p[-4] == 'i' && p[-3] == 'm')) )
			return "text/x-tcl";
		return "text/x-shellscript";
	}

	/* Python - python, python2, python3
	 * Note: file-5.47 changes this to 'text/x-script.python'. For
	 * now, let's keep the old one so we don't break installations. */
	if (len >= 6 && memcmp(interp, "python", 6) == 0)
		return "text/x-python";

	/* Perl - perl, perl5 */
	if (len >= 4 && memcmp(interp, "perl", 4) == 0)
		return "text/x-perl";

	/* Lua */
	if (len >= 3 && memcmp(interp, "lua", 3) == 0)
		return "text/x-lua";

	/* Node.js */
	if (len >= 4 && memcmp(interp, "node", 4) == 0)
		return "application/javascript";

	/* SystemTap */
	if (len >= 4 && memcmp(interp, "stap", 4) == 0)
		return "text/x-systemtap";

	/* PHP */
	if (len >= 3 && memcmp(interp, "php", 3) == 0)
		return "text/x-php";

	/* R / Rscript */
	if ((len >= 7 && memcmp(interp, "Rscript", 7) == 0) ||
	    (len == 1 && interp[0] == 'R'))
		return "text/x-R";

	if (len >= 8 && memcmp(interp, "ocamlrun", 8) == 0)
		return "application/x-bytecode.ocaml";

	/*
	 * Unknown interpreter - return NULL to fall through to libmagic.
	 * Being conservative here avoids misclassifying exotic interpreters.
	 */
	return NULL;
}


/*
 * detect_by_magic_number - detect common binaries from their magic number
 * @hdr: file header bytes
 * @len: number of bytes available in @hdr
 *
 * Performs O(1) checks for well-known magic numbers so libmagic can be
 * avoided when the type is obvious. Returns a mime type string or NULL
 * when no match is found.
 */
const char *detect_by_magic_number(const unsigned char *hdr, size_t len)
{
	// We only access hdr[3] at the most so require at least 4 bytes
	if (len < 4)
		return NULL;

	/* PNG */
	if (hdr[0] == 0x89 && hdr[1] == 'P' && hdr[2] == 'N' && hdr[3] == 'G')
		return "image/png";

	/* JPEG */
	if (hdr[0] == 0xFF && hdr[1] == 0xD8 && hdr[2] == 0xFF)
		return "image/jpeg";

	/* GIF */
	if (hdr[0] == 'G' && hdr[1] == 'I' && hdr[2] == 'F' && hdr[3] == '8')
		return "image/gif";

	/* gzip */
	if (hdr[0] == 0x1F && hdr[1] == 0x8B)
		return "application/gzip";

	/* Python bytecode - FIXME: Redo this with exact numbers
	 * Magic varies by version but all start with recognizable pattern */
	if (len >= 4 && (hdr[2] == '\r' && hdr[3] == '\n'))
		return "application/x-bytecode.python";

	return NULL;
}


/*
 * detect_text_format - determine text subtype from initial bytes
 * @hdr: file header bytes
 * @len: number of bytes available in @hdr
 *
 * Looks for BOM, leading whitespace, and markup indicators to quickly
 * classify common text formats. Returns a mime type string or NULL when
 * further analysis is needed.
 */
const char *detect_text_format(const char *hdr, size_t len)
{
	if (len < 5)
		return NULL;

	/* Skip UTF-8 BOM if present */
	const char *p = hdr;
	const char *end = hdr + len;
	if (len >= 3 &&
	   (unsigned char)hdr[0] == 0xEF &&
	   (unsigned char)hdr[1] == 0xBB &&
	   (unsigned char)hdr[2] == 0xBF)
		p += 3;

	/* Skip leading whitespace */
	while (p < end && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r'))
		p++;

	/* Check remaining length before string comparisons */
	size_t remaining = end - p;
	if (remaining < 5)
		return NULL;

	/* HTML */
	if (remaining >= 14 && strncasecmp(p, "<!DOCTYPE html", 14) == 0)
		return "text/html";
	if (remaining >= 5 && strncasecmp(p, "<html", 5) == 0)
		return "text/html";

	/* XML */
	if (remaining >= 5 && strncmp(p, "<?xml", 5) == 0) {
		/* XML - but check if it's SVG */
		const char *svg = memmem(p, remaining > 384 ? 384 : remaining,
					 "<svg", 4);
		if (svg)
			return "image/svg+xml";
		return "text/xml";
	}

	return NULL;
}


// This function will determine the mime type of the passed file descriptor.
// If it returns NULL, then an error of some kind happed. Otherwise it
// fills in "buf" and returns a pointer to it.
char *get_file_type_from_fd(int fd, const struct file_info *i, const char *path,
	size_t blen, char *buf)
{
	const char *ptr;
	char header[512 + 1];
	size_t header_len = 0;
	ssize_t header_read;

	// libmagic is unpredictable in determining elf files.
	// We need to do it ourselves for consistency (and speed).
	if (i->mode & S_IFREG) {
		// If its a regular file (block devices have 0 length, too)
		// check to see if it's empty to skip doing all of the
		// expensive checks. Empty files are unexpectedly common.
		if (i->size == 0) {
			strncpy(buf, "application/x-empty", blen-1);
			buf[blen-1] = 0;
			return buf;
		}

		uint32_t elf = gather_elf(fd, i->size);
		if (elf & IS_ELF) {
			ptr = classify_elf_info(elf, path);
			if (ptr == NULL)
				return (char *)ptr;
			strncpy(buf, ptr, blen-1);
			buf[blen-1] = 0;
			return buf;
		}

		header_read = pread(fd, header, sizeof(header) - 1, 0);
		if (header_read > 0) {
			header_len = header_read;
			header[header_len] = '\0';
			rewind_fd(fd);
		} else
			header[0] = '\0';

		if (elf & HAS_SHEBANG) {
			// See if we can identify the mime-type
			char interp[64];

			if (extract_shebang_interpreter(header, header_len,
						interp,	sizeof(interp))) {
				ptr = mime_from_shebang(interp);
				if (ptr) {
					strncpy(buf, ptr, blen-1);
					buf[blen-1] = 0;
					return buf;
				}
			}

		}

		// Quick magic number check for common binary formats
		ptr = detect_by_magic_number((const unsigned char *)header,
			header_len);
		if (ptr) {
			strncpy(buf, ptr, blen-1);
			buf[blen-1] = 0;
			return buf;
		}

		// Quick text format detection
		if (elf & TEXT_SCRIPT) {
			ptr = detect_text_format(header, header_len);
			if (ptr) {
				strncpy(buf, ptr, blen-1);
				buf[blen-1] = 0;
				return buf;
			}
		}
	}

	// Take a look to see if its a device
	ptr = classify_device(i->mode);
	if (ptr) {
		strncpy(buf, ptr, blen-1);
		buf[blen-1] = 0;
		return buf;
	}

	// Do the fast classification
	ptr = magic_descriptor(magic_fast, fd);
	if (ptr == NULL ||
	    (ptr && (memcmp(ptr, "text/plain", 10) == 0 ||
		    memcmp(ptr, "application/octet-stream", 24) == 0))) {
		// Fall back to the whole database lookup
		rewind_fd(fd);
		ptr = magic_descriptor(magic_full, fd);
		if (ptr == NULL)
			return NULL;
	}
	char *str;
	strncpy(buf, ptr, blen-1);
	buf[blen-1] = 0;
	str = strchr(buf, ';');
	if (str)
		*str = 0;

	return buf;
}


// This function converts byte array into asciie hex
char *bytes2hex(char *final, const unsigned char *buf, unsigned int size)
{
	unsigned int i;
	char *ptr = final;
	const char *hex = "0123456789abcdef";

	if (final == NULL)
		return final;

	for (i=0; i<size; i++) {
		*ptr++ = hex[(buf[i] & 0xF0)>>4]; /* Upper nibble */
		*ptr++ = hex[buf[i] & 0x0F];      /* Lower nibble */
	}
	*ptr = 0;
	return final;
}


// This function wraps read(2) so its signal-safe
static ssize_t safe_read(int fd, char *buf, size_t size)
{
	ssize_t len;

	do {
		len = read(fd, buf, size);
	} while (len < 0 && errno == EINTR);

	return len;
}

/*
 * get_hash_from_fd2 - calculate the requested file digest.
 * @fd: open descriptor whose contents should be measured.
 * @size: number of bytes to include in the digest calculation.
 * @alg: digest algorithm to use for the measurement.
 * Returns a heap-allocated hex string on success or NULL when hashing fails.
 */
static const char *degenerate_hash_sha1 =
	"da39a3ee5e6b4b0d3255bfef95601890afd80709";
static const char *degenerate_hash_sha256 =
	"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
static const char *degenerate_hash_sha512 =
	"cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
	"47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";
static const char *degenerate_hash_md5 =
	"d41d8cd98f00b204e9800998ecf8427e";
char *get_hash_from_fd2(int fd, size_t size, file_hash_alg_t alg)
{
	unsigned char *mapped;
	char *digest = NULL;
	size_t digest_length;

	if (size == 0) {
		switch (alg) {
		case FILE_HASH_ALG_SHA1:
			return strdup(degenerate_hash_sha1);
		case FILE_HASH_ALG_SHA256:
			return strdup(degenerate_hash_sha256);
		case FILE_HASH_ALG_SHA512:
			return strdup(degenerate_hash_sha512);
		case FILE_HASH_ALG_MD5:
			return strdup(degenerate_hash_md5);
		default:
			return NULL;
		}
	}

	digest_length = file_hash_length(alg);
	if (digest_length == 0)
		return NULL;

	mapped = mmap(0, size, PROT_READ, MAP_PRIVATE|MAP_POPULATE, fd, 0);
	if (mapped != MAP_FAILED) {
		unsigned char hptr[SHA512_DIGEST_LENGTH];
		int computed = 0;

		switch (alg) {
		case FILE_HASH_ALG_SHA1:
			SHA1(mapped, size, hptr);
			computed = 1;
			break;
		case FILE_HASH_ALG_SHA256:
			SHA256(mapped, size, hptr);
			computed = 1;
			break;
		case FILE_HASH_ALG_SHA512:
			SHA512(mapped, size, hptr);
			computed = 1;
			break;
		case FILE_HASH_ALG_MD5:
#ifdef USE_DEB
			MD5(mapped, size, hptr);
			computed = 1;
#endif
			break;
		default:
			break;
		}
		munmap(mapped, size);

		if (computed) {
			digest = malloc((digest_length * 2) + 1);
			if (digest)
				bytes2hex(digest, hptr, digest_length);
		}
	}
	return digest;
}

// This function returns 0 on error and 1 if successful
/*
 * get_ima_hash - Decode the IMA digest-ng xattr and expose the measurement.
 * @fd: open file descriptor backed by an IMA measurement.
 * @alg: output parameter updated with the parsed algorithm, may be NULL.
 * @sha: caller supplied buffer large enough for FILE_DIGEST_STRING_MAX.
 * Returns 1 when a supported digest is parsed successfully, or 0 on failure.
 */
int get_ima_hash(int fd, file_hash_alg_t *alg, char *sha)
{
	const struct ima_algo_desc *desc;
	unsigned char tmp[2 + SHA512_LEN];
	ssize_t len;

	if (alg)
		*alg = FILE_HASH_ALG_NONE;

	/*
	 * digest-ng places the format type in byte 0 and the hash algorithm in
	 * byte 1. The remaining bytes hold the binary digest whose length depends
	 * on the algorithm chosen by the policy, so we size the buffer for the
	 * largest algorithm we support.
	 */
	len = fgetxattr(fd, "security.ima", tmp, sizeof(tmp));
	if (len < 2) {
		msg(LOG_DEBUG, "Can't read ima xattr");
		return 0;
	}

	if (tmp[0] != IMA_XATTR_DIGEST_NG) {
		msg(LOG_DEBUG, "Wrong ima xattr type");
		return 0;
	}

	desc = ima_lookup_algo(tmp[1]);
	if (desc == NULL) {
		msg(LOG_DEBUG, "Unsupported ima hash algorithm %u", tmp[1]);
		return 0;
	}
	if (len < (ssize_t)(2 + desc->digest_len)) {
		msg(LOG_DEBUG, "ima xattr too small for alg %u", tmp[1]);
		return 0;
	}

	bytes2hex(sha, &tmp[2], desc->digest_len);
	if (alg)
		*alg = desc->alg;

	return 1;
}


static unsigned char e_ident[EI_NIDENT];
static int read_preliminary_header(int fd)
{
	ssize_t rc = safe_read(fd, (char *)e_ident, EI_NIDENT);
	if (rc == EI_NIDENT)
		return 0;
	return 1;
}


static Elf32_Ehdr *read_header32(int fd, Elf32_Ehdr *ptr)
{
	memcpy(ptr->e_ident, e_ident, EI_NIDENT);
	ssize_t rc = safe_read(fd, (char *)ptr + EI_NIDENT,
				sizeof(Elf32_Ehdr) - EI_NIDENT);
	if (rc == (sizeof(Elf32_Ehdr) - EI_NIDENT))
		return ptr;
	return NULL;
}


static Elf64_Ehdr *read_header64(int fd, Elf64_Ehdr *ptr)
{
	memcpy(ptr->e_ident, e_ident, EI_NIDENT);
	ssize_t rc = safe_read(fd, (char *)ptr + EI_NIDENT,
				sizeof(Elf64_Ehdr) - EI_NIDENT);
	if (rc == (sizeof(Elf64_Ehdr) - EI_NIDENT))
		return ptr;
	return NULL;
}


/**
 * Check interpreter provided as an argument obtained from the ELF against
 * known fixed locations in the file hierarchy.
 */
static int check_interpreter(const char *interp)
{
	unsigned i;

	for (i = 0; i < MAX_INTERPS; i++) {
		if (strcmp(interp, interpreters[i]) == 0)
			return 0;
	}

	return 1;
}

static int looks_like_text_script(int fd)
{
	unsigned char hdr[512];
	ssize_t n = pread(fd, hdr, sizeof(hdr), 0);
	if (n < 4)
		return 0;                   /* too small */

	/* if it contains a NUL or control characters, call it binary */
	for (ssize_t i = 0; i < n; ++i)
		if (hdr[i] < 0x09)
			return 0;

	return 1; /* looks like plain text */
}

// size is the file size from fstat done when event was received
uint32_t gather_elf(int fd, off_t size)
{
	uint32_t info = 0;

	if (read_preliminary_header(fd))
		goto rewind_out;

	/* Detect scripts via shebang before ELF check */
	if (e_ident[0] == '#' && e_ident[1] == '!') {
		info |= HAS_SHEBANG;
		goto rewind_out;
	}

	/* Check ELF magic */
	if (strncmp((char *)e_ident, ELFMAG, 4)) {
		// Not ELF - see if it might be text script
		if (looks_like_text_script(fd))
			info |= TEXT_SCRIPT;
		goto rewind_out;
	}

	info |= IS_ELF;
	if (e_ident[EI_CLASS] == ELFCLASS32) {
		unsigned i, type;
		Elf32_Phdr *ph_tbl = NULL;
		Elf32_Ehdr hdr_buf;

		Elf32_Ehdr *hdr = read_header32(fd, &hdr_buf);
		if (hdr == NULL) {
			info |= HAS_ERROR;
			goto rewind_out;
		}

		type = hdr->e_type & 0xFFFF;
		if (type == ET_EXEC)
			info |= HAS_EXEC;
		else if (type == ET_REL)
			info |= HAS_REL;
		else if (type == ET_CORE)
			info |= HAS_CORE;

		// Look for program header information
		// We want to do a basic size check to make sure
		unsigned long sz =
			(unsigned)hdr->e_phentsize * (unsigned)hdr->e_phnum;

		// Program headers are meaning for executable & shared obj only
		if (sz == 0 && type == ET_REL)
			goto done32_obj;

		/* Verify the entry size is right */
		if ((unsigned)hdr->e_phentsize != sizeof(Elf32_Phdr) ||
		    (unsigned)hdr->e_phnum == 0) {
			info |= HAS_ERROR;
			goto rewind_out;
		}
		if (sz > ((unsigned long)size - sizeof(Elf32_Ehdr))) {
			info |= HAS_ERROR;
			goto rewind_out;
		}
		ph_tbl = malloc(sz);
		if (ph_tbl == NULL)
			goto err_out32;

		if ((unsigned int)lseek(fd, (off_t)hdr->e_phoff, SEEK_SET) !=
					hdr->e_phoff)
			goto err_out32;

		// Read in complete table
		if ((unsigned int)safe_read(fd, (char *)ph_tbl, sz) != sz)
			goto err_out32;

		// Check for rpath record
		for (i = 0; i < hdr->e_phnum; i++) {
			if (ph_tbl[i].p_type == PT_LOAD) {
				info |= HAS_LOAD;

				// If we have RWE flags, something is wrong
				if (ph_tbl[i].p_flags == (PF_X|PF_W|PF_R))
					info |= HAS_RWE_LOAD;
			}

			if (ph_tbl[i].p_type == PT_PHDR)
				info |= HAS_PHDR;

			// Obtain program interpreter from ELF object file
			if (ph_tbl[i].p_type == PT_INTERP) {
				uint32_t len;
				char interp[65];
				uint32_t filesz = ph_tbl[i].p_filesz;
				uint32_t offset = ph_tbl[i].p_offset;

				info |= HAS_INTERP;
				if ((unsigned int) lseek(fd, offset, SEEK_SET)
								!= offset)
					goto err_out32;

				len = (filesz < 65 ? filesz : 65);

				if ((unsigned int) safe_read(fd, (char *)
						interp, len) != len)
					goto err_out32;

				// Explictly terminate the string
				if (len == 0)
					interp[0] = 0;
				else
					interp[len - 1] = '\0';

				// Perform ELF interpreter validation
				if (check_interpreter(interp))
					info |= HAS_BAD_INTERP;
			}

			if (ph_tbl[i].p_type == PT_GNU_STACK) {
				// If we have Execute flags, something is wrong
				if (ph_tbl[i].p_flags & PF_X)
					info |= HAS_EXE_STACK;
			}

			if (ph_tbl[i].p_type == PT_DYNAMIC) {
				unsigned int j = 0;
				unsigned int num;

				info |= HAS_DYNAMIC;

				if (ph_tbl[i].p_filesz > size)
					goto err_out32;

				Elf64_Dyn *dyn_tbl = malloc(ph_tbl[i].p_filesz);

				if((unsigned int)lseek(fd, ph_tbl[i].p_offset,
							SEEK_SET) !=
						ph_tbl[i].p_offset) {
					free(dyn_tbl);
					goto err_out32;
				}

				num = ph_tbl[i].p_filesz / sizeof(Elf64_Dyn);
				if (num > 1000) {
					free(dyn_tbl);
					goto err_out32;
				}

				if ((unsigned int)safe_read(fd, (char *)dyn_tbl,
						ph_tbl[i].p_filesz) !=
						ph_tbl[i].p_filesz) {
					free(dyn_tbl);
					goto err_out32;
				}

				while (j < num) {
					if (dyn_tbl[j].d_tag == DT_NEEDED) {
						// intentional
					} /* else if (dyn_tbl[j].d_tag ==
								DT_RUNPATH)
						info |= HAS_RPATH;
					else if (dyn_tbl[j].d_tag == DT_RPATH)
						info |= HAS_RPATH; */
					else if (dyn_tbl[j].d_tag == DT_DEBUG) {
						info |= HAS_DEBUG;
						break;
					}
					j++;
				}
				free(dyn_tbl);
			}
//			if (info & HAS_RPATH)
//				break;
		}
		goto done32;
err_out32:
		info |= HAS_ERROR;
done32:
		free(ph_tbl);
done32_obj:
		; // fix an 'error label at end of compound statement'
	} else if (e_ident[EI_CLASS] == ELFCLASS64) {
		unsigned i, type;
		Elf64_Phdr *ph_tbl;
		Elf64_Ehdr hdr_buf;

		Elf64_Ehdr *hdr = read_header64(fd, &hdr_buf);
		if (hdr == NULL) {
			info |= HAS_ERROR;
			goto rewind_out;
		}

		type = hdr->e_type & 0xFFFF;
		if (type == ET_EXEC)
			info |= HAS_EXEC;
		else if (type == ET_REL)
			info |= HAS_REL;
		else if (type == ET_CORE)
			info |= HAS_CORE;

		// Look for program header information
		// We want to do a basic size check to make sure
		unsigned long sz =
			(unsigned)hdr->e_phentsize * (unsigned)hdr->e_phnum;

		// Program headers are meaning for executable & shared obj only
		if (sz == 0 && type == ET_REL)
			goto done64_obj;

		/* Verify the entry size is right */
		if ((unsigned)hdr->e_phentsize != sizeof(Elf64_Phdr) ||
		    (unsigned)hdr->e_phnum == 0) {
			info |= HAS_ERROR;
			goto rewind_out;
		}
		if (sz > ((unsigned long)size - sizeof(Elf64_Ehdr))) {
			info |= HAS_ERROR;
			goto rewind_out;
		}
		ph_tbl = malloc(sz);
		if (ph_tbl == NULL)
			goto err_out64;

		if ((unsigned int)lseek(fd, (off_t)hdr->e_phoff, SEEK_SET) !=
					hdr->e_phoff)
			goto err_out64;

		// Read in complete table
		if ((unsigned int)safe_read(fd, (char *)ph_tbl, sz) != sz)
			goto err_out64;

		// Check for rpath record
		for (i = 0; i < hdr->e_phnum; i++) {
			if (ph_tbl[i].p_type == PT_LOAD) {
				info |= HAS_LOAD;

				// If we have RWE flags, something is wrong
				if (ph_tbl[i].p_flags == (PF_X|PF_W|PF_R))
					info |= HAS_RWE_LOAD;
			}

			if (ph_tbl[i].p_type == PT_PHDR)
				info |= HAS_PHDR;

			// Obtain program interpreter from ELF object file
			if (ph_tbl[i].p_type == PT_INTERP) {
				uint64_t len;
				char interp[65];
				uint64_t filesz = ph_tbl[i].p_filesz;
				uint64_t offset = ph_tbl[i].p_offset;

				info |= HAS_INTERP;
				if ((unsigned int) lseek(fd, offset, SEEK_SET)
								!= offset)
					goto err_out64;

				len = (filesz < 65 ? filesz : 65);

				if ((unsigned int) safe_read(fd, (char *)
						interp, len) != len)
					goto err_out64;

				/* Explicitly terminate the string */
				if (len == 0)
					interp[0] = 0;
				else
					interp[len - 1] = '\0';

				// Perform ELF interpreter validation
				if (check_interpreter(interp))
					info |= HAS_BAD_INTERP;
			}

			if (ph_tbl[i].p_type == PT_GNU_STACK) {
				// If we have Execute flags, something is wrong
				if (ph_tbl[i].p_flags & PF_X)
					info |= HAS_EXE_STACK;
			}

			if (ph_tbl[i].p_type == PT_DYNAMIC) {
				unsigned int j = 0;
				unsigned int num;

				info |= HAS_DYNAMIC;

				if (ph_tbl[i].p_filesz>(long unsigned int)size)
					goto err_out64;

				Elf64_Dyn *dyn_tbl = malloc(ph_tbl[i].p_filesz);

				if ((unsigned int)lseek(fd, ph_tbl[i].p_offset,
							SEEK_SET) !=
						ph_tbl[i].p_offset) {
					free(dyn_tbl);
					goto err_out64;
				}
				num = ph_tbl[i].p_filesz / sizeof(Elf64_Dyn);
				if (num > 1000) {
					free(dyn_tbl);
					goto err_out64;
				}
				if ((unsigned int)safe_read(fd, (char *)dyn_tbl,
						ph_tbl[i].p_filesz) !=
						ph_tbl[i].p_filesz) {
					free(dyn_tbl);
					goto err_out64;
				}
				while (j < num) {
					if (dyn_tbl[j].d_tag == DT_NEEDED) {
						// intentional
					} /* else if (dyn_tbl[j].d_tag ==
								DT_RUNPATH)
						info |= HAS_RPATH;
					else if (dyn_tbl[j].d_tag == DT_RPATH)
						info |= HAS_RPATH; */
					else if (dyn_tbl[j].d_tag == DT_DEBUG) {
						info |= HAS_DEBUG;
						break;
					}
					j++;
				}
				free(dyn_tbl);
			}
//			if (info & HAS_RPATH)
//				break;
		}
		goto done64;
err_out64:
		info |= HAS_ERROR;
done64:
		free(ph_tbl);
done64_obj:
		; // fix an 'error label at end of compound statement'
	} else // Invalid ELF class
		info |= HAS_ERROR;
rewind_out:
	rewind_fd(fd);
	return info;
}

