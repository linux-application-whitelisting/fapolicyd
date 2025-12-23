/*
 * file.h - Header file for file.c
 * Copyright (c) 2016,2018-20,2022 Red Hat Inc.
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

#ifndef FILE_HEADER
#define FILE_HEADER

#include <sys/types.h>
#include <stdint.h>
#include <sys/stat.h>
#include "gcc-attributes.h"

// Supported digest algorithms for file content measurement
typedef enum {
	FILE_HASH_ALG_NONE = 0,
	FILE_HASH_ALG_MD5,       // Legacy support for MD5-based trust sources
	FILE_HASH_ALG_SHA1,
	FILE_HASH_ALG_SHA256,
	FILE_HASH_ALG_SHA512,
} file_hash_alg_t;

#define MD5_LEN		16
#define SHA1_LEN	20
#define SHA256_LEN	32
#define SHA512_LEN	64

// Longest printable digest string expected - includes algorithm prefix and NUL
// (SHA512_LEN * 2) + 8 = 136 bytes including the terminating NUL
#define FILE_DIGEST_STRING_MAX 136
#define FILE_DIGEST_STRING_WIDTH 135
#define TRUSTDB_DATA_BUFSZ (FILE_DIGEST_STRING_MAX + 64)

// Information we will cache to identify the same executable
struct file_info
{
	dev_t    device;
	ino_t    inode;
	mode_t   mode;
	off_t    size;
	struct timespec time;
	file_hash_alg_t digest_alg;
	char digest[FILE_DIGEST_STRING_MAX];
};

void file_init(void);
void file_close(void);
struct file_info *stat_file_entry(int fd) __attr_dealloc_free;
void file_info_reset_digest(struct file_info *info);
file_hash_alg_t file_hash_alg(unsigned len);
file_hash_alg_t file_hash_alg_fast(const char *digest);
void file_info_cache_digest(struct file_info *info, file_hash_alg_t alg);
size_t file_hash_length(file_hash_alg_t alg);
const char *file_hash_alg_name(file_hash_alg_t alg);
file_hash_alg_t file_hash_name_alg(const char *name);
int compare_file_infos(const struct file_info *p1, const struct file_info *p2);
int check_ignore_mount_noexec(const char *mounts_file, const char *point);
int iterate_ignore_mounts(const char *ignore_list,
	int (*callback)(const char *mount, void *user_data), void *user_data);
int check_ignore_mount_warning(const char *mounts_file, const char *point,
	const char **warning);
char *get_file_from_fd(int fd, pid_t pid, size_t blen, char *buf)
	__attr_access ((__write_only__, 4, 3));
char *get_device_from_stat(unsigned int device, size_t blen, char *buf)
	__attr_access ((__write_only__, 3, 2));
const char *classify_device(mode_t mode);
const char *classify_elf_info(uint32_t elf, const char *path);
const char *extract_shebang_interpreter(const char *data, size_t len,
	char *buf, size_t buflen) __attr_access ((__write_only__, 3, 4));
const char *mime_from_shebang(const char *interp);
const char *detect_by_magic_number(const unsigned char *hdr, size_t len);
const char *detect_text_format(const char *hdr, size_t len);
char *get_file_type_from_fd(int fd, const struct file_info *i, const char *path,
	size_t blen, char *buf)
	__attr_access ((__write_only__, 5, 4));
char *bytes2hex(char *final, const unsigned char *buf, unsigned int size)
	 __attr_access ((__read_only__, 2, 3));
char *get_hash_from_fd2(int fd, size_t size, file_hash_alg_t alg)
	__attr_dealloc_free;
int get_ima_hash(int fd, file_hash_alg_t *alg, char *sha);
uint32_t gather_elf(int fd, off_t size);

#endif
