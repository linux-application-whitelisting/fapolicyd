/*
 * process.c - functions to access attributes of processes
 * Copyright (c) 2016,2020-22 Red Hat Inc.
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
//#ifdef HAVE_STDIO_EXT_H
# include <stdio_ext.h>
//#endif
#include <limits.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <magic.h>
#include "process.h"
#include "file.h"

#define BUF_SIZE 8192 // Buffer for reading pid status, mainly for group list

#define BUFSZ 12  // Largest unsigned int is 10 characters long
/*
 * This is an optimized integer to string conversion. It only
 * does base 10 which is exactly what you need to access per
 * process files in the proc file system. It is about 30% faster
 * than snprint.
 */
static const char *uitoa(unsigned int j)
{
	static __thread char buf[BUFSZ];
	if (j == 0)
		return "0";

	char *ptr = &buf[BUFSZ - 1];
	*ptr = 0;
	do {
		*--ptr = '0' + (j % 10);
		j /= 10;
	} while (j);

	return ptr;
}

static __thread char ppath[40] = "/proc/";
static inline const char *proc_path(pid_t pid, const char *file)
{
	char *p = stpcpy(ppath + 6, uitoa((unsigned int)pid));
	if (file)
		stpcpy(p, file);
	return ppath;
}

struct proc_info *stat_proc_entry(pid_t pid)
{
	struct stat sb;
	const char *path = proc_path(pid, NULL);
	if (stat(path, &sb) == 0) {
		struct proc_info *info = malloc(sizeof(struct proc_info));
		if (info == NULL)
			return info;

		info->pid = pid;
		info->device = sb.st_dev;
		info->inode = sb.st_ino;
		info->time.tv_sec = sb.st_ctim.tv_sec;
		info->time.tv_nsec = sb.st_ctim.tv_nsec;
		// Make all paths empty
		info->path1 = NULL;
		info->path2 = NULL;
		info->state = STATE_COLLECTING;
		info->elf_info = 0;

		return info;
	}
	return NULL;
}


void clear_proc_info(struct proc_info *info)
{
	free(info->path1);
	free(info->path2);
	info->path1 = NULL;
	info->path2 = NULL;
}


// Returns 0 if equal and 1 if not equal
int compare_proc_infos(const struct proc_info *p1, const struct proc_info *p2)
{
	if (p1 == NULL || p2 == NULL)
		return 1;

	// Compare in the order to find likely mismatch first
	if (p1->inode != p2->inode)
		return 1;
	if (p1->pid != p2->pid)
		return 1;
	if (p1->time.tv_nsec != p2->time.tv_nsec)
		return 1;
	if (p1->time.tv_sec != p2->time.tv_sec)
		return 1;
	if (p1->device != p2->device)
		return 1;

	return 0;
}


char *get_comm_from_pid(pid_t pid, size_t blen, char *buf)
{
	ssize_t rc;
	int fd;

	if (blen == 0)
		return NULL;

	const char *path = proc_path(pid, "/comm");
	fd = open(path, O_RDONLY|O_CLOEXEC);
	if (fd >= 0) {
		char *ptr;
		rc = read(fd, buf, blen);
		close(fd);
		if (rc < 0)
			return NULL;

		if ((size_t)rc < blen)
			buf[rc] = 0;
		else
			buf[blen-1] = 0;

		// Trim the newline
		ptr = strchr(buf, 0x0A);
		if (ptr)
			*ptr = 0;
	} else
		return NULL;

	return buf;
}


char *get_program_from_pid(pid_t pid, size_t blen, char *buf)
{
	ssize_t path_len;

	if (blen == 0)
		return NULL;

	const char *path = proc_path(pid, "/exe");
	path_len = readlink(path, buf, blen - 1);
	if (path_len <= 0) {
		if (errno == ENOENT)
			return get_comm_from_pid(pid, blen, buf);

		snprintf(buf, blen,
			"Error-getting-exe(errno=%d,pid=%d)",
			 errno, pid);

		return buf;
	}

	size_t len;
	if ((size_t)path_len < blen)
		len = path_len;
	else
		len = blen - 1;

	buf[len] = '\0';
	if (len == 0)
		return buf;
	// some binaries can be deleted after execution
	// then we need to delete the suffix so they are
	// trusted even after deletion

	// strlen(" deleted") == 10
	if (len > 10 && buf[len-1] == ')') {

		if (strcmp(&buf[len - 10], " (deleted)") == 0)
			buf[len - 10] = '\0';
	}

	return buf;
}


char *get_type_from_pid(pid_t pid, size_t blen, char *buf)
{
	int fd;

	if (blen == 0)
		return NULL;

	const char *path = proc_path(pid, "/exe");
	fd = open(path, O_RDONLY|O_NOATIME|O_CLOEXEC);
	if (fd >= 0) {
		const char *ptr;
		extern magic_t magic_cookie;
		struct stat sb;

		// Most of the time, the process will be ELF.
		// We can identify it much faster than libmagic.
		if (fstat(fd, &sb) == 0) {
			uint32_t elf = gather_elf(fd, sb.st_size);
			if (elf & IS_ELF) {
				ptr = classify_elf_info(elf, path);
				close(fd);
				if (ptr == NULL)
					return (char *)ptr;
				strncpy(buf, ptr, blen-1);
				buf[blen-1] = 0;
				return buf;
			}
		}

		ptr = magic_descriptor(magic_cookie, fd);
		close(fd);
		if (ptr) {
			char *str;
			strncpy(buf, ptr, blen);
			buf[blen-1] = 0;
			str = strchr(buf, ';');
			if (str)
				*str = 0;
		} else
			return NULL;

		return buf;
	}

	return NULL;
}


uid_t get_program_auid_from_pid(pid_t pid)
{
	ssize_t rc;
	int fd;

	const char *path = proc_path(pid, "/loginuid");
	fd = open(path, O_RDONLY|O_CLOEXEC);
	if (fd >= 0) {
		char buf[16];
		uid_t auid;

		rc = read(fd, buf, sizeof(buf)-1);
		close(fd);
		if (rc > 0) {
			buf[rc] = 0;  // manually terminate, read doesn't
			errno = 0;
			auid = strtol(buf, NULL, 10);
			if (errno == 0)
				return auid;
		}
	}
	return -1;
}


int get_program_sessionid_from_pid(pid_t pid)
{
	ssize_t rc;
	int fd;

	const char *path = proc_path(pid, "/sessionid");
	fd = open(path, O_RDONLY|O_CLOEXEC);
	if (fd >= 0) {
		char buf[16];
		int ses;

		rc = read(fd, buf, sizeof(buf)-1);
		close(fd);
		if (rc > 0) {
			buf[rc] = 0;  // manually terminate, read doesn't
			errno = 0;
			ses = strtol(buf, NULL, 10);
			if (errno == 0)
				return ses;
		}
	}
	return -1;
}


pid_t get_program_ppid_from_pid(pid_t pid)
{
	char buf[128];
	int ppid = -1;
	FILE *f;

	const char *path = proc_path(pid, "/status");
	f = fopen(path, "rt");
	if (f) {
		__fsetlocking(f, FSETLOCKING_BYCALLER);
		while (fgets(buf, 128, f)) {
			if (memcmp(buf, "PPid:", 4) == 0) {
				sscanf(buf, "PPid: %d ", &ppid);
				break;
			}
		}
		fclose(f);
	}
	return ppid;
}


uid_t get_program_uid_from_pid(pid_t pid)
{
	char buf[128];
	uid_t uid = 0;
	FILE *f;

	const char *path = proc_path(pid, "/status");
	f = fopen(path, "rt");
	if (f) {
		__fsetlocking(f, FSETLOCKING_BYCALLER);
		while (fgets(buf, 128, f)) {
			if (memcmp(buf, "Uid:", 4) == 0) {
				sscanf(buf, "Uid: %u ", &uid);
				break;
			}
		}
		fclose(f);
	}
	return uid;
}


attr_sets_entry_t *get_gid_set_from_pid(pid_t pid)
{
	char buf[BUF_SIZE];
	gid_t gid = 0;
	FILE *f;
	attr_sets_entry_t *set = init_standalone_set(UNSIGNED);

	if (set) {
		const char *path = proc_path(pid, "/status");
		f = fopen(path, "rt");
		if (f) {
			__fsetlocking(f, FSETLOCKING_BYCALLER);
			while (fgets(buf, BUF_SIZE, f)) {
				if (memcmp(buf, "Gid:", 4) == 0) {
					sscanf(buf, "Gid: %u ", &gid);
					append_int_attr_set(set, (int64_t)gid);
					break;
				}
			}

			char *data;
			int offset;
			while (fgets(buf, BUF_SIZE, f)) {
				if (memcmp(buf, "Groups:", 7) == 0) {
					data = buf + 7;
					while (sscanf(data, " %u%n", &gid,
						      &offset) == 1) {
						data += offset;
						append_int_attr_set(set, (int64_t)gid);
					}
					break;
				}
			}
			fclose(f);
		}
	}
	return set;
}


// Returns 0 if environ is clean, 1 if problems, -1 on error
int check_environ_from_pid(pid_t pid)
{
	int rc = -1;
	char *line = NULL;
	size_t len = 0;
	FILE *f;

	const char *path = proc_path(pid, "/environ");
	f = fopen(path, "rt");
	if (f) {
		__fsetlocking(f, FSETLOCKING_BYCALLER);
		while (getline(&line, &len, f) != -1) {
			char *match = strstr(line, "LD_PRELOAD");
			if (!match)
				match = strstr(line, "LD_AUDIT");
			if (match) {
				rc = 1;
				break;
			}
		}
		fclose(f);
		if (rc == -1)
			rc = 0;
		free(line);
	}
	return rc;
}

