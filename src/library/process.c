/*
 * process.c - functions to access attributes of processes
 * Copyright (c) 2016,2020 Red Hat Inc.
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


struct proc_info *stat_proc_entry(pid_t pid)
{
	char path[32];
	struct stat sb;

	snprintf(path, sizeof(path), "/proc/%d", pid);
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
	char path[32];
	ssize_t rc;
	int fd;

	snprintf(path, sizeof(path), "/proc/%d/comm", pid);
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
	} else  // FIXME: this should be NULL
		snprintf(buf, blen-1,
			"Error-getting-comm(errno=%d,pid=%d)",
			errno, pid);
	return buf;
}


char *get_program_from_pid(pid_t pid, size_t blen, char *buf)
{
	char path[32];
	ssize_t path_len;

	snprintf(path, sizeof(path), "/proc/%d/exe", pid);
	path_len = readlink(path, buf, blen - 1);
	if (path_len < 0) {
		if (errno == ENOENT)
			return get_comm_from_pid(pid, blen, buf);

		snprintf(buf, blen,
			"Error-getting-exe(errno=%d,pid=%d)",
			 errno, pid);

		return buf;
	}

	size_t len = 0;
	if ((size_t)path_len < blen)
		len = path_len;
	else
		len = blen-1;

	buf[len] = '\0';
	// some binaries can be deleted after execution
	// then we need to delete the suffix so they are
	// trusted even after deletion

	// strlen(" deleted") == 10
	if (buf[len-1] == ')' && len > 10) {

		if (strcmp(&buf[len - 10], " (deleted)") == 0)
			buf[len - 10] = '\0';
	}

	return buf;
}


char *get_type_from_pid(pid_t pid, size_t blen, char *buf)
{
	char path[32];
	int fd;

	snprintf(path, sizeof(path), "/proc/%d/exe", pid);
	fd = open(path, O_RDONLY|O_NOATIME|O_CLOEXEC);
	if (fd >= 0) {
		const char *ptr;
		extern magic_t magic_cookie;

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
	char path[32];
	ssize_t rc;
	int fd;

	snprintf(path, sizeof(path), "/proc/%d/loginuid", pid);
	fd = open(path, O_RDONLY|O_CLOEXEC);
	if (fd >= 0) {
		uid_t auid;

		rc = read(fd, path, sizeof(path)-1);
		close(fd);
		if (rc > 0) {
			path[rc] = 0;  // manually terminate, read doesn't
			errno = 0;
			auid = strtol(path, NULL, 10);
			if (errno == 0)
				return auid;
		}
	}
	return -1;
}


int get_program_sessionid_from_pid(pid_t pid)
{
	char path[32];
	ssize_t rc;
	int fd;

	snprintf(path, sizeof(path), "/proc/%d/sessionid", pid);
	fd = open(path, O_RDONLY|O_CLOEXEC);
	if (fd >= 0) {
		int ses;

		rc = read(fd, path, sizeof(path)-1);
		close(fd);
		if (rc > 0) {
			path[rc] = 0;  // manually terminate, read doesn't
			errno = 0;
			ses = strtol(path, NULL, 10);
			if (errno == 0)
				return ses;
		}
	}
	return -1;
}


uid_t get_program_uid_from_pid(pid_t pid)
{
	char path[128];
	int uid = -1;
	FILE *f;

	snprintf(path, sizeof(path), "/proc/%d/status", pid);
	f = fopen(path, "rt");
	if (f) {
		__fsetlocking(f, FSETLOCKING_BYCALLER);
		while (fgets(path, 128, f)) {
			if (memcmp(path, "Uid:", 4) == 0) {
				sscanf(path, "Uid: %d ", &uid);
                                break;
                        }
		}
		fclose(f);
	}
	return uid;
}

// Returns 0 if environ is clean, 1 if problems, -1 on error
int check_environ_from_pid(pid_t pid)
{
	int rc = -1;
	char path[128];
	char *line = NULL;
	size_t len = 0;
	ssize_t nread;
	FILE *f;

	snprintf(path, sizeof(path), "/proc/%d/environ", pid);
	f = fopen(path, "rt");
	if (f) {
		__fsetlocking(f, FSETLOCKING_BYCALLER);
		while ((nread = getline(&line, &len, f)) != -1) {
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

