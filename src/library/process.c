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
#include "fd-fgets.h"
#include "attr-sets.h"

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

/*
 * Check for the existance of an exe file. This is needed to help identify
 * kworker threads. return 1 if exists and is readable and 0 if not.
 */
int does_exe_exist(pid_t pid)
{
	const char *path = proc_path(pid, "/exe");
	return access(path, R_OK) == 0;
}


char *get_program_from_pid(pid_t pid, size_t blen, char *buf)
{
	ssize_t path_len;

	if (blen == 0)
		return NULL;

	const char *path = proc_path(pid, "/exe");
	path_len = readlink(path, buf, blen - 1);
	if (path_len <= 0) {
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

/*
 * read_proc_status - Collect selected fields from /proc/<pid>/status.
 * @pid: identifier of the process to inspect
 * @fields: bitmap of PROC_STAT_* flags describing desired data
 * @info: storage describing the results for the requested fields
 *
 * The helper parses the status file once and populates @info for every
 * requested field.  Existing data for the requested fields is released
 * before new values are recorded.  The function returns 0 on success and
 * -1 when the status file cannot be processed.
 */
int read_proc_status(pid_t pid, unsigned int fields,
		     struct proc_status_info *info)
{
	char buf[80];
	int fd, rc = 0;
	unsigned int found = 0;

	if (info == NULL || fields == 0)
		return 0;

	// Initialize info struct
	if (fields & PROC_STAT_UID) {
		if (info->uid) {
			destroy_attr_set(info->uid);
			free(info->uid);
			info->uid = NULL;
		}
		info->uid = init_standalone_set(UNSIGNED);
		if (info->uid == NULL)
			return -1;
	}
	if (fields & PROC_STAT_GID) {
		if (info->groups) {
			destroy_attr_set(info->groups);
			free(info->groups);
			info->groups = NULL;

		}
		info->groups = init_standalone_set(UNSIGNED);
		if (info->groups == NULL) {
			if (fields & PROC_STAT_UID) {
				destroy_attr_set(info->uid);
				free(info->uid);
				info->uid = NULL;
			}
			return -1;
		}
	}
	if (fields & PROC_STAT_COMM) {
		free(info->comm);
		info->comm = NULL;
	}
	if (fields & PROC_STAT_PPID)
		info->ppid = -1;

	const char *path = proc_path(pid, "/status");
	fd = open(path, O_RDONLY|O_CLOEXEC);
	if (fd < 0) {
		if (fields & PROC_STAT_UID) {
			destroy_attr_set(info->uid);
			free(info->uid);
			info->uid = NULL;
		}
		if (fields & PROC_STAT_GID) {
			destroy_attr_set(info->groups);
			free(info->groups);
			info->groups = NULL;
		}
		return -1;
	}

	fd_fgets_state_t *st = fd_fgets_init();

	do {
		rc = fd_fgets_r(st, buf, sizeof(buf), fd);
		if (rc == -1)
			break;
		else if (rc > 0) {
			if ((fields & PROC_STAT_COMM) &&
				    info->comm == NULL &&
				    memcmp(buf, "Name:", 5) == 0) {
				char *name = buf + 5;
				while (*name == ' ' || *name == '\t')
					name++;
				char *newline = strchr(name, '\n');
				if (newline)
					*newline = '\0';
				info->comm = strdup(name);
				if (info->comm == NULL)
					rc = -1;
				found |= PROC_STAT_COMM;
				continue;
			}
			if ((fields & PROC_STAT_PPID) &&
				    info->ppid == -1 &&
				    memcmp(buf, "PPid:", 5) == 0) {
				long value;
				if (sscanf(buf, "PPid: %ld", &value) == 1)
					info->ppid = (pid_t)value;
				found |= PROC_STAT_PPID;
				continue;
			}
			/*
			 * UID/GID credentials may differ between the real,
			 * effective, saved, and filesystem slots. Cache all
			 * but saved so the rule engine can evaluate all
			 * possible identities during matching.
			 */
			if ((fields & PROC_STAT_UID) &&
			    is_attr_set_empty(info->uid) &&
			    memcmp(buf, "Uid:", 4) == 0) {
				unsigned int real_uid = 0, eff_uid = 0;
				unsigned int saved_uid = 0, fs_uid = 0;
				int fields_read = sscanf(buf,
						 "Uid: %u %u %u %u",
						 &real_uid, &eff_uid,
						 &saved_uid, &fs_uid);
				if (info->uid) {
					if (fields_read >= 1)
						append_int_attr_set(info->uid,
							(int64_t)real_uid);
					if (fields_read >= 2)
						append_int_attr_set(info->uid,
							(int64_t)eff_uid);
					if (fields_read >= 4)
						append_int_attr_set(info->uid,
							(int64_t)fs_uid);
				}
				found |= PROC_STAT_UID;
				continue;
			}
			if ((fields & PROC_STAT_GID) &&
			    is_attr_set_empty(info->groups) &&
			    memcmp(buf, "Gid:", 4) == 0) {
				unsigned int real_gid = 0, eff_gid = 0;
				unsigned int saved_gid = 0, fs_gid = 0;
				int fields_read = sscanf(buf,
						"Gid: %u %u %u %u",
						&real_gid, &eff_gid,
						&saved_gid, &fs_gid);
				if (info->groups) {
					if (fields_read >= 1)
					    append_int_attr_set(info->groups,
							(int64_t)real_gid);
					if (fields_read >= 2)
					    append_int_attr_set(info->groups,
							(int64_t)eff_gid);
					if (fields_read >= 4)
					    append_int_attr_set(info->groups,
							(int64_t)fs_gid);
				}
				// Not marking found - wait for supplemental
				continue;
			}
			/*
			 * The "Groups" line enumerates supplemental group
			 * memberships as a whitespace separated list; walk the
			 * tokens in place rather than reallocating buffers.
			 * Not checking if empty cause it shouldn't be.
			 */
			if ((fields & PROC_STAT_GID) &&
			    memcmp(buf, "Groups:", 7) == 0) {
				if (info->groups) {
					char *data = buf + 7;
					int offset;
					unsigned int gid;

					while (sscanf(data,
						" %u%n", &gid, &offset) == 1) {
					      data += offset;
					      append_int_attr_set(info->groups,
								(int64_t)gid);
					}
				}
				found |= PROC_STAT_GID;
				continue;
			}
		}
	// if more text, no errors, and we're not done, loop again
	} while (!fd_fgets_eof_r(st) && rc > 0 && found != fields);

	fd_fgets_destroy(st);
	close(fd);

	return 0;
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

