/*
 * process.h - Header file for process.c
 * Copyright (c) 2016,2019-22 Red Hat Inc.
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

#ifndef PROCESS_HEADER
#define PROCESS_HEADER

#include <sys/types.h>
#include <stdint.h>
#include "attr-sets.h"
#include "gcc-attributes.h"

typedef enum {	STATE_COLLECTING=0,	// initial state - execute
		STATE_REOPEN,		// anticipating open perm next, always skips the path
		STATE_DEFAULT_REOPEN,  // reopen after dyn. linker exec, never skips the path
		STATE_STATIC_REOPEN,	// static app aniticipating
		STATE_PARTIAL,		// second path collected
		STATE_STATIC_PARTIAL,	// second path collected
		STATE_FULL,		// third path seen - decision time
		STATE_NORMAL,		// normal pattern
		STATE_NOT_ELF,		// not elf, ignore
		STATE_LD_SO,		// app started by ld.so
		STATE_STATIC,		// app is static
		STATE_BAD_ELF,		// app is elf but malformed
		STATE_LD_PRELOAD	// app has LD_PRELOAD or LD_AUDIT set
} state_t;

// This is used to determine what kind of elf file we are looking at.
// HAS_LOAD but no HAS_DYNAMIC is staticly linked app. Normally you see both.
#define IS_ELF		0x00001
#define HAS_ERROR	0x00002
// #define HAS_RPATH	0x00004
#define HAS_DYNAMIC	0x00008
#define HAS_LOAD	0x00010
#define HAS_INTERP	0x00020
#define HAS_BAD_INTERP	0x00040
#define HAS_EXEC	0x00080
#define HAS_CORE	0x00100
#define HAS_REL		0x00200
#define HAS_DEBUG	0x00400
#define HAS_RWE_LOAD	0x00800
#define HAS_PHDR	0x01000
#define HAS_EXE_STACK	0x02000

// Information we will cache to identify the same executable
struct proc_info
{
	pid_t	pid;
	dev_t	device;
	ino_t	inode;
	struct timespec time;
	state_t state;
	char *path1;
	char *path2;
	uint32_t elf_info;
};

struct proc_info *stat_proc_entry(pid_t pid) MALLOCLIKE;
void clear_proc_info(struct proc_info *info);
int compare_proc_infos(const struct proc_info *p1, const struct proc_info *p2);
char *get_comm_from_pid(pid_t pid, size_t blen, char *buf)
	__attr_access ((__write_only__, 3, 2));
char *get_program_from_pid(pid_t pid, size_t blen, char *buf)
	__attr_access ((__write_only__, 3, 2));
char *get_type_from_pid(pid_t pid, size_t blen, char *buf)
	__attr_access ((__write_only__, 3, 2));
uid_t get_program_auid_from_pid(pid_t pid);
int get_program_sessionid_from_pid(pid_t pid);
pid_t get_program_ppid_from_pid(pid_t pid);
uid_t get_program_uid_from_pid(pid_t pid);
attr_sets_entry_t *get_gid_set_from_pid(pid_t pid);
int check_environ_from_pid(pid_t pid);

#endif
