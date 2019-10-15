/*
 * process.h - Header file for process.c
 * Copyright (c) 2016,2019 Red Hat Inc., Durham, North Carolina.
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

typedef enum { STATE_COLLECTING=0, STATE_PARTIAL, STATE_FULL, STATE_NORMAL,
	STATE_NOT_ELF, /*STATE_LD_PRELOAD,*/ STATE_BAD_INTERPRETER,
	STATE_LD_SO, STATE_STATIC, STATE_BAD_ELF } state_t;

// This is used to determine what kind of elf file we are looking at.
// HAS_LOAD but no HAS_DYNAMIC is staticly linked app. Normally you see both.
#define IS_ELF		0x01
#define HAS_ERROR	0x02
#define HAS_RPATH	0x04
#define HAS_DYNAMIC	0x08
#define HAS_LOAD	0x10
#define HAS_INTERP	0x20
#define HAS_BAD_INTERP	0x40

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
	char *path3;
	uint32_t elf_info;
};

struct proc_info *stat_proc_entry(pid_t pid);
void clear_proc_info(struct proc_info *info);
int compare_proc_infos(const struct proc_info *p1, const struct proc_info *p2);
char *get_comm_from_pid(pid_t pid, size_t blen, char *buf);
char *get_program_from_pid(pid_t pid, size_t blen, char *buf);
char *get_type_from_pid(pid_t pid, size_t blen, char *buf);
uid_t get_program_auid_from_pid(pid_t pid);
int get_program_sessionid_from_pid(pid_t pid);
uid_t get_program_uid_from_pid(pid_t pid);

#endif
