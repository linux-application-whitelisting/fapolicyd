/*
 * file.c - functions for accessing attributes of files
 * Copyright (c) 2016,2018 Red Hat Inc., Durham, North Carolina.
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
#include <gcrypt.h>
#include <magic.h>
#include <libudev.h>
#include <elf.h>
#include "file.h"
#include "message.h"
#include "process.h" // For elf info bit mask

// Local variables
static struct udev *udev;
magic_t magic_cookie;
struct cache { dev_t device; const char *devname; };
struct cache c = { 0, NULL };

// Initialize what we can now so that its not done each call
void file_init(void)
{
	// Setup udev
	udev = udev_new();

	// Setup libmagic
	unsetenv("MAGIC");
	magic_cookie = magic_open(MAGIC_MIME|MAGIC_ERROR|MAGIC_NO_CHECK_CDF|
			MAGIC_NO_CHECK_ELF);
	if (magic_cookie == NULL) {
		msg(LOG_ERR, "Unable to init libmagic");
		exit(1); 
	}
	if (magic_load(magic_cookie, NULL) != 0) {
		msg(LOG_ERR, "Unable to load magic database");
		exit(1);
	}
}

// Release memory during shutdown
void file_close(void)
{
	udev_unref(udev);
	magic_close(magic_cookie);
	free((void *)c.devname);
}

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
		return info;
	}
	return NULL;
}

// Returns 0 if equal and 1 if not equal
#include "message.h"
int compare_file_infos(const struct file_info *p1, const struct file_info *p2)
{
	if (p1 == NULL || p2 == NULL)
		return 1;

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

char *get_program_cwd_from_pid(pid_t pid, size_t blen, char *buf)
{
	char path[PATH_MAX+1];
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
	strcpy(tpath, pcwd);
	// Add the relative path
	if (tlen >= PATH_MAX)
		tlen=PATH_MAX-1;
	strncat(tpath, path, PATH_MAX - tlen - 1);
	tpath[PATH_MAX] = 0;

	// Ask for it to be resolved
	if (realpath(tpath, path) == NULL) {
		strncpy(path, tpath, len);
		path[len - 1] = 0;
	}
}

char *get_file_from_fd(int fd, pid_t pid, size_t blen, char *buf)
{
	char procfd_path[PATH_MAX+1];
	ssize_t path_len;

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

// NOTE: This is probably risky to do from a root running program.
// Consider pushing this to a child process that has no permissions.
char *get_file_type_from_fd(int fd, size_t blen, char *buf)
{
	const char *ptr;

	ptr = magic_descriptor(magic_cookie, fd);
	if (ptr) {
		char *str;
		strncpy(buf, ptr, blen-1);
		buf[blen-1] = 0;
		str = strchr(buf, ';');
		if (str)
			*str = 0;
	} else
		return NULL;
	
	lseek(fd, 0, SEEK_SET);
	return buf;
}

// This function converts byte array into asciie hex
static char *bytes2hex(char *final, const char *buf, unsigned int size)
{
	unsigned int i;
	char *ptr = final;
	const char *hex = "0123456789ABCDEF";

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

char *get_hash_from_fd(int fd)
{
	gcry_md_hd_t ctx;
	gcry_error_t error;
	char fbuf[4096], *hptr, *digest;
	int len;

	// Initialize a context
	error=gcry_md_open(&ctx, GCRY_MD_SHA256, 0);
	if (error)
		return NULL;

	// read in a buffer at a time and hand to gcrypt
	while ((len = safe_read(fd, fbuf, 4096)) > 0) {
		gcry_md_write(ctx, fbuf, len);
		if (len != 4096)
			break;
	}
	
	// Ask for the grand total to be calculated
	gcry_md_final(ctx);

	// Ask for buffer size and allocate it
	len = gcry_md_get_algo_dlen(GCRY_MD_SHA256) * sizeof(char);
	digest = malloc((2 * len) + 1);

	// Get pointer to array of hex bytes
	hptr = (char *)gcry_md_read(ctx, GCRY_MD_SHA256);

	// Convert to ASCII string
	bytes2hex(digest, hptr, len);
	gcry_md_close(ctx);
	lseek(fd, 0, SEEK_SET);

	return digest;
}

static unsigned char e_ident[EI_NIDENT];

static int read_preliminary_header(int fd)
{
	ssize_t rc = safe_read(fd, (char *)e_ident, EI_NIDENT);
	if (rc == EI_NIDENT)
		return 0;
	return 1;
}

static Elf32_Ehdr *read_header32(int fd)
{
	Elf32_Ehdr *ptr = malloc(sizeof(Elf32_Ehdr));
	strcpy(ptr->e_ident, e_ident);
	ssize_t rc = safe_read(fd, (char *)&(ptr->e_type), sizeof(Elf32_Ehdr) - EI_NIDENT);
	if (rc == (sizeof(Elf32_Ehdr) - EI_NIDENT))
		return ptr;
	free(ptr);
	return NULL;
}

static Elf64_Ehdr *read_header64(int fd)
{
	Elf64_Ehdr *ptr = malloc(sizeof(Elf64_Ehdr));
	strcpy(ptr->e_ident, e_ident);
	ssize_t rc = safe_read(fd, (char *)&(ptr->e_type),
				sizeof(Elf64_Ehdr) - EI_NIDENT);
	if (rc == (sizeof(Elf64_Ehdr) - EI_NIDENT))
		return ptr;
	free(ptr);
	return NULL;
}

uint32_t gather_elf(int fd)
{
	//struct elf_info *e;
	uint32_t info = 0;
	if (read_preliminary_header(fd))
		return 0;

	if (strncmp((char *)e_ident, ELFMAG, 4))
		return 0;

	/* e = malloc(sizeof(struct elf_info));
	if (e == NULL)
		return 0;
	e->first_lib = NULL; */
	info |= IS_ELF;
	if (e_ident[4] == 1) {
		unsigned i;
		Elf32_Phdr *ph_tbl = NULL;
		
		Elf32_Ehdr *hdr = read_header32(fd);
		if (hdr == NULL)
			return 0;

		// Look for program header information
		// FIXME: Should there be a size check?
		ph_tbl = malloc(hdr->e_phentsize * hdr->e_phnum);
		if ((unsigned int)lseek(fd, (off_t)hdr->e_phoff, SEEK_SET) !=
					hdr->e_phoff)
			goto err_out32;

		// Read in complete table
		if ((unsigned int)safe_read(fd, (char *)ph_tbl,
					hdr->e_phentsize * hdr->e_phnum) !=
					hdr->e_phentsize * hdr->e_phnum)
			goto err_out32;

		// Check for rpath record
		for (i = 0; i < hdr->e_phnum; i++) {
			if (ph_tbl[i].p_type == PT_LOAD)
				info |= HAS_LOAD;
			else if (ph_tbl[i].p_type == PT_DYNAMIC) {
				unsigned int j = 0;
				unsigned int num;

				info |= HAS_DYNAMIC;
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
					} else if (dyn_tbl[j].d_tag == DT_RUNPATH)
						info |= HAS_RPATH;
					else if (dyn_tbl[j].d_tag == DT_RPATH) {
						info |= HAS_RPATH;
						break;
					}
					j++;
				} 
				free(dyn_tbl); 
			}
			if (info & HAS_RPATH)
				break;
		}
		goto done32;
err_out32:
//		free(e->first_lib);
//		free(e);
//		e = NULL;
		info |= HAS_ERROR;
done32:
		free(ph_tbl);
		free(hdr);
	} else if (e_ident[4] == 2) {
		unsigned i;
		Elf64_Phdr *ph_tbl;
		
		Elf64_Ehdr *hdr = read_header64(fd);
		if (hdr == NULL)
			return 0;

		// Look for program header information
		// FIXME: Should there be a size check?
		ph_tbl = malloc(hdr->e_phentsize * hdr->e_phnum);
		if ((unsigned int)lseek(fd, (off_t)hdr->e_phoff, SEEK_SET) !=
					hdr->e_phoff)
			goto err_out64;

		// Read in complete table
		if ((unsigned int)safe_read(fd, (char *)ph_tbl,
					hdr->e_phentsize * hdr->e_phnum) !=
					hdr->e_phentsize * hdr->e_phnum)
			goto err_out64;

		// Check for rpath record
		for (i = 0; i < hdr->e_phnum; i++) {
			if (ph_tbl[i].p_type == PT_LOAD)
				info |= HAS_LOAD;
			if (ph_tbl[i].p_type == PT_DYNAMIC) {
				unsigned int j = 0;
				unsigned int num;

				info |= HAS_DYNAMIC;
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
					} else if (dyn_tbl[j].d_tag == DT_RUNPATH)
						info |= HAS_RPATH;
					else if (dyn_tbl[j].d_tag == DT_RPATH) {
						info |= HAS_RPATH;
						break;
					}
					j++;
				}
				free(dyn_tbl); 
			}
			if (info & HAS_RPATH)
				break;
		}
		goto done64;
err_out64:
//		free(e->first_lib);
//		free(e);
//		e = NULL;
		info |= HAS_ERROR;
done64:
		free(ph_tbl);
		free(hdr);
	}
	lseek(fd, 0, SEEK_SET);
	return info;
}

