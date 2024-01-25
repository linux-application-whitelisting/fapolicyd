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

#include "file.h"
#include "message.h"
#include "process.h" // For elf info bit mask

// Local defines
#define IMA_XATTR_DIGEST_NG 0x04	// security/integrity/integrity.h

// Local variables
static struct udev *udev;
magic_t magic_cookie;
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
	"/lib/ld-linux-armhf.so.3",   // fedora armv7hl
	"/lib/ld-linux-aarch64.so.1", // fedora aarch64
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
	magic_cookie = magic_open(MAGIC_MIME|MAGIC_ERROR|MAGIC_NO_CHECK_CDF|
			MAGIC_NO_CHECK_ELF);
	if (magic_cookie == NULL) {
		msg(LOG_ERR, "Unable to init libmagic");
		exit(1);
	}
	// Load our overrides and the default magic definitions
	if (magic_load(magic_cookie,
	  "/usr/share/fapolicyd/fapolicyd-magic.mgc:/usr/share/misc/magic.mgc")
									!= 0) {
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


// This function will determine the mime type of the passed file descriptor.
// If it returns NULL, then an error of some kind happed. Otherwise it
// fills in "buf" and returns a pointer to it.
char *get_file_type_from_fd(int fd, const struct file_info *i, const char *path,
	size_t blen, char *buf)
{
	const char *ptr;

	// libmagic is unpredictable in determining elf files.
	// We need to do it ourselves for consistency.
	if (i->mode & S_IFREG) {
		uint32_t elf = gather_elf(fd, i->size);
		if (elf) {
			ptr = classify_elf_info(elf, path);
			if (ptr == NULL)
				return (char *)ptr;
			return strncpy(buf, ptr, blen-1);
		}
	}

	// Take a look to see if its a device
	ptr = classify_device(i->mode);
	if (ptr)
		return strncpy(buf, ptr, blen-1);

	// Do the normal classification
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
 * Given a fd, calculate the hash by accessing size bytes of the file.
 * Calculate SHA256 by default or compute MD5.
 * Returns a char pointer of the hash which the caller must free.
 * If a size of 0 is passed, it will return a NULL pointer.
 * If there is an error with mmap, it will also return a NULL pointer.
 */
static const char *degenerate_hash_sha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
static const char *degenerate_hash_md5 = "d41d8cd98f00b204e9800998ecf8427e";
char *get_hash_from_fd2(int fd, size_t size, const int is_sha)
{
	unsigned char *mapped;
	char *digest = NULL;

	if (size == 0) {
		if (is_sha)
			return strdup(degenerate_hash_sha);
		return strdup(degenerate_hash_md5);
	}

	mapped = mmap(0, size, PROT_READ, MAP_PRIVATE|MAP_POPULATE, fd, 0);
	if (mapped != MAP_FAILED) {
		const int digest_length = is_sha ? SHA256_DIGEST_LENGTH : 16;
		// Just use the larger one as buffer.
		unsigned char hptr[SHA256_DIGEST_LENGTH];

		if (is_sha) {
			SHA256(mapped, size, (unsigned char *)&hptr);
		} else {
			MD5(mapped, size, (unsigned char *)&hptr);
		}
		munmap(mapped, size);
		digest = malloc((SHA256_LEN * 2) + 1);

		// Convert to ASCII string
		bytes2hex(digest, hptr, digest_length);
	}
	return digest;
}

// This function returns 0 on error and 1 if successful
int get_ima_hash(int fd, char *sha)
{
	unsigned char tmp[34];

	if (fgetxattr(fd, "security.ima", tmp, sizeof(tmp)) < 0) {
		msg(LOG_DEBUG, "Can't read ima xattr");
		return 0;
	}

	// Let's check what we got
	if (tmp[0] != IMA_XATTR_DIGEST_NG) {
		msg(LOG_DEBUG, "Wrong ima xattr type");
		return 0;
	}
	if (tmp[1] != HASH_ALGO_SHA256) {
		msg(LOG_DEBUG, "Wrong ima hash algorithm");
		return 0;
	}

	// Looks like it what we want...
	bytes2hex(sha, &tmp[2], SHA256_LEN);
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


// size is the file size from fstat done when event was received
uint32_t gather_elf(int fd, off_t size)
{
	uint32_t info = 0;

	if (read_preliminary_header(fd))
		goto rewind_out;

	if (strncmp((char *)e_ident, ELFMAG, 4))
		goto rewind_out;

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
				char interp[23];
				uint32_t filesz = ph_tbl[i].p_filesz;
				uint32_t offset = ph_tbl[i].p_offset;

				info |= HAS_INTERP;
				if ((unsigned int) lseek(fd, offset, SEEK_SET)
								!= offset)
					goto err_out32;

				len = (filesz < 23 ? filesz : 23);

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
				char interp[33];
				uint64_t filesz = ph_tbl[i].p_filesz;
				uint64_t offset = ph_tbl[i].p_offset;

				info |= HAS_INTERP;
				if ((unsigned int) lseek(fd, offset, SEEK_SET)
								!= offset)
					goto err_out64;

				len = (filesz < 33 ? filesz : 33);

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
	} else // Invalid ELF class
		info |= HAS_ERROR;
rewind_out:
	rewind_fd(fd);
	return info;
}
