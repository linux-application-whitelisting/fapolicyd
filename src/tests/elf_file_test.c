/*
 * elf_file_test.c - verify gather_elf flag classification
 *
 * Each case writes a synthetic object into an anonymous descriptor created
 * by memfd_create (or an unlinked temporary file when memfd is unavailable),
 * then checks the returned flag bitmap.  Coverage includes 32-bit/64-bit
 * executables, text and shebang scripts, truncated ELF headers, and an
 * oversized program header table.  The expectations cover IS_ELF, HAS_LOAD,
 * HAS_ERROR, TEXT_SCRIPT, HAS_SHEBANG, and HAS_RWE_LOAD.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <elf.h>

#include "file.h"
#include "process.h"

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0
#endif

static void build_ident(unsigned char ident[EI_NIDENT], unsigned char elf_class)
{
	memset(ident, 0, EI_NIDENT);
	ident[EI_MAG0] = ELFMAG0;
	ident[EI_MAG1] = ELFMAG1;
	ident[EI_MAG2] = ELFMAG2;
	ident[EI_MAG3] = ELFMAG3;
	ident[EI_CLASS] = elf_class;
	ident[EI_DATA] = ELFDATA2LSB;
	ident[EI_VERSION] = EV_CURRENT;
}

static size_t make_elf32(unsigned char *buf, int with_load)
{
	Elf32_Ehdr *eh = (Elf32_Ehdr *)buf;
	Elf32_Phdr *ph = (Elf32_Phdr *)(buf + sizeof(Elf32_Ehdr));

	memset(buf, 0, sizeof(Elf32_Ehdr) + sizeof(Elf32_Phdr));
	build_ident(eh->e_ident, ELFCLASS32);
	eh->e_type = ET_EXEC;
	eh->e_machine = EM_386;
	eh->e_version = EV_CURRENT;
	eh->e_entry = 0x8048000;
	eh->e_phoff = sizeof(Elf32_Ehdr);
	eh->e_ehsize = sizeof(Elf32_Ehdr);
	eh->e_phentsize = sizeof(Elf32_Phdr);
	eh->e_phnum = with_load ? 1 : 0;

	if (!with_load)
		return sizeof(Elf32_Ehdr);

	ph->p_type = PT_LOAD;
	ph->p_offset = 0;
	ph->p_vaddr = 0x8048000;
	ph->p_paddr = 0x8048000;
	ph->p_filesz = 0x1000;
	ph->p_memsz = 0x1000;
	ph->p_flags = PF_R | PF_X;
	ph->p_align = 0x1000;

	return sizeof(Elf32_Ehdr) + sizeof(Elf32_Phdr);
}

static size_t make_elf64(unsigned char *buf, unsigned int flags)
{
	Elf64_Ehdr *eh = (Elf64_Ehdr *)buf;
	Elf64_Phdr *ph = (Elf64_Phdr *)(buf + sizeof(Elf64_Ehdr));

	memset(buf, 0, sizeof(Elf64_Ehdr) + sizeof(Elf64_Phdr));
	build_ident(eh->e_ident, ELFCLASS64);
	eh->e_type = ET_EXEC;
	eh->e_machine = EM_X86_64;
	eh->e_version = EV_CURRENT;
	eh->e_entry = 0x400000;
	eh->e_phoff = sizeof(Elf64_Ehdr);
	eh->e_ehsize = sizeof(Elf64_Ehdr);
	eh->e_phentsize = sizeof(Elf64_Phdr);
	eh->e_phnum = 1;

	ph->p_type = PT_LOAD;
	ph->p_offset = 0;
	ph->p_vaddr = 0x400000;
	ph->p_paddr = 0x400000;
	ph->p_filesz = 0x2000;
	ph->p_memsz = 0x2000;
	ph->p_flags = flags;
	ph->p_align = 0x200000;

	return sizeof(Elf64_Ehdr) + sizeof(Elf64_Phdr);
}

static size_t make_elf64_header_only(unsigned char *buf, unsigned short phnum)
{
	Elf64_Ehdr *eh = (Elf64_Ehdr *)buf;

	memset(buf, 0, sizeof(Elf64_Ehdr));
	build_ident(eh->e_ident, ELFCLASS64);
	eh->e_type = ET_EXEC;
	eh->e_machine = EM_X86_64;
	eh->e_version = EV_CURRENT;
	eh->e_entry = 0x400000;
	eh->e_phoff = sizeof(Elf64_Ehdr);
	eh->e_ehsize = sizeof(Elf64_Ehdr);
	eh->e_phentsize = sizeof(Elf64_Phdr);
	eh->e_phnum = phnum;

	return sizeof(Elf64_Ehdr);
}

static size_t make_truncated32(unsigned char *buf)
{
	memset(buf, 0, EI_NIDENT + 4);
	build_ident(buf, ELFCLASS32);
	return EI_NIDENT + 4;
}

static int fd_from_buffer(const char *name, const void *buf, size_t len)
{
	int fd = memfd_create(name, MFD_CLOEXEC);
	if (fd < 0) {
		char path[] = "/tmp/fapolicyd-elftest-XXXXXX";
		fd = mkstemp(path);
		if (fd < 0)
			return -1;
		unlink(path);
	}

	if (write(fd, buf, len) != (ssize_t)len) {
		int saved = errno;
		close(fd);
		errno = saved;
		return -1;
	}

	if (lseek(fd, 0, SEEK_SET) < 0) {
		int saved = errno;
		close(fd);
		errno = saved;
		return -1;
	}

	return fd;
}

static void expect_flags(const char *label, const void *buf, size_t len, uint32_t expect)
{
	int fd = fd_from_buffer(label, buf, len);
	if (fd < 0)
		error(1, errno, "%s: unable to obtain descriptor", label);

	uint32_t got = gather_elf(fd, (off_t)len);
	close(fd);

	if (got != expect)
		error(1, 0, "%s: expected 0x%x got 0x%x", label, expect, got);
}

int main(void)
{
	unsigned char buf[sizeof(Elf64_Ehdr) + sizeof(Elf64_Phdr)];
	unsigned char shebang[] = "#!/bin/sh\nexit 0\n";
	unsigned char text_script[] = "echo hello world\n";
	unsigned char trunc_buf[EI_NIDENT + 4];

	size_t sz32 = make_elf32(buf, 1);
	expect_flags("elf32-load", buf, sz32, IS_ELF | HAS_EXEC | HAS_LOAD);

	size_t sz64 = make_elf64(buf, PF_R | PF_W | PF_X);
	expect_flags("elf64-rwe", buf, sz64,
		     IS_ELF | HAS_EXEC | HAS_LOAD | HAS_RWE_LOAD);

	size_t shebang_len = sizeof(shebang) - 1;
	expect_flags("shebang", shebang, shebang_len, HAS_SHEBANG);

	size_t text_len = sizeof(text_script) - 1;
	expect_flags("text-script", text_script, text_len, TEXT_SCRIPT);

	size_t bad32 = make_truncated32(trunc_buf);
	expect_flags("truncated32", trunc_buf, bad32, IS_ELF | HAS_ERROR);

	size_t head64 = make_elf64_header_only(buf, 4);
	expect_flags("oversized-ph", buf, head64, IS_ELF | HAS_EXEC | HAS_ERROR);

	return 0;
}
