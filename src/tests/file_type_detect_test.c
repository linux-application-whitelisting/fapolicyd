/*
 * file_type_detect_test.c - verify quick file type helpers
 */

#define _GNU_SOURCE
#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

#include "file.h"

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0
#endif

static int fd_from_buffer(const char *name, const void *buf, size_t len)
{
	int fd = memfd_create(name, MFD_CLOEXEC);

	if (fd < 0) {
		char path[] = "/tmp/fapolicyd-filetype-XXXXXX";

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

static void expect_extract(const char *label, const char *script,
			    const char *expected)
{
	char buf[64];
	int fd = fd_from_buffer(label, script, strlen(script));

	if (fd < 0)
		error(1, errno, "%s: unable to obtain descriptor", label);

	const char *got = extract_shebang_interpreter(fd, buf, sizeof(buf));
	close(fd);

	if (expected == NULL) {
		if (got != NULL)
			error(1, 0, "%s: expected NULL, got %s", label, got);
		return;
	}

	if (!got || strcmp(got, expected) != 0)
		error(1, 0, "%s: expected %s got %s", label, expected,
		      got ? got : "(null)");
}

static void expect_mime(const char *label, const char *interp,
			const char *expected)
{
	const char *got = mime_from_shebang(interp);

	if (expected == NULL) {
		if (got != NULL)
			error(1, 0, "%s: expected NULL, got %s", label, got);
		return;
	}

	if (!got || strcmp(got, expected) != 0)
		error(1, 0, "%s: expected %s got %s", label, expected,
		      got ? got : "(null)");
}

static void expect_magic(const char *label, const unsigned char *hdr,
			  size_t len, const char *expected)
{
	int fd = fd_from_buffer(label, hdr, len);

	if (fd < 0)
		error(1, errno, "%s: unable to obtain descriptor", label);

	const char *got = detect_by_magic_number(fd);
	close(fd);

	if (expected == NULL) {
		if (got != NULL)
			error(1, 0, "%s: expected NULL, got %s", label, got);
		return;
	}

	if (!got || strcmp(got, expected) != 0)
		error(1, 0, "%s: expected %s got %s", label, expected,
		      got ? got : "(null)");
}

static void expect_text(const char *label, const char *buf, size_t len,
			 const char *expected)
{
	int fd = fd_from_buffer(label, buf, len);

	if (fd < 0)
		error(1, errno, "%s: unable to obtain descriptor", label);

	const char *got = detect_text_format(fd);
	close(fd);

	if (expected == NULL) {
		if (got != NULL)
			error(1, 0, "%s: expected NULL, got %s", label, got);
		return;
	}

	if (!got || strcmp(got, expected) != 0)
		error(1, 0, "%s: expected %s got %s", label, expected,
		      got ? got : "(null)");
}

int main(void)
{
	const unsigned char png_hdr[] = { 0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n' };
	const unsigned char jpg_hdr[] = { 0xFF, 0xD8, 0xFF, 0xE0 };
	const unsigned char gzip_hdr[] = { 0x1F, 0x8B, 0x08, 0x00 };
	const unsigned char pyc_hdr[] = { 0x03, 0xF3, '\r', '\n', 0, 0, 0, 0 };
	const unsigned char bom_json[] = { 0xEF, 0xBB, 0xBF, ' ', '{', '"', 'k', '"', ':', '1', '}' };

	expect_extract("bash", "#!/bin/bash\n", "bash");
	expect_extract("env-python", "#! /usr/bin/env -S python3 -u\n", "python3");
	expect_extract("env-path", "#!/usr/bin/env /opt/perl5.32/bin/perl5.32\n",
	"perl5");
	expect_extract("no-shebang", "echo hello\n", NULL);

	expect_mime("shell", "bash", "text/x-shellscript");
	expect_mime("python", "python3", "text/x-python");
	expect_mime("php", "php", "text/x-php");
	expect_mime("unknown", "ruby", NULL);

	expect_magic("png", png_hdr, sizeof(png_hdr), "image/png");
	expect_magic("jpeg", jpg_hdr, sizeof(jpg_hdr), "image/jpeg");
	expect_magic("gzip", gzip_hdr, sizeof(gzip_hdr), "application/gzip");
	expect_magic("pyc", pyc_hdr, sizeof(pyc_hdr), "application/x-bytecode.python");
	expect_magic("unknown", (const unsigned char *)"abc", 3, NULL);

	expect_text("html", "   <!DOCTYPE html><html></html>\n",
	strlen("   <!DOCTYPE html><html></html>\n"), "text/html");
	expect_text("xml", "\n<?xml version=\"1.0\"?><root/>",
	strlen("\n<?xml version=\"1.0\"?><root/>"),
	"application/xml");
	expect_text("json", (const char *)bom_json, sizeof(bom_json),
	"application/json");
	expect_text("plain", "just some text\n", strlen("just some text\n"), NULL);

	return 0;
}
