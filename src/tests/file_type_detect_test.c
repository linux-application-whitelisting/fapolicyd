/*
 * file_type_detect_test.c - verify quick file type helpers
 */

#define _GNU_SOURCE
#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <magic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "file.h"

extern magic_t magic_fast, magic_full;

#ifndef TEST_BASE
#define TEST_BASE "."
#endif

static void expect_extract(const char *label, const char *script,
	const char *expected)
{
	char buf[64];
	size_t len = strlen(script);
	const char *got = extract_shebang_interpreter(script, len, buf,
		sizeof(buf));

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
	const char *got = detect_by_magic_number(hdr, len);

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
	char local[513];

	if (len >= sizeof(local))
		error(1, 0, "%s: test buffer too large", label);

	memcpy(local, buf, len);
	local[len] = '\0';

	const char *got = detect_text_format(local, len);

	if (expected == NULL) {
		if (got != NULL)
			error(1, 0, "%s: expected NULL, got %s", label, got);
		return;
	}

	if (!got || strcmp(got, expected) != 0)
		error(1, 0, "%s: expected %s got %s", label, expected,
		      got ? got : "(null)");
}

/*
 * init_magic_handles - initialize the libmagic handles used by file.c globals.
 * Returns 0 on success, -1 on failure.
 */
static int init_magic_handles(void)
{
	char path[512];
	const char *fast_db[] = {
		TEST_BASE "/init/fapolicyd-magic",
		"./init/fapolicyd-magic",
		"../init/fapolicyd-magic",
		"../../init/fapolicyd-magic",
		NULL,
	};
	int i;

	unsetenv("MAGIC");
	magic_fast = magic_open(
		MAGIC_MIME |
		MAGIC_ERROR |
		MAGIC_NO_CHECK_CDF |
		MAGIC_NO_CHECK_ELF |
		MAGIC_NO_CHECK_COMPRESS |
		MAGIC_NO_CHECK_TAR |
		MAGIC_NO_CHECK_APPTYPE |
		MAGIC_NO_CHECK_TOKENS |
		MAGIC_NO_CHECK_JSON
	);
	if (!magic_fast)
		return -1;

	for (i = 0; fast_db[i]; i++) {
		(void)snprintf(path, sizeof(path), "%s", fast_db[i]);
		if (magic_load(magic_fast, path) == 0)
			break;
	}
	if (!fast_db[i])
		return -1;

	magic_full = magic_open(MAGIC_MIME | MAGIC_ERROR |
		MAGIC_NO_CHECK_CDF | MAGIC_NO_CHECK_ELF);
	if (!magic_full)
		return -1;

	if (magic_load(magic_full, NULL) != 0)
		return -1;

	return 0;
}

/*
 * close_magic_handles - release libmagic handles used in direct tests.
 */
static void close_magic_handles(void)
{
	if (magic_fast)
		magic_close(magic_fast);
	if (magic_full)
		magic_close(magic_full);
}

/*
 * create_tmp_file - create a temporary file populated with text content.
 * Returns a readable descriptor on success.
 */
static int create_tmp_file(const char *content)
{
	char path[] = "/tmp/file-type-test-XXXXXX";
	int fd = mkstemp(path);
	size_t len = strlen(content);

	if (fd < 0)
		error(1, errno, "mkstemp failed");

	if (unlink(path) != 0)
		error(1, errno, "unlink failed");

	if (write(fd, content, len) != (ssize_t)len)
		error(1, errno, "write failed");

	if (lseek(fd, 0, SEEK_SET) != 0)
		error(1, errno, "lseek failed");

	return fd;
}

/*
 * expect_magic_descriptor - call magic_descriptor directly and compare mime.
 */
static void expect_magic_descriptor(const char *label, magic_t cookie,
		int fd, const char *expected)
{
	const char *got;
	char type[128];
	const char *semi;
	size_t len;

	if (lseek(fd, 0, SEEK_SET) != 0)
		error(1, errno, "%s: lseek failed", label);

	got = magic_descriptor(cookie, fd);
	if (!got)
		error(1, 0, "%s: expected %s got (null)", label, expected);

	semi = strchr(got, ';');
	len = semi ? (size_t)(semi - got) : strlen(got);
	if (len >= sizeof(type))
		error(1, 0, "%s: mime too large", label);

	memcpy(type, got, len);
	type[len] = '\0';

	if (strcmp(type, expected) != 0)
		error(1, 0, "%s: expected %s got %s", label, expected,
		      type);
}

int main(void)
{
	int fd;
	const unsigned char png_hdr[] = { 0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n' };
	const unsigned char jpg_hdr[] = { 0xFF, 0xD8, 0xFF, 0xE0 };
	const unsigned char gzip_hdr[] = { 0x1F, 0x8B, 0x08, 0x00 };

	if (init_magic_handles() != 0)
		error(1, 0, "failed to initialize test libmagic handles");

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
	expect_magic("unknown", (const unsigned char *)"abc", 3, NULL);

	expect_text("html", "   <!DOCTYPE html><html></html>\n",
	strlen("   <!DOCTYPE html><html></html>\n"), "text/html");
	expect_text("plain", "just some text\n", strlen("just some text\n"), NULL);

	if (strcmp(classify_device(S_IFIFO), "inode/fifo") != 0)
		error(1, 0, "classify_device: expected inode/fifo");

	fd = create_tmp_file("#!/bin/awk\nBEGIN { print 1 }\n");
	expect_magic_descriptor("full-awk-bin", magic_full, fd, "text/x-awk");
	close(fd);

	fd = create_tmp_file("#!/usr/bin/gawk\nBEGIN { print 1 }\n");
	expect_magic_descriptor("full-gawk-usr-bin", magic_full, fd,
		"text/x-gawk");
	close(fd);

	fd = create_tmp_file("#!/usr/bin/perl\nprint qq(hi);\n");
	expect_magic_descriptor("full-perl-usr-bin", magic_full, fd,
		"text/x-perl");
	close(fd);

	fd = create_tmp_file("#!/usr/bin/python3\nprint(1)\n");
	expect_magic_descriptor("full-python-usr-bin", magic_full, fd,
		"text/x-script.python");
	close(fd);

	fd = create_tmp_file("#!/usr/bin/R\nprint(1)\n");
	expect_magic_descriptor("full-r-usr-bin", magic_full, fd, "text/plain");
	close(fd);

	fd = create_tmp_file("#!/usr/bin/guile\n(display 1)\n");
	expect_magic_descriptor("fast-guile-usr-bin", magic_fast, fd,
		"text/x-script.guile");
	close(fd);

	fd = create_tmp_file("#!/usr/bin/gjs\nprint(1);\n");
	expect_magic_descriptor("fast-gjs-usr-bin", magic_fast, fd,
		"application/javascript");
	close(fd);

	fd = create_tmp_file("#!/usr/sbin/nft\nadd table inet t\n");
	expect_magic_descriptor("fast-nft-usr-sbin", magic_fast, fd,
		"text/x-nftables");
	close(fd);

	close_magic_handles();

	return 0;
}
