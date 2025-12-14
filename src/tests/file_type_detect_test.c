/*
 * file_type_detect_test.c - verify quick file type helpers
 */

#define _GNU_SOURCE
#include <errno.h>
#include <error.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "file.h"

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

int main(void)
{
	const unsigned char png_hdr[] = { 0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n' };
	const unsigned char jpg_hdr[] = { 0xFF, 0xD8, 0xFF, 0xE0 };
	const unsigned char gzip_hdr[] = { 0x1F, 0x8B, 0x08, 0x00 };
	const unsigned char pyc_hdr[] = { 0x03, 0xF3, '\r', '\n', 0, 0, 0, 0 };

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
		"text/xml");
	expect_text("plain", "just some text\n", strlen("just some text\n"), NULL);

	return 0;
}
