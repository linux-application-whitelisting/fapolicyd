/*
 * escape_test.c - tests for shell escaping helpers
 */

#include "escape.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <error.h>

int main(void)
{
	char *tmp;
	size_t sz;

	/* check_escape_shell */
	sz = check_escape_shell("plain");
	if (sz != 0) {
		fprintf(stderr, "[ERROR:1] plain input %zu\n", sz);
		return 1;
	}
	sz = check_escape_shell("a b");
	if (sz != 4) {
		fprintf(stderr, "[ERROR:1] space %zu\n", sz);
		return 1;
	}
	sz = check_escape_shell("a$b");
	if (sz != 4) {
		fprintf(stderr, "[ERROR:1] metachar %zu\n", sz);
		return 1;
	}
	sz = check_escape_shell("a\nb");
	if (sz != 6) {
		fprintf(stderr, "[ERROR:1] control %zu\n", sz);
		return 1;
	}

	/* escape_shell */
	tmp = escape_shell(NULL, 0);
	if (tmp) {
		fprintf(stderr, "[ERROR:2] NULL input\n");
		free(tmp);
		return 2;
	}
	char big_in[8192];
	strcpy(big_in, "abc");
	tmp = escape_shell(big_in, 8192);
	if (tmp) {
		fprintf(stderr, "[ERROR:2] size check\n");
		free(tmp);
		return 2;
	}
	sz = check_escape_shell("a b");
	tmp = escape_shell("a b", sz);
	if (!tmp) {
		fprintf(stderr, "[ERROR:2] escape_shell failed\n");
		return 2;
	}
	if (strcmp(tmp, "a\\ b")) {
		fprintf(stderr, "[ERROR:2] escaped '%s'\n", tmp);
		free(tmp);
		return 2;
	}
	free(tmp);

	/* unescape_shell */
	char buf1[] = "\\040\\$";
	unescape_shell(buf1, sizeof(buf1));
	if (strcmp(buf1, " $")) {
		fprintf(stderr, "[ERROR:3] unescape_shell octal '%s'\n", buf1);
		return 3;
	}
	char buf2[] = "abc\\";
	unescape_shell(buf2, sizeof(buf2));
	if (strcmp(buf2, "abc\\")) {
		fprintf(stderr, "[ERROR:3] trailing '%s'\n", buf2);
		return 3;
	}
	char buf3[] = "abc\\0";
	unescape_shell(buf3, strlen(buf3));
	if (strcmp(buf3, "abc\\0")) {
		fprintf(stderr, "[ERROR:3] malformed '%s'\n", buf3);
		return 3;
	}

	/* unescape */
	tmp = unescape("%41%42");
	if (!tmp || strcmp(tmp, "AB")) {
		fprintf(stderr, "[ERROR:4] unescape valid\n");
		free(tmp);
		return 4;
	}
	free(tmp);
	tmp = unescape("%4");
	if (!tmp || strcmp(tmp, "%4")) {
		fprintf(stderr, "[ERROR:4] unescape short\n");
		free(tmp);
		return 4;
	}
	free(tmp);
	tmp = unescape("%GG");
	if (!tmp || strcmp(tmp, "%GG")) {
		fprintf(stderr, "[ERROR:4] unescape invalid\n");
		free(tmp);
		return 4;
	}
	free(tmp);
	char big[4097 + 1];
	memset(big, 'A', sizeof(big));
	big[sizeof(big) - 1] = '\0';
	tmp = unescape(big);
	if (tmp) {
		fprintf(stderr, "[ERROR:4] unescape big\n");
		free(tmp);
		return 4;
	}

	return 0;
}
