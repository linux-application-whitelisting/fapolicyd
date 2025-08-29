/*
 * filter_test.c - tests for filter configuration loading and matching
 */
#include <stdio.h>
#include <stdlib.h>

#include "filter.h"

struct test_case {
	const char *path;
	int expected;
};

int main(void)
{
	struct test_case tests[] = {
		{ "/usr/include/stdio.h", 0 },
		{ "/usr/share/doc.txt", 1 },
		{ "/usr/share/cache.tmp", 1 },
		{ "/usr/share/script.py", 1 },
		{ "/usr/src/kernel123/driver.c", 1 },
		{ "/usr/src/kernel123/scripts/build", 1 },
		{ "/etc/hosts", 1 },
		{ "/var/log/messages", 1 },
		{ "/var/log/public/info.log", 1 },
	};
	int rc = 0;

	const char *conf = getenv("FILTER_CONF");
	if (conf == NULL) {
		fprintf(stderr, "FILTER_CONF environmental variable is missing\n");
		return 1;
	}

	if (filter_init()) {
		fprintf(stderr, "filter_init failed\n");
		return 2;
	}

	if (filter_load_file(conf)) {
		fprintf(stderr, "filter_load_file failed for %s\n", conf);
		filter_destroy();
		return 3;
	}

	for (size_t i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		int res = filter_check(tests[i].path);
		if (res != tests[i].expected) {
			fprintf(stderr,
				"test %zu failed for %s: got %d expected %d\n",
				i, tests[i].path, res, tests[i].expected);
			rc = 4;
		}
	}

	filter_destroy();
	return rc;
}

