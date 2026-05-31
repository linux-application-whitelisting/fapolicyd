/*
 * ignore_mounts_risk_test.c - verify ignored-mount risk categories
 */

#define _GNU_SOURCE

#include <error.h>
#include <stdbool.h>
#include <string.h>
#include <sys/stat.h>

bool verbose;

#include "../cli/ignore-mounts.c"

struct risk_case {
	const char *label;
	const char *path;
	mode_t mode;
	const char *mime;
	const avl_tree_t *languages;
	unsigned int expected;
};

struct dir_case {
	const char *label;
	const char *path;
	unsigned int expected;
};

/*
 * expect_risk - verify that a file path and MIME produce expected risks.
 * @test: test case describing the path, MIME, language set, and expectation.
 * Returns nothing.
 */
static void expect_risk(const struct risk_case *test)
{
	struct stat sb;
	unsigned int got;

	memset(&sb, 0, sizeof(sb));
	sb.st_mode = S_IFREG | test->mode;

	got = classify_file_risks(test->path, &sb, test->mime,
				  test->languages);
	if (got != test->expected)
		error(1, 0, "%s: expected 0x%x got 0x%x", test->label,
		      test->expected, got);
}

/*
 * expect_dir_risk - verify that a directory path produces expected risks.
 * @test: test case describing the directory path and expectation.
 * Returns nothing.
 */
static void expect_dir_risk(const struct dir_case *test)
{
	unsigned int got = classify_dir_risks(test->path);

	if (got != test->expected)
		error(1, 0, "%s: expected 0x%x got 0x%x", test->label,
		      test->expected, got);
}

int main(void)
{
	avl_tree_t languages;
	struct risk_case risk_cases[] = {
		{
			"executable mode", "/mnt/bin/tool", 0755,
			"text/plain", NULL,
			RISK_BIT(RISK_EXECUTABLE_REGULAR)
		},
		{
			"elf shared", "/mnt/lib/libdemo.so", 0644,
			"application/x-sharedlib", NULL,
			RISK_BIT(RISK_ELF_SHARED)
		},
		{
			"archive extension", "/mnt/cache/app.JAR", 0644,
			"application/octet-stream", NULL,
			RISK_BIT(RISK_ARCHIVE)
		},
		{
			"archive mime", "/mnt/cache/blob", 0644,
			"application/zip", NULL,
			RISK_BIT(RISK_ARCHIVE)
		},
		{
			"bytecode cache", "/mnt/pkg/__pycache__/m.pyc", 0644,
			"application/octet-stream", NULL,
			RISK_BIT(RISK_BYTECODE)
		},
		{
			"python bytecode mime", "/mnt/pkg/module", 0644,
			"application/x-bytecode.python", NULL,
			RISK_BIT(RISK_BYTECODE)
		},
		{
			"elisp bytecode mime", "/mnt/pkg/module", 0644,
			"application/x-elc", NULL,
			RISK_BIT(RISK_BYTECODE)
		},
		{
			"zstd archive mime", "/mnt/cache/blob", 0644,
			"application/zstd", NULL,
			RISK_BIT(RISK_ARCHIVE)
		},
		{
			"language mime", "/mnt/scripts/task.py", 0644,
			"text/x-python", &languages,
			RISK_BIT(RISK_LANGUAGE)
		},
		{
			"combined risks", "/mnt/pkg/app.zip", 0755,
			"application/x-executable", NULL,
			RISK_BIT(RISK_EXECUTABLE_REGULAR) |
			RISK_BIT(RISK_ELF_SHARED) |
			RISK_BIT(RISK_ARCHIVE)
		},
		{ NULL, NULL, 0, NULL, NULL, 0 }
	};
	struct dir_case dir_cases[] = {
		{
			"pycache dir", "/mnt/pkg/__pycache__",
			RISK_BIT(RISK_BYTECODE)
		},
		{
			"runtime dir", "/mnt/pkg/site-packages",
			RISK_BIT(RISK_PLUGIN_RUNTIME_DIR)
		},
		{ "ordinary dir", "/mnt/data/reports", 0 },
		{ NULL, NULL, 0 }
	};

	avl_init(&languages, compare_language_entry);
	if (insert_language_mime(&languages, "text/x-python"))
		error(1, 0, "failed to add language MIME");

	for (unsigned int i = 0; risk_cases[i].label; i++)
		expect_risk(&risk_cases[i]);
	for (unsigned int i = 0; dir_cases[i].label; i++)
		expect_dir_risk(&dir_cases[i]);

	free_language_mimes(&languages);
	return 0;
}
