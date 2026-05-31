/*
 * ignore-mounts.c - CLI ignore_mounts scanner
 * Copyright (c) 2026 Red Hat Inc.
 * All Rights Reserved.
 *
 * This software may be freely redistributed and/or modified under the
 * terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2, or (at your option) any
 * later version.
 */

#include "config.h"
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <limits.h>
#include <mntent.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <unistd.h>
#include "avl.h"
#include "conf.h"
#include "daemon-config.h"
#include "file-cli.h"
#include "file.h"
#include "ignore-mounts.h"
#include "llist.h"
#include "message.h"
#include "paths.h"
#include "string-util.h"

extern bool verbose;
extern conf_t config;

enum risk_category {
	RISK_EXECUTABLE_REGULAR,
	RISK_ELF_SHARED,
	RISK_ARCHIVE,
	RISK_BYTECODE,
	RISK_PLUGIN_RUNTIME_DIR,
	RISK_LANGUAGE,
	RISK_CATEGORY_COUNT
};

#define RISK_BIT(risk) (1U << (risk))

struct risk_counts {
	unsigned long total_entries;
	unsigned long category[RISK_CATEGORY_COUNT];
};

struct mount_scan_state {
	const avl_tree_t *languages;
	struct risk_counts *counts;
	int had_error;
};

static struct mount_scan_state scan_state;
static const char * const risk_labels[RISK_CATEGORY_COUNT] = {
	"executable regular files",
	"ELF/shared objects",
	"archives/JARs/ZIPs",
	"bytecode caches",
	"plugin/runtime directories",
	"language/interpreter files",
};

/*
 * reset_ignore_mounts_config - release CLI config used during the scan.
 * Returns nothing.
 */
static void reset_ignore_mounts_config(void)
{
	free_daemon_config(&config);
	memset(&config, 0, sizeof(config));
}

/*
 * append_mount_entry - duplicate an ignore_mounts entry into a list.
 * @mount: trimmed ignore_mounts entry.
 * @data: list receiving duplicated entries.
 * Returns 0 on success and 1 on allocation failure.
 */
static int append_mount_entry(const char *mount, void *data)
{
	list_t *mounts = data;
	char *copy = strdup(mount);

	if (copy == NULL)
		return 1;

	if (list_append(mounts, copy, NULL)) {
		free(copy);
		return 1;
	}

	return 0;
}

/*
 * populate_mount_list - split ignore_mounts string into individual entries.
 * @ignore_list: comma separated mount list from the configuration.
 * @mounts: list that receives duplicated mount paths.
 * Returns 0 on success and 1 on allocation failure.
 */
static int populate_mount_list(const char *ignore_list, list_t *mounts)
{
	int rc;

	if (ignore_list == NULL)
		return 0;

	rc = iterate_ignore_mounts(ignore_list, append_mount_entry, mounts);
	if (rc) {
		list_empty(mounts);
		return 1;
	}

	return 0;
}

/*
 * path_basename - return the final path component without modifying path.
 * @path: path to inspect.
 * Returns a pointer inside @path.
 */
static const char *path_basename(const char *path)
{
	const char *slash = strrchr(path, '/');

	return slash ? slash + 1 : path;
}

/*
 * name_in_list - compare a name against a NULL terminated list.
 * @name: file or directory basename.
 * @list: NULL terminated list of lowercase names.
 * Returns 1 when @name matches a list entry, 0 otherwise.
 */
static int name_in_list(const char *name, const char * const *list)
{
	for (unsigned int i = 0; list[i]; i++) {
		if (strcasecmp(name, list[i]) == 0)
			return 1;
	}

	return 0;
}

/*
 * path_has_suffix - case-insensitive suffix check for risk extensions.
 * @path: path to inspect.
 * @suffix: file suffix, including the leading period.
 * Returns 1 when @path ends in @suffix, 0 otherwise.
 */
static int path_has_suffix(const char *path, const char *suffix)
{
	size_t path_len = strlen(path);
	size_t suffix_len = strlen(suffix);

	if (path_len < suffix_len)
		return 0;

	return strcasecmp(path + path_len - suffix_len, suffix) == 0;
}

/*
 * path_has_suffix_list - check a path against known risk extensions.
 * @path: path to inspect.
 * @suffixes: NULL terminated list of suffixes.
 * Returns 1 when any suffix matches, 0 otherwise.
 */
static int path_has_suffix_list(const char *path,
				const char * const *suffixes)
{
	for (unsigned int i = 0; suffixes[i]; i++) {
		if (path_has_suffix(path, suffixes[i]))
			return 1;
	}

	return 0;
}

/*
 * path_has_component - find an exact component in a slash separated path.
 * @path: path to inspect.
 * @component: component name to find.
 * Returns 1 when the component is present, 0 otherwise.
 */
static int path_has_component(const char *path, const char *component)
{
	const char *match = path;
	size_t component_len = strlen(component);

	while ((match = strstr(match, component))) {
		int left_ok = match == path || match[-1] == '/';
		int right_ok = match[component_len] == 0 ||
			       match[component_len] == '/';

		if (left_ok && right_ok)
			return 1;
		match += component_len;
	}

	return 0;
}

struct language_entry {
	avl_t avl;
	char *mime;
};

/*
 * compare_language_entry - compare two MIME tree nodes alphabetically.
 * @a: first tree entry for comparison.
 * @b: second tree entry for comparison.
 * Returns <0 when @a sorts before @b, >0 when it sorts after, and 0 when they
 * match.
 */
static int compare_language_entry(void *a, void *b)
{
	const struct language_entry *la = a;
	const struct language_entry *lb = b;

	return strcmp(la->mime, lb->mime);
}

/*
 * insert_language_mime - add a MIME string to the %languages tree.
 * @languages: AVL tree tracking the known MIME values.
 * @mime: MIME string trimmed from the rules file.
 * Returns 0 on success and 1 on allocation failure.
 */
static int insert_language_mime(avl_tree_t *languages, const char *mime)
{
	struct language_entry *entry;
	avl_t *ret;

	entry = malloc(sizeof(*entry));
	if (entry == NULL)
		return 1;

	entry->mime = strdup(mime);
	if (entry->mime == NULL) {
		free(entry);
		return 1;
	}

	ret = avl_insert(languages, &entry->avl);
	if (ret != &entry->avl) {
		free(entry->mime);
		free(entry);
	}

	return 0;
}

/*
 * free_language_mimes - release all nodes stored in the MIME AVL tree.
 * @languages: AVL tree previously filled by load_language_mimes().
 */
static void free_language_mimes(avl_tree_t *languages)
{
	while (languages->root) {
		struct language_entry *entry =
			(struct language_entry *)languages->root;

		avl_remove(languages, &entry->avl);
		free(entry->mime);
		free(entry);
	}
}

/*
 * mime_is_language - check whether MIME belongs to the %languages macro.
 * @languages: AVL tree built from %languages.
 * @mime: MIME string returned by file type detection.
 * Returns 1 on match, 0 otherwise.
 */
static int mime_is_language(const avl_tree_t *languages, const char *mime)
{
	struct language_entry key = {
		.mime = (char *)mime,
	};

	if (languages == NULL || mime == NULL)
		return 0;

	return avl_search(languages, &key.avl) != NULL;
}

/*
 * mime_is_elf_shared - classify ELF, shared library, and object MIME names.
 * @mime: MIME string returned by file type detection.
 * Returns 1 when the MIME is ELF-related, 0 otherwise.
 */
static int mime_is_elf_shared(const char *mime)
{
	static const char * const elf_mimes[] = {
		"application/x-bad-elf",
		"application/x-executable",
		"application/x-object",
		"application/x-pie-executable",
		"application/x-sharedlib",
		NULL
	};

	return mime && name_in_list(mime, elf_mimes);
}

/*
 * mime_is_archive - classify archive, compressed archive, JAR, and ZIP MIME.
 * @mime: MIME string returned by file type detection.
 * Returns 1 when the MIME is archive-like, 0 otherwise.
 */
static int mime_is_archive(const char *mime)
{
	static const char * const archive_mimes[] = {
		"application/gzip",
		"application/java-archive",
		"application/vnd.android.package-archive",
		"application/vnd.ms-cab-compressed",
		"application/vnd.rar",
		"application/x-archive",
		"application/x-7z-compressed",
		"application/x-bzip",
		"application/x-bzip2",
		"application/x-compress",
		"application/x-cpio",
		"application/x-gzip",
		"application/x-java-jmod",
		"application/x-java-archive",
		"application/x-java-pack200",
		"application/x-lrzip",
		"application/x-lzip",
		"application/x-rar",
		"application/x-rpm",
		"application/x-stuffit",
		"application/x-tar",
		"application/x-xz",
		"application/x-xar",
		"application/x-zip",
		"application/x-zoo",
		"application/x-zstd",
		"application/zstd",
		"application/zip",
		NULL
	};

	return mime && name_in_list(mime, archive_mimes);
}

/*
 * mime_is_bytecode - classify bytecode MIME names.
 * @mime: MIME string returned by file type detection.
 * Returns 1 when the MIME is bytecode-like, 0 otherwise.
 */
static int mime_is_bytecode(const char *mime)
{
	static const char * const bytecode_mimes[] = {
		"application/java-vm",
		"application/wasm",
		"application/x-bytecode.python",
		"application/x-elc",
		"application/x-java-applet",
		"application/x-lua-bytecode",
		"application/x-python-bytecode",
		NULL
	};

	if (mime == NULL)
		return 0;
	if (strstr(mime, "bytecode"))
		return 1;

	return name_in_list(mime, bytecode_mimes);
}

/*
 * path_is_archive - classify archive-like paths by extension.
 * @path: path to inspect.
 * Returns 1 when the suffix indicates an archive, 0 otherwise.
 */
static int path_is_archive(const char *path)
{
	static const char * const archive_suffixes[] = {
		".7z",
		".apk",
		".bz2",
		".ear",
		".egg",
		".gz",
		".jar",
		".rar",
		".tar",
		".tar.bz2",
		".tar.gz",
		".tar.xz",
		".tar.zst",
		".tbz",
		".tbz2",
		".tgz",
		".txz",
		".war",
		".whl",
		".xz",
		".zip",
		".zst",
		NULL
	};

	return path_has_suffix_list(path, archive_suffixes);
}

/*
 * path_is_bytecode - classify bytecode files and cache paths.
 * @path: path to inspect.
 * Returns 1 when the path indicates bytecode, 0 otherwise.
 */
static int path_is_bytecode(const char *path)
{
	static const char * const bytecode_suffixes[] = {
		".class",
		".elc",
		".luac",
		".pyc",
		".pyo",
		".wasm",
		NULL
	};

	return path_has_component(path, "__pycache__") ||
	       path_has_suffix_list(path, bytecode_suffixes);
}

/*
 * path_is_plugin_runtime_dir - classify plugin or runtime dependency dirs.
 * @path: directory path to inspect.
 * Returns 1 when the basename is a known plugin/runtime directory.
 */
static int path_is_plugin_runtime_dir(const char *path)
{
	static const char * const runtime_dirs[] = {
		".venv",
		"add-ons",
		"addons",
		"bower_components",
		"dist-packages",
		"extension",
		"extensions",
		"gems",
		"node_modules",
		"pear",
		"pecl",
		"perl5",
		"plugin",
		"plugins",
		"site-packages",
		"vendor",
		"venv",
		"virtualenv",
		NULL
	};

	return name_in_list(path_basename(path), runtime_dirs);
}

/*
 * classify_file_risks - classify a regular file into risk categories.
 * @path: file path being scanned.
 * @sb: stat data for the file.
 * @mime: MIME string returned by file type detection.
 * @languages: AVL tree built from %languages.
 * Returns a bitmask of risk categories.
 */
static unsigned int classify_file_risks(const char *path,
					const struct stat *sb,
					const char *mime,
					const avl_tree_t *languages)
{
	unsigned int risks = 0;

	if (sb->st_mode & 0111)
		risks |= RISK_BIT(RISK_EXECUTABLE_REGULAR);
	if (mime_is_elf_shared(mime))
		risks |= RISK_BIT(RISK_ELF_SHARED);
	if (mime_is_archive(mime) || path_is_archive(path))
		risks |= RISK_BIT(RISK_ARCHIVE);
	if (mime_is_bytecode(mime) || path_is_bytecode(path))
		risks |= RISK_BIT(RISK_BYTECODE);
	if (mime_is_language(languages, mime))
		risks |= RISK_BIT(RISK_LANGUAGE);

	return risks;
}

/*
 * classify_dir_risks - classify a directory into risk categories.
 * @path: directory path being scanned.
 * Returns a bitmask of risk categories.
 */
static unsigned int classify_dir_risks(const char *path)
{
	unsigned int risks = 0;

	if (strcasecmp(path_basename(path), "__pycache__") == 0)
		risks |= RISK_BIT(RISK_BYTECODE);
	if (path_is_plugin_runtime_dir(path))
		risks |= RISK_BIT(RISK_PLUGIN_RUNTIME_DIR);

	return risks;
}

/*
 * print_verbose_risks - print one verbose risk entry.
 * @path: file or directory path that matched.
 * @risks: risk bitmask for the path.
 * @mime: optional MIME string for regular files.
 * Returns nothing.
 */
static void print_verbose_risks(const char *path, unsigned int risks,
				const char *mime)
{
	int first = 1;

	printf("%s: ", path);
	for (unsigned int i = 0; i < RISK_CATEGORY_COUNT; i++) {
		if ((risks & RISK_BIT(i)) == 0)
			continue;
		printf("%s%s", first ? "" : ", ", risk_labels[i]);
		first = 0;
	}
	if (mime && *mime)
		printf(" (%s)", mime);
	putchar('\n');
}

/*
 * record_risk_entry - update counters and optionally print a verbose entry.
 * @path: file or directory path that matched.
 * @risks: risk bitmask for the path.
 * @mime: optional MIME string for regular files.
 * Returns nothing.
 */
static void record_risk_entry(const char *path, unsigned int risks,
			      const char *mime)
{
	if (risks == 0)
		return;

	if (verbose)
		print_verbose_risks(path, risks, mime);

	if (scan_state.counts) {
		scan_state.counts->total_entries++;
		for (unsigned int i = 0; i < RISK_CATEGORY_COUNT; i++) {
			if (risks & RISK_BIT(i))
				scan_state.counts->category[i]++;
		}
	}
}

/*
 * add_risk_counts - add per-mount counts into an aggregate.
 * @total: aggregate counts to update.
 * @mount: per-mount counts to add.
 * Returns nothing.
 */
static void add_risk_counts(struct risk_counts *total,
			    const struct risk_counts *mount)
{
	total->total_entries += mount->total_entries;
	for (unsigned int i = 0; i < RISK_CATEGORY_COUNT; i++)
		total->category[i] += mount->category[i];
}

/*
 * print_risk_summary - print the per-mount risk summary.
 * @mount: mount point that was scanned.
 * @counts: risk counts collected while scanning the mount.
 * Returns nothing.
 */
static void print_risk_summary(const char *mount,
			       const struct risk_counts *counts)
{
	printf("Summary for %s:\n", mount);
	printf("  total risky entries: %lu\n", counts->total_entries);
	for (unsigned int i = 0; i < RISK_CATEGORY_COUNT; i++)
		printf("  %s: %lu\n", risk_labels[i], counts->category[i]);
}

/*
 * print_skipped_summary - print a summary for a mount that was not scanned.
 * @mount: mount point or configured path that was skipped.
 * Returns nothing.
 */
static void print_skipped_summary(const char *mount)
{
	printf("Summary for %s:\n", mount);
	printf("  scan skipped\n");
}

/*
 * load_language_mimes - gather MIME types belonging to %languages.
 * @languages: AVL tree populated with MIME type strings.
 * @source_path: returns the path used while loading definitions.
 * Returns 0 on success and 1 on failure.
 */
static int load_language_mimes(avl_tree_t *languages, const char **source_path)
{
	FILE *fp;
	char *line = NULL;
	size_t len = 0;
	int rc = 1, found = 0;

	*source_path = LANGUAGE_RULES_FILE;
	fp = fopen(*source_path, "rm");
	if (fp == NULL) {
		*source_path = RULES_FILE;
		fp = fopen(*source_path, "rm");
		if (fp == NULL)
			return 1;
	}

	while (getline(&line, &len, fp) != -1) {
		char *entry = fapolicyd_strtrim(line);

		if (strncmp(entry, "%languages=", 11) == 0) {
			char *value = entry + 11;
			char *tmp = strdup(value);
			char *ptr, *saved;

			if (tmp == NULL)
				goto done;

			ptr = strtok_r(tmp, ",", &saved);
			while (ptr) {
				char *mime = fapolicyd_strtrim(ptr);

				if (*mime) {
					if (insert_language_mime(languages, mime)) {
						free(tmp);
						free_language_mimes(languages);
						goto done;
					}
				}
				ptr = strtok_r(NULL, ",", &saved);
			}
			free(tmp);
			found = 1;
			break;
		}
	}

	if (found)
		rc = 0;

done:
	free(line);
	fclose(fp);
	return rc;
}

/*
 * is_mount_point - determine whether the supplied path is a mount point.
 * @path: directory to inspect.
 * Returns 1 when the path is mounted, 0 when it is not, and -1 when the
 * mount table cannot be read.
 */
static int is_mount_point(const char *path)
{
	FILE *fp;
	struct mntent *ent;

	fp = setmntent(MOUNTS_FILE, "r");
	if (fp == NULL)
		return -1;

	while ((ent = getmntent(fp))) {
		if (strcmp(ent->mnt_dir, path) == 0) {
			endmntent(fp);
			return 1;
		}
	}

	endmntent(fp);
	return 0;
}

/*
 * validate_override_mount - verify CLI override path and copy it to config.
 * @override: path supplied by the administrator.
 * Returns 0 on success and 1 on failure.
 */
static int validate_override_mount(const char *override)
{
	char resolved[PATH_MAX];
	char *rpath;
	struct stat sb;
	int mount_rc;

	rpath = realpath(override, resolved);
	if (rpath == NULL) {
		fprintf(stderr, "Cannot resolve %s (%s)\n", override,
			strerror(errno));
		return CLI_EXIT_PATH_CONFIG;
	}
	if (stat(rpath, &sb) || S_ISDIR(sb.st_mode) == 0) {
		fprintf(stderr, "%s is not a directory\n", rpath);
		return CLI_EXIT_PATH_CONFIG;
	}

	mount_rc = is_mount_point(rpath);
	if (mount_rc <= 0) {
		if (mount_rc == 0)
			fprintf(stderr, "%s is not a mount point\n", rpath);
		else
			fprintf(stderr, "Unable to read %s (%s)\n", MOUNTS_FILE,
				strerror(errno));
		return CLI_EXIT_PATH_CONFIG;
	}

	free((void *)config.ignore_mounts);
	config.ignore_mounts = strdup(rpath);
	if (config.ignore_mounts == NULL) {
		fprintf(stderr, "Out of memory\n");
		return CLI_EXIT_INTERNAL;
	}

	return CLI_EXIT_SUCCESS;
}

/*
 * load_ignore_mounts_config - populate ignore_mounts field for scanning.
 * @override: optional CLI path override.
 * Returns 0 on success and 1 on failure.
 */
static int load_ignore_mounts_config(const char *override)
{
	if (override)
		return validate_override_mount(override);

	set_message_mode(MSG_STDERR, DBG_YES);
	if (load_daemon_config(&config))
		return CLI_EXIT_PATH_CONFIG;

	return CLI_EXIT_SUCCESS;
}

/*
 * inspect_mount_entry - nftw callback that records risky files and dirs.
 * @fpath: path of the entry being inspected.
 * @sb: stat buffer describing the entry.
 * @typeflag: nftw type flag.
 * @ftwbuf_unused: unused nftw traversal metadata.
 * Returns FTW_CONTINUE so the walk keeps running.
 */
static int inspect_mount_entry(const char *fpath, const struct stat *sb,
	int typeflag,
	struct FTW *ftwbuf_unused __attribute__ ((unused)))
{
	int fd;
	struct file_info info;
	char buf[128];
	char *mime;
	unsigned int risks;

	if (typeflag == FTW_D || typeflag == FTW_DP) {
		risks = classify_dir_risks(fpath);
		record_risk_entry(fpath, risks, NULL);
		return FTW_CONTINUE;
	}

	/* Only evaluate regular files discovered during the walk. */
	if (S_ISREG(sb->st_mode) == 0)
		return FTW_CONTINUE;

	/* Open the file and collect metadata for libmagic. */
	fd = open(fpath, O_RDONLY|O_CLOEXEC);
	if (fd < 0) {
		fprintf(stderr, "Unable to open %s (%s)\n", fpath,
			strerror(errno));
		scan_state.had_error = 1;
		return FTW_CONTINUE;
	}

	memset(&info, 0, sizeof(info));
	info.device = sb->st_dev;
	info.inode = sb->st_ino;
	info.mode = sb->st_mode;
	info.size = sb->st_size;
	info.time = sb->st_mtim;

	mime = get_file_type_from_fd(fd, &info, fpath, sizeof(buf), buf);
	close(fd);
	if (mime == NULL) {
		fprintf(stderr, "Unable to determine mime for %s\n", fpath);
		scan_state.had_error = 1;
		return FTW_CONTINUE;
	}

	risks = classify_file_risks(fpath, sb, mime, scan_state.languages);
	record_risk_entry(fpath, risks, buf);

	return FTW_CONTINUE;
}

/*
 * scan_mount_entry - scan a single ignore_mounts entry for risky content.
 * @mount: entry from config.ignore_mounts.
 * @risk_totals: aggregate counters updated with matches.
 * @override: 0 ignore_mounts list, 1 command line override
 * Returns 0 when the mount was scanned successfully and 1 when errors
 * prevent a full scan.
 */
static int scan_mount_entry(const char *mount, struct risk_counts *risk_totals,
			    int override)
{
	char resolved[PATH_MAX];
	char *rpath;
	struct risk_counts mount_counts = { 0 };
	struct stat sb;
	int rc = CLI_EXIT_SUCCESS;
	int scanned = 0;

	rpath = realpath(mount, resolved);
	if (rpath == NULL) {
		fprintf(stderr, "Cannot resolve %s (%s)\n", mount,
			strerror(errno));
		print_skipped_summary(mount);
		return CLI_EXIT_PATH_CONFIG;
	}

	if (stat(rpath, &sb)) {
		fprintf(stderr, "%s does not exist\n", rpath);
		print_skipped_summary(rpath);
		return CLI_EXIT_PATH_CONFIG;
	}
	if (S_ISDIR(sb.st_mode) == 0) {
		fprintf(stderr, "%s is not a directory\n", rpath);
		print_skipped_summary(rpath);
		return CLI_EXIT_PATH_CONFIG;
	}

	const char *warning = NULL;
	int mount_rc = check_ignore_mount_warning(MOUNTS_FILE, rpath, &warning);

	if (warning) {
		if (override && warning[0] == 'i')
			warning += 20; // skip the ignore_mount part
		fprintf(stderr, warning, rpath, MOUNTS_FILE);
		fputc('\n', stderr);
	}

	// A warning was already printed -  just return
	if (mount_rc != 1)
		return CLI_EXIT_PATH_CONFIG;

	scan_state.counts = &mount_counts;
	scan_state.had_error = 0;
	if (nftw(rpath, inspect_mount_entry, 1024, FTW_PHYS)) {
		fprintf(stderr, "Unable to scan %s (%s)\n", rpath,
			strerror(errno));
		print_skipped_summary(rpath);
		rc = CLI_EXIT_IO;
	} else
		scanned = 1;

	if (scan_state.had_error)
		rc = CLI_EXIT_IO;

	if (scanned) {
		print_risk_summary(rpath, &mount_counts);
		add_risk_counts(risk_totals, &mount_counts);
	}

	scan_state.counts = NULL;

	if (!scanned)
		return rc;

	return rc;
}

/*
 * check_ignore_mounts - validate ignore_mounts entries and scan for matches.
 * @override: optional mount path provided on the command line.
 * Returns CLI_EXIT_SUCCESS when no risky entries are found, CLI_EXIT_GENERIC
 * when risky entries are detected, and other CLI_EXIT_* codes on error.
 */
int check_ignore_mounts(const char *override)
{
	list_t mounts;
	avl_tree_t languages;
	int rc = CLI_EXIT_SUCCESS;
	struct risk_counts risk_totals = { 0 };
	int errors = 0;
	int file_ready = 0;
	const char *languages_path;

	reset_ignore_mounts_config();
	list_init(&mounts);
	avl_init(&languages, compare_language_entry);

	/* Load ignore_mounts either from the override path or daemon config. */
	rc = load_ignore_mounts_config(override);
	if (rc)
		goto finish;

	if (config.ignore_mounts == NULL) {
		printf("No ignore_mounts entries configured\n");
		rc = CLI_EXIT_SUCCESS;
		goto finish;
	}

	if (populate_mount_list(config.ignore_mounts, &mounts)) {
		fprintf(stderr, "Failed to parse ignore_mounts entries\n");
		rc = CLI_EXIT_INTERNAL;
		goto finish;
	}

	if (mounts.first == NULL) {
		printf("No ignore_mounts entries configured\n");
		rc = CLI_EXIT_SUCCESS;
		goto finish;
	}

	/* Build a fast lookup tree of MIME types associated with %languages. */
	if (load_language_mimes(&languages, &languages_path)) {
		fprintf(stderr,
			"Unable to load %%languages definitions from %s\n",
			languages_path);
		rc = CLI_EXIT_RULE_FILTER;
		goto finish;
	}

	/* Initialize libmagic once so nftw() callbacks can reuse it. */
	if (file_init()) {
		fprintf(stderr, "Cannot initialize file helper libraries\n");
		rc = CLI_EXIT_INTERNAL;
		goto finish;
	}

	file_ready = 1;
	scan_state.languages = &languages;

	/* Walk each ignore_mounts entry and flag risky files or directories. */
	for (list_item_t *lptr = mounts.first; lptr; lptr = lptr->next) {
		int scan_rc = scan_mount_entry(lptr->index, &risk_totals,
					       override ? 1 : 0);
		if (scan_rc) {
			errors = 1;
			if (rc == CLI_EXIT_SUCCESS)
				rc = scan_rc;
		}
	}

	if (errors == 0 && risk_totals.total_entries == 0)
		rc = CLI_EXIT_SUCCESS;

finish:
	if (file_ready)
		file_close();
	list_empty(&mounts);
	free_language_mimes(&languages);
	scan_state.languages = NULL;
	scan_state.counts = NULL;
	scan_state.had_error = 0;
	reset_ignore_mounts_config();
	if (risk_totals.total_entries > 0)
		return CLI_EXIT_GENERIC;
	if (errors)
		return rc;
	return rc;
}
