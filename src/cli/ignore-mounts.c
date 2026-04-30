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

struct mount_scan_state {
	const avl_tree_t *languages;
	unsigned long *count;
	int had_error;
};

static struct mount_scan_state scan_state;

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
 * inspect_mount_file - nftw callback that records suspicious files.
 * @fpath: path of the file being inspected.
 * @sb: stat buffer describing the file.
 * @typeflag_unused: unused nftw type flag.
 * @ftwbuf_unused: unused nftw traversal metadata.
 * Returns FTW_CONTINUE so the walk keeps running.
 */
static int inspect_mount_file(const char *fpath, const struct stat *sb,
	int typeflag_unused __attribute__ ((unused)),
	struct FTW *ftwbuf_unused __attribute__ ((unused)))
{
	int fd;
	struct file_info info;
	char buf[128];
	char *mime;

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

	/* Look up the MIME in the %languages tree and report matches. */
	struct language_entry key = {
		.mime = buf,
	};

	if (avl_search(scan_state.languages, &key.avl)) {
		if (verbose)
			printf("%s: %s\n", fpath, buf);
		if (scan_state.count)
			(*scan_state.count)++;
	}

	return FTW_CONTINUE;
}

/*
 * scan_mount_entry - scan a single ignore_mounts entry for suspicious files.
 * @mount: entry from config.ignore_mounts.
 * @suspicious_total: aggregate counter updated with matches.
 * @override: 0 ignore_mounts list, 1 command line override
 * Returns 0 when the mount was scanned successfully and 1 when errors
 * prevent a full scan.
 */
static int scan_mount_entry(const char *mount, unsigned long *suspicious_total,
			    int override)
{
	char resolved[PATH_MAX];
	char *rpath;
	unsigned long mount_count = 0;
	struct stat sb;
	int rc = CLI_EXIT_SUCCESS;
	int scanned = 0;

	rpath = realpath(mount, resolved);
	if (rpath == NULL) {
		fprintf(stderr, "Cannot resolve %s (%s)\n", mount,
			strerror(errno));
		printf("Summary for %s: 0 suspicious file(s) (scan skipped)\n",
		       mount);
		return CLI_EXIT_PATH_CONFIG;
	}

	if (stat(rpath, &sb)) {
		fprintf(stderr, "%s does not exist\n", rpath);
		printf("Summary for %s: 0 suspicious file(s) (scan skipped)\n",
		       rpath);
		return CLI_EXIT_PATH_CONFIG;
	}
	if (S_ISDIR(sb.st_mode) == 0) {
		fprintf(stderr, "%s is not a directory\n", rpath);
		printf("Summary for %s: 0 suspicious file(s) (scan skipped)\n",
		       rpath);
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

	scan_state.count = &mount_count;
	scan_state.had_error = 0;
	if (nftw(rpath, inspect_mount_file, 1024, FTW_PHYS)) {
		fprintf(stderr, "Unable to scan %s (%s)\n", rpath,
			strerror(errno));
		printf("Summary for %s: 0 suspicious file(s) (scan skipped)\n",
		       rpath);
		rc = CLI_EXIT_IO;
	} else
		scanned = 1;

	if (scan_state.had_error)
		rc = CLI_EXIT_IO;

	if (scanned) {
		printf("Summary for %s: %lu suspicious file(s)\n", rpath,
		       mount_count);
		*suspicious_total += mount_count;
	}

	scan_state.count = NULL;

	if (!scanned)
		return rc;

	return rc;
}

/*
 * check_ignore_mounts - validate ignore_mounts entries and scan for matches.
 * @override: optional mount path provided on the command line.
 * Returns CLI_EXIT_SUCCESS when no suspicious files are found, CLI_EXIT_GENERIC
 * when suspicious files are detected, and other CLI_EXIT_* codes on error.
 */
int check_ignore_mounts(const char *override)
{
	list_t mounts;
	avl_tree_t languages;
	int rc = CLI_EXIT_SUCCESS;
	unsigned long suspicious_total = 0;
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

	/* Walk each ignore_mounts entry and flag suspicious MIME matches. */
	for (list_item_t *lptr = mounts.first; lptr; lptr = lptr->next) {
		int scan_rc = scan_mount_entry(lptr->index, &suspicious_total,
					       override ? 1 : 0);
		if (scan_rc) {
			errors = 1;
			if (rc == CLI_EXIT_SUCCESS)
				rc = scan_rc;
		}
	}

	if (errors == 0 && suspicious_total == 0)
		rc = CLI_EXIT_SUCCESS;

finish:
	if (file_ready)
		file_close();
	list_empty(&mounts);
	free_language_mimes(&languages);
	scan_state.languages = NULL;
	scan_state.count = NULL;
	scan_state.had_error = 0;
	reset_ignore_mounts_config();
	if (suspicious_total > 0)
		return CLI_EXIT_GENERIC;
	if (errors)
		return rc;
	return rc;
}
