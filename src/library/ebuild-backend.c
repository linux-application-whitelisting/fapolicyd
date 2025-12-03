/**
 * @file ebuild-backend.c
 * @brief Implementation of the ebuild backend for fapolicyd.
 *
 * This file contains the implementation of the ebuild backend for fapolicyd.
 * The ebuild backend is responsible for loading the list of installed packages
 * and their corresponding files and directories from the VDB (/var/db/pkg/).
 * It parses the CONTENTS file of each package and extracts the information
 * about the installed files, including their paths, MD5 checksums, and modification timestamps.
 *
 * The ebuild_load_list function is the entry point for loading the package list.
 * It takes a pointer to the conf_t structure, which contains the configuration options
 * for fapolicyd, and returns an integer indicating the success or failure of the operation.
 */

#include "config.h"				// for DEBUG
#include <dirent.h>				// for dirent, closedir, opendir, DIR, readdir
#include <errno.h>				// for errno
#include <stdio.h>				// for NULL, perror, asprintf, getline, fopen
#include <stdlib.h>				// for free, malloc, abort, reallocarray
#include <string.h>				// for strcmp, strdup, strlen, strtok_r, strcat
#include <sys/stat.h>			// for stat, fstatat, S_ISDIR, S_ISREG
#include <syslog.h>				// for LOG_ERR, LOG_DEBUG, LOG_INFO
#include <stdatomic.h>			// for atomic_bool
#include <sys/mman.h>			// for memfd_create, MFD_CLOEXEC, MFD_ALLOW_SEALING
#include <fcntl.h>				// for fcntl, F_ADD_SEALS, F_SEAL_SHRINK
#include <unistd.h>				// for close
#include "conf.h"				// for conf_t
#include "fapolicyd-backend.h"	// for SRC_EBUILD, backend
#include "filter.h"				// for filter_destroy, filter_init, filter_l...
#include "llist.h"				// for list_empty, list_init
#include "md5-backend.h"		// for add_file_to_backend_by_md5
#include "message.h"			// for msg

#ifndef VDB_PATH
#define VDB_PATH "/var/db/pkg"
#endif

extern atomic_bool stop;

static const char *get_vdb_path(void) {
	const char *path = getenv("FAPOLICYD_VDB_PATH");
	if (path) return path;
	return VDB_PATH;
}

static const char kEbuildBackend[] = "ebuilddb";

static int ebuild_init_backend(void);
static int ebuild_load_list(const conf_t *);
static int ebuild_destroy_backend(void);

backend ebuild_backend = {
		kEbuildBackend,
		ebuild_init_backend,
		ebuild_load_list,
		ebuild_destroy_backend,
		-1,
		-1,
};

/*
 * Collection of paths and MD5s for a package
 */
typedef struct contents {
	char *md5;
	char *path;
} ebuildfiles;

/*
 * Struct that contains the information we need about a package
 */
struct epkg {
	char *cpv;
	char *slot;
	char *repo;
	int files;
	ebuildfiles *content;
};

/*
 * Holds the category name and package name while we recurse
 */
typedef struct {
	char *category;
	char *package;
} PackageData;

/*
 * Remove the trailing newline from a string
 *
 * This function takes a string as input and removes the trailing newline character, if present.
 * It modifies the input string in-place and returns a pointer to the modified string.
 *
 * @param string - The input string to remove the trailing newline from
 * @return A pointer to the modified string
 */
char* remove_newline(char* string) {
	int len = strlen(string);
	if (len > 0 && string[len-1] == '\n') {
		string[len-1] = '\0';
	}
	return string;
}


/**
 * Recursively process a directory
 *
 * This function takes a directory pointer and a function pointer as input.
 * It processes the directory based on the provided function pointer.
 *
 * @param dir The directory pointer to be processed.
 * @param process_entry The function pointer that defines how each entry in the directory should be processed.
 * @param packages A pointer to an integer that will store the number of packages processed.
 * @param capacity A pointer to an integer that will store the current capacity of the packages array.
 * @param vdbpackages A pointer to an array of struct epkg pointers that will store the processed packages.
 * @param data A pointer to a PackageData pointer that will store additional data related to the processed packages.
 * @return The updated array of struct epkg pointers representing the processed packages.
 */
struct epkg** process_directory(DIR *dir, struct epkg** (*process_entry)(struct dirent *, int *, int *, struct epkg **, PackageData **),
	int *packages, int *capacity, struct epkg **vdbpackages, PackageData **data) {
	struct dirent *dp;
	int dir_fd = dirfd(dir);
	while ((dp = readdir(dir)) != NULL) {
		if (stop)
			break;

		if (strcmp(dp->d_name, ".") == 0 || strcmp(dp->d_name, "..") == 0)
			continue;

		unsigned char d_type = dp->d_type;

		if (d_type == DT_UNKNOWN) {
			struct stat sb;
			if (fstatat(dir_fd, dp->d_name, &sb, 0) == 0) {
				if (S_ISDIR(sb.st_mode)) {
					d_type = DT_DIR;
				} else if (S_ISREG(sb.st_mode)) {
					d_type = DT_REG;
				}
			}
		}

		if (d_type == DT_DIR || d_type == DT_REG) {
			vdbpackages = process_entry(dp, packages, capacity, vdbpackages, data);
		}
	}

	return vdbpackages;
}


/*
 * Read and process SLOT, repository, CONTENTS from a VDB package directory
 * CATEGORY and PF are already known, but could be read at this stage
 *
 * @param packages A pointer to an integer representing the number of packages
 * @param capacity A pointer to an integer representing the capacity of the packages array
 * @param vdbpackages An array of pointers to struct epkg representing VDB packages
 * @param data A pointer to a pointer to PackageData struct representing package data
 *
 * @return The updated array of pointers to struct epkg representing processed packages.
 *         If an error occurs or the operation is stopped, the function cleans up
 *         locally allocated memory and returns the original (or potentially resized) array.
 */
struct epkg** process_pkgdir(int *packages, int *capacity, struct epkg **vdbpackages, PackageData **data) {
	char *pkgrepo = NULL;
	char *pkgslot = NULL;
	int pkgfiles = 0;
	int pkgfiles_capacity = 0;
	ebuildfiles* pkgcontents = NULL;

	char *filenames[] = {"repository", "SLOT", "CONTENTS"};
	int nfilenames = sizeof(filenames) / sizeof(filenames[0]);


	for (int i = 0; i < nfilenames; i++) {
		if (stop)
			goto cleanup;

		#ifdef DEBUG
		msg(LOG_DEBUG, "\tProcessing %s", filenames[i]);
		#endif
		char *filepath;
		if (asprintf(&filepath, "%s/%s/%s/%s", get_vdb_path(), (*data)->category, (*data)->package, filenames[i]) == -1) {
			perror("asprintf");
			filepath = NULL;
		}
		if (filepath) {
			FILE *fp;
			char *line = NULL;
			size_t len = 0;
			ssize_t read;
			if ((fp = fopen(filepath, "r")) == NULL) {
				msg(LOG_ERR, "Could not open %s", filepath);
				free(filepath);
				goto cleanup;
			}

			if (strcmp(filenames[i], "SLOT") == 0 || strcmp(filenames[i], "repository") == 0) {
				// SLOT and repository will only ever contain a single line
				if ((read = getline(&line, &len, fp)) != -1) {
					if (strcmp(filenames[i], "SLOT") == 0) {
						pkgslot = strdup(line);
						remove_newline(pkgslot);
						#ifdef DEBUG
						msg(LOG_DEBUG, "\t\tslot: %s", pkgslot);
						#endif
					} else if (strcmp(filenames[i], "repository") == 0) {
						pkgrepo = strdup(line);
						remove_newline(pkgrepo);
						#ifdef DEBUG
						msg(LOG_DEBUG, "\t\trepo: %s", pkgrepo);
						#endif
					}
				}
			} else if (strcmp(filenames[i], "CONTENTS") == 0) {
				while ((read = getline(&line, &len, fp)) != -1) {
					// Format: type path md5 timestamp
					// e.g. obj /usr/bin/clamscan 3ade185bd024e29880e959e6ad187515 1693552964

					// Parse from right to left - there might be spaces in the path
					// Remove trailing newline
					if (read > 0 && line[read - 1] == '\n') {
						line[read - 1] = '\0';
						read--;
					}

					if (strncmp(line, "obj ", 4) != 0) {
						continue;
					}

					// Find the last space (before timestamp)
					char *last_space = strrchr(line, ' ');
					if (!last_space) continue;
					*last_space = '\0';

					// Find the space before that (before md5)
					char *md5_space = strrchr(line, ' ');
					if (!md5_space) continue;
					*md5_space = '\0';

					char *path_start = line + 4; // Skip "obj "
					char *md5_start = md5_space + 1;

					ebuildfiles file;
					file.path = strdup(path_start);
					file.md5 = strdup(md5_start);

					if (!file.path || !file.md5) {
						msg(LOG_ERR, "Memory allocation failed");
						abort();
					}

					if (pkgfiles >= pkgfiles_capacity) {
						int new_capacity = (pkgfiles_capacity == 0) ? 16 : pkgfiles_capacity * 2;
						ebuildfiles *newpkgcontents = reallocarray(pkgcontents, new_capacity, sizeof(ebuildfiles));
						if (newpkgcontents == NULL) {
							abort();
						}
						pkgcontents = newpkgcontents;
						pkgfiles_capacity = new_capacity;
					}
					pkgcontents[pkgfiles] = file;
					pkgfiles++;
				}
				#ifdef DEBUG
				msg(LOG_DEBUG, "\t\tfiles: %i", pkgfiles);
				#endif
			}

			free(line);
			fclose(fp);
			free(filepath);
			}
		}

	// Construct a CPVR string e.g. dev-libs/libxml2-2.9.10{-r0}
	// We're not processing based on this information, but it's useful for logging
	// If there's a need to split into components see
	// https://github.com/gentoo/portage-utils/blob/master/libq/atom.c
	char *catpkgver = malloc(strlen((*data)->category) + strlen((*data)->package) + 2);
	if (catpkgver == NULL) {
		msg(LOG_ERR, "Could not allocate memory.");
		perror("malloc");
		goto cleanup;
	}
	strcpy(catpkgver, (*data)->category);
	strcat(catpkgver, "/");
	strcat(catpkgver, (*data)->package);

	// make a new package
	struct epkg *package = malloc(sizeof(struct epkg));
	if (package == NULL) {
		msg(LOG_ERR, "Could not allocate memory.");
		free(catpkgver);
		goto cleanup;
	}
	package->cpv = catpkgver;
	package->slot = pkgslot;
	package->repo = pkgrepo;
	package->files = pkgfiles;
	package->content = pkgcontents;

	#ifdef DEBUG
	msg(LOG_DEBUG, "Stored:\n\tPackage: %s\n\tSlot: %s\n\tRepo: %s\n\tFiles: %i",
		package->cpv, package->slot, package->repo, package->files);
	msg(LOG_DEBUG, "Package number %i", *packages + 1);
	#endif

	if (*packages >= *capacity) {
		int new_capacity = (*capacity == 0) ? 16 : (*capacity) * 2;
		struct epkg** expanded_vdbpackages = reallocarray(vdbpackages, new_capacity, sizeof(struct epkg *));
		if(expanded_vdbpackages == NULL) {
			msg(LOG_ERR, "Could not allocate memory.");
			abort();
		}
		vdbpackages = expanded_vdbpackages;
		*capacity = new_capacity;
	}
	vdbpackages[*packages] = package;
	(*packages)++;

	return vdbpackages;

cleanup:
	if (pkgrepo) free(pkgrepo);
	if (pkgslot) free(pkgslot);
	if (pkgcontents) {
		for (int k = 0; k < pkgfiles; k++) {
			free(pkgcontents[k].path);
			free(pkgcontents[k].md5);
		}
		free(pkgcontents);
	}
	return vdbpackages;
}


/**
 * Process a package within a directory pointer in the vdb (portage internal database).
 *
 * This function takes a directory pointer `pkgdp` within a category and processes the package.
 * It updates the number of packages `*packages`, the array of vdb packages `**vdbpackages`,
 * and the package data `**data`.
 *
 * @param pkgdp A pointer to the `dirent` structure representing the package directory.
 * @param packages A pointer to the number of packages in the vdb.
 * @param capacity A pointer to the capacity of the packages array.
 * @param vdbpackages A pointer to the array of vdb packages.
 * @param data A pointer to the package data.
 * @return The updated array of vdb packages.
 */
struct epkg** process_vdb_package(struct dirent *pkgdp, int *packages, int *capacity, struct epkg **vdbpackages, PackageData **data) {
	char *pkgpath;
	// construct the package directory path using the category name and package name
	if (asprintf(&pkgpath, "%s/%s/%s", get_vdb_path(), (*data)->category, pkgdp->d_name) == -1) {
		pkgpath = NULL;
		perror("asprintf");
	}

	msg(LOG_INFO, "Loading package %s/%s", (*data)->category, pkgdp->d_name);
	#ifdef DEBUG
	msg(LOG_DEBUG, "\tPath: %s", pkgpath);
	#endif

	if((*data)->package != NULL) {
		free((*data)->package);
		(*data)->package = NULL;
	}
	(*data)->package = strdup(pkgdp->d_name);

	if((*data)->package == NULL) {
		msg(LOG_ERR, "Memory allocation failed!");
		perror("strdup");
		abort();
	}


	if (pkgpath) {
		free(pkgpath);
		vdbpackages = process_pkgdir(packages, capacity, vdbpackages, data);
	}

	return vdbpackages;
}


/**
 * Process a directory (category) within the VDB root.
 *
 * This function opens a category directory and processes its contents.
 *
 * @param vdbdp A pointer to the dirent structure representing the category directory.
 * @param packages A pointer to an integer variable to store the number of packages processed.
 * @param capacity A pointer to an integer variable to store the capacity of the packages array.
 * @param vdbpackages An array of pointers to epkg structures representing the processed packages.
 * @param data A pointer to the PackageData structure to store additional package data.
 * @return The updated array of pointers to epkg structures representing the processed packages.
 */
struct epkg** process_vdb_category(struct dirent *vdbdp, int *packages, int *capacity, struct epkg **vdbpackages, PackageData **data) {

	char *catdir;
	// construct the category directory path
	if (asprintf(&catdir, "%s/%s", get_vdb_path(), vdbdp->d_name) == -1) {
		catdir = NULL;
		perror("asprintf");
	}

	msg(LOG_INFO, "Loading category %s", vdbdp->d_name);
	if ((*data)->category != NULL) {
		free((*data)->category);
		(*data)->category = NULL;
	}
	((*data)->category) = strdup(vdbdp->d_name);

	if (catdir) {
		DIR *category;
		if ((category = opendir(catdir)) == NULL) {
			msg(LOG_ERR, "Could not open %s", catdir);
			msg(LOG_ERR, "Error: %s", strerror(errno));
			free(catdir);
			return vdbpackages;
		}

		vdbpackages = process_directory(category, process_vdb_package, packages, capacity, vdbpackages, data);

		closedir(category);
		free(catdir);
	}
	return vdbpackages;
}

/*
 * Portage stores data about installed packages in the VDB (/var/db/pkg/).
 * We care about /var/db/pkg/category/package-version/CONTENTS
 * which lists files and directories that are installed as part of a package 'merge'
 * operation. All files are prefixed with 'obj' and are in the format:
 * obj /path/to/file $(md5sum /path/to/file) $(date -r /path/to/file "+%s")
 * e.g.
 * obj /usr/bin/clamscan 3ade185bd024e29880e959e6ad187515 1693552964
 */
static int ebuild_load_list(const conf_t *conf) {
	struct _hash_record *hashtable = NULL;
	struct _hash_record **hashtable_ptr = &hashtable;

	// Initialise filter for this load operation
	if (filter_init())
		return 1;

	if (filter_load_file(NULL)) {
		filter_destroy();
		return 1;
	}

	int memfd = memfd_create("ebuild_snapshot", MFD_CLOEXEC | MFD_ALLOW_SEALING);
	if (memfd < 0) {
		msg(LOG_ERR, "memfd_create failed for ebuild backend (%s)",
		    strerror(errno));
		filter_destroy();
		return 1;
	}
	ebuild_backend.memfd = memfd;
	ebuild_backend.entries = 0;

	DIR *vdbdir;

	if ((vdbdir = opendir(get_vdb_path())) == NULL) {
		msg(LOG_ERR, "Could not open %s", get_vdb_path());
		filter_destroy();
		return 1;
	}

	struct epkg **vdbpackages = NULL;
	int packages = 0;
	int capacity = 0;

	msg(LOG_INFO, "Initialising ebuild backend");
	msg(LOG_DEBUG, "Processing VDB");

	/*
	 * recurse through category/package-version/ dirs,
	 * process CONTENTS (files, md5s), repository, SLOT,
	 * store in epkg array
	*/
	PackageData *data = malloc(sizeof(PackageData));
	data->category = NULL;
	data->package = NULL;
	vdbpackages = process_directory(vdbdir, process_vdb_category, &packages, &capacity, vdbpackages, &data);
	if (data->category) free(data->category);
	if (data->package) free(data->package);
	free(data);
	closedir(vdbdir);

	msg(LOG_INFO, "Processed %d packages.", packages);

	for (int j = 0; j < packages; j++) {
		struct epkg *package = vdbpackages[j];

		// slot "0" is the default slot for packages that aren't slotted; we don't need to include it in the log
		#ifdef DEBUG
		if (!stop) {
			if ((strcmp(package->slot,"0")) == 0) {
				msg(LOG_DEBUG, "Adding %s (::%s) to the ebuild backend; %i files",
					package->cpv, package->repo, package->files);
			} else {
				msg(LOG_DEBUG, "Adding %s:%s (::%s) to the ebuild backend; %i files",
					package->cpv, package->slot, package->repo, package->files);
			}
		}
		#endif
		for (int k = 0; k < package->files; k++) {
			ebuildfiles *file = &package->content[k];
			if (!stop) {
				if (filter_check(file->path)) {
					if (add_file_to_backend_by_md5(file->path, file->md5, hashtable_ptr, SRC_EBUILD, &ebuild_backend) == 0)
						ebuild_backend.entries++;
				} else {
					#ifdef DEBUG
					msg(LOG_DEBUG, "File %s is in the filter list; ignoring", file->path);
					#endif
				}
			}
			free(file->path);
			free(file->md5);
		}
		free(package->content);
		free(package->cpv);
		free(package->slot);
		free(package->repo);
		free(package);
	}
	free(vdbpackages);

	struct _hash_record *item, *tmp;
	HASH_ITER(hh, hashtable, item, tmp) {
		HASH_DEL(hashtable, item);
		free((void *)item->key);
		free(item);
	}

	if (fcntl(ebuild_backend.memfd, F_ADD_SEALS, F_SEAL_SHRINK |
		  F_SEAL_GROW | F_SEAL_WRITE) == -1)
		// Not a fatal error
		msg(LOG_WARNING, "Failed to seal ebuild backend memfd (%s)",
		    strerror(errno));

	filter_destroy();

	if (stop)
		return 1;

	return 0;

}

static int ebuild_init_backend(void)
{
	return 0;
}

static int ebuild_destroy_backend(void)
{
	if (ebuild_backend.memfd >= 0) {
		close(ebuild_backend.memfd);
		ebuild_backend.memfd = -1;
	}
	return 0;
}
