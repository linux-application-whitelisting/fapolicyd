#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <uthash.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "conf.h"
#include "config.h"
#include "fapolicyd-backend.h"
#include "file.h"
#include "llist.h"
#include "md5-backend.h"
#include "message.h"

#include "filter.h"

static const char kEbuildBackend[] = "ebuilddb";

static int ebuild_init_backend(void);
static int ebuild_load_list(const conf_t *);
static int ebuild_destroy_backend(void);

backend ebuild_backend = {
		kEbuildBackend,
		ebuild_init_backend,
		ebuild_load_list,
		ebuild_destroy_backend,
		/* list initialization */
		{0, 0, NULL},
};

/*
 * Collection of paths and MD5s for a package
 */
typedef struct contents {
	char *md5;
	char *path;
} ebuildfiles;

/*
 * A package
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
 */
char* remove_newline(char* string) {
	int len = strlen(string);
	if (len > 0 && string[len-1] == '\n') {
		string[len-1] = '\0';
	}
	return string;
}

/*
 * Recursively process a directory
 *
 * This function takes a directory pointer and a function pointer as input.
 * It processes the directory based on the provided function pointer.
 *
 * @param dir The directory pointer.
 * @param process_entry The function pointer to the function to process the directory.
 * @param ... The variable argument list containing the additional arguments.
 * @return void
 */
struct epkg** process_directory(DIR *dir, struct epkg** (*process_entry)(struct dirent *, int *, struct epkg **, PackageData **),
	int *packages, struct epkg **vdbpackages, PackageData **data) {
	struct dirent *dp;
	while ((dp = readdir(dir)) != NULL) {
		if ((dp->d_type == DT_DIR && strcmp(dp->d_name, ".") != 0
			&& strcmp(dp->d_name, "..") != 0) || dp->d_type == DT_REG) {
			vdbpackages = process_entry(dp, packages, vdbpackages, data);
		}
	}

	return vdbpackages;
}

/*
 * Read and process SLOT, repository, CONTENTS from a VDB package directory
 * CATEGORY and PF are already known, but could be read at this stage
 *
 * This function takes a character pointer for the category name, and a character pointer for the package name.
 * It processes the package directory based on the provided arguments.
 *
 * @param packages The integer pointer to store the number of packages.
 * @param vdbpackages The double pointer to struct epkg to store the packages.
 * @param categoryname The character pointer for the category name.
 * @param pkgname The character pointer for the package name.
 */
struct epkg** process_pkgdir(int *packages, struct epkg **vdbpackages, PackageData **data) {
	char *pkgrepo = NULL;
	char *pkgslot = NULL;
	int pkgfiles = 0;
	ebuildfiles* pkgcontents = NULL;

	char *filenames[] = {"repository", "SLOT", "CONTENTS"};
	int nfilenames = sizeof(filenames) / sizeof(filenames[0]);


	for (int i = 0; i < nfilenames; i++) {
		#ifdef DEBUG
		msg(LOG_DEBUG, "\tProcessing %s", filenames[i]);
		#endif
		char *filepath;
		if (asprintf(&filepath, "/var/db/pkg/%s/%s/%s", (*data)->category, (*data)->package, filenames[i]) == -1) {
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
				return vdbpackages;
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
					char *token;
					char *saveptr;

					token = strtok_r(line, " ", &saveptr); // obj/dir/sym, /path/to/file, md5, datestamp

					if (token) {
						// we only care about files
						if ((strcmp(token, "dir")) == 0 || (strcmp(token, "sym")) == 0) {
							continue;
						}

						ebuildfiles *file = malloc(sizeof(ebuildfiles));
						token = strtok_r(NULL, " ", &saveptr);
						file->path = strdup(token);
						token = strtok_r(NULL, " ", &saveptr);
						file->md5 = strdup(token);

						// we don't care about the datestamp
						ebuildfiles *newpkgcontents = reallocarray(pkgcontents, sizeof(ebuildfiles), pkgfiles + 1);
						if (newpkgcontents == NULL) {
							abort();
						}
						pkgcontents = newpkgcontents;
						pkgcontents[pkgfiles] = *file;
						pkgfiles++;
						free(file);
					}
				}
				#ifdef DEBUG
				msg(LOG_DEBUG, "\t\tfiles: %i", pkgfiles);
				#endif
			}

			free(line);
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
		return vdbpackages;
	}
	strcpy(catpkgver, (*data)->category);
	strcat(catpkgver, "/");
	strcat(catpkgver, (*data)->package);

	// make a new package
	struct epkg *package = malloc(sizeof(struct epkg));
	package->cpv = strdup(catpkgver);
	package->slot = strdup(pkgslot);
	package->repo = strdup(pkgrepo);
	package->files = pkgfiles;
	package->content = pkgcontents;

	#ifdef DEBUG
	msg(LOG_DEBUG, "Stored:\n\tPackage: %s\n\tSlot: %s\n\tRepo: %s\n\tFiles: %i",
		package->cpv, package->slot, package->repo, package->files);
	msg(LOG_DEBUG, "Package number %i", *packages + 1);
	#endif

	// add it to the array
	#ifdef DEBUG
	msg(LOG_DEBUG, "vdbpackages: %p", vdbpackages);
	msg(LOG_DEBUG, "packages: %p", packages);
	#endif
	struct epkg** expanded_vdbpackages = reallocarray(vdbpackages, sizeof(struct epkg), (*packages + 1));
	if(expanded_vdbpackages == NULL) {
		msg(LOG_ERR, "Could not allocate memory.");
		abort();
	}
	vdbpackages = expanded_vdbpackages;

	(vdbpackages)[*packages] = package;
	(*packages)++;

	free(catpkgver);
	free(pkgslot);
	free(pkgrepo);
	free(package);
	return vdbpackages;
}


/**
 * For a directory pointer within a category, process a package
 *
 * It takes in a dirent structure pointer and a variable argument list
 * The packages and vdbpackages pointers are extracted from the variable argument list.
 *
 * @param pkgdp A pointer to a dirent structure representing a package.
 * @param args A variable argument list containing the packages, vdbpackages, and category name.
 *             The arguments should be passed in the following order:
 *             - packages: A pointer to the packages.
 *             - vdbpackages: A pointer to the vdbpackages.
 *             - category_name: The name of the category.
 * @return void
 */
struct epkg** process_vdb_package(struct dirent *pkgdp, int *packages, struct epkg **vdbpackages, PackageData **data) {
	char *pkgpath;
	// construct the package directory path using the category name and package name
	if (asprintf(&pkgpath, "/var/db/pkg/%s/%s", (*data)->category, pkgdp->d_name) == -1) {
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
		return vdbpackages;
	}


	if (pkgpath) {
		DIR *pkgdir;
		if ((pkgdir = opendir(pkgpath)) == NULL) {
			msg(LOG_ERR, "Could not open %s", pkgpath);
			msg(LOG_ERR, "Error: %s", strerror(errno));
			free(pkgpath);
			return vdbpackages;
		}

		// close the dir now, we will directly open the files by name
		closedir(pkgdir);
		free(pkgpath);
		vdbpackages = process_pkgdir(packages, vdbpackages, data);
		#ifdef DEBUG
		msg(LOG_DEBUG, "got pointer %p", vdbpackages);
		#endif
	}

	return vdbpackages;
}


/*
 * For a directory pointer within the VDB root, process a directory (category)
 *
 * This function opens a category directory and processes its contents.
 * It takes a `struct dirent` pointer and a variable argument list as input.
 *
 * @param vdbdp A pointer to a `struct dirent` representing the category directory entry.
 * @param args   A variable argument list containing the following arguments:
 *               - packages: A pointer to an integer representing the number of packages.
 *               - vdbpackages: A pointer to an array of `struct epkg` pointers representing the vdb packages.
 */
struct epkg** process_vdb_category(struct dirent *vdbdp, int *packages, struct epkg **vdbpackages, PackageData **data) {

	char *catdir;
	// construct the category directory path
	if (asprintf(&catdir, "/var/db/pkg/%s", vdbdp->d_name) == -1) {
		catdir = NULL;
		perror("asprintf");
	}

	msg(LOG_INFO, "Loading category %s", vdbdp->d_name);
	((*data)->category) = strdup(vdbdp->d_name);

	if (catdir) {
		DIR *category;
		if ((category = opendir(catdir)) == NULL) {
			msg(LOG_ERR, "Could not open %s", catdir);
			msg(LOG_ERR, "Error: %s", strerror(errno));
			free(catdir);
			return vdbpackages;
		}

		vdbpackages = process_directory(category, process_vdb_package, packages, vdbpackages, data);
		closedir(category);
		free(catdir);
	}
	free((*data)->category);
	return vdbpackages;
}

/*
 * Exclude a known list of paths that shouldn't contain binaries
 * (installed by a package manager, anyway).
 */
int exclude_path(const char *path) {
	const char *excluded_paths[] = {
	"/usr/share/",
	"/usr/src/",
	};
	const int num_excluded_paths = sizeof(excluded_paths) / sizeof(excluded_paths[0]);
	for (int i = 0; i < num_excluded_paths; i++) {
		if (strncmp(path, excluded_paths[i], strlen(excluded_paths[i])) == 0) {
			return 1;
		}
	}
	return 0;
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
	list_empty(&ebuild_backend.list);
	struct _hash_record *hashtable = NULL;
	struct _hash_record **hashtable_ptr = &hashtable;

	DIR *vdbdir;

	if ((vdbdir = opendir("/var/db/pkg")) == NULL) {
		msg(LOG_ERR, "Could not open /var/db/pkg");
		return 1;
	}

	struct epkg **vdbpackages = malloc(sizeof(struct epkg));
	int packages = 0;

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
	process_directory(vdbdir, process_vdb_category, &packages, vdbpackages, &data);
	free(data);
	closedir(vdbdir);

	msg(LOG_INFO, "Processed %d packages.", packages);

	for (int j = 0; j < packages; j++) {
		struct epkg *package = vdbpackages[j];

		// slot "0" is the default slot for packages that aren't slotted; we don't need to include it in the log
		// TODO: Files listed here include paths we filter in add_file_to_backend_by_md5
		if ((strcmp(package->slot,"0")) == 0) {
			msg(LOG_INFO, "Adding %s:%s (::%s) to the ebuild backend; %i files",
				package->cpv, package->slot, package->repo, package->files);
		} else {
			msg(LOG_INFO, "Adding %s (::%s) to the ebuild backend; %i files",
				package->cpv, package->repo, package->files);
		}
		for (int k = 0; k < package->files; k++) {
			ebuildfiles *file = &package->content[k];
			// skip files in excluded paths
			if (exclude_path(file->path)) {
				continue;
			}
			add_file_to_backend_by_md5(file->path, file->md5, hashtable_ptr, SRC_EBUILD, &ebuild_backend);
		}
		free(package);
	}
	free(vdbpackages);
	return 0;
}

static int ebuild_init_backend(void)
{
	if (filter_init())
		return 1;

	if (filter_load_file()) {
		filter_destroy();
		return 1;
	}

	list_init(&ebuild_backend.list);

	return 0;
}

static int ebuild_destroy_backend(void)
{
	filter_destroy();
	list_empty(&ebuild_backend.list);
	return 0;
}
