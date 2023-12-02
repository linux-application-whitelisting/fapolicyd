#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <uthash.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "conf.h"
#include "fapolicyd-backend.h"
#include "file.h"
#include "llist.h"
#include "message.h"
#include "md5-backend.h"

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

typedef struct contents {
	char *md5;
	char *path;
} ebuildfiles;

struct epkg {
	char *cpv;
	char *slot;
	char *repo;
	int files;
	ebuildfiles *content;
};


char* remove_newline(char* string) {
    int len = strlen(string);
    if (len > 0 && string[len-1] == '\n') {
        string[len-1] = '\0';
    }
    return string;
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
	struct dirent *vdbdp;

	if ((vdbdir = opendir("/var/db/pkg")) == NULL) {
		msg(LOG_ERR, "Could not open /var/db/pkg");
		return 1;
	}

	struct epkg *vdbpackages = NULL;
	int i = 0;

	/*
	 * recurse through category/package-version/ dirs,
	 * process CONTENTS (files, md5s), repository, SLOT,
	 * store in epkg array
	*/
	while ((vdbdp = readdir(vdbdir)) != NULL) {

		if (vdbdp->d_type == DT_DIR && strcmp(vdbdp->d_name, ".") != 0 &&
				strcmp(vdbdp->d_name, "..") != 0) {

			char *catdir;
			if (asprintf(&catdir, "/var/db/pkg/%s", vdbdp->d_name) == -1) {
				catdir = NULL;
			}

			msg(LOG_INFO, "Loading category %s", vdbdp->d_name);

			if (catdir) {
				DIR *cat;
				struct dirent *catdp;
				if ((cat = opendir(catdir)) == NULL) {
					msg(LOG_ERR, "Could not open %s", catdir);
					free(catdir);
					continue;
				}

				while ((catdp = readdir(cat)) != NULL) {

					if (catdp->d_type == DT_DIR && strcmp(catdp->d_name, ".") != 0 &&
							strcmp(catdp->d_name, "..") != 0) {
						char *pkgverdir;

						if (asprintf(&pkgverdir, "%s/%s", catdir, catdp->d_name) == -1) {
							pkgverdir = NULL;
						}

						msg(LOG_INFO, "Loading package %s/%s", vdbdp->d_name, catdp->d_name);
						char *pkgrepo = NULL;
						char *pkgslot = NULL;
						int pkgfiles = 0;
						ebuildfiles* pkgcontents = NULL;


						if (pkgverdir) {
							DIR *pkgver;
							struct dirent *pkgverdp;

							if ((pkgver = opendir(pkgverdir)) == NULL) {
								msg(LOG_ERR, "Could not open %s", pkgverdir);
								free(pkgverdir);
								continue;
							}

							while ((pkgverdp = readdir(pkgver)) != NULL) {

								// SLOT
								if (pkgverdp->d_type == DT_REG &&
										strcmp(pkgverdp->d_name, "SLOT") == 0) {
									char *slot;
									if (asprintf(&slot, "%s/%s", pkgverdir,
															 pkgverdp->d_name) == -1) {
										slot = NULL;
									}
									if (slot) {
										FILE *fp;
										char *line = NULL;
										size_t len = 0;
										ssize_t read;
										if ((fp = fopen(slot, "r")) == NULL) {
											msg(LOG_ERR, "Could not open %s", slot);
											free(slot);
											continue;
										}
										// SLOT will only ever contain a single line
										if ((read = getline(&line, &len, fp)) != -1) {
											pkgslot = strdup(line);
											remove_newline(pkgslot);
										}
										#ifdef DEBUG
										msg(LOG_DEBUG, "\tslot: %s", pkgslot);
										#endif
										free(line);
										free(slot);
									}
								}

								// repository
								if (pkgverdp->d_type == DT_REG &&
										strcmp(pkgverdp->d_name, "repository") == 0) {
									char *repo;
									if (asprintf(&repo, "%s/%s", pkgverdir,
															 pkgverdp->d_name) == -1) {
										repo = NULL;
									}
									if (repo) {
										FILE *fp;
										char *line = NULL;
										size_t len = 0;
										ssize_t read;
										if ((fp = fopen(repo, "r")) == NULL) {
											msg(LOG_ERR, "Could not open %s", repo);
											free(repo);
											continue;
										}
										// repository will only ever contain a single line
										if ((read = getline(&line, &len, fp)) != -1) {
											pkgrepo = strdup(line);
											remove_newline(pkgrepo);
										}
										#ifdef DEBUG
										msg(LOG_DEBUG, "\trepo: %s", pkgrepo);
										#endif
										free(line);
										free(repo);
									}
								}
								// CONTENTS
								if (pkgverdp->d_type == DT_REG &&
										strcmp(pkgverdp->d_name, "CONTENTS") == 0) {
									char *contents;
									if (asprintf(&contents, "%s/%s", pkgverdir,
															 pkgverdp->d_name) == -1) {
										contents = NULL;
									}
									if (contents) {
										FILE *fp;
										char *line = NULL;
										size_t len = 0;
										ssize_t read;
										if ((fp = fopen(contents, "r")) == NULL) {
											msg(LOG_ERR, "Could not open %s", contents);
											free(contents);
											continue;
										}

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

												pkgcontents = realloc(pkgcontents, sizeof(ebuildfiles) * (pkgfiles + 1));
												pkgcontents[pkgfiles] = *file;
												pkgfiles++;
												free(file);
											}

										}
									}
								}

							}
							// Construct a CPV string from VDB path fragments e.g. dev-libs/libxml2-2.9.10{-r0}
							// We're not processing based on this information, but it's useful for logging
							// If there's a need to split into components see
							// https://github.com/gentoo/portage-utils/blob/master/libq/atom.c
							char *catpkgver = malloc(strlen(vdbdp->d_name) + strlen(catdp->d_name) + 2);
							if (catpkgver == NULL) {
								msg(LOG_ERR, "Could not allocate memory.");
								return 1;
							}
							strcpy(catpkgver, vdbdp->d_name);
							strcat(catpkgver, "/");
							strcat(catpkgver, catdp->d_name);

							// add to pkgs array
							struct epkg *package = malloc(sizeof(struct epkg));
							package->cpv = strdup(catpkgver);
							package->slot = strdup(pkgslot);
							package->repo = strdup(pkgrepo);
							package->files = pkgfiles;
							package->content = pkgcontents;
							vdbpackages = realloc(vdbpackages, sizeof(struct epkg) * (i + 1));
							vdbpackages[i] = *package;
							i++;

							#ifdef DEBUG
							msg(LOG_DEBUG, "Package %s\n\tSlot %s\n\tRepo %s\n\tFiles %i",
								package->cpv, package->slot, package->repo, package->files);
							#endif
							free(catpkgver);
							free(pkgslot);
							free(pkgrepo);
							free(package);
						}
					}
				}
			}
		}
	}

	msg(LOG_INFO, "Processed %d packages.", i);

	for (int j = 0; j < i; j++) {
		struct epkg *package = &vdbpackages[j];

		// slot "0" is the default slot for packages that aren't slotted; we don't need to include it in the log
		// TODO: Files listed here include paths we filter in add_file_to_backend_by_md5
		if ((strcmp(package->slot,"0")) == 0) {
			msg(LOG_INFO, "Adding %s:%s (::%s) to the ebuild backend; %i files", package->cpv, package->slot, package->repo, package->files);
		} else {
			msg(LOG_INFO, "Adding %s (::%s) to the ebuild backend; %i files", package->cpv, 	package->repo, package->files);
		}
		for (int k = 0; k < package->files; k++) {
			ebuildfiles *file = &package->content[k];
			add_file_to_backend_by_md5(file->path, file->md5, hashtable_ptr, SRC_EBUILD, &ebuild_backend);
		}
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
