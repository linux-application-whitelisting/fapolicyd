/*
 * rpm-backend.c - rpm backend
 * Copyright (c) 2020 Red Hat Inc., Durham, North Carolina.
 * All Rights Reserved.
 *
 * This software may be freely redistributed and/or modified under the
 * terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; see the file COPYING. If not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor
 * Boston, MA 02110-1335, USA.
 *
 * Authors:
 *   Radovan Sroka <rsroka@redhat.com>
 */

#include "config.h"
#include <stddef.h>
#include <sys/types.h>
#include <rpm/rpmlib.h>
#include <rpm/rpmts.h>
#include <rpm/rpmmacro.h>
#include <rpm/rpmlog.h>
#include <rpm/rpmdb.h>
#include <fnmatch.h>

#include <uthash.h>

#include "message.h"

#include "fapolicyd-backend.h"
#include "llist.h"

static int rpm_init_backend(void);
static int rpm_load_list(void);
static int rpm_destroy_backend(void);

backend rpm_backend =
{
	"rpmdb",
	rpm_init_backend,
	rpm_load_list,
	rpm_destroy_backend,
	/* list initialization */
	{ 0, 0, NULL },
};

static rpmts ts = NULL;
static rpmdbMatchIterator mi = NULL;

static int init_rpm(void)
{
	return rpmReadConfigFiles ((const char *)NULL, (const char *)NULL);
}

static Header h = NULL;
static int get_next_package_rpm(void)
{
	// If this is the first time, create a package iterator
	if (mi == NULL) {
		ts = rpmtsCreate();
		mi = rpmtsInitIterator(ts, RPMDBI_PACKAGES, NULL, 0);
		if (mi == NULL)
			return 0;
	}

	if (h)	// Decrement reference count, and free memory
		headerFree(h);

	h = rpmdbNextIterator(mi);
	if (h == NULL)
		return 0;	// No more packages, done

	// Increment reference count
	headerLink(h);

	return 1;
}

static rpmfi fi = NULL;
static int get_next_file_rpm(void)
{
	// If its the first time, make file iterator
	if (fi == NULL)
		fi = rpmfiNew(NULL, h, RPMTAG_BASENAMES, RPMFI_KEEPHEADER);

	if (fi) {
		if (rpmfiNext(fi) == -1) {
			// No more files, cleanup iterator
			rpmfiFree(fi);
			fi = NULL;
			return 0;
		}
        }
	return 1;
}

// Like strdup, but sets a minimum size for safety 
static inline char *strmdup(const char *s, size_t min)
{
	char *new;
	size_t len = strlen(s) + 1;

	new = malloc(len < min ? min : len);
	if (new == NULL)
		return NULL;

	return (char *)memcpy(new, s, len);
}

static const char *get_file_name_rpm(void)
{
	return strmdup(rpmfiFN(fi), 7);
}

static rpm_loff_t get_file_size_rpm(void)
{
	return rpmfiFSize(fi);
}

static char *get_sha256_rpm(void)
{
	return rpmfiFDigestHex(fi, NULL);
}

static int is_dir_link_rpm(void)
{
	mode_t mode = rpmfiFMode(fi);
	if (S_ISDIR(mode) || S_ISLNK(mode))
		return 1;
	return 0;
}

/* We don't want doc files in the database */
static int is_doc_rpm(void)
{
	if (rpmfiFFlags(fi) & (RPMFILE_DOC|RPMFILE_README|
				RPMFILE_GHOST|RPMFILE_LICENSE|RPMFILE_PUBKEY))
		return 1;
	return 0;
}

/* Config files can have a changed hash. We want them in the db since
 * they are trusted. */
static int is_config_rpm(void)
{
	if (rpmfiFFlags(fi) &
		(RPMFILE_CONFIG|RPMFILE_MISSINGOK|RPMFILE_NOREPLACE))
		return 1;
	return 0;
}

static void close_rpm(void)
{
	rpmfiFree(fi);
	fi = NULL;
	headerFree(h);
	h = NULL;
	rpmdbFreeIterator(mi);
	mi = NULL;
	rpmtsFree(ts);
	ts = NULL;
	rpmFreeCrypto();
	rpmFreeRpmrc();
	rpmFreeMacros(NULL);
	rpmlogClose();
}

// This function will check a passed file name to see if the path should
// be kept or dropped. 1 means discard it, and 0 means keep it.
static int drop_path(const char *file_name)
{
	if (file_name[1] == 'u') {
		if (file_name[5] == 's') {
			// Drop anything in /usr/share that's
			// not python, javascript, or has a libexec dir
			if (file_name[6] == 'h' ) {
				// These are roughly ordered by quantity
				// Python byte code
				if (fnmatch("*.py?",
						 file_name, 0) == 0)
					return 0;
				// Python text files
				else if (fnmatch("*.py",
						 file_name, 0) == 0)
					return 0;
				// Some apps have a private libexec
				else if (fnmatch("*/libexec/*",
						file_name, 0) == 0)
					return 0;
				// Ruby
				else if (fnmatch("*.rb",
						 file_name, 0) == 0)
					return 0;
				// Perl
				else if (fnmatch("*.pl",
						 file_name, 0) == 0)
					return 0;
				// System Tap
				else if (fnmatch("*.stp",
						 file_name, 0) == 0)
					return 0;
				// Javascript
				else if (fnmatch("*.js",
						 file_name, 0) == 0)
					return 0;
				// Java
				else if (fnmatch("*.jar",
						 file_name, 0) == 0)
					return 0;
				// M4
				else if (fnmatch("*.m4",
						 file_name, 0) == 0)
					return 0;
				// PHP
				else if (fnmatch("*.php",
						 file_name, 0) == 0)
					return 0;
				// Lisp
				else if (fnmatch("*.el",
						 file_name, 0) == 0)
					return 0;
				// Perl Modules
				else if (fnmatch("*.pm",
						 file_name, 0) == 0)
					return 0;
				// Lua
				else if (fnmatch("*.lua",
						 file_name, 0) == 0)
					return 0;
				// Java
				else if (fnmatch("*.class",
						 file_name, 0) == 0)
					return 0;
				// Compiled Lisp
				else if (fnmatch("*.elc",
						 file_name, 0) == 0)
					return 0;
				return 1;
			// Akmod need scripts in /usr/src/kernel
			} else if (file_name[6] == 'r' ) {
				if (fnmatch("*/scripts/*",
						 file_name, 0) == 0)
					return 0;
				else if (fnmatch(
					"*/tools/objtool/*",
						 file_name, 0) == 0)
					return 0;
				return 1;
			}
		// Drop anything in /usr/include
		} else if (file_name[5] == 'i')
			return 1;
	}
	return 0;
}

struct _hash_record {
	const char * key;
	UT_hash_handle hh;
};

extern int debug;
static int rpm_load_list(void)
{
	int rc;
	unsigned int msg_count = 0;

	// empty list before loading
	list_empty(&rpm_backend.list);

	// hash table
	struct _hash_record *hashtable = NULL;

	msg(LOG_INFO, "Loading rpmdb backend");
	if ((rc = init_rpm())) {
		msg(LOG_ERR, "init_rpm() failed (%d)", rc);
		return rc;
	}

	// Loop across the rpm database
	while (get_next_package_rpm()) {
		// Loop across the packages
		while (get_next_file_rpm()) {
			// We do not want directories or symlinks in the
			// database. Multiple packages can own the same
			// directory and that causes problems in the size info.
			if (is_dir_link_rpm())
				continue;

			// We do not want any documentation in the database
			if (is_doc_rpm())
				continue;

			// We do not want any configuration files in database
			if (is_config_rpm())
				continue;

			// Get specific file information
			const char *file_name = get_file_name_rpm();
			rpm_loff_t sz = get_file_size_rpm();
			const char *sha = get_sha256_rpm();
			char *data;
			unsigned int tsource = SRC_RPM;

			if (file_name == NULL)
				continue;

			if (drop_path(file_name)) {
				free((void *)file_name);
				free((void *)sha);
				continue;
			}

			if (strlen(sha) != 64) {
				// Limit this to 5 if production
				if (debug || msg_count++ < 5) {
					msg(LOG_WARNING, "No SHA256 for %s",
							    file_name);
				}
			}

			if (asprintf(	&data,
					DATA_FORMAT,
					tsource,
					sz,
					sha) == -1) {
				data = NULL;
			}

			if (data) {
				// getting rid of the duplicates
				struct _hash_record *rcd = NULL;
				char key[4096];
				snprintf(key, 4095, "%s %s", file_name, data);

				HASH_FIND_STR( hashtable, key, rcd );

				if (!rcd) {
					rcd = (struct _hash_record*) malloc(sizeof(struct _hash_record));
					rcd->key = strdup(key);
					HASH_ADD_KEYPTR( hh, hashtable, rcd->key, strlen(rcd->key), rcd );
					list_append(&rpm_backend.list, file_name, data);
				} else {
					free((void*)file_name);
					free((void*)data);
				}
			} else {
				free((void*)file_name);
			}
			free((void *)sha);
		}
	}

	close_rpm();

	// cleaning up
	struct _hash_record *item, *tmp;
	HASH_ITER( hh, hashtable, item, tmp) {
		HASH_DEL( hashtable, item );
		free((void*)item->key);
		free((void*)item);
	}

	return 0;
}

static int rpm_init_backend(void)
{
	list_init(&rpm_backend.list);
	return 0;
}

static int rpm_destroy_backend(void)
{
	list_empty(&rpm_backend.list);
	return 0;
}
