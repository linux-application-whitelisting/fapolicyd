/*
 * database.c - Trust database
 * Copyright (c) 2016,2018-23 Red Hat Inc.
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
 *   Steve Grubb <sgrubb@redhat.com>
 *   Radovan Sroka <rsroka@redhat.com>
 *   Marek Tamaskovic <mtamasko@redhat.com>
 */

#include "config.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdatomic.h>
#include <poll.h>
#include <pthread.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <openssl/sha.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "database.h"
#include "message.h"
#include "llist.h"
#include "file.h"
#include "fd-fgets.h"

#include "fapolicyd-backend.h"
#include "backend-manager.h"
#include "gcc-attributes.h"
#include "paths.h"
#include "policy.h"

// Local defines
enum { READ_DATA, READ_TEST_KEY, READ_DATA_DUP };
typedef enum { DB_NO_OP, ONE_FILE, RELOAD_DB, FLUSH_CACHE, RELOAD_RULES } db_ops_t;
#define BUFFER_SIZE 4096
#define MEGABYTE	(1024*1024)

// Local variables
static MDB_env *env;
static MDB_dbi dbi;
static int dbi_init = 0;
static unsigned MDB_maxkeysize;
static const char *data_dir = DB_DIR;
static const char *db = DB_NAME;
static int lib_symlink=0, lib64_symlink=0, bin_symlink=0, sbin_symlink=0;
static struct pollfd ffd[1] =  { {0, 0, 0} };
static integrity_t integrity;
static atomic_int reload_db = 0;

static pthread_t update_thread;
static pthread_mutex_t update_lock;
static pthread_mutex_t rule_lock;

// Local functions
static void *update_thread_main(void *arg);
static int update_database(conf_t *config);

// External variables
extern volatile atomic_bool stop;
extern volatile atomic_bool needs_flush;
extern volatile atomic_bool reload_rules;


static int is_link(const char *path)
{
	int rc;
	struct stat sb;

	rc = lstat(path, &sb);
	if (rc == 0) {
		if (S_ISLNK(sb.st_mode))
			return 1;
	}
	return 0;
}

const char *lookup_tsource(unsigned int tsource)
{
	switch (tsource)
	{
	case SRC_RPM:
		return "rpmdb";
	case SRC_DEB:
		return "debdb";
	case SRC_EBUILD:
		return "ebuilddb";
	case SRC_FILE_DB:
		return "filedb";
	}
	return "src_unknown";
}

int preconstruct_fifo(const conf_t *config)
{
	int rc;
	char err_buff[BUFFER_SIZE];

	/* Ensure that the RUN_DIR exists */
	if (mkdir(RUN_DIR, 0770) && errno != EEXIST) {
		msg(LOG_ERR, "Failed to create a directory %s (%s)", RUN_DIR,
		    strerror_r(errno, err_buff, BUFFER_SIZE));
		return 1;
	} else {
		/* Make sure that there is no such file/fifo */
		unlink_fifo();
	}

	rc = mkfifo(fifo_path, 0660);

	if (rc != 0) {
		msg(LOG_ERR, "Failed to create a pipe %s (%s)", fifo_path,
		    strerror_r(errno, err_buff, BUFFER_SIZE));
		return 1;
	}

	if ((ffd[0].fd = open(fifo_path, O_RDWR)) == -1) {
		msg(LOG_ERR, "Failed to open a pipe %s (%s)", fifo_path,
		    strerror_r(errno, err_buff, BUFFER_SIZE));
		unlink_fifo();
		return 1;
	}

	if (config->gid != getgid()) {
		if ((fchown(ffd[0].fd, 0, config->gid))) {
			msg(LOG_ERR, "Failed to fix ownership of pipe %s (%s)",
			    fifo_path, strerror_r(errno, err_buff,
						  BUFFER_SIZE));
			unlink_fifo();
			close(ffd[0].fd);
			return 1;
		}
	}

	return 0;
}


static int init_db(const conf_t *config)
{
	unsigned int flags = MDB_MAPASYNC|MDB_NOSYNC;
#ifndef DEBUG
	flags |= MDB_WRITEMAP;
#endif
	if (mdb_env_create(&env))
		return 1;

	if (mdb_env_set_maxdbs(env, 2))
		return 2;

	if (mdb_env_set_mapsize(env, config->db_max_size*MEGABYTE))
		return 3;

	if (mdb_env_set_maxreaders(env, 4))
		return 4;

	int rc = mdb_env_open(env, data_dir, flags, 0660);
	if (rc) {
		msg(LOG_ERR, "env_open error: %s", mdb_strerror(rc));
		return 5;
	}

	MDB_maxkeysize = mdb_env_get_maxkeysize(env);
	integrity = config->integrity;
	msg(LOG_INFO, "fapolicyd integrity is %u", integrity);

	lib_symlink = is_link("/lib");
	lib64_symlink = is_link("/lib64");
	bin_symlink = is_link("/bin");
	sbin_symlink = is_link("/sbin");

	return 0;
}


static unsigned get_pages_in_use(void);
static unsigned long pages, max_pages;
static void close_db(int do_report)
{
	if (do_report) {
		MDB_envinfo st;

		// Collect useful stats
		unsigned size = get_pages_in_use();
		if (size == 0) {
			msg(LOG_DEBUG,
			    "The trust database is empty.");
		} else {
			mdb_env_info(env, &st);
			max_pages = st.me_mapsize / size;
			msg(LOG_DEBUG, "Trust database max pages: %lu", max_pages);
			msg(LOG_DEBUG, "Trust database pages in use: %lu (%lu%%)", pages,
			    max_pages ? ((100*pages)/max_pages) : 0);
		}
	}

	// Now close down
	mdb_close(env, dbi);
	mdb_env_close(env);
}

static void check_db_size(void)
{
	MDB_envinfo st;

	// Collect stats
	unsigned long size = get_pages_in_use();

	if (size == 0) {
		msg(LOG_WARNING,
		    "The trust database is empty");
		return;
	}

	mdb_env_info(env, &st);
	max_pages = st.me_mapsize / size;
	unsigned long percent = max_pages ? (100*pages)/max_pages : 0;
	if (percent > 80)
		msg(LOG_WARNING, "Trust database at %lu%% capacity - "
		   "might want to increase db_max_size setting", percent);
}

void database_report(FILE *f)
{
	fprintf(f, "Trust database max pages: %lu\n", max_pages);
	fprintf(f, "Trust database pages in use: %lu (%lu%%)\n", pages,
		max_pages ? ((100*pages)/max_pages) : 0);
}


/*
 * A DBI has to be associated with any new txn instance. It can be
 * reused within the same environment unless an abort is used. Aborts
 * close the data base instance.
 */
static int open_dbi(MDB_txn *txn)
{
	if (!dbi_init) {
		int rc;
		if ((rc = mdb_dbi_open(txn, db, MDB_CREATE|MDB_DUPSORT, &dbi))){
			msg(LOG_ERR, "%s", mdb_strerror(rc));
			return rc;
		}
		dbi_init = 1;
	}
	return 0;
}


static void abort_transaction(MDB_txn *txn)
{
	mdb_txn_abort(txn);
	dbi_init = 0;
}


/*
 * Convert path to a hash value. Used when the path exceeds the LMDB key
 * limit(511).  Note: Returned value must be deallocated.
 */
static char *path_to_hash(const char *path, const size_t path_len) MALLOCLIKE;
static char *path_to_hash(const char *path, const size_t path_len)
{
	unsigned char hptr[80];
	char *digest;

	if (path_len == 0)
		return NULL;

	SHA512((unsigned char *)path, path_len, (unsigned char *)&hptr);
	digest = malloc((SHA512_LEN * 2) + 1);
	if (digest == NULL)
		return digest;

	bytes2hex(digest, hptr, SHA512_LEN);

	return digest;
}


/*
 * path - key
 * status, file size, sha256 hash - data
 * status means if data is confirmed: unknown, yes, no
 */
static int write_db(const char *idx, const char *data)
{
	MDB_val key, value;
	MDB_txn *txn;
	int rc, ret_val = 0;
	size_t len;
	char *hash = NULL;

	if (mdb_txn_begin(env, NULL, 0, &txn))
		return 1;

	if (open_dbi(txn)) {
		abort_transaction(txn);
		return 2;
	}

	len = strlen(idx);
	if (len > MDB_maxkeysize) {
		hash = path_to_hash(idx, len);
		if (hash == NULL) {
			abort_transaction(txn);
			return 5;
		}
		key.mv_data = (void *)hash;
		key.mv_size = (SHA512_LEN * 2) + 1;
	} else {
		key.mv_data = (void *)idx;
		key.mv_size = len;
	}
	value.mv_data = (void *)data;
	value.mv_size = strlen(data);

	if ((rc = mdb_put(txn, dbi, &key, &value, 0))) {
		msg(LOG_ERR, "%s", mdb_strerror(rc));
		abort_transaction(txn);
		ret_val = 3;
		goto out;
	}

	if ((rc = mdb_txn_commit(txn))) {
		msg(LOG_ERR, "%s", mdb_strerror(rc));
		ret_val = 4;
		goto out;
	}

out:
	if (len > MDB_maxkeysize)
		free(hash);

	return ret_val;
}


/*
 * The idea with this set of code is that we can set up ops once
 * and perform many read operations. This reduces the need to setup
 * a read lock every time and initial a whole transaction. It returns
 * a 0 on success and a 1 on error.
 */
static MDB_txn *lt_txn = NULL;
static MDB_cursor *lt_cursor = NULL;
static int start_long_term_read_ops(void)
{
	int rc;

	if (lt_txn == NULL) {
		if (mdb_txn_begin(env, NULL, MDB_RDONLY, &lt_txn))
			return 1;
	}
	if ((rc = open_dbi(lt_txn))) {
		msg(LOG_ERR, "open_dbi:%s", mdb_strerror(rc));
		abort_transaction(lt_txn);
		lt_txn = NULL;
		return 1;
	}
	if (lt_cursor == NULL) {
		if ((rc = mdb_cursor_open(lt_txn, dbi, &lt_cursor))) {
			msg(LOG_ERR, "cursor_open:%s", mdb_strerror(rc));
			abort_transaction(lt_txn);
			lt_txn = NULL;
			return 1;
		}
	}

	return 0;
}


/*
 * We are finished with read ops. Close it up.
 */
static void end_long_term_read_ops(void)
{
	mdb_cursor_close(lt_cursor);
	lt_cursor = NULL;
	abort_transaction(lt_txn);
	lt_txn = NULL;
}


static unsigned get_pages_in_use(void)
{
	MDB_stat st;

	start_long_term_read_ops();
	mdb_stat(lt_txn, dbi, &st);
	end_long_term_read_ops();
	pages = st.ms_leaf_pages + st.ms_branch_pages +
		st.ms_overflow_pages;
	return st.ms_psize;
}

// if success, the function returns positive number of entries in database
// if error, it returns -1
static long get_number_of_entries(void)
{
	MDB_stat status;

	start_long_term_read_ops();
	mdb_stat(lt_txn, dbi, &status);
	end_long_term_read_ops();

	return status.ms_entries;
}


/*
 * This is the long term read operation. It takes a path as input and
 * search for the data. It returns NULL on error or if no data found.
 * The returned string must be freed by the caller.
 */
static char *lt_read_db(const char *index, int operation, int *error) MALLOCLIKE;
static char *lt_read_db(const char *index, int operation, int *error)
{
	int rc;
	char *data, *hash = NULL;
	MDB_val key, value;
	size_t len;
	*error = 1; // Assume an error

	// If the path is too long, convert to a hash
	len = strlen(index);
	if (len > MDB_maxkeysize) {
		hash = path_to_hash(index, len);
		if (hash == NULL)
			return NULL;
		key.mv_data = (void *)hash;
		key.mv_size = (SHA512_LEN * 2) + 1;
	} else {
		key.mv_data = (void *)index;
		key.mv_size = len;
	}
	value.mv_data = NULL;
	value.mv_size = 0;

	// set cursor and read first data
	if (operation == READ_DATA || operation == READ_TEST_KEY) {

		// Read the value pointed to by key
		if ((rc = mdb_cursor_get(lt_cursor, &key, &value, MDB_SET))) {
			free(hash);
			if (rc == MDB_NOTFOUND) {
				*error = 0;
			} else {
				msg(LOG_ERR, "MDB_SET: cursor_get:%s", mdb_strerror(rc));
			}
			return NULL;
		}

	}

	// read next available data
	// READ_DATA_DUP is supposed to be used
	// as subsequent call just after READ_DATA
	if (operation == READ_DATA_DUP) {
		size_t nleaves;
		mdb_cursor_count(lt_cursor, &nleaves);
		if (nleaves <= 1) {
			free(hash);
			*error = 0;
			return NULL;
		}

		// is there a next duplicate?
		if ((rc = mdb_cursor_get(lt_cursor, &key, &value,
					 MDB_NEXT_DUP))) {
			free(hash);
			if (rc == MDB_NOTFOUND) {
				*error = 0;
			} else {
				msg(LOG_ERR, "MDB_NEXT_DUP: cursor_get:%s", mdb_strerror(rc));
			}
			return NULL;
		}
	}

	if (len > MDB_maxkeysize)
		free(hash);

	// Failure was already returned. Need to return a pointer of
	// some kind. Using the db name since its non-NULL.
	// A next step might be to check the status field to see that its
	// trusted.
	*error = 0;
	if (operation == READ_TEST_KEY) {
		return strndup(db, MDB_maxkeysize);
	}

	if ((data = malloc(value.mv_size+1))) {
		memcpy(data, value.mv_data, value.mv_size);
		data[value.mv_size] = 0;
	}

	return data;
}


/*
 * This function takes a path as input and looks it up. If found it
 * will delete the entry.
 *
 static int delete_entry_db(const char *index)
 {
	MDB_txn *txn;
	MDB_val key, value;

	if (mdb_txn_begin(env, NULL, 0, &txn))
		return 1;

	if (open_dbi(txn)) {
		abort_transaction(txn);
		return 1;
	}


// FIXME: if we ever use this function, it will need patching
// to use hashes if the path is larger than MDB_maxkeysize.
	key.mv_data = (void *)index;
	key.mv_size = strlen(index);
	value.mv_data = NULL;
	value.mv_size = 0;

	if (mdb_del(txn, dbi, &key, &value)) {
		abort_transaction(txn);
		return 1;
	}

	if (mdb_txn_commit(txn))
		return 1;

	return 0;
}*/


// This function checks the database to see if its empty. It returns
// a 0 if it has entries, 1 on empty, and -1 if an error
static int database_empty(void)
{
	MDB_stat status;
	if (mdb_env_stat(env, &status))
		return -1;
	if (status.ms_entries == 0)
		return 1;
	return 0;
}


static int delete_all_entries_db()
{
	int rc = 0;
	MDB_txn *txn;

	if (mdb_txn_begin(env, NULL, 0, &txn))
		return 1;

	if (open_dbi(txn)) {
		abort_transaction(txn);
		return 2;
	}

	// 0 -> delete , 1 -> delete and close
	if ((rc = mdb_drop(txn, dbi, 0))) {
		msg(LOG_DEBUG, "mdb_drop -> %s", mdb_strerror(rc));
		abort_transaction(txn);
		return 3;
	}

	if ((rc = mdb_txn_commit(txn))) {
		if (rc == MDB_MAP_FULL)
			msg(LOG_ERR, "db_max_size needs to be increased");
		else
			msg(LOG_DEBUG, "mdb_txn_commit -> %s",
			    mdb_strerror(rc));
		return 4;
	}

	return 0;
}


static int create_database(int with_sync)
{
	msg(LOG_INFO, "Creating trust database");
	int rc = 0;

	for (backend_entry *be = backend_get_first() ; be != NULL ;
						     be = be->next ) {
		msg(LOG_INFO,"Loading trust data from %s backend",
		    be->backend->name);

		list_item_t *item = list_get_first(&be->backend->list);
		for (; item != NULL; item = item->next) {
			if ((rc = write_db(item->index, item->data)))
				msg(LOG_ERR,
				    "Error (%d) writing key=\"%s\" data=\"%s\"",
				    rc, (const char*)item->index,
				    (const char*)item->data);
		}
	}
	// Flush everything to disk
	if (with_sync)
		mdb_env_sync(env, 1);

	// Check if database is getting full and warn
	check_db_size();

	return rc;
}


// 1 -> data match
// 0 -> not found
// matched -> returns index of the matched duplicate
static int check_data_presence(const char * index, const char * data, int * matched)
{
	int found = 0;
	int error;
	char *read;
	int operation = READ_DATA;
	int cnt = 0;

	while (1) {
		error = 0;
		read = NULL;
		read = lt_read_db(index, operation, &error);

		if (error)
			msg(LOG_DEBUG, "Error when reading from DB!");

		if (!read)
			break;

		// check strings
		if (strcmp(data, read) == 0) {
			found = 1;
		}

		free(read);
		cnt++;

		if (found)
			break;

		if (operation == READ_DATA)
			operation = READ_DATA_DUP;
	}

	*matched = cnt;
	return found;
}


/*
 * This function will compare the backend database against our copy
 * of the database. It returns a 1 if they do not match, 0 if they do
 * match, and -1 if there is an error.
 */
static int check_database_copy(void)
{
	msg(LOG_INFO, "Checking if the trust database up to date");
	long problems = 0;

	if (start_long_term_read_ops())
		return -1;

	long backend_total_entries = 0;
	long backend_added_entries = 0;

	for (backend_entry *be = backend_get_first() ; be != NULL ;
							 be = be->next ) {
		msg(LOG_INFO, "Importing trust data from %s backend",
							 be->backend->name);

		backend_total_entries += be->backend->list.count;
		list_item_t *item = list_get_first(&be->backend->list);
		for (; item != NULL; item = item->next) {

			int matched = 0;
			int found = check_data_presence(item->index,
							item->data,
							&matched);

			if (!found) {
				problems++;
				// missing in db
				// recently added file
				if (matched == 0) {
					msg(LOG_DEBUG, "%s is not in the trust database",
					    (char*)item->index);
					backend_added_entries++;
				}

				// updated file
				// data miscompare
				if (matched > 0) {
					msg(LOG_DEBUG, "Trust data miscompare for %s",
					    (char*)item->index);
				}
			}
		}
	}

	end_long_term_read_ops();

	long db_total_entries = get_number_of_entries();
	// something wrong
	if (db_total_entries == -1)
		return -1;

	msg(	LOG_INFO,
		"Entries in trust DB: %ld",
		db_total_entries);

	// Check if database is getting full and warn
	check_db_size();

	msg(	LOG_INFO,
		"Loaded trust info from all backends(without duplicates): %ld",
		backend_total_entries);

	// do not print 0
	if (backend_added_entries > 0)
		msg(LOG_INFO, "New trust database entries: %ld",
		    backend_added_entries);

	// db contains records that are not present in backends anymore
	long removed = labs(db_total_entries
			    - (backend_total_entries - backend_added_entries)
			    );
	// do not print 0
	if (removed > 0)
		msg(LOG_INFO, "Removed trust database entries: %ld", removed);

	problems += removed;

	if (problems) {
		msg(LOG_WARNING, "Found %ld problematic trust database entries",
		    problems);
		return 1;
	} else
		msg(LOG_INFO, "Trust database checks OK");
	return 0;
}


/*
 * This function removes the trust database files.
 */
int unlink_db(void)
{
	int rc, ret_val = 0;
	char path[64];

	snprintf(path, sizeof(path), "%s/data.mdb", data_dir);
	rc = unlink(path);
	if (rc == -1 && errno != ENOENT) {
		msg(LOG_ERR, "Could not unlink %s (%s)", path, strerror(errno));
		ret_val = 1;
	}
	snprintf(path, sizeof(path), "%s/lock.mdb", data_dir);
	rc = unlink(path);
	if (rc == -1 && errno != ENOENT) {
		msg(LOG_ERR, "Could not unlink %s (%s)", path, strerror(errno));
		ret_val = 1;
	}
	snprintf(path, sizeof(path), "%s/db.ver", data_dir);
	rc = unlink(path);
	if (rc == -1 && errno != ENOENT) {
		msg(LOG_ERR, "Could not unlink %s (%s)", path, strerror(errno));
		ret_val = 1;
	}

	return ret_val;
}


/*
 * DB version 1 = unique keys (0.8 - 0.9.2)
 * DB version 2 = allow duplicate keys (0.9.3 - )
 *
 * This function is used to detect if we are using version1 of the database.
 * If so, we have to delete the database and rebuild it. We cannot mix
 * database versions because lmdb doesn't do that.
 * Returns 0 success and 1 for failure.
 */
static int migrate_database(void)
{
	int fd;
	char vpath[64];

	snprintf(vpath, sizeof(vpath), "%s/db.ver", data_dir);
	fd = open(vpath, O_RDONLY);
	if (fd < 0) {
		msg(LOG_INFO, "Trust database migration will be performed.");

		// Then we have a version1 db since it does not track versions
		if (unlink_db())
			return 1;

		// Create the new, db version tracker and write current version
		fd = open(vpath, O_CREAT|O_EXCL|O_WRONLY, 0640);
		if (fd < 0) {
			msg(LOG_ERR, "Failed writing db version %s",
			    strerror(errno));
			return 1;
		}
		write(fd, "2", 1);
		close(fd);

		return 0;
	} else {
		// We have a version file, read it and check the version
		int rc = read(fd, vpath, 2);
		close(fd);
		if ((rc > 0) && (vpath[0] == '2'))
			return 0;
	}

	return 1;
}


/*
 * This function is responsible for getting the database ready to use.
 * It will first check to see if a database is populated. If so, then
 * it will verify it against the backend database just in case something
 * has changed. If the database does not exist, then it will create one.
 * It returns 0 on success and a non-zero on failure.
 */
int init_database(conf_t *config)
{
	int rc;

	msg(LOG_INFO, "Initializing the trust database");

	// update_lock is used in update_database()
	pthread_mutex_init(&update_lock, NULL);
	pthread_mutex_init(&rule_lock, NULL);

	if (migrate_database())
		return 1;

	if ((rc = init_db(config))) {
		msg(LOG_ERR, "Cannot open the trust database, init_db() (%d)",
		    rc);
		return rc;
	}

	if ((rc = backend_init(config))) {
		msg(LOG_ERR, "Failed to load trust data from backend (%d)", rc);
		close_db(0);
		return rc;
	}

	if ((rc = backend_load(config))) {
		msg(LOG_ERR, "Failed to load data from backend (%d)", rc);
		close_db(0);
		return rc;
	}

	rc = database_empty();
	if (rc > 0) {
		if ((rc = create_database(/*with_sync*/1))) {
			msg(LOG_ERR,
			"Failed to create trust database, create_database() (%d)",
			   rc);
			close_db(0);
			return rc;
		}
	} else {
		// check if our internal database is synced
		rc = check_database_copy();
		if (rc > 0) {
			rc = update_database(config);
			if (rc)
				msg(LOG_ERR,
				    "Failed updating the trust database");
		}
	}

	// Conserve memory by dumping the linked lists
	backend_close();

	pthread_create(&update_thread, NULL, update_thread_main, config);

	return rc;
}


/*
 * This function handles the integrity check and any retries. Retries are
 * necessary if the system has both i686 and x86_64 packages installed. It
 * takes a path as input and searches for the data. It returns 0 if no
 * data is found or if the integrity check has failed. There is no
 * distinguishing which is the case since both mean you cannot trust the file.
 * It returns a 1 if the file is found and trustworthy. Callers have to
 * check the error variable before trusting it's results.
 */
static int read_trust_db(const char *path, int *error, struct file_info *info,
	int fd)
{
	int do_integrity = 0, mode = READ_TEST_KEY;
	char *res;
	int retry = 0;
	char sha_xattr[65];

	if (integrity != IN_NONE && info) {
		do_integrity = 1;
		mode = READ_DATA;
		sha_xattr[0] = 0; // Make sure we can't re-use stack value
	}

retry_res:
	retry++;

	if (retry >= 128) {
		msg(LOG_ERR, "Checked 128 duplicates for %s "
			"and there is no match. Breaking the cycle.", path);
		*error = 1;
		return 0;
	}

	res = lt_read_db(path, mode, error);

	// For subjects we do a limited check because the process had to
	// pass some kind of trust check to even be started and we do not
	// have an open fd to the file.
	if (!do_integrity) {
		if (res == NULL)
			return 0;
		free(res);
		return 1;
	} else {
		unsigned int tsource;
		off_t size;
		char sha[65];

		// record not found
		if (res == NULL)
			return 0;

		if (sscanf(res, DATA_FORMAT, &tsource, &size, sha) != 3) {
			free(res);
			*error = 1;
			return 1;
		}

		// Need to do the compare and free res
		free(res);

		// prepare for next reading
		if (mode != READ_DATA_DUP)
			mode = READ_DATA_DUP;

		if (integrity == IN_SIZE) {

			// match!
			if (size == info->size) {
				return 1;
			} else {
				goto retry_res;
			}

		} else if (integrity == IN_IMA) {
			int rc = 1;

			// read xattr only the first time
			if (retry == 1)
				rc = get_ima_hash(fd, sha_xattr);

			if (rc) {
				if ((size == info->size) &&
					(strcmp(sha, sha_xattr) == 0)) {
					return 1;
				} else {
					goto retry_res;
				}

			} else {
				*error = 1;
				return 0;
			}

		} else if (integrity == IN_SHA256) {
			char *hash = NULL;

			// Calculate a hash only one time
			if (retry == 1) {
				hash = get_hash_from_fd2(fd, info->size, 1);
				if (hash) {
					strncpy(sha_xattr, hash, 64);
					sha_xattr[64] = 0;
					free(hash);
				} else {
					*error = 1;
					return 0;
				}
			}

			if ((size == info->size) &&
				(strcmp(sha, sha_xattr) == 0))
				return 1;
			else {
				goto retry_res;
			}
		}
	}

	*error = 1;
	return 0;
}

// Returns a 1 if trusted and 0 if not and -1 on error
int check_trust_database(const char *path, struct file_info *info, int fd)
{
	int retval = 0, error;
	int res;

	// this function is going to be used from decision_thread
	// that means we need to be sure database won't change under
	// our hands
	lock_update_thread();

	if (start_long_term_read_ops()) {
		unlock_update_thread();
		return -1;
	}

	res = read_trust_db(path, &error, info, fd);
	if (error)
		retval = -1;
	else if (res)
		retval = 1;
	else if (lib64_symlink || lib_symlink || bin_symlink || sbin_symlink) {
		// If we are on a system that symlinks the top level
		// directories to /usr, then let's try again without the /usr
		// dir. There shouldn't be many packages that have this
		// problem. These are sorted from most likely to least.
		if (strncmp(path, "/usr/", 5) == 0) {
			if ((lib64_symlink &&
			     strncmp(&path[5], "lib64/", 6) == 0) ||
			    (lib_symlink &&
			     strncmp(&path[5], "lib/", 4) == 0) ||
			    (bin_symlink &&
			     strncmp(&path[5], "bin/", 4) == 0) ||
			    (sbin_symlink &&
			     strncmp(&path[5], "sbin/", 5) == 0)) {
				// We have a symlink, retry
				res = read_trust_db(&path[4], &error, info, fd);
				if (error)
					retval = -1;
				else if (res)
					retval = 1;
			}
		}
	}

	end_long_term_read_ops();
	unlock_update_thread();

	return retval;
}


void close_database(void)
{
	pthread_join(update_thread, NULL);

	// we can close db when we are really sure update_thread does not exist
	close_db(1);
	pthread_mutex_destroy(&update_lock);
	pthread_mutex_destroy(&rule_lock);

	backend_close();
	unlink_fifo();
}


void unlink_fifo(void)
{
	unlink(fifo_path);
}


/*
 * Lock wrapper for update mutex
 */
void lock_update_thread(void) {
	pthread_mutex_lock(&update_lock);
	//msg(LOG_DEBUG, "lock_update_thread()");
}

/*
 * Unlock wrapper for update mutex
 */
void unlock_update_thread(void) {
	pthread_mutex_unlock(&update_lock);
	//msg(LOG_DEBUG, "unlock_update_thread()");
}

/*
 * Lock wrapper for rule mutex
 */
void lock_rule(void) {
	pthread_mutex_lock(&rule_lock);
	//msg(LOG_DEBUG, "lock_rule()");
}

/*
 * Unlock wrapper for rule mutex
 */
void unlock_rule(void) {
	pthread_mutex_unlock(&rule_lock);
	//msg(LOG_DEBUG, "unlock_rule()");
}

/*
 * This function reloads updated backend db into our internal database.
 * It returns 0 on success and non-zero on error.
 */
static int update_database(conf_t *config)
{
	int rc;

	msg(LOG_INFO, "Updating trust database");
	msg(LOG_DEBUG, "Loading trust database backends");

	/*
	 * backend loading/reloading should be done in upper level
	 */
	/*
	   if ((rc = backend_load(config))) {
	   msg(LOG_ERR, "Cannot open the backend database (%d)", rc);
	   return rc;
	   }*/

	lock_update_thread();

	if ((rc = delete_all_entries_db())) {
		msg(LOG_ERR, "Cannot delete database (%d)", rc);
		unlock_update_thread();
		return rc;
	}

	rc = create_database(/*with_sync*/0);

	// signal that cache need to be flushed
	needs_flush = true;

	unlock_update_thread();
	mdb_env_sync(env, 1);

	if (rc) {
		msg(LOG_ERR, "Failed to create the trust database (%d)", rc);
		close_db(1);
		return rc;
	}

	return 0;
}

static int handle_record(const char * buffer)
{
	char path[2048+1];
	char hash[64+1];
	off_t size;

	// validating input
	int res = sscanf(buffer, "%2048s %lu %64s", path, &size, hash);
	msg(LOG_DEBUG, "update_thread: Parsing input buffer: %s", buffer);
	msg(LOG_DEBUG,
	    "update_thread: Parsing input words(expected 3): %d",
	    res);

	if (res != 3) {
		msg(LOG_INFO, "Corrupted data read, ignoring...");
		return 1;
	}

	char data[BUFFER_SIZE];
	snprintf(data, BUFFER_SIZE, DATA_FORMAT, (unsigned int)SRC_UNKNOWN,
		 size, hash);

	msg(LOG_DEBUG, "update_thread: Saving %s %s", path, data);
	lock_update_thread();
	write_db(path, data);
	unlock_update_thread();

	return 0;
}

void set_reload_trust_database(void)
{
	reload_db = 1;
}

static void do_reload_db(conf_t* config)
{
	msg(LOG_INFO,"It looks like there was an update of the system... Syncing DB.");

	int rc;
	backend_close();
	backend_init(config);
	backend_load(config);

	if ((rc = update_database(config))) {
		msg(LOG_ERR,
			"Cannot update trust database!");
		close(ffd[0].fd);
		backend_close();
		unlink_fifo();
		exit(rc);
	}

	msg(LOG_INFO, "Updated");

	// Conserve memory
	backend_close();
}

static void *update_thread_main(void *arg)
{
	int rc;
	sigset_t sigs;
	char buff[BUFFER_SIZE];
	char err_buff[BUFFER_SIZE];
	conf_t *config = (conf_t *)arg;

	int do_operation = DB_NO_OP;;

#ifdef DEBUG
	msg(LOG_DEBUG, "Update thread main started");
#endif

	/* This is a worker thread. Don't handle external signals. */
	sigemptyset(&sigs);
	sigaddset(&sigs, SIGTERM);
	sigaddset(&sigs, SIGHUP);
	sigaddset(&sigs, SIGUSR1);
	sigaddset(&sigs, SIGINT);
	sigaddset(&sigs, SIGQUIT);
	pthread_sigmask(SIG_SETMASK, &sigs, NULL);

	if (ffd[0].fd == 0) {
		if (preconstruct_fifo(config))
			return NULL;
	}

	fcntl(ffd[0].fd, F_SETFL, O_NONBLOCK);
	ffd[0].events = POLLIN;

	while (!stop) {

		rc = poll(ffd, 1, 1000);

		if (reload_rules) {
			reload_rules = 0;
			load_rule_file();

			lock_rule();
			do_reload_rules(config);
			unlock_rule();
		}
		// got SIGHUP
		if (reload_db) {
			reload_db = 0;
			do_reload_db(config);
		}

#ifdef DEBUG
		msg(LOG_DEBUG, "Update poll interrupted");
#endif

		if (rc < 0) {
			if (errno == EINTR) {
#ifdef DEBUG
				msg(LOG_DEBUG, "update poll rc = EINTR");
#endif
				continue;
			} else {
				msg(LOG_ERR, "Update poll error (%s)",
				    strerror_r(errno, err_buff, BUFFER_SIZE));
				goto finalize;
			}
		} else if (rc == 0) {
#ifdef DEBUG
			msg(LOG_DEBUG, "Update poll timeout expired");
#endif
			continue;
		} else {
			if (ffd[0].revents & POLLIN) {

				do {
					fd_fgets_rewind();
					int res = fd_fgets(buff, sizeof(buff), ffd[0].fd);

					// nothing to read
					if (res == -1)
						break;
					else if (res > 0) {
						char* end  = strchr(buff, '\n');

						if (end == NULL) {
							msg(LOG_ERR, "Too long line?");
							continue;
						}

						int count = end - buff;

						*end = '\0';

						for (int i = 0 ; i < count ; i++) {
							// assume file name
							// operation = 0
							if (buff[i] == '/') {
								do_operation = ONE_FILE;
								break;
							}

							if (buff[i] == RELOAD_TRUSTDB_COMMAND) {
								do_operation = RELOAD_DB;
								break;
							}

							if (buff[i] == FLUSH_CACHE_COMMAND) {
								do_operation = FLUSH_CACHE;
								break;
							}

							if (buff[i] == RELOAD_RULES_COMMAND) {
								do_operation = RELOAD_RULES;
								break;
							}

							if (isspace(buff[i]))
								continue;

							msg(LOG_ERR, "Cannot handle data \"%s\" from pipe", buff);
							break;
						}

						*end = '\n';

						// got "1" -> reload db
						if (do_operation == RELOAD_DB) {
							do_operation = DB_NO_OP;
							do_reload_db(config);
						} else if (do_operation == RELOAD_RULES) {
							do_operation = DB_NO_OP;

							load_rule_file();

							lock_rule();
							do_reload_rules(config);
							unlock_rule();

							// got "2" -> flush cache
						} else if (do_operation == FLUSH_CACHE) {
							do_operation = DB_NO_OP;
							needs_flush = true;
						} else if (do_operation == ONE_FILE) {
							do_operation = DB_NO_OP;
							if (handle_record(buff))
								continue;
						}
					}

				} while(!fd_fgets_eof());
			}
		}
	}

finalize:
	close(ffd[0].fd);
	unlink_fifo();

	return NULL;
}


/***********************************************************************
 * This section of functions are used by the command line utility to
 * iterate across the database to verify each entry. It will be a read
 * only operation.
 ***********************************************************************/
static walkdb_entry_t wdb_entry;

// Returns 0 on success and 1 on failure
int walk_database_start(conf_t *config)
{
	int rc;

	// Initialize the database
	if (init_db(config)) {
		printf("Cannot open the trust database\n");
		return 1;
	}
	if (database_empty()) {
		printf("The trust database is empty - nothing to do\n");
		return 1;
	}

	// Position to the first entry
	mdb_txn_begin(env, NULL, MDB_RDONLY, &lt_txn);

	if ((rc = open_dbi(lt_txn))) {
		puts(mdb_strerror(rc));
		abort_transaction(lt_txn);
		return 1;
	}

	if ((rc = mdb_cursor_open(lt_txn, dbi, &lt_cursor))) {
		puts(mdb_strerror(rc));
		abort_transaction(lt_txn);
		return 1;
	}

	if ((rc = mdb_cursor_get(lt_cursor, &wdb_entry.path, &wdb_entry.data,
							MDB_FIRST)) == 0)
		return 0;

	if (rc != MDB_NOTFOUND)
		puts(mdb_strerror(rc));

	return 1;
}

walkdb_entry_t *walk_database_get_entry(void)
{
	return &wdb_entry;
}

// Returns 1 on success and 0 in error
int walk_database_next(void)
{
	int rc;

	if ((rc = mdb_cursor_get(lt_cursor, &wdb_entry.path, &wdb_entry.data,
							MDB_NEXT)) == 0)
		return 1;

	if (rc != MDB_NOTFOUND)
		puts(mdb_strerror(rc));

	return 0;
}

void walk_database_finish(void)
{
	mdb_cursor_close(lt_cursor);
	abort_transaction(lt_txn);
	close_db(0);
}
