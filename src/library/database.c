/*
 * database.c - Trust database
 * Copyright (c) 2016,2018-20 Red Hat Inc.
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
#include <lmdb.h>
#include <string.h>
#include <stdlib.h>
#include <stdatomic.h>
#include <poll.h>
#include <pthread.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <gcrypt.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "database.h"
#include "message.h"
#include "llist.h"
#include "file.h"

#include "fapolicyd-backend.h"
#include "backend-manager.h"


// Local defines
enum { READ_DATA, READ_TEST_KEY, READ_DATA_DUP };
#define BUFFER_SIZE 1024
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
static const char *fifo_path = "/run/fapolicyd/fapolicyd.fifo";
static integrity_t integrity;

static pthread_t update_thread;
static pthread_mutex_t update_lock;

// Local functions
static void *update_thread_main(void *arg);
static int update_database(conf_t *config);

// External variables
extern volatile atomic_bool stop;
extern volatile atomic_bool needs_flush;


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
	case SRC_FILE_DB:
		return "filedb";
	}
	return "src_unknown";
}

int preconstruct_fifo(const conf_t *config)
{
	int rc;
	char err_buff[BUFFER_SIZE];

	/* Make sure that there is no such file/fifo */
	unlink_fifo();

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
	if (rc)
		return 5;

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
static void close_db(void)
{
	MDB_envinfo stat;

	// Collect useful stats
	unsigned size = get_pages_in_use();
	mdb_env_info(env, &stat);
	max_pages = stat.me_mapsize / size;
	msg(LOG_DEBUG, "Database max pages: %lu", max_pages);
	msg(LOG_DEBUG, "Database pages in use: %lu (%lu%%)", pages,
	    max_pages ? ((100*pages)/max_pages) : 0);

	// Now close down
	mdb_close(env, dbi);
	mdb_env_close(env);
}

void database_report(FILE *f)
{
	fprintf(f, "Database max pages: %lu\n", max_pages);
	fprintf(f, "Database pages in use: %lu (%lu%%)\n\n", pages,
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
static char *path_to_hash(const char *path, const size_t path_len)
{
	gcry_md_hd_t h;
	unsigned int len;
	char *digest, *hptr;

	if (gcry_md_open(&h, GCRY_MD_SHA512, GCRY_MD_FLAG_SECURE))
		return NULL;

	gcry_md_write(h, path, path_len);
	hptr = (char *)gcry_md_read(h, GCRY_MD_SHA512);

	len = gcry_md_get_algo_dlen(GCRY_MD_SHA512) * sizeof(char);
	digest = malloc((2 * len) + 1);
	if (digest == NULL) {
		gcry_md_close(h);
		return digest;
	}

	bytes2hex(digest, hptr, len);
	gcry_md_close(h);

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
	int rc;
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
		if (hash == NULL)
			return 5;
		key.mv_data = (void *)hash;
		key.mv_size = gcry_md_get_algo_dlen(GCRY_MD_SHA512) * 2 + 1;
	} else {
		key.mv_data = (void *)idx;
		key.mv_size = len;
	}
	value.mv_data = (void *)data;
	value.mv_size = strlen(data);

	if ((rc = mdb_put(txn, dbi, &key, &value, 0))) {
		msg(LOG_ERR, "%s", mdb_strerror(rc));
		abort_transaction(txn);
		return 3;
	}

	if ((rc = mdb_txn_commit(txn))) {
		msg(LOG_ERR, "%s", mdb_strerror(rc));
		return 4;
	}

	if (len > MDB_maxkeysize)
		free(hash);

	return 0;
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
	MDB_stat stat;

	start_long_term_read_ops();
	mdb_stat(lt_txn, dbi, &stat);
	end_long_term_read_ops();
	pages = stat.ms_leaf_pages + stat.ms_branch_pages +
		stat.ms_overflow_pages;
	return stat.ms_psize;
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
		key.mv_size = gcry_md_get_algo_dlen(GCRY_MD_SHA512) * 2 + 1;
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
				return NULL;
			}
			msg(LOG_ERR, "cursor_get:%s", mdb_strerror(rc));
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

		// There's duplicate, grab the second one.
		if ((rc = mdb_cursor_get(lt_cursor, &key, &value,
					 MDB_NEXT_DUP))) {
			free(hash);
			msg(LOG_ERR, "cursor_get:%s", mdb_strerror(rc));
			return NULL;
		}

		if ((rc = mdb_cursor_get(lt_cursor, &key, &value,
					 MDB_GET_CURRENT))) {
			free(hash);
			msg(LOG_ERR, "cursor_get:%s", mdb_strerror(rc));
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
	if (operation == READ_TEST_KEY)
		return (char *)db;

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

	if (mdb_txn_commit(txn))
		return 4;

	return 0;
}


static int create_database(int with_sync)
{
	msg(LOG_INFO, "Creating database");
	int rc = 0;

	for (backend_entry *be = backend_get_first() ; be != NULL ;
						     be = be->next ) {
		msg(LOG_INFO,"Loading data from %s backend", be->backend->name);

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
	return rc;
}


/*
 * This function will compare the backend database against our copy
 * of the database. It returns a 1 if they do not match, 0 if they do
 * match, and -1 if there is an error.
 */
static int check_database_copy(void)
{
	msg(LOG_INFO, "Checking database");
	long problems = 0;

	if (start_long_term_read_ops())
		return -1;

	long backend_total_entries = 0;
	long backend_added_entries = 0;

	for (backend_entry *be = backend_get_first() ; be != NULL ;
							 be = be->next ) {
		msg(LOG_INFO, "Importing data from %s backend",
							 be->backend->name);

		backend_total_entries += be->backend->list.count;
		list_item_t *item = list_get_first(&be->backend->list);
		for (; item != NULL; item = item->next) {
			int error;

			char *data = lt_read_db(item->index, READ_DATA, &error);
			if (data && !error) {
				if (strcmp(item->data, data)) {
					// Let's retry its duplicate
					free(data);
					data = lt_read_db(item->index,
							READ_DATA_DUP, &error);
					if (error) {
						free(data);
						end_long_term_read_ops();
						return -1;
					}

					// If no dup or miscompare, problems
					if (!data || strcmp(item->data, data)) {
						msg(LOG_DEBUG,
					    "Data miscompare for %s:%s vs %s",
						    (const char *)item->index,
						    (const char *)item->data,
						    data);
						problems++;
					}
				}
			} else if (!error) {
				msg(LOG_WARNING, "%s is not in database",
				    (const char *)item->index);
				problems++;
				// record is new, we need to exclude it from comparison
				backend_added_entries++;
			}

			free(data);
			if (error) {
				end_long_term_read_ops();
				return -1;
			}
		}
	}


	end_long_term_read_ops();

	long db_total_entries = get_number_of_entries();
	// something wrong
	if (db_total_entries == -1)
		return -1;

	msg(LOG_INFO, "Entries in DB: %ld", db_total_entries);
	msg(LOG_INFO, "Loaded from all backends(without duplicates): %ld", backend_total_entries);

	// do not print 0
	if (backend_added_entries > 0)
		msg(LOG_INFO, "New entries: %ld", backend_added_entries);

	// db contains records that are not present in backends anymore
	long removed = labs(db_total_entries - (backend_total_entries - backend_added_entries));
	// do not print 0
	if (removed > 0)
		msg(LOG_INFO, "Removed entries: %ld", removed);

	problems += removed;

	if (problems) {
		msg(LOG_WARNING, "Found %ld problems", problems);
		return 1;
	} else
		msg(LOG_INFO, "Database checks OK");
	return 0;
}


/*
 * This function removes the trust database files.
 */
void unlink_db(void)
{
	char path[64];

	snprintf(path, sizeof(path), "%s/data.mdb", data_dir);
	unlink(path);
	snprintf(path, sizeof(path), "%s/lock.mdb", data_dir);
	unlink(path);
}


/*
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
		msg(LOG_INFO, "Database migration will be performed.");

		// Then we have a version1 db since it does not track versions
		unlink_db();

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

	msg(LOG_INFO, "Initializing the database");

	// update_lock is used in update_database()
	pthread_mutex_init(&update_lock, NULL);

	if (migrate_database())
		return 1;

	if ((rc = init_db(config))) {
		msg(LOG_ERR, "Cannot open the database, init_db() (%d)", rc);
		return rc;
	}

	if ((rc = backend_init(config))) {
		msg(LOG_ERR, "Failed to load data from backend (%d)", rc);
		close_db();
		return rc;
	}

	if ((rc = backend_load())) {
		msg(LOG_ERR, "Failed to load data from backend (%d)", rc);
		close_db();
		return rc;
	}

	rc = database_empty();
	if (rc > 0) {
		if ((rc = create_database(/*with_sync*/1))) {
			msg(LOG_ERR,
			   "Failed to create database, create_database() (%d)",
			   rc);
			close_db();
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
	int do_integrity = 0, mode = READ_TEST_KEY, retry = 0, ret_val = 0;
	char *res;
	char sha_xattr[65];

	if (integrity != IN_NONE && info) {
		do_integrity = 1;
		mode = READ_DATA;
		sha_xattr[0] = 0; // Make sure we can't re-use stack value
	}

	res = lt_read_db(path, mode, error);
retry_res:
	if (!do_integrity) {
		ret_val = res ? 1 : 0;
	} else {
		unsigned int tsource;
		off_t size;
		char sha[65];

		if (res == NULL)
			return 0;

		if (sscanf(res, DATA_FORMAT, &tsource, &size, sha) != 3) {
			free(res);
			*error = 1;
			return 1;
		}

		// Need to do the compare and free res
		free(res);
		ret_val = 1;
		if (integrity == IN_SIZE) {
			// If the size doesn't match, return NULL
			if (size != info->size) {
				// Gotta retry in case its the other one
				if (retry == 0) {
					retry = 1;
					res = lt_read_db(path,
							READ_DATA_DUP, error);
					goto retry_res;
				}
				ret_val = 0;
				msg(LOG_DEBUG, "size miscompare");
			}
		} else if (integrity == IN_IMA) {
			int rc = 1;

			// read xattr only the first time
			if (retry == 0)
				rc = get_ima_hash(fd, sha_xattr);

			if (rc) {
				if (size != info->size ||
						strcmp(sha, sha_xattr)) {
					if (retry == 0) {
						retry = 1;
						res = lt_read_db(path,
							 READ_DATA_DUP, error);
						goto retry_res;
					}
					ret_val = 0;
					msg(LOG_DEBUG, "IMA hash miscompare");
				}
			} else {
				ret_val = 0;
				*error = 1;
			}
		} else if (integrity == IN_SHA256) {
			int rc = 1;
			char *hash;

			// Calculate a hash only one time
			if (retry == 0) {
				hash = get_hash_from_fd(fd);
				if (hash) {
					strncpy(sha_xattr, hash, 64);
					sha_xattr[64] = 0;
					free(hash);
				} else {
					rc = 0;
					*error = 1;
				}
			}

			if (rc) {
				if (size != info->size ||
				    strcmp(sha, sha_xattr)) {
					if (retry == 0) {
						retry = 1;
						res = lt_read_db(path,
							 READ_DATA_DUP, error);
						goto retry_res;
					}
					ret_val = 0;
					msg(LOG_DEBUG, "sha256 miscompare");
				}

			} else
				ret_val = 0;
		}
	}

	return ret_val;
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

	if (start_long_term_read_ops())
		return -1;

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
	close_db();
	pthread_mutex_destroy(&update_lock);

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
 * This function reloads updated backend db into our internal database.
 * It returns 0 on success and non-zero on error.
 */
static int update_database(conf_t *config)
{
	int rc;

	msg(LOG_INFO, "Updating database");
	msg(LOG_DEBUG, "Loading database backends");

	/*
	 * backend loading/reloading should be done in upper level
	 */
	/*
	   if ((rc = backend_load())) {
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
		msg(LOG_ERR, "Failed to create database (%d)", rc);
		close_db();
		return rc;
	}

	return 0;
}


static void *update_thread_main(void *arg)
{
	int rc;
	sigset_t sigs;
	char buff[BUFFER_SIZE];
	char err_buff[BUFFER_SIZE];
	conf_t *config = (conf_t *)arg;

#ifdef DEBUG
	msg(LOG_DEBUG, "Update thread main started");
#endif

	/* This is a worker thread. Don't handle signals. */
	sigemptyset(&sigs);
	sigaddset(&sigs, SIGTERM);
	sigaddset(&sigs, SIGHUP);
	sigaddset(&sigs, SIGINT);
	sigaddset(&sigs, SIGSEGV);
	pthread_sigmask(SIG_SETMASK, &sigs, NULL);

	if (ffd[0].fd == 0) {
		if (preconstruct_fifo(config))
			return NULL;
	}

	ffd[0].events = POLLIN;

	while (!stop) {

		rc = poll(ffd, 1, 1000);

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
				goto err_out;
			}
		} else if (rc == 0) {
#ifdef DEBUG
			msg(LOG_DEBUG, "Update poll timeout expired");
#endif
			continue;
		} else {
			if (ffd[0].revents & POLLIN) {
				ssize_t count = read(ffd[0].fd, buff,
						     BUFFER_SIZE-1);

				if (count == -1) {
					msg(LOG_ERR,
					   "Failed to read from a pipe %s (%s)",
					   fifo_path,
					   strerror_r(errno, err_buff,
						      BUFFER_SIZE));
					goto err_out;
				}

				if (count == 0) {
#ifdef DEBUG
					msg(LOG_DEBUG,
					    "Buffer contains zero bytes!");
#endif
					continue;
				} else // Manually terminate buff
					buff[count] = 0;
#ifdef DEBUG
				msg(LOG_DEBUG, "Buffer contains: \"%s\"", buff);
#endif
				int check = 1;
				for (int i = 0 ; i < count ; i++) {
					if (buff[i] != '1' && buff[i] != '\n' &&
							buff[i] != '\0') {
						check = 0;
						msg(LOG_ERR,
						"Read bad content from pipe %s",
							fifo_path);
						break;
					}
				}

				if (check) {
					msg(LOG_INFO,
	    "It looks like there was an update of the system... Syncing DB.");

					backend_close();
					backend_init(config);
					backend_load();

					if ((rc = update_database(config))) {
						msg(LOG_ERR,
						   "Cannot update a database!");
						close(ffd[0].fd);
						backend_close();
						unlink_fifo();
						exit(rc);
					} else
						msg(LOG_INFO, "Updated");

					// Conserve memory
					backend_close();
				}
			}
		}

	}

err_out:
	close(ffd[0].fd);
	unlink_fifo();

	return NULL;
}

