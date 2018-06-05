#include "config.h"
#include <stdio.h>
#include <lmdb.h>
#include <string.h>
#include <stdlib.h>
#include <rpm/rpmlib.h>
#include <rpm/rpmts.h>
#include <rpm/rpmmacro.h>
#include <rpm/rpmlog.h>
#include <rpm/rpmdb.h>
#include "database.h"
#include "message.h"


static MDB_env *env;
static MDB_dbi dbi;
static int dbi_init = 0;
const char *data_dir = "/var/lib/fapolicyd";
const char *db = "trust.db";

#define READ_DATA	0
#define READ_TEST_KEY	1
#define MEGABYTE	1024*1024
#define DATA_FORMAT "%i %lu %s"


static int init_db(struct daemon_conf *config)
{
	if (mdb_env_create(&env))
		return 1;
	if (mdb_env_set_maxdbs(env, 2))
		return 1;
	if (mdb_env_set_mapsize(env, config->db_max_size*MEGABYTE))
		return 1;
	if (mdb_env_set_maxreaders(env, 4))
		return 1;
	if (mdb_env_open(env, data_dir, MDB_MAPASYNC|MDB_NOSYNC , 0664))
		return 1;
	return 0;
}

static void close_db(void)
{
	mdb_close(env, dbi);
	mdb_env_close(env);
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
		if ((rc = mdb_open(txn, db, MDB_CREATE, &dbi))) {
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
 * path - key
 * status, file size, sha256 hash - data
 * status means if data is confirmed: unknown, yes, no
*/
static int write_db(const char *index, const char *data)
{
	MDB_val key, value;
	MDB_txn *txn;
	int rc;

	if (mdb_txn_begin(env, NULL, 0, &txn))
		return 1;

	if (open_dbi(txn)) {
		abort_transaction(txn);
		return 2;
	}

	key.mv_data = (void *)index;
	key.mv_size = strlen(index);
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

	return 0;
}

/*
 * The idea with this set of code is that we can set up ops once
 * and perform many read operations. This reduces the need to setup
 * a read lock every time and initial a whole transaction.
 */
static MDB_txn *lt_txn = NULL;
static MDB_cursor *lt_cursor = NULL;
static int lt_txn_uses = 0;
static int start_long_term_read_ops(void)
{
	int rc;

	if (lt_txn == NULL) {
		lt_txn_uses = 0;
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
 * Periodically close the transaction. Next time we start a read operation
 * everything will get re-initialized.
 */
static void long_term_read_abort(void)
{
	if (++lt_txn_uses > 1000) {
		// Closes dbi
		abort_transaction(lt_txn);
		lt_txn = NULL;
		lt_txn_uses = 0;
		mdb_cursor_close(lt_cursor);
		lt_cursor = NULL;
	}
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

/*
 * This is the long term read operation. It takes a path as input and
 * search for the data. It returns NULL on error or if no data found.
 * The returned string must be freed by the caller.
 */
static char *lt_read_db(const char *index, int only_check_key)
{
	int rc;
	char *data;
	MDB_val key, value;

	if (start_long_term_read_ops())
		return NULL;

	key.mv_data = (void *)index;
	key.mv_size = strlen(index);
	value.mv_data = NULL;
	value.mv_size = 0;

	if ((rc = mdb_cursor_get(lt_cursor, &key, &value, MDB_SET_KEY))) {
		if (rc == MDB_NOTFOUND)
			return NULL;
		msg(LOG_ERR, "cursor_get:%s", mdb_strerror(rc));
		return NULL;
	}

	// Failure means NULL was returned. Need to return a non-null value
	// for success. Using the db name since its non-NULL.
	// A next step might be to check the status field to see that its
	// trusted.
	if (only_check_key == READ_TEST_KEY)
		return (char *)db;

	if ((data = malloc(value.mv_size+1))) {
		memcpy(data, value.mv_data, value.mv_size);
		data[value.mv_size] = 0;
	}

	long_term_read_abort();

	return data;
}

/*
 * This function takes a path as input and looks it up. If found it
 * will delete the entry.
 */
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
}

static int database_empty(void)
{
	MDB_stat stat;
	if (mdb_env_stat(env, &stat))
		return 1;
	if (stat.ms_entries == 0)
		return 1;
	return 0;
}


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

static const char *get_file_name_rpm(void)
{
	return strdup(rpmfiFN(fi));
}

static off_t get_file_size_rpm(void)
{
	return rpmfiFSize(fi);
}

static char *get_sha256_rpm(void)
{
	return rpmfiFDigestHex(fi, NULL);
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

static int create_database(void)
{
	if (init_rpm()) {
		msg(LOG_ERR, "Cannot open the rpm database");
		return 1;
	}

	// Loop across the rpm database
	while (get_next_package_rpm()) {
		// Loop across the packages
		while (get_next_file_rpm()) {
			// Get specific file information
			const char *file_name = get_file_name_rpm();
			off_t sz = get_file_size_rpm();
			const char *sha = get_sha256_rpm();
			char *data;
			int verified = 0, rc;
			if (asprintf(&data, DATA_FORMAT,
						verified, sz, sha) == -1) {
				rc = 1;
				goto out;
			}

			if ((rc = write_db(file_name, data)))
				msg(LOG_ERR, "Error (%d) writing %s",
						rc, file_name);
out:
			free((void *)file_name);
			free((void *)sha);
			free(data);
			if (rc) {
				mdb_env_sync(env, 1);
				close_rpm();
				return 1;
			}
		}
	}

	// Flush everything to disk
	mdb_env_sync(env, 1);
	close_rpm();
	return 0;
}

/*
 * This function will compare the rpm database against our copy
 * of the database. It returns a 1 if they do not match.
 */
static int check_database_copy(void)
{
	int problems = 0;
	if (init_rpm()) {
		msg(LOG_ERR, "Cannot open the rpm database");
		return 1;
	}

	start_long_term_read_ops();

	// Loop across the rpm database
	while (get_next_package_rpm()) {
		// Loop across the packages
		while (get_next_file_rpm()) {
			// Get specific file information
			const char *file_name = get_file_name_rpm();
			off_t sz = get_file_size_rpm();
			const char *sha = get_sha256_rpm();
			char *data1, *data2;
			int verified = 0;
			if (asprintf(&data1, DATA_FORMAT,
						verified, sz, sha) == -1) {
				msg(LOG_WARNING, "asprintf error");
				data2 = NULL;
				goto out2;
			}

			data2 = lt_read_db(file_name, READ_DATA);
			if (data2) {
				if (strcmp(data1, data2)) {
					// FIXME: can we correct?
					msg(LOG_WARNING,
					    "Data miscompare for %s:%s vs %s",
						file_name, data1, data2);
					problems++;
				}
			} else	{ // FIXME: should we add it? If we need to
				  // fix this, then we have to switch to
				  // write mode, do the update, and come back
				  // to read mode.
				msg(LOG_WARNING, "%s is not in database",
						file_name);
				problems++;
			}

out2:
			free((void *)file_name);
			free((void *)sha);
			free(data1);
			free(data2);
		}
	}

	// Flush everything to disk - only if fixed
	// mdb_env_sync(env, 1);
	close_rpm();
	end_long_term_read_ops();
	if (problems)
		msg(LOG_WARNING, "Found %d problems", problems);
	else
		msg(LOG_INFO, "Database checks OK");
	return 0;
}

/*
 * This function compares the database against the files on disk. This
 * way we can tell if something has changed.
 */
static int verify_database_entries(void)
{
	return 0;
}

/*
 * This function is responsible for getting the database ready to use.
 * It will first check to see if a database is populated. If so, then
 * it will verify it against the rpm database just in case something
 * has changed. If the database does not exist, then it will create one.
 */
int init_database(struct daemon_conf *config)
{
	if (init_db(config)) {
		msg(LOG_ERR, "Cannot open the database");
		return 1;
	}

	if (database_empty()) {
		if (create_database()) {
			msg(LOG_ERR, "Failed to create database");
			close_db();
			return 1;
		}
	} else
		return check_database_copy();

	return 0;
}

// Returns a 1 if trusted and 0 if not
int check_trust_database(const char *path)
{
	int rc = 0;
	start_long_term_read_ops();

	if (lt_read_db(path, READ_TEST_KEY))
		rc = 1;

	end_long_term_read_ops();
	return rc;
}

void close_database(void)
{
	close_db();
}

