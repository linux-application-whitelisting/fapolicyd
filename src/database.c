/*
 * database.c - Trust database
 * Copyright (c) 2016,2018-19 Red Hat Inc., Durham, North Carolina.
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
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <rpm/rpmlib.h>
#include <rpm/rpmts.h>
#include <rpm/rpmmacro.h>
#include <rpm/rpmlog.h>
#include <rpm/rpmdb.h>

#include "database.h"
#include "message.h"
#include "event.h"
#include "temporary_db.h"

#define BUFFER_SIZE 1024

static MDB_env *env;
static MDB_dbi dbi;
static int dbi_init = 0;
const char *data_dir = "/var/lib/fapolicyd";
const char *db = "trust.db";
static int lib_symlink=0, lib64_symlink=0, bin_symlink=0, sbin_symlink=0;
static struct pollfd ffd[1] =  { {0, 0, 0} };

// External variables
extern volatile atomic_bool stop;

static const char* fifo_path = "/run/fapolicyd/fapolicyd.fifo";


static pthread_t update_thread;
static pthread_mutex_t update_lock;

#define READ_DATA	0
#define READ_TEST_KEY	1
#define MEGABYTE	1024*1024
#define DATA_FORMAT "%i %lu %s"

static void *update_thread_main(void *arg);

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

int preconstruct_fifo(struct daemon_conf *config)
{
	int rc;
	char err_buff[BUFFER_SIZE];

	/* Make sure that there is no such file/fifo */
	unlink(fifo_path);

	rc = mkfifo(fifo_path, 0660);

	if (rc != 0) {
	msg(LOG_ERR, "Failed to create a pipe %s (%s)", fifo_path,
			strerror_r(errno, err_buff, BUFFER_SIZE));
		return 1;
	}

	if ((ffd[0].fd = open(fifo_path, O_RDWR)) == -1) {
		msg(LOG_ERR, "Failed to open a pipe %s (%s)", fifo_path,
			 strerror_r(errno, err_buff, BUFFER_SIZE));
		unlink(fifo_path);
		return 1;
	}

	if (config->gid != getgid()) {
		if ((fchown(ffd[0].fd, 0, config->gid))) {
			msg(LOG_ERR, "Failed to fix ownership of pipe %s (%s)",
				fifo_path, strerror_r(errno, err_buff,
				BUFFER_SIZE));
			unlink(fifo_path);
			close(ffd[0].fd);
			return 1;
		}
	}

	return 0;
}

static int init_db(struct daemon_conf *config)
{
	if (mdb_env_create(&env))
		return 1;

	if (mdb_env_set_maxdbs(env, 2))
		return 2;

	if (mdb_env_set_mapsize(env, config->db_max_size*MEGABYTE))
		return 3;

	if (mdb_env_set_maxreaders(env, 4))
		return 4;

	int rc = mdb_env_open(env, data_dir, MDB_MAPASYNC|MDB_NOSYNC , 0660);
	if (rc)
		return 5;

	lib_symlink = is_link("/lib");
	lib64_symlink = is_link("/lib64");
	bin_symlink = is_link("/bin");
	sbin_symlink = is_link("/sbin");

	init_db_list();
	return 0;
}

static void close_db(void)
{
	mdb_close(env, dbi);
	mdb_env_close(env);

	empty_db_list();
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

static int is_dir_rpm(void)
{
	mode_t mode = rpmfiFMode(fi);
	if (S_ISDIR(mode))
		return 1;
	return 0;
}

static int is_doc_rpm(void)
{
	if (rpmfiFFlags(fi) & RPMFILE_DOC)
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

static int load_rpmdb_into_memory()
{
	msg(LOG_INFO, "Reading RPMDB into memory");
	int rc = 0;
	if ((rc = init_rpm())) {
		msg(LOG_ERR, "init_rpm() failed (%d)", rc);
		return rc;
	}

	// Loop across the rpm database
	while (get_next_package_rpm()) {
		// Loop across the packages
		while (get_next_file_rpm()) {
			// We do not want directories in the database
			// Multiple packages can own the same directory
			// and that causes problems in the size info.
			if (is_dir_rpm())
				continue;

			// We do not want any documentation in the database
			if (is_doc_rpm())
				continue;

			// Get specific file information
			const char *file_name = get_file_name_rpm();
			off_t sz = get_file_size_rpm();
			const char *sha = get_sha256_rpm();
			char *data;
			int verified = 0;
			if (asprintf(&data, DATA_FORMAT,
						verified, sz, sha) == -1) {
				data = NULL;
			}

			if (data) append_db_list(file_name, data);
			else {
				free((void*)file_name);
			}

			free((void *)sha);
		}
	}

	close_rpm();
	return 0;
}

static int create_database(int with_sync)
{
	msg(LOG_INFO, "Creating database");
	int rc = 0;

	db_item_t * item = get_first_from_db_list();

	for (; item != NULL; item = item->next) {

		if ((rc = write_db(item->index, item->data)))
			msg(LOG_ERR, "Error (%d) writing %s",
					rc, item->index);
	}

	// Flush everything to disk
	if (with_sync) mdb_env_sync(env, 1);
	empty_db_list();
	return rc;
}

/*
 * This function will compare the rpm database against our copy
 * of the database. It returns a 1 if they do not match.
 */
static int check_database_copy(void)
{
	int problems = 0;
	int rc = 0;
	msg(LOG_INFO, "Checking database");
	if ((rc = init_rpm())) {
		msg(LOG_ERR, "Cannot open the rpm database, rpm_init() (%d)", rc);
		return rc;
	}

	start_long_term_read_ops();

	// Loop across the rpm database - breakout when problem detected
	while (!problems && get_next_package_rpm()) {
		// Loop across the packages
		while (!problems && get_next_file_rpm()) {
			// Directories are not being kept, skip them.
			if (is_dir_rpm())
				continue;

			// Documentation is not being kept, skip them
			if (is_doc_rpm())
				continue;

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
	if (problems) {
		msg(LOG_WARNING, "Found %d problems", problems);
		return 1;
	}
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
	int rc = 0;

	msg(LOG_INFO, "Initializing the database");
	if ((rc = init_db(config))) {
		msg(LOG_ERR, "Cannot open the database, init_db() (%d)", rc);
		return rc;
	}

	if (database_empty()) {
		if ((rc = load_rpmdb_into_memory())) {
			msg(LOG_ERR, "Failed to load rpm database (%d)", rc);
			close_db();
			return rc;
		}

		if ((rc = create_database(/*with_sync*/1))) {
			msg(LOG_ERR, "Failed to create database, create_database() (%d)", rc);
			close_db();
			return rc;
		}
	} else {
		// check if our internal database is synced
		if (check_database_copy()) {
			update_database(config);
		}
	}


	pthread_mutex_init(&update_lock, NULL);
	pthread_create(&update_thread, NULL, update_thread_main, config);

	return rc;
}

// Returns a 1 if trusted and 0 if not
int check_trust_database(const char *path)
{
	int rc = 0;
	start_long_term_read_ops();

	if (lt_read_db(path, READ_TEST_KEY))
		rc = 1;
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
				// We h
				if (lt_read_db(&path[4], READ_TEST_KEY))
					rc = 1;
			}
		}
	}

	end_long_term_read_ops();
	return rc;
}

void close_database(void)
{
	close_db();
	pthread_join(update_thread, NULL);
	pthread_mutex_destroy(&update_lock);
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
 * This function reloads updated rpmdb into our internal database
 */

int update_database(struct daemon_conf *config)
{
	int rc = 0;
	msg(LOG_INFO, "Updating database");

	msg(LOG_DEBUG, "Loading RPM database");
	if ((rc = load_rpmdb_into_memory())) {
		msg(LOG_ERR, "Cannot open the rpm database (%d)", rc);
		return rc;
	}

	lock_update_thread();

	if ((rc = delete_all_entries_db())) {
		msg(LOG_ERR, "Cannot delete database (%d)", rc);
		unlock_update_thread();
		return rc;
	}

	rc = create_database(/*with_sync*/0);
	flush_cache(config);

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
	struct daemon_conf *config = (struct daemon_conf *)arg;

#ifdef DEBUG
	msg(LOG_DEBUG, "Update thread main started");
#endif

	/* This is a worker thread. Don't handle signals. */
	sigemptyset(&sigs);
	sigaddset(&sigs, SIGTERM);
	sigaddset(&sigs, SIGHUP);
	sigaddset(&sigs, SIGINT);
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
				msg(LOG_ERR, "Update poll error (%s)", strerror_r(errno, err_buff, BUFFER_SIZE));
				goto err_out;
			}
		} else if (rc == 0) {
#ifdef DEBUG
			msg(LOG_DEBUG, "Update poll timeout expired");
#endif
			continue;
		} else {
			if (ffd[0].revents & POLLIN) {
				memset(buff, 0, BUFFER_SIZE);
				ssize_t count = read(ffd[0].fd, buff, BUFFER_SIZE);

				if (count == -1) {
					msg(LOG_ERR, "Failed to read from a pipe %s (%s)", fifo_path, strerror_r(errno, err_buff, BUFFER_SIZE));
					goto err_out;
				}

				if (count == 0) {
#ifdef DEBUG
                                        msg(LOG_DEBUG, "Buffer contains zero bytes!");
#endif
					continue;
				}
#ifdef DEBUG
				msg(LOG_DEBUG, "Buffer contains: \"%s\"", buff);
#endif
				int check = 1;
				for (int i = 0 ; i < count ; i++) {
					if (buff[i] != '1' && buff[i] != '\n' && buff[i] != '\0') {
						check = 0;
						msg(LOG_ERR, "Read bad content from pipe %s", fifo_path);
						break;
					}
				}

				if (check) {
					msg(LOG_INFO, "It looks like there was an update of the system... Syncing DB.");

					if ((rc = update_database(config))) {
						msg(LOG_ERR, "Cannot update a database!");
						close(ffd[0].fd);
						unlink(fifo_path);
						exit(rc);
					} else {
						msg(LOG_INFO, "Updated");
					}
				}
			}
		}

	}

err_out:
	close(ffd[0].fd);
	unlink(fifo_path);

	return NULL;
}
