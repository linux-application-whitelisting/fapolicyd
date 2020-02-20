/*
 * database.c - Trust database
 * Copyright (c) 2016,2018-20 Red Hat Inc., Durham, North Carolina.
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
#include "event.h"
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
static const char *data_dir = "/var/lib/fapolicyd";
static const char *db = "trust.db";
static int lib_symlink=0, lib64_symlink=0, bin_symlink=0, sbin_symlink=0;
static struct pollfd ffd[1] =  { {0, 0, 0} };
static const char* fifo_path = "/run/fapolicyd/fapolicyd.fifo";

static pthread_t update_thread;
static pthread_mutex_t update_lock;

// Local functions
static void *update_thread_main(void *arg);
static int update_database(conf_t *config);

// External variables
extern volatile atomic_bool stop;


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

int preconstruct_fifo(const conf_t *config)
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

	lib_symlink = is_link("/lib");
	lib64_symlink = is_link("/lib64");
	bin_symlink = is_link("/bin");
	sbin_symlink = is_link("/sbin");

	backend_init(config);

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
							(100*pages)/max_pages);

	// Now close down
	backend_close();
	mdb_close(env, dbi);
	mdb_env_close(env);
}

void database_report(FILE *f)
{
	fprintf(f, "Database max pages: %lu\n", max_pages);
	fprintf(f, "Database pages in use: %lu (%lu%%)\n\n", pages,
							(100*pages)/max_pages);
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
 * Convert path to a hash value. Used when the path exceeds the LMDB key limit(511).
 * Note: Returned value must be deallocated.
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

/*
 * This is the long term read operation. It takes a path as input and
 * search for the data. It returns NULL on error or if no data found.
 * The returned string must be freed by the caller.
 */
static char *lt_read_db(const char *index, int only_check_key)
{
	int rc;
	char *data, *hash = NULL;
	MDB_val key, value;
	size_t len;

	if (start_long_term_read_ops())
		return NULL;

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

	// Read the value pointed to by key
	if ((rc = mdb_cursor_get(lt_cursor, &key, &value, MDB_SET))) {
		free(hash);
		if (rc == MDB_NOTFOUND)
			return NULL;
		msg(LOG_ERR, "cursor_get:%s", mdb_strerror(rc));
		return NULL;
	}

	// Some packages have the same file and thus duplicate entries
	// If one hash miscompares, we can try again to see if there's a dup
	if (only_check_key == READ_DATA_DUP) {
		size_t nleaves;
		mdb_cursor_count(lt_cursor, &nleaves);
		if (nleaves <= 1) {
			free(hash);
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

static int database_empty(void)
{
	MDB_stat status;
	if (mdb_env_stat(env, &status))
		return 1;
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

	for (backend_entry* be = backend_get_first() ; be != NULL ; be = be->next ) {
		msg(LOG_INFO, "Loading data from %s backend", be->backend->name);

		list_item_t * item = list_get_first(&be->backend->list);
		for (; item != NULL; item = item->next) {
			if ((rc = write_db(item->index, item->data)))
				msg(LOG_ERR, "Error (%d) writing key=\"%s\" data=\"%s\"",
				    rc, (const char*)item->index, (const char*)item->data);
		}
	}
	// Flush everything to disk
	if (with_sync) mdb_env_sync(env, 1);
	return rc;
}

/*
 * This function will compare the backend database against our copy
 * of the database. It returns a 1 if they do not match.
 */
static int check_database_copy(void)
{
	msg(LOG_INFO, "Checking database");
	long problems = 0;

	start_long_term_read_ops();
	for (backend_entry* be = backend_get_first() ; be != NULL ; be = be->next ) {
		msg(LOG_INFO, "Importing data from %s backend", be->backend->name);

		list_item_t * item = list_get_first(&be->backend->list);
		for (; item != NULL; item = item->next) {

			char * data = lt_read_db(item->index, READ_DATA);
			if (data) {
				if (strcmp(item->data, data)) {
					// Let's retry its duplicate
					data = lt_read_db(item->index,
								READ_DATA_DUP);
					// If no dup or miscompare, problems
					if (!data || strcmp(item->data, data)) {
						msg(LOG_DEBUG,
					      "Data miscompare for %s:%s vs %s",
						(const char *)item->index,
						(const char *)item->data, data);
						problems++;
					}
				}
			} else {
				msg(LOG_WARNING, "%s is not in database",
				    (const char *)item->index);
				problems++;
			}

			free(data);
		}
	}

	end_long_term_read_ops();

	if (problems) {
		msg(LOG_WARNING, "Found %ld problems", problems);
		return 1;
	} else
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
		char path[64];
		msg(LOG_INFO, "Database migration will be perfomed.");

		// Then we have a version1 db since it does not track versions
		snprintf(path, sizeof(path), "%s/data.mdb", data_dir);
		unlink(path);
		snprintf(path, sizeof(path), "%s/lock.mdb", data_dir);
		unlink(path);

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
		read(fd, vpath, 2);
		close(fd);
		if (vpath[0] == '2')
			return 0;
	}

	return 1;
}

/*
 * This function is responsible for getting the database ready to use.
 * It will first check to see if a database is populated. If so, then
 * it will verify it against the backend database just in case something
 * has changed. If the database does not exist, then it will create one.
 */
int init_database(conf_t *config)
{
	int rc;

	msg(LOG_INFO, "Initializing the database");

	migrate_database();

	if ((rc = init_db(config))) {
		msg(LOG_ERR, "Cannot open the database, init_db() (%d)", rc);
		return rc;
	}

	if ((rc = backend_load())) {
		msg(LOG_ERR, "Failed to load data from backend (%d)", rc);
		close_db();
		return rc;
	}

	if (database_empty()) {
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
 * This function reloads updated backend db into our internal database
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
	conf_t *config = (conf_t *)arg;

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

					backend_close();
					backend_init(config);
					backend_load();

					if ((rc = update_database(config))) {
						msg(LOG_ERR, "Cannot update a database!");
						close(ffd[0].fd);
						backend_close();
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
