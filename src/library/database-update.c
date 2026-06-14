/*
 * database-update.c - trust database update controller
 * Copyright (c) 2016,2018-26 Red Hat Inc.
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
 */

/*
 * Overview
 * -------
 *
 * This file owns the daemon-side control plane for trust database updates.
 * The LMDB storage, generation publication, sizing, and lookup rules live in
 * database.c. This module keeps the operational machinery around that database:
 * the update FIFO, the background polling thread, reload request coalescing,
 * cache-flush commands, and the legacy locks used to block readers during a
 * controlled environment swap.
 *
 * The boundary is intentionally small. The controller parses external commands
 * and calls database_reload_from_backends(), database_compact_from_backends(),
 * or database_store_update_record(). It does not reach into LMDB handles or
 * generation state. Conversely, database.c calls database_update_read_lock()
 * when a decision lookup needs shared read ownership.
 *
 * RELOAD_TRUSTDB_COMMAND requests are coalesced. If a reload arrives while one
 * is active, one follow-up request stays pending so a SIGHUP that changes
 * backend configuration cannot be hidden by an earlier rebuild.
 */

#include "config.h"
#include <stdio.h>
#include <string.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <poll.h>
#include <pthread.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "database.h"
#include "database-internal.h"
#include "event.h"
#include "failure-action.h"
#include "fd-fgets.h"
#include "message.h"
#include "paths.h"
#include "policy.h"

enum {
	DB_NO_OP,
	ONE_FILE,
	RELOAD_DB,
	FLUSH_CACHE,
	RELOAD_RULES,
	COMPACT_DB,
};

#define UPDATE_BUFFER_SIZE 4096

static struct pollfd ffd[1] = { { 0, 0, 0 } };
static pthread_t update_thread;
static int update_thread_created;
static int update_lock_inited;
static int rule_lock_inited;
static pthread_rwlock_t update_lock;
static pthread_mutex_t rule_lock;
static atomic_bool reload_db = false;
static atomic_bool reload_db_active = false;

extern atomic_bool stop;
extern atomic_bool reload_rules;

static void *update_thread_main(void *arg);

/*
 * database_update_close_fifo - close the update FIFO if it is open.
 *
 * Returns nothing.
 */
static void database_update_close_fifo(void)
{
	if (ffd[0].fd > 0) {
		close(ffd[0].fd);
		ffd[0].fd = 0;
	}
}

/*
 * preconstruct_fifo - create and open the daemon update FIFO.
 * @config: daemon configuration containing the target group id.
 *
 * Returns 0 on success and 1 on failure.
 */
int preconstruct_fifo(const conf_t *config)
{
	int rc;
	char err_buff[UPDATE_BUFFER_SIZE];

	/* Keep RUN_DIR mode/owner aligned with daemon IPC expectations. */
	if (mkdir(RUN_DIR, 0770) && errno != EEXIST) {
		msg(LOG_ERR, "Failed to create a directory %s (%s)", RUN_DIR,
		    strerror_r(errno, err_buff, UPDATE_BUFFER_SIZE));
		return 1;
	} else {

		if ((chmod(RUN_DIR, 0770))) {
			msg(LOG_ERR, "Failed to fix mode of dir %s (%s)",
			    RUN_DIR, strerror_r(errno, err_buff,
						UPDATE_BUFFER_SIZE));
			return 1;
		}

		if ((chown(RUN_DIR, 0, config->gid))) {
			msg(LOG_ERR, "Failed to fix ownership of dir %s (%s)",
			    RUN_DIR, strerror_r(errno, err_buff,
						UPDATE_BUFFER_SIZE));
			return 1;
		}

		/* Make sure that there is no such file/fifo */
		unlink_fifo();
	}

	rc = mkfifo(fifo_path, 0660);

	if (rc != 0) {
		msg(LOG_ERR, "Failed to create a pipe %s (%s)", fifo_path,
		    strerror_r(errno, err_buff, UPDATE_BUFFER_SIZE));
		return 1;
	}

	if ((ffd[0].fd = open(fifo_path, O_RDWR)) == -1) {
		msg(LOG_ERR, "Failed to open a pipe %s (%s)", fifo_path,
		    strerror_r(errno, err_buff, UPDATE_BUFFER_SIZE));
		ffd[0].fd = 0;
		unlink_fifo();
		return 1;
	}

	if (config->gid != getgid()) {
		if ((fchown(ffd[0].fd, 0, config->gid))) {
			msg(LOG_ERR, "Failed to fix ownership of pipe %s (%s)",
			    fifo_path, strerror_r(errno, err_buff,
						  UPDATE_BUFFER_SIZE));
			unlink_fifo();
			close(ffd[0].fd);
			ffd[0].fd = 0;
			return 1;
		}
	}

	return 0;
}

/*
 * unlink_fifo - remove the daemon update FIFO.
 *
 * Returns nothing.
 */
void unlink_fifo(void)
{
	unlink(fifo_path);
}

/*
 * database_update_controls_init - initialize update/rule synchronization.
 *
 * Returns 0 on success or a pthread error code.
 */
int database_update_controls_init(void)
{
	int rc;

	if (!update_lock_inited) {
		rc = pthread_rwlock_init(&update_lock, NULL);
		if (rc)
			return rc;
		update_lock_inited = 1;
	}

	if (!rule_lock_inited) {
		rc = pthread_mutex_init(&rule_lock, NULL);
		if (rc)
			return rc;
		rule_lock_inited = 1;
	}

	return 0;
}

/*
 * database_update_controls_destroy - destroy update/rule synchronization.
 *
 * Returns nothing.
 */
void database_update_controls_destroy(void)
{
	if (update_lock_inited) {
		pthread_rwlock_destroy(&update_lock);
		update_lock_inited = 0;
	}

	if (rule_lock_inited) {
		pthread_mutex_destroy(&rule_lock);
		rule_lock_inited = 0;
	}
}

/*
 * database_update_thread_start - start the background update controller.
 * @config: daemon configuration passed to reload and FIFO setup paths.
 *
 * Returns 0 on success or a pthread error code.
 */
int database_update_thread_start(conf_t *config)
{
	char err_buff[UPDATE_BUFFER_SIZE];
	int rc;

	if (update_thread_created)
		return 0;

	rc = database_update_controls_init();
	if (rc)
		return rc;

	rc = pthread_create(&update_thread, NULL, update_thread_main, config);
	if (rc == 0) {
		update_thread_created = 1;
		return 0;
	}

	msg(LOG_ERR, "Failed to create update thread (%s)",
	    strerror_r(rc, err_buff, sizeof(err_buff)));
	return rc;
}

/*
 * database_update_thread_stop - join the update thread and clean the FIFO.
 *
 * Returns nothing.
 */
void database_update_thread_stop(void)
{
	if (update_thread_created) {
		pthread_join(update_thread, NULL);
		update_thread_created = 0;
	}

	database_update_close_fifo();
	unlink_fifo();
}

/*
 * lock_update_thread - take exclusive trust DB update ownership.
 *
 * Returns nothing.
 */
void lock_update_thread(void)
{
	pthread_rwlock_wrlock(&update_lock);
	//msg(LOG_DEBUG, "lock_update_thread()");
}

/*
 * unlock_update_thread - release exclusive trust DB update ownership.
 *
 * Returns nothing.
 */
void unlock_update_thread(void)
{
	pthread_rwlock_unlock(&update_lock);
	//msg(LOG_DEBUG, "unlock_update_thread()");
}

/*
 * database_update_read_lock - take shared trust DB read ownership.
 *
 * Returns nothing.
 */
void database_update_read_lock(void)
{
	pthread_rwlock_rdlock(&update_lock);
}

/*
 * database_update_read_unlock - release shared trust DB read ownership.
 *
 * Returns nothing.
 */
void database_update_read_unlock(void)
{
	pthread_rwlock_unlock(&update_lock);
}

/*
 * lock_rule - take the rule reload mutex when it is available.
 *
 * Returns nothing.
 */
void lock_rule(void)
{
	/*
	 * Rules load before init_database() creates this mutex, and the final
	 * shutdown report can run after close_database() destroys it. Those
	 * phases are single-threaded with no rule reload race to serialize.
	 */
	if (!rule_lock_inited)
		return;
	pthread_mutex_lock(&rule_lock);
	//msg(LOG_DEBUG, "lock_rule()");
}

/*
 * unlock_rule - release the rule reload mutex when it is available.
 *
 * Returns nothing.
 */
void unlock_rule(void)
{
	if (!rule_lock_inited)
		return;
	pthread_mutex_unlock(&rule_lock);
	//msg(LOG_DEBUG, "unlock_rule()");
}

/*
 * handle_update_record - process one path update from the FIFO.
 * @buffer: Raw line containing path, file size, and SHA256 hash.
 *
 * Returns 0 after successfully storing the record, 1 when processing should
 * stop due to malformed data or a shutdown request.
 */
static int handle_update_record(const char *buffer)
{
	char path[2048 + 1];
	char hash[64 + 1];
	size_t size;
	int rc;
	int res;

	if (stop)
		return 1;

	// validating input
	res = sscanf(buffer, "%2048s %zu %64s", path, &size, hash);
	msg(LOG_DEBUG, "update_thread: Parsing input buffer: %s", buffer);
	msg(LOG_DEBUG,
	    "update_thread: Parsing input words(expected 3): %d",
	    res);

	if (res != 3) {
		msg(LOG_INFO, "Corrupted data read, ignoring...");
		return 1;
	}

	msg(LOG_DEBUG, "update_thread: Saving %s", path);
	rc = database_store_update_record(path, size, hash);
	return rc ? 1 : 0;
}

/*
 * request_reload_trust_database - queue a trust DB reload if one is needed.
 * @source: short log label for the caller requesting reload.
 *
 * A trust DB reload rebuilds the database from the current backend snapshots.
 * If another request is already pending, the later request does not add more
 * ordering information: both reloads would consume the same current backend
 * state by the time the update thread can run them. Requests received during
 * an active reload are left pending because SIGHUP can change the configured
 * backend list after the active rebuild has already selected its snapshots.
 * This still coalesces many in-flight requests into one follow-up rebuild.
 *
 * Returns 1 when a new request was queued, 0 when it was coalesced.
 */
static int request_reload_trust_database(const char *source)
{
	if (atomic_exchange_explicit(&reload_db, true, memory_order_acq_rel)) {
		msg(LOG_INFO,
		    "Dropping trust database reload from %s: reload already pending",
		    source);
		return 0;
	}

	if (atomic_load_explicit(&reload_db_active, memory_order_acquire))
		msg(LOG_INFO,
		    "Queued trust database reload from %s: reload already active",
		    source);

	return 1;
}

/*
 * set_reload_trust_database - queue a SIGHUP-triggered trust DB reload.
 *
 * Returns nothing.
 */
void set_reload_trust_database(void)
{
	request_reload_trust_database("SIGHUP");
}

/*
 * begin_trust_database_reload - mark a trust DB reload active.
 * @source: short log label for the caller starting reload.
 *
 * Returns 1 when the caller may run the reload, 0 when another reload is
 * already active.
 */
static int begin_trust_database_reload(const char *source)
{
	bool expected = false;

	/*
	 * Consume the request before publishing the active marker. A SIGHUP that
	 * arrives after this point must remain pending for a follow-up reload;
	 * clearing reload_db after reload_db_active becomes true could drop that
	 * config-changing request.
	 */
	atomic_store_explicit(&reload_db, false, memory_order_release);

	if (!atomic_compare_exchange_strong_explicit(&reload_db_active,
					&expected, true,
					memory_order_acq_rel,
					memory_order_acquire)) {
		atomic_store_explicit(&reload_db, true, memory_order_release);
		msg(LOG_INFO,
		    "Deferring trust database reload from %s: reload already active",
		    source);
		return 0;
	}

	return 1;
}

/*
 * finish_trust_database_reload - clear the active trust DB reload marker.
 *
 * Returns nothing.
 */
static void finish_trust_database_reload(void)
{
	atomic_store_explicit(&reload_db_active, false, memory_order_release);
}

/*
 * run_trust_database_reload - run a coalesced trust DB reload request.
 * @config: active daemon configuration.
 * @source: short log label for the request source.
 *
 * Returns 1 when a reload ran, 0 when the request was coalesced with another
 * active reload.
 */
static int run_trust_database_reload(conf_t *config, const char *source)
{
	if (!begin_trust_database_reload(source))
		return 0;

	database_reload_from_backends(config);
	finish_trust_database_reload();
	return 1;
}

/*
 * reload_rules_from_file - perform a requested rule reload.
 * @config: daemon configuration used for parsing syslog fields.
 *
 * Returns 0 on success and non-zero on failure.
 */
static int reload_rules_from_file(conf_t *config)
{
	int rc;

	if (load_rule_file()) {
		failure_action_record(FAILURE_REASON_RULE_RELOAD_FAILURE);
		msg(LOG_ERR,
		    "Rule reload aborted: unable to open rules file (%s)",
		    strerror(errno));
		return 1;
	}

	/*
	 * Rules now publish as immutable snapshots. Parsing can be slow for
	 * large macro/set based policies, so do not hold the legacy rule mutex
	 * here; decisions keep using the old snapshot until publish succeeds.
	 */
	rc = do_reload_rules(config);
	if (rc)
		msg(LOG_ERR, "Rule reload failed; previous policy preserved");
	return rc;
}

/*
 * update_thread_main - poll the update FIFO and dispatch daemon commands.
 * @arg: active daemon configuration.
 *
 * Returns NULL when the thread exits.
 */
static void *update_thread_main(void *arg)
{
	int rc;
	int flags;
	sigset_t sigs;
	char buff[UPDATE_BUFFER_SIZE];
	char err_buff[UPDATE_BUFFER_SIZE];
	conf_t *config = (conf_t *)arg;
	int do_operation = DB_NO_OP;

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

	/*
	 * fd_fgets_r() must not block if poll readiness is consumed or only
	 * a partial line is available.
	 */
	flags = fcntl(ffd[0].fd, F_GETFL);
	if (flags == -1) {
		msg(LOG_ERR, "Failed to read pipe flags (%s)",
		    strerror_r(errno, err_buff, UPDATE_BUFFER_SIZE));
		goto finalize;
	}
	if (fcntl(ffd[0].fd, F_SETFL, flags | O_NONBLOCK) == -1) {
		msg(LOG_ERR, "Failed to set non-blocking pipe mode (%s)",
		    strerror_r(errno, err_buff, UPDATE_BUFFER_SIZE));
		goto finalize;
	}
	ffd[0].events = POLLIN;

	while (!stop) {
		int trust_reload_done_this_cycle = 0;

		/*
		 * The FIFO connected at ffd[0] carries update commands from
		 * fapolicy-cli and backend helper processes. Commands may be
		 * the single-character control values defined in database.h
		 * or full path entries emitted by the backend notifier when a
		 * package manager changes a file.
		 */
		rc = poll(ffd, 1, 1000);

		if (stop)
			break;

		if (reload_rules) {
			reload_rules = false;
			reload_rules_from_file(config);
		}
		// got SIGHUP
		if (atomic_load_explicit(&reload_db, memory_order_acquire))
			trust_reload_done_this_cycle =
				run_trust_database_reload(config,
							  "pending request");

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
				    strerror_r(errno, err_buff,
					       UPDATE_BUFFER_SIZE));
				goto finalize;
			}
		} else if (rc == 0) {
#ifdef DEBUG
			msg(LOG_DEBUG, "Update poll timeout expired");
#endif
			continue;
		} else {
			if (ffd[0].revents & POLLIN) {
				fd_fgets_state_t *st = fd_fgets_init();

				if (st == NULL) {
					msg(LOG_ERR,
				  "Failed to initialize buffered FIFO reader");
					break;
				}
				do {
					int res;

					if (stop)
						break;
					res = fd_fgets_r(st, buff,
						sizeof(buff), ffd[0].fd);

					// nothing to read
					if (res == -1)
						break;
					else if (res > 0) {
						char *end = strchr(buff, '\n');
						int count;

						if (end == NULL) {
							msg(LOG_ERR, "Too long line?");
							continue;
						}

						count = end - buff;
						*end = '\0';

						for (int i = 0; i < count; i++) {
							/*
							 * Identify the requested action by scanning
							 * the buffer. Control characters map directly
							 * to values above while a leading slash
							 * indicates a file path update.
							 */
							if (stop)
								break;
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

							if (buff[i] == COMPACT_TRUSTDB_COMMAND) {
								do_operation = COMPACT_DB;
								break;
							}

							if (isspace((unsigned char)buff[i]))
								continue;

							msg(LOG_ERR,
							    "Cannot handle data \"%s\" from pipe",
							    buff);
							break;
						}

						*end = '\n';

						if (stop)
							break;

						// got "1" -> reload db
						if (do_operation == RELOAD_DB) {
							/*
							 * A RELOAD_TRUSTDB_COMMAND triggers a
							 * complete rebuild from all configured
							 * backends.
							 */
							do_operation = DB_NO_OP;
							if (trust_reload_done_this_cycle) {
								msg(LOG_INFO,
								    "Dropping trust database reload from FIFO: "
								    "reload already handled in this update cycle");
							} else {
								trust_reload_done_this_cycle =
									run_trust_database_reload(config,
												  "FIFO");
							}
						} else if (do_operation == RELOAD_RULES) {
							/*
							 * The rules command instructs the daemon
							 * to re-parse policy files.
							 */
							do_operation = DB_NO_OP;
							reload_rules_from_file(config);
						} else if (do_operation == COMPACT_DB) {
							/*
							 * Explicit maintenance command: build a
							 * replacement LMDB environment from backend
							 * snapshots and swap it after validation.
							 */
							do_operation = DB_NO_OP;
							database_compact_from_backends(config);

							// got "2" -> flush cache
						} else if (do_operation == FLUSH_CACHE) {
							/*
							 * Cache flushes originate from helper
							 * tools needing clients to drop cached
							 * trust decisions.
							 */
							do_operation = DB_NO_OP;
							atomic_store_explicit(&needs_flush, true,
									      memory_order_release);
						} else if (do_operation == ONE_FILE) {
							/*
							 * Backend helpers send path/size/hash
							 * tuples for individual files that
							 * changed on disk.
							 */
							do_operation = DB_NO_OP;
							if (handle_update_record(buff))
								continue;
						}
					}
				} while (!fd_fgets_eof_r(st) && !stop);
				fd_fgets_destroy(st);
			}
		}
	}

finalize:
	database_update_close_fifo();
	unlink_fifo();

	return NULL;
}
