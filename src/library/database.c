/*
 * database.c - Trust database
 * Copyright (c) 2016,2018-24 Red Hat Inc.
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
#include <limits.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <openssl/sha.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <ctype.h>	/* isspace() */

#include "database.h"
#include "decision-config.h"
#include "decision-timing.h"
#include "failure-action.h"
#include "message.h"
#include "file.h"
#include "fd-fgets.h"
#include "string-util.h"
#include "fapolicyd-backend.h"
#include "backend-manager.h"
#include "gcc-attributes.h"
#include "paths.h"
#include "policy.h"

// Local defines
enum { READ_DATA, READ_TEST_KEY, READ_DATA_DUP };
typedef enum { DB_NO_OP, ONE_FILE, RELOAD_DB, FLUSH_CACHE, RELOAD_RULES } db_ops_t;
enum autosize_plan_mode {
	AUTOSIZE_STARTUP_INSPECTION,
	AUTOSIZE_LIVE_INSPECTION,
	AUTOSIZE_RELOAD_PREFLIGHT,
};
#define BUFFER_SIZE 4096
#define MEGABYTE    (1024*1024)
#define MAX_DELIMS  3	// Trustdb has 4 fields - therefore 3 delimiters
#define DEFAULT_DB_MAX_SIZE_MB 100
#define WRITE_DB_MAP_FULL 6
#define UPDATE_DB_PRESERVED 7
#define TRUST_DB_ACTIVE_TARGET_PERCENT 75
#define TRUST_DB_RELOAD_HIGHWATER_PERCENT 85
#define TRUST_DB_SHRINK_TRIGGER_PERCENT 65
#define TRUST_DB_SHRINK_HYSTERESIS_PERCENT 90
#define TRUST_DB_RELOAD_WORK_FACTOR 2
#define TRUST_DB_REBUILD_TXN_RECORDS 4096
/*
 * The decision worker configuration is added later in the worker-pool
 * roadmap. Size LMDB readers now for that planned cap plus maintenance users
 * so read-side concurrency does not immediately trip MDB_READERS_FULL.
 */
#define TRUST_DB_DECISION_READER_CAP 32
#define TRUST_DB_MAINTENANCE_READERS 8

// Local variables
static MDB_env *env;
static MDB_dbi dbi;
static int dbi_init = 0;
static unsigned int db_max_readers;
static unsigned MDB_maxkeysize;
static const char *data_dir = DB_DIR;
static const char *db = DB_NAME;
static int update_lock_inited;
static int rule_lock_inited;
static int lib_symlink=0, lib64_symlink=0, bin_symlink=0, sbin_symlink=0;
static struct pollfd ffd[1] =  { {0, 0, 0} };
static atomic_bool reload_db = false;
static atomic_bool reload_db_active = false;
static unsigned int autosize_reload_floor_mb;
/*
 * IMA mismatch logging policy: five LOG_ERR entries, five LOG_CRIT entries,
 * one silence notice, then suppression to protect syslog from floods.
 */
static unsigned int ima_mismatch_err_budget = 5;
static unsigned int ima_mismatch_crit_budget = 5;
static int ima_mismatch_silenced;

static pthread_t update_thread;
static int update_thread_created;
static pthread_rwlock_t update_lock;
static pthread_mutex_t rule_lock;

struct trust_db_read_handle {
	MDB_txn *txn;
	MDB_cursor *cursor;
};

struct trust_db_lookup {
	const char *path;
	struct file_info *info;
	int fd;
	int *error;
};

struct trust_db_record_input {
	const char *idx;
	size_t idx_len;
	const char *data;
};

struct trust_db_key {
	MDB_val val;
	char *hash;
};

struct trust_db_metrics_snapshot {
	unsigned long lookups;
	unsigned long reader_slots_full;
};

struct trust_db_metrics {
	atomic_ulong lookups;
	atomic_ulong reader_slots_full;
};

static struct trust_db_metrics trust_metrics;
static struct trust_db_read_handle walk_read;

struct trust_db_sizing_state {
	size_t page_size;
	size_t map_pages;
	size_t active_pages;
	size_t allocated_pages;
	size_t reload_work_pages;
	size_t active_target_pages;
	size_t highwater_target_pages;
	size_t recommended_pages;
	unsigned int current_mb;
	unsigned int recommended_mb;
	unsigned long active_percent;
	unsigned long allocated_percent;
	size_t entries;
};

/*
 * lmdb_record - Parsed representation of a single LMDB value payload.
 * @tsource: Trust source identifier stored alongside the record.
 * @size: Expected file size for integrity verification.
 * @digest: Hex encoded digest string extracted from the LMDB record.
 * @digest_len: Cached length of the @digest field for comparisons.
 * @alg: Inferred digest algorithm. RPM entries may carry multiple algorithms
 *       while other backends default to SHA256 for backward compatibility.
 */
struct lmdb_record {
	unsigned int tsource;
	off_t size;
	char digest[FILE_DIGEST_STRING_MAX];
	file_hash_alg_t alg;
};

// Local functions
static void *update_thread_main(void *arg);
static int update_database(conf_t *config);
static int write_db(const char *idx, size_t idx_len, const char *data)
	__attr_access ((__read_only__, 1, 2))  __wur;
static void log_lmdb_state(int priority, const char *context, int lmdb_rc);
static void lock_trust_database_reader(void);
static void unlock_trust_database_reader(void);

// External variables
extern atomic_bool stop;
extern atomic_bool needs_flush;
extern atomic_bool reload_rules;


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
	case SRC_FILE_DB:
		return "filedb";
	}
	return "src_unknown";
}

int preconstruct_fifo(const conf_t *config)
{
	int rc;
	char err_buff[BUFFER_SIZE];

	/* Keep RUN_DIR mode/owner aligned with daemon IPC expectations. */
	if (mkdir(RUN_DIR, 0770) && errno != EEXIST) {
		msg(LOG_ERR, "Failed to create a directory %s (%s)", RUN_DIR,
		    strerror_r(errno, err_buff, BUFFER_SIZE));
		return 1;
	} else {

		if ((chmod(RUN_DIR, 0770))) {
			msg(LOG_ERR, "Failed to fix mode of dir %s (%s)",
			    RUN_DIR, strerror_r(errno, err_buff, BUFFER_SIZE));
			return 1;
		}

		if ((chown(RUN_DIR, 0, config->gid))) {
			msg(LOG_ERR, "Failed to fix ownership of dir %s (%s)",
			    RUN_DIR, strerror_r(errno, err_buff, BUFFER_SIZE));
			return 1;
		}

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

/*
 * database_set_location - Override LMDB environment directory and DB name.
 * @dir: Directory containing LMDB files. When NULL, use default DB_DIR.
 * @name: Logical LMDB database name. When NULL, use default DB_NAME.
 *
 * Returns 0 when values were accepted, or 1 when either argument is empty.
 */
int database_set_location(const char *dir, const char *name)
{
	if (dir && dir[0] == '\0')
		return 1;
	if (name && name[0] == '\0')
		return 1;

	data_dir = dir ? dir : DB_DIR;
	db = name ? name : DB_NAME;

	return 0;
}

unsigned get_default_db_max_size(void)
{
	return DEFAULT_DB_MAX_SIZE_MB; /* 100 MiB baseline */
}

/*
 * configured_reader_limit - compute LMDB reader slots to reserve.
 * @config: active daemon configuration. The future decision_threads setting
 *          will feed this calculation; today the roadmap worker cap is used.
 *
 * Returns the number of LMDB reader slots requested for the environment.
 */
static unsigned int configured_reader_limit(const conf_t *config)
{
	(void)config;

	return TRUST_DB_DECISION_READER_CAP + TRUST_DB_MAINTENANCE_READERS;
}

/*
 * trust_metric_add - add to an unsigned long metric.
 * @counter: metric counter to update.
 * @value: amount to add.
 *
 * Returns nothing.
 */
static void trust_metric_add(atomic_ulong *counter, unsigned long value)
{
	atomic_fetch_add_explicit(counter, value, memory_order_relaxed);
}

/*
 * trust_db_record_reader_error - count full LMDB reader slot table errors.
 * @rc: LMDB return code from a read transaction open.
 *
 * Returns nothing.
 */
static void trust_db_record_reader_error(int rc)
{
	if (rc == MDB_READERS_FULL)
		trust_metric_add(&trust_metrics.reader_slots_full, 1);
}

/*
 * pages_for_percent - calculate map pages needed for a utilization target.
 * @pages: pages that must fit in the map.
 * @percent: target utilization percentage.
 *
 * Returns the number of map pages needed so @pages occupies no more than
 * @percent of the map, rounded up.
 */
static size_t pages_for_percent(size_t pages, unsigned int percent)
{
	if (pages == 0 || percent == 0)
		return 0;

	return ((pages * 100) + percent - 1) / percent;
}

/*
 * pages_times - multiply page counts without wrapping.
 * @pages: base page count.
 * @factor: integer multiplier.
 *
 * Returns the product, or the largest size_t value if it would overflow.
 */
static size_t pages_times(size_t pages, unsigned int factor)
{
	if (factor != 0 && pages > ((size_t)-1) / factor)
		return (size_t)-1;
	return pages * factor;
}

/*
 * percent_of - calculate an integer percentage.
 * @used: numerator value.
 * @total: denominator value.
 *
 * Returns @used as a percentage of @total, or 0 when @total is 0.
 */
static unsigned long percent_of(size_t used, size_t total)
{
	if (total == 0)
		return 0;

	return (100 * used) / total;
}

/*
 * bytes_to_mb - convert bytes to whole MiB for db_max_size.
 * @bytes: byte count to convert.
 *
 * Returns a ceil-rounded MiB value clamped to unsigned int.
 */
static unsigned int bytes_to_mb(size_t bytes)
{
	size_t mb = (bytes + MEGABYTE - 1) / MEGABYTE;

	if (mb > UINT_MAX)
		return UINT_MAX;
	if (mb == 0)
		return 1;
	return mb;
}

/*
 * pages_to_mb - convert LMDB page count to whole MiB.
 * @pages: LMDB pages.
 * @page_size: LMDB page size in bytes.
 *
 * Returns a ceil-rounded MiB value clamped to unsigned int.
 */
static unsigned int pages_to_mb(size_t pages, size_t page_size)
{
	size_t max_bytes = (size_t)UINT_MAX * MEGABYTE;

	if (page_size == 0)
		page_size = 4096;
	if (pages > max_bytes / page_size)
		return UINT_MAX;
	return bytes_to_mb(pages * page_size);
}

/*
 * complete_lmdb_sizing_state - derive autosize targets from raw LMDB state.
 * @state: sizing state with raw page counts already populated.
 *
 * Returns nothing.
 */
static void complete_lmdb_sizing_state(struct trust_db_sizing_state *state)
{
	size_t reload_cap = pages_times(state->active_pages,
					TRUST_DB_RELOAD_WORK_FACTOR);

	/*
	 * me_last_pgno is LMDB's file high-water mark. It is useful for
	 * seeing that reload churn has touched most of the map, but it is not
	 * the same as live trust data. If auto sizing chases that monotonic
	 * high-water mark directly, every drop/rebuild can make the next
	 * target slightly larger even when the backend entry set is unchanged.
	 *
	 * Bound the reload target to a working set derived from the active DB:
	 * one copy for the currently published trust set and one copy for a
	 * rebuild when old pages cannot be reused immediately because LMDB
	 * readers or freelist bookkeeping still reference them. This keeps
	 * enough headroom for copy-on-write reloads without turning file
	 * high-water growth into permanent map growth.
	 */
	state->reload_work_pages = state->allocated_pages;
	if (state->reload_work_pages < state->active_pages)
		state->reload_work_pages = state->active_pages;
	if (reload_cap && state->reload_work_pages > reload_cap)
		state->reload_work_pages = reload_cap;

	state->active_target_pages = pages_for_percent(state->active_pages,
					TRUST_DB_ACTIVE_TARGET_PERCENT);
	state->highwater_target_pages =
		pages_for_percent(state->reload_work_pages,
				  TRUST_DB_RELOAD_HIGHWATER_PERCENT);
	state->recommended_pages = state->active_target_pages;
	if (state->highwater_target_pages > state->recommended_pages)
		state->recommended_pages = state->highwater_target_pages;
	state->recommended_pages++;
	state->recommended_mb = pages_to_mb(state->recommended_pages,
					    state->page_size);
	state->active_percent = percent_of(state->active_pages,
					   state->map_pages);
	state->allocated_percent = percent_of(state->allocated_pages,
					      state->map_pages);
}

/*
 * fill_lmdb_sizing_state - collect named DB and map sizing details.
 * @txn: read transaction for the environment.
 * @sizing_dbi: named database handle to inspect.
 * @info: environment info already read from the same environment.
 * @state: destination sizing state.
 *
 * Returns 0 on success or an LMDB error code.
 */
static int fill_lmdb_sizing_state(MDB_txn *txn, MDB_dbi sizing_dbi,
				  const MDB_envinfo *info,
				  struct trust_db_sizing_state *state)
{
	MDB_stat stat;
	int rc;

	memset(state, 0, sizeof(*state));
	rc = mdb_stat(txn, sizing_dbi, &stat);
	if (rc)
		return rc;

	state->page_size = stat.ms_psize ? stat.ms_psize : 4096;
	state->map_pages = info->me_mapsize / state->page_size;
	state->allocated_pages = info->me_last_pgno + 1;
	state->active_pages = stat.ms_branch_pages + stat.ms_leaf_pages +
			      stat.ms_overflow_pages;
	state->entries = stat.ms_entries;
	state->current_mb = bytes_to_mb(info->me_mapsize);
	complete_lmdb_sizing_state(state);
	return 0;
}

/*
 * autosize_effective_target_mb - apply any runtime reload safety floor.
 * @state: sizing state with computed recommendation.
 * @mode: caller context for startup, live inspection, or reload preflight.
 *
 * Returns the MiB target after honoring recent reload growth when appropriate.
 */
static unsigned int autosize_effective_target_mb(
		const struct trust_db_sizing_state *state,
		enum autosize_plan_mode mode)
{
	unsigned int target_mb = state->recommended_mb;

	if (mode != AUTOSIZE_STARTUP_INSPECTION &&
	    autosize_reload_floor_mb &&
	    target_mb < autosize_reload_floor_mb)
		target_mb = autosize_reload_floor_mb;
	return target_mb;
}

/*
 * autosize_shrink_allowed - decide whether auto mode may reduce map size.
 * @config: active daemon configuration.
 * @state: LMDB sizing state from the environment being considered.
 * @target_mb: proposed new map size after any reload safety floor.
 * @mode: caller context for startup, live inspection, or reload preflight.
 *
 * Shrink is intentionally conservative. The final trust DB is usually stable,
 * but reload is not an in-place no-op: fapolicyd drops the named database and
 * reinserts records from backend snapshots. LMDB must commit copy-on-write
 * metadata and freelist changes before old pages are reusable. If we shrink
 * as soon as active pages dip below the steady-state target, a reload storm
 * can push the allocated high-water mark back to MDB_MAP_FULL. Require both
 * active pages and allocated pages to be comfortably low, and require the
 * proposed shrink to be large enough to avoid map-size oscillation. Startup
 * is the exception for allocated high-water pages: after a daemon restart
 * there are no old fapolicyd reader transactions to pin deleted pages, so
 * startup compaction may use the bounded rebuild working set instead of
 * preserving a stale file high-water mark forever.
 *
 * Returns 1 when shrink is allowed, 0 otherwise.
 */
static int autosize_shrink_allowed(const conf_t *config,
				   const struct trust_db_sizing_state *state,
				   unsigned int target_mb,
				   enum autosize_plan_mode mode)
{
	if (target_mb >= config->db_max_size)
		return 0;
	if (state->active_percent >= TRUST_DB_SHRINK_TRIGGER_PERCENT)
		return 0;
	if (mode != AUTOSIZE_STARTUP_INSPECTION &&
	    state->allocated_percent >= TRUST_DB_RELOAD_HIGHWATER_PERCENT)
		return 0;
	if ((unsigned long long)target_mb * 100 >
	    (unsigned long long)config->db_max_size *
	    TRUST_DB_SHRINK_HYSTERESIS_PERCENT)
		return 0;
	return 1;
}

/*
 * apply_autosize_plan - update config->db_max_size from LMDB sizing state.
 * @config: active daemon configuration.
 * @state: LMDB sizing state from either the live or on-disk environment.
 * @mode: caller context for startup, live inspection, or reload preflight.
 * @context: short log label describing the caller.
 *
 * Auto sizing has two targets. The active-page target keeps the final trust
 * database near 75 percent utilization so normal package changes have room.
 * The reload target keeps a bounded copy-on-write working set below 85
 * percent so a full drop/rebuild reload has room to commit metadata before
 * old pages are reusable. Manual configurations are not changed here; callers
 * should log the recommended size for administrators.
 *
 * Returns 1 when config->db_max_size changed, 0 otherwise.
 */
static int apply_autosize_plan(conf_t *config,
			       const struct trust_db_sizing_state *state,
			       enum autosize_plan_mode mode,
			       const char *context)
{
	unsigned int target_mb = autosize_effective_target_mb(state, mode);

	if (state->active_pages == 0) {
		msg(LOG_INFO,
		    "autosize: empty DB during %s - keeping %u MiB",
		    context, config->db_max_size);
		return 0;
	}

	if (target_mb > config->db_max_size) {
		msg(LOG_INFO,
		    "autosize: %s growing map %u->%u MiB "
		    "(entries=%zu active=%zu/%zu pages %lu%%, "
		    "allocated=%zu/%zu pages %lu%%, reload_work=%zu)",
		    context, config->db_max_size, target_mb, state->entries,
		    state->active_pages, state->map_pages,
		    state->active_percent, state->allocated_pages,
		    state->map_pages, state->allocated_percent,
		    state->reload_work_pages);
		config->db_max_size = target_mb;
		return 1;
	}

	if (mode == AUTOSIZE_RELOAD_PREFLIGHT ||
	    !autosize_shrink_allowed(config, state, target_mb, mode)) {
		msg(LOG_INFO,
		    "autosize: %s keeping %u MiB "
		    "(target=%u MiB active=%lu%% allocated=%lu%%)",
		    context, config->db_max_size, target_mb,
		    state->active_percent, state->allocated_percent);
		return 0;
	}

	msg(LOG_INFO,
	    "autosize: %s shrinking map %u->%u MiB "
	    "(entries=%zu active=%zu/%zu pages %lu%%, "
	    "allocated=%zu/%zu pages %lu%%, reload_work=%zu)",
	    context, config->db_max_size, target_mb, state->entries,
	    state->active_pages, state->map_pages, state->active_percent,
	    state->allocated_pages, state->map_pages,
	    state->allocated_percent, state->reload_work_pages);
	config->db_max_size = target_mb;
	return 1;
}

/*
 * read_live_lmdb_sizing_state - inspect the currently open LMDB environment.
 * @state: destination sizing state.
 *
 * Returns 0 on success or an LMDB error code.
 */
static int read_live_lmdb_sizing_state(struct trust_db_sizing_state *state)
{
	MDB_envinfo info;
	MDB_txn *txn = NULL;
	int rc;

	rc = mdb_env_info(env, &info);
	if (rc)
		return rc;

	rc = mdb_txn_begin(env, NULL, MDB_RDONLY, &txn);
	if (rc)
		return rc;

	rc = fill_lmdb_sizing_state(txn, dbi, &info, state);
	mdb_txn_abort(txn);
	return rc;
}

/*
 * read_existing_lmdb_sizing_state - inspect the on-disk LMDB environment.
 * @state: destination sizing state.
 *
 * This is used before applying a resize to the live environment. The read-only
 * handle avoids LMDB lockfile mutexes because autosize only needs sizing
 * metadata and must not interfere with the daemon's active environment.
 *
 * Returns 0 on success or an LMDB error code.
 */
static int read_existing_lmdb_sizing_state(struct trust_db_sizing_state *state)
{
	MDB_env *tmp_env = NULL;
	MDB_envinfo info;
	MDB_txn *txn = NULL;
	MDB_dbi dbi_tmp;
	int rc;

	rc = mdb_env_create(&tmp_env);
	if (rc)
		return rc;

	rc = mdb_env_set_maxdbs(tmp_env, 2);
	if (rc)
		goto out_close;

	rc = mdb_env_open(tmp_env, data_dir, MDB_RDONLY|MDB_NOLOCK, 0);
	if (rc)
		goto out_close;

	rc = mdb_env_info(tmp_env, &info);
	if (rc)
		goto out_close;

	rc = mdb_txn_begin(tmp_env, NULL, MDB_RDONLY, &txn);
	if (rc)
		goto out_close;

	rc = mdb_dbi_open(txn, db, 0, &dbi_tmp);
	if (rc)
		goto out_abort;

	rc = fill_lmdb_sizing_state(txn, dbi_tmp, &info, state);

out_abort:
	mdb_txn_abort(txn);
out_close:
	mdb_env_close(tmp_env);
	return rc;
}

/*
 * dir_file_path - format a child path below a directory.
 * @buf: destination buffer.
 * @buf_size: destination buffer size.
 * @dir: parent directory.
 * @name: file name below @dir.
 *
 * Returns 0 on success or ENAMETOOLONG.
 */
static int dir_file_path(char *buf, size_t buf_size, const char *dir,
			 const char *name)
{
	int written;

	written = snprintf(buf, buf_size, "%s/%s", dir, name);
	if (written < 0 || (size_t)written >= buf_size)
		return ENAMETOOLONG;
	return 0;
}

/*
 * lmdb_file_path - format a path below the LMDB environment directory.
 * @buf: destination buffer.
 * @buf_size: destination buffer size.
 * @name: file name below data_dir.
 *
 * Returns 0 on success or ENAMETOOLONG.
 */
static int lmdb_file_path(char *buf, size_t buf_size, const char *name)
{
	return dir_file_path(buf, buf_size, data_dir, name);
}

/*
 * compact_existing_lmdb - compact the on-disk environment before startup.
 * @target_mb: autosize target that will be used when init_db() reopens LMDB.
 *
 * A live mdb_env_set_mapsize() cannot move pages; if the file high-water mark
 * has grown to the emergency map size, LMDB may silently keep the larger map
 * even when the active named DB needs far less space. Startup is the one
 * point where fapolicyd can safely replace data.mdb before publishing a live
 * environment. Use LMDB's compact copy to rewrite only live pages, then
 * atomically replace data.mdb. The existing lock.mdb and db.ver are left in
 * place.
 *
 * Returns 0 on success or an errno/LMDB error code on failure.
 */
static int compact_existing_lmdb(unsigned int target_mb)
{
	MDB_env *copy_env = NULL;
	char tmpdir[PATH_MAX];
	char live_data[PATH_MAX];
	char compact_data[PATH_MAX];
	char backup_data[PATH_MAX];
	int backup_fd;
	int rc;

	rc = lmdb_file_path(live_data, sizeof(live_data), "data.mdb");
	if (rc)
		return rc;

	rc = lmdb_file_path(backup_data, sizeof(backup_data),
			    "data.mdb.autosize.XXXXXX");
	if (rc)
		return rc;

	rc = lmdb_file_path(tmpdir, sizeof(tmpdir), ".autosize-compact.XXXXXX");
	if (rc)
		return rc;

	if (mkdtemp(tmpdir) == NULL)
		return errno;

	rc = mdb_env_create(&copy_env);
	if (rc)
		goto out_remove_dir;

	rc = mdb_env_set_maxdbs(copy_env, 2);
	if (rc)
		goto out_close;

	rc = mdb_env_open(copy_env, data_dir, MDB_RDONLY, 0);
	if (rc)
		goto out_close;

	rc = mdb_env_copy2(copy_env, tmpdir, MDB_CP_COMPACT);
	if (rc)
		goto out_close;

	mdb_env_close(copy_env);
	copy_env = NULL;

	rc = dir_file_path(compact_data, sizeof(compact_data), tmpdir,
			   "data.mdb");
	if (rc)
		goto out_remove_dir;

	backup_fd = mkstemp(backup_data);
	if (backup_fd < 0) {
		rc = errno;
		goto out_remove_dir;
	}
	close(backup_fd);
	unlink(backup_data);

	if (link(live_data, backup_data) < 0) {
		rc = errno;
		goto out_remove_dir;
	}

	if (rename(compact_data, live_data) < 0) {
		rc = errno;
		unlink(backup_data);
		goto out_remove_dir;
	}

	unlink(backup_data);
	msg(LOG_INFO,
	    "autosize: compacted trust DB before startup reopen at %u MiB",
	    target_mb);
	rc = 0;

out_close:
	if (copy_env)
		mdb_env_close(copy_env);
out_remove_dir:
	if (dir_file_path(compact_data, sizeof(compact_data), tmpdir,
			  "data.mdb") == 0)
		unlink(compact_data);
	if (dir_file_path(compact_data, sizeof(compact_data), tmpdir,
			  "lock.mdb") == 0)
		unlink(compact_data);
	rmdir(tmpdir);
	return rc;
}

/* autosize_database - compute new map size when utilisation drifts
 * @config: active daemon configuration, db_max_size is updated in-place
 * @mode: startup or live reload context.
 * Returns 1 when the configured map size was modified, 0 otherwise. On
 * inspection error the function keeps the caller's db_max_size. If startup
 * compaction fails after a shrink decision, db_max_size is restored to the
 * actual existing map size so init_db() can safely open the preserved DB. */
static int autosize_database(conf_t *config, enum autosize_plan_mode mode)
{
	struct trust_db_sizing_state state;
	unsigned int current_mb;
	unsigned int target_mb;
	int rc;

	/*
	 * Open the existing environment read-only without LMDB lockfile
	 * mutexes. This start/reload inspection only needs a point-in-time
	 * sizing view and must not disturb the live daemon environment.
	 */
	rc = read_existing_lmdb_sizing_state(&state);
	if (rc) {
		msg(LOG_WARNING,
		    "autosize: could not inspect LMDB (%s) - keeping %u MiB",
		    mdb_strerror(rc), config->db_max_size);
		return 0;
	}

	current_mb = config->db_max_size;
	if (state.current_mb != config->db_max_size) {
		msg(LOG_INFO,
		    "autosize: database inspection using actual map %u MiB "
		    "instead of configured baseline %u MiB",
		    state.current_mb, config->db_max_size);
		config->db_max_size = state.current_mb;
	}

	if (!apply_autosize_plan(config, &state, mode,
				 "database inspection")) {
		if (current_mb != config->db_max_size)
			return 1;
		return 0;
	}

	target_mb = autosize_effective_target_mb(&state, mode);
	if (mode == AUTOSIZE_STARTUP_INSPECTION &&
	    target_mb < state.current_mb) {
		rc = compact_existing_lmdb(target_mb);
		if (rc) {
			msg(LOG_WARNING,
			    "autosize: startup compaction failed (%s) - "
			    "keeping %u MiB",
			    mdb_strerror(rc), state.current_mb);
			config->db_max_size = state.current_mb;
			return 0;
		}
	}

	return 1;
}

/* Grow the live LMDB map after encountering MDB_MAP_FULL during rebuilds.
 * @config: active daemon configuration updated in place on success
 * Returns 0 when the map was expanded, otherwise 1.
 */
static int grow_map_after_full(conf_t *config)
{
	unsigned long old_mb = config->db_max_size;
	unsigned long new_mb = old_mb + (old_mb / 4);

	if (new_mb <= old_mb)
		new_mb++;

	/*
	 * Emergency growth should be rare. Dump the complete map/reader state
	 * before changing the map so QA can tell whether the full condition was
	 * caused by reader pinning, high-water growth, or a genuine active-data
	 * increase.
	 */
	log_lmdb_state(LOG_ERR, "trust DB autosize grow trigger",
		       MDB_MAP_FULL);

	int rc = mdb_env_set_mapsize(env, new_mb * MEGABYTE);
	if (rc) {
		msg(LOG_ERR,
		    "autosize: failed to grow trust DB to %lu MiB (%s)",
		    new_mb, mdb_strerror(rc));
		return 1;
	}

	config->db_max_size = new_mb;
	if (autosize_reload_floor_mb < new_mb)
		autosize_reload_floor_mb = new_mb;
	msg(LOG_INFO,
	    "autosize: trust DB full at %lu MiB - grew to %lu MiB, retrying rebuild",
	    old_mb, new_mb);
	log_lmdb_state(LOG_INFO, "trust DB autosize after grow", 0);

	return 0;
}

/*
 * autosize_reload_preflight - grow the live LMDB map before drop/rebuild.
 * @config: active daemon configuration.
 *
 * Reload is a complete named-database drop followed by a full import from the
 * backend snapshots. Identical backend contents do not make the operation a
 * no-op: LMDB still has to commit the drop transaction and the freelist
 * metadata before old data pages are reusable. A map sized only for the final
 * active database can therefore hit MDB_MAP_FULL during mdb_drop() after
 * repeated reloads raise the allocated high-water mark. This hook runs while
 * the update thread owns the trust DB write lock and grows auto-sized maps
 * before the destructive transaction starts. Manual configurations are left
 * unchanged, but the recommended size is logged so self-managed installs have
 * an actionable value instead of a generic "increase db_max_size" error.
 *
 * Returns 0 on success or when no resize is needed, non-zero on resize error.
 */
static int autosize_reload_preflight(conf_t *config)
{
	struct trust_db_sizing_state state;
	unsigned int old_db_max_size = config->db_max_size;
	unsigned int old_reload_floor_mb = autosize_reload_floor_mb;
	int rc;

	rc = read_live_lmdb_sizing_state(&state);
	if (rc) {
		msg(LOG_WARNING,
		    "autosize: reload preflight could not inspect LMDB (%s)",
		    mdb_strerror(rc));
		return 0;
	}

	if (!config->do_audit_db_sizing) {
		if (state.recommended_pages > state.map_pages)
			msg(LOG_WARNING,
			    "db_max_size may be too small for safe reload: "
			    "active=%zu pages, allocated=%zu pages, "
			    "configured=%u MiB, recommended at least %u MiB",
			    state.active_pages, state.allocated_pages,
			    config->db_max_size, state.recommended_mb);
		return 0;
	}

	if (!apply_autosize_plan(config, &state, AUTOSIZE_RELOAD_PREFLIGHT,
				 "reload preflight"))
		return 0;

	rc = mdb_env_set_mapsize(env, (size_t)config->db_max_size * MEGABYTE);
	if (rc) {
		msg(LOG_ERR, "autosize: reload preflight resize to %u MiB: %s",
		    config->db_max_size, mdb_strerror(rc));
		config->db_max_size = old_db_max_size;
		autosize_reload_floor_mb = old_reload_floor_mb;
		return rc;
	}

	return 0;
}

/*
 * init_dbi - open and publish the LMDB database handle.
 *
 * Returns 0 on success or a non-zero LMDB error code.
 */
static int init_dbi(void)
{
	MDB_txn *txn;
	int rc;

	rc = mdb_txn_begin(env, NULL, 0, &txn);
	if (rc)
		return rc;

	rc = mdb_dbi_open(txn, db, MDB_CREATE|MDB_DUPSORT, &dbi);
	if (rc) {
		msg(LOG_ERR, "%s", mdb_strerror(rc));
		mdb_txn_abort(txn);
		return rc;
	}

	rc = mdb_txn_commit(txn);
	if (rc) {
		msg(LOG_ERR, "%s", mdb_strerror(rc));
		dbi_init = 0;
		return rc;
	}

	dbi_init = 1;
	return 0;
}

static int init_db(const conf_t *config)
{
	unsigned int flags = MDB_MAPASYNC|MDB_NOSYNC;
	int rc;
#ifndef DEBUG
	flags |= MDB_WRITEMAP;
#endif
	if (mdb_env_create(&env)) {
		/* env not allocated on failure, but ensure it's NULL */
		env = NULL;
		return 1;
	}

	if (mdb_env_set_maxdbs(env, 2)) {
		/* Clean up environment on failure */
		mdb_env_close(env);
		env = NULL;
		return 2;
	}

	if (mdb_env_set_mapsize(env, config->db_max_size*MEGABYTE)) {
		/* Clean up environment on failure */
		mdb_env_close(env);
		env = NULL;
		return 3;
	}

	db_max_readers = configured_reader_limit(config);
	if (mdb_env_set_maxreaders(env, db_max_readers)) {
		/* Clean up environment on failure */
		mdb_env_close(env);
		env = NULL;
		return 4;
	}

	rc = mdb_env_open(env, data_dir, flags, 0660);
	if (rc) {
		msg(LOG_ERR, "env_open error: %s", mdb_strerror(rc));
		/* Clean up environment on failure */
		mdb_env_close(env);
		env = NULL;
		return 5;
	}

	rc = init_dbi();
	if (rc) {
		/* Clean up environment on failure */
		mdb_env_close(env);
		env = NULL;
		return 6;
	}

	MDB_maxkeysize = mdb_env_get_maxkeysize(env);
	msg(LOG_INFO, "fapolicyd integrity is %u",
	    decision_config_integrity(NULL));

	lib_symlink = is_link("/lib");
	lib64_symlink = is_link("/lib64");
	bin_symlink = is_link("/bin");
	sbin_symlink = is_link("/sbin");

	return 0;
}


static unsigned get_pages_in_use(void);
static unsigned long pages, max_pages;
static unsigned long allocated_pages, allocated_pages_percent;

/*
 * close_env - close LMDB env and clear cached handle state
 * @do_close_dbi: non-zero closes cached dbi before env close
 *
 * Returns: none
 */
static void close_env(int do_close_dbi)
{
	if (env == NULL)
		return;

	if (do_close_dbi && dbi_init)
		mdb_close(env, dbi);

	mdb_env_close(env);
	env = NULL;
	dbi_init = 0;
	memset(&walk_read, 0, sizeof(walk_read));
}

struct lmdb_reader_log {
	int priority;
	const char *context;
	unsigned int lines;
};

/*
 * log_lmdb_reader_line - bridge mdb_reader_list() output into syslog.
 * @line: reader-table line provided by LMDB.
 * @ctx: struct lmdb_reader_log with priority and context.
 *
 * Returns 0 so LMDB continues listing reader slots.
 */
static int log_lmdb_reader_line(const char *line, void *ctx)
{
	struct lmdb_reader_log *log = ctx;

	if (line == NULL || log == NULL)
		return 0;

	msg(log->priority, "LMDB reader after %s: %s",
	    log->context, line);
	log->lines++;
	return 0;
}

/*
 * log_lmdb_readers - dump LMDB reader slots for map-full diagnostics.
 * @priority: syslog priority used for the diagnostic lines.
 * @context: short description of the operation being diagnosed.
 *
 * The configured max reader count only says how many slots may exist. The
 * reader-list dump shows whether any slot is actually active and which
 * transaction id it pins, which separates reader pinning from write-churn
 * growth during reload storms.
 *
 * Returns: none.
 */
static void log_lmdb_readers(int priority, const char *context)
{
	struct lmdb_reader_log log = {
		.priority = priority,
		.context = context ? context : "unknown operation",
	};
	int rc;

	if (env == NULL)
		return;

	rc = mdb_reader_list(env, log_lmdb_reader_line, &log);
	if (rc < 0)
		msg(priority, "LMDB reader list after %s failed: %s",
		    log.context, mdb_strerror(rc));
	else if (log.lines == 0)
		msg(priority, "LMDB reader after %s: no active readers",
		    log.context);
}

/*
 * log_lmdb_state - log LMDB map, named DB, and reader-table state.
 * @priority: syslog priority used for the diagnostic lines.
 * @context: short description of the operation being diagnosed.
 * @lmdb_rc: LMDB return code that triggered the diagnostic, or 0.
 *
 * LMDB map pressure follows the environment high-water mark, not just the
 * current named database page count. Rebuilding a steady set of trust entries
 * can still run out of map space when old reader transactions keep deleted
 * pages from being reused. These diagnostics are intentionally grouped around
 * failures and size checks so the logs show active DB pages, allocated pages,
 * the last transaction id, and reader-table pressure together.
 *
 * Returns: none.
 */
static void log_lmdb_state(int priority, const char *context, int lmdb_rc)
{
	MDB_envinfo info;
	MDB_stat stat;
	MDB_txn *txn = NULL;
	const char *where = context ? context : "unknown operation";
	size_t page_size = 4096;
	size_t map_pages = 0;
	size_t env_allocated_pages = 0;
	size_t db_pages = 0;
	int stale_readers = 0;
	int reader_rc;
	int stat_rc = 0;
	int rc;

	if (env == NULL) {
		msg(priority, "LMDB state after %s: environment is closed",
		    where);
		return;
	}

	rc = mdb_env_info(env, &info);
	if (rc) {
		msg(priority, "LMDB state after %s: mdb_env_info failed: %s",
		    where, mdb_strerror(rc));
		return;
	}

	reader_rc = mdb_reader_check(env, &stale_readers);

	if (dbi_init) {
		stat_rc = mdb_txn_begin(env, NULL, MDB_RDONLY, &txn);
		if (stat_rc == 0) {
			stat_rc = mdb_stat(txn, dbi, &stat);
			mdb_txn_abort(txn);
		}
	} else {
		stat_rc = EINVAL;
	}

	if (stat_rc == 0) {
		page_size = stat.ms_psize;
		db_pages = stat.ms_branch_pages + stat.ms_leaf_pages +
			   stat.ms_overflow_pages;
	}

	if (page_size)
		map_pages = info.me_mapsize / page_size;
	env_allocated_pages = info.me_last_pgno + 1;

	if (lmdb_rc)
		msg(priority, "LMDB state after %s: error=%s (%d)",
		    where, mdb_strerror(lmdb_rc), lmdb_rc);

	msg(priority,
	    "LMDB env after %s: map=%zu MiB pages=%zu "
	    "allocated=%zu (%zu%%) last_pgno=%zu txnid=%zu",
	    where, info.me_mapsize / MEGABYTE, map_pages, env_allocated_pages,
	    map_pages ? (100 * env_allocated_pages) / map_pages : 0,
	    info.me_last_pgno, info.me_last_txnid);

	if (stat_rc == 0) {
		msg(priority,
		    "LMDB db after %s: entries=%zu pages=%zu (%zu%%) "
		    "branch=%zu leaf=%zu overflow=%zu depth=%u page_size=%zu",
		    where, stat.ms_entries, db_pages,
		    map_pages ? (100 * db_pages) / map_pages : 0,
		    stat.ms_branch_pages, stat.ms_leaf_pages,
		    stat.ms_overflow_pages, stat.ms_depth, page_size);
	} else {
		msg(priority, "LMDB db after %s: stat unavailable: %s",
		    where, mdb_strerror(stat_rc));
	}

	if (reader_rc) {
		msg(priority,
		    "LMDB readers after %s: reader_check failed: %s slots_used=%u max=%u",
		    where, mdb_strerror(reader_rc), info.me_numreaders,
		    info.me_maxreaders);
	} else {
		msg(priority,
		    "LMDB readers after %s: slots_used=%u max=%u "
		    "stale_cleared=%d configured_max=%u",
		    where, info.me_numreaders, info.me_maxreaders,
		    stale_readers, db_max_readers);
	}

	if (lmdb_rc == MDB_MAP_FULL)
		log_lmdb_readers(priority, where);
}

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
			allocated_pages = st.me_last_pgno + 1;
			allocated_pages_percent = max_pages ?
				((100 * allocated_pages) / max_pages) : 0;
			msg(LOG_DEBUG, "Trust database max pages: %lu", max_pages);
			msg(LOG_DEBUG, "Trust database pages in use: %lu (%lu%%)", pages,
			    max_pages ? ((100*pages)/max_pages) : 0);
			msg(LOG_DEBUG,
			    "Trust database allocated high-water pages: %lu (%lu%%)",
			    allocated_pages, allocated_pages_percent);
		}
	}

	// Now close down
	close_env(1);
}

static void check_db_size(const conf_t *config)
{
	struct trust_db_sizing_state state;
	unsigned int target_mb;
	int rc;

	rc = read_live_lmdb_sizing_state(&state);
	if (rc || state.page_size == 0) {
		msg(LOG_WARNING,
		    "Cannot inspect trust database size (%s)",
		    rc ? mdb_strerror(rc) : "empty database");
		pages = 0;
		allocated_pages = 0;
		allocated_pages_percent = 0;
		return;
	}

	pages = state.active_pages;
	max_pages = state.map_pages;
	allocated_pages = state.allocated_pages;
	allocated_pages_percent = state.allocated_percent;

	// Active DB pages can stay steady while LMDB's high-water mark grows
	// across repeated rebuilds. In auto mode this is informational unless
	// a write actually fails; manual mode keeps it as a warning because the
	// administrator may need to adjust db_max_size.
	msg(LOG_DEBUG,
	    "Trust database active pages: %lu (%lu%%), allocated pages: %zu (%lu%%)",
	    pages, state.active_percent, state.allocated_pages,
	    state.allocated_percent);
	if (state.allocated_percent > TRUST_DB_RELOAD_HIGHWATER_PERCENT &&
	    state.allocated_percent > state.active_percent) {
		int priority = config->do_audit_db_sizing ? LOG_INFO :
			       LOG_WARNING;

		msg(priority,
		    "Trust database LMDB map high-water at %lu%% capacity "
		    "while active DB pages are at %lu%%",
		    state.allocated_percent, state.active_percent);
		if (!config->do_audit_db_sizing)
			log_lmdb_state(LOG_WARNING,
				       "trust database size check", 0);
	}

	target_mb = autosize_effective_target_mb(&state,
						 AUTOSIZE_LIVE_INSPECTION);
	if (config->do_audit_db_sizing) {
		if (target_mb > config->db_max_size) {
			if (state.active_target_pages > state.map_pages)
				msg(LOG_INFO,
				    "Trust database at %lu%% capacity - "
				    "map will grow automatically before next rebuild",
				    state.active_percent);
			else
				msg(LOG_INFO,
				    "Trust database reload headroom target is %u MiB "
				    "(active=%lu%% high-water=%lu%%) - "
				    "map will grow automatically before next rebuild",
				    target_mb, state.active_percent,
				    state.allocated_percent);
		} else if (autosize_shrink_allowed(config, &state, target_mb,
						   AUTOSIZE_LIVE_INSPECTION)) {
			msg(LOG_INFO, "Trust database at %lu%% capacity - "
			    "map will shrink automatically on next rebuild",
			    state.active_percent);
		}
		return;
	}

	if (target_mb > config->db_max_size) {
		msg(LOG_WARNING,
		    "Trust database may need %u MiB for safe reload "
		    "(active=%lu%% allocated=%lu%%)",
		    target_mb, state.active_percent, state.allocated_percent);
	} else if (state.active_percent < TRUST_DB_SHRINK_TRIGGER_PERCENT) {
		msg(LOG_WARNING, "Trust database at %lu%% capacity - "
		    "might consider shrinking the size to save space",
		    state.active_percent);
	}
}

/*
 * database_config_report - write trust database configured size.
 * @f: report stream.
 * Returns nothing.
 */
void database_config_report(FILE *f)
{
	fprintf(f, "Trust database max pages: %lu\n", max_pages);
	fprintf(f, "Trust database max readers: %u\n", db_max_readers);
}

/*
 * database_utilization_report - write current trust database utilization.
 * @f: report stream.
 * Returns nothing.
 */
void database_utilization_report(FILE *f)
{
	fprintf(f, "Trust database pages in use: %lu (%lu%%)\n", pages,
		max_pages ? ((100*pages)/max_pages) : 0);
	fprintf(f, "Trust database allocated high-water pages: %lu (%lu%%)\n",
		allocated_pages, allocated_pages_percent);
}

void database_report(FILE *f)
{
	database_config_report(f);
	database_utilization_report(f);
}

/*
 * trust_metric_snapshot_ulong - copy and optionally reset an ulong metric.
 * @counter: metric counter to read.
 * @reset: non-zero resets the counter after copying.
 *
 * Returns the copied metric value.
 */
static unsigned long trust_metric_snapshot_ulong(atomic_ulong *counter,
						 int reset)
{
	if (reset)
		return atomic_exchange_explicit(counter, 0,
						memory_order_relaxed);

	return atomic_load_explicit(counter, memory_order_relaxed);
}

/*
 * database_metrics_snapshot_reset - copy trust DB metrics.
 * @metrics: destination snapshot.
 * @reset: non-zero resets counters after copying.
 *
 * Returns nothing.
 */
static void database_metrics_snapshot_reset(
		struct trust_db_metrics_snapshot *metrics, int reset)
{
	if (metrics == NULL)
		return;

	metrics->lookups = trust_metric_snapshot_ulong(
		&trust_metrics.lookups, reset);
	metrics->reader_slots_full = trust_metric_snapshot_ulong(
		&trust_metrics.reader_slots_full, reset);
}

/*
 * database_metrics_report_reset - write resettable trust DB read metrics.
 * @f: report stream.
 * @reset: non-zero resets counters after copying.
 *
 * Returns nothing.
 */
void database_metrics_report_reset(FILE *f, int reset)
{
	struct trust_db_metrics_snapshot metrics;

	if (f == NULL)
		return;

	database_metrics_snapshot_reset(&metrics, reset);

	fputs("\nTrust database lookups:\n", f);
	fprintf(f, "Trust DB lookups: %lu\n", metrics.lookups);
	fprintf(f, "Trust DB reader slots full: %lu\n",
		metrics.reader_slots_full);
}

/*
 * open_dbi - verify that init_db() published the LMDB database handle.
 * @txn: transaction associated with the caller's operation, kept for the
 *       historical signature.
 *
 * Returns 0 when a DBI is available, or EINVAL when the environment was not
 * initialized successfully.
 */
static int open_dbi(MDB_txn *txn)
{
	(void)txn;

	if (!dbi_init)
		return EINVAL;
	return 0;
}


static void abort_transaction(MDB_txn *txn)
{
	mdb_txn_abort(txn);
}

/*
 * Fast parser for one LMDB record line: "<tsource> <size> <hex-digest>".
 * Returns 0 on success, 1 on malformed input or overflow.
 */
static int lmdb_scan_record(const char *rec, unsigned int *tsource,
			    off_t *size, char *digest)
{
	const char *p = rec;
	char *end;

	/* --- tsource -------------------------------------------------- */
	errno = 0;
	unsigned long v = strtoul(p, &end, 10);
	if (end == p || errno == ERANGE)
		return 1;
	*tsource = (unsigned int)v;

	/* skip whitespace */
	p = end;
	while (isspace((unsigned char)*p))
		p++;

	/* --- size ----------------------------------------------------- */
	errno = 0;
#if SIZE_MAX >= (1ULL << 32)
	unsigned long long sval = strtoull(p, &end, 10);
	if (end == p || errno == ERANGE)
		return 1;
	*size = (off_t)sval;
#else
	unsigned long sval = strtoul(p, &end, 10);
	if (end == p || errno == ERANGE)
		return 1;
	*size = (off_t)sval;
#endif

	/* skip whitespace */
	p = end;
	while (isspace((unsigned char)*p))
		p++;

	/* --- digest --------------------------------------------------- */
	size_t len = 0;
	while (p[len] && !isspace((unsigned char)p[len]))
		len++;
	if (len == 0 || len >= FILE_DIGEST_STRING_MAX)
		return 1;

	memcpy(digest, p, len);
	digest[len] = '\0';
	return 0;
}

/*
 * parse_lmdb_record - Convert a serialized LMDB entry into structured data.
 * @record: Raw string pulled from the LMDB value.
 * @parsed: Output structure populated on success.
 *
 * Returns 0 when the record can be decoded, or 1 on parse/validation errors.
 * The algorithm is inferred from the stored digest length, but legacy
 * fragments without an algorithm hint still fall back to SHA256 so older
 * entries remain valid.
 */
static int parse_lmdb_record(const char *record, struct lmdb_record *parsed)
{
	if (lmdb_scan_record(record, &parsed->tsource,
			     &parsed->size, parsed->digest))
		return 1;

	/* Fast-path: identify the algorithm without a full-string strlen */
	parsed->alg = file_hash_alg_fast(parsed->digest);
	if (parsed->alg == FILE_HASH_ALG_NONE)
		parsed->alg = FILE_HASH_ALG_SHA256;     /* legacy fallback */

	size_t digest_len = file_hash_length(parsed->alg) * 2;
	if (digest_len == 0 || digest_len >= FILE_DIGEST_STRING_MAX)
		return 1;

	return 0;
}

/*
 * log_ima_mismatch - Rate-limit diagnostics when IMA measurements disagree.
 * @path: file path associated with the mismatch.
 * @record_alg: algorithm stored in metadata backing the trust database.
 * @ima_alg: algorithm parsed from the security.ima digest-ng header.
 */
static void log_ima_mismatch(const char *path, file_hash_alg_t record_alg,
			      file_hash_alg_t ima_alg)
{
	const char *meta = file_hash_alg_name(record_alg);
	const char *ima = file_hash_alg_name(ima_alg);

	if (ima_mismatch_silenced)
		return;

	if (ima_mismatch_err_budget) {
		ima_mismatch_err_budget--;
		msg(LOG_ERR,
			"IMA digest mismatch for %s (metadata %s, xattr %s)",
			path, meta ? meta : "unknown",
			ima ? ima : "unknown");
		return;
	}

	if (ima_mismatch_crit_budget) {
		ima_mismatch_crit_budget--;
		msg(LOG_CRIT,
		    "IMA digest mismatch for %s (metadata %s, xattr %s)",
		    path, meta ? meta : "unknown",
		    ima ? ima : "unknown");
		return;
	}

	msg(LOG_NOTICE,
	    "IMA digest mismatch logging silenced after repeated reports");
	ima_mismatch_silenced = 1;
}

/*
 * Convert path to a hash value. Used when the path exceeds the LMDB key
 * limit(511).  Note: Returned value must be deallocated.
 */
static char *path_to_hash(const char *path, const size_t path_len) __attr_dealloc_free __attr_access ((__read_only__, 1, 2));
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
 * trust_db_key_init - prepare an LMDB key from a trust path.
 * @key: caller-owned key wrapper to initialize.
 * @idx: path string used as the key.
 * @idx_len: length hint for @idx, or 0 when unknown.
 *
 * Long paths are stored by SHA512 of the full path, not by a truncated
 * prefix. The returned key may point into @idx or into @key->hash; callers
 * must finish with trust_db_key_destroy().
 *
 * Returns 0 on success or ENOMEM.
 */
static int trust_db_key_init(struct trust_db_key *key, const char *idx,
			     size_t idx_len)
{
	memset(key, 0, sizeof(*key));

	if (idx_len == 0)
		idx_len = strlen(idx);

	if (idx_len > MDB_maxkeysize) {
		key->hash = path_to_hash(idx, idx_len);
		if (key->hash == NULL)
			return ENOMEM;
		key->val.mv_data = key->hash;
		key->val.mv_size = (SHA512_LEN * 2) + 1;
	} else {
		key->val.mv_data = (void *)idx;
		key->val.mv_size = idx_len;
	}

	return 0;
}

/*
 * trust_db_key_destroy - release storage owned by a prepared key.
 * @key: key initialized by trust_db_key_init().
 *
 * Returns nothing.
 */
static void trust_db_key_destroy(struct trust_db_key *key)
{
	free(key->hash);
	memset(key, 0, sizeof(*key));
}

/*
 * trust_db_begin_write_txn - begin a trust DB write transaction.
 * @txn: destination transaction handle.
 * @context: log label describing the caller.
 *
 * Returns 0 on success, WRITE_DB_MAP_FULL for map exhaustion, or a stage
 * code compatible with write_db().
 */
static int trust_db_begin_write_txn(MDB_txn **txn, const char *context)
{
	int rc;

	rc = mdb_txn_begin(env, NULL, 0, txn);
	if (rc) {
		msg(LOG_ERR, "mdb_txn_begin failed before %s: %s",
		    context, mdb_strerror(rc));
		log_lmdb_state(LOG_ERR, context, rc);
		return rc == MDB_MAP_FULL ? WRITE_DB_MAP_FULL : 1;
	}

	rc = open_dbi(*txn);
	if (rc) {
		abort_transaction(*txn);
		*txn = NULL;
		msg(LOG_ERR, "open_dbi failed before %s: %s",
		    context, mdb_strerror(rc));
		return 2;
	}

	return 0;
}

/*
 * trust_db_commit_write_txn - commit a trust DB write transaction.
 * @txn: transaction handle to commit and clear.
 * @context: log label describing the caller.
 *
 * Returns 0 on success, WRITE_DB_MAP_FULL for map exhaustion, or a stage
 * code compatible with write_db().
 */
static int trust_db_commit_write_txn(MDB_txn **txn, const char *context)
{
	int rc;

	if (*txn == NULL)
		return 0;

	rc = mdb_txn_commit(*txn);
	*txn = NULL;
	if (rc) {
		msg(LOG_ERR, "mdb_txn_commit failed after %s: %s",
		    context, mdb_strerror(rc));
		log_lmdb_state(LOG_ERR, context, rc);
		return rc == MDB_MAP_FULL ? WRITE_DB_MAP_FULL : 4;
	}

	return 0;
}

/*
 * trust_db_put_record - write one prepared record into an active transaction.
 * @txn: writable LMDB transaction.
 * @record: parsed trust DB record.
 * @context: log label describing the caller.
 *
 * Returns 0 on success, WRITE_DB_MAP_FULL for map exhaustion, 3 for mdb_put
 * failures, and 5 when key hashing fails.
 */
static int trust_db_put_record(MDB_txn *txn,
			       const struct trust_db_record_input *record,
			       const char *context)
{
	struct trust_db_key key;
	MDB_val value;
	int rc;

	rc = trust_db_key_init(&key, record->idx, record->idx_len);
	if (rc)
		return 5;

	value.mv_data = (void *)record->data;
	value.mv_size = strlen(record->data);

	rc = mdb_put(txn, dbi, &key.val, &value, 0);
	trust_db_key_destroy(&key);
	if (rc) {
		msg(LOG_ERR, "mdb_put failed during %s: %s",
		    context, mdb_strerror(rc));
		return rc == MDB_MAP_FULL ? WRITE_DB_MAP_FULL : 3;
	}

	return 0;
}

/*
 * write_db - Persist a single trust record into the LMDB database.
 * @idx: Path string used as the key for the record. When the path exceeds
 *       the LMDB key size limit the function hashes the path before storage.
 * @idx_len: Length hint for @idx. Pass 0 if length unknown.
 * @data: Serialized metadata for the path. The buffer contains the integrity
 *        status, file size, and SHA256 hash sourced from the backend loaders.
 *
 * Returns 0 on success, or an error code describing the stage that failed:
 * 1 when the transaction cannot start, 2 on dbi open failure, 3 if mdb_put
 * reports an error, 4 if mdb_txn_commit fails, and 5 when key hashing fails.
 */
static int write_db(const char *idx, size_t idx_len, const char *data)
{
	struct trust_db_record_input record = {
		.idx = idx,
		.idx_len = idx_len,
		.data = data,
	};
	MDB_txn *txn = NULL;
	int rc;

	rc = trust_db_begin_write_txn(&txn, "single trust DB write");
	if (rc)
		return rc;

	rc = trust_db_put_record(txn, &record, "single trust DB write");
	if (rc) {
		abort_transaction(txn);
		log_lmdb_state(LOG_ERR, "single trust DB write",
			       rc == WRITE_DB_MAP_FULL ? MDB_MAP_FULL : 0);
		return rc;
	}

	return trust_db_commit_write_txn(&txn, "single trust DB write");
}


/*
 * trust_db_read_open - open a private LMDB read transaction and cursor.
 * @read: caller-owned read handle to initialize.
 *
 * Returns 0 on success or 1 on error. MDB_READERS_FULL is counted so admins
 * can see when worker concurrency exhausted LMDB reader slots.
 */
static int trust_db_read_open(struct trust_db_read_handle *read)
{
	int rc;

	memset(read, 0, sizeof(*read));

	rc = mdb_txn_begin(env, NULL, MDB_RDONLY, &read->txn);
	if (rc) {
		trust_db_record_reader_error(rc);
		msg(LOG_ERR, "txn_begin:%s", mdb_strerror(rc));
		return 1;
	}

	if ((rc = open_dbi(read->txn))) {
		msg(LOG_ERR, "open_dbi:%s", mdb_strerror(rc));
		abort_transaction(read->txn);
		memset(read, 0, sizeof(*read));
		return 1;
	}

	if ((rc = mdb_cursor_open(read->txn, dbi, &read->cursor))) {
		msg(LOG_ERR, "cursor_open:%s", mdb_strerror(rc));
		abort_transaction(read->txn);
		memset(read, 0, sizeof(*read));
		return 1;
	}

	return 0;
}


/*
 * trust_db_read_close - close a private LMDB read transaction and cursor.
 * @read: read handle previously initialized by trust_db_read_open().
 *
 * Returns nothing.
 */
static void trust_db_read_close(struct trust_db_read_handle *read)
{
	if (read->cursor)
		mdb_cursor_close(read->cursor);
	if (read->txn)
		abort_transaction(read->txn);
	memset(read, 0, sizeof(*read));
}


/*
 * read_database_stat - read LMDB statistics from a private read txn.
 * @st: destination for database statistics.
 *
 * Returns 0 on success or an LMDB error code on failure.
 */
static int read_database_stat(MDB_stat *st)
{
	MDB_txn *txn;
	int rc;

	rc = mdb_txn_begin(env, NULL, MDB_RDONLY, &txn);
	if (rc) {
		trust_db_record_reader_error(rc);
		return rc;
	}

	rc = mdb_stat(txn, dbi, st);
	mdb_txn_abort(txn);
	return rc;
}

static unsigned get_pages_in_use(void)
{
	MDB_stat st;

	if (read_database_stat(&st)) {
		pages = 0;
		return 0;
	}

	pages = st.ms_leaf_pages + st.ms_branch_pages +
		st.ms_overflow_pages;
	return st.ms_psize;
}

// if success, the function returns positive number of entries in database
// if error, it returns -1
static long get_number_of_entries(void)
{
	MDB_stat status;

	if (read_database_stat(&status))
		return -1;

	return status.ms_entries;
}


/*
 * trust_db_read_record - read one LMDB record through a private cursor.
 * @read: active read handle whose cursor keeps duplicate-key position.
 * @index: path key to find.
 * @operation: READ_DATA, READ_TEST_KEY, or READ_DATA_DUP.
 * @error: set to non-zero on LMDB or allocation failure.
 *
 * Returns a newly allocated value string, or NULL on error/not-found. The
 * returned string must be freed by the caller.
 */
static char *trust_db_read_record(struct trust_db_read_handle *read,
				  const char *index, int operation,
				  int *error) __attr_dealloc_free;
static char *trust_db_read_record(struct trust_db_read_handle *read,
				  const char *index, int operation,
				  int *error)
{
	int rc;
	char *data, *hash = NULL;
	MDB_val key, value;
	size_t len;
	*error = 1; // Assume an error

	// If the path is too long, convert to a hash
	// Need the whole length so read/write matches
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
		if ((rc = mdb_cursor_get(read->cursor, &key, &value,
					 MDB_SET))) {
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
		mdb_cursor_count(read->cursor, &nleaves);
		if (nleaves <= 1) {
			free(hash);
			*error = 0;
			return NULL;
		}

		// is there a next duplicate?
		if ((rc = mdb_cursor_get(read->cursor, &key, &value,
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

	if (read_database_stat(&status))
		return -1;
	if (status.ms_entries == 0)
		return 1;
	return 0;
}


/*
 * delete_all_entries_db - Clear all trust records in one LMDB transaction.
 *
 * The old trust database remains published until the drop transaction
 * commits. Any error reported here means the delete did not become visible to
 * readers, so callers can preserve the current trust database instead of
 * treating the reload as a partially applied update. MDB_MAP_FULL is returned
 * as WRITE_DB_MAP_FULL so auto-sizing paths can grow the live map and retry.
 *
 * Returns 0 on success, WRITE_DB_MAP_FULL for map exhaustion, and a non-zero
 * stage code for other failures.
 */
static int delete_all_entries_db()
{
	int rc = 0;
	MDB_txn *txn;

	rc = mdb_txn_begin(env, NULL, 0, &txn);
	if (rc) {
		msg(LOG_ERR, "mdb_txn_begin failed before trust DB delete: %s",
		    mdb_strerror(rc));
		log_lmdb_state(LOG_ERR, "trust DB delete begin", rc);
		return 1;
	}

	if (open_dbi(txn)) {
		abort_transaction(txn);
		return 2;
	}

	// 0 -> delete , 1 -> delete and close
	if ((rc = mdb_drop(txn, dbi, 0))) {
		abort_transaction(txn);
		msg(LOG_ERR, "mdb_drop failed while clearing trust DB: %s",
		    mdb_strerror(rc));
		log_lmdb_state(LOG_ERR, "trust DB delete", rc);
		return rc == MDB_MAP_FULL ? WRITE_DB_MAP_FULL : 3;
	}

	if ((rc = mdb_txn_commit(txn))) {
		if (rc == MDB_MAP_FULL)
			msg(LOG_ERR,
			    "mdb_txn_commit hit MDB_MAP_FULL while clearing trust DB");
		else
			msg(LOG_ERR, "mdb_txn_commit while clearing trust DB: %s",
			    mdb_strerror(rc));
		log_lmdb_state(LOG_ERR, "trust DB delete commit", rc);
		return rc == MDB_MAP_FULL ? WRITE_DB_MAP_FULL : 4;
	}

	return 0;
}

/*
 * trust_db_record_from_line - parse one backend snapshot line.
 * @buff: mutable line buffer, converted into key and value strings.
 * @record: parsed record pointing into @buff.
 *
 * Backend records are "path source size digest". The path may contain spaces,
 * so parsing starts from the end and finds the three metadata delimiters.
 *
 * Returns 0 on success or 1 for malformed input.
 */
static int trust_db_record_from_line(char *buff,
				     struct trust_db_record_input *record)
{
	char *end;
	char *delim = NULL;
	int delims = 0;
	int size;

	end = fapolicyd_strnchr(buff, '\n', BUFFER_SIZE);
	if (end == NULL) {
		msg(LOG_ERR, "Too long line?");
		return 1;
	}

	size = end - buff;
	*end = '\0';

	for (int i = size - 1 ; i >= 0 ; i--) {
		if (isspace((unsigned char)buff[i])) {
			delim = &buff[i];
			delims++;
		}
		if (delims >= MAX_DELIMS) {
			buff[i] = '\0';
			break;
		}
	}

	if (delim == NULL) {
		msg(LOG_ERR, "Malformed backend record: %s", buff);
		return 1;
	}

	record->idx = buff;
	record->idx_len = delim - buff;
	record->data = delim + 1;
	return 0;
}

/*
 * do_memfd_update - Populate the LMDB trust database from a backend memfd.
 *
 * Full rebuilds used to call write_db() once per backend record, which meant
 * one LMDB write transaction and one freelist/metadata commit per path. During
 * reload storms that can advance LMDB's high-water page number even when the
 * active trust set is unchanged. Import records in bounded chunks instead:
 * large enough to avoid per-record commit churn, but small enough that a
 * single transaction does not become the next map-pressure problem.
 *
 * Returns 0 when all records write successfully, 1 when reading fails, or a
 * WRITE_DB_* code when LMDB reports an import failure.
 */
int do_memfd_update(int memfd, long *entries)
{
	int rc = 0;
	*entries = 0;
	struct stat sb;
	char buff[BUFFER_SIZE];
	fd_fgets_state_t *st = fd_fgets_init();
	MDB_txn *txn = NULL;
	unsigned int txn_records = 0;
	unsigned long txns_committed = 0;

	if (st == NULL) {
		msg(LOG_ERR, "Failed to initialize buffered memfd reader");
		return 1;
	}

	// On any failure, fall back to descriptor based reads
	lseek(memfd, 0, SEEK_SET); /* rewind in case */
	if (fstat(memfd, &sb) == 0) {
		void *base = mmap(NULL, sb.st_size, PROT_READ,
				  MAP_PRIVATE, memfd, 0);
		if (base != MAP_FAILED)
			fd_setvbuf_r(st,base,sb.st_size,MEM_MMAP_FILE);
	}

	do {
		int res = fd_fgets_r(st, buff, sizeof(buff), memfd);
		if (res == -1) {
			msg(LOG_ERR, "fd_fgets_r on memfd (%s)",
			    strerror(errno));
			rc = 1;
			break;
		} else if (res > 0) {
			struct trust_db_record_input record;

			(*entries)++;

			if (trust_db_record_from_line(buff, &record))
				continue;

			if (txn == NULL) {
				res = trust_db_begin_write_txn(&txn,
						"bulk trust DB import");
				if (res) {
					rc = res;
					break;
				}
			}

			res = trust_db_put_record(txn, &record,
						  "bulk trust DB import");
			if (res) {
				abort_transaction(txn);
				txn = NULL;
				log_lmdb_state(LOG_ERR, "bulk trust DB import",
					       res == WRITE_DB_MAP_FULL ?
					       MDB_MAP_FULL : 0);
				msg(LOG_ERR,
				    "Error (%d) writing key=\"%s\" data=\"%s\"",
				    res, record.idx, record.data);
				if (rc == 0)
					rc = res;
				break;
			}

			txn_records++;
			if (txn_records >= TRUST_DB_REBUILD_TXN_RECORDS) {
				res = trust_db_commit_write_txn(&txn,
						"bulk trust DB import");
				if (res) {
					rc = res;
					break;
				}
				txns_committed++;
				txn_records = 0;
			}
		}
	} while (!fd_fgets_eof_r(st) && !stop);

	if (txn != NULL) {
		if (rc == 0 && !stop) {
			rc = trust_db_commit_write_txn(&txn,
					"bulk trust DB import");
			if (rc == 0)
				txns_committed++;
		} else {
			abort_transaction(txn);
			txn = NULL;
		}
	}

	if (rc == 0 && !stop && txns_committed)
		msg(LOG_DEBUG,
		    "Trust database bulk import committed %ld records in %lu transactions",
		    *entries, txns_committed);

	fd_fgets_destroy(st); // calls munmap, memfd is closed by backend_close

	return rc;
}

/*
 * create_database - Populate the LMDB trust database from loaded backends.
 * @with_sync: Non-zero forces an mdb_env_sync call to flush data immediately
 *             after populating the records. A zero value leaves flushing to
 *             the environment's normal durability policy.
 *
 * Each backend in the manager exposes its cached data through a memfd
 * snapshot. The function iterates over every backend and imports records
 * using do_memfd_update(), which writes in bounded LMDB transactions during
 * full rebuilds. Processing stops early when the global stop flag becomes
 * true or a backend import fails.
 *
 * Returns 0 when no backend reports an error and stop is not signaled.
 * Non-zero indicates that processing was interrupted or that a helper
 * reported a failure while storing records. Helper routines log detailed
 * errors.
 */
static int create_database(int with_sync, conf_t *config)
{
	msg(LOG_INFO, "Creating trust database");
	int rc = 0;
	int retries = 0;

	for (;;) {
		log_lmdb_state(LOG_DEBUG, "trust DB rebuild before import", 0);
		for (backend_entry *be = backend_get_first();
		     be != NULL && !stop; be = be->next ) {
			msg(LOG_INFO, "Loading trust data from %s backend",
			    be->backend->name);
			if (be->backend->memfd != -1) {
				rc = do_memfd_update(be->backend->memfd,
				     &be->backend->entries);
				if (rc)
					msg(LOG_ERR,
					    "Failed to import trust data from %s backend",
					    be->backend->name);
				if (rc)
					break;
			}
		}
		log_lmdb_state(rc ? LOG_ERR : LOG_DEBUG,
			       "trust DB rebuild after import",
			       rc == WRITE_DB_MAP_FULL ? MDB_MAP_FULL : 0);

		if (rc == WRITE_DB_MAP_FULL &&
		    config->do_audit_db_sizing && retries == 0) {
			if (grow_map_after_full(config) == 0 &&
			    delete_all_entries_db() == 0) {
				retries++;
				rc = 0;
				continue;
			}
		}

		break;
	}

	if (stop)
		return 1;

	// Flush everything to disk
	if (with_sync)
		mdb_env_sync(env, 1);

	// Check if database is getting full and warn
	check_db_size(config);

	return rc;
}


/*
 * check_data_presence - Look up an LMDB record and compare its stored data.
 * @read: active read handle.
 * @index: Key used for the LMDB lookup.
 * @data: Data string expected to be present for the key.
 * @matched: Updated with the number of duplicate records inspected.
 *
 * Returns 1 when an exact match is discovered, or 0 if the supplied data
 * cannot be located. Errors encountered by the LMDB read are logged separately.
 */
static int check_data_presence(struct trust_db_read_handle *handle,
			       const char *index, const char *data,
			       int *matched)
{
	int found = 0;
	int error;
	char *record;
	int operation = READ_DATA;
	int cnt = 0;

	while (1) {
		error = 0;
		record = NULL;
		record = trust_db_read_record(handle, index, operation,
					      &error);

		if (error)
			msg(LOG_DEBUG, "Error when reading from DB!");

		if (!record)
			break;

		// check strings
		if (strcmp(data, record) == 0) {
			found = 1;
		}

		free(record);
		cnt++;

		if (found)
			break;

		if (operation == READ_DATA)
			operation = READ_DATA_DUP;
	}

	*matched = cnt;
	return found;
}

long backend_added_entries = 0;
/*
 * check_from_memfd - Compare backend memfd contents with the LMDB database.
 * @read: active read handle used for all lookups.
 * @memfd: File descriptor providing newline-delimited backend records.
 * @entries: Location where the number of processed records is stored.
 *
 * Returns the number of discrepancies discovered between backend data and
 * the local LMDB copy while incrementing backend_added_entries for newly
 * observed records. Logs diagnostic information for missing or mismatched
 * entries.
 */
static long check_from_memfd(struct trust_db_read_handle *read, int memfd,
			     long *entries)
{
	*entries = 0;
	long problems = 0;
	struct stat sb;
	char buff[BUFFER_SIZE];
	fd_fgets_state_t *st = fd_fgets_init();

	if (st == NULL) {
		msg(LOG_ERR, "Failed to initialize buffered memfd reader");
		return 1;
	}

	// On any failure, fall back to descriptor based reads
	lseek(memfd, 0, SEEK_SET); /* rewind in case */
	if (fstat(memfd, &sb) == 0) {
		void *base = mmap(NULL, sb.st_size, PROT_READ,
				  MAP_PRIVATE, memfd, 0);
		if (base != MAP_FAILED)
			fd_setvbuf_r(st,base,sb.st_size,MEM_MMAP_FILE);
	}

	do {
		int res = fd_fgets_r(st, buff, sizeof(buff), memfd);
		if (res == -1) {
			msg(LOG_ERR, "fd_fgets_r on memfd (%s)",
			    strerror(errno));
			break;
		} else if (res > 0) {
			(*entries)++;
			char *end = fapolicyd_strnchr(buff, '\n', BUFFER_SIZE);
			if (end == NULL) {
				msg(LOG_ERR, "Too long line?");
				continue;
			}
			int size = end - buff;
			*end = '\0';

			// its better to parse it from the end because
			// there can be space in file name
			int delims = 0;
			char *delim = NULL;
			for (int i = size-1 ; i >= 0 ; i--) {
				if (isspace(buff[i])) {
					delim = &buff[i];
					delims++;
				}
				if (delims >= MAX_DELIMS) {
					buff[i] = '\0';
					break;
				}
			}

			if (delim == NULL) {
				msg(LOG_ERR, "Malformed backend record: %s",
				    buff);
				continue;
			}

			// We have everything, now do the check
			char *index = buff;
			char *data = delim + 1;
			int matched = 0;
			int found = check_data_presence(read, index, data,
							&matched);
			if (!found) {
				problems++;
				// missing in db
				// recently added file
				if (matched == 0) {
					msg(LOG_DEBUG,
					    "%s is not in the trust database",
					    index);
					backend_added_entries++;
				}

				// updated file
				// data miscompare
				if (matched > 0) {
					msg(LOG_DEBUG,
					    "Trust data miscompare for %s",
					    index);
				}
			}
		}
	} while (!fd_fgets_eof_r(st) && !stop);

	fd_fgets_destroy(st); // calls munmap, memfd is closed by backend_close

	return problems;
}

/*
 * check_database_copy - Validate LMDB contents against backend snapshots.
 *
 * Iterates each backend and invokes check_from_memfd to compare the cached
 * backend view with the local LMDB store. Summaries of the totals and
 * detected discrepancies are logged for diagnostics.
 *
 * Returns 0 when the databases agree, 1 when differences or an early stop are
 * encountered, and -1 when an unrecoverable error occurs.
 */
static int check_database_copy(const conf_t *config)
{
	struct trust_db_read_handle read;

	msg(LOG_INFO, "Checking if the trust database up to date");
	if (trust_db_read_open(&read))
		return -1;

	long problems = 0;
	long backend_total_entries = 0;
	backend_added_entries = 0;

	for (backend_entry *be = backend_get_first(); be != NULL && !stop;
						      be = be->next) {
		msg(LOG_INFO, "Importing trust data from %s backend",
		    be->backend->name);

		if (be->backend->memfd != -1) {
			problems += check_from_memfd(&read, be->backend->memfd,
						     &be->backend->entries);
			backend_total_entries += be->backend->entries;
		} else {
			msg(LOG_ERR,
			    "%s backend does not provide a memfd snapshot",
			    be->backend->name);
			problems++;
		}
	}

	trust_db_read_close(&read);
	if (stop)
		return 1;

	long db_total_entries = get_number_of_entries();
	// Is something wrong?
	if (db_total_entries == -1)
		return -1;

	msg(LOG_INFO, "Entries in trust DB: %ld", db_total_entries);

	// Check if database is getting full and warn
	check_db_size(config);

	msg(LOG_INFO,
	    "Loaded trust info from all backends (without duplicates): %ld",
	    backend_total_entries);

	// do not print 0
	if (backend_added_entries > 0)
		msg(LOG_INFO, "New trust database entries: %ld",
		    backend_added_entries);

	// db contains records that are not present in backends anymore
	long removed = labs(db_total_entries -
			    (backend_total_entries - backend_added_entries));

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
	char err_buff[BUFFER_SIZE];

	msg(LOG_INFO, "Initializing the trust database");

	// update_lock is used in update_database()
	pthread_rwlock_init(&update_lock, NULL);
	pthread_mutex_init(&rule_lock, NULL);
	update_lock_inited = 1;
	rule_lock_inited = 1;

	if (migrate_database())
		return 1;

	/* One-shot utilisation-driven sizing */
	if (config->do_audit_db_sizing &&
	    autosize_database(config, AUTOSIZE_STARTUP_INSPECTION))
		msg(LOG_INFO, "autosize: map size recomputed to %u MiB",
		    config->db_max_size);

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
		if ((rc = create_database(/*with_sync*/1, config))) {
			msg(LOG_ERR,
			"Failed to create trust database, create_database() (%d)",
			   rc);
			close_db(0);
			return rc;
		}
	} else {
		// check if our internal database is synced
		rc = check_database_copy(config);
		if (rc > 0) {
			rc = update_database(config);
			if (rc)
				msg(LOG_ERR,
				    "Failed updating the trust database");
		}
	}

	// Conserve memory by dumping unneeded resources
	backend_close();

	if (rc == 0) {
		rc = pthread_create(&update_thread, NULL, update_thread_main,
				    config);
		if (rc == 0)
			update_thread_created = 1;
		else
			msg(LOG_ERR, "Failed to create update thread (%s)",
			    strerror_r(rc, err_buff, sizeof(err_buff)));
	}

	return rc;
}


/*
 * read_trust_db - run trust lookup and optional integrity checks.
 * @read: private LMDB read handle for this lookup.
 * @lookup: path, file info, fd and error return storage.
 *
 * Returns 0 when no data is found or integrity failed, and 1 when the file is
 * found and trustworthy. Callers must check lookup->error before trusting the
 * result because not-found and integrity failure are both untrusted.
 */
static int read_trust_db(struct trust_db_read_handle *read,
			 struct trust_db_lookup *lookup)
{
	int do_integrity = 0, mode = READ_TEST_KEY;
	integrity_t integrity = decision_config_integrity(NULL);
	char *res;
	int retry = 0;
	char sha_xattr[FILE_DIGEST_STRING_MAX];
	char calc_digest[FILE_DIGEST_STRING_MAX];
	struct lmdb_record record;
	const char *path = lookup->path;
	struct file_info *info = lookup->info;
	int fd = lookup->fd;
	int *error = lookup->error;

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

	res = trust_db_read_record(read, path, mode, error);

	// For subjects we do a limited check because the process had to
	// pass some kind of trust check to even be started and we do not
	// have an open fd to the file.
	if (!do_integrity) {
		if (res == NULL)
			return 0;
		free(res);
		return 1;
	} else {
		// record not found
		if (res == NULL)
			return 0;

		if (parse_lmdb_record(res, &record)) {
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
			if (record.size == info->size) {
				return 1;
			} else {
				goto retry_res;
			}

		} else if (integrity == IN_IMA) {
			int rc = 1;
			char *hash = NULL;
			file_hash_alg_t ima_alg = FILE_HASH_ALG_NONE;

			// read xattr only the first time
			if (retry == 1)
				rc = get_ima_hash(fd, &ima_alg, sha_xattr);

			if (rc) {
				if ((record.size == info->size) &&
				(strcmp(record.digest,
				sha_xattr) == 0)) {
					file_info_cache_digest(info, ima_alg);
					strncpy(info->digest, sha_xattr,
						FILE_DIGEST_STRING_MAX-1);
					info->digest[FILE_DIGEST_STRING_MAX-1]=0;
					return 1;
				} else if (retry == 1 &&
						ima_alg != FILE_HASH_ALG_NONE) {
				/*
				 * Rehash using the IMA algorithm to separate
				 * metadata drift from content changes. This maps
				 * the enum to the hashing helper and caches the
				 * result for the FILE_HASH attribute to avoid
				 * repeating the costly recomputation.
				 */
				hash = get_hash_from_fd2(fd, info->size, ima_alg);
				if (hash) {
					strncpy(calc_digest, hash,
					FILE_DIGEST_STRING_MAX-1);
					calc_digest[FILE_DIGEST_STRING_MAX-1]=0;
					free(hash);
					file_info_cache_digest(info, ima_alg);
					strncpy(info->digest, calc_digest,
						FILE_DIGEST_STRING_MAX-1);
					info->digest[FILE_DIGEST_STRING_MAX-1]=0;
					if ((record.size == info->size) &&
					(strcmp(record.digest, calc_digest)==0))
						return 1;
				} else {
					*error = 1;
					return 0;
				}
				}

				log_ima_mismatch(path, record.alg, ima_alg);
				goto retry_res;

			} else {
				*error = 1;
				return 0;
			}

		} else if (integrity == IN_SHA256) {
			/*
			 * The name is historical; recomputation follows the
			 * stored digest algorithm (for example SHA512) while
			 * legacy fragments still default to SHA256 via
			 * parse_lmdb_record().
			 */
			size_t digest_len = file_hash_length(record.alg) * 2;

			char *hash = NULL;

			// Calculate a hash only one time
			if (retry == 1) {
				hash = get_hash_from_fd2(fd, info->size,
							 record.alg);
				if (hash) {
					strncpy(calc_digest, hash,
						FILE_DIGEST_STRING_MAX-1);
					calc_digest[FILE_DIGEST_STRING_MAX-1]=0;
					if (digest_len < FILE_DIGEST_STRING_MAX)
						calc_digest[digest_len] = 0;
					free(hash);
					file_info_cache_digest(info,
							       record.alg);
					strncpy(info->digest, calc_digest,
						FILE_DIGEST_STRING_MAX-1);
				     info->digest[FILE_DIGEST_STRING_MAX-1] = 0;
				} else {
					*error = 1;
					return 0;
				}
			}

			if ((record.size == info->size) &&
				    (strcmp(record.digest, calc_digest) == 0))
				return 1;
			else
				goto retry_res;
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
	struct trust_db_read_handle read;
	struct trust_db_lookup lookup;
	struct decision_timing_span lock_timing;
	struct decision_timing_span read_timing;
	struct decision_timing_span total_timing;

	trust_metric_add(&trust_metrics.lookups, 1);
	decision_timing_trust_db_stage_begin(DECISION_TIMING_TRUST_DB_TOTAL,
					     &total_timing);
	decision_timing_trust_db_stage_begin(
		DECISION_TIMING_TRUST_DB_LOCK_WAIT, &lock_timing);
	lock_trust_database_reader();
	decision_timing_stage_end(&lock_timing);

	decision_timing_trust_db_stage_begin(DECISION_TIMING_TRUST_DB_READ,
					     &read_timing);
	if (trust_db_read_open(&read)) {
		retval = -1;
		goto out_unlock;
	}

	lookup.path = path;
	lookup.info = info;
	lookup.fd = fd;
	lookup.error = &error;
	res = read_trust_db(&read, &lookup);
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
				lookup.path = &path[4];
				res = read_trust_db(&read, &lookup);
				if (error)
					retval = -1;
				else if (res)
					retval = 1;
			}
		}
	}

	trust_db_read_close(&read);
out_unlock:
	decision_timing_stage_end(&read_timing);
	unlock_trust_database_reader();
	decision_timing_stage_end(&total_timing);

	return retval;
}


void close_database(void)
{
	if (update_thread_created) {
		pthread_join(update_thread, NULL);
		update_thread_created = 0;
	}

	// we can close db when we are really sure update_thread does not exist
	close_db(1);
	if (update_lock_inited) {
		pthread_rwlock_destroy(&update_lock);
		update_lock_inited = 0;
	}
	if (rule_lock_inited) {
		pthread_mutex_destroy(&rule_lock);
		rule_lock_inited = 0;
	}

	backend_close();
	unlink_fifo();
}

/*
 * database_open_for_tests - Open LMDB for isolated unit test execution.
 * @config: Configuration providing map size and integrity mode.
 *
 * Returns 0 on success or the init_db return code on failure.
 */
int database_open_for_tests(conf_t *config)
{
	if (!update_lock_inited) {
		pthread_rwlock_init(&update_lock, NULL);
		update_lock_inited = 1;
	}

	if (!rule_lock_inited) {
		pthread_mutex_init(&rule_lock, NULL);
		rule_lock_inited = 1;
	}

	return init_db(config);
}

/*
 * database_close_for_tests - Close LMDB state opened via test helper API.
 *
 * Returns: none.
 */
void database_close_for_tests(void)
{
	close_db(0);

	if (update_lock_inited) {
		pthread_rwlock_destroy(&update_lock);
		update_lock_inited = 0;
	}

	if (rule_lock_inited) {
		pthread_mutex_destroy(&rule_lock);
		rule_lock_inited = 0;
	}
}


void unlink_fifo(void)
{
	unlink(fifo_path);
}


/*
 * lock_update_thread - take exclusive trust DB update ownership.
 *
 * Returns nothing.
 */
void lock_update_thread(void) {
	pthread_rwlock_wrlock(&update_lock);
	//msg(LOG_DEBUG, "lock_update_thread()");
}

/*
 * unlock_update_thread - release exclusive trust DB update ownership.
 *
 * Returns nothing.
 */
void unlock_update_thread(void) {
	pthread_rwlock_unlock(&update_lock);
	//msg(LOG_DEBUG, "unlock_update_thread()");
}

/*
 * lock_trust_database_reader - take shared trust DB read ownership.
 *
 * Returns nothing.
 */
static void lock_trust_database_reader(void)
{
	pthread_rwlock_rdlock(&update_lock);
}

/*
 * unlock_trust_database_reader - release shared trust DB read ownership.
 *
 * Returns nothing.
 */
static void unlock_trust_database_reader(void)
{
	pthread_rwlock_unlock(&update_lock);
}

/*
 * Lock wrapper for rule mutex
 */
void lock_rule(void) {
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
 * Unlock wrapper for rule mutex
 */
void unlock_rule(void) {
	if (!rule_lock_inited)
		return;
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
	int retries = 0;

	msg(LOG_INFO, "Updating trust database");
	msg(LOG_DEBUG, "Loading trust database backends");

	/*
	 * backend loading/reloading should be done in upper level
	 */
	if (stop)
		return 1;

	lock_update_thread();
	log_lmdb_state(LOG_DEBUG, "trust DB reload start", 0);

	rc = autosize_reload_preflight(config);
	if (rc) {
		msg(LOG_ERR, "Trust database reload preflight failed (%d)",
		    rc);
		unlock_update_thread();
		return UPDATE_DB_PRESERVED;
	}
	log_lmdb_state(LOG_DEBUG, "trust DB reload after preflight", 0);

	for (;;) {
		rc = delete_all_entries_db();
		if (rc == 0) {
			log_lmdb_state(LOG_DEBUG, "trust DB reload after drop",
				       0);
			break;
		}

		// The existing DB is still active because the drop did not
		// commit; grow auto-sized maps once before giving up.
		if (rc == WRITE_DB_MAP_FULL && config->do_audit_db_sizing &&
		    retries == 0 && grow_map_after_full(config) == 0) {
			retries++;
			continue;
		}

		msg(LOG_ERR, "Cannot delete database (%d)", rc);
		unlock_update_thread();
		/*
		 * delete_all_entries_db() failed before a transaction commit
		 * completed. The current LMDB contents are still the active
		 * trust database, so report the failed reload without killing
		 * the daemon.
		 */
		return UPDATE_DB_PRESERVED;
	}

	if (stop) {
		unlock_update_thread();
		return 1;
	}

	if (!stop)
		rc = create_database(/*with_sync*/0, config);
	else
		rc = 1;
	log_lmdb_state(rc ? LOG_ERR : LOG_DEBUG,
		       "trust DB reload after rebuild",
		       rc == WRITE_DB_MAP_FULL ? MDB_MAP_FULL : 0);

	// signal that cache need to be flushed
	if (!stop)
		atomic_store_explicit(&needs_flush, true,
				      memory_order_release);

	unlock_update_thread();
	mdb_env_sync(env, 1);

	if (rc) {
		msg(LOG_ERR, "Failed to create the trust database (%d)", rc);
		close_db(1);
		return rc;
	}

	return 0;
}

/*
 * handle_record - Process a single update command received from the FIFO.
 * @buffer: Raw line of text read from the update pipe. For file updates the
 *          buffer contains a path, file size, and SHA256 hash separated by
 *          whitespace.
 *
 * Returns 0 after successfully storing the record, 1 when processing should
 * stop due to malformed data or a shutdown request.
 */
static int handle_record(const char * buffer)
{
	char path[2048+1];
	char hash[64+1];
	unsigned long long ull_size;

	if (stop)
		return 1;

	// validating input
	int res = sscanf(buffer, "%2048s %llu %64s", path, &ull_size, hash);
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
		 ull_size, hash);

	msg(LOG_DEBUG, "update_thread: Saving %s %s", path, data);
	lock_update_thread();
	write_db(path, 0, data);
	unlock_update_thread();

	return 0;
}

/*
 * request_reload_trust_database - queue a trust DB reload if one is needed.
 * @source: short log label for the caller requesting reload.
 *
 * A trust DB reload rebuilds the database from the current backend snapshots.
 * If another request arrives while a reload is pending or already active, the
 * later request does not add more ordering information: both reloads would
 * consume the same current backend state by the time the update thread can
 * run them. Coalescing those duplicates avoids back-to-back drop/rebuild
 * cycles that only churn LMDB high-water pages and make map pressure worse.
 *
 * Returns 1 when a new request was queued, 0 when it was coalesced.
 */
static int request_reload_trust_database(const char *source)
{
	bool expected = false;

	if (atomic_load_explicit(&reload_db_active, memory_order_acquire)) {
		msg(LOG_INFO,
		    "Dropping trust database reload from %s: reload already active",
		    source);
		return 0;
	}

	if (!atomic_compare_exchange_strong_explicit(&reload_db, &expected,
					true, memory_order_acq_rel,
					memory_order_acquire)) {
		msg(LOG_INFO,
		    "Dropping trust database reload from %s: reload already pending",
		    source);
		return 0;
	}

	return 1;
}

void set_reload_trust_database(void)
{
	request_reload_trust_database("SIGHUP");
}

/*
 * record_trust_reload_failure - count a failed trust database reload.
 * @void: no arguments are required.
 *
 * Failed trust reloads currently keep compatibility behavior. The counter
 * gives later high-security profiles a single place to drive fail-closed or
 * degraded decisions.
 *
 * Returns nothing.
 */
static void record_trust_reload_failure(void)
{
	failure_action_record(FAILURE_REASON_TRUST_RELOAD_FAILURE);
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

	if (!atomic_compare_exchange_strong_explicit(&reload_db_active,
					&expected, true,
					memory_order_acq_rel,
					memory_order_acquire)) {
		msg(LOG_INFO,
		    "Dropping trust database reload from %s: reload already active",
		    source);
		return 0;
	}

	atomic_store_explicit(&reload_db, false, memory_order_release);
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

static void do_reload_db(conf_t* config)
{
	msg(LOG_INFO,
	    "It looks like there was an update of the system... Syncing DB.");

	int rc;
	unsigned int old_db_max_size = config->db_max_size;
	unsigned int old_reload_floor_mb = autosize_reload_floor_mb;

	backend_close();

	/* One-shot utilisation-driven sizing */
	if (config->do_audit_db_sizing &&
	    autosize_database(config, AUTOSIZE_LIVE_INSPECTION)) {
		msg(LOG_INFO, "autosize: map size recomputed to %u MiB",
			config->db_max_size);

		/*
		 * LMDB may unmap/remap the environment during resize. Use
		 * the same lock that protects decision reads and rebuild
		 * writes before touching the live map.
		 */
		if (config->db_max_size < old_db_max_size) {
			lock_update_thread();
			close_env(0);

			rc = init_db(config);
			unlock_update_thread();

			if (rc) {
				msg(LOG_ERR,
			     "Cannot open the trust database, init_db() (%d)",
					rc);
				if (stop)
					goto out;

				record_trust_reload_failure();
				close(ffd[0].fd);
				backend_close();
				unlink_fifo();
				exit(rc);
			}
		} else if (config->db_max_size > old_db_max_size) {
			lock_update_thread();
			rc = mdb_env_set_mapsize(env,
				(size_t)config->db_max_size * MEGABYTE);
			unlock_update_thread();
			if (rc) {
				config->db_max_size = old_db_max_size;
				autosize_reload_floor_mb = old_reload_floor_mb;
				msg(LOG_ERR,
					"env_set_mapsize error: %s",
					mdb_strerror(rc));
				record_trust_reload_failure();
				goto out;
			}
		}
	}

	if ((rc = backend_init(config))) {
		msg(LOG_ERR, "Failed to load trust data from backend (%d)", rc);
		record_trust_reload_failure();
		close_db(0);
		goto out;
	}

	if ((rc = backend_load(config))) {
		msg(LOG_ERR, "Failed to load data from backend (%d)", rc);
		record_trust_reload_failure();
		close_db(0);
		goto out;
	}

	if ((rc = update_database(config))) {
		msg(LOG_ERR,
			"Cannot update trust database!");
		if (stop)
			goto out;

		record_trust_reload_failure();
		if (rc == UPDATE_DB_PRESERVED) {
			// update_database() failed before clearing the live DB.
			// Keep running with the last successfully built trust set.
			msg(LOG_ERR,
			    "Previous trust database preserved after reload failure");
			goto out;
		}

		close(ffd[0].fd);
		backend_close();
		unlink_fifo();
		exit(rc);
	}

	msg(LOG_INFO, "Updated");

out:
	// Conserve memory
	backend_close();
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

	do_reload_db(config);
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

static void *update_thread_main(void *arg)
{
	int rc;
	int flags;
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

	/*
	 * fd_fgets_r() must not block if poll readiness is consumed or only
	 * a partial line is available.
	 */
	flags = fcntl(ffd[0].fd, F_GETFL);
	if (flags == -1) {
		msg(LOG_ERR, "Failed to read pipe flags (%s)",
		    strerror_r(errno, err_buff, BUFFER_SIZE));
		goto finalize;
	}
	if (fcntl(ffd[0].fd, F_SETFL, flags | O_NONBLOCK) == -1) {
		msg(LOG_ERR, "Failed to set non-blocking pipe mode (%s)",
		    strerror_r(errno, err_buff, BUFFER_SIZE));
		goto finalize;
	}
	ffd[0].events = POLLIN;

	while (!stop) {
		int trust_reload_done_this_cycle = 0;

		/*
		 * The FIFO connected at ffd[0] carries update commands from
		 * fapolicy-cli and backend helper processes. Commands may be
		 * the single-character control values defined in paths.h
		 * (for example RELOAD_TRUSTDB_COMMAND) or full path entries
		 * emitted by the backend notifier when a package manager
		 * changes a file.
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
				fd_fgets_state_t *st = fd_fgets_init();
				if (st == NULL) {
					msg(LOG_ERR,
				  "Failed to initialize buffered FIFO reader");
					break;
				}
				do {
					if (stop)
						break;
					int res = fd_fgets_r(st, buff,
						sizeof(buff), ffd[0].fd);

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
							/*
							 * Identify the requested action by scanning
							 * the buffer. Control characters map directly
							 * to db_ops_t values while a leading slash
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

							if (isspace((unsigned char)buff[i]))
								continue;

							msg(LOG_ERR, "Cannot handle data \"%s\" from pipe", buff);
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
							 * The rules command instructs the
							 * daemon to re-parse policy files.
							 */
							do_operation = DB_NO_OP;
							reload_rules_from_file(config);

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
							if (handle_record(buff))
								continue;
						}
					}

				} while(!fd_fgets_eof_r(st) && !stop);
				fd_fgets_destroy(st);
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
	rc = mdb_txn_begin(env, NULL, MDB_RDONLY, &walk_read.txn);
	if (rc) {
		trust_db_record_reader_error(rc);
		puts(mdb_strerror(rc));
		return 1;
	}

	if ((rc = open_dbi(walk_read.txn))) {
		puts(mdb_strerror(rc));
		abort_transaction(walk_read.txn);
		memset(&walk_read, 0, sizeof(walk_read));
		return 1;
	}

	if ((rc = mdb_cursor_open(walk_read.txn, dbi, &walk_read.cursor))) {
		puts(mdb_strerror(rc));
		abort_transaction(walk_read.txn);
		memset(&walk_read, 0, sizeof(walk_read));
		return 1;
	}

	if ((rc = mdb_cursor_get(walk_read.cursor, &wdb_entry.path,
							&wdb_entry.data,
							MDB_FIRST)) == 0)
		return 0;

	if (rc != MDB_NOTFOUND)
		puts(mdb_strerror(rc));

	trust_db_read_close(&walk_read);
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

	if ((rc = mdb_cursor_get(walk_read.cursor, &wdb_entry.path,
							&wdb_entry.data,
							MDB_NEXT)) == 0)
		return 1;

	if (rc != MDB_NOTFOUND)
		puts(mdb_strerror(rc));

	return 0;
}

void walk_database_finish(void)
{
	trust_db_read_close(&walk_read);
	close_db(0);
}
