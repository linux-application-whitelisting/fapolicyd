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
#include <pthread.h>
#include <errno.h>
#include <limits.h>
#include <unistd.h>
#include <fcntl.h>
#include <openssl/sha.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <time.h>
#include <ctype.h>	/* isspace() */

#include "database.h"
#include "database-internal.h"
#include "daemon-config.h"
#include "decision-config.h"
#include "decision-timing.h"
#include "event.h"
#include "failure-action.h"
#include "message.h"
#include "file.h"
#include "fd-fgets.h"
#include "string-util.h"
#include "fapolicyd-backend.h"
#include "backend-manager.h"
#include "gcc-attributes.h"
#include "paths.h"

// Local defines
enum { READ_DATA, READ_TEST_KEY, READ_DATA_DUP };
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
#define TRUST_DB_RELOAD_HIGHWATER_PERCENT 80
#define TRUST_DB_SHRINK_TRIGGER_PERCENT 65
#define TRUST_DB_SHRINK_HYSTERESIS_PERCENT 90
#define TRUST_DB_RELOAD_WORK_FACTOR 2
#define TRUST_DB_REBUILD_TXN_RECORDS 4096
#define TRUST_DB_GENERATION_SLOT_PREFIX "trust.slot"
#define TRUST_DB_GENERATION_DB_SLOTS 32
/*
 * mdb_env_set_maxdbs() sizes LMDB's named-DB slot table for each
 * transaction, and mdb_dbi_open() searches opened slots linearly. Keep the
 * cap close to the reusable trust generation slots while leaving room for
 * metadata, old DB names during migration, and future small additions.
 */
#define TRUST_DB_RESERVED_NAMED_DBS 8
#define TRUST_DB_MAX_NAMED_DBS \
	(TRUST_DB_GENERATION_DB_SLOTS + TRUST_DB_RESERVED_NAMED_DBS)
#define TRUST_DB_COMPACT_REASON_SIZE 160
/*
 * Trust database generation lifecycle
 * ===================================
 *
 * The trust database is stored in one LMDB environment with multiple named
 * databases. The small metadata database named TRUST_DB_METADATA_NAME stores
 * TRUST_DB_METADATA_KEY, whose value identifies the currently published named
 * database, the daemon-local generation number, entry count, publish time, and
 * sizing snapshot. The named database in metadata is durable. The generation
 * number is deliberately a daemon-runtime epoch, like config and ruleset
 * generations, so startup reports begin at generation 1.
 *
 * Startup path:
 * - init_database() performs migration and startup autosizing, then calls
 *   init_db().
 * - init_db() opens LMDB and calls init_dbi().
 * - init_dbi() opens the metadata DB, reads the persisted active named DB if
 *   present, opens that named DB, and publishes it in memory as generation 1.
 *   It ignores the persisted generation number because that belonged to the
 *   previous daemon run, then rewrites metadata with generation 1.
 * - backend_load() builds backend snapshots. database_empty() populates a new
 *   empty DB in place as generation 1. If check_database_copy() finds a
 *   mismatch in an existing DB, init_database() calls update_database(config,
 *   1), which resets next_generation so the startup rebuild also publishes
 *   generation 1.
 *
 * Runtime reload path:
 * - database-update.c coalesces external reload requests from SIGHUP, the
 *   update FIFO, and fapolicy-cli into database_reload_from_backends().
 * - database_reload_from_backends() refreshes backends and calls
 *   update_database(config, 0).
 *   update_database() runs autosize_reload_preflight(), creates a candidate
 *   generation, imports all backend records, publishes only a complete
 *   candidate, and requests a cache flush on success.
 *
 * Candidate creation and publication:
 * - create_candidate_generation() chooses a bounded reusable LMDB slot name
 *   through trust_db_candidate_name(). Slots are named with
 *   TRUST_DB_GENERATION_SLOT_PREFIX and are skipped while active or retired
 *   generations still reference them.
 * - create_database_for_generation() populates the candidate from backend
 *   memfd snapshots using do_memfd_update_to_dbi(). Imports are chunked by
 *   TRUST_DB_REBUILD_TXN_RECORDS so large rebuilds do not hold one huge write
 *   transaction.
 * - Failed imports call drop_candidate_generation(); active_generation and
 *   metadata are unchanged, so readers keep using the last complete DB.
 * - publish_candidate_generation() writes metadata for the candidate in one
 *   LMDB transaction. Only after that commit succeeds does it swap
 *   active_generation and dbi under generation_lock. The old generation is
 *   moved to retired_generations with retired_time set.
 *
 * Reader safety and reclamation:
 * - Decision lookups call trust_db_read_open(), which acquires the active
 *   generation via trust_db_generation_acquire() before opening the LMDB read
 *   transaction and cursor. trust_db_read_close() releases that reference.
 * - Retired generations remain open while their readers count is non-zero.
 *   trust_db_reclaim_retired() drops the LMDB named database only after all
 *   daemon-local readers drain. If drop fails, the retired generation is put
 *   back on the list so it is retried later instead of being forgotten.
 * - CLI maintenance readers open their own MDB_RDONLY environment but still use
 *   LMDB's reader table. They do not pin daemon generation structs, so LMDB
 *   must keep their old transaction pages from being reused after reload.
 *
 * LMDB environment generations:
 * - Trust DB generations are logical content epochs inside one open LMDB
 *   environment. They solve normal reload publication: new decisions can move
 *   to a complete named database while old decisions finish on the previous
 *   named database.
 * - LMDB environment generations are physical storage epochs. They advance
 *   only when fapolicyd closes the live environment and reopens a replacement
 *   data.mdb. This is intentionally rarer than trust DB generation publish
 *   because the environment contains LMDB's page allocation history, free
 *   list, reader table relationship, and map high-water mark.
 * - Offline rebuild uses backend memfd snapshots as the source of truth,
 *   writes a complete replacement environment in a temporary directory,
 *   validates that environment, and then swaps it during a controlled window
 *   where decision readers are blocked and the live environment is closed.
 *   If validation, rename, or reopen fails, the previous data.mdb is kept or
 *   restored before readers are released.
 * - The two generation layers complement each other. Normal reloads should
 *   stay on the logical trust DB generation path because it keeps the hot path
 *   available. Offline environment replacement is for compaction and
 *   high-water reset after LMDB allocation churn, not for ordinary reload
 *   publication.
 *
 * Operator and QE signals:
 * - database_generation_snapshot() feeds the status and metrics headers with
 *   the active trust DB generation and entry count.
 * - The same header also reports the active LMDB environment generation so an
 *   operator can distinguish a normal trust-data publish from a physical
 *   environment replacement.
 * - database_utilization_report() reports active pages, allocated high-water
 *   pages, retired generation count, oldest retired age, and max reclaim
 *   delay. Stable active pages with growing high-water pages point at LMDB
 *   reload working-set pressure. Non-zero retired count or growing oldest age
 *   means readers are holding old generations. Max reclaim delay shows the
 *   worst observed reader drain delay. Manual db_max_size deployments also
 *   get a resize recommendation here when the map is below the same safe
 *   reload target that auto sizing would use.
 * - Auto sizing retries one MDB_MAP_FULL reload after growing the live map.
 *   If an earlier bounded shrink target was too small for LMDB's current
 *   allocation history, that emergency grow starts from the actual live map
 *   size, not the stale configured target, and records a reload floor so later
 *   live inspections do not immediately pick the same bad size again.
 * - database_metrics_report_reset() reports trust lookup count and reader-slot
 *   exhaustion. Reader-slot exhaustion indicates max reader pressure, not a
 *   generation leak.
 *
 * Sizing knobs:
 * - TRUST_DB_ACTIVE_TARGET_PERCENT targets steady-state active-page usage.
 *   Lowering it uses more disk for ordinary growth headroom.
 * - TRUST_DB_RELOAD_WORK_FACTOR models how many active-sized copies must fit
 *   during a full rebuild. It is 2 for current generation plus candidate.
 *   Change it only if the reload algorithm starts keeping more or fewer full
 *   copies live at once.
 * - TRUST_DB_RELOAD_HIGHWATER_PERCENT targets the bounded reload working set.
 *   Lowering it grows the map and gives reload storms more room. Raising it
 *   saves disk but increases MDB_MAP_FULL risk. Tune with repeated HUP reload
 *   tests and watch allocated high-water pages converge.
 * - TRUST_DB_SHRINK_TRIGGER_PERCENT and TRUST_DB_SHRINK_HYSTERESIS_PERCENT
 *   keep auto shrink conservative so the daemon does not oscillate map size
 *   during reload churn.
 * - TRUST_DB_GENERATION_DB_SLOTS bounds reusable named databases. Increase it
 *   only if tests show many held readers pin more retired generations than
 *   available slots. TRUST_DB_MAX_NAMED_DBS must stay comfortably above the
 *   slot count plus metadata and any legacy DB name.
 */
// Local variables
static MDB_env *env;
static MDB_dbi dbi;
static MDB_dbi metadata_dbi;
static int dbi_init = 0;
static int metadata_dbi_init = 0;
static unsigned int db_max_readers;
static unsigned MDB_maxkeysize;
static const char *data_dir = DB_DIR;
static const char *db = DB_NAME;
static int lib_symlink=0, lib64_symlink=0, bin_symlink=0, sbin_symlink=0;
static unsigned int autosize_reload_floor_mb;
static unsigned int startup_compaction_target_mb;
static unsigned int startup_compaction_fallback_mb;
/*
 * IMA mismatch logging policy: five LOG_ERR entries, five LOG_CRIT entries,
 * one silence notice, then suppression to protect syslog from floods.
 */
static unsigned int ima_mismatch_err_budget = 5;
static unsigned int ima_mismatch_crit_budget = 5;
static int ima_mismatch_silenced;

static pthread_mutex_t generation_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t generation_reclaim_lock = PTHREAD_MUTEX_INITIALIZER;

struct trust_db_read_handle {
	MDB_txn *txn;
	MDB_cursor *cursor;
	struct trust_db_generation *generation;
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
static MDB_env *readonly_lookup_env;
static MDB_dbi readonly_lookup_dbi;
static int readonly_lookup_open;

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

struct trust_db_metadata {
	unsigned long generation;
	char name[TRUST_DB_GENERATION_NAME_SIZE];
	long entries;
	time_t publish_time;
};

struct trust_db_generation {
	unsigned long generation;
	char name[TRUST_DB_GENERATION_NAME_SIZE];
	MDB_dbi handle;
	unsigned long readers;
	long entries;
	time_t publish_time;
	struct trust_db_sizing_state sizing;
	time_t retired_time;
	struct trust_db_generation *next;
};

struct lmdb_environment_generation {
	unsigned long generation;
	time_t publish_time;
};

struct offline_lmdb {
	char tmpdir[PATH_MAX];
	MDB_env *env;
	MDB_dbi metadata_dbi;
	MDB_dbi trust_dbi;
	unsigned int maxkeysize;
	long entries;
	unsigned long trust_generation;
	unsigned long env_generation;
};

static struct trust_db_generation *active_generation;
static struct trust_db_generation *retired_generations;
static unsigned long next_generation = 1;
static unsigned long max_generation_reclaim_delay;
static pthread_mutex_t lmdb_environment_lock = PTHREAD_MUTEX_INITIALIZER;
static struct lmdb_environment_generation lmdb_environment = {
	.generation = 0,
	.publish_time = 0,
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
static int update_database(conf_t *config, int startup_rebuild);
static int write_db(const char *idx, size_t idx_len, const char *data)
	__attr_access ((__read_only__, 1, 2))  __wur;
static int refresh_active_generation_metadata(void);
static struct trust_db_generation *trust_db_generation_acquire(void);
static void trust_db_generation_release(struct trust_db_generation *gen);
static void trust_db_reclaim_retired(void);
static int compact_trust_database(conf_t *config, const char *source_name);
static int init_db_with_generations(const conf_t *config,
	unsigned long trust_generation, unsigned long env_generation);
static void check_db_size(const conf_t *config);
static int trust_db_record_from_line(char *buff,
	struct trust_db_record_input *record);
static int trust_db_key_init_with_max(struct trust_db_key *key,
	const char *idx, size_t idx_len, unsigned int maxkeysize);
static void trust_db_key_destroy(struct trust_db_key *key);
static int do_memfd_update_to_dbi_in_env(MDB_env *target_env, int memfd,
	MDB_dbi target_dbi, unsigned int maxkeysize, long *entries);
static void close_env(int do_close_dbi);
static void log_lmdb_state(int priority, const char *context, int lmdb_rc);
static void walk_database_reset(void);
static int check_trust_database_with_read(struct trust_db_read_handle *read,
	const char *path, struct file_info *info, int fd);

// External variables
extern atomic_bool stop;


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
	if (env == NULL) {
		pthread_mutex_lock(&generation_lock);
		next_generation = 1;
		max_generation_reclaim_delay = 0;
		pthread_mutex_unlock(&generation_lock);
		pthread_mutex_lock(&lmdb_environment_lock);
		lmdb_environment.generation = 0;
		lmdb_environment.publish_time = 0;
		pthread_mutex_unlock(&lmdb_environment_lock);
	}

	return 0;
}

unsigned get_default_db_max_size(void)
{
	return DEFAULT_DB_MAX_SIZE_MB; /* 100 MiB baseline */
}

/*
 * configured_reader_limit - compute LMDB reader slots to reserve.
 * @config: active daemon configuration.
 *
 * Returns the number of LMDB reader slots requested for the environment.
 */
static unsigned int configured_reader_limit(const conf_t *config)
{
	return daemon_config_lmdb_reader_limit(config);
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
 * lmdb_environment_publish - update the physical LMDB environment epoch.
 * @generation: generation number to report.
 *
 * Trust DB generations describe logical content publication. This environment
 * generation describes the currently opened data.mdb file. It starts at one
 * for a daemon run and advances only after controlled environment replacement.
 */
static void lmdb_environment_publish(unsigned long generation)
{
	pthread_mutex_lock(&lmdb_environment_lock);
	lmdb_environment.generation = generation;
	lmdb_environment.publish_time = time(NULL);
	pthread_mutex_unlock(&lmdb_environment_lock);
}

/*
 * lmdb_environment_next_generation - return the next environment epoch.
 *
 * The caller uses this before closing the old environment so the replacement
 * reopen can publish a monotonic physical generation after it succeeds.
 */
static unsigned long lmdb_environment_next_generation(void)
{
	unsigned long generation;

	pthread_mutex_lock(&lmdb_environment_lock);
	generation = lmdb_environment.generation + 1;
	if (generation == 0)
		generation = 1;
	pthread_mutex_unlock(&lmdb_environment_lock);

	return generation;
}

/*
 * lmdb_environment_snapshot - copy the current physical environment epoch.
 * @generation: destination generation value.
 * @publish_time: destination effective timestamp.
 */
static void lmdb_environment_snapshot(unsigned long *generation,
				      time_t *publish_time)
{
	pthread_mutex_lock(&lmdb_environment_lock);
	if (generation)
		*generation = lmdb_environment.generation;
	if (publish_time)
		*publish_time = lmdb_environment.publish_time;
	pthread_mutex_unlock(&lmdb_environment_lock);
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
	/*
	 * me_last_pgno is LMDB's file high-water mark. It is useful for
	 * seeing that reload churn has touched most of the map, but it is not
	 * the same as live trust data. If auto sizing chases that monotonic
	 * high-water mark directly, every drop/rebuild can make the next
	 * target slightly larger even when the backend entry set is unchanged.
	 *
	 * Generation publication keeps the active DB live while a candidate
	 * named DB is populated. Size reload work for both copies. This gives
	 * the candidate room to complete without turning old file high-water
	 * growth into permanent map growth.
	 */
	state->reload_work_pages = pages_times(state->active_pages,
					TRUST_DB_RELOAD_WORK_FACTOR);
	if (state->reload_work_pages < state->active_pages)
		state->reload_work_pages = state->active_pages;

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
 * The reload target keeps a bounded copy-on-write working set below 80
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
	struct trust_db_generation *gen;
	int rc;

	rc = mdb_env_info(env, &info);
	if (rc)
		return rc;

	gen = trust_db_generation_acquire();
	if (gen == NULL)
		return EINVAL;

	rc = mdb_txn_begin(env, NULL, MDB_RDONLY, &txn);
	if (rc) {
		trust_db_generation_release(gen);
		return rc;
	}

	rc = fill_lmdb_sizing_state(txn, gen->handle, &info, state);
	mdb_txn_abort(txn);
	trust_db_generation_release(gen);
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
	char active_name[TRUST_DB_GENERATION_NAME_SIZE];
	int rc;

	rc = mdb_env_create(&tmp_env);
	if (rc)
		return rc;

	rc = mdb_env_set_maxdbs(tmp_env, TRUST_DB_MAX_NAMED_DBS);
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

	rc = database_read_active_name(txn, active_name, sizeof(active_name));
	if (rc)
		goto out_abort;

	rc = mdb_dbi_open(txn, active_name, 0, &dbi_tmp);
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
 * trust_db_generation_alloc - create in-memory state for one named DB.
 * @generation: Monotonic generation number associated with the DB.
 * @name: LMDB named database that stores this generation's trust records.
 *
 * Returns a new generation object, or NULL on allocation/name errors.
 */
static struct trust_db_generation *trust_db_generation_alloc(
		unsigned long generation, const char *name)
{
	struct trust_db_generation *gen;

	if (name == NULL || name[0] == 0 ||
	    strlen(name) >= TRUST_DB_GENERATION_NAME_SIZE)
		return NULL;

	gen = calloc(1, sizeof(*gen));
	if (gen == NULL)
		return NULL;

	gen->generation = generation;
	snprintf(gen->name, sizeof(gen->name), "%s", name);
	return gen;
}

/*
 * trust_db_generation_slot_name - format one reusable LMDB generation slot.
 * @slot: Bounded slot number to include in the name.
 * @name: Destination buffer.
 *
 * Returns 0 on success or ENAMETOOLONG.
 */
static int trust_db_generation_slot_name(unsigned int slot,
				    char name[TRUST_DB_GENERATION_NAME_SIZE])
{
	int len;

	len = snprintf(name, TRUST_DB_GENERATION_NAME_SIZE, "%s_%u",
		       TRUST_DB_GENERATION_SLOT_PREFIX, slot);
	if (len < 0 || len >= TRUST_DB_GENERATION_NAME_SIZE)
		return ENAMETOOLONG;
	return 0;
}

/*
 * trust_db_generation_name_in_use - check active/retired generation names.
 * @name: Candidate LMDB named database.
 *
 * generation_lock must be held by the caller.
 *
 * Returns 1 when an active or retired reader may still reference @name.
 */
static int trust_db_generation_name_in_use(const char *name)
{
	struct trust_db_generation *gen;

	if (active_generation && strcmp(active_generation->name, name) == 0)
		return 1;

	for (gen = retired_generations; gen; gen = gen->next) {
		if (strcmp(gen->name, name) == 0)
			return 1;
	}

	return 0;
}

/*
 * trust_db_candidate_name - choose a reusable LMDB named DB slot.
 * @name: Destination buffer.
 *
 * generation_lock must be held by the caller.
 *
 * Returns 0 on success, EBUSY if every bounded slot is pinned by an active or
 * retired generation, or a formatting error.
 */
static int trust_db_candidate_name(char name[TRUST_DB_GENERATION_NAME_SIZE])
{
	char slot_name[TRUST_DB_GENERATION_NAME_SIZE];
	unsigned int slot;
	int rc;

	for (slot = 0; slot < TRUST_DB_GENERATION_DB_SLOTS; slot++) {
		rc = trust_db_generation_slot_name(slot, slot_name);
		if (rc)
			return rc;
		if (trust_db_generation_name_in_use(slot_name))
			continue;
		snprintf(name, TRUST_DB_GENERATION_NAME_SIZE, "%s", slot_name);
		return 0;
	}

	return EBUSY;
}

/*
 * trust_db_metadata_parse - parse the current-generation metadata value.
 * @data: NUL-terminated metadata value.
 * @metadata: Destination metadata.
 *
 * Returns 0 when at least generation and DB name were parsed.
 */
static int trust_db_metadata_parse(const char *data,
				   struct trust_db_metadata *metadata)
{
	char *copy, *line, *save = NULL;
	int have_generation = 0, have_name = 0;

	memset(metadata, 0, sizeof(*metadata));
	copy = strdup(data);
	if (copy == NULL)
		return 1;

	for (line = strtok_r(copy, "\n", &save); line;
	     line = strtok_r(NULL, "\n", &save)) {
		if (sscanf(line, "generation=%lu",
			   &metadata->generation) == 1) {
			have_generation = 1;
		} else if (strncmp(line, "name=", 5) == 0) {
			snprintf(metadata->name, sizeof(metadata->name),
				 "%s", line + 5);
			have_name = metadata->name[0] != 0;
		} else if (sscanf(line, "entries=%ld",
				  &metadata->entries) == 1) {
			continue;
		} else {
			long long publish_time;

			if (sscanf(line, "publish_time=%lld",
				   &publish_time) == 1)
				metadata->publish_time = (time_t)publish_time;
		}
	}

	free(copy);
	return !(have_generation && have_name);
}

/*
 * trust_db_metadata_read_from_dbi - read current-generation metadata.
 * @txn: active transaction.
 * @source_dbi: metadata DBI in the same environment as @txn.
 * @metadata: destination metadata.
 *
 * Offline rebuild validation cannot use the daemon globals because it opens a
 * temporary LMDB environment beside the live one. Keep the metadata parser
 * shared and pass the DBI explicitly so live and offline readers validate the
 * same publication record.
 */
static int trust_db_metadata_read_from_dbi(MDB_txn *txn, MDB_dbi source_dbi,
					   struct trust_db_metadata *metadata)
{
	MDB_val key, value;
	char data[BUFFER_SIZE];
	int rc;

	key.mv_data = (void *)TRUST_DB_METADATA_KEY;
	key.mv_size = sizeof(TRUST_DB_METADATA_KEY) - 1;
	rc = mdb_get(txn, source_dbi, &key, &value);
	if (rc)
		return rc;
	if (value.mv_size >= sizeof(data))
		return EINVAL;

	memcpy(data, value.mv_data, value.mv_size);
	data[value.mv_size] = 0;
	if (trust_db_metadata_parse(data, metadata))
		return EINVAL;
	return 0;
}

/*
 * database_read_active_name - read the currently published trust DB name.
 * @txn: read transaction for an LMDB environment containing trust metadata.
 * @name: destination buffer.
 * @name_size: size of @name.
 *
 * Older trust databases did not have generation metadata, so missing metadata
 * falls back to the default DB name. Present but unreadable metadata is an
 * error because otherwise callers may inspect a stale generation.
 */
int database_read_active_name(MDB_txn *txn, char *name, size_t name_size)
{
	MDB_dbi active_metadata_dbi;
	struct trust_db_metadata metadata;
	int len;
	int rc;

	if (name_size == 0)
		return EINVAL;

	len = snprintf(name, name_size, "%s", db);
	if (len < 0 || len >= (int)name_size)
		return ENAMETOOLONG;

	rc = mdb_dbi_open(txn, TRUST_DB_METADATA_NAME, 0,
			  &active_metadata_dbi);
	if (rc == MDB_NOTFOUND)
		return 0;
	if (rc)
		return rc;

	rc = trust_db_metadata_read_from_dbi(txn, active_metadata_dbi,
					     &metadata);
	if (rc == MDB_NOTFOUND)
		return 0;
	if (rc)
		return rc;

	len = snprintf(name, name_size, "%s", metadata.name);
	if (len < 0 || len >= (int)name_size)
		return ENAMETOOLONG;
	return 0;
}

/*
 * trust_db_metadata_read - read current-generation metadata from live LMDB.
 * @txn: Active transaction.
 * @metadata: Destination metadata.
 *
 * Returns 0 on success, MDB_NOTFOUND when metadata is absent, or an LMDB/
 * parse error code.
 */
static int trust_db_metadata_read(MDB_txn *txn,
				  struct trust_db_metadata *metadata)
{
	if (!metadata_dbi_init)
		return EINVAL;

	return trust_db_metadata_read_from_dbi(txn, metadata_dbi, metadata);
}

/*
 * trust_db_metadata_write_to_env - persist publication metadata.
 * @target_env: LMDB environment containing @txn.
 * @target_metadata_dbi: metadata DBI in @target_env.
 * @txn: Writable transaction that makes the metadata visible atomically.
 * @gen: Generation being published or refreshed.
 *
 * Returns 0 on success or an LMDB/formatting error.
 */
static int trust_db_metadata_write_to_env(MDB_env *target_env,
					  MDB_dbi target_metadata_dbi,
					  MDB_txn *txn,
					  struct trust_db_generation *gen)
{
	MDB_envinfo info;
	MDB_val key, value;
	char data[BUFFER_SIZE];
	int len, rc;

	rc = mdb_env_info(target_env, &info);
	if (rc)
		return rc;

	rc = fill_lmdb_sizing_state(txn, gen->handle, &info, &gen->sizing);
	if (rc)
		return rc;

	gen->entries = (long)gen->sizing.entries;
	if (gen->publish_time == 0)
		gen->publish_time = time(NULL);

	len = snprintf(data, sizeof(data),
		       "generation=%lu\n"
		       "name=%s\n"
		       "entries=%ld\n"
		       "publish_time=%lld\n"
		       "page_size=%zu\n"
		       "map_pages=%zu\n"
		       "active_pages=%zu\n"
		       "allocated_pages=%zu\n"
		       "reload_work_pages=%zu\n"
		       "recommended_pages=%zu\n",
		       gen->generation, gen->name, gen->entries,
		       (long long)gen->publish_time, gen->sizing.page_size,
		       gen->sizing.map_pages, gen->sizing.active_pages,
		       gen->sizing.allocated_pages,
		       gen->sizing.reload_work_pages,
		       gen->sizing.recommended_pages);
	if (len < 0 || len >= (int)sizeof(data))
		return ENAMETOOLONG;

	key.mv_data = (void *)TRUST_DB_METADATA_KEY;
	key.mv_size = sizeof(TRUST_DB_METADATA_KEY) - 1;
	value.mv_data = data;
	value.mv_size = len;
	return mdb_put(txn, target_metadata_dbi, &key, &value, 0);
}

/*
 * trust_db_metadata_write - persist live current-generation metadata.
 * @txn: writable transaction that makes the metadata visible atomically.
 * @gen: generation being published or refreshed.
 *
 * Returns 0 on success or an LMDB/formatting error.
 */
static int trust_db_metadata_write(MDB_txn *txn,
				   struct trust_db_generation *gen)
{
	return trust_db_metadata_write_to_env(env, metadata_dbi, txn, gen);
}

/*
 * trust_db_generation_acquire - pin the current trust DB generation.
 *
 * Returns the active generation with its reader count incremented, or NULL
 * when no trust DB has been initialized.
 */
static struct trust_db_generation *trust_db_generation_acquire(void)
{
	struct trust_db_generation *gen;

	pthread_mutex_lock(&generation_lock);
	gen = active_generation;
	if (gen)
		gen->readers++;
	pthread_mutex_unlock(&generation_lock);
	return gen;
}

/*
 * trust_db_generation_release - release a pinned trust DB generation.
 * @gen: Generation returned by trust_db_generation_acquire().
 *
 * Returns nothing.
 */
static void trust_db_generation_release(struct trust_db_generation *gen)
{
	if (gen == NULL)
		return;

	pthread_mutex_lock(&generation_lock);
	if (gen->readers)
		gen->readers--;
	pthread_mutex_unlock(&generation_lock);

	trust_db_reclaim_retired();
}

/*
 * drop_generation_database - delete a retired named DB from LMDB.
 * @gen: Retired generation with no readers.
 *
 * Returns 0 on success or an LMDB error code.
 */
static int drop_generation_database(struct trust_db_generation *gen)
{
	MDB_txn *txn = NULL;
	int rc;

	rc = mdb_txn_begin(env, NULL, 0, &txn);
	if (rc)
		return rc;

	rc = mdb_drop(txn, gen->handle, 1);
	if (rc) {
		mdb_txn_abort(txn);
		return rc;
	}

	rc = mdb_txn_commit(txn);
	if (rc)
		return rc;

	return 0;
}

/*
 * trust_db_reclaim_retired - drop retired generations that have no readers.
 *
 * Returns nothing. Failed drops are left on the retired list for a later
 * attempt so old generations are never forgotten before LMDB deletes them.
 */
static void trust_db_reclaim_retired(void)
{
	struct trust_db_generation *gen, **link;
	time_t now;
	int rc;

	if (env == NULL)
		return;

	pthread_mutex_lock(&generation_reclaim_lock);
	for (;;) {
		gen = NULL;
		pthread_mutex_lock(&generation_lock);
		for (link = &retired_generations; *link;
		     link = &(*link)->next) {
			if ((*link)->readers == 0) {
				gen = *link;
				*link = gen->next;
				gen->next = NULL;
				break;
			}
		}
		pthread_mutex_unlock(&generation_lock);

		if (gen == NULL)
			break;

		rc = drop_generation_database(gen);
		if (rc) {
			msg(LOG_WARNING,
			    "Could not reclaim retired trust DB generation %lu (%s): %s",
			    gen->generation, gen->name, mdb_strerror(rc));
			pthread_mutex_lock(&generation_lock);
			gen->next = retired_generations;
			retired_generations = gen;
			pthread_mutex_unlock(&generation_lock);
			break;
		}

		now = time(NULL);
		if (gen->retired_time && now >= gen->retired_time) {
			unsigned long delay = now - gen->retired_time;

			pthread_mutex_lock(&generation_lock);
			if (delay > max_generation_reclaim_delay)
				max_generation_reclaim_delay = delay;
			pthread_mutex_unlock(&generation_lock);
			msg(LOG_INFO,
			    "Reclaimed retired trust DB generation %lu (%s) after %lu seconds",
			    gen->generation, gen->name, delay);
		}
		free(gen);
	}
	pthread_mutex_unlock(&generation_reclaim_lock);
}

/*
 * trust_db_reset_next_generation - reset the runtime publication counter.
 * @generation: Next generation number to publish.
 *
 * Trust DB metadata persists the LMDB named database, but the reported
 * generation is a daemon-runtime epoch like ruleset and config generations.
 * Startup rebuilds use this to publish generation 1 regardless of the prior
 * daemon's last persisted value.
 *
 * Returns nothing.
 */
static void trust_db_reset_next_generation(unsigned long generation)
{
	pthread_mutex_lock(&generation_lock);
	next_generation = generation;
	pthread_mutex_unlock(&generation_lock);
}

/*
 * trust_db_generation_report_snapshot - copy publication/reclamation state.
 * @report: Destination report snapshot.
 *
 * Returns nothing.
 */
static void trust_db_generation_report_snapshot(
		database_generation_report_t *report)
{
	struct trust_db_generation *gen;
	time_t now = time(NULL);

	memset(report, 0, sizeof(*report));

	pthread_mutex_lock(&generation_lock);
	if (active_generation) {
		report->generation = active_generation->generation;
		report->entries = active_generation->entries;
		report->publish_time = active_generation->publish_time;
	}
	for (gen = retired_generations; gen; gen = gen->next) {
		unsigned long age = 0;

		report->retired_count++;
		if (gen->retired_time && now >= gen->retired_time)
			age = now - gen->retired_time;
		if (age > report->oldest_retired_age)
			report->oldest_retired_age = age;
	}
	report->max_reclaim_delay = max_generation_reclaim_delay;
	pthread_mutex_unlock(&generation_lock);
	lmdb_environment_snapshot(&report->lmdb_generation,
				  &report->lmdb_publish_time);
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
 * remove_lmdb_environment_dir - remove temporary LMDB files and directory.
 * @dir: temporary directory created by mkdtemp().
 *
 * This cleanup is deliberately narrow. Offline rebuild temporary directories
 * should only contain LMDB's data and lock files; anything else is left behind
 * so an unexpected path does not get silently deleted.
 */
static void remove_lmdb_environment_dir(const char *dir)
{
	char path[PATH_MAX];

	if (dir == NULL || dir[0] == 0)
		return;

	if (dir_file_path(path, sizeof(path), dir, "data.mdb") == 0)
		unlink(path);
	if (dir_file_path(path, sizeof(path), dir, "lock.mdb") == 0)
		unlink(path);
	rmdir(dir);
}

/*
 * trust_db_generation_readers_active - check if environment replacement waits.
 * @reason: optional text destination for a human-readable blocker.
 * @reason_size: size of @reason.
 *
 * The update rwlock blocks normal decision reads before a controlled swap, but
 * this check catches maintenance/test references and unreclaimed retired named
 * DBs. Closing an LMDB environment while a generation can still be referenced
 * would turn a logical generation safety feature into a use-after-close bug.
 *
 * Returns 1 when the environment must not be replaced, 0 when it is quiescent.
 */
static int trust_db_generation_readers_active(char *reason,
					      size_t reason_size)
{
	struct trust_db_generation *gen;
	int busy = 0;

	pthread_mutex_lock(&generation_lock);
	if (active_generation && active_generation->readers) {
		busy = 1;
		if (reason && reason_size)
			snprintf(reason, reason_size,
				 "active generation has %lu readers",
				 active_generation->readers);
	} else if (retired_generations) {
		busy = 1;
		gen = retired_generations;
		if (reason && reason_size)
			snprintf(reason, reason_size,
				 "retired generation %lu is still pinned or unreclaimed",
				 gen->generation);
	}
	pthread_mutex_unlock(&generation_lock);

	return busy;
}

/*
 * trust_db_current_generation_number - read active logical generation number.
 *
 * The controlled swap saves this before close_env() forgets in-memory handles.
 * If restoring the old environment is needed, reports continue to show the
 * same trust DB generation instead of appearing to publish new trust content.
 */
static unsigned long trust_db_current_generation_number(void)
{
	unsigned long generation = 1;

	pthread_mutex_lock(&generation_lock);
	if (active_generation)
		generation = active_generation->generation;
	pthread_mutex_unlock(&generation_lock);

	return generation;
}

/*
 * trust_db_next_generation_number - reserve the next logical generation id.
 *
 * Offline environment replacement publishes a complete trust database built
 * from current backend snapshots. In a live daemon that is a real logical
 * trust DB publish, so it consumes the same monotonic generation sequence used
 * by named-DB reload publication.
 */
static unsigned long trust_db_next_generation_number(void)
{
	unsigned long generation;

	pthread_mutex_lock(&generation_lock);
	generation = next_generation;
	if (generation == 0)
		generation = 1;
	pthread_mutex_unlock(&generation_lock);

	return generation;
}

/*
 * open_offline_lmdb - create a temporary replacement LMDB environment.
 * @candidate: replacement environment state to initialize.
 * @config: map/read sizing source.
 *
 * The replacement is built beside the live environment so data.mdb can be
 * renamed into place. It starts with one logical trust DB named slot 0; after
 * publication, later normal reloads can rotate through the usual slots.
 *
 * Returns 0 on success or an errno/LMDB error code.
 */
static int open_offline_lmdb(struct offline_lmdb *candidate,
			     const conf_t *config) __nonnull ((1, 2));
static int open_offline_lmdb(struct offline_lmdb *candidate,
			     const conf_t *config)
{
	MDB_txn *txn = NULL;
	struct trust_db_generation gen;
	char name[TRUST_DB_GENERATION_NAME_SIZE];
	unsigned int flags = MDB_MAPASYNC|MDB_NOSYNC;
	int rc;

#ifndef DEBUG
	flags |= MDB_WRITEMAP;
#endif

	memset(candidate->tmpdir, 0, sizeof(candidate->tmpdir));
	candidate->env = NULL;
	candidate->metadata_dbi = 0;
	candidate->trust_dbi = 0;
	candidate->maxkeysize = 0;
	candidate->entries = 0;

	rc = lmdb_file_path(candidate->tmpdir, sizeof(candidate->tmpdir),
			    ".offline-rebuild.XXXXXX");
	if (rc)
		return rc;
	if (mkdtemp(candidate->tmpdir) == NULL)
		return errno;

	rc = trust_db_generation_slot_name(0, name);
	if (rc)
		goto out_remove;

	memset(&gen, 0, sizeof(gen));
	gen.generation = candidate->trust_generation;
	snprintf(gen.name, sizeof(gen.name), "%s", name);

	rc = mdb_env_create(&candidate->env);
	if (rc)
		goto out_remove;
	rc = mdb_env_set_maxdbs(candidate->env, TRUST_DB_MAX_NAMED_DBS);
	if (rc)
		goto out_close;
	rc = mdb_env_set_mapsize(candidate->env,
				 (size_t)config->db_max_size * MEGABYTE);
	if (rc)
		goto out_close;
	rc = mdb_env_set_maxreaders(candidate->env,
				    configured_reader_limit(config));
	if (rc)
		goto out_close;
	rc = mdb_env_open(candidate->env, candidate->tmpdir, flags, 0660);
	if (rc)
		goto out_close;

	candidate->maxkeysize = mdb_env_get_maxkeysize(candidate->env);
	rc = mdb_txn_begin(candidate->env, NULL, 0, &txn);
	if (rc)
		goto out_close;
	rc = mdb_dbi_open(txn, TRUST_DB_METADATA_NAME, MDB_CREATE,
			  &candidate->metadata_dbi);
	if (rc)
		goto out_abort;
	rc = mdb_dbi_open(txn, gen.name, MDB_CREATE|MDB_DUPSORT,
			  &candidate->trust_dbi);
	if (rc)
		goto out_abort;
	rc = mdb_txn_commit(txn);
	txn = NULL;
	if (rc)
		goto out_close;

	return 0;

out_abort:
	mdb_txn_abort(txn);
out_close:
	if (candidate->env) {
		mdb_env_close(candidate->env);
		candidate->env = NULL;
	}
out_remove:
	remove_lmdb_environment_dir(candidate->tmpdir);
	candidate->tmpdir[0] = 0;
	return rc;
}

/*
 * write_offline_metadata - write replacement environment publication metadata.
 * @candidate: populated replacement environment.
 *
 * Returns 0 on success or an LMDB error code.
 */
static int write_offline_metadata(struct offline_lmdb *candidate)
	__nonnull ((1));
static int write_offline_metadata(struct offline_lmdb *candidate)
{
	MDB_txn *txn = NULL;
	struct trust_db_generation gen;
	char name[TRUST_DB_GENERATION_NAME_SIZE];
	int rc;

	rc = trust_db_generation_slot_name(0, name);
	if (rc)
		return rc;

	memset(&gen, 0, sizeof(gen));
	gen.generation = candidate->trust_generation;
	snprintf(gen.name, sizeof(gen.name), "%s", name);
	gen.handle = candidate->trust_dbi;
	gen.publish_time = time(NULL);

	rc = mdb_txn_begin(candidate->env, NULL, 0, &txn);
	if (rc)
		return rc;
	rc = trust_db_metadata_write_to_env(candidate->env,
					    candidate->metadata_dbi, txn, &gen);
	if (rc) {
		mdb_txn_abort(txn);
		return rc;
	}

	candidate->entries = gen.entries;
	return mdb_txn_commit(txn);
}

/*
 * import_backends_to_offline_lmdb - copy backend snapshots into temp LMDB.
 * @candidate: replacement environment being populated.
 *
 * Returns 0 on success or a write/import error code.
 */
static int import_backends_to_offline_lmdb(struct offline_lmdb *candidate)
{
	long entries;
	int rc;

	for (backend_entry *be = backend_get_first();
	     be != NULL && !stop; be = be->next) {
		msg(LOG_INFO, "Loading trust data from %s backend",
		    be->backend->name);
		if (be->backend->memfd == -1) {
			msg(LOG_ERR,
			    "%s backend does not provide a memfd snapshot",
			    be->backend->name);
			return EINVAL;
		}
		rc = do_memfd_update_to_dbi_in_env(candidate->env,
			be->backend->memfd, candidate->trust_dbi,
			candidate->maxkeysize, &entries);
		if (rc) {
			msg(LOG_ERR,
			    "Failed to import trust data from %s backend",
			    be->backend->name);
			return rc;
		}
		be->backend->entries = entries;
		candidate->entries += entries;
	}

	if (stop)
		return EINTR;
	return 0;
}

/*
 * validate_offline_lmdb - validate replacement LMDB before publication.
 * @candidate: closed replacement environment.
 *
 * MVP validation is intentionally structural. Reopen the candidate read-only,
 * verify that publication metadata names an existing DUPSORT trust DB, and
 * compare LMDB's entry count with the backend import count. Full record-by-
 * record checking remains the normal check-trustdb responsibility.
 */
static int validate_offline_lmdb(const struct offline_lmdb *candidate)
	__nonnull ((1));
static int validate_offline_lmdb(const struct offline_lmdb *candidate)
{
	MDB_env *validate_env = NULL;
	MDB_txn *txn = NULL;
	MDB_dbi validate_metadata_dbi;
	MDB_dbi validate_trust_dbi;
	MDB_stat stat;
	struct trust_db_metadata metadata;
	int rc;

	rc = mdb_env_create(&validate_env);
	if (rc)
		return rc;
	rc = mdb_env_set_maxdbs(validate_env, TRUST_DB_MAX_NAMED_DBS);
	if (rc)
		goto out_close;
	rc = mdb_env_open(validate_env, candidate->tmpdir,
			  MDB_RDONLY|MDB_NOLOCK, 0);
	if (rc)
		goto out_close;

	rc = mdb_txn_begin(validate_env, NULL, MDB_RDONLY, &txn);
	if (rc)
		goto out_close;
	rc = mdb_dbi_open(txn, TRUST_DB_METADATA_NAME, 0,
			  &validate_metadata_dbi);
	if (rc)
		goto out_abort;
	rc = trust_db_metadata_read_from_dbi(txn, validate_metadata_dbi,
					     &metadata);
	if (rc)
		goto out_abort;
	rc = mdb_dbi_open(txn, metadata.name, MDB_DUPSORT,
			  &validate_trust_dbi);
	if (rc)
		goto out_abort;
	rc = mdb_stat(txn, validate_trust_dbi, &stat);
	if (rc)
		goto out_abort;

	if ((long)stat.ms_entries != candidate->entries ||
	    metadata.entries != candidate->entries) {
		msg(LOG_ERR,
		    "Rebuilt trust DB validation count mismatch: stat=%zu metadata=%ld backend=%ld",
		    stat.ms_entries, metadata.entries, candidate->entries);
		rc = EINVAL;
	} else {
		rc = 0;
	}

out_abort:
	if (txn)
		mdb_txn_abort(txn);
out_close:
	mdb_env_close(validate_env);
	return rc;
}

/*
 * build_offline_lmdb_from_backends - build and validate replacement LMDB.
 * @config: active daemon configuration.
 * @candidate: replacement environment plan/result.
 *
 * Returns 0 when @candidate contains a complete validated replacement
 * environment. On failure the temporary environment is removed and the live
 * environment has not been touched.
 */
static int build_offline_lmdb_from_backends(conf_t *config,
					    struct offline_lmdb *candidate)
{
	int rc;

	// Build in isolation while the live LMDB environment remains open.
	rc = open_offline_lmdb(candidate, config);
	if (rc)
		return rc;

	// Backend memfds are the authoritative trust source for replacement.
	rc = import_backends_to_offline_lmdb(candidate);
	if (rc)
		goto out_close;

	// Metadata makes the candidate self-describing after reopen.
	rc = write_offline_metadata(candidate);
	if (rc)
		goto out_close;
	rc = mdb_env_sync(candidate->env, 1);
	if (rc)
		goto out_close;

	mdb_env_close(candidate->env);
	candidate->env = NULL;

	// Validate the persisted files, not the writer's in-memory handles.
	rc = validate_offline_lmdb(candidate);
	if (rc)
		goto out_remove;

	return 0;

out_close:
	if (candidate->env) {
		mdb_env_close(candidate->env);
		candidate->env = NULL;
	}
out_remove:
	remove_lmdb_environment_dir(candidate->tmpdir);
	candidate->tmpdir[0] = 0;
	return rc;
}

struct lmdb_swap_backup {
	char data_backup[PATH_MAX];
	int have_data_backup;
};

/*
 * lmdb_swap_backup_init - create an old-data backup path.
 * @backup: backup descriptor to initialize.
 *
 * Returns 0 on success or errno on failure.
 */
static int lmdb_swap_backup_init(struct lmdb_swap_backup *backup)
{
	int fd;
	int rc;

	memset(backup, 0, sizeof(*backup));
	rc = lmdb_file_path(backup->data_backup, sizeof(backup->data_backup),
			    "data.mdb.compact-backup.XXXXXX");
	if (rc)
		return rc;

	fd = mkstemp(backup->data_backup);
	if (fd < 0)
		return errno;
	close(fd);
	unlink(backup->data_backup);
	return 0;
}

/*
 * swap_lmdb_data_file - publish replacement data.mdb on disk.
 * @tmpdir: validated temporary LMDB environment.
 * @backup: receives a hard-link backup of the previous data.mdb.
 *
 * Only data.mdb is replaced. The live lock.mdb is removed after the live
 * environment is closed so LMDB recreates a reader table matching the reopened
 * environment. If anything fails before data.mdb is renamed, the old file is
 * still the live file.
 */
static int swap_lmdb_data_file(const char *tmpdir,
			       struct lmdb_swap_backup *backup)
{
	char live_data[PATH_MAX];
	char live_lock[PATH_MAX];
	char tmp_data[PATH_MAX];
	int rc;

	rc = lmdb_file_path(live_data, sizeof(live_data), "data.mdb");
	if (rc)
		return rc;
	rc = lmdb_file_path(live_lock, sizeof(live_lock), "lock.mdb");
	if (rc)
		return rc;
	rc = dir_file_path(tmp_data, sizeof(tmp_data), tmpdir, "data.mdb");
	if (rc)
		return rc;
	rc = lmdb_swap_backup_init(backup);
	if (rc)
		return rc;

	if (link(live_data, backup->data_backup) == 0) {
		backup->have_data_backup = 1;
	} else if (errno != ENOENT) {
		rc = errno;
		return rc;
	}

	if (rename(tmp_data, live_data) < 0) {
		rc = errno;
		if (backup->have_data_backup)
			unlink(backup->data_backup);
		return rc;
	}

	/*
	 * The data file is authoritative. Removing the stale lock file avoids
	 * carrying old reader slots into an environment generation that has no
	 * live readers yet. Missing lock files are harmless because LMDB creates
	 * one on reopen.
	 */
	if (unlink(live_lock) && errno != ENOENT)
		msg(LOG_WARNING, "Could not remove stale LMDB lock file: %s",
		    strerror(errno));

	return 0;
}

/*
 * restore_lmdb_data_file - restore old data.mdb after failed replacement.
 * @backup: backup descriptor from swap_lmdb_data_file().
 *
 * Returns 0 on success or errno on restore failure.
 */
static int restore_lmdb_data_file(const struct lmdb_swap_backup *backup)
{
	char live_data[PATH_MAX];
	char live_lock[PATH_MAX];
	int rc;

	rc = lmdb_file_path(live_data, sizeof(live_data), "data.mdb");
	if (rc)
		return rc;
	rc = lmdb_file_path(live_lock, sizeof(live_lock), "lock.mdb");
	if (rc)
		return rc;

	if (backup->have_data_backup) {
		if (rename(backup->data_backup, live_data) < 0)
			return errno;
	} else if (unlink(live_data) && errno != ENOENT) {
		return errno;
	}
	if (unlink(live_lock) && errno != ENOENT)
		return errno;
	return 0;
}

/*
 * finish_lmdb_swap_backup - remove old-data backup after successful reopen.
 * @backup: backup descriptor from swap_lmdb_data_file().
 */
static void finish_lmdb_swap_backup(const struct lmdb_swap_backup *backup)
{
	if (backup->have_data_backup)
		unlink(backup->data_backup);
}

/*
 * reopen_old_environment_after_swap_failure - restore and reopen old LMDB.
 * @config: daemon configuration. db_max_size must already describe old env.
 * @backup: old data.mdb backup.
 * @old_trust_generation: logical generation to preserve in reports.
 * @old_env_generation: physical generation to preserve in reports.
 *
 * Returns 0 when the old environment was restored and reopened.
 */
static int reopen_old_environment_after_swap_failure(conf_t *config,
		const struct lmdb_swap_backup *backup,
		unsigned long old_trust_generation,
		unsigned long old_env_generation)
{
	int rc;

	rc = restore_lmdb_data_file(backup);
	if (rc) {
		msg(LOG_ERR,
		    "Failed to restore previous LMDB environment after compaction failure: %s",
		    strerror(rc));
		return rc;
	}

	rc = init_db_with_generations(config, old_trust_generation,
				      old_env_generation);
	if (rc)
		msg(LOG_ERR,
		    "Failed to reopen restored LMDB environment: init_db() (%d)",
		    rc);
	return rc;
}

/*
 * publish_offline_lmdb - swap a validated temp environment into service.
 * @config: active daemon configuration.
 * @candidate: validated temporary LMDB environment.
 *
 * The caller has already done slow build and validation. This function owns
 * the short maintenance window: block readers, verify no pinned generation
 * remains, close the live environment, rename data.mdb, and reopen. Any
 * failure before a successful reopen attempts to restore and reopen the old
 * environment before releasing the update lock.
 */
static int publish_offline_lmdb(conf_t *config,
		const struct offline_lmdb *candidate) __nonnull ((1, 2));
static int publish_offline_lmdb(conf_t *config,
				const struct offline_lmdb *candidate)
{
	struct lmdb_swap_backup backup;
	char reason[TRUST_DB_COMPACT_REASON_SIZE];
	unsigned long old_trust_generation;
	unsigned long old_env_generation;
	int rc;

	old_trust_generation = trust_db_current_generation_number();
	lmdb_environment_snapshot(&old_env_generation, NULL);
	if (old_env_generation == 0)
		old_env_generation = 1;

	lock_update_thread();

	// Enter the short maintenance window only after the candidate is ready.
	trust_db_reclaim_retired();
	if (trust_db_generation_readers_active(reason, sizeof(reason))) {
		msg(LOG_WARNING,
		    "Trust DB compaction postponed: %s", reason);
		unlock_update_thread();
		return EBUSY;
	}

	// No live generations are pinned; close LMDB before replacing data.mdb.
	close_env(1);
	rc = swap_lmdb_data_file(candidate->tmpdir, &backup);
	if (rc) {
		int reopen_rc;

		msg(LOG_ERR, "Could not publish rebuilt LMDB environment: %s",
		    strerror(rc));
		reopen_rc = init_db_with_generations(config,
				old_trust_generation, old_env_generation);
		unlock_update_thread();
		return reopen_rc ? reopen_rc : rc;
	}

	// Publication is complete only after the replacement reopens cleanly.
	rc = init_db_with_generations(config, candidate->trust_generation,
				      candidate->env_generation);
	if (rc) {
		msg(LOG_ERR,
		    "Could not reopen rebuilt LMDB environment: init_db() (%d)",
		    rc);
		rc = reopen_old_environment_after_swap_failure(config,
				&backup, old_trust_generation,
				old_env_generation);
		unlock_update_thread();
		return rc ? rc : EIO;
	}

	finish_lmdb_swap_backup(&backup);
	unlock_update_thread();
	return 0;
}

/*
 * install_offline_lmdb_at_startup - publish replacement before daemon starts.
 * @config: daemon configuration.
 * @candidate: validated temporary LMDB environment.
 *
 * Startup has no live LMDB readers yet, but it still uses the same backup and
 * restore rules as the runtime path. The function leaves an LMDB environment
 * open for the rest of init_database().
 */
static int install_offline_lmdb_at_startup(conf_t *config,
				const struct offline_lmdb *candidate)
{
	struct lmdb_swap_backup backup;
	int rc;

	rc = swap_lmdb_data_file(candidate->tmpdir, &backup);
	if (rc)
		return rc;

	rc = init_db_with_generations(config, candidate->trust_generation,
				      candidate->env_generation);
	if (rc) {
		unsigned int compact_target = config->db_max_size;

		msg(LOG_ERR,
		    "Could not open rebuilt startup LMDB environment: init_db() (%d)",
		    rc);
		config->db_max_size = startup_compaction_fallback_mb;
		if (reopen_old_environment_after_swap_failure(config, &backup,
				1, 1) == 0) {
			msg(LOG_WARNING,
			    "Startup trust DB compaction at %u MiB failed; previous environment preserved",
			    compact_target);
			return UPDATE_DB_PRESERVED;
		}
		return rc;
	}

	finish_lmdb_swap_backup(&backup);
	return 0;
}

/*
 * compact_trust_database - rebuild and replace the LMDB environment.
 * @config: active daemon configuration.
 * @source: caller category for logs/status.
 *
 * Backend snapshots must already be loaded. This keeps the admin path explicit
 * about when package/trust-file state is refreshed and avoids hidden
 * filesystem swaps during ordinary reloads.
 */
static int compact_trust_database(conf_t *config, const char *source_name)
{
	struct offline_lmdb candidate = { 0 };
	int rc;

	candidate.trust_generation = trust_db_next_generation_number();
	candidate.env_generation = lmdb_environment_next_generation();
	msg(LOG_INFO,
	    "Starting %s trust DB compaction into LMDB environment generation %lu",
	    source_name, candidate.env_generation);

	// Slow path: build and validate a complete replacement off to the side.
	rc = build_offline_lmdb_from_backends(config, &candidate);
	if (rc)
		goto out_status;

	// Fast path: briefly close/reopen the live environment for the swap.
	rc = publish_offline_lmdb(config, &candidate);
	remove_lmdb_environment_dir(candidate.tmpdir);
	if (rc)
		goto out_status;

	request_object_cache_flush();
	mdb_env_sync(env, 1);
	check_db_size(config);

out_status:
	if (rc) {
		msg(LOG_ERR,
		    "Trust DB compaction from %s failed (%s); previous environment preserved",
		    source_name, mdb_strerror(rc));
	} else {
		msg(LOG_INFO,
		    "Trust DB compaction from %s published LMDB environment generation %lu",
		    source_name, candidate.env_generation);
	}

	return rc;
}

/*
 * compact_trust_database_at_startup - rebuild compact environment before use.
 * @config: active daemon configuration.
 *
 * Backend snapshots must already be loaded. On build/swap failure this leaves
 * the old environment open when possible so startup can continue with the
 * preserved trust DB instead of failing closed due only to compaction.
 */
static int compact_trust_database_at_startup(conf_t *config)
{
	struct offline_lmdb candidate = {
		.trust_generation = 1,
		.env_generation = 1,
	};
	int rc;

	msg(LOG_INFO,
	    "Starting startup trust DB compaction into a new LMDB environment");

	// Startup has backend snapshots but no live LMDB readers yet.
	rc = build_offline_lmdb_from_backends(config, &candidate);
	if (rc)
		goto out_failed;

	rc = install_offline_lmdb_at_startup(config, &candidate);
	remove_lmdb_environment_dir(candidate.tmpdir);
	if (rc == UPDATE_DB_PRESERVED) {
		return 0;
	}
	if (rc)
		goto out_failed;

	check_db_size(config);
	msg(LOG_INFO, "Startup trust DB compaction completed");
	return 0;

out_failed:
	if (candidate.tmpdir[0])
		remove_lmdb_environment_dir(candidate.tmpdir);
	config->db_max_size = startup_compaction_fallback_mb;
	if (env == NULL) {
		int open_rc = init_db_with_generations(config, 1, 1);

		if (open_rc)
			return open_rc;
	}
	msg(LOG_WARNING,
	    "Startup trust DB compaction failed (%s); previous environment preserved",
	    mdb_strerror(rc));
	return 0;
}

/*
 * mark_startup_compaction_needed - remember startup compaction recommendation.
 * @target_mb: compacted map size selected by autosize.
 * @fallback_mb: current map size to restore if compaction fails.
 *
 * Autosize inspection runs before backend snapshots are loaded. Store the
 * recommendation so init_database() can build the replacement from backend
 * truth after backend_load() succeeds.
 */
static void mark_startup_compaction_needed(unsigned int target_mb,
					   unsigned int fallback_mb)
{
	msg(LOG_INFO,
	    "autosize: startup will rebuild compact trust DB environment at %u MiB",
	    target_mb);
	startup_compaction_target_mb = target_mb;
	startup_compaction_fallback_mb = fallback_mb;
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
		mark_startup_compaction_needed(target_mb, state.current_mb);
	}

	return 1;
}

/*
 * autosize_reload_growth_step_mb - grow one emergency retry step.
 * @base_mb: baseline map size in MiB.
 *
 * Returns a 25 percent growth step, or one MiB when integer rounding would
 * otherwise leave the value unchanged.
 */
static unsigned long autosize_reload_growth_step_mb(unsigned long base_mb)
{
	unsigned long new_mb = base_mb + (base_mb / 4);

	if (new_mb <= base_mb)
		new_mb++;
	return new_mb;
}

/*
 * autosize_reload_grow_from_state_mb - choose a map-full retry size.
 * @old_mb: Current configured map size.
 * @state: Optional live LMDB sizing state.
 *
 * A bounded auto shrink can make config->db_max_size smaller than the live
 * LMDB map if the file high-water allocation cannot physically shrink. On
 * MDB_MAP_FULL, grow from the actual map in that case; growing from the stale
 * configured value may call mdb_env_set_mapsize() with a size that still does
 * not expand the mapping, causing the retry to repeat the same full map.
 *
 * Returns the retry target clamped to the configuration type range.
 */
static unsigned long autosize_reload_grow_from_state_mb(unsigned long old_mb,
			const struct trust_db_sizing_state *state)
{
	unsigned long base_mb = old_mb;
	unsigned long new_mb;

	if (state && base_mb < state->current_mb)
		base_mb = state->current_mb;

	new_mb = autosize_reload_growth_step_mb(base_mb);
	if (state) {
		unsigned int target_mb = autosize_effective_target_mb(state,
					AUTOSIZE_RELOAD_PREFLIGHT);

		if (new_mb < target_mb)
			new_mb = target_mb;
	}

	if (new_mb > UINT_MAX)
		new_mb = UINT_MAX;
	return new_mb;
}

/*
 * autosize_reload_grow_target_mb - choose a map-full retry size.
 * @old_mb: Current configured map size.
 *
 * Returns the larger of the historical emergency growth increment and the
 * current generation-aware autosize recommendation. The recommendation matters
 * when an existing single-generation database was compacted under the old
 * in-place reload assumptions and now needs room for the live generation plus
 * the candidate generation.
 */
static unsigned long autosize_reload_grow_target_mb(unsigned long old_mb)
{
	struct trust_db_sizing_state state;

	if (read_live_lmdb_sizing_state(&state) == 0)
		return autosize_reload_grow_from_state_mb(old_mb, &state);
	return autosize_reload_grow_from_state_mb(old_mb, NULL);
}

/* Grow the live LMDB map after encountering MDB_MAP_FULL during rebuilds.
 * @config: active daemon configuration updated in place on success
 * Returns 0 when the map was expanded, otherwise 1.
 */
static int grow_map_after_full(conf_t *config)
{
	unsigned long old_mb = config->db_max_size;
	unsigned long new_mb = autosize_reload_grow_target_mb(old_mb);

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

	if (!config->do_auto_db_sizing) {
		if (state.recommended_pages > state.map_pages)
			msg(LOG_WARNING,
			    "db_max_size may be too small for safe reload: "
			    "active=%zu pages, allocated=%zu pages, "
			    "configured=%u MiB, recommended at least %u MiB; "
			    "set db_max_size to at least this value or use auto",
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
 * init_dbi - open metadata and publish the active LMDB generation handle.
 *
 * Returns 0 on success or a non-zero LMDB error code.
 */
static int init_dbi(unsigned long generation)
{
	MDB_txn *txn;
	struct trust_db_metadata metadata;
	struct trust_db_generation *gen = NULL;
	const char *active_name = db;
	unsigned int active_flags = MDB_DUPSORT|MDB_CREATE;
	int rc;

	rc = mdb_txn_begin(env, NULL, 0, &txn);
	if (rc)
		return rc;

	rc = mdb_dbi_open(txn, TRUST_DB_METADATA_NAME, MDB_CREATE,
			  &metadata_dbi);
	if (rc) {
		msg(LOG_ERR, "%s", mdb_strerror(rc));
		mdb_txn_abort(txn);
		return rc;
	}
	metadata_dbi_init = 1;

	rc = trust_db_metadata_read(txn, &metadata);
	if (rc == 0) {
		active_name = metadata.name;
		// Persisted generation belongs to the previous daemon run.
		active_flags = MDB_DUPSORT;
	} else if (rc != MDB_NOTFOUND) {
		msg(LOG_WARNING,
		    "Ignoring unreadable trust DB generation metadata: %s",
		    mdb_strerror(rc));
	}

	gen = trust_db_generation_alloc(generation, active_name);
	if (gen == NULL) {
		metadata_dbi_init = 0;
		mdb_txn_abort(txn);
		return ENOMEM;
	}

	rc = mdb_dbi_open(txn, gen->name, active_flags, &gen->handle);
	if (rc) {
		msg(LOG_ERR, "%s", mdb_strerror(rc));
		metadata_dbi_init = 0;
		free(gen);
		mdb_txn_abort(txn);
		return rc;
	}

	gen->publish_time = time(NULL);
	rc = trust_db_metadata_write(txn, gen);
	if (rc) {
		msg(LOG_ERR, "Could not write trust DB metadata: %s",
		    mdb_strerror(rc));
		metadata_dbi_init = 0;
		free(gen);
		mdb_txn_abort(txn);
		return rc;
	}

	rc = mdb_txn_commit(txn);
	if (rc) {
		msg(LOG_ERR, "%s", mdb_strerror(rc));
		dbi_init = 0;
		metadata_dbi_init = 0;
		free(gen);
		return rc;
	}

	pthread_mutex_lock(&generation_lock);
	active_generation = gen;
	dbi = gen->handle;
	next_generation = gen->generation + 1;
	pthread_mutex_unlock(&generation_lock);
	dbi_init = 1;
	return 0;
}

static int init_db_with_generations(const conf_t *config,
				    unsigned long trust_generation,
				    unsigned long env_generation)
{
	/*
	 * Decision workers are long-lived across autosize close/reopen cycles
	 * and may re-enter trust lookups from one OS thread. Keep LMDB reader
	 * slots tied to transactions instead of thread TLS so each aborted read
	 * transaction fully releases its slot before the next lookup.
	 */
	unsigned int flags = MDB_MAPASYNC|MDB_NOSYNC|MDB_NOTLS;
	int rc;
#ifndef DEBUG
	flags |= MDB_WRITEMAP;
#endif
	if (mdb_env_create(&env)) {
		/* env not allocated on failure, but ensure it's NULL */
		env = NULL;
		return 1;
	}

	if (mdb_env_set_maxdbs(env, TRUST_DB_MAX_NAMED_DBS)) {
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

	rc = init_dbi(trust_generation);
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

	lmdb_environment_publish(env_generation);
	return 0;
}

static int init_db(const conf_t *config)
{
	return init_db_with_generations(config, 1, 1);
}


static unsigned get_pages_in_use(void);
static unsigned long pages, max_pages;
static unsigned long allocated_pages, allocated_pages_percent;

/*
 * forget_generation_list - release in-memory generation handles.
 * @list: List of generations to free.
 * @close_handles: Non-zero closes DBI handles before freeing.
 *
 * Returns nothing.
 */
static void forget_generation_list(struct trust_db_generation *list,
				   int close_handles)
{
	struct trust_db_generation *next;

	while (list) {
		next = list->next;
		if (close_handles && env)
			mdb_close(env, list->handle);
		free(list);
		list = next;
	}
}

/*
 * forget_generations - clear active and retired generation state.
 * @close_handles: Non-zero closes DBI handles before forgetting them.
 *
 * Returns nothing.
 */
static void forget_generations(int close_handles)
{
	struct trust_db_generation *active, *retired;

	pthread_mutex_lock(&generation_lock);
	active = active_generation;
	retired = retired_generations;
	active_generation = NULL;
	retired_generations = NULL;
	next_generation = 1;
	pthread_mutex_unlock(&generation_lock);

	if (active) {
		active->next = NULL;
		forget_generation_list(active, close_handles);
	}
	forget_generation_list(retired, close_handles);
}

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

	forget_generations(do_close_dbi);
	if (do_close_dbi && metadata_dbi_init)
		mdb_close(env, metadata_dbi);

	mdb_env_close(env);
	env = NULL;
	dbi_init = 0;
	metadata_dbi_init = 0;
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
	struct trust_db_generation *gen = NULL;
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
		gen = trust_db_generation_acquire();
	}

	if (gen) {
		stat_rc = mdb_txn_begin(env, NULL, MDB_RDONLY, &txn);
		if (stat_rc == 0) {
			stat_rc = mdb_stat(txn, gen->handle, &stat);
			mdb_txn_abort(txn);
		}
	} else {
		stat_rc = EINVAL;
	}
	if (gen)
		trust_db_generation_release(gen);

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
		int priority = config->do_auto_db_sizing ? LOG_INFO :
			       LOG_WARNING;

		msg(priority,
		    "Trust database LMDB map high-water at %lu%% capacity "
		    "while active DB pages are at %lu%%",
		    state.allocated_percent, state.active_percent);
		if (!config->do_auto_db_sizing)
			log_lmdb_state(LOG_WARNING,
				       "trust database size check", 0);
	}

	target_mb = autosize_effective_target_mb(&state,
						 AUTOSIZE_LIVE_INSPECTION);
	if (config->do_auto_db_sizing) {
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
		    "(active=%lu%% allocated=%lu%%); set db_max_size to at "
		    "least this value or use auto",
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
 * database_resize_report - write manual-size growth recommendation.
 * @f: report stream.
 * @config: active daemon configuration.
 *
 * Auto mode owns map growth itself, so this report is intentionally silent
 * unless an administrator has selected a numeric db_max_size. In manual mode,
 * the daemon preserves the old DB on reload failure but will not grow the map;
 * the status report gives the administrator the same target used by autosize.
 */
static void database_resize_report(FILE *f, const conf_t *config)
{
	struct trust_db_sizing_state state;
	const char *recommended = "no";
	const char *reason = "manual db_max_size has safe reload headroom";
	unsigned int target_mb = 0;
	int rc;

	if (config == NULL || config->do_auto_db_sizing)
		return;

	rc = read_live_lmdb_sizing_state(&state);
	if (rc) {
		reason = "could not inspect LMDB sizing";
	} else {
		target_mb = autosize_effective_target_mb(&state,
					AUTOSIZE_LIVE_INSPECTION);
		if (target_mb > config->db_max_size) {
			recommended = "yes";
			reason = "manual db_max_size is below the safe reload target";
		} else {
			target_mb = 0;
		}
	}

	fprintf(f, "Trust database resize recommended: %s\n", recommended);
	fprintf(f, "Trust database resize reason: %s\n", reason);
	if (target_mb)
		fprintf(f, "Trust database resize target: %u MiB\n",
			target_mb);
}

/*
 * database_compaction_report - write compaction recommendation.
 * @f: report stream.
 * @generation_report: active generation/reclamation snapshot.
 *
 * Compaction is useful when LMDB's allocated high-water mark is much larger
 * than the active trust DB footprint and no retired generations are pinned.
 * If retired generations are still present, the first fix is to find the held
 * readers; replacing the whole environment would have to wait for the same
 * safety condition.
 */
static void database_compaction_report(FILE *f,
		const database_generation_report_t *generation_report)
{
	struct trust_db_sizing_state state;
	const char *recommended = "no";
	const char *reason = "high-water usage is within the active working set";
	unsigned int target_mb = 0;
	int rc;

	rc = read_live_lmdb_sizing_state(&state);
	if (rc) {
		reason = "could not inspect LMDB sizing";
	} else if (generation_report->retired_count) {
		reason = "retired trust database generations are still pinned";
	} else if (state.allocated_percent > TRUST_DB_RELOAD_HIGHWATER_PERCENT &&
		   state.allocated_percent > state.active_percent + 15) {
		recommended = "yes";
		reason = "allocated high-water is much larger than active pages";
		target_mb = autosize_effective_target_mb(&state,
					AUTOSIZE_LIVE_INSPECTION);
	}

	fprintf(f, "Trust database compaction recommended: %s\n",
		recommended);
	fprintf(f, "Trust database compaction reason: %s\n", reason);
	if (target_mb)
		fprintf(f, "Trust database compaction target: %u MiB\n",
			target_mb);
}

/*
 * database_utilization_report - write current trust database utilization.
 * @f: report stream.
 * @config: active daemon configuration, or NULL when unavailable.
 * Returns nothing.
 */
void database_utilization_report(FILE *f, const conf_t *config)
{
	database_generation_report_t report;

	trust_db_generation_report_snapshot(&report);
	fprintf(f, "Trust database pages in use: %lu (%lu%%)\n", pages,
		max_pages ? ((100*pages)/max_pages) : 0);
	fprintf(f, "Trust database allocated high-water pages: %lu (%lu%%)\n",
		allocated_pages, allocated_pages_percent);
	fprintf(f, "Retired trust database generations: %u\n",
		report.retired_count);
	fprintf(f, "Oldest retired trust database generation age: %lu seconds\n",
		report.oldest_retired_age);
	fprintf(f, "Max trust database generation reclaim delay: %lu seconds\n",
		report.max_reclaim_delay);
	database_resize_report(f, config);
	database_compaction_report(f, &report);
}

void database_report(FILE *f)
{
	database_config_report(f);
	database_utilization_report(f, NULL);
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
 * trust_db_key_init_with_max - prepare an LMDB key from a trust path.
 * @key: caller-owned key wrapper to initialize.
 * @idx: path string used as the key.
 * @idx_len: length hint for @idx, or 0 when unknown.
 * @maxkeysize: LMDB key limit for the target environment.
 *
 * Long paths are stored by SHA512 of the full path, not by a truncated
 * prefix. The returned key may point into @idx or into @key->hash; callers
 * must finish with trust_db_key_destroy().
 *
 * Returns 0 on success or ENOMEM.
 */
static int trust_db_key_init_with_max(struct trust_db_key *key,
				      const char *idx, size_t idx_len,
				      unsigned int maxkeysize)
{
	memset(key, 0, sizeof(*key));

	if (idx_len == 0)
		idx_len = strlen(idx);

	if (idx_len > maxkeysize) {
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
 * @key: key initialized by trust_db_key_init_with_max().
 *
 * Returns nothing.
 */
static void trust_db_key_destroy(struct trust_db_key *key)
{
	free(key->hash);
	memset(key, 0, sizeof(*key));
}

/*
 * trust_db_begin_write_txn_for_env - begin a trust DB write transaction.
 * @target_env: LMDB environment to write.
 * @txn: destination transaction handle.
 * @context: log label describing the caller.
 *
 * Returns 0 on success, WRITE_DB_MAP_FULL for map exhaustion, or a stage
 * code compatible with write_db().
 */
static int trust_db_begin_write_txn_for_env(MDB_env *target_env,
					    MDB_txn **txn,
					    const char *context)
{
	int rc;

	rc = mdb_txn_begin(target_env, NULL, 0, txn);
	if (rc) {
		msg(LOG_ERR, "mdb_txn_begin failed before %s: %s",
		    context, mdb_strerror(rc));
		if (target_env == env)
			log_lmdb_state(LOG_ERR, context, rc);
		return rc == MDB_MAP_FULL ? WRITE_DB_MAP_FULL : 1;
	}

	if (target_env == env && !dbi_init) {
		abort_transaction(*txn);
		*txn = NULL;
		msg(LOG_ERR, "open_dbi failed before %s: %s",
		    context, mdb_strerror(EINVAL));
		return 2;
	}

	return 0;
}

/*
 * trust_db_begin_write_txn - begin a live trust DB write transaction.
 * @txn: destination transaction handle.
 * @context: log label describing the caller.
 *
 * Returns 0 on success, WRITE_DB_MAP_FULL for map exhaustion, or a stage
 * code compatible with write_db().
 */
static int trust_db_begin_write_txn(MDB_txn **txn, const char *context)
{
	return trust_db_begin_write_txn_for_env(env, txn, context);
}

/*
 * trust_db_commit_write_txn_for_env - commit a trust DB write transaction.
 * @target_env: LMDB environment to write.
 * @txn: transaction handle to commit and clear.
 * @context: log label describing the caller.
 *
 * Returns 0 on success, WRITE_DB_MAP_FULL for map exhaustion, or a stage
 * code compatible with write_db().
 */
static int trust_db_commit_write_txn_for_env(MDB_env *target_env,
					     MDB_txn **txn,
					     const char *context)
{
	int rc;

	if (*txn == NULL)
		return 0;

	rc = mdb_txn_commit(*txn);
	*txn = NULL;
	if (rc) {
		msg(LOG_ERR, "mdb_txn_commit failed after %s: %s",
		    context, mdb_strerror(rc));
		if (target_env == env)
			log_lmdb_state(LOG_ERR, context, rc);
		return rc == MDB_MAP_FULL ? WRITE_DB_MAP_FULL : 4;
	}

	return 0;
}

/*
 * trust_db_commit_write_txn - commit a live trust DB write transaction.
 * @txn: transaction handle to commit and clear.
 * @context: log label describing the caller.
 *
 * Returns 0 on success, WRITE_DB_MAP_FULL for map exhaustion, or a stage
 * code compatible with write_db().
 */
static int trust_db_commit_write_txn(MDB_txn **txn, const char *context)
{
	return trust_db_commit_write_txn_for_env(env, txn, context);
}

/*
 * trust_db_put_record_with_max - write one record into an active transaction.
 * @txn: writable LMDB transaction.
 * @record: parsed trust DB record.
 * @maxkeysize: LMDB key limit for the target environment.
 * @context: log label describing the caller.
 *
 * Returns 0 on success, WRITE_DB_MAP_FULL for map exhaustion, 3 for mdb_put
 * failures, and 5 when key hashing fails.
 */
static int trust_db_put_record_with_max(MDB_txn *txn, MDB_dbi target_dbi,
				const struct trust_db_record_input *record,
				unsigned int maxkeysize, const char *context)
{
	struct trust_db_key key;
	MDB_val value;
	int rc;

	rc = trust_db_key_init_with_max(&key, record->idx, record->idx_len,
					maxkeysize);
	if (rc)
		return 5;

	value.mv_data = (void *)record->data;
	value.mv_size = strlen(record->data);

	rc = mdb_put(txn, target_dbi, &key.val, &value, 0);
	trust_db_key_destroy(&key);
	if (rc) {
		msg(LOG_ERR, "mdb_put failed during %s: %s",
		    context, mdb_strerror(rc));
		return rc == MDB_MAP_FULL ? WRITE_DB_MAP_FULL : 3;
	}

	return 0;
}

/*
 * trust_db_put_record - write one record into the live environment.
 * @txn: writable LMDB transaction.
 * @target_dbi: destination named database.
 * @record: parsed trust DB record.
 * @context: log label describing the caller.
 *
 * Returns 0 on success, WRITE_DB_MAP_FULL for map exhaustion, 3 for mdb_put
 * failures, and 5 when key hashing fails.
 */
static int trust_db_put_record(MDB_txn *txn, MDB_dbi target_dbi,
			       const struct trust_db_record_input *record,
			       const char *context)
{
	return trust_db_put_record_with_max(txn, target_dbi, record,
					    MDB_maxkeysize, context);
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
	struct trust_db_generation *gen;
	MDB_txn *txn = NULL;
	int rc;

	gen = trust_db_generation_acquire();
	if (gen == NULL)
		return 2;

	rc = trust_db_begin_write_txn(&txn, "single trust DB write");
	if (rc) {
		trust_db_generation_release(gen);
		return rc;
	}

	rc = trust_db_put_record(txn, gen->handle, &record,
				 "single trust DB write");
	if (rc) {
		abort_transaction(txn);
		log_lmdb_state(LOG_ERR, "single trust DB write",
			       rc == WRITE_DB_MAP_FULL ? MDB_MAP_FULL : 0);
		trust_db_generation_release(gen);
		return rc;
	}

	rc = trust_db_commit_write_txn(&txn, "single trust DB write");
	trust_db_generation_release(gen);
	return rc;
}

/*
 * database_store_update_record - persist one FIFO path update in LMDB.
 * @path: Trust path received from a backend helper.
 * @size: File size to store with the record.
 * @hash: SHA256 digest string received from a backend helper.
 *
 * This is the deliberate bridge from database-update.c into LMDB storage for
 * incremental updates. The controller validates the command shape; database.c
 * owns serialization, locking around the write transaction, and metadata
 * refresh for the active generation.
 *
 * Package-manager integrations may send these records while an rpm/dnf
 * transaction is still running. That intentionally updates the active
 * generation instead of waiting for the next full reload, because scriptlets
 * can execute a newly installed file before the candidate generation is built
 * and published. The active DB uses duplicate keys so old and new hashes for
 * one path can coexist during that window; the next successful full reload
 * publishes a backend snapshot and drops stale duplicates.
 *
 * Returns 0 on success or the write_db() stage code on failure.
 */
int database_store_update_record(const char *path, size_t size,
				 const char *hash)
{
	char data[BUFFER_SIZE];
	int rc;

	snprintf(data, BUFFER_SIZE, DATA_FORMAT, (unsigned int)SRC_UNKNOWN,
		 size, hash);

	lock_update_thread();
	rc = write_db(path, 0, data);
	if (rc == 0)
		refresh_active_generation_metadata();
	unlock_update_thread();

	return rc;
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
	struct trust_db_generation *gen;
	int rc;

	memset(read, 0, sizeof(*read));
	gen = trust_db_generation_acquire();
	if (gen == NULL)
		return 1;
	read->generation = gen;

	rc = mdb_txn_begin(env, NULL, MDB_RDONLY, &read->txn);
	if (rc) {
		trust_db_record_reader_error(rc);
		msg(LOG_ERR, "txn_begin:%s", mdb_strerror(rc));
		trust_db_generation_release(gen);
		memset(read, 0, sizeof(*read));
		return 1;
	}

	if (!dbi_init) {
		msg(LOG_ERR, "open_dbi:%s", mdb_strerror(EINVAL));
		abort_transaction(read->txn);
		trust_db_generation_release(gen);
		memset(read, 0, sizeof(*read));
		return 1;
	}

	if ((rc = mdb_cursor_open(read->txn, gen->handle, &read->cursor))) {
		msg(LOG_ERR, "cursor_open:%s", mdb_strerror(rc));
		abort_transaction(read->txn);
		trust_db_generation_release(gen);
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
	trust_db_generation_release(read->generation);
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
	struct trust_db_generation *gen;
	MDB_txn *txn;
	int rc;

	gen = trust_db_generation_acquire();
	if (gen == NULL)
		return EINVAL;

	rc = mdb_txn_begin(env, NULL, MDB_RDONLY, &txn);
	if (rc) {
		trust_db_record_reader_error(rc);
		trust_db_generation_release(gen);
		return rc;
	}

	rc = mdb_stat(txn, gen->handle, st);
	mdb_txn_abort(txn);
	trust_db_generation_release(gen);
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
		const char *name = read->generation ? read->generation->name : db;

		return strndup(name, MDB_maxkeysize);
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
static int delete_all_entries_db(MDB_dbi target_dbi)
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

	if (!dbi_init) {
		abort_transaction(txn);
		return 2;
	}

	// 0 -> delete , 1 -> delete and close
	if ((rc = mdb_drop(txn, target_dbi, 0))) {
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
static int do_memfd_update_to_dbi_in_env(MDB_env *target_env, int memfd,
					 MDB_dbi target_dbi,
					 unsigned int maxkeysize,
					 long *entries)
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
				res = trust_db_begin_write_txn_for_env(
						target_env, &txn,
						"bulk trust DB import");
				if (res) {
					rc = res;
					break;
				}
			}

			res = trust_db_put_record_with_max(txn, target_dbi,
						&record, maxkeysize,
						"bulk trust DB import");
			if (res) {
				abort_transaction(txn);
				txn = NULL;
				if (target_env == env)
					log_lmdb_state(LOG_ERR,
						"bulk trust DB import",
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
				res = trust_db_commit_write_txn_for_env(
						target_env, &txn,
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
			rc = trust_db_commit_write_txn_for_env(target_env,
					&txn, "bulk trust DB import");
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

static int do_memfd_update_to_dbi(int memfd, MDB_dbi target_dbi,
				  long *entries)
{
	return do_memfd_update_to_dbi_in_env(env, memfd, target_dbi,
					     MDB_maxkeysize, entries);
}

int do_memfd_update(int memfd, long *entries)
{
	struct trust_db_generation *gen;
	int rc;

	gen = trust_db_generation_acquire();
	if (gen == NULL)
		return 2;

	rc = do_memfd_update_to_dbi(memfd, gen->handle, entries);
	trust_db_generation_release(gen);
	if (rc == 0)
		refresh_active_generation_metadata();
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
static int create_database_for_generation(struct trust_db_generation *gen,
					  int with_sync, conf_t *config)
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
				rc = do_memfd_update_to_dbi(be->backend->memfd,
				     gen->handle, &be->backend->entries);
				if (rc) {
					msg(LOG_ERR,
					    "Failed to import trust data from %s backend",
					    be->backend->name);
					break;
				}
			}
		}
		log_lmdb_state(rc ? LOG_ERR : LOG_DEBUG,
			       "trust DB rebuild after import",
			       rc == WRITE_DB_MAP_FULL ? MDB_MAP_FULL : 0);

		if (rc == WRITE_DB_MAP_FULL &&
		    config->do_auto_db_sizing && retries == 0) {
			int grown;

			lock_update_thread();
			grown = grow_map_after_full(config);
			unlock_update_thread();
			if (grown == 0 &&
			    delete_all_entries_db(gen->handle) == 0) {
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

	return rc;
}

static int create_database(int with_sync, conf_t *config)
{
	struct trust_db_generation *gen;
	int rc;

	gen = trust_db_generation_acquire();
	if (gen == NULL)
		return 2;

	rc = create_database_for_generation(gen, with_sync, config);
	trust_db_generation_release(gen);
	if (rc == 0) {
		refresh_active_generation_metadata();
		check_db_size(config);
	}
	return rc;
}

/*
 * create_candidate_generation - open an empty named DB for the next rebuild.
 * @candidate: Destination for the new candidate generation.
 *
 * Returns 0 on success or an LMDB/errno-style error code.
 */
static int create_candidate_generation(struct trust_db_generation **candidate)
{
	struct trust_db_generation *gen;
	char name[TRUST_DB_GENERATION_NAME_SIZE];
	MDB_txn *txn = NULL;
	unsigned long generation;
	int rc;

	pthread_mutex_lock(&generation_lock);
	generation = next_generation;
	rc = trust_db_candidate_name(name);
	pthread_mutex_unlock(&generation_lock);
	if (rc)
		return rc;

	gen = trust_db_generation_alloc(generation, name);
	if (gen == NULL)
		return ENOMEM;

	rc = mdb_txn_begin(env, NULL, 0, &txn);
	if (rc)
		goto out_free;

	rc = mdb_dbi_open(txn, gen->name, MDB_CREATE|MDB_DUPSORT,
			  &gen->handle);
	if (rc)
		goto out_abort;

	rc = mdb_txn_commit(txn);
	txn = NULL;
	if (rc)
		goto out_free;

	rc = delete_all_entries_db(gen->handle);
	if (rc)
		goto out_drop;

	*candidate = gen;
	return 0;

out_abort:
	mdb_txn_abort(txn);
out_free:
	free(gen);
	return rc;
out_drop:
	drop_generation_database(gen);
	free(gen);
	return rc;
}

/*
 * drop_candidate_generation - remove an unpublished candidate DB.
 * @candidate: Candidate generation that must not become visible to readers.
 *
 * Returns nothing.
 */
static void drop_candidate_generation(struct trust_db_generation *candidate)
{
	int rc;

	if (candidate == NULL)
		return;

	rc = drop_generation_database(candidate);
	if (rc)
		msg(LOG_WARNING,
		    "Could not drop failed trust DB generation %lu (%s): %s",
		    candidate->generation, candidate->name, mdb_strerror(rc));
	free(candidate);
}

/*
 * refresh_active_generation_metadata - rewrite metadata for the active DB.
 *
 * Returns 0 on success or an LMDB error code. This is used after startup or
 * direct single-generation imports so reports contain current entry counts.
 */
static int refresh_active_generation_metadata(void)
{
	struct trust_db_generation *gen;
	MDB_txn *txn = NULL;
	int rc;

	gen = trust_db_generation_acquire();
	if (gen == NULL)
		return EINVAL;

	rc = mdb_txn_begin(env, NULL, 0, &txn);
	if (rc)
		goto out_release;

	rc = trust_db_metadata_write(txn, gen);
	if (rc) {
		mdb_txn_abort(txn);
		goto out_release;
	}

	rc = mdb_txn_commit(txn);

out_release:
	trust_db_generation_release(gen);
	return rc;
}

/*
 * publish_candidate_generation - publish a rebuilt trust DB generation.
 * @candidate: Fully populated candidate generation.
 *
 * Returns 0 on success. On failure the active generation is unchanged and the
 * caller still owns @candidate.
 */
static int publish_candidate_generation(struct trust_db_generation *candidate)
{
	struct trust_db_generation *old;
	MDB_txn *txn = NULL;
	int rc;

	candidate->publish_time = time(NULL);
	rc = mdb_txn_begin(env, NULL, 0, &txn);
	if (rc)
		return rc;

	rc = trust_db_metadata_write(txn, candidate);
	if (rc) {
		mdb_txn_abort(txn);
		return rc;
	}

	rc = mdb_txn_commit(txn);
	if (rc)
		return rc;

	pthread_mutex_lock(&generation_lock);
	old = active_generation;
	active_generation = candidate;
	dbi = candidate->handle;
	if (next_generation <= candidate->generation)
		next_generation = candidate->generation + 1;
	if (old) {
		old->retired_time = time(NULL);
		old->next = retired_generations;
		retired_generations = old;
	}
	pthread_mutex_unlock(&generation_lock);

	msg(LOG_INFO,
	    "Published trust DB generation %lu (%s) with %ld entries",
	    candidate->generation, candidate->name, candidate->entries);
	trust_db_reclaim_retired();
	return 0;
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

	msg(LOG_INFO, "Initializing the trust database");
	startup_compaction_target_mb = 0;
	startup_compaction_fallback_mb = 0;

	rc = database_update_controls_init();
	if (rc) {
		msg(LOG_ERR, "Failed to initialize database update controls (%d)",
		    rc);
		return rc;
	}

	if (migrate_database())
		return 1;

	/* One-shot utilisation-driven sizing */
	if (config->do_auto_db_sizing &&
	    autosize_database(config, AUTOSIZE_STARTUP_INSPECTION))
		msg(LOG_INFO, "autosize: map size recomputed to %u MiB",
		    config->db_max_size);

	if ((rc = backend_init(config))) {
		msg(LOG_ERR, "Failed to load trust data from backend (%d)", rc);
		return rc;
	}

	if ((rc = backend_load(config))) {
		msg(LOG_ERR, "Failed to load data from backend (%d)", rc);
		backend_close();
		return rc;
	}

	if (startup_compaction_target_mb) {
		rc = compact_trust_database_at_startup(config);
		if (rc) {
			backend_close();
			return rc;
		}
	}

	if (env == NULL && (rc = init_db(config))) {
		msg(LOG_ERR, "Cannot open the trust database, init_db() (%d)",
		    rc);
		backend_close();
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
			rc = update_database(config, 1);
			if (rc)
				msg(LOG_ERR,
				    "Failed updating the trust database");
		}
	}

	// Conserve memory by dumping unneeded resources
	backend_close();

	if (rc == 0)
		rc = database_update_thread_start(config);

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

/*
 * check_trust_database_with_read - run trust lookup using caller's read handle.
 * @read: active trust DB read handle.
 * @path: filesystem path to check.
 * @info: optional file metadata for integrity checks.
 * @fd: optional open file descriptor for integrity checks.
 *
 * Returns 1 if trusted, 0 if untrusted, and -1 on read or integrity error.
 */
static int check_trust_database_with_read(struct trust_db_read_handle *read,
	const char *path, struct file_info *info, int fd)
{
	int retval = 0, error;
	int res;
	struct trust_db_lookup lookup;

	lookup.path = path;
	lookup.info = info;
	lookup.fd = fd;
	lookup.error = &error;
	error = 0;
	res = read_trust_db(read, &lookup);
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
				error = 0;
				res = read_trust_db(read, &lookup);
				if (error)
					retval = -1;
				else if (res)
					retval = 1;
			}
		}
	}

	return retval;
}

/*
 * check_trust_database - check trust using the daemon's live DB state.
 * @path: filesystem path to check.
 * @info: optional file metadata for integrity checks.
 * @fd: optional open file descriptor for integrity checks.
 *
 * This is the normal daemon lookup path. It takes the database update read
 * lock, opens a read handle on the current generation, and records timing and
 * trust lookup metrics. fapolicyd-cli uses check_trust_database_readonly()
 * when it needs a private read-only environment.
 *
 * Returns 1 if trusted, 0 if untrusted, and -1 on read or integrity error.
 */
int check_trust_database(const char *path, struct file_info *info, int fd)
{
	int retval;
	struct trust_db_read_handle read;
	struct decision_timing_span lock_timing;
	struct decision_timing_span read_timing;
	struct decision_timing_span total_timing;

	trust_metric_add(&trust_metrics.lookups, 1);
	decision_timing_trust_db_stage_begin(DECISION_TIMING_TRUST_DB_TOTAL,
					     &total_timing);
	decision_timing_trust_db_stage_begin(
		DECISION_TIMING_TRUST_DB_LOCK_WAIT, &lock_timing);
	database_update_read_lock();
	decision_timing_stage_end(&lock_timing);

	decision_timing_trust_db_stage_begin(DECISION_TIMING_TRUST_DB_READ,
					     &read_timing);
	if (trust_db_read_open(&read)) {
		retval = -1;
		goto out_unlock;
	}

	retval = check_trust_database_with_read(&read, path, info, fd);
	trust_db_read_close(&read);
out_unlock:
	decision_timing_stage_end(&read_timing);
	database_update_read_unlock();
	decision_timing_stage_end(&total_timing);

	return retval;
}

/*
 * database_readonly_lookup_finish - close read-only CLI trust lookup state.
 * @void: no arguments are required.
 *
 * This state is used only by fapolicyd-cli and is separate from the daemon's
 * live LMDB environment.
 *
 * Returns nothing.
 */
void database_readonly_lookup_finish(void)
{
	if (readonly_lookup_env)
		mdb_env_close(readonly_lookup_env);
	readonly_lookup_env = NULL;
	readonly_lookup_dbi = 0;
	readonly_lookup_open = 0;
}

/*
 * database_readonly_lookup_start - open a private read-only trust DB handle.
 * @void: no arguments are required.
 *
 * This state is used only by fapolicyd-cli. The CLI opens its own read-only
 * LMDB environment so path checks do not initialize or lock the daemon's live
 * environment.
 *
 * Returns 0 on success or an LMDB error code.
 */
int database_readonly_lookup_start(void)
{
	MDB_txn *txn = NULL;
	char active_name[TRUST_DB_GENERATION_NAME_SIZE];
	int rc;

	database_readonly_lookup_finish();
	snprintf(active_name, sizeof(active_name), "%s", db);

	rc = mdb_env_create(&readonly_lookup_env);
	if (rc)
		return rc;

	rc = mdb_env_set_maxdbs(readonly_lookup_env, TRUST_DB_MAX_NAMED_DBS);
	if (rc)
		goto error;

	/*
	 * This stays read-only, but it must use LMDB's reader table.  A live
	 * CLI transaction that bypasses locking is invisible to daemon reloads,
	 * which may otherwise drop retired named DBs while the CLI still reads
	 * their old pages.
	 */
	rc = mdb_env_open(readonly_lookup_env, data_dir, MDB_RDONLY, 0);
	if (rc)
		goto error;

	rc = mdb_txn_begin(readonly_lookup_env, NULL, MDB_RDONLY, &txn);
	if (rc)
		goto error;

	rc = database_read_active_name(txn, active_name, sizeof(active_name));
	if (rc)
		goto out_abort;

	rc = mdb_dbi_open(txn, active_name, MDB_DUPSORT,
			  &readonly_lookup_dbi);
	if (rc)
		goto out_abort;

	/*
	 * LMDB DBI handles opened in a transaction stay private until that
	 * transaction commits. Aborting here would close readonly_lookup_dbi
	 * before check_trust_database_readonly() starts its lookup transaction.
	 */
	rc = mdb_txn_commit(txn);
	if (rc)
		goto error;

	MDB_maxkeysize = mdb_env_get_maxkeysize(readonly_lookup_env);
	lib_symlink = is_link("/lib");
	lib64_symlink = is_link("/lib64");
	bin_symlink = is_link("/bin");
	sbin_symlink = is_link("/sbin");
	readonly_lookup_open = 1;
	return 0;

out_abort:
	mdb_txn_abort(txn);

error:
	database_readonly_lookup_finish();
	return rc;
}

/*
 * check_trust_database_readonly - check trust through read-only CLI LMDB state.
 * @path: filesystem path to check.
 * @info: optional file metadata for integrity checks.
 * @fd: optional open file descriptor for integrity checks.
 *
 * This entry point is used only by fapolicyd-cli after
 * database_readonly_lookup_start(). It deliberately avoids daemon update
 * locks and daemon LMDB handles.
 *
 * Returns 1 if trusted, 0 if untrusted, and -1 on read or integrity error.
 */
int check_trust_database_readonly(const char *path, struct file_info *info,
		int fd)
{
	struct trust_db_read_handle read = { 0 };
	int retval;
	int rc;

	if (!readonly_lookup_open)
		return -1;

	rc = mdb_txn_begin(readonly_lookup_env, NULL, MDB_RDONLY, &read.txn);
	if (rc) {
		msg(LOG_ERR, "txn_begin:%s", mdb_strerror(rc));
		return -1;
	}

	rc = mdb_cursor_open(read.txn, readonly_lookup_dbi, &read.cursor);
	if (rc) {
		msg(LOG_ERR, "cursor_open:%s", mdb_strerror(rc));
		mdb_txn_abort(read.txn);
		return -1;
	}

	retval = check_trust_database_with_read(&read, path, info, fd);
	mdb_cursor_close(read.cursor);
	mdb_txn_abort(read.txn);
	return retval;
}


void close_database(void)
{
	database_update_thread_stop();

	// we can close db when we are really sure update_thread does not exist
	close_db(1);
	database_update_controls_destroy();

	backend_close();
}

/*
 * database_open_for_tests - Open LMDB for isolated unit test execution.
 * @config: Configuration providing map size and integrity mode.
 *
 * Returns 0 on success or the init_db return code on failure.
 */
int database_open_for_tests(conf_t *config)
{
	int rc;

	rc = database_update_controls_init();
	if (rc)
		return rc;
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
	database_update_controls_destroy();
}

/*
 * publish_memfd_for_tests - publish one memfd as a new generation.
 * @memfd: Backend-style trust records to import into the candidate DB.
 * @config: Test configuration used for sizing reports.
 * @startup_rebuild: Non-zero to use startup generation numbering.
 *
 * Returns 0 on successful publication or a non-zero import/publish error.
 */
static int publish_memfd_for_tests(int memfd, conf_t *config,
				   int startup_rebuild)
{
	struct trust_db_generation *candidate = NULL;
	long entries = 0;
	int rc;

	if (startup_rebuild)
		trust_db_reset_next_generation(1);

	rc = create_candidate_generation(&candidate);
	if (rc)
		return rc;

	rc = do_memfd_update_to_dbi(memfd, candidate->handle, &entries);
	if (rc) {
		drop_candidate_generation(candidate);
		return rc;
	}

	rc = publish_candidate_generation(candidate);
	if (rc) {
		drop_candidate_generation(candidate);
		return rc;
	}

	check_db_size(config);
	request_object_cache_flush();
	return 0;
}

/*
 * database_publish_memfd_for_tests - publish one memfd as a new generation.
 * @memfd: Backend-style trust records to import into the candidate DB.
 * @config: Test configuration used for sizing reports.
 *
 * Returns 0 on successful publication or a non-zero import/publish error.
 */
int database_publish_memfd_for_tests(int memfd, conf_t *config)
{
	return publish_memfd_for_tests(memfd, config, 0);
}

/*
 * database_publish_startup_memfd_for_tests - publish a startup rebuild.
 * @memfd: Backend-style trust records to import into the candidate DB.
 * @config: Test configuration used for sizing reports.
 *
 * Returns 0 on successful publication or a non-zero import/publish error.
 */
int database_publish_startup_memfd_for_tests(int memfd, conf_t *config)
{
	return publish_memfd_for_tests(memfd, config, 1);
}

/*
 * database_nested_lookup_for_tests - start a lookup while one read txn is open.
 * @path: Path expected to exist in the active trust database.
 *
 * Returns the nested check_trust_database() result, or -1 when the setup read
 * transaction cannot be opened.
 */
int database_nested_lookup_for_tests(const char *path)
{
	struct trust_db_read_handle read;
	int rc;

	if (trust_db_read_open(&read))
		return -1;

	rc = check_trust_database(path, NULL, -1);
	trust_db_read_close(&read);
	return rc;
}

/*
 * database_drop_candidate_after_import_for_tests - simulate rebuild failure.
 * @memfd: Backend-style trust records to import before dropping candidate.
 *
 * Returns the import result. The candidate generation is always unpublished.
 */
int database_drop_candidate_after_import_for_tests(int memfd)
{
	struct trust_db_generation *candidate = NULL;
	long entries = 0;
	int rc;

	rc = create_candidate_generation(&candidate);
	if (rc)
		return rc;

	rc = do_memfd_update_to_dbi(memfd, candidate->handle, &entries);
	drop_candidate_generation(candidate);
	return rc;
}

/*
 * database_compact_memfd_for_tests - swap a rebuilt environment from memfd.
 * @memfd: Backend-style trust records for the replacement environment.
 * @config: Test configuration used for map sizing.
 *
 * Returns 0 on successful environment replacement. This bypasses the backend
 * manager but still exercises offline build, read-back validation, controlled
 * close/swap/reopen, generation publication, and old-environment preservation
 * on failures in the same code paths used by production.
 */
int database_compact_memfd_for_tests(int memfd, conf_t *config)
{
	struct offline_lmdb candidate = {
		.trust_generation = trust_db_next_generation_number(),
		.env_generation = lmdb_environment_next_generation(),
	};
	int rc;

	rc = open_offline_lmdb(&candidate, config);
	if (rc)
		goto out_failure;

	rc = do_memfd_update_to_dbi_in_env(candidate.env, memfd,
					   candidate.trust_dbi,
					   candidate.maxkeysize,
					   &candidate.entries);
	if (rc)
		goto out_close;
	rc = write_offline_metadata(&candidate);
	if (rc)
		goto out_close;
	rc = mdb_env_sync(candidate.env, 1);
	if (rc)
		goto out_close;
	mdb_env_close(candidate.env);
	candidate.env = NULL;

	rc = validate_offline_lmdb(&candidate);
	if (rc)
		goto out_remove;
	rc = publish_offline_lmdb(config, &candidate);
	if (rc)
		goto out_remove;

	remove_lmdb_environment_dir(candidate.tmpdir);
	check_db_size(config);
	request_object_cache_flush();
	return 0;

out_close:
	if (candidate.env)
		mdb_env_close(candidate.env);
out_remove:
	remove_lmdb_environment_dir(candidate.tmpdir);
out_failure:
	return rc;
}

void *database_generation_hold_for_tests(void)
{
	return trust_db_generation_acquire();
}

void database_generation_release_for_tests(void *cookie)
{
	trust_db_generation_release(cookie);
}

void database_reclaim_generations_for_tests(void)
{
	trust_db_reclaim_retired();
}

/*
 * database_generation_snapshot - copy trust DB generation state.
 * @report: Destination report snapshot.
 *
 * Returns 0.
 */
int database_generation_snapshot(database_generation_report_t *report)
{
	trust_db_generation_report_snapshot(report);
	return 0;
}

int database_generation_report_for_tests(
		database_generation_test_report_t *report)
{
	return database_generation_snapshot(report);
}

/*
 * database_autosize_target_mb_for_tests - compute autosize target.
 * @active_pages: Pages used by the published trust DB.
 * @env_allocated_pages: LMDB environment high-water pages.
 * @map_pages: Current map size in pages.
 * @page_size: LMDB page size.
 *
 * Returns the recommended map size in MiB for unit tests that exercise sizing
 * policy without creating very large LMDB fixtures.
 */
unsigned int database_autosize_target_mb_for_tests(unsigned long active_pages,
	unsigned long env_allocated_pages, unsigned long map_pages,
	unsigned long page_size)
{
	struct trust_db_sizing_state state;

	memset(&state, 0, sizeof(state));
	state.active_pages = active_pages;
	state.allocated_pages = env_allocated_pages;
	state.map_pages = map_pages;
	state.page_size = page_size;
	state.current_mb = pages_to_mb(map_pages, page_size);
	complete_lmdb_sizing_state(&state);
	return autosize_effective_target_mb(&state,
					    AUTOSIZE_RELOAD_PREFLIGHT);
}

/*
 * database_autosize_retry_mb_for_tests - compute auto retry grow target.
 * @old_mb: Current configured map size.
 * @active_pages: Pages used by the published trust DB.
 * @map_pages: Current live LMDB map size in pages.
 * @page_size: LMDB page size.
 *
 * Returns the MDB_MAP_FULL retry target used by auto sizing.
 */
unsigned int database_autosize_retry_mb_for_tests(unsigned long old_mb,
	unsigned long active_pages, unsigned long map_pages,
	unsigned long page_size)
{
	struct trust_db_sizing_state state;

	memset(&state, 0, sizeof(state));
	state.active_pages = active_pages;
	state.allocated_pages = active_pages;
	state.map_pages = map_pages;
	state.page_size = page_size;
	state.current_mb = pages_to_mb(map_pages, page_size);
	complete_lmdb_sizing_state(&state);
	return autosize_reload_grow_from_state_mb(old_mb, &state);
}

/*
 * update_database - reload backend snapshots into a new trust DB generation.
 * @config: Active daemon configuration.
 * @startup_rebuild: Non-zero when init_database() is rebuilding at startup.
 *
 * It returns 0 on success and non-zero on error.
 */
static int update_database(conf_t *config, int startup_rebuild)
{
	int rc;
	struct trust_db_generation *candidate = NULL;

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
	unlock_update_thread();

	if (startup_rebuild)
		trust_db_reset_next_generation(1);

	rc = create_candidate_generation(&candidate);
	if (rc) {
		msg(LOG_ERR, "Cannot create candidate trust DB generation (%d)",
		    rc);
		return UPDATE_DB_PRESERVED;
	}

	if (stop) {
		drop_candidate_generation(candidate);
		return 1;
	}

	if (!stop)
		rc = create_database_for_generation(candidate,
						   /*with_sync*/0, config);
	else
		rc = 1;
	log_lmdb_state(rc ? LOG_ERR : LOG_DEBUG,
		       "trust DB reload after rebuild",
		       rc == WRITE_DB_MAP_FULL ? MDB_MAP_FULL : 0);

	if (rc) {
		msg(LOG_ERR, "Failed to create the trust database (%d)", rc);
		drop_candidate_generation(candidate);
		return UPDATE_DB_PRESERVED;
	}

	rc = publish_candidate_generation(candidate);
	if (rc) {
		msg(LOG_ERR, "Failed to publish trust DB generation: %s",
		    mdb_strerror(rc));
		drop_candidate_generation(candidate);
		return UPDATE_DB_PRESERVED;
	}

	check_db_size(config);
	if (!stop)
		request_object_cache_flush();
	mdb_env_sync(env, 1);

	return 0;
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
 * database_reload_from_backends - reload backend snapshots into LMDB.
 * @config: active daemon configuration.
 *
 * The update controller owns request coalescing and FIFO dispatch. This
 * function owns the database work behind a reload: refreshing backend
 * snapshots, applying any auto-size plan, and publishing a complete LMDB
 * trust DB generation only after the rebuild succeeds.
 *
 * Returns 0 on success and non-zero when the previous DB was preserved or a
 * fatal reload error occurred.
 */
int database_reload_from_backends(conf_t *config)
{
	msg(LOG_INFO,
	    "It looks like there was an update of the system... Syncing DB.");

	int rc = 0;
	unsigned int old_db_max_size = config->db_max_size;
	unsigned int old_reload_floor_mb = autosize_reload_floor_mb;

	backend_close();

	/* One-shot utilisation-driven sizing */
	if (config->do_auto_db_sizing &&
	    autosize_database(config, AUTOSIZE_LIVE_INSPECTION)) {
		msg(LOG_INFO, "autosize: map size recomputed to %u MiB",
			config->db_max_size);

		if (config->db_max_size < old_db_max_size) {
			unsigned long old_trust_generation;
			unsigned long old_env_generation;

			/*
			 * This is a map-size reopen, not controlled
			 * compaction. If high-water usage needs physical file
			 * rewrite, status reports recommend the explicit admin
			 * compaction command instead of hiding a swap in reload.
			 */
			old_trust_generation =
				trust_db_current_generation_number();
			lmdb_environment_snapshot(&old_env_generation, NULL);
			if (old_env_generation == 0)
				old_env_generation = 1;

			lock_update_thread();
			close_env(1);

			rc = init_db_with_generations(config,
				old_trust_generation, old_env_generation);
			if (rc) {
				int reopen_rc;

				msg(LOG_ERR,
				    "Cannot open the resized trust database, init_db() (%d)",
				    rc);
				config->db_max_size = old_db_max_size;
				autosize_reload_floor_mb = old_reload_floor_mb;
				reopen_rc = init_db_with_generations(config,
					old_trust_generation,
					old_env_generation);
				if (reopen_rc) {
					msg(LOG_ERR,
					    "Cannot reopen previous trust database, init_db() (%d)",
					    reopen_rc);
					rc = reopen_rc;
				} else
					msg(LOG_ERR,
					    "Previous trust database preserved after reload sizing failure");
			}
			unlock_update_thread();

			if (rc) {
				if (stop)
					goto out;

				record_trust_reload_failure();
				goto out;
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
		goto out;
	}

	if ((rc = backend_load(config))) {
		msg(LOG_ERR, "Failed to load data from backend (%d)", rc);
		record_trust_reload_failure();
		goto out;
	}

	if ((rc = update_database(config, 0))) {
		msg(LOG_ERR,
			"Cannot update trust database!");
		if (stop)
			goto out;

		record_trust_reload_failure();
		if (rc == UPDATE_DB_PRESERVED) {
			msg(LOG_ERR,
			    "Previous trust database preserved after reload failure");
			goto out;
		}

		msg(LOG_ERR,
		    "Trust database reload failed with active DB under daemon control");
		goto out;
	}

	msg(LOG_INFO, "Updated");

out:
	// Conserve memory
	backend_close();
	return rc;
}

/*
 * database_reload_for_tests - run the trust reload path directly.
 * @config: test configuration containing backend and LMDB settings.
 *
 * Returns 0 on success and non-zero when reload failed.
 */
int database_reload_for_tests(conf_t *config)
{
	return database_reload_from_backends(config);
}

/*
 * database_compact_from_backends - perform admin trust DB compaction.
 * @config: active daemon configuration.
 *
 * This is intentionally separate from database_reload_from_backends(). A
 * reload publishes a logical trust DB generation inside the current LMDB
 * environment; compaction rebuilds a whole replacement environment and briefly
 * closes the live one after the replacement has validated. Keeping the entry
 * points separate makes operator intent clear in logs and avoids hidden
 * filesystem swaps on SIGHUP.
 */
void database_compact_from_backends(conf_t *config)
{
	int rc;

	msg(LOG_INFO, "Admin requested trust DB LMDB compaction");
	backend_close();

	if ((rc = backend_init(config))) {
		msg(LOG_ERR, "Failed to load trust data from backend (%d)", rc);
		record_trust_reload_failure();
		goto out;
	}

	if ((rc = backend_load(config))) {
		msg(LOG_ERR, "Failed to load data from backend (%d)", rc);
		record_trust_reload_failure();
		goto out;
	}

	rc = compact_trust_database(config, "admin");
	if (rc) {
		record_trust_reload_failure();
		msg(LOG_ERR,
		    "Trust DB compaction request failed; previous environment preserved");
	} else {
		msg(LOG_INFO, "Trust DB compaction request completed");
	}

out:
	backend_close();
}


/***********************************************************************
 * This section of functions are used by the command line utility to
 * iterate across the database to verify each entry. It will be a read
 * only operation.
 ***********************************************************************/
static walkdb_entry_t wdb_entry;
static MDB_env *walk_env;
static MDB_txn *walk_txn;
static MDB_cursor *walk_cursor;

/*
 * walk_database_reset - close private read-only CLI walk state.
 * @void: no arguments are required.
 *
 * The walker owns these handles. They are intentionally separate from the
 * daemon's global LMDB environment so cleanup here never closes or mutates
 * daemon state.
 *
 * Returns nothing.
 */
static void walk_database_reset(void)
{
	if (walk_cursor)
		mdb_cursor_close(walk_cursor);
	if (walk_txn)
		mdb_txn_abort(walk_txn);
	if (walk_env)
		mdb_env_close(walk_env);
	walk_cursor = NULL;
	walk_txn = NULL;
	walk_env = NULL;
}

/*
 * walk_database_start - open the trust DB for CLI verification.
 * @config: Unused legacy argument kept for the CLI walker API.
 *
 * This must stay a read-only walk. Do not call init_db() or
 * trust_db_read_open() here: those paths open the daemon-style environment and
 * may take write-side LMDB state while setting up handles. The CLI verifier
 * only needs a private read transaction and cursor over the active named DB.
 *
 * Returns WALK_DATABASE_SUCCESS, WALK_DATABASE_EMPTY, or WALK_DATABASE_ERROR.
 */
int walk_database_start(conf_t *config)
{
	MDB_dbi walk_dbi;
	char active_name[TRUST_DB_GENERATION_NAME_SIZE];
	int rc;

	(void)config;
	walk_database_reset();
	snprintf(active_name, sizeof(active_name), "%s", db);

	rc = mdb_env_create(&walk_env);
	if (rc) {
		printf("Cannot create the trust database environment\n");
		return WALK_DATABASE_ERROR;
	}

	rc = mdb_env_set_maxdbs(walk_env, TRUST_DB_MAX_NAMED_DBS);
	if (rc)
		goto error;

	/*
	 * This stays read-only, but it must use LMDB's reader table.  The walk
	 * keeps one transaction open across iteration, so MDB_NOLOCK would let a
	 * daemon reload reclaim old named DB pages behind the verifier's cursor.
	 */
	rc = mdb_env_open(walk_env, data_dir, MDB_RDONLY, 0);
	if (rc)
		goto error;

	rc = mdb_txn_begin(walk_env, NULL, MDB_RDONLY, &walk_txn);
	if (rc)
		goto error;

	rc = database_read_active_name(walk_txn, active_name,
				       sizeof(active_name));
	if (rc)
		goto error;

	rc = mdb_dbi_open(walk_txn, active_name, MDB_DUPSORT, &walk_dbi);
	if (rc)
		goto error;

	rc = mdb_cursor_open(walk_txn, walk_dbi, &walk_cursor);
	if (rc)
		goto error;

	/*
	 * Keep walk_txn open for the cursor lifetime. The returned MDB_val
	 * buffers point into LMDB-managed memory and remain valid until the
	 * cursor/transaction is closed by walk_database_reset().
	 */
	rc = mdb_cursor_get(walk_cursor, &wdb_entry.path, &wdb_entry.data,
			    MDB_FIRST);
	if (rc == 0) {
		/* Keep handles open so walk_database_next() can continue. */
		return WALK_DATABASE_SUCCESS;
	}

	if (rc == MDB_NOTFOUND) {
		printf("The trust database is empty - nothing to do\n");
		walk_database_reset();
		return WALK_DATABASE_EMPTY;
	}

error:
	if (rc)
		puts(mdb_strerror(rc));
	walk_database_reset();
	return WALK_DATABASE_ERROR;
}

/*
 * walk_database_get_entry - return the current walker entry.
 * @void: no arguments are required.
 *
 * The entry's MDB_val buffers are owned by LMDB and are valid until the next
 * walk_database_next() call or walk_database_finish().
 *
 * Returns a pointer to the current walker entry.
 */
walkdb_entry_t *walk_database_get_entry(void)
{
	return &wdb_entry;
}

/*
 * walk_database_next - advance the CLI verification cursor.
 * @void: no arguments are required.
 *
 * Returns 1 when another entry is available and 0 at end of walk or on error.
 */
int walk_database_next(void)
{
	int rc;

	rc = mdb_cursor_get(walk_cursor, &wdb_entry.path, &wdb_entry.data,
			    MDB_NEXT);
	if (rc == 0)
		return 1;

	if (rc != MDB_NOTFOUND)
		puts(mdb_strerror(rc));

	return 0;
}

/*
 * walk_database_finish - close the CLI verification cursor.
 * @void: no arguments are required.
 *
 * Returns nothing.
 */
void walk_database_finish(void)
{
	walk_database_reset();
}

/*
 * database_walk_reader_slots_for_tests - report walker LMDB reader table use.
 * @void: no arguments are required.
 *
 * Returns the number of reader slots LMDB has allocated for the active walker
 * environment, or -1 when no walker is active or LMDB cannot report state.
 */
int database_walk_reader_slots_for_tests(void)
{
	MDB_envinfo info;

	if (walk_env == NULL || walk_txn == NULL)
		return -1;
	if (mdb_env_info(walk_env, &info))
		return -1;
	return (int)info.me_numreaders;
}
