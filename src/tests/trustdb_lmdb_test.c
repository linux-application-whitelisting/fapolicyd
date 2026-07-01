// Copyright 2026 Red Hat
// SPDX-License-Identifier: GPL-2.0-or-later

#define _GNU_SOURCE
#include <stdatomic.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "database.h"
#include "database-internal.h"
#include "decision-config.h"
#include "event.h"
#include "failure-action.h"
#include "fapolicyd-backend.h"

#define CONCURRENT_READERS 32
#define CONCURRENT_ITERATIONS 64
#define RELOAD_READERS 8

#define CHECK(cond, code, msg) \
	do { \
		if (!(cond)) \
			return check_failed(__func__, __LINE__, #cond, \
					    code, msg); \
	} while (0)

struct concurrent_lookup {
	const char *path;
	atomic_bool *start;
	int failed;
};

struct reload_lookup {
	const char *path;
	atomic_bool *start;
	atomic_bool *stop;
	int failed;
};

/*
 * check_failed - report enough context to diagnose hidden Automake logs.
 * @func: Test function containing the failed check.
 * @line: Source line of the failed check.
 * @expr: Failed expression text.
 * @code: Exit code returned by the check.
 * @msg: Human-readable failure message.
 *
 * Returns @code after writing failure context to stderr.
 */
static int check_failed(const char *func, int line, const char *expr,
			int code, const char *msg)
{
	int saved_errno = errno;

	fprintf(stderr, "%s\n", msg);
	fprintf(stderr, "  test: %s\n", func);
	fprintf(stderr, "  check: %s:%d: %s\n", __FILE__, line, expr);
	if (saved_errno)
		fprintf(stderr, "  last errno: %d (%s)\n",
			saved_errno, strerror(saved_errno));

	return code;
}

static int remove_lmdb_files(const char *dir)
{
	char path[512];
	int rc;

	snprintf(path, sizeof(path), "%s/data.mdb", dir);
	rc = unlink(path);
	if (rc == -1 && errno != ENOENT)
		fprintf(stderr, "failed to remove %s: %s\n",
			path, strerror(errno));
	snprintf(path, sizeof(path), "%s/lock.mdb", dir);
	rc = unlink(path);
	if (rc == -1 && errno != ENOENT)
		fprintf(stderr, "failed to remove %s: %s\n",
			path, strerror(errno));

	rc = rmdir(dir);
	if (rc == -1)
		fprintf(stderr, "failed to remove %s: %s\n",
			dir, strerror(errno));

	return rc;
}

/*
 * make_memfd_input - Build an in-memory backend snapshot payload.
 * @text: Newline-delimited trust records.
 *
 * Returns an fd positioned at offset 0 on success, or -1 on failure.
 */
static int make_memfd_input(const char *text)
{
	int fd;
	size_t len = strlen(text);

	fd = memfd_create("trustdb-test", 0);
	if (fd == -1)
		return -1;

	if (write(fd, text, len) != (ssize_t)len) {
		close(fd);
		return -1;
	}

	if (lseek(fd, 0, SEEK_SET) == -1) {
		close(fd);
		return -1;
	}

	return fd;
}

/*
 * build_long_path - Produce a deterministic long path string.
 * @suffix: Distinguishing suffix appended after a shared long prefix.
 *
 * Returns newly allocated path string on success, NULL on allocation error.
 */
static char *build_long_path(const char *suffix)
{
	size_t prefix_len = 700;
	size_t suffix_len = strlen(suffix);
	size_t len = 5 + prefix_len + 1 + suffix_len;
	char *path = malloc(len + 1);

	if (path == NULL)
		return NULL;

	memcpy(path, "/tmp/", 5);
	memset(path + 5, 'p', prefix_len);
	path[5 + prefix_len] = '/';
	memcpy(path + 5 + prefix_len + 1, suffix, suffix_len);
	path[len] = '\0';

	return path;
}

static int import_records(const char *payload, long *entries)
{
	int fd = make_memfd_input(payload);
	int rc;

	if (fd == -1)
		return 1;

	rc = do_memfd_update(fd, entries);
	close(fd);
	return rc;
}

static int publish_records(conf_t *cfg, const char *payload)
{
	int fd = make_memfd_input(payload);
	int rc;

	if (fd == -1)
		return 1;

	rc = database_publish_memfd_for_tests(fd, cfg);
	close(fd);
	return rc;
}

static int publish_startup_records(conf_t *cfg, const char *payload)
{
	int fd = make_memfd_input(payload);
	int rc;

	if (fd == -1)
		return 1;

	rc = database_publish_startup_memfd_for_tests(fd, cfg);
	close(fd);
	return rc;
}

static int drop_candidate_records(const char *payload)
{
	int fd = make_memfd_input(payload);
	int rc;

	if (fd == -1)
		return 1;

	rc = database_drop_candidate_after_import_for_tests(fd);
	close(fd);
	return rc;
}

/*
 * write_all - write a complete test payload to an open descriptor.
 * @fd: descriptor to write.
 * @contents: NUL-terminated test payload.
 *
 * Returns 0 after writing all bytes, or 1 on write failure.
 */
static int write_all(int fd, const char *contents)
{
	size_t len = strlen(contents);
	size_t done = 0;

	while (done < len) {
		ssize_t written = write(fd, contents + done, len - done);

		if (written == -1) {
			if (errno == EINTR)
				continue;
			return 1;
		}
		if (written == 0)
			return 1;
		done += written;
	}

	return 0;
}

/*
 * write_contents - replace the contents of an open test file.
 * @fd: descriptor to rewrite and rewind.
 * @contents: NUL-terminated test payload.
 *
 * Returns 0 on success, or 1 on truncate, seek, or write failure.
 */
static int write_contents(int fd, const char *contents)
{
	if (ftruncate(fd, 0) == -1)
		return 1;
	if (lseek(fd, 0, SEEK_SET) == -1)
		return 1;
	if (write_all(fd, contents))
		return 1;
	if (lseek(fd, 0, SEEK_SET) == -1)
		return 1;

	return 0;
}

/*
 * create_test_file - create a temporary file with known contents.
 * @path: caller buffer receiving the created path.
 * @path_size: size of @path.
 * @contents: NUL-terminated test payload.
 *
 * Returns an open descriptor on success, or -1 on failure.
 */
static int create_test_file(char *path, size_t path_size, const char *contents)
{
	char template[] = "/tmp/fapolicyd-trustdb-file-XXXXXX";
	int fd;
	int saved_errno;

	fd = mkstemp(template);
	if (fd == -1)
		return -1;

	if (strlen(template) + 1 > path_size) {
		saved_errno = ENAMETOOLONG;
		close(fd);
		unlink(template);
		errno = saved_errno;
		return -1;
	}

	if (write_contents(fd, contents)) {
		saved_errno = errno;
		close(fd);
		unlink(template);
		errno = saved_errno;
		return -1;
	}

	strcpy(path, template);
	return fd;
}

/*
 * replace_test_file - atomically replace a path while old fds stay open.
 * @path: existing path to replace with a new inode.
 * @contents: NUL-terminated replacement payload.
 *
 * Returns 0 on success, or 1 on failure.
 */
static int replace_test_file(const char *path, const char *contents)
{
	char template[] = "/tmp/fapolicyd-trustdb-replacement-XXXXXX";
	int fd;
	int saved_errno;

	fd = mkstemp(template);
	if (fd == -1)
		return 1;

	if (write_contents(fd, contents))
		goto fail;
	if (close(fd) == -1) {
		fd = -1;
		goto fail;
	}
	fd = -1;

	if (rename(template, path) == -1)
		goto fail;

	return 0;

fail:
	saved_errno = errno;
	if (fd != -1)
		close(fd);
	unlink(template);
	errno = saved_errno;
	return 1;
}

/*
 * describe_test_file - collect file metadata and SHA256 digest for trust.
 * @fd: descriptor to describe.
 * @info: receives allocated file metadata.
 * @hash: receives allocated SHA256 digest text.
 *
 * Returns 0 on success, or 1 on stat/hash failure.
 */
static int describe_test_file(int fd, struct file_info **info, char **hash)
{
	*info = stat_file_entry(fd);
	if (*info == NULL)
		return 1;

	*hash = get_hash_from_fd2(fd, (*info)->size, FILE_HASH_ALG_SHA256);
	if (*hash == NULL) {
		free(*info);
		*info = NULL;
		return 1;
	}

	return 0;
}

/*
 * read_database_metrics_report - capture trust DB metrics text.
 * @buf: output buffer for report text.
 * @size: size of @buf.
 * @reset: non-zero resets metrics after snapshotting.
 *
 * Returns 0 on success and 1 on failure.
 */
static int read_database_metrics_report(char *buf, size_t size, int reset)
{
	FILE *report;
	size_t used;

	report = tmpfile();
	if (report == NULL)
		return 1;

	database_metrics_report_reset(report, reset);
	fflush(report);
	rewind(report);
	used = fread(buf, 1, size - 1, report);
	fclose(report);
	buf[used] = '\0';

	return 0;
}

/*
 * read_database_utilization_text - capture trust DB status text.
 * @cfg: configuration passed to the utilization report.
 * @buf: output buffer for report text.
 * @size: size of @buf.
 *
 * Returns 0 on success and 1 on failure.
 */
static int read_database_utilization_text(conf_t *cfg, char *buf, size_t size)
{
	FILE *report;
	size_t used;

	report = tmpfile();
	if (report == NULL)
		return 1;

	database_utilization_report(report, cfg);
	fflush(report);
	rewind(report);
	used = fread(buf, 1, size - 1, report);
	fclose(report);
	buf[used] = '\0';

	return 0;
}

/*
 * concurrent_lookup_worker - repeatedly read one trust DB key.
 * @arg: struct concurrent_lookup pointer.
 *
 * Returns NULL after recording any lookup failure in @arg.
 */
static void *concurrent_lookup_worker(void *arg)
{
	struct concurrent_lookup *lookup = arg;

	while (!atomic_load_explicit(lookup->start, memory_order_acquire))
		;

	for (unsigned int i = 0; i < CONCURRENT_ITERATIONS; i++) {
		if (check_trust_database(lookup->path, NULL, -1) != 1) {
			lookup->failed = 1;
			break;
		}
	}

	return NULL;
}

/*
 * reload_lookup_worker - read one key until a publish storm finishes.
 * @arg: struct reload_lookup pointer.
 *
 * Returns NULL after recording any lookup failure in @arg.
 */
static void *reload_lookup_worker(void *arg)
{
	struct reload_lookup *lookup = arg;

	while (!atomic_load_explicit(lookup->start, memory_order_acquire))
		;

	while (!atomic_load_explicit(lookup->stop, memory_order_acquire)) {
		if (check_trust_database(lookup->path, NULL, -1) != 1) {
			lookup->failed = 1;
			break;
		}
	}

	return NULL;
}

static int with_temp_db(char *tmpdir, size_t tmpdir_sz, conf_t *cfg)
{
	char template[] = "/tmp/fapolicyd-lmdb-XXXXXX";
	char *dir = mkdtemp(template);
	int rc;

	if (dir == NULL) {
		fprintf(stderr, "mkdtemp failed for %s: %s\n",
			template, strerror(errno));
		return 1;
	}

	if (strlen(dir) + 1 > tmpdir_sz) {
		fprintf(stderr, "temporary LMDB path too long: %s\n", dir);
		return 1;
	}

	strcpy(tmpdir, dir);
	memset(cfg, 0, sizeof(*cfg));
	cfg->db_max_size = 16;
	cfg->integrity = IN_NONE;
	/*
	 * Some subtests intentionally start CONCURRENT_READERS lookup threads.
	 * Size the LMDB reader table for that pressure so success does not
	 * depend on whether the scheduler overlaps more than the default
	 * one-worker reader budget.
	 */
	cfg->decision_threads = CONCURRENT_READERS;

	rc = database_set_location(tmpdir, NULL);
	if (rc) {
		fprintf(stderr, "database_set_location(%s) failed: %d\n",
			tmpdir, rc);
		return 1;
	}

	rc = database_open_for_tests(cfg);
	if (rc)
		fprintf(stderr, "database_open_for_tests(%s) failed: %d\n",
			tmpdir, rc);

	return rc;
}

static int test_data_format_round_trip(void)
{
	const char *digest =
	"68879112e7d8a66c61178c409b07d1233270bcf2375d2ea029ca68f355284656"
	"3426b625f946c478c37b910373c44a0b89c08b9897885e9b135b11a6db604550";
	char data[TRUSTDB_DATA_BUFSZ];
	char parsed_digest[FILE_DIGEST_STRING_MAX];
	unsigned int tsource;
	off_t size;
	int written;

	written = snprintf(data, sizeof(data), DATA_FORMAT, SRC_RPM,
			   (off_t)9400, digest);
	CHECK(written >= 0 && written < (int)sizeof(data), 10,
	      "[ERROR:10] DATA_FORMAT output truncated");

	CHECK(sscanf(data, DATA_FORMAT_IN, &tsource, &size, parsed_digest) == 3,
	      11, "[ERROR:11] DATA_FORMAT_IN parse failed");
	CHECK(strcmp(digest, parsed_digest) == 0, 12,
	      "[ERROR:12] digest mismatch after round trip");
	return 0;
}

static int test_lmdb_short_path_round_trip(void)
{
	conf_t cfg;
	char dir[128];
	long entries = 0;
	int rc;
	const char *path = "/usr/bin/short-path";
	const char *digest =
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
	char payload[256];

	rc = with_temp_db(dir, sizeof(dir), &cfg);
	CHECK(rc == 0, 20, "[ERROR:20] failed to open temporary LMDB");

	snprintf(payload, sizeof(payload), "%s " DATA_FORMAT "\n", path,
		 SRC_FILE_DB, (size_t)1234, digest);
	rc = import_records(payload, &entries);
	CHECK(rc == 0 && entries == 1, 21,
	      "[ERROR:21] short-path record import failed");

	CHECK(check_trust_database(path, NULL, -1) == 1, 22,
	      "[ERROR:22] short-path lookup failed");

	database_close_for_tests();
	database_set_location(NULL, NULL);
	CHECK(remove_lmdb_files(dir) == 0, 23,
	      "[ERROR:23] short-path cleanup failed");
	return 0;
}

static int test_lmdb_long_path_round_trip(void)
{
	conf_t cfg;
	char dir[128];
	long entries = 0;
	int rc;
	char payload[2048];
	char *path = build_long_path("long-round-trip");
	const char *digest =
		"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

	CHECK(path != NULL, 30, "[ERROR:30] failed to allocate long path");

	rc = with_temp_db(dir, sizeof(dir), &cfg);
	CHECK(rc == 0, 31, "[ERROR:31] failed to open temporary LMDB");

	snprintf(payload, sizeof(payload), "%s " DATA_FORMAT "\n", path,
		 SRC_FILE_DB, (size_t)2048, digest);
	rc = import_records(payload, &entries);
	CHECK(rc == 0 && entries == 1, 32,
	      "[ERROR:32] long-path record import failed");

	CHECK(check_trust_database(path, NULL, -1) == 1, 33,
	      "[ERROR:33] long-path lookup failed");

	free(path);
	database_close_for_tests();
	database_set_location(NULL, NULL);
	CHECK(remove_lmdb_files(dir) == 0, 34,
	      "[ERROR:34] long-path cleanup failed");
	return 0;
}

static int test_lmdb_long_path_shared_prefix_no_collision(void)
{
	conf_t cfg;
	char dir[128];
	long entries = 0;
	int rc;
	int count = 1;
	char *path_a = build_long_path("shared-suffix-a");
	char *path_b = build_long_path("shared-suffix-b");
	char payload[4096];
	walkdb_entry_t *entry;
	const char *digest_a =
		"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
	const char *digest_b =
		"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

	CHECK(path_a && path_b, 40,
	      "[ERROR:40] failed to allocate shared-prefix long paths");

	rc = with_temp_db(dir, sizeof(dir), &cfg);
	CHECK(rc == 0, 41, "[ERROR:41] failed to open temporary LMDB");

	/*
	 * Security regression guard: these paths intentionally share a very long
	 * prefix and diverge only after LMDB key size limits. If lookup-side code
	 * hashes a truncated prefix instead of the full path length, one of these
	 * lookups will fail or collide.
	 */
	snprintf(payload, sizeof(payload), "%s " DATA_FORMAT "\n"
		 "%s " DATA_FORMAT "\n",
		 path_a, SRC_FILE_DB, (size_t)3000, digest_a,
		 path_b, SRC_FILE_DB, (size_t)3001, digest_b);
	rc = import_records(payload, &entries);
	CHECK(rc == 0 && entries == 2, 42,
	      "[ERROR:42] shared-prefix record import failed");

	CHECK(check_trust_database(path_a, NULL, -1) == 1, 43,
	      "[ERROR:43] long-path A lookup failed");
	CHECK(check_trust_database(path_b, NULL, -1) == 1, 44,
	      "[ERROR:44] long-path B lookup failed");

	database_close_for_tests();

	CHECK(walk_database_start(&cfg) == 0, 45,
	      "[ERROR:45] walk_database_start failed");
	CHECK(database_walk_reader_slots_for_tests() > 0, 49,
	      "[ERROR:49] walker did not register an LMDB reader");
	entry = walk_database_get_entry();
	CHECK(entry != NULL, 46, "[ERROR:46] walk_database_get_entry failed");
	while (walk_database_next())
		count++;
	walk_database_finish();
	CHECK(count == 2, 47, "[ERROR:47] walker did not see two entries");

	database_set_location(NULL, NULL);
	CHECK(remove_lmdb_files(dir) == 0, 48,
	      "[ERROR:48] shared-prefix cleanup failed");

	free(path_a);
	free(path_b);
	return 0;
}

/*
 * test_lmdb_readonly_probe_does_not_break_live_env - Guard LMDB mutexes.
 *
 * Returns 0 when a read-only probe environment can be opened and closed
 * without breaking the existing writable trust database handle.
 */
static int test_lmdb_readonly_probe_does_not_break_live_env(void)
{
	conf_t cfg;
	char dir[128];
	long entries = 0;
	int rc;
	MDB_env *probe = NULL;
	const char *digest_a =
		"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
	const char *digest_b =
		"1111111111111111111111111111111111111111111111111111111111111111";
	char payload[512];

	rc = with_temp_db(dir, sizeof(dir), &cfg);
	CHECK(rc == 0, 60, "[ERROR:60] failed to open temporary LMDB");

	snprintf(payload, sizeof(payload), "%s " DATA_FORMAT "\n",
		 "/usr/bin/probe-a", SRC_FILE_DB, (size_t)123, digest_a);
	rc = import_records(payload, &entries);
	CHECK(rc == 0 && entries == 1, 61,
	      "[ERROR:61] initial record import failed");

	rc = mdb_env_create(&probe);
	CHECK(rc == 0, 62, "[ERROR:62] failed to create probe environment");
	rc = mdb_env_set_maxdbs(probe, 2);
	CHECK(rc == 0, 63, "[ERROR:63] failed to size probe environment");
	rc = mdb_env_open(probe, dir, MDB_RDONLY|MDB_NOLOCK, 0);
	CHECK(rc == 0, 64, "[ERROR:64] failed to open probe environment");
	mdb_env_close(probe);
	probe = NULL;

	entries = 0;
	snprintf(payload, sizeof(payload), "%s " DATA_FORMAT "\n",
		 "/usr/bin/probe-b", SRC_FILE_DB, (size_t)456, digest_b);
	rc = import_records(payload, &entries);
	CHECK(rc == 0 && entries == 1, 65,
	      "[ERROR:65] live environment import failed after probe close");

	CHECK(check_trust_database("/usr/bin/probe-b", NULL, -1) == 1, 66,
	      "[ERROR:66] post-probe lookup failed");

	database_close_for_tests();
	database_set_location(NULL, NULL);
	CHECK(remove_lmdb_files(dir) == 0, 67,
	      "[ERROR:67] probe cleanup failed");
	return 0;
}

/*
 * test_lmdb_readonly_lookup_keeps_dbi_valid - Guard CLI read-only lookups.
 *
 * Returns 0 when the DBI opened during read-only lookup setup remains usable
 * by later lookup transactions.
 */
static int test_lmdb_readonly_lookup_keeps_dbi_valid(void)
{
	conf_t cfg;
	char dir[128];
	long entries = 0;
	int rc;
	const char *trusted_path = "/usr/bin/readonly-dbi";
	const char *digest =
		"abababababababababababababababababababababababababababababababab";
	char payload[512];

	rc = with_temp_db(dir, sizeof(dir), &cfg);
	CHECK(rc == 0, 250, "[ERROR:250] failed to open temporary LMDB");

	snprintf(payload, sizeof(payload), "%s " DATA_FORMAT "\n",
		 trusted_path, SRC_FILE_DB, (size_t)789, digest);
	rc = import_records(payload, &entries);
	CHECK(rc == 0 && entries == 1, 251,
	      "[ERROR:251] readonly lookup record import failed");

	database_close_for_tests();

	rc = database_readonly_lookup_start();
	CHECK(rc == 0, 252, "[ERROR:252] readonly lookup start failed");
	CHECK(check_trust_database_readonly(trusted_path, NULL, -1) == 1, 253,
	      "[ERROR:253] readonly lookup could not read trusted path");

	database_readonly_lookup_finish();
	database_set_location(NULL, NULL);
	CHECK(remove_lmdb_files(dir) == 0, 254,
	      "[ERROR:254] readonly lookup cleanup failed");
	return 0;
}

static int test_lmdb_chunked_import(void)
{
	const unsigned int record_count = 4105;
	const char *digest =
		"2222222222222222222222222222222222222222222222222222222222222222";
	conf_t cfg;
	char dir[128];
	char first_path[64];
	char last_path[64];
	char *payload = NULL;
	size_t payload_size = 0;
	FILE *stream;
	long entries = 0;
	int rc;

	rc = with_temp_db(dir, sizeof(dir), &cfg);
	CHECK(rc == 0, 90, "[ERROR:90] failed to open temporary LMDB");

	stream = open_memstream(&payload, &payload_size);
	CHECK(stream != NULL, 91,
	      "[ERROR:91] failed to allocate chunked payload");

	for (unsigned int i = 0; i < record_count; i++) {
		fprintf(stream, "/usr/bin/chunked-%04u " DATA_FORMAT "\n",
			i, SRC_FILE_DB, (size_t)(9000 + i), digest);
	}
	fclose(stream);

	rc = import_records(payload, &entries);
	free(payload);
	CHECK(rc == 0 && entries == (long)record_count, 92,
	      "[ERROR:92] chunked record import failed");

	snprintf(first_path, sizeof(first_path), "/usr/bin/chunked-%04u", 0);
	snprintf(last_path, sizeof(last_path), "/usr/bin/chunked-%04u",
		 record_count - 1);
	CHECK(check_trust_database(first_path, NULL, -1) == 1, 93,
	      "[ERROR:93] first chunked lookup failed");
	CHECK(check_trust_database(last_path, NULL, -1) == 1, 94,
	      "[ERROR:94] last chunked lookup failed");

	database_close_for_tests();
	database_set_location(NULL, NULL);
	CHECK(remove_lmdb_files(dir) == 0, 95,
	      "[ERROR:95] chunked cleanup failed");
	return 0;
}

static int test_lmdb_long_path_negative_lookup(void)
{
	conf_t cfg;
	char dir[128];
	long entries = 0;
	int rc;
	char *path_a = build_long_path("negative-a");
	char *path_b = build_long_path("negative-b");
	char payload[2048];
	const char *digest =
		"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";

	CHECK(path_a && path_b, 50,
	      "[ERROR:50] failed to allocate negative-lookup paths");

	rc = with_temp_db(dir, sizeof(dir), &cfg);
	CHECK(rc == 0, 51, "[ERROR:51] failed to open temporary LMDB");

	snprintf(payload, sizeof(payload), "%s " DATA_FORMAT "\n", path_a,
		 SRC_FILE_DB, (size_t)4100, digest);
	rc = import_records(payload, &entries);
	CHECK(rc == 0 && entries == 1, 52,
	      "[ERROR:52] negative-lookup record import failed");

	CHECK(check_trust_database(path_b, NULL, -1) == 0, 53,
	      "[ERROR:53] non-existent long path unexpectedly found");

	free(path_a);
	free(path_b);
	database_close_for_tests();
	database_set_location(NULL, NULL);
	CHECK(remove_lmdb_files(dir) == 0, 54,
	      "[ERROR:54] negative-lookup cleanup failed");
	return 0;
}

/*
 * test_lmdb_concurrent_read_handles - exercise per-call LMDB readers.
 *
 * Returns 0 when concurrent trust lookups all succeed and lookup metrics are
 * reported/reset correctly.
 */
static int test_lmdb_concurrent_read_handles(void)
{
	conf_t cfg;
	char dir[128];
	long entries = 0;
	int rc;
	const char *path = "/usr/bin/concurrent-reader";
	const char *digest =
		"9999999999999999999999999999999999999999999999999999999999999999";
	char payload[256];
	char report[512];
	char expected[64];
	pthread_t readers[CONCURRENT_READERS];
	struct concurrent_lookup lookup[CONCURRENT_READERS];
	atomic_bool start = false;
	unsigned long expected_lookups =
		CONCURRENT_READERS * CONCURRENT_ITERATIONS;

	rc = with_temp_db(dir, sizeof(dir), &cfg);
	CHECK(rc == 0, 70, "[ERROR:70] failed to open temporary LMDB");

	snprintf(payload, sizeof(payload), "%s " DATA_FORMAT "\n", path,
		 SRC_FILE_DB, (size_t)555, digest);
	rc = import_records(payload, &entries);
	CHECK(rc == 0 && entries == 1, 71,
	      "[ERROR:71] concurrent record import failed");

	CHECK(read_database_metrics_report(report, sizeof(report), 1) == 0,
	      72, "[ERROR:72] metrics reset report failed");

	for (unsigned int i = 0; i < CONCURRENT_READERS; i++) {
		lookup[i].path = path;
		lookup[i].start = &start;
		lookup[i].failed = 0;
		rc = pthread_create(&readers[i], NULL,
				    concurrent_lookup_worker, &lookup[i]);
		CHECK(rc == 0, 73,
		      "[ERROR:73] failed to create lookup reader");
	}

	atomic_store_explicit(&start, true, memory_order_release);

	for (unsigned int i = 0; i < CONCURRENT_READERS; i++) {
		rc = pthread_join(readers[i], NULL);
		CHECK(rc == 0, 74,
		      "[ERROR:74] failed to join lookup reader");
		CHECK(lookup[i].failed == 0, 75,
		      "[ERROR:75] concurrent lookup failed");
	}

	CHECK(read_database_metrics_report(report, sizeof(report), 1) == 0,
	      76, "[ERROR:76] metrics report failed");
	snprintf(expected, sizeof(expected), "Trust DB lookups: %lu",
		 expected_lookups);
	CHECK(strstr(report, expected) != NULL, 77,
	      "[ERROR:77] lookup metrics count mismatch");
	CHECK(strstr(report, "Trust DB reader slots full: 0") != NULL, 78,
	      "[ERROR:78] reader slots full metric changed");
	CHECK(strstr(report, "Trust DB lookup average") == NULL, 79,
	      "[ERROR:79] lookup average latency metric in metrics report");
	CHECK(strstr(report, "Trust DB lookup max") == NULL, 80,
	      "[ERROR:80] lookup max latency metric in metrics report");

	CHECK(read_database_metrics_report(report, sizeof(report), 0) == 0,
	      81, "[ERROR:81] post-reset metrics report failed");
	CHECK(strstr(report, "Trust DB lookups: 0") != NULL, 82,
	      "[ERROR:82] lookup metrics reset failed");

	database_close_for_tests();
	database_set_location(NULL, NULL);
	CHECK(remove_lmdb_files(dir) == 0, 83,
	      "[ERROR:83] concurrent cleanup failed");
	return 0;
}

static int test_lmdb_nested_read_transaction(void)
{
	conf_t cfg;
	char dir[128];
	long entries = 0;
	int rc;
	const char *path = "/usr/bin/nested-reader";
	const char *digest =
		"8989898989898989898989898989898989898989898989898989898989898989";
	char payload[256];

	rc = with_temp_db(dir, sizeof(dir), &cfg);
	CHECK(rc == 0, 154, "[ERROR:154] failed to open temporary LMDB");

	snprintf(payload, sizeof(payload), "%s " DATA_FORMAT "\n", path,
		 SRC_FILE_DB, (size_t)556, digest);
	rc = import_records(payload, &entries);
	CHECK(rc == 0 && entries == 1, 155,
	      "[ERROR:155] nested record import failed");

	CHECK(database_nested_lookup_for_tests(path) == 1, 156,
	      "[ERROR:156] nested trust lookup failed");
	CHECK(check_trust_database(path, NULL, -1) == 1, 157,
	      "[ERROR:157] post-nested trust lookup failed");

	database_close_for_tests();
	database_set_location(NULL, NULL);
	CHECK(remove_lmdb_files(dir) == 0, 158,
	      "[ERROR:158] nested cleanup failed");
	return 0;
}

static int test_lmdb_failed_candidate_preserves_generation(void)
{
	conf_t cfg;
	char dir[128];
	long entries = 0;
	int rc;
	database_generation_test_report_t before, after;
	const char *path_a = "/usr/bin/preserved-a";
	const char *path_b = "/usr/bin/unpublished-b";
	const char *digest_a =
		"abababababababababababababababababababababababababababababababab";
	const char *digest_b =
		"babababababababababababababababababababababababababababababababa";
	char payload[512];
	unsigned long flush_generation;

	rc = with_temp_db(dir, sizeof(dir), &cfg);
	CHECK(rc == 0, 100, "[ERROR:100] failed to open temporary LMDB");

	snprintf(payload, sizeof(payload), "%s " DATA_FORMAT "\n", path_a,
		 SRC_FILE_DB, (size_t)100, digest_a);
	rc = import_records(payload, &entries);
	CHECK(rc == 0 && entries == 1, 101,
	      "[ERROR:101] preserved record import failed");
	CHECK(database_generation_report_for_tests(&before) == 0, 102,
	      "[ERROR:102] generation report failed");

	flush_generation = object_cache_flush_generation_snapshot();
	snprintf(payload, sizeof(payload), "%s " DATA_FORMAT "\n", path_b,
		 SRC_FILE_DB, (size_t)200, digest_b);
	rc = drop_candidate_records(payload);
	CHECK(rc == 0, 103, "[ERROR:103] candidate import/drop failed");
	CHECK(database_generation_report_for_tests(&after) == 0, 104,
	      "[ERROR:104] post-drop generation report failed");
	CHECK(after.generation == before.generation, 105,
	      "[ERROR:105] failed candidate changed active generation");
	CHECK(check_trust_database(path_a, NULL, -1) == 1, 106,
	      "[ERROR:106] preserved generation lookup failed");
	CHECK(check_trust_database(path_b, NULL, -1) == 0, 107,
	      "[ERROR:107] dropped candidate became visible");
	CHECK(object_cache_flush_generation_snapshot() == flush_generation, 108,
	      "[ERROR:108] failed candidate requested cache flush");

	database_close_for_tests();
	database_set_location(NULL, NULL);
	CHECK(remove_lmdb_files(dir) == 0, 109,
	      "[ERROR:109] failed-candidate cleanup failed");
	return 0;
}

static int test_lmdb_reload_failure_preserves_generation(void)
{
	conf_t cfg;
	char dir[128];
	long entries = 0;
	int rc;
	unsigned long before_failures, after_failures;
	database_generation_test_report_t before, after;
	const char *path = "/usr/bin/reload-preserved";
	const char *digest =
		"cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";
	char payload[256];

	rc = with_temp_db(dir, sizeof(dir), &cfg);
	CHECK(rc == 0, 210, "[ERROR:210] failed to open temporary LMDB");

	snprintf(payload, sizeof(payload), "%s " DATA_FORMAT "\n", path,
		 SRC_FILE_DB, (size_t)300, digest);
	rc = import_records(payload, &entries);
	CHECK(rc == 0 && entries == 1, 211,
	      "[ERROR:211] reload-preserve record import failed");
	CHECK(database_generation_report_for_tests(&before) == 0, 212,
	      "[ERROR:212] generation report failed before reload failure");

	cfg.trust = "unsupported-test-backend";
	before_failures =
		failure_action_count(FAILURE_REASON_TRUST_RELOAD_FAILURE);
	rc = database_reload_for_tests(&cfg);
	after_failures =
		failure_action_count(FAILURE_REASON_TRUST_RELOAD_FAILURE);
	CHECK(rc != 0, 213, "[ERROR:213] reload failure unexpectedly passed");
	CHECK(after_failures == before_failures + 1, 214,
	      "[ERROR:214] reload failure was not recorded");
	CHECK(database_generation_report_for_tests(&after) == 0, 215,
	      "[ERROR:215] generation report failed after reload failure");
	CHECK(after.generation == before.generation, 216,
	      "[ERROR:216] failed reload changed active generation");
	CHECK(check_trust_database(path, NULL, -1) == 1, 217,
	      "[ERROR:217] failed reload lost previous trust DB");

	database_close_for_tests();
	database_set_location(NULL, NULL);
	CHECK(remove_lmdb_files(dir) == 0, 218,
	      "[ERROR:218] reload-failure cleanup failed");
	return 0;
}

/*
 * test_lmdb_incremental_update_keeps_duplicate_hashes - package update window.
 *
 * A package transaction can replace a trusted executable and then run the new
 * file from a scriptlet before the next full trust DB rebuild publishes. The
 * per-file update path must add the new hash to the active generation without
 * dropping the old hash that existing open executables may still need.
 *
 * Returns 0 when both old and new file contents are trusted after an
 * incremental active update.
 */
static int test_lmdb_incremental_update_keeps_duplicate_hashes(void)
{
	const char old_contents[] = "shadow-utils-useradd-old\n";
	const char new_contents[] = "shadow-utils-useradd-new\n";
	conf_t cfg;
	char dir[128];
	char path[128];
	char payload[512];
	struct file_info *old_info = NULL;
	struct file_info *new_info = NULL;
	char *old_hash = NULL;
	char *new_hash = NULL;
	long entries = 0;
	int old_fd = -1;
	int new_fd = -1;
	int rc;

	old_fd = create_test_file(path, sizeof(path), old_contents);
	CHECK(old_fd != -1, 230,
	      "[ERROR:230] failed to create old package file");
	rc = describe_test_file(old_fd, &old_info, &old_hash);
	CHECK(rc == 0, 231, "[ERROR:231] failed to hash old package file");

	rc = with_temp_db(dir, sizeof(dir), &cfg);
	CHECK(rc == 0, 232, "[ERROR:232] failed to open temporary LMDB");

	cfg.integrity = IN_SHA256;
	rc = decision_config_publish(&cfg);
	CHECK(rc == 0, 233,
	      "[ERROR:233] failed to publish SHA256 integrity config");

	snprintf(payload, sizeof(payload), "%s " DATA_FORMAT "\n", path,
		 SRC_RPM, (size_t)old_info->size, old_hash);
	rc = import_records(payload, &entries);
	CHECK(rc == 0 && entries == 1, 234,
	      "[ERROR:234] old package record import failed");
	CHECK(check_trust_database(path, old_info, old_fd) == 1, 235,
	      "[ERROR:235] old package file was not trusted");

	rc = replace_test_file(path, new_contents);
	CHECK(rc == 0, 236, "[ERROR:236] failed to replace package file");
	new_fd = open(path, O_RDONLY|O_CLOEXEC);
	CHECK(new_fd != -1, 237,
	      "[ERROR:237] failed to open replacement package file");
	rc = describe_test_file(new_fd, &new_info, &new_hash);
	CHECK(rc == 0, 238,
	      "[ERROR:238] failed to hash replacement package file");
	CHECK(old_info->size == new_info->size, 239,
	      "[ERROR:239] replacement test contents changed size");
	CHECK(strcmp(old_hash, new_hash) != 0, 240,
	      "[ERROR:240] replacement test contents did not change hash");
	CHECK(check_trust_database(path, new_info, new_fd) == 0, 241,
	      "[ERROR:241] replacement file trusted before incremental update");

	rc = database_store_update_record(path, (size_t)new_info->size, new_hash);
	CHECK(rc == 0, 242, "[ERROR:242] incremental update failed");
	CHECK(check_trust_database(path, new_info, new_fd) == 1, 243,
	      "[ERROR:243] replacement file was not trusted after update");
	CHECK(check_trust_database(path, old_info, old_fd) == 1, 244,
	      "[ERROR:244] old duplicate hash was not retained");

	close(new_fd);
	close(old_fd);
	unlink(path);
	free(new_hash);
	free(old_hash);
	free(new_info);
	free(old_info);
	decision_config_destroy();
	database_close_for_tests();
	database_set_location(NULL, NULL);
	CHECK(remove_lmdb_files(dir) == 0, 245,
	      "[ERROR:245] incremental-duplicate cleanup failed");
	return 0;
}

static int test_lmdb_autosize_generation_reload_target(void)
{
	unsigned int target;

	target = database_autosize_target_mb_for_tests(
		/*active_pages*/14277,
		/*allocated_pages*/14283,
		/*map_pages*/21760,
		/*page_size*/4096);
	CHECK(target >= 140, 110,
	      "[ERROR:110] autosize target ignored reload headroom");
	CHECK(target > 85, 111,
	      "[ERROR:111] autosize target kept undersized map");
	return 0;
}

static int test_lmdb_autosize_retry_uses_actual_map(void)
{
	unsigned int retry;

	retry = database_autosize_retry_mb_for_tests(
		/*old_mb*/8,
		/*active_pages*/256,
		/*map_pages*/25600,
		/*page_size*/4096);
	CHECK(retry >= 125, 134,
	      "[ERROR:134] autosize retry ignored actual LMDB map size");
	CHECK(retry > 8, 135,
	      "[ERROR:135] autosize retry did not grow configured size");
	return 0;
}

static int test_lmdb_manual_resize_report_is_gated(void)
{
	conf_t cfg;
	char dir[128];
	char report[2048];
	char *payload;
	size_t used = 0;
	long entries = 0;
	int rc;
	const unsigned int records = 12000;
	const char *digest =
		"9191919191919191919191919191919191919191919191919191919191919191";

	rc = with_temp_db(dir, sizeof(dir), &cfg);
	CHECK(rc == 0, 112, "[ERROR:112] failed to open temporary LMDB");

	payload = calloc(records, 192);
	CHECK(payload != NULL, 113,
	      "[ERROR:113] resize report payload allocation failed");

	for (unsigned int i = 0; i < records; i++) {
		int written = snprintf(payload + used, records * 192 - used,
			"/usr/bin/resize-report-%04u " DATA_FORMAT "\n",
			i, SRC_FILE_DB, (size_t)(1000 + i), digest);

		CHECK(written > 0 && (size_t)written < records * 192 - used,
		      114, "[ERROR:114] resize report payload truncated");
		used += written;
	}

	rc = import_records(payload, &entries);
	free(payload);
	CHECK(rc == 0 && entries == records, 115,
	      "[ERROR:115] resize report import failed");

	/*
	 * Simulate a manual configuration that is below the computed reload
	 * target without reopening the test map. The report is about the
	 * administrator's numeric db_max_size, not LMDB's current file size.
	 */
	cfg.db_max_size = 1;
	cfg.do_auto_db_sizing = false;
	CHECK(read_database_utilization_text(&cfg, report, sizeof(report)) == 0,
	      116, "[ERROR:116] manual resize report failed");
	CHECK(strstr(report, "Trust database resize recommended: yes") != NULL,
	      117, "[ERROR:117] manual resize recommendation missing");
	CHECK(strstr(report, "Trust database resize target:") != NULL,
	      118, "[ERROR:118] manual resize target missing");

	cfg.do_auto_db_sizing = true;
	CHECK(read_database_utilization_text(&cfg, report, sizeof(report)) == 0,
	      119, "[ERROR:119] auto resize report failed");
	CHECK(strstr(report, "Trust database resize recommended:") == NULL,
	      132, "[ERROR:132] resize recommendation shown in auto mode");

	database_close_for_tests();
	database_set_location(NULL, NULL);
	CHECK(remove_lmdb_files(dir) == 0, 133,
	      "[ERROR:133] resize report cleanup failed");
	return 0;
}

static int test_lmdb_startup_generation_resets(void)
{
	conf_t cfg;
	char dir[128];
	long entries = 0;
	int rc;
	database_generation_test_report_t report;
	const char *path_a = "/usr/bin/startup-generation-a";
	const char *path_b = "/usr/bin/startup-generation-b";
	const char *path_c = "/usr/bin/startup-generation-c";
	const char *path_d = "/usr/bin/startup-generation-d";
	const char *digest =
		"edededededededededededededededededededededededededededededededed";
	char payload[512];

	rc = with_temp_db(dir, sizeof(dir), &cfg);
	CHECK(rc == 0, 160, "[ERROR:160] failed to open temporary LMDB");

	snprintf(payload, sizeof(payload), "%s " DATA_FORMAT "\n", path_a,
		 SRC_FILE_DB, (size_t)100, digest);
	rc = import_records(payload, &entries);
	CHECK(rc == 0 && entries == 1, 161,
	      "[ERROR:161] startup generation initial import failed");
	CHECK(database_generation_report_for_tests(&report) == 0, 162,
	      "[ERROR:162] startup generation initial report failed");
	CHECK(report.generation == 1, 163,
	      "[ERROR:163] initial generation did not start at one");

	snprintf(payload, sizeof(payload), "%s " DATA_FORMAT "\n", path_b,
		 SRC_FILE_DB, (size_t)200, digest);
	rc = publish_records(&cfg, payload);
	CHECK(rc == 0, 164,
	      "[ERROR:164] runtime generation publish failed");
	CHECK(database_generation_report_for_tests(&report) == 0, 165,
	      "[ERROR:165] runtime generation report failed");
	CHECK(report.generation == 2, 166,
	      "[ERROR:166] runtime generation did not advance");

	database_close_for_tests();
	rc = database_open_for_tests(&cfg);
	CHECK(rc == 0, 167, "[ERROR:167] failed to reopen LMDB");
	CHECK(database_generation_report_for_tests(&report) == 0, 168,
	      "[ERROR:168] reopened generation report failed");
	CHECK(report.generation == 1, 169,
	      "[ERROR:169] persisted generation did not reset on startup");
	CHECK(check_trust_database(path_b, NULL, -1) == 1, 170,
	      "[ERROR:170] reopened generation lookup failed");

	snprintf(payload, sizeof(payload), "%s " DATA_FORMAT "\n", path_c,
		 SRC_FILE_DB, (size_t)300, digest);
	rc = publish_startup_records(&cfg, payload);
	CHECK(rc == 0, 171,
	      "[ERROR:171] startup rebuild publish failed");
	CHECK(database_generation_report_for_tests(&report) == 0, 172,
	      "[ERROR:172] startup rebuild report failed");
	CHECK(report.generation == 1, 173,
	      "[ERROR:173] startup rebuild did not reset generation");

	snprintf(payload, sizeof(payload), "%s " DATA_FORMAT "\n", path_d,
		 SRC_FILE_DB, (size_t)400, digest);
	rc = publish_records(&cfg, payload);
	CHECK(rc == 0, 174,
	      "[ERROR:174] post-startup runtime publish failed");
	CHECK(database_generation_report_for_tests(&report) == 0, 175,
	      "[ERROR:175] post-startup runtime report failed");
	CHECK(report.generation == 2, 176,
	      "[ERROR:176] post-startup runtime generation mismatch");

	database_close_for_tests();
	database_set_location(NULL, NULL);
	CHECK(remove_lmdb_files(dir) == 0, 177,
	      "[ERROR:177] startup generation cleanup failed");
	return 0;
}

static int test_lmdb_offline_compaction_swaps_environment(void)
{
	conf_t cfg;
	char dir[128];
	long entries = 0;
	int rc;
	database_generation_test_report_t before, after;
	const char *path_a = "/usr/bin/offline-compact-a";
	const char *path_b = "/usr/bin/offline-compact-b";
	const char *digest_a =
		"1212121212121212121212121212121212121212121212121212121212121212";
	const char *digest_b =
		"3434343434343434343434343434343434343434343434343434343434343434";
	char payload[512];
	unsigned long flush_generation;

	rc = with_temp_db(dir, sizeof(dir), &cfg);
	CHECK(rc == 0, 180, "[ERROR:180] failed to open temporary LMDB");

	snprintf(payload, sizeof(payload), "%s " DATA_FORMAT "\n", path_a,
		 SRC_FILE_DB, (size_t)500, digest_a);
	rc = import_records(payload, &entries);
	CHECK(rc == 0 && entries == 1, 181,
	      "[ERROR:181] offline initial import failed");
	CHECK(database_generation_report_for_tests(&before) == 0, 182,
	      "[ERROR:182] offline initial report failed");
	CHECK(before.generation == 1 && before.lmdb_generation == 1, 183,
	      "[ERROR:183] initial LMDB generation mismatch");

	flush_generation = object_cache_flush_generation_snapshot();
	snprintf(payload, sizeof(payload), "%s " DATA_FORMAT "\n", path_b,
		 SRC_FILE_DB, (size_t)600, digest_b);
	{
		int fd = make_memfd_input(payload);

		CHECK(fd != -1, 184,
		      "[ERROR:184] offline compaction memfd failed");
		rc = database_compact_memfd_for_tests(fd, &cfg);
		close(fd);
	}
	CHECK(rc == 0, 185, "[ERROR:185] offline compaction failed");
	CHECK(database_generation_report_for_tests(&after) == 0, 186,
	      "[ERROR:186] offline compaction report failed");
	CHECK(after.generation == before.generation + 1, 187,
	      "[ERROR:187] trust generation did not advance");
	CHECK(after.lmdb_generation == before.lmdb_generation + 1, 188,
	      "[ERROR:188] LMDB environment generation did not advance");
	CHECK(check_trust_database(path_a, NULL, -1) == 0, 189,
	      "[ERROR:189] old environment record survived replacement");
	CHECK(check_trust_database(path_b, NULL, -1) == 1, 190,
	      "[ERROR:190] rebuilt environment record missing");
	CHECK(object_cache_flush_generation_snapshot() > flush_generation, 191,
	      "[ERROR:191] offline compaction did not request cache flush");

	database_close_for_tests();
	database_set_location(NULL, NULL);
	CHECK(remove_lmdb_files(dir) == 0, 192,
	      "[ERROR:192] offline compaction cleanup failed");
	return 0;
}

static int test_lmdb_offline_compaction_preserves_busy_environment(void)
{
	conf_t cfg;
	char dir[128];
	long entries = 0;
	int rc;
	void *held;
	database_generation_test_report_t before, after;
	const char *path_a = "/usr/bin/offline-preserve-a";
	const char *path_b = "/usr/bin/offline-preserve-b";
	const char *digest =
		"5656565656565656565656565656565656565656565656565656565656565656";
	char payload[512];

	rc = with_temp_db(dir, sizeof(dir), &cfg);
	CHECK(rc == 0, 193, "[ERROR:193] failed to open temporary LMDB");

	snprintf(payload, sizeof(payload), "%s " DATA_FORMAT "\n", path_a,
		 SRC_FILE_DB, (size_t)700, digest);
	rc = import_records(payload, &entries);
	CHECK(rc == 0 && entries == 1, 194,
	      "[ERROR:194] preserve initial import failed");
	CHECK(database_generation_report_for_tests(&before) == 0, 195,
	      "[ERROR:195] preserve initial report failed");

	held = database_generation_hold_for_tests();
	CHECK(held != NULL, 196,
	      "[ERROR:196] preserve generation hold failed");

	snprintf(payload, sizeof(payload), "%s " DATA_FORMAT "\n", path_b,
		 SRC_FILE_DB, (size_t)800, digest);
	{
		int fd = make_memfd_input(payload);

		CHECK(fd != -1, 197,
		      "[ERROR:197] preserve compaction memfd failed");
		rc = database_compact_memfd_for_tests(fd, &cfg);
		close(fd);
	}
	CHECK(rc != 0, 198,
	      "[ERROR:198] compaction unexpectedly swapped busy environment");
	database_generation_release_for_tests(held);
	CHECK(database_generation_report_for_tests(&after) == 0, 199,
	      "[ERROR:199] preserve after report failed");
	CHECK(after.generation == before.generation, 200,
	      "[ERROR:200] failed compaction changed trust generation");
	CHECK(after.lmdb_generation == before.lmdb_generation, 201,
	      "[ERROR:201] failed compaction changed LMDB generation");
	CHECK(check_trust_database(path_a, NULL, -1) == 1, 202,
	      "[ERROR:202] old record missing after failed compaction");
	CHECK(check_trust_database(path_b, NULL, -1) == 0, 203,
	      "[ERROR:203] failed compaction published new record");

	database_close_for_tests();
	database_set_location(NULL, NULL);
	CHECK(remove_lmdb_files(dir) == 0, 204,
	      "[ERROR:204] preserve compaction cleanup failed");
	return 0;
}

static int test_lmdb_held_reader_delays_reclamation(void)
{
	conf_t cfg;
	char dir[128];
	long entries = 0;
	int rc;
	void *held;
	database_generation_test_report_t report;
	const char *path_a = "/usr/bin/held-reader-a";
	const char *path_b = "/usr/bin/held-reader-b";
	const char *digest_a =
		"cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";
	const char *digest_b =
		"dcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdc";
	char payload[512];

	rc = with_temp_db(dir, sizeof(dir), &cfg);
	CHECK(rc == 0, 120, "[ERROR:120] failed to open temporary LMDB");

	snprintf(payload, sizeof(payload), "%s " DATA_FORMAT "\n", path_a,
		 SRC_FILE_DB, (size_t)300, digest_a);
	rc = import_records(payload, &entries);
	CHECK(rc == 0 && entries == 1, 121,
	      "[ERROR:121] held-reader initial import failed");

	held = database_generation_hold_for_tests();
	CHECK(held != NULL, 122, "[ERROR:122] failed to hold generation");

	snprintf(payload, sizeof(payload), "%s " DATA_FORMAT "\n", path_b,
		 SRC_FILE_DB, (size_t)400, digest_b);
	rc = publish_records(&cfg, payload);
	CHECK(rc == 0, 123, "[ERROR:123] held-reader publish failed");
	CHECK(database_generation_report_for_tests(&report) == 0, 124,
	      "[ERROR:124] held-reader report failed");
	CHECK(report.retired_count == 1, 125,
	      "[ERROR:125] held reader did not delay retired generation");

	database_reclaim_generations_for_tests();
	CHECK(database_generation_report_for_tests(&report) == 0, 126,
	      "[ERROR:126] held-reader reclaim report failed");
	CHECK(report.retired_count == 1, 127,
	      "[ERROR:127] reclaimed generation while reader was held");

	database_generation_release_for_tests(held);
	database_reclaim_generations_for_tests();
	CHECK(database_generation_report_for_tests(&report) == 0, 128,
	      "[ERROR:128] post-release report failed");
	CHECK(report.retired_count == 0, 129,
	      "[ERROR:129] released generation was not reclaimed");
	CHECK(check_trust_database(path_b, NULL, -1) == 1, 130,
	      "[ERROR:130] published generation lookup failed");

	database_close_for_tests();
	database_set_location(NULL, NULL);
	CHECK(remove_lmdb_files(dir) == 0, 131,
	      "[ERROR:131] held-reader cleanup failed");
	return 0;
}

static int test_lmdb_concurrent_publish_storm(void)
{
	conf_t cfg;
	char dir[128];
	long entries = 0;
	int rc;
	const char *stable_path = "/usr/bin/reload-stable";
	const char *last_path = "/usr/bin/reload-storm-5";
	const char *digest =
		"efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef";
	char payload[512];
	pthread_t readers[RELOAD_READERS];
	struct reload_lookup lookup[RELOAD_READERS];
	atomic_bool start = false;
	atomic_bool stop_readers = false;
	database_generation_test_report_t before, after;
	unsigned long flush_generation;

	rc = with_temp_db(dir, sizeof(dir), &cfg);
	CHECK(rc == 0, 140, "[ERROR:140] failed to open temporary LMDB");

	snprintf(payload, sizeof(payload), "%s " DATA_FORMAT "\n",
		 stable_path, SRC_FILE_DB, (size_t)500, digest);
	rc = import_records(payload, &entries);
	CHECK(rc == 0 && entries == 1, 141,
	      "[ERROR:141] reload-storm initial import failed");
	CHECK(database_generation_report_for_tests(&before) == 0, 142,
	      "[ERROR:142] reload-storm initial report failed");

	for (unsigned int i = 0; i < RELOAD_READERS; i++) {
		lookup[i].path = stable_path;
		lookup[i].start = &start;
		lookup[i].stop = &stop_readers;
		lookup[i].failed = 0;
		rc = pthread_create(&readers[i], NULL, reload_lookup_worker,
				    &lookup[i]);
		CHECK(rc == 0, 143,
		      "[ERROR:143] failed to create reload reader");
	}

	flush_generation = object_cache_flush_generation_snapshot();
	atomic_store_explicit(&start, true, memory_order_release);
	for (unsigned int i = 0; i < 6; i++) {
		snprintf(payload, sizeof(payload),
			 "%s " DATA_FORMAT "\n"
			 "/usr/bin/reload-storm-%u " DATA_FORMAT "\n",
			 stable_path, SRC_FILE_DB, (size_t)(600 + i), digest,
			 i, SRC_FILE_DB, (size_t)(700 + i), digest);
		rc = publish_records(&cfg, payload);
		CHECK(rc == 0, 144,
		      "[ERROR:144] reload-storm publish failed");
		CHECK(object_cache_flush_generation_snapshot() >
		      flush_generation, 145,
		      "[ERROR:145] publish did not request cache flush");
		flush_generation = object_cache_flush_generation_snapshot();
	}

	atomic_store_explicit(&stop_readers, true, memory_order_release);
	for (unsigned int i = 0; i < RELOAD_READERS; i++) {
		rc = pthread_join(readers[i], NULL);
		CHECK(rc == 0, 146,
		      "[ERROR:146] failed to join reload reader");
		CHECK(lookup[i].failed == 0, 147,
		      "[ERROR:147] concurrent lookup failed during publish");
	}

	database_reclaim_generations_for_tests();
	CHECK(database_generation_report_for_tests(&after) == 0, 148,
	      "[ERROR:148] reload-storm final report failed");
	CHECK(after.generation == before.generation + 6, 149,
	      "[ERROR:149] reload-storm generation count mismatch");
	CHECK(after.retired_count == 0, 150,
	      "[ERROR:150] reload-storm retired generations leaked");
	CHECK(check_trust_database(stable_path, NULL, -1) == 1, 151,
	      "[ERROR:151] stable path missing after reload storm");
	CHECK(check_trust_database(last_path, NULL, -1) == 1, 152,
	      "[ERROR:152] last reload-storm path missing");

	database_close_for_tests();
	database_set_location(NULL, NULL);
	CHECK(remove_lmdb_files(dir) == 0, 153,
	      "[ERROR:153] reload-storm cleanup failed");
	return 0;
}

int main(void)
{
	int rc;

	rc = test_data_format_round_trip();
	if (rc)
		return rc;

	rc = test_lmdb_short_path_round_trip();
	if (rc)
		return rc;

	rc = test_lmdb_long_path_round_trip();
	if (rc)
		return rc;

	rc = test_lmdb_long_path_shared_prefix_no_collision();
	if (rc)
		return rc;

	rc = test_lmdb_long_path_negative_lookup();
	if (rc)
		return rc;

	rc = test_lmdb_readonly_probe_does_not_break_live_env();
	if (rc)
		return rc;

	rc = test_lmdb_readonly_lookup_keeps_dbi_valid();
	if (rc)
		return rc;

	rc = test_lmdb_chunked_import();
	if (rc)
		return rc;

	rc = test_lmdb_concurrent_read_handles();
	if (rc)
		return rc;

	rc = test_lmdb_nested_read_transaction();
	if (rc)
		return rc;

	rc = test_lmdb_failed_candidate_preserves_generation();
	if (rc)
		return rc;

	rc = test_lmdb_reload_failure_preserves_generation();
	if (rc)
		return rc;

	rc = test_lmdb_incremental_update_keeps_duplicate_hashes();
	if (rc)
		return rc;

	rc = test_lmdb_autosize_generation_reload_target();
	if (rc)
		return rc;

	rc = test_lmdb_autosize_retry_uses_actual_map();
	if (rc)
		return rc;

	rc = test_lmdb_manual_resize_report_is_gated();
	if (rc)
		return rc;

	rc = test_lmdb_startup_generation_resets();
	if (rc)
		return rc;

	rc = test_lmdb_offline_compaction_swaps_environment();
	if (rc)
		return rc;

	rc = test_lmdb_offline_compaction_preserves_busy_environment();
	if (rc)
		return rc;

	rc = test_lmdb_held_reader_delays_reclamation();
	if (rc)
		return rc;

	rc = test_lmdb_concurrent_publish_storm();
	if (rc)
		return rc;

	return 0;
}
