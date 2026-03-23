// Copyright 2026 Red Hat
// SPDX-License-Identifier: GPL-2.0-or-later

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "database.h"
#include "fapolicyd-backend.h"

#define CHECK(cond, code, msg) \
	do { \
		if (!(cond)) { \
			fprintf(stderr, "%s\n", msg); \
			return code; \
		} \
	} while (0)

static int remove_lmdb_files(const char *dir)
{
	char path[512];

	snprintf(path, sizeof(path), "%s/data.mdb", dir);
	unlink(path);
	snprintf(path, sizeof(path), "%s/lock.mdb", dir);
	unlink(path);

	return rmdir(dir);
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

static int with_temp_db(char *tmpdir, size_t tmpdir_sz, conf_t *cfg)
{
	char template[] = "/tmp/fapolicyd-lmdb-XXXXXX";
	char *dir = mkdtemp(template);

	if (dir == NULL)
		return 1;

	if (strlen(dir) + 1 > tmpdir_sz)
		return 1;

	strcpy(tmpdir, dir);
	memset(cfg, 0, sizeof(*cfg));
	cfg->db_max_size = 16;
	cfg->integrity = IN_NONE;

	if (database_set_location(tmpdir, NULL))
		return 1;

	return database_open_for_tests(cfg);
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

	return 0;
}
