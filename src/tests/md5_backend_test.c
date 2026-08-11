/*
 * md5_backend_test.c - verify Debian MD5 backend return classifications
 */

#include "config.h"

#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "fapolicyd-backend.h"
#include "file.h"
#include "md5-backend.h"

#define BAD_MD5 "00000000000000000000000000000000"
#define TEST_TEXT "dpkg-owned test file\n"

#define CHECK(expr, code, msg) \
	do { \
		if (!(expr)) \
			error(code, 0, "%s", msg); \
	} while (0)

/*
 * cleanup_hash_table - release duplicate tracking entries from the MD5 helper.
 * @table: hash table pointer updated to NULL after cleanup.
 * Returns nothing.
 */
static void cleanup_hash_table(struct _hash_record **table)
{
	struct _hash_record *item, *tmp;

	HASH_ITER(hh, *table, item, tmp) {
		HASH_DEL(*table, item);
		free((void *)item->key);
		free(item);
	}
	*table = NULL;
}

/*
 * write_all - write a complete buffer to a descriptor.
 * @fd: open descriptor to write.
 * @data: nul-terminated test payload.
 * Returns nothing. Exits on write failure.
 */
static void write_all(int fd, const char *data)
{
	size_t done = 0;
	size_t len = strlen(data);

	while (done < len) {
		ssize_t written = write(fd, data + done, len - done);

		if (written < 0) {
			if (errno == EINTR)
				continue;
			error(1, errno, "write failed");
		}
		if (written == 0)
			error(1, 0, "write made no progress");
		done += (size_t)written;
	}
}

/*
 * make_temp_file - create a regular file with the standard test payload.
 * @path: mkstemp template updated with the created path.
 * Returns nothing. Exits on setup failure.
 */
static void make_temp_file(char *path)
{
	int fd = mkstemp(path);

	if (fd < 0)
		error(1, errno, "mkstemp failed");
	write_all(fd, TEST_TEXT);
	if (close(fd) < 0)
		error(1, errno, "close failed");
}

/*
 * make_memfd - create a writable backend snapshot descriptor for tests.
 * Returns an open memfd. Exits on setup failure.
 */
static int make_memfd(void)
{
	int fd = memfd_create("md5-backend-test", MFD_CLOEXEC);

	if (fd < 0)
		error(1, errno, "memfd_create failed");
	return fd;
}

/*
 * md5_for_file - compute the MD5 digest expected by the backend helper.
 * @path: regular file to hash.
 * Returns a heap-allocated digest string. Exits on setup or hash failure.
 */
static char *md5_for_file(const char *path)
{
	struct stat sb;
	char *hash;
	int fd;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		error(1, errno, "open failed");
	if (fstat(fd, &sb) < 0)
		error(1, errno, "fstat failed");

	hash = get_hash_from_fd2(fd, sb.st_size, FILE_HASH_ALG_MD5);
	if (close(fd) < 0)
		error(1, errno, "close failed");
	if (hash == NULL)
		error(1, 0, "MD5 digest returned NULL");
	return hash;
}

/*
 * read_snapshot - read a memfd snapshot into a nul-terminated buffer.
 * @fd: memfd to rewind and read.
 * @buf: caller-provided destination buffer.
 * @size: size of @buf.
 * Returns the number of bytes read. Exits on read failure.
 */
static ssize_t read_snapshot(int fd, char *buf, size_t size)
{
	ssize_t len;

	if (lseek(fd, 0, SEEK_SET) < 0)
		error(1, errno, "lseek failed");
	len = read(fd, buf, size - 1);
	if (len < 0)
		error(1, errno, "read failed");
	buf[len] = 0;
	return len;
}

/*
 * test_hash_mismatch_skips - changed dpkg-owned files must not abort loading.
 * Returns nothing. Exits on unexpected helper behavior.
 */
static void test_hash_mismatch_skips(void)
{
	struct _hash_record *hashtable = NULL;
	char path[] = "/tmp/fapolicyd-md5-backend-XXXXXX";
	backend dst = { .name = "test", .memfd = make_memfd(), .entries = -1 };
	md5_backend_result_t rc;

	make_temp_file(path);
	rc = add_file_to_backend_by_md5(path, BAD_MD5, &hashtable, SRC_DEB,
					&dst);

	CHECK(rc == MD5_BACKEND_SKIPPED, 1,
	      "[ERROR:1] hash mismatch was not classified as skipped");
	CHECK(hashtable == NULL, 2,
	      "[ERROR:2] skipped hash mismatch added a duplicate entry");

	close(dst.memfd);
	unlink(path);
}

/*
 * test_missing_file_skips - dpkg file list races are per-file skips.
 * Returns nothing. Exits on unexpected helper behavior.
 */
static void test_missing_file_skips(void)
{
	struct _hash_record *hashtable = NULL;
	char path[128];
	backend dst = { .name = "test", .memfd = make_memfd(), .entries = -1 };
	md5_backend_result_t rc;

	snprintf(path, sizeof(path), "/tmp/fapolicyd-md5-missing-%ld",
		 (long)getpid());
	unlink(path);
	rc = add_file_to_backend_by_md5(path, BAD_MD5, &hashtable, SRC_DEB,
					&dst);

	CHECK(rc == MD5_BACKEND_SKIPPED, 3,
	      "[ERROR:3] missing file was not classified as skipped");
	CHECK(hashtable == NULL, 4,
	      "[ERROR:4] skipped missing file added a duplicate entry");

	close(dst.memfd);
}

/*
 * test_matching_file_records - matching dpkg MD5 records a trust snapshot line.
 * Returns nothing. Exits on malformed output or helper failure.
 */
static void test_matching_file_records(void)
{
	struct _hash_record *hashtable = NULL;
	char path[] = "/tmp/fapolicyd-md5-backend-XXXXXX";
	char buf[512];
	char sha[FILE_DIGEST_STRING_MAX];
	unsigned int source;
	trustdb_size_t size;
	char *data;
	char *md5;
	backend dst = { .name = "test", .memfd = make_memfd(), .entries = -1 };
	md5_backend_result_t rc;

	make_temp_file(path);
	md5 = md5_for_file(path);
	rc = add_file_to_backend_by_md5(path, md5, &hashtable, SRC_DEB, &dst);

	CHECK(rc == MD5_BACKEND_ADDED, 5,
	      "[ERROR:5] matching file was not added");
	CHECK(read_snapshot(dst.memfd, buf, sizeof(buf)) > 0, 6,
	      "[ERROR:6] matching file wrote no snapshot data");
	data = strchr(buf, ' ');
	CHECK(data != NULL, 7, "[ERROR:7] snapshot line missing data");
	data++;
	CHECK(sscanf(data, DATA_FORMAT_IN, &source, &size, sha) == 3, 8,
	      "[ERROR:8] snapshot data did not parse");
	CHECK(source == SRC_DEB, 9, "[ERROR:9] snapshot source is not SRC_DEB");
	CHECK(size == (trustdb_size_t)strlen(TEST_TEXT), 10,
	      "[ERROR:10] snapshot size does not match file");

	free(md5);
	cleanup_hash_table(&hashtable);
	close(dst.memfd);
	unlink(path);
}

/*
 * test_snapshot_write_failure_is_fatal - failed memfd writes abort snapshots.
 * Returns nothing. Exits on unexpected helper behavior.
 */
static void test_snapshot_write_failure_is_fatal(void)
{
	struct _hash_record *hashtable = NULL;
	char path[] = "/tmp/fapolicyd-md5-backend-XXXXXX";
	char *md5;
	int readonly_fd;
	backend dst = { .name = "test", .memfd = -1, .entries = -1 };
	md5_backend_result_t rc;

	make_temp_file(path);
	md5 = md5_for_file(path);
	readonly_fd = open(path, O_RDONLY);
	if (readonly_fd < 0)
		error(1, errno, "open read-only failed");
	dst.memfd = readonly_fd;

	rc = add_file_to_backend_by_md5(path, md5, &hashtable, SRC_DEB, &dst);
	CHECK(rc == MD5_BACKEND_FATAL, 11,
	      "[ERROR:11] snapshot write failure was not fatal");
	CHECK(hashtable == NULL, 12,
	      "[ERROR:12] fatal snapshot write added a duplicate entry");

	free(md5);
	close(readonly_fd);
	unlink(path);
}

/*
 * main - run MD5 backend return classification coverage.
 * Returns 0 on success. Exits with error() on test failure.
 */
int main(void)
{
	test_hash_mismatch_skips();
	test_missing_file_skips();
	test_matching_file_records();
	test_snapshot_write_failure_is_fatal();

	return 0;
}
