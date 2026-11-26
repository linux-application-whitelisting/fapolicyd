/*
 * file_hash_test.c - verify file digests and truncation handling
 */

#include "config.h"

#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "file.h"

#define EXPECTED_SHA1 \
	"a099ca5cbe1becb78bd94430e035df4032de1a76"
#define EXPECTED_SHA256 \
	"c6cec71309bc174dd0a7c15163784983a8da282e8341f35a6ebc0c00c0969bec"
#define EXPECTED_SHA512 \
	"727b236231f615746f0d2446208e06be1f16c2dae32b4300f0134efad0" \
	"eb7056c5a45c188c2c15b175eb849b1471b501c55f09c114ef546a6d11c4c0ec8bca11"
#ifdef USE_DEB
#define EXPECTED_MD5 "2b977a988458801d013863e61625b7d0"
#endif
#define EMPTY_SHA256 \
	"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

/*
 * check_digest - compare the measured digest with a known file digest.
 * @fd: open file descriptor to hash.
 * @size: number of bytes to hash.
 * @alg: algorithm to verify.
 * @expected: expected hex digest.
 * Returns nothing; exits with an error if hashing differs or fails.
 */
static void check_digest(int fd, off_t size, file_hash_alg_t alg,
			 const char *expected)
{
	char *digest = get_hash_from_fd2(fd, size, alg);

	if (digest == NULL || strcmp(digest, expected) != 0)
		error(1, 0, "incorrect digest for algorithm %d", alg);
	free(digest);
}

/*
 * main - check hashing across chunks and a file that shrinks after stat.
 * Returns 0 on success; exits with an error if any hash result is wrong.
 */
int main(void)
{
	char path[] = "/tmp/fapolicyd-file-hash-XXXXXX";
	struct stat sb;
	char *digest;
	int fd;

	fd = mkstemp(path);
	if (fd < 0)
		error(1, errno, "mkstemp failed");
	if (unlink(path) < 0)
		error(1, errno, "unlink failed");
	if (pwrite(fd, "a", 1, 0) != 1 ||
	    pwrite(fd, "b", 1, 65536) != 1)
		error(1, errno, "pwrite failed");
	if (fstat(fd, &sb) < 0 || sb.st_size != 65537)
		error(1, errno, "unexpected file size");
	if (lseek(fd, 13, SEEK_SET) != 13)
		error(1, errno, "lseek failed");

	check_digest(fd, sb.st_size, FILE_HASH_ALG_SHA1, EXPECTED_SHA1);
	check_digest(fd, sb.st_size, FILE_HASH_ALG_SHA256, EXPECTED_SHA256);
	check_digest(fd, sb.st_size, FILE_HASH_ALG_SHA512, EXPECTED_SHA512);
#ifdef USE_DEB
	check_digest(fd, sb.st_size, FILE_HASH_ALG_MD5, EXPECTED_MD5);
#endif
	if (lseek(fd, 0, SEEK_CUR) != 13)
		error(1, 0, "hashing changed the descriptor offset");

	/* The saved size can outlive the file contents during policy evaluation. */
	if (ftruncate(fd, 1) < 0)
		error(1, errno, "ftruncate failed");
	errno = 0;
	digest = get_hash_from_fd2(fd, sb.st_size, FILE_HASH_ALG_SHA256);
	if (digest != NULL || errno != EIO)
		error(1, 0, "short read did not fail with EIO");
	if (ftruncate(fd, 0) < 0)
		error(1, errno, "ftruncate failed");
	errno = 0;
	digest = get_hash_from_fd2(fd, sb.st_size, FILE_HASH_ALG_SHA256);
	if (digest != NULL || errno != EIO)
		error(1, 0, "premature EOF did not fail with EIO");

	check_digest(fd, 0, FILE_HASH_ALG_SHA256, EMPTY_SHA256);
	if (lseek(fd, 0, SEEK_CUR) != 13)
		error(1, 0, "failed hashing changed the descriptor offset");
	if (close(fd) < 0)
		error(1, errno, "close failed");
	return 0;
}
