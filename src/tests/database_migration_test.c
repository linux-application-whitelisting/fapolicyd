/* Verify database migration preserves data after a version-file open error. */
#include "config.h"

#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "conf.h"
#include "database.h"
#include "message.h"

static char version_path[64];
static int fail_version_write;

ssize_t __real_write(int fd, const void *buf, size_t count);

/* Identify the marker by inode regardless of the libc open entry point.
 * Record the injection so an unrelated startup error cannot pass the test. */
ssize_t __wrap_write(int fd, const void *buf, size_t count)
{
	struct stat marker, target;

	if (fail_version_write && !stat(version_path, &marker) &&
	    !fstat(fd, &target) && target.st_dev == marker.st_dev &&
	    target.st_ino == marker.st_ino) {
		fail_version_write = 0;
		errno = ENOSPC;
		return -1;
	}
	return __real_write(fd, buf, count);
}

/*
 * create_file - write a small marker representing an existing DB file.
 * @path: file to create.
 * @text: marker content.
 * Returns 0 on success, 1 on I/O failure.
 */
static int create_file(const char *path, const char *text)
{
	FILE *f = fopen(path, "w");
	int failed;

	if (f == NULL)
		return 1;
	failed = fputs(text, f) == EOF;
	if (fclose(f) == EOF)
		failed = 1;
	return failed;
}

int main(void)
{
	char directory[] = "/tmp/fapolicyd-migrate-XXXXXX";
	char data_path[64] = { 0 }, lock_path[64] = { 0 };
	conf_t config = { 0 };
	FILE *f;
	int rc = 1;

	set_message_mode(MSG_STDERR, DBG_NO);
	/* Stop after successful migration with an unsupported backend. */
	config.trust = "migration-test-no-such-backend";
	if (mkdtemp(directory) == NULL)
		return 1;
	if (snprintf(version_path, sizeof(version_path), "%s/db.ver",
		     directory) >= (int)sizeof(version_path) ||
	    snprintf(data_path, sizeof(data_path), "%s/data.mdb",
		     directory) >= (int)sizeof(data_path) ||
	    snprintf(lock_path, sizeof(lock_path), "%s/lock.mdb",
		     directory) >= (int)sizeof(lock_path))
		goto out;
	if (database_set_location(directory, NULL) ||
	    create_file(data_path, "keep") ||
	    create_file(lock_path, "keep"))
		goto out;

	/* Real open errors must preserve both files, including as root. */
	if (symlink("db.ver", version_path) ||
	    init_database(&config) != 1 || access(data_path, F_OK) ||
	    access(lock_path, F_OK) || unlink(version_path))
		goto out;
	if (geteuid() != 0) {
		if (create_file(version_path, "2") || chmod(version_path, 0) ||
		    init_database(&config) != 1 || access(data_path, F_OK) ||
		    access(lock_path, F_OK) || unlink(version_path))
			goto out;
	}

	/* A dangling marker is an existing directory entry. */
	if (symlink("missing-target", version_path) ||
	    init_database(&config) != 1 || access(data_path, F_OK) ||
	    access(lock_path, F_OK) || unlink(version_path))
		goto out;

	/* An actually missing marker still performs the normal migration. */
	if (init_database(&config) != 1 ||
	    access(data_path, F_OK) == 0 ||
	    access(lock_path, F_OK) == 0)
		goto out;
	f = fopen(version_path, "r");
	if (f == NULL)
		goto out;
	int version = fgetc(f);
	if (fclose(f) == EOF || version != '2')
		goto out;

	/* A failed version write must not leave an empty marker behind. */
	if (unlink(version_path) < 0 || create_file(data_path, "keep"))
		goto out;
	fail_version_write = 1;
	if (init_database(&config) != 1)
		goto out;
	if (fail_version_write || access(version_path, F_OK) == 0)
		goto out;
	rc = 0;

out:
	database_set_location(NULL, NULL);
	unlink(version_path);
	if (data_path[0])
		unlink(data_path);
	if (lock_path[0])
		unlink(lock_path);
	rmdir(directory);
	if (rc)
		fprintf(stderr, "database migration test failed: %s\n",
			strerror(errno));
	return rc;
}
