/* Verify database migration preserves data after a version-file open error. */
#include "config.h"

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "conf.h"
#include "database.h"
#include "message.h"

static char version_path[64];
static int version_fd = -1;
static int fail_version_open;
static int fail_version_write;

int __real_open(const char *path, int flags, ...);
ssize_t __real_write(int fd, const void *buf, size_t count);

/* Inject only the version-file failure; other initialization stays real. */
int __wrap_open(const char *path, int flags, ...)
{
	int fd;

	if (fail_version_open && strcmp(path, version_path) == 0 &&
	    (flags & O_ACCMODE) == O_RDONLY) {
		errno = EACCES;
		return -1;
	}
	if (flags & O_CREAT) {
		va_list ap;
		mode_t mode;

		va_start(ap, flags);
		mode = va_arg(ap, int);
		va_end(ap);
		fd = __real_open(path, flags, mode);
		if (strcmp(path, version_path) == 0)
			version_fd = fd;
		return fd;
	}
	return __real_open(path, flags);
}

ssize_t __wrap_write(int fd, const void *buf, size_t count)
{
	if (fail_version_write && fd == version_fd) {
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
	/* Stop after successful migration with an unsupported backend. LTO can
	 * bypass the linker wrapper for backend_init(), so config.trust must be
	 * non-NULL even when the real backend initialization runs. */
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

	/* EACCES must leave both old database files in place. */
	fail_version_open = 1;
	if (init_database(&config) != 1)
		goto out;
	fail_version_open = 0;
	if (access(data_path, F_OK) != 0 ||
	    access(lock_path, F_OK) != 0)
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
	version_fd = -1;
	fail_version_write = 1;
	if (init_database(&config) != 1)
		goto out;
	fail_version_write = 0;
	if (access(version_path, F_OK) == 0)
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
