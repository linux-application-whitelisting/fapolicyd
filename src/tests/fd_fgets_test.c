#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <fd-fgets.h>

/*
 * Exercises the fd_fgets_r family of APIs with multiple backing buffers and
 * input patterns.  The goal is to cover the behaviours that fapolicyd relies
 * on: incremental reads from pipes, truncated lines, anonymous mmap buffers
 * and pre-populated mmap()'d files.
 */

#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS MAP_ANON
#endif

static void write_all(int fd, const char *data)
{
	size_t done = 0, len = strlen(data);

	while (done < len) {
		ssize_t rc = write(fd, data + done, len - done);
		assert(rc > 0);
		done += (size_t)rc;
	}
}

/*
 * Verify the default "self managed" buffer path.  This covers the most
 * common usage in fapolicyd where lines arrive from a pipe incrementally.
 */
static void test_pipe_self_managed(void)
{
	int fds[2];
	char buf[16];
	char custom[32];
	fd_fgets_state_t *st;

	assert(pipe(fds) == 0);

	st = fd_fgets_init();
	assert(st);
	assert(fd_setvbuf_r(st, custom, sizeof(custom), MEM_SELF_MANAGED) == 0);

	/* Nothing buffered yet. */
	assert(fd_fgets_more_r(st, sizeof(buf)) == 0);
	assert(fd_fgets_eof_r(st) == 0);

	write_all(fds[1], "hello\nworld\n");
	close(fds[1]);

	/* Read first line and ensure the buffer reports more data. */
	int len = fd_fgets_r(st, buf, sizeof(buf), fds[0]);
	assert(len == 6);
	assert(strcmp(buf, "hello\n") == 0);
	assert(fd_fgets_more_r(st, sizeof(buf)) == 1);

	len = fd_fgets_r(st, buf, sizeof(buf), fds[0]);
	assert(len == 6);
	assert(strcmp(buf, "world\n") == 0);

	/* EOF is detected on the next call. */
	len = fd_fgets_r(st, buf, sizeof(buf), fds[0]);
	assert(len == 0);
	assert(fd_fgets_eof_r(st) == 1);

	fd_fgets_clear_r(st);
	assert(fd_fgets_eof_r(st) == 0);

	close(fds[0]);
	fd_fgets_destroy(st);
}

/*
 * A long line must be returned in multiple chunks when the destination buffer
 * is too small.  The second call should resume from where the first one
 * stopped and deliver the trailing newline.
 */
static void test_truncation_resume(void)
{
	int fds[2];
	char buf[6];
	fd_fgets_state_t *st;

	assert(pipe(fds) == 0);
	st = fd_fgets_init();
	assert(st);

	write_all(fds[1], "123456789\n");
	close(fds[1]);

	int len = fd_fgets_r(st, buf, sizeof(buf), fds[0]);
	assert(len == 5);
	assert(strcmp(buf, "12345") == 0);
	assert(fd_fgets_more_r(st, sizeof(buf)) == 1);

	len = fd_fgets_r(st, buf, sizeof(buf), fds[0]);
	assert(len == 5);
	assert(strcmp(buf, "6789\n") == 0);

	len = fd_fgets_r(st, buf, sizeof(buf), fds[0]);
	assert(len == 0);
	assert(fd_fgets_eof_r(st) == 1);

	close(fds[0]);
	fd_fgets_destroy(st);
}

/*
 * Allocate the working buffer with malloc() so that the destroy path frees it
 * for us.  Exercise blank lines, the clear helper, and the ability to process
 * additional data after clearing.
 */
static void test_malloc_buffer(void)
{
	int fds[2];
	char buf[32];
	char *custom;
	fd_fgets_state_t *st;

	assert(pipe(fds) == 0);
	st = fd_fgets_init();
	assert(st);

	custom = malloc(128);
	assert(custom);
	assert(fd_setvbuf_r(st, custom, 128, MEM_MALLOC) == 0);

	write_all(fds[1], "first\n\n");

	int len = fd_fgets_r(st, buf, sizeof(buf), fds[0]);
	assert(len == 6);
	assert(strcmp(buf, "first\n") == 0);

	len = fd_fgets_r(st, buf, sizeof(buf), fds[0]);
	assert(len == 1);
	assert(strcmp(buf, "\n") == 0);

	fd_fgets_clear_r(st);
	assert(fd_fgets_eof_r(st) == 0);

	write_all(fds[1], "third\n");
	close(fds[1]);

	len = fd_fgets_r(st, buf, sizeof(buf), fds[0]);
	assert(len == 6);
	assert(strcmp(buf, "third\n") == 0);

	len = fd_fgets_r(st, buf, sizeof(buf), fds[0]);
	assert(len == 0);
	assert(fd_fgets_eof_r(st) == 1);

	close(fds[0]);
	fd_fgets_destroy(st);
}

/*
 * Use an anonymous mmap() backed buffer.  Start with a partial line so that
 * the first call returns 0 while the writer is still open, then complete the
 * line and ensure it becomes available without losing data.
 */
static void test_mmap_buffer(void)
{
	int fds[2];
	char buf[64];
	void *region;
	fd_fgets_state_t *st;

	assert(pipe(fds) == 0);
	st = fd_fgets_init();
	assert(st);

	region = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
		      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	assert(region != MAP_FAILED);
	assert(fd_setvbuf_r(st, region, 4096, MEM_MMAP) == 0);

	write_all(fds[1], "hello");

	int len = fd_fgets_r(st, buf, sizeof(buf), fds[0]);
	assert(len == 0);
	assert(fd_fgets_more_r(st, sizeof(buf)) == 0);
	assert(fd_fgets_eof_r(st) == 0);

	write_all(fds[1], " world\n");
	close(fds[1]);

	len = fd_fgets_r(st, buf, sizeof(buf), fds[0]);
	assert(len == 12);
	assert(strcmp(buf, "hello world\n") == 0);

	len = fd_fgets_r(st, buf, sizeof(buf), fds[0]);
	assert(len == 0);
	assert(fd_fgets_eof_r(st) == 1);

	close(fds[0]);
	fd_fgets_destroy(st);
}

/*
 * Keep unread data in place until the working buffer runs out of space.
 * The first read consumes the entire buffer without seeing a newline, so the
 * second read must trigger a deferred compaction before pulling in the tail of
 * the line.
 */
static void test_deferred_compaction(void)
{
	int fds[2];
	char buf[64];
	char custom[33];
	const char *line =
		"0123456789abcdef0123456789abcdefQRSTUVWX\n";
	fd_fgets_state_t *st;
	size_t line_len = strlen(line);
	size_t capacity = sizeof(custom) - 1;

	assert(pipe(fds) == 0);
	st = fd_fgets_init();
	assert(st);
	assert(fd_setvbuf_r(st, custom, capacity, MEM_SELF_MANAGED) == 0);

	write_all(fds[1], line);
	close(fds[1]);

	int len = fd_fgets_r(st, buf, sizeof(buf), fds[0]);
	assert(len == (int)capacity);
	assert(strncmp(buf, line, (size_t)len) == 0);
	assert(fd_fgets_eof_r(st) == 0);

	len = fd_fgets_r(st, buf, sizeof(buf), fds[0]);
	assert(len == (int)(line_len - capacity));
	assert(strcmp(buf, line + capacity) == 0);

	len = fd_fgets_r(st, buf, sizeof(buf), fds[0]);
	assert(len == 0);
	assert(fd_fgets_eof_r(st) == 1);

	close(fds[0]);
	fd_fgets_destroy(st);
}

/*
 * Map README.md directly and parse it without issuing read() calls.  This is
 * the MEM_MMAP_FILE path that the daemon relies on for audit log replay.
 */
static void test_mmap_file_readme(void)
{
	const char *srcdir = getenv("srcdir");
	char path[512];
	int fd;
	fd_fgets_state_t *st;
	char buf[256];
	int lines = 0;
	struct stat sb;
	void *base;

	if (!srcdir)
		srcdir = "src/tests";

	snprintf(path, sizeof(path), "%s/../../README.md", srcdir);

	fd = open(path, O_RDONLY);
	assert(fd >= 0);
	assert(fstat(fd, &sb) == 0);

	base = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	assert(base != MAP_FAILED);

	st = fd_fgets_init();
	assert(st);
	assert(fd_setvbuf_r(st, base, sb.st_size, MEM_MMAP_FILE) == 0);

	int len = fd_fgets_r(st, buf, sizeof(buf), fd);
	assert(len > 0);
	assert(strncmp(buf, "File Access Policy Daemon", 25) == 0);
	lines++;

	/* Clearing should rewind the file mapping to the start. */
	fd_fgets_clear_r(st);
	len = fd_fgets_r(st, buf, sizeof(buf), fd);
	assert(len > 0);
	assert(strncmp(buf, "File Access Policy Daemon", 25) == 0);
	lines++;

	do {
		len = fd_fgets_r(st, buf, sizeof(buf), fd);
		if (len > 0)
			lines++;
	} while (!fd_fgets_eof_r(st));

	assert(lines > 50);

	fd_fgets_destroy(st);
	close(fd);
}

int main(void)
{
	test_pipe_self_managed();
	test_truncation_resume();
	test_malloc_buffer();
	test_mmap_buffer();
	test_deferred_compaction();
	test_mmap_file_readme();
	printf("fd-fgets_r tests: all passed\n");
	return 0;
}

