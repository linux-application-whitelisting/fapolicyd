/*
 * message_test.c - unit tests for synchronous and async logging in message.c
 */
#include "config.h"
#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>

#include "message.h"

#define CHECK(expr, code, msg) \
	do { \
		if (!(expr)) \
			error(1, 0, "%s", msg); \
	} while (0)

/*
 * struct capture - redirect stderr to a pipe so a test can inspect what
 * msg() actually wrote, then restore the original stderr afterward.
 */
struct capture {
	int saved_stderr;
	int read_fd;
};

/*
 * capture_start - point stderr at the write end of a fresh pipe.
 * @cap: capture state to initialize.
 * Returns nothing. Exits on any setup failure.
 */
static void capture_start(struct capture *cap)
{
	int fds[2];

	if (pipe(fds))
		error(1, errno, "pipe failed");
	cap->saved_stderr = dup(STDERR_FILENO);
	if (cap->saved_stderr < 0)
		error(1, errno, "dup failed");
	if (dup2(fds[1], STDERR_FILENO) < 0)
		error(1, errno, "dup2 failed");
	close(fds[1]);
	if (fcntl(fds[0], F_SETFL, O_NONBLOCK))
		error(1, errno, "fcntl failed");
	cap->read_fd = fds[0];
}

/*
 * capture_read - copy everything currently buffered in the pipe into @buf.
 * @cap: active capture.
 * @buf: destination buffer, always NUL terminated on return.
 * @size: size of @buf.
 * Returns nothing. Only call once the writer side is done producing, or
 * some content may still be in flight and missed.
 */
static void capture_read(struct capture *cap, char *buf, size_t size)
{
	size_t used = 0;
	ssize_t n;

	while (used + 1 < size) {
		n = read(cap->read_fd, buf + used, size - 1 - used);
		if (n > 0) {
			used += (size_t)n;
			continue;
		}
		if (n < 0 && errno == EINTR)
			continue;
		break;
	}
	buf[used] = 0;
}

/*
 * capture_end - restore the original stderr.
 * @cap: active capture.
 * Returns nothing.
 */
static void capture_end(struct capture *cap)
{
	fflush(stderr);
	if (dup2(cap->saved_stderr, STDERR_FILENO) < 0)
		error(1, errno, "dup2 restore failed");
	close(cap->saved_stderr);
}

/*
 * capture_close - release the read end of a finished capture.
 * @cap: capture to close.
 * Returns nothing.
 */
static void capture_close(struct capture *cap)
{
	close(cap->read_fd);
}

/*
 * test_basic_sync_logging - verify msg() reaches stderr synchronously.
 * Returns nothing. Exits with error() on failure.
 */
static void test_basic_sync_logging(void)
{
	struct capture cap;
	char buf[4096];

	set_message_mode(MSG_STDERR, DBG_NO);
	capture_start(&cap);

	msg(LOG_WARNING, "sync-basic-%d", 12345);

	capture_read(&cap, buf, sizeof(buf));
	capture_end(&cap);
	capture_close(&cap);

	CHECK(strstr(buf, "sync-basic-12345") != NULL, 1,
	      "[ERROR:1] synchronous message missing from stderr");
	CHECK(strstr(buf, "WARNING") != NULL, 2,
	      "[ERROR:2] synchronous message missing level name");

	set_message_mode(MSG_QUIET, DBG_NO);
}

/*
 * test_basic_async_logging - verify msg() reaches stderr once the async
 * writer thread is running, and message_async_stop() drains it.
 * Returns nothing. Exits with error() on failure.
 */
static void test_basic_async_logging(void)
{
	struct capture cap;
	char buf[4096];
	int rc;

	set_message_mode(MSG_STDERR, DBG_NO);
	rc = message_async_start();
	CHECK(rc == 0, 3, "[ERROR:3] message_async_start failed");

	capture_start(&cap);
	msg(LOG_WARNING, "async-basic-%d", 67890);
	message_async_stop();

	capture_read(&cap, buf, sizeof(buf));
	capture_end(&cap);
	capture_close(&cap);

	CHECK(strstr(buf, "async-basic-67890") != NULL, 4,
	      "[ERROR:4] async message missing from stderr after stop");

	set_message_mode(MSG_QUIET, DBG_NO);
}

/*
 * test_async_start_failure - verify message_async_start() reports failure
 * when the writer thread cannot be created, and recovers cleanly afterward.
 *
 * RLIMIT_NPROC is not enforced for privileged processes, so this test skips
 * itself (with a visible note, not a failure) when it cannot actually force
 * pthread_create() to fail - that is an environment limitation, not a bug.
 * Returns nothing. Exits with error() on failure.
 */
static void test_async_start_failure(void)
{
	struct rlimit orig, tiny;
	int rc;

	if (getrlimit(RLIMIT_NPROC, &orig))
		error(1, errno, "getrlimit failed");

	tiny.rlim_cur = 1;
	tiny.rlim_max = orig.rlim_max;
	if (setrlimit(RLIMIT_NPROC, &tiny)) {
		fprintf(stderr, "[SKIP] cannot lower RLIMIT_NPROC here, "
			"skipping message_async_start failure test\n");
		return;
	}

	rc = message_async_start();

	/* Restore before asserting anything, so a failed CHECK() below does
	 * not leave the process thread-starved on exit. */
	if (setrlimit(RLIMIT_NPROC, &orig))
		error(1, errno, "setrlimit restore failed");

	if (rc == 0) {
		fprintf(stderr, "[SKIP] RLIMIT_NPROC not enforced here "
			"(root or a sandbox); cannot force "
			"message_async_start() to fail, skipping\n");
		message_async_stop();
		return;
	}

	CHECK(rc != 0, 5, "[ERROR:5] message_async_start unexpectedly "
	      "reported success");

	/* A failed start must not corrupt state: once resources free up,
	 * a later start must still succeed. */
	rc = message_async_start();
	CHECK(rc == 0, 6, "[ERROR:6] message_async_start did not recover "
	      "after a failed attempt");
	message_async_stop();
}

/*
 * test_long_messages - verify a full-length path is logged intact, and a
 * grossly oversized message is truncated with a visible marker rather than
 * silently cut off.
 * Returns nothing. Exits with error() on failure.
 */
static void test_long_messages(void)
{
	struct capture cap;
	char buf[32768];
	char *path, *huge;
	size_t path_len = (size_t)PATH_MAX - 1;
	size_t huge_len = 3 * (size_t)PATH_MAX;
	int rc;

	path = malloc(path_len + 1);
	huge = malloc(huge_len + 1);
	if (!path || !huge)
		error(1, errno, "malloc failed");
	memset(path, 'a', path_len);
	path[path_len] = 0;
	memset(huge, 'b', huge_len);
	huge[huge_len] = 0;

	set_message_mode(MSG_STDERR, DBG_NO);
	rc = message_async_start();
	CHECK(rc == 0, 7, "[ERROR:7] message_async_start failed");

	capture_start(&cap);
	msg(LOG_NOTICE, "Cannot open %s", path);
	msg(LOG_NOTICE, "%s", huge);
	message_async_stop();

	capture_read(&cap, buf, sizeof(buf));
	capture_end(&cap);
	capture_close(&cap);

	CHECK(strstr(buf, path) != NULL, 8,
	      "[ERROR:8] a full-length path message was truncated");
	CHECK(strstr(buf, "[truncated]") != NULL, 9,
	      "[ERROR:9] a grossly oversized message was not marked "
	      "truncated");

	free(path);
	free(huge);
	set_message_mode(MSG_QUIET, DBG_NO);
}

/*
 * test_drain_on_stop - verify every message queued before
 * message_async_stop() is called is still written before it returns.
 * Returns nothing. Exits with error() on failure.
 */
static void test_drain_on_stop(void)
{
	struct capture cap;
	char buf[16384];
	char expect[32];
	int rc, i;
	const int n = 50;

	set_message_mode(MSG_STDERR, DBG_NO);
	rc = message_async_start();
	CHECK(rc == 0, 10, "[ERROR:10] message_async_start failed");

	capture_start(&cap);
	for (i = 0; i < n; i++)
		msg(LOG_NOTICE, "drain-marker-%d", i);
	message_async_stop();

	capture_read(&cap, buf, sizeof(buf));
	capture_end(&cap);
	capture_close(&cap);

	for (i = 0; i < n; i++) {
		snprintf(expect, sizeof(expect), "drain-marker-%d", i);
		CHECK(strstr(buf, expect) != NULL, 11,
		      "[ERROR:11] a message queued before stop() was never "
		      "drained");
	}

	set_message_mode(MSG_QUIET, DBG_NO);
}

#define PRODUCER_THREADS 16
#define MESSAGES_PER_THREAD 10

struct producer_arg {
	int id;
};

/*
 * producer_thread - log a fixed, identifiable burst of messages.
 * @arg: struct producer_arg pointer.
 * Returns NULL.
 */
static void *producer_thread(void *arg)
{
	struct producer_arg *pa = arg;
	int i;

	for (i = 0; i < MESSAGES_PER_THREAD; i++)
		msg(LOG_NOTICE, "producer-%d-msg-%d", pa->id, i);
	return NULL;
}

/*
 * test_concurrent_producers - verify many threads logging at once neither
 * crash nor corrupt each other's messages.
 * Returns nothing. Exits with error() on failure.
 */
static void test_concurrent_producers(void)
{
	struct capture cap;
	char buf[65536];
	pthread_t threads[PRODUCER_THREADS];
	struct producer_arg args[PRODUCER_THREADS];
	char expect[48];
	int rc, i, j;

	set_message_mode(MSG_STDERR, DBG_NO);
	rc = message_async_start();
	CHECK(rc == 0, 12, "[ERROR:12] message_async_start failed");

	capture_start(&cap);

	for (i = 0; i < PRODUCER_THREADS; i++) {
		args[i].id = i;
		rc = pthread_create(&threads[i], NULL, producer_thread,
				     &args[i]);
		CHECK(rc == 0, 13, "[ERROR:13] pthread_create failed");
	}
	for (i = 0; i < PRODUCER_THREADS; i++) {
		rc = pthread_join(threads[i], NULL);
		CHECK(rc == 0, 14, "[ERROR:14] pthread_join failed");
	}

	message_async_stop();

	capture_read(&cap, buf, sizeof(buf));
	capture_end(&cap);
	capture_close(&cap);

	for (i = 0; i < PRODUCER_THREADS; i++) {
		for (j = 0; j < MESSAGES_PER_THREAD; j++) {
			snprintf(expect, sizeof(expect),
				 "producer-%d-msg-%d", i, j);
			CHECK(strstr(buf, expect) != NULL, 15,
			      "[ERROR:15] a concurrently-produced message "
			      "was lost or corrupted");
		}
	}

	set_message_mode(MSG_QUIET, DBG_NO);
}

#define BLOCK_TEST_MESSAGES 40
#define BLOCK_TEST_PAYLOAD  2000

static atomic_bool reader_should_stop;
static volatile sig_atomic_t watchdog_fired;

/*
 * watchdog_handler - last-resort exit if the blocking test hangs.
 * @sig: unused signal number.
 * Returns nothing; terminates the process.
 */
static void watchdog_handler(int sig)
{
	(void)sig;
	watchdog_fired = 1;
	_exit(99);
}

/*
 * pipe_reader_thread - drain and discard the capture pipe in the
 * background so a stalled drain thread can make progress again.
 * @arg: struct capture pointer.
 * Returns NULL.
 */
static void *pipe_reader_thread(void *arg)
{
	struct capture *cap = arg;
	char discard[4096];

	while (!atomic_load_explicit(&reader_should_stop,
				     memory_order_relaxed)) {
		ssize_t n = read(cap->read_fd, discard, sizeof(discard));

		if (n > 0)
			continue;
		if (n == 0)
			break;
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			struct timespec ts = { 0, 1000000 };
			nanosleep(&ts, NULL);
			continue;
		}
		if (errno == EINTR)
			continue;
		break;
	}
	return NULL;
}

/*
 * test_producer_does_not_block - verify msg() returns promptly even while
 * the log destination itself is stalled (a full, unread pipe standing in
 * for a wedged journald/stderr), which is the entire reason this async
 * logger exists.
 * Returns nothing. Exits with error() on failure.
 */
static void test_producer_does_not_block(void)
{
	struct capture cap;
	pthread_t reader;
	char *payload;
	struct timespec start, end;
	double elapsed;
	int rc, i;

	payload = malloc(BLOCK_TEST_PAYLOAD + 1);
	if (!payload)
		error(1, errno, "malloc failed");
	memset(payload, 'x', BLOCK_TEST_PAYLOAD);
	payload[BLOCK_TEST_PAYLOAD] = 0;

	atomic_store_explicit(&reader_should_stop, false,
			      memory_order_relaxed);
	watchdog_fired = 0;
	signal(SIGALRM, watchdog_handler);
	alarm(10);

	set_message_mode(MSG_STDERR, DBG_NO);
	rc = message_async_start();
	CHECK(rc == 0, 16, "[ERROR:16] message_async_start failed");

	capture_start(&cap);

	/*
	 * Nothing reads the pipe yet, and BLOCK_TEST_MESSAGES *
	 * BLOCK_TEST_PAYLOAD comfortably exceeds a pipe's default 64KiB
	 * buffer, so the drain thread is expected to be stuck inside
	 * write() well before this loop finishes. If msg() blocked on the
	 * same destination, this loop would take as long as the pipe stays
	 * full; it must not.
	 */
	clock_gettime(CLOCK_MONOTONIC, &start);
	for (i = 0; i < BLOCK_TEST_MESSAGES; i++)
		msg(LOG_NOTICE, "%s", payload);
	clock_gettime(CLOCK_MONOTONIC, &end);

	elapsed = (double)(end.tv_sec - start.tv_sec) +
		  (double)(end.tv_nsec - start.tv_nsec) / 1e9;

	CHECK(elapsed < 2.0, 17, "[ERROR:17] msg() blocked the producer "
	      "while the log destination was stalled");

	/* Now unstick the drain thread so shutdown can complete. */
	rc = pthread_create(&reader, NULL, pipe_reader_thread, &cap);
	CHECK(rc == 0, 18, "[ERROR:18] pthread_create for pipe reader "
	      "failed");

	message_async_stop();
	alarm(0);

	atomic_store_explicit(&reader_should_stop, true, memory_order_relaxed);
	pthread_join(reader, NULL);

	capture_end(&cap);
	capture_close(&cap);
	free(payload);
	set_message_mode(MSG_QUIET, DBG_NO);

	CHECK(!watchdog_fired, 19, "[ERROR:19] watchdog fired during "
	      "blocking test");
}

#define STOP_RACE_ITERATIONS 300
#define STOP_RACE_PRODUCERS 4
#define STOP_RACE_MSG "stop race producer message"

struct stop_race_ctx {
	atomic_bool keep_going;
};

static atomic_ulong stop_race_sent;
static atomic_ulong stop_race_received;
static atomic_ulong stop_race_dropped;

/*
 * stop_race_producer - call msg() as fast as possible until told to stop,
 * counting every attempt.
 * @arg: struct stop_race_ctx pointer.
 * Returns NULL.
 *
 * Deliberately never paused around the caller's message_async_start()/
 * message_async_stop() calls. Some of these msg() calls will read
 * LOG_ASYNC_RUNNING and then reach log_enqueue() only after a concurrent
 * message_async_stop() has already flipped log_state to STOPPING - exactly
 * the race log_inflight (see msg() and message_async_stop() in message.c)
 * exists to make safe without dropping the message.
 */
static void *stop_race_producer(void *arg)
{
	struct stop_race_ctx *ctx = arg;

	while (atomic_load_explicit(&ctx->keep_going, memory_order_relaxed)) {
		msg(LOG_INFO, STOP_RACE_MSG);
		atomic_fetch_add_explicit(&stop_race_sent, 1,
					  memory_order_relaxed);
	}
	return NULL;
}

/*
 * stop_race_reader_thread - drain the capture pipe continuously, tallying
 * every delivered producer message and every message the drain thread
 * reports as dropped, so producer threads never block on a full pipe and
 * the flood this test generates does not need to be retained in memory to
 * prove nothing vanished silently.
 * @arg: struct capture pointer.
 * Returns NULL.
 */
static void *stop_race_reader_thread(void *arg)
{
	struct capture *cap = arg;
	char tail[64] = { 0 };
	size_t tail_len = 0;

	while (!atomic_load_explicit(&reader_should_stop,
				     memory_order_relaxed)) {
		char work[4096];
		ssize_t n;

		memcpy(work, tail, tail_len);
		/* A compile-time-constant read size, rather than
		 * sizeof(work) - tail_len - 1, lets the compiler prove
		 * work + tail_len has room for it (tail_len <= sizeof(tail)
		 * always) instead of flagging a theoretical overflow. */
		n = read(cap->read_fd, work + tail_len,
			 sizeof(work) - sizeof(tail) - 1);
		if (n > 0) {
			size_t total = tail_len + (size_t)n;
			size_t keep;
			const char *p;

			work[total] = 0;

			/*
			 * A match entirely inside the carried tail was
			 * already counted on the previous pass, which scanned
			 * that same tail as the end of its own buffer - only
			 * count a match that reaches at least one freshly
			 * read byte, so nothing is tallied twice.
			 */
			p = work;
			while ((p = strstr(p, STOP_RACE_MSG)) != NULL) {
				size_t idx = (size_t)(p - work);

				if (idx + strlen(STOP_RACE_MSG) > tail_len)
					atomic_fetch_add_explicit(
						&stop_race_received, 1,
						memory_order_relaxed);
				p += strlen(STOP_RACE_MSG);
			}

			p = work;
			while ((p = strstr(p, "Dropped ")) != NULL) {
				size_t idx = (size_t)(p - work);
				unsigned long n_dropped;

				if (idx + strlen("Dropped ") > tail_len &&
				    sscanf(p, "Dropped %lu",
					   &n_dropped) == 1)
					atomic_fetch_add_explicit(
						&stop_race_dropped, n_dropped,
						memory_order_relaxed);
				p += strlen("Dropped ");
			}

			keep = total < sizeof(tail) ? total : sizeof(tail);
			memcpy(tail, work + total - keep, keep);
			tail_len = keep;
			continue;
		}
		if (n == 0)
			break;
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			struct timespec ts = { 0, 1000000 };
			nanosleep(&ts, NULL);
			continue;
		}
		if (errno == EINTR)
			continue;
		break;
	}
	return NULL;
}

/*
 * test_stop_races_running_producers - drive msg() calls across
 * message_async_stop() while producer threads are still running, and
 * confirm every message a producer sent is accounted for - either
 * delivered or explicitly counted as dropped, never silently lost.
 *
 * This mirrors fapolicyd.c's poll()-error shutdown path, where
 * message_async_stop() runs right after nudge_queue() with worker threads
 * not yet joined - the only place in the daemon where a producer can still
 * be calling msg() as the async logger is torn down. Producer threads spin
 * on msg() continuously while the main thread cycles message_async_start()/
 * message_async_stop() hundreds of times underneath them, so the narrow
 * race window - a producer observes LOG_ASYNC_RUNNING in msg() just as a
 * concurrent message_async_stop() begins tearing the queue down - opens on
 * every single stop() call. Before log_inflight, that race meant the
 * message was dropped purely because of shutdown timing, not because the
 * queue was actually full; now message_async_stop() waits for any such
 * producer to finish enqueueing before it touches log_sem, so a stop() race
 * alone must never cause a drop - see message.c.
 * Returns nothing. Exits with error() on failure/hang/lost message.
 */
static void test_stop_races_running_producers(void)
{
	struct stop_race_ctx ctx;
	pthread_t producers[STOP_RACE_PRODUCERS];
	pthread_t reader;
	struct capture cap;
	unsigned long sent, received, dropped;
	int i, iter, rc;

	watchdog_fired = 0;
	signal(SIGALRM, watchdog_handler);
	alarm(20);

	set_message_mode(MSG_STDERR, DBG_NO);
	capture_start(&cap);

	atomic_store_explicit(&reader_should_stop, false,
			      memory_order_relaxed);
	atomic_store_explicit(&stop_race_sent, 0, memory_order_relaxed);
	atomic_store_explicit(&stop_race_received, 0, memory_order_relaxed);
	atomic_store_explicit(&stop_race_dropped, 0, memory_order_relaxed);
	rc = pthread_create(&reader, NULL, stop_race_reader_thread, &cap);
	CHECK(rc == 0, 20, "[ERROR:20] pthread_create for reader failed");

	atomic_store_explicit(&ctx.keep_going, true, memory_order_relaxed);
	for (i = 0; i < STOP_RACE_PRODUCERS; i++) {
		rc = pthread_create(&producers[i], NULL, stop_race_producer,
				     &ctx);
		CHECK(rc == 0, 21, "[ERROR:21] pthread_create failed");
	}

	for (iter = 0; iter < STOP_RACE_ITERATIONS; iter++) {
		rc = message_async_start();
		CHECK(rc == 0, 22, "[ERROR:22] message_async_start failed");
		message_async_stop();
	}

	atomic_store_explicit(&ctx.keep_going, false, memory_order_relaxed);
	for (i = 0; i < STOP_RACE_PRODUCERS; i++)
		pthread_join(producers[i], NULL);

	/*
	 * One more quiescent cycle with producers fully joined: pthread_join()
	 * above establishes happens-before visibility for every increment the
	 * race loop made, and message_async_stop() never returns until the
	 * drain thread has fully emptied the ring - so by the time this call
	 * returns, every message this test will ever send has already been
	 * written to the capture pipe or counted as dropped.
	 */
	rc = message_async_start();
	CHECK(rc == 0, 23, "[ERROR:23] message_async_start failed");
	message_async_stop();

	sent = atomic_load_explicit(&stop_race_sent, memory_order_relaxed);

	/*
	 * The reader thread just needs a little more time to catch up with
	 * data that is already sitting in the pipe. Poll for convergence
	 * instead of a fixed sleep so this returns as soon as it can, with
	 * the alarm(20) watchdog above as the backstop if it never does.
	 */
	for (;;) {
		received = atomic_load_explicit(&stop_race_received,
						memory_order_relaxed);
		dropped = atomic_load_explicit(&stop_race_dropped,
					       memory_order_relaxed);
		if (received + dropped >= sent)
			break;
		struct timespec ts = { 0, 1000000 };
		nanosleep(&ts, NULL);
	}

	atomic_store_explicit(&reader_should_stop, true, memory_order_relaxed);
	pthread_join(reader, NULL);

	capture_end(&cap);
	capture_close(&cap);

	alarm(0);
	set_message_mode(MSG_QUIET, DBG_NO);

	CHECK(!watchdog_fired, 24, "[ERROR:24] watchdog fired - "
	      "message_async_stop() likely hung racing a producer");
	CHECK(sent > 0, 25, "[ERROR:25] no producer messages were sent - "
	      "the race window was never exercised");
	CHECK(received + dropped == sent, 26, "[ERROR:26] a producer message "
	      "vanished without being delivered or counted as dropped - "
	      "message_async_stop() raced a producer and lost a message");
}

/*
 * main - run all message.c logging tests.
 * Returns 0 on success. Exits with error() on test failure.
 */
int main(void)
{
	test_basic_sync_logging();
	test_basic_async_logging();
	test_async_start_failure();
	test_long_messages();
	test_drain_on_stop();
	test_concurrent_producers();
	test_producer_does_not_block();
	test_stop_races_running_producers();

	return 0;
}
