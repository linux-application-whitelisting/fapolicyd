/*
 * message_test.c - unit tests for async logging in message.c
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

#define ACCOUNTING_STABLE_ITERATIONS 200

/*
 * wait_for_accounting - block until @a and @b (received/dropped style
 * atomic counters) sum to at least @target, or until their sum stops
 * changing for a sustained interval, meaning nothing further will ever
 * arrive. Bounding the wait this way means a genuine accounting mismatch
 * fails fast via a later CHECK() instead of hanging until an alarm()
 * watchdog kills the whole process.
 * Returns nothing.
 */
static void wait_for_accounting(atomic_ulong *a, atomic_ulong *b,
				 unsigned long target)
{
	unsigned long last = (unsigned long)-1;
	int stable = 0;

	for (;;) {
		unsigned long total = atomic_load_explicit(a,
						memory_order_relaxed) +
				       atomic_load_explicit(b,
						memory_order_relaxed);

		if (total >= target)
			return;
		if (total == last) {
			if (++stable >= ACCOUNTING_STABLE_ITERATIONS)
				return;
		} else {
			stable = 0;
			last = total;
		}
		struct timespec ts = { 0, 1000000 };
		nanosleep(&ts, NULL);
	}
}

/*
 * test_rate_limit_allow - directly exercise message_rate_limit_allow()
 * across its documented edge cases: fresh state, interval boundaries,
 * clock rollback, disabled limits, and unavailable clocks.
 * Returns nothing. Exits with error() on failure.
 */
static void test_rate_limit_allow(void)
{
	struct message_rate_limit rl = MESSAGE_RATE_LIMIT_INIT(10);
	struct message_rate_limit disabled = MESSAGE_RATE_LIMIT_INIT(0);
	struct message_rate_limit negative = MESSAGE_RATE_LIMIT_INIT(-5);
	int i;

	CHECK(message_rate_limit_allow(&rl, 1000) == 1, 27,
	      "[ERROR:27] first call on a fresh rate limit was not allowed");
	CHECK(message_rate_limit_allow(&rl, 1005) == 0, 28,
	      "[ERROR:28] a call inside the interval was incorrectly allowed");
	CHECK(message_rate_limit_allow(&rl, 1009) == 0, 29,
	      "[ERROR:29] a call one second before the interval elapsed was "
	      "incorrectly allowed");
	CHECK(message_rate_limit_allow(&rl, 1010) == 1, 30,
	      "[ERROR:30] a call exactly at the interval boundary was not "
	      "allowed");
	CHECK(message_rate_limit_allow(&rl, 1011) == 0, 31,
	      "[ERROR:31] a call immediately after a reset was incorrectly "
	      "allowed");

	/* a wall-clock rollback must emit immediately rather than wait out
	 * the interval against a now-unreachable future timestamp */
	CHECK(message_rate_limit_allow(&rl, 500) == 1, 32,
	      "[ERROR:32] a clock rollback did not immediately allow a "
	      "message");
	CHECK(message_rate_limit_allow(&rl, 501) == 0, 33,
	      "[ERROR:33] a call just after a clock-rollback reset was "
	      "incorrectly allowed");

	for (i = 0; i < 5; i++)
		CHECK(message_rate_limit_allow(&disabled, 1000 + i) == 1, 34,
		      "[ERROR:34] a zero-interval rate limit suppressed a "
		      "message");
	for (i = 0; i < 5; i++)
		CHECK(message_rate_limit_allow(&negative, 1000 + i) == 1, 35,
		      "[ERROR:35] a negative-interval rate limit suppressed a "
		      "message");

	CHECK(message_rate_limit_allow(&rl, (time_t)-1) == 1, 36,
	      "[ERROR:36] an unavailable clock reading was not always "
	      "allowed");
	CHECK(message_rate_limit_allow(NULL, 2000) == 1, 37,
	      "[ERROR:37] a NULL rate limit was not always allowed");
}

/*
 * test_message_mode_quiet - verify msg() emits nothing at all, at any
 * priority, while in MSG_QUIET mode.
 * Returns nothing. Exits with error() on failure.
 */
static void test_message_mode_quiet(void)
{
	struct capture cap;
	char buf[4096];

	set_message_mode(MSG_QUIET, DBG_NO);
	capture_start(&cap);

	msg(LOG_EMERG, "quiet-mode-should-not-appear");
	msg(LOG_DEBUG, "quiet-mode-debug-should-not-appear");

	capture_read(&cap, buf, sizeof(buf));
	capture_end(&cap);
	capture_close(&cap);

	CHECK(buf[0] == 0, 38,
	      "[ERROR:38] a message was emitted while in MSG_QUIET mode");
}

/*
 * test_debug_gating - verify LOG_DEBUG messages are suppressed unless
 * debug output was explicitly enabled via set_message_mode().
 * Returns nothing. Exits with error() on failure.
 */
static void test_debug_gating(void)
{
	struct capture cap;
	char buf[4096];
	int rc;

	set_message_mode(MSG_STDERR, DBG_NO);
	rc = message_async_start();
	CHECK(rc == 0, 59, "[ERROR:59] message_async_start failed");
	capture_start(&cap);
	msg(LOG_DEBUG, "debug-hidden-message");
	message_async_stop();
	capture_read(&cap, buf, sizeof(buf));
	capture_end(&cap);
	capture_close(&cap);
	CHECK(buf[0] == 0, 39,
	      "[ERROR:39] a LOG_DEBUG message was emitted with debug "
	      "disabled");

	set_message_mode(MSG_STDERR, DBG_YES);
	rc = message_async_start();
	CHECK(rc == 0, 59, "[ERROR:59] message_async_start failed");
	capture_start(&cap);
	msg(LOG_DEBUG, "debug-visible-message");
	message_async_stop();
	capture_read(&cap, buf, sizeof(buf));
	capture_end(&cap);
	capture_close(&cap);
	CHECK(strstr(buf, "debug-visible-message") != NULL, 40,
	      "[ERROR:40] a LOG_DEBUG message was suppressed with debug "
	      "enabled");

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
 * test_literal_percent_in_message - verify data passed as a msg() argument
 * (not as its format string) reaches stderr byte-for-byte. log_write()
 * forwards queued text via a literal "%s" (see message.c), so a
 * caller-controlled '%' must never be re-interpreted as a format specifier
 * on the way out.
 * Returns nothing. Exits with error() on failure.
 */
static void test_literal_percent_in_message(void)
{
	struct capture cap;
	char buf[4096];
	const char *payload = "50% off %n and %s and %x should stay literal";
	int rc;

	set_message_mode(MSG_STDERR, DBG_NO);
	rc = message_async_start();
	CHECK(rc == 0, 42, "[ERROR:42] message_async_start failed");
	capture_start(&cap);
	msg(LOG_WARNING, "data: %s", payload);
	message_async_stop();
	capture_read(&cap, buf, sizeof(buf));
	capture_end(&cap);
	capture_close(&cap);
	CHECK(strstr(buf, payload) != NULL, 43,
	      "[ERROR:43] format specifiers in message data were not "
	      "preserved literally");

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
 * test_truncation_boundary_exact - verify the truncation decision at the
 * exact slot-size boundary, not just deep inside/outside it: a message one
 * byte under the internal LOG_SLOT_SIZE limit must survive intact, and one
 * exactly at the limit must be marked truncated. slot_size below mirrors
 * LOG_SLOT_SIZE (PATH_MAX * 2) in message.c, which isn't exposed to tests.
 * Returns nothing. Exits with error() on failure.
 */
static void test_truncation_boundary_exact(void)
{
	struct capture cap;
	char buf[32768];
	char *exact_fit, *one_over;
	size_t slot_size = (size_t)PATH_MAX * 2;
	size_t fit_len = slot_size - 1;
	int rc;

	exact_fit = malloc(fit_len + 1);
	one_over = malloc(slot_size + 1);
	if (!exact_fit || !one_over)
		error(1, errno, "malloc failed");
	memset(exact_fit, 'c', fit_len);
	exact_fit[fit_len] = 0;
	memset(one_over, 'd', slot_size);
	one_over[slot_size] = 0;

	set_message_mode(MSG_STDERR, DBG_NO);
	rc = message_async_start();
	CHECK(rc == 0, 44, "[ERROR:44] message_async_start failed");

	capture_start(&cap);
	msg(LOG_NOTICE, "%s", exact_fit);
	msg(LOG_NOTICE, "MARK-AFTER-EXACT-FIT");
	message_async_stop();
	capture_read(&cap, buf, sizeof(buf));
	capture_end(&cap);
	capture_close(&cap);

	CHECK(strstr(buf, exact_fit) != NULL, 45,
	      "[ERROR:45] a message one byte under the slot limit was "
	      "altered");
	CHECK(strstr(buf, "[truncated]") == NULL, 46,
	      "[ERROR:46] a message that fit exactly was marked truncated");
	CHECK(strstr(buf, "MARK-AFTER-EXACT-FIT") != NULL, 47,
	      "[ERROR:47] the message following an exact-fit message was "
	      "lost");

	rc = message_async_start();
	CHECK(rc == 0, 48, "[ERROR:48] message_async_start failed");
	capture_start(&cap);
	msg(LOG_NOTICE, "%s", one_over);
	message_async_stop();
	capture_read(&cap, buf, sizeof(buf));
	capture_end(&cap);
	capture_close(&cap);

	CHECK(strstr(buf, "[truncated]") != NULL, 49,
	      "[ERROR:49] a message exactly at the slot limit was not "
	      "marked truncated");

	free(exact_fit);
	free(one_over);
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

/*
 * test_async_start_stop_idempotent - verify message_async_stop() is a safe
 * no-op when nothing is running, and a redundant message_async_start()
 * call while already running neither fails nor disturbs the running
 * writer thread.
 * Returns nothing. Exits with error() on failure.
 */
static void test_async_start_stop_idempotent(void)
{
	struct capture cap;
	char buf[4096];
	int rc;

	/* stopping when nothing is running must be a safe no-op */
	message_async_stop();
	message_async_stop();

	set_message_mode(MSG_STDERR, DBG_NO);
	rc = message_async_start();
	CHECK(rc == 0, 56, "[ERROR:56] message_async_start failed");

	rc = message_async_start();
	CHECK(rc == 0, 57, "[ERROR:57] a redundant message_async_start() "
	      "call while already running reported failure");

	capture_start(&cap);
	msg(LOG_NOTICE, "idempotent-start-check");
	message_async_stop();
	capture_read(&cap, buf, sizeof(buf));
	capture_end(&cap);
	capture_close(&cap);

	CHECK(strstr(buf, "idempotent-start-check") != NULL, 58,
	      "[ERROR:58] logging broke after a redundant "
	      "message_async_start() call");

	/* stopping twice in a row after a real stop must also be safe */
	message_async_stop();

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

#define OVERFLOW_TEST_MESSAGES 400
#define OVERFLOW_TEST_PAYLOAD  2000
#define OVERFLOW_MSG_MARK "overflow-test-marker"
#define PIPE_FILLER_CHUNK 65536

static atomic_ulong overflow_received;
static atomic_ulong overflow_dropped_reported;

/*
 * overflow_reader_thread - drain the capture pipe, tallying every
 * delivered overflow marker and every count from the drain thread's own
 * "Dropped N messages" report, so a flood that outruns the ring buffer
 * doesn't need to be retained in memory to prove nothing vanished
 * silently. Uses a tail-carry technique so a match split across two reads
 * is still counted exactly once.
 * @arg: struct capture pointer.
 * Returns NULL.
 */
static void *overflow_reader_thread(void *arg)
{
	struct capture *cap = arg;
	char tail[64] = { 0 };
	size_t tail_len = 0;

	while (!atomic_load_explicit(&reader_should_stop,
				     memory_order_relaxed)) {
		char work[8192];
		ssize_t n;

		memcpy(work, tail, tail_len);
		n = read(cap->read_fd, work + tail_len,
			 sizeof(work) - sizeof(tail) - 1);
		if (n > 0) {
			size_t total = tail_len + (size_t)n;
			size_t keep;
			const char *p;

			work[total] = 0;

			p = work;
			while ((p = strstr(p, OVERFLOW_MSG_MARK)) != NULL) {
				size_t idx = (size_t)(p - work);

				if (idx + strlen(OVERFLOW_MSG_MARK) > tail_len)
					atomic_fetch_add_explicit(
						&overflow_received, 1,
						memory_order_relaxed);
				p += strlen(OVERFLOW_MSG_MARK);
			}

			p = work;
			while ((p = strstr(p, "Dropped ")) != NULL) {
				size_t idx = (size_t)(p - work);
				unsigned long n_dropped;

				if (idx + strlen("Dropped ") > tail_len &&
				    sscanf(p, "Dropped %lu",
					   &n_dropped) == 1)
					atomic_fetch_add_explicit(
						&overflow_dropped_reported,
						n_dropped, memory_order_relaxed);
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
 * test_queue_overflow_drops_and_reports - stall the log destination so the
 * ring buffer fills past LOG_QUEUE_DEPTH, then verify excess messages are
 * dropped (never corrupted, never hung) and the drain thread's own
 * drop-count report exactly accounts for what went missing.
 *
 * The pipe is pre-filled to capacity with raw filler bytes before any
 * msg() call is made, so the drain thread's very first write() blocks
 * immediately. Without that, the drain thread can slip in a handful of
 * successful writes (whatever fits in the pipe's own buffer) interleaved
 * with the producer loop, occasionally observing and reporting a tiny
 * non-zero drop count seconds before the real overflow develops; the
 * process-global 30-second throttle on log_drop_limit (message.c) then
 * swallows the real, much larger count, and this test's accounting never
 * converges. Pre-filling collapses the whole burst into one uninterrupted
 * window with a single check-and-report at the end.
 *
 * Must also run before any other test that could trigger a drop: that same
 * throttle has no reset hook, so only the *first* drop in the whole test
 * binary is guaranteed to be reported immediately.
 * Returns nothing. Exits with error() on failure/hang/unaccounted loss.
 */
static void test_queue_overflow_drops_and_reports(void)
{
	pthread_t reader;
	struct capture cap;
	char *payload, *filler;
	unsigned long received, dropped;
	int rc, i, flags;

	payload = malloc(OVERFLOW_TEST_PAYLOAD + 1);
	filler = malloc(PIPE_FILLER_CHUNK);
	if (!payload || !filler)
		error(1, errno, "malloc failed");
	memset(payload, 'o', OVERFLOW_TEST_PAYLOAD);
	payload[OVERFLOW_TEST_PAYLOAD] = 0;
	memset(filler, 'f', PIPE_FILLER_CHUNK);

	atomic_store_explicit(&overflow_received, 0, memory_order_relaxed);
	atomic_store_explicit(&overflow_dropped_reported, 0,
			      memory_order_relaxed);
	atomic_store_explicit(&reader_should_stop, false,
			      memory_order_relaxed);

	watchdog_fired = 0;
	signal(SIGALRM, watchdog_handler);
	alarm(20);

	set_message_mode(MSG_STDERR, DBG_NO);
	capture_start(&cap);

	flags = fcntl(STDERR_FILENO, F_GETFL);
	CHECK(flags != -1, 50, "[ERROR:50] fcntl F_GETFL on stderr failed");
	rc = fcntl(STDERR_FILENO, F_SETFL, flags | O_NONBLOCK);
	CHECK(rc == 0, 50, "[ERROR:50] fcntl F_SETFL on stderr failed");
	while (write(STDERR_FILENO, filler, PIPE_FILLER_CHUNK) > 0)
		;
	rc = fcntl(STDERR_FILENO, F_SETFL, flags);
	CHECK(rc == 0, 50, "[ERROR:50] restoring stderr flags failed");

	rc = message_async_start();
	CHECK(rc == 0, 50, "[ERROR:50] message_async_start failed");

	/*
	 * The pipe is already full, so the drain thread's first write()
	 * blocks as soon as it picks up message #1. Everything from here
	 * until the reader thread starts purely enqueues into or drops from
	 * the ring, with no interleaved draining.
	 */
	for (i = 0; i < OVERFLOW_TEST_MESSAGES; i++)
		msg(LOG_NOTICE, "%s-%s", OVERFLOW_MSG_MARK, payload);

	rc = pthread_create(&reader, NULL, overflow_reader_thread, &cap);
	CHECK(rc == 0, 51, "[ERROR:51] pthread_create for reader failed");

	message_async_stop();

	/* let the reader thread catch up with data already sitting in the
	 * pipe; the alarm(20) watchdog above is the backstop if it never
	 * converges, so it must stay armed across this wait */
	wait_for_accounting(&overflow_received, &overflow_dropped_reported,
			    OVERFLOW_TEST_MESSAGES);
	received = atomic_load_explicit(&overflow_received,
					memory_order_relaxed);
	dropped = atomic_load_explicit(&overflow_dropped_reported,
				       memory_order_relaxed);

	atomic_store_explicit(&reader_should_stop, true, memory_order_relaxed);
	pthread_join(reader, NULL);

	capture_end(&cap);
	capture_close(&cap);
	alarm(0);
	free(payload);
	free(filler);
	set_message_mode(MSG_QUIET, DBG_NO);

	CHECK(!watchdog_fired, 52, "[ERROR:52] watchdog fired during the "
	      "queue overflow test");
	CHECK(received < OVERFLOW_TEST_MESSAGES, 53,
	      "[ERROR:53] no message was actually dropped - the overflow "
	      "path was never exercised");
	CHECK(dropped > 0, 54, "[ERROR:54] the drain thread never reported "
	      "the messages it dropped");
	CHECK(received + dropped == OVERFLOW_TEST_MESSAGES, 55,
	      "[ERROR:55] a message vanished without being delivered or "
	      "counted as dropped");
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

/*
 * main - run all message.c logging tests.
 * Returns 0 on success. Exits with error() on test failure.
 */
int main(void)
{
	test_rate_limit_allow();
	test_message_mode_quiet();
	test_debug_gating();
	test_basic_async_logging();
	test_literal_percent_in_message();
	test_async_start_failure();
	test_long_messages();
	test_truncation_boundary_exact();
	test_drain_on_stop();
	test_queue_overflow_drops_and_reports();
	test_async_start_stop_idempotent();
	test_concurrent_producers();
	test_producer_does_not_block();

	return 0;
}
