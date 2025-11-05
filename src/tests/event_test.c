/*
 * event_test.c - unit tests for new_event subject/object cache behavior
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
#include <sys/fanotify.h>

#include "event.h"
#include "conf.h"
#include "process.h"
#include "object.h"
#include "subject.h"

/*
 * Test doubles
 * ------------
 * The tests below replace the process and file fingerprint helpers used by
 * new_event().  Each stub returns deterministic data so we can control cache
 * reuse and eviction without touching /proc or real file descriptors.
 */

/*
 * Test strategy
 * -------------
 * The fixtures configure small, deterministic caches so that each test can
 * exercise a specific branch inside new_event().  The helpers below provide
 * stable process and file identities which lets us trigger subject cache
 * reuse, deliberate evictions, and skip-path behavior without relying on
 * kernel state.  Each scenario asserts the resulting event_t contents as well
 * as the cache side effects (state transitions and cache pointer reuse).
 *
 * Extending the suite is straightforward: add new rows to the stub tables or
 * new helper routines that model additional metadata, then write another test
 * that seeds fanotify_event_metadata with the desired pid/fd pair.  Tests can
 * reuse init_caches() to size caches appropriately and the CHECK macro to
 * report deterministic failures.  Future scenarios to consider include
 * multi-object fanotify events, additional needs_flush interactions, or
 * validating that trust-database results propagate into the event fields.
 */

extern atomic_bool needs_flush;

struct proc_info *stat_proc_entry(pid_t pid);
void clear_proc_info(struct proc_info *info);
int compare_proc_infos(const struct proc_info *p1, const struct proc_info *p2);
struct file_info *stat_file_entry(int fd);
int compare_file_infos(const struct file_info *p1, const struct file_info *p2);
char *get_file_from_fd(int fd, pid_t pid, size_t blen, char *buf);
uint32_t gather_elf(int fd, off_t size);
void msg(int priority, const char *fmt, ...);
unsigned int rules_get_proc_status_mask(void);
unsigned int policy_get_syslog_proc_status_mask(void);
int read_proc_status(pid_t pid, unsigned int fields, struct proc_status_info *info);
char *get_program_from_pid(pid_t pid, size_t blen, char *buf);
char *get_type_from_pid(pid_t pid, size_t blen, char *buf);
uid_t get_program_auid_from_pid(pid_t pid);
int get_program_sessionid_from_pid(pid_t pid);
int does_exe_exist(pid_t pid);
int check_trust_database(const char *exe, const char *digest, int mode);
char *get_device_from_stat(unsigned int device, size_t blen, char *buf);
char *get_file_type_from_fd(int fd, const struct file_info *i, const char *path,
			    size_t blen, char *buf);
char *get_hash_from_fd2(int fd, size_t size, int is_sha);

struct stub_proc_record {
	pid_t pid;
	dev_t device;
	ino_t inode;
	long nsec;
};

static const struct stub_proc_record proc_table[] = {
	{ 100, 1,  111, 100 },
	{ 200, 2,  222, 200 },
	{ 201, 3,  333, 300 },
	{ 202, 4,  444, 400 },
	{ 300, 5,  555, 500 },
	{ 301, 6,  666, 600 },
	{ 400, 7,  777, 700 },
};

struct stub_file_record {
	int fd;
	dev_t device;
	ino_t inode;
	off_t size;
	long nsec;
	const char *path;
};

static const struct stub_file_record file_table[] = {
	{ 10, 11, 1010, 4096, 101, "/stub/bin/first" },
	{ 11, 12, 1111, 4096, 111, "/stub/bin/first-open" },
	{ 20, 21, 2020, 2048, 202, "/stub/bin/second" },
	{ 21, 22, 2121, 1024, 212, "/stub/bin/third" },
	{ 30, 31, 3030, 512,  303, "/stub/bin/fourth" },
	{ 31, 32, 3131, 512,  313, "/stub/bin/fifth" },
	{ 40, 41, 4040, 256,  404, "/stub/bin/sixth" },
};

/* --- Stub implementations ------------------------------------------------ */

/*
 * Locate the stubbed proc entry for the given pid or NULL when missing.
 */
static const struct stub_proc_record *find_proc(pid_t pid)
{
	size_t i;

	for (i = 0; i < sizeof(proc_table)/sizeof(proc_table[0]); i++)
		if (proc_table[i].pid == pid)
			return &proc_table[i];
	return NULL;
}

/*
 * Locate the stubbed file entry for the given descriptor or NULL when absent.
 */
static const struct stub_file_record *find_file(int fd)
{
	size_t i;

	for (i = 0; i < sizeof(file_table)/sizeof(file_table[0]); i++)
		if (file_table[i].fd == fd)
			return &file_table[i];
	return NULL;
}

/*
 * Allocate a proc_info populated from the stub table, emulating /proc stats.
 */
struct proc_info *stat_proc_entry(pid_t pid)
{
	const struct stub_proc_record *rec = find_proc(pid);
	struct proc_info *info;

	if (rec == NULL)
		return NULL;

	info = malloc(sizeof(*info));
	if (info == NULL)
		return NULL;

	info->pid = rec->pid;
	info->device = rec->device;
	info->inode = rec->inode;
	info->time.tv_sec = 0;
	info->time.tv_nsec = rec->nsec;
	info->state = STATE_COLLECTING;
	info->path1 = NULL;
	info->path2 = NULL;
	info->elf_info = 0;
	return info;
}

/*
 * Release any heap-allocated strings contained inside the stub proc_info.
 */
void clear_proc_info(struct proc_info *info)
{
	if (info == NULL)
		return;
	free(info->path1);
	free(info->path2);
	info->path1 = NULL;
	info->path2 = NULL;
}

/*
 * Provide the equality predicate required by the subject cache machinery.
 */
int compare_proc_infos(const struct proc_info *p1, const struct proc_info *p2)
{
	if (p1 == NULL || p2 == NULL)
		return 1;
	if (p1->pid != p2->pid)
		return 1;
	if (p1->device != p2->device)
		return 1;
	if (p1->inode != p2->inode)
		return 1;
	if (p1->time.tv_sec != p2->time.tv_sec)
		return 1;
	if (p1->time.tv_nsec != p2->time.tv_nsec)
		return 1;
	return 0;
}

/*
 * Pretend every stubbed process has an executable symlink available.
 */
int does_exe_exist(pid_t pid)
{
	(void)pid;
	return 1;
}

/*
 * Allocate a file_info populated from the stub table for the supplied fd.
 */
struct file_info *stat_file_entry(int fd)
{
	const struct stub_file_record *rec = find_file(fd);
	struct file_info *info;

	if (rec == NULL)
		return NULL;

	info = malloc(sizeof(*info));
	if (info == NULL)
		return NULL;

	info->device = rec->device;
	info->inode = rec->inode;
	info->mode = 0;
	info->size = rec->size;
	info->time.tv_sec = 0;
	info->time.tv_nsec = rec->nsec;
	return info;
}

/*
 * Implement the object cache equality predicate using stub file metadata.
 */
int compare_file_infos(const struct file_info *p1, const struct file_info *p2)
{
	if (p1 == NULL || p2 == NULL)
		return 1;
	if (p1->device != p2->device)
		return 1;
	if (p1->inode != p2->inode)
		return 1;
	if (p1->size != p2->size)
		return 1;
	if (p1->time.tv_sec != p2->time.tv_sec)
		return 1;
	if (p1->time.tv_nsec != p2->time.tv_nsec)
		return 1;
	return 0;
}

/*
 * Return a synthetic path for the provided fd so path collection can succeed.
 */
char *get_file_from_fd(int fd, pid_t pid, size_t blen, char *buf)
{
	const struct stub_file_record *rec = find_file(fd);

	(void)pid;
	if (rec == NULL)
		return NULL;

	if (strlen(rec->path) + 1 > blen)
		return NULL;

	strcpy(buf, rec->path);
	return buf;
}

/*
 * Produce a deterministic ELF signature based on the stubbed fd and size.
 */
uint32_t gather_elf(int fd, off_t size)
{
	return ((uint32_t)fd << 8) ^ (uint32_t)size;
}

/*
 * Stub out the logging hook invoked by new_event(); nothing to record here.
 */
void msg(int priority, const char *fmt, ...)
{
	(void)priority;
	(void)fmt;
}

/* Return zero to disable reading of /proc status fields during tests. */
unsigned int rules_get_proc_status_mask(void)
{
	return 0;
}

/* Avoid requesting additional /proc status fields in this isolated harness. */
unsigned int policy_get_syslog_proc_status_mask(void)
{
	return 0;
}

/*
 * Provide an inert implementation for read_proc_status() that always succeeds.
 */
int read_proc_status(pid_t pid, unsigned int fields, struct proc_status_info *info)
{
	(void)pid;
	(void)fields;
	if (info == NULL)
		return -1;
	info->ppid = -1;
	info->uid = NULL;
	info->groups = NULL;
	info->comm = NULL;
	return 0;
}

/*
 * Fabricate a program path based on pid so subject attributes remain stable.
 */
char *get_program_from_pid(pid_t pid, size_t blen, char *buf)
{
	if (snprintf(buf, blen, "/proc/%d/exe", pid) < 0)
		return NULL;
	return buf;
}

/* Fabricate a subject type string that is unique per pid. */
char *get_type_from_pid(pid_t pid, size_t blen, char *buf)
{
	if (snprintf(buf, blen, "type-%d", pid) < 0)
		return NULL;
	return buf;
}

/* Return a deterministic audit uid derived from the pid. */
uid_t get_program_auid_from_pid(pid_t pid)
{
	return (uid_t)pid;
}

/* Return a deterministic session id derived from the pid. */
int get_program_sessionid_from_pid(pid_t pid)
{
	return (int)pid;
}

/* Bypass trust database lookups while keeping the signature intact. */
int check_trust_database(const char *exe, const char *digest, int mode)
{
	(void)exe;
	(void)digest;
	(void)mode;
	return 0;
}

/*
 * Report a stringified device identifier to satisfy object attribute updates.
 */
char *get_device_from_stat(unsigned int device, size_t blen, char *buf)
{
	if (snprintf(buf, blen, "dev-%u", device) < 0)
		return NULL;
	return buf;
}

/*
 * Provide a deterministic object type string incorporating the fd and path.
 */
char *get_file_type_from_fd(int fd, const struct file_info *i, const char *path,
			    size_t blen, char *buf)
{
	(void)i;
	if (snprintf(buf, blen, "ftype-%d-%s", fd, path ? path : "?") < 0)
		return NULL;
	return buf;
}

/*
 * Produce a fake digest string so new_event() can populate hash attributes.
 */
char *get_hash_from_fd2(int fd, size_t size, int is_sha)
{
	(void)is_sha;
	char *out = malloc(32);
	if (out == NULL)
		return NULL;
	snprintf(out, 32, "hash-%d-%zu", fd, (size_t)size);
	return out;
}

/* --- Test helpers -------------------------------------------------------- */

#define CHECK(cond, code, msg) \
	do { \
		if (!(cond)) { \
			fprintf(stderr, "%s\n", msg); \
			return code; \
		} \
	} while (0)

/*
 * Configure the event system with predictable cache sizes for each scenario.
 */
static int init_caches(unsigned int subj_size, unsigned int obj_size)
{
	conf_t cfg = { 0 };

	cfg.subj_cache_size = subj_size;
	cfg.obj_cache_size = obj_size;
	needs_flush = false;
	return init_event_system(&cfg);
}

/*
 * Verify that a second FAN_OPEN_PERM event for the same pid reuses the cached
 * subject, transitions STATE_COLLECTING -> STATE_REOPEN, and skips path
 * collection.
 */
static int test_reopen_skip_path(void)
{
	struct fanotify_event_metadata meta = { 0 };
	event_t first = { 0 };
	event_t reopen = { 0 };
	object_attr_t *path;

	CHECK(init_caches(4, 4) == 0, 1, "[ERROR:1] init_event_system failed");

	meta.mask = FAN_OPEN_EXEC_PERM;
	meta.fd = 10;
	meta.pid = 100;
	CHECK(new_event(&meta, &first) == 0, 2, "[ERROR:2] first new_event failed");

	CHECK(first.pid == 100, 3, "[ERROR:3] pid not copied");
	CHECK(first.fd == 10, 4, "[ERROR:4] fd not copied");
	CHECK((first.type & FAN_OPEN_EXEC_PERM) != 0, 5,
	      "[ERROR:5] mask missing FAN_OPEN_EXEC_PERM");
	CHECK(first.s && first.s->info, 6, "[ERROR:6] missing subject info");
	CHECK(first.o && first.o->info, 7, "[ERROR:7] missing object info");

	path = object_access(first.o, PATH);
	CHECK(path != NULL, 8, "[ERROR:8] path attribute missing");
	CHECK(strcmp(path->o, "/stub/bin/first") == 0, 9,
	      "[ERROR:9] unexpected path1");
	CHECK(first.s->info->path1 &&
	      strcmp(first.s->info->path1, "/stub/bin/first") == 0, 10,
	      "[ERROR:10] subject path1 not captured");
	CHECK(first.s->info->state == STATE_COLLECTING, 11,
	      "[ERROR:11] initial state mutated");

	meta.mask = FAN_OPEN_PERM;
	CHECK(new_event(&meta, &reopen) == 0, 12,
	      "[ERROR:12] reopen new_event failed");
	CHECK(reopen.s == first.s, 13, "[ERROR:13] subject cache miss");
	CHECK(reopen.o == first.o, 14, "[ERROR:14] object cache miss");
	CHECK(reopen.s->info->state == STATE_REOPEN, 15,
	      "[ERROR:15] state did not transition to STATE_REOPEN");
	CHECK(reopen.s->info->path2 == NULL, 16,
	      "[ERROR:16] path2 collected despite skip_path");

	destroy_event_system();
	return 0;
}

/*
 * Ensure that a tiny subject cache evicts the previous entry when a different
 * pid hashes to the same slot.
 */
static int test_subject_eviction(void)
{
	struct fanotify_event_metadata meta = { 0 };
	event_t first = { 0 };
	event_t second = { 0 };
	int first_pid;

	CHECK(init_caches(1, 2) == 0, 20,
	      "[ERROR:20] init_event_system failed");

	meta.mask = FAN_OPEN_EXEC_PERM;
	meta.fd = 30;
	meta.pid = 300;
	CHECK(new_event(&meta, &first) == 0, 21,
	      "[ERROR:21] first new_event failed");
	CHECK(first.s && first.s->info, 22, "[ERROR:22] subject missing");
	first_pid = first.s->info->pid;

	meta.fd = 31;
	meta.pid = 301;
	CHECK(new_event(&meta, &second) == 0, 23,
	      "[ERROR:23] second new_event failed");
	CHECK(second.s && second.s->info, 24,
	      "[ERROR:24] subject info missing after eviction");
	CHECK(second.s->info->pid != first_pid, 25,
	      "[ERROR:25] subject cache did not evict prior entry");

	destroy_event_system();
	return 0;
}

/*
 * Verify that needs_flush triggers an object cache flush so the next lookup
 * allocates a fresh entry.
 */
static int test_needs_flush_resets_object_cache(void)
{
	struct fanotify_event_metadata meta = { 0 };
	event_t first = { 0 };
	event_t second = { 0 };
	o_array *cached_object;

	CHECK(init_caches(4, 1) == 0, 30,
	      "[ERROR:30] init_event_system failed");

	meta.mask = FAN_OPEN_EXEC_PERM;
	meta.fd = 40;
	meta.pid = 400;
	CHECK(new_event(&meta, &first) == 0, 31,
	      "[ERROR:31] first new_event failed");
	cached_object = first.o;
	CHECK(cached_object != NULL, 32, "[ERROR:32] object missing");

	needs_flush = true;
	meta.mask = FAN_OPEN_PERM;
	CHECK(new_event(&meta, &second) == 0, 33,
	      "[ERROR:33] second new_event failed");
	CHECK(!needs_flush, 34, "[ERROR:34] needs_flush not cleared");
	CHECK(second.s == first.s, 35,
	      "[ERROR:35] subject cache should reuse same entry");
	CHECK(second.o != cached_object, 36,
	      "[ERROR:36] object cache not flushed");

	destroy_event_system();
	return 0;
}

/* Run each scenario in sequence, propagating the first non-zero error code. */
int main(void)
{
	int rc;

	rc = test_reopen_skip_path();
	if (rc)
		return rc;

	rc = test_subject_eviction();
	if (rc)
		return rc;

	rc = test_needs_flush_resets_object_cache();
	if (rc)
		return rc;

	return 0;
}
