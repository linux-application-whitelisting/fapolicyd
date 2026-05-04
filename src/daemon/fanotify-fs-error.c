/*
 * fanotify-fs-error.c - FAN_FS_ERROR health monitoring
 * Copyright (c) 2026 Red Hat Inc.
 * All Rights Reserved.
 *
 * This software may be freely redistributed and/or modified under the
 * terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2, or (at your option) any
 * later version.
 */

/*
 * Overview
 * --------
 *
 * FAN_FS_ERROR events are filesystem health notifications delivered through a
 * fanotify notification group. They are not permission events: there is no file
 * descriptor to answer and no policy decision to make. The daemon opens a
 * second, notification-only fanotify group with FAN_REPORT_FID, marks each
 * watched filesystem for FAN_FS_ERROR, and polls that fd beside the normal
 * permission-event fd.
 *
 * When the health fd becomes readable, this module drains the fanotify records
 * and parses the variable-length info records attached to each metadata block.
 * The ERROR info record carries the errno-style failure and the kernel's
 * suppression count. FID records identify the affected object, but the daemon
 * currently counts them only so status output can show what kind of payload was
 * received. Malformed records are still counted as health events because the
 * kernel reported trouble even if user space could not parse every detail.
 *
 * Runtime handling is intentionally observe-only. Each event is recorded in the
 * shared failure-action counters, the most recent details are published for
 * state reports, and rate-limited log messages describe the failure. Recording
 * the failure wakes the report path so operators see the new health signal
 * promptly without mixing this notification-only path into the permission
 * queue handled by notify.c.
 *
 * Header and kernel support vary across supported build targets. Public entry
 * points stay available even when FAN_FS_ERROR symbols are absent; in that case
 * initialization reports that monitoring is unavailable and all other helpers
 * become harmless no-ops.
 */

#include "config.h" /* Needed to get O_LARGEFILE definition */
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "escape.h"
#include "failure-action.h"
#include "fanotify-fs-error.h"
#include "message.h"
#include "notify.h"

#define FANOTIFY_FS_ERROR_BUFFER_SIZE 8192
#define FS_ERROR_LOG_INTERVAL 60

#if defined(FAN_FS_ERROR) && defined(FAN_REPORT_FID) && \
	defined(FAN_MARK_FILESYSTEM) && \
	defined(FAN_EVENT_INFO_TYPE_ERROR) && \
	defined(FAN_EVENT_INFO_TYPE_FID)
#define FAPOLICYD_HAVE_FANOTIFY_FS_ERROR 1

struct fanotify_fs_error_info_record {
	struct fanotify_event_info_header hdr;
	int32_t error;
	uint32_t error_count;
};
#else
#define FAPOLICYD_HAVE_FANOTIFY_FS_ERROR 0
#endif

struct fanotify_fs_error_details {
	int valid;
	int has_error;
	int malformed;
	int error;
	unsigned int error_count;
	unsigned int info_records;
	unsigned int fid_records;
	uint32_t event_len;
	uint16_t metadata_len;
	pid_t pid;
	time_t when;
};

extern atomic_bool stop, run_stats;

static int fs_error_fd = -1;
static struct message_rate_limit fanotify_fs_error_log =
	MESSAGE_RATE_LIMIT_INIT(FS_ERROR_LOG_INTERVAL);
static pthread_mutex_t fs_error_lock = PTHREAD_MUTEX_INITIALIZER;
static struct fanotify_fs_error_details last_fs_error;

static const char *fs_error_status(
		const struct fanotify_fs_error_details *details);
static const char *fs_error_code_text(int error);
static const char *format_fs_error_time(time_t when, char *buf,
					size_t buf_size);
static int parse_fs_error_record(
		const struct fanotify_event_metadata *metadata,
		struct fanotify_fs_error_details *details);
static void save_fs_error_details(
		const struct fanotify_fs_error_details *details);
static void log_fs_error_event(
		const struct fanotify_fs_error_details *details,
		unsigned long total);
static void record_fs_error_event(
		const struct fanotify_event_metadata *metadata);
static void fanotify_fs_error_failure_action(void);
static const char *escape_path_for_log(const char *path, char **escaped);

/*
 * getFanotifyFilesystemErrors - return FAN_FS_ERROR health event count.
 * Returns the number of FAN_FS_ERROR events reported by the kernel.
 */
unsigned long getFanotifyFilesystemErrors(void)
{
	return failure_action_count(FAILURE_REASON_FANOTIFY_FS_ERROR);
}

/*
 * fs_error_status - return a parse status name for status output.
 * @details: most recent FAN_FS_ERROR details.
 * Returns a stable status string.
 */
static const char *fs_error_status(
		const struct fanotify_fs_error_details *details)
{
	if (!details->valid)
		return "none";
	if (details->malformed)
		return "malformed";
	if (!details->has_error)
		return "missing_error_record";
	return "ok";
}

/*
 * fs_error_code_text - return printable text for a FAN_FS_ERROR errno.
 * @error: errno-style value reported by the kernel.
 * Returns strerror text for @error.
 */
static const char *fs_error_code_text(int error)
{
	if (error < 0)
		error = -error;
	return strerror(error);
}

/*
 * format_fs_error_time - format a filesystem error timestamp.
 * @when: timestamp saved with the error details.
 * @buf: destination buffer.
 * @buf_size: destination size.
 * Returns @buf.
 */
static const char *format_fs_error_time(time_t when, char *buf,
					size_t buf_size)
{
	struct tm tm;

	if (buf_size == 0)
		return buf;

	if (when == 0) {
		strncpy(buf, "never", buf_size - 1);
		buf[buf_size - 1] = 0;
		return buf;
	}

	if (localtime_r(&when, &tm) == NULL ||
	    strftime(buf, buf_size, "%Y-%m-%d %H:%M:%S %z", &tm) == 0) {
		strncpy(buf, "unavailable", buf_size - 1);
		buf[buf_size - 1] = 0;
	}

	return buf;
}

#if FAPOLICYD_HAVE_FANOTIFY_FS_ERROR
/*
 * parse_fs_error_record - parse FAN_FS_ERROR info records.
 * @metadata: fanotify event metadata from the kernel.
 * @details: destination for recent error details.
 * Returns 0 when the event was well-formed and -1 when it was malformed.
 */
static int parse_fs_error_record(
		const struct fanotify_event_metadata *metadata,
		struct fanotify_fs_error_details *details)
{
	const char *event = (const char *)metadata;
	size_t offset, end;

	details->event_len = metadata->event_len;
	details->metadata_len = metadata->metadata_len;
	details->pid = metadata->pid;
	details->when = time(NULL);
	if (details->when == (time_t)-1)
		details->when = 0;

	if (metadata->metadata_len < sizeof(*metadata) ||
	    metadata->metadata_len > metadata->event_len) {
		details->malformed = 1;
		return -1;
	}

	end = metadata->event_len;
	offset = metadata->metadata_len;
	while (offset + sizeof(struct fanotify_event_info_header) <= end) {
		const struct fanotify_event_info_header *info;

		info = (const struct fanotify_event_info_header *)
			(event + offset);
		if (info->len < sizeof(*info) || offset + info->len > end) {
			details->malformed = 1;
			return -1;
		}

		details->info_records++;
		switch (info->info_type) {
		case FAN_EVENT_INFO_TYPE_ERROR:
			if (info->len <
			    sizeof(struct fanotify_fs_error_info_record)) {
				details->malformed = 1;
				return -1;
			} else {
				const struct fanotify_fs_error_info_record *err;

				err = (const struct fanotify_fs_error_info_record *)
					info;
				details->has_error = 1;
				details->error = err->error;
				details->error_count = err->error_count;
			}
			break;
		case FAN_EVENT_INFO_TYPE_FID:
			details->fid_records++;
			break;
		default:
			break;
		}

		offset += info->len;
	}

	if (offset != end) {
		details->malformed = 1;
		return -1;
	}

	if (!details->has_error)
		return -1;

	return 0;
}
#else
/*
 * parse_fs_error_record - older headers cannot expose FAN_FS_ERROR details.
 * @metadata: unused fanotify event metadata.
 * @details: unused details destination.
 * Returns -1 because this build cannot parse FAN_FS_ERROR records.
 */
static int parse_fs_error_record(
		const struct fanotify_event_metadata *metadata,
		struct fanotify_fs_error_details *details)
{
	(void)metadata;
	(void)details;
	return -1;
}
#endif

/*
 * save_fs_error_details - publish recent filesystem error details.
 * @details: details parsed from the current kernel event.
 * Returns nothing.
 */
static void save_fs_error_details(
		const struct fanotify_fs_error_details *details)
{
	pthread_mutex_lock(&fs_error_lock);
	last_fs_error = *details;
	pthread_mutex_unlock(&fs_error_lock);
}

/*
 * log_fs_error_event - log one rate-limited filesystem health event.
 * @details: parsed details from the kernel event.
 * @total: total FAN_FS_ERROR events observed.
 * Returns nothing.
 */
static void log_fs_error_event(
		const struct fanotify_fs_error_details *details,
		unsigned long total)
{
	time_t now = details->when;

	if (now == 0)
		now = time(NULL);
	if (!message_rate_limit_allow(&fanotify_fs_error_log, now))
		return;

	if (details->has_error) {
		msg(LOG_ERR,
		    "Filesystem error reported by fanotify: error=%d (%s) "
		    "suppressed=%u pid=%d status=%s "
		    "(fanotify_filesystem_errors=%lu)",
		    details->error, fs_error_code_text(details->error),
		    details->error_count, details->pid,
		    fs_error_status(details), total);
	} else {
		msg(LOG_ERR,
		    "Filesystem error reported by fanotify without a "
		    "parseable error record: status=%s event_len=%u "
		    "metadata_len=%u (fanotify_filesystem_errors=%lu)",
		    fs_error_status(details), details->event_len,
		    details->metadata_len, total);
	}
}

/*
 * record_fs_error_event - count and publish a FAN_FS_ERROR health event.
 * @metadata: fanotify event metadata from the kernel.
 * Returns nothing.
 */
static void record_fs_error_event(
		const struct fanotify_event_metadata *metadata)
{
	struct fanotify_fs_error_details details = { 0 };
	unsigned long total;

	details.valid = 1;
	parse_fs_error_record(metadata, &details);

	total = failure_action_record(FAILURE_REASON_FANOTIFY_FS_ERROR);
	save_fs_error_details(&details);
	log_fs_error_event(&details, total);
	fanotify_fs_error_failure_action();
}

/*
 * fanotify_fs_error_report - write recent FAN_FS_ERROR details.
 * @f: report stream.
 * Returns nothing.
 */
void fanotify_fs_error_report(FILE *f)
{
	struct fanotify_fs_error_details details;
	char when[64];

	if (f == NULL)
		return;

	pthread_mutex_lock(&fs_error_lock);
	details = last_fs_error;
	pthread_mutex_unlock(&fs_error_lock);

	fprintf(f, "Filesystem error last status: %s\n",
		fs_error_status(&details));
	fprintf(f, "Filesystem error last seen: %s\n",
		format_fs_error_time(details.when, when, sizeof(when)));
	if (!details.valid)
		return;

	if (details.has_error) {
		fprintf(f, "Filesystem error last errno: %d\n", details.error);
		fprintf(f, "Filesystem error last errno text: %s\n",
			fs_error_code_text(details.error));
		fprintf(f, "Filesystem error last suppressed count: %u\n",
			details.error_count);
	}
	fprintf(f, "Filesystem error last pid: %d\n", details.pid);
	fprintf(f, "Filesystem error last info records: %u\n",
		details.info_records);
	fprintf(f, "Filesystem error last fid records: %u\n",
		details.fid_records);
	fprintf(f, "Filesystem error last event length: %u\n",
		details.event_len);
	fprintf(f, "Filesystem error last metadata length: %u\n",
		details.metadata_len);
}

/*
 * fanotify_fs_error_failure_action - run the observe-only failure response.
 * Returns nothing.
 */
static void fanotify_fs_error_failure_action(void)
{
	/*
	 * FAN_FS_ERROR is a daemon health signal, not a policy decision. Wake
	 * the report path so the signal becomes visible promptly.
	 */
	run_stats = true;
	nudge_queue();
}

/*
 * escape_path_for_log - return a shell-escaped path for logging.
 * @path: path that may include control characters.
 * @escaped: optional output pointer to an allocated escaped buffer.
 * Returns escaped @path when needed, original @path when not needed,
 * or "<unavailable>" if escaping is needed but allocation fails.
 */
static const char *escape_path_for_log(const char *path, char **escaped)
{
	size_t escaped_size;

	if (escaped)
		*escaped = NULL;

	escaped_size = check_escape_shell(path);
	if (escaped_size == 0)
		return path;

	if (escaped)
		*escaped = escape_shell(path, escaped_size);
	if (escaped && *escaped)
		return *escaped;

	return "<unavailable>";
}

#if FAPOLICYD_HAVE_FANOTIFY_FS_ERROR
/*
 * fanotify_fs_error_close - close the filesystem error fanotify group.
 * Returns nothing.
 */
void fanotify_fs_error_close(void)
{
	if (fs_error_fd >= 0) {
		close(fs_error_fd);
		fs_error_fd = -1;
	}
}

/*
 * fanotify_fs_error_mark - add one FAN_FS_ERROR filesystem mark.
 * @path: mount path whose filesystem should be monitored.
 * Returns 0 on success, -2 when FAN_FS_ERROR is unsupported, and -1 for
 * per-filesystem failures or disabled monitoring.
 */
int fanotify_fs_error_mark(const char *path)
{
	char *escaped_path = NULL;
	const char *safe_path;
	int saved_errno;

	if (fs_error_fd < 0 || path == NULL)
		return -1;

	safe_path = escape_path_for_log(path, &escaped_path);
	if (fanotify_mark(fs_error_fd, FAN_MARK_ADD | FAN_MARK_FILESYSTEM,
			  FAN_FS_ERROR, AT_FDCWD, path) == -1) {
		saved_errno = errno;
		switch (saved_errno) {
		case EINVAL:
		case ENOSYS:
			msg(LOG_INFO,
			    "FAN_FS_ERROR marks unsupported by running kernel");
			free(escaped_path);
			return -2;
		case ENODEV:
#ifdef EOPNOTSUPP
		case EOPNOTSUPP:
#endif
		case EXDEV:
			msg(LOG_DEBUG,
			    "FAN_FS_ERROR monitoring unavailable for %s (%s)",
			    safe_path, strerror(saved_errno));
			break;
		default:
			msg(LOG_WARNING,
			    "Error (%s) adding FAN_FS_ERROR mark for %s",
			    strerror(saved_errno), safe_path);
			break;
		}
		free(escaped_path);
		return -1;
	}

	msg(LOG_DEBUG, "added %s filesystem error monitor", safe_path);
	free(escaped_path);
	return 0;
}

/*
 * fanotify_fs_error_unmark - flush the FAN_FS_ERROR mark for one path.
 * @path: mount path whose filesystem mark should be flushed.
 * Returns nothing.
 */
void fanotify_fs_error_unmark(const char *path)
{
	char *escaped_path = NULL;
	const char *safe_path;

	if (fs_error_fd < 0 || path == NULL)
		return;

	safe_path = escape_path_for_log(path, &escaped_path);
	if (fanotify_mark(fs_error_fd, FAN_MARK_FLUSH | FAN_MARK_FILESYSTEM,
			  0, -1, path) == -1)
		msg(LOG_ERR, "Failed flushing FAN_FS_ERROR path %s  (%s)",
		    safe_path, strerror(errno));
	free(escaped_path);
}

/*
 * fanotify_fs_error_init - initialize notification-only FS error monitoring.
 * @m: watched mount list.
 * Returns the fanotify fd when monitoring is active, or -1 when disabled.
 */
int fanotify_fs_error_init(mlist *m)
{
	const char *path;
	unsigned int marked = 0;

	if (m == NULL)
		return -1;

	fs_error_fd = fanotify_init(FAN_CLOEXEC | FAN_CLASS_NOTIF |
				    FAN_NONBLOCK | FAN_REPORT_FID,
				    O_RDONLY | O_LARGEFILE | O_CLOEXEC |
				    O_NOATIME);
	if (fs_error_fd < 0) {
		if (errno == EINVAL || errno == ENOSYS)
			msg(LOG_INFO,
			    "FAN_FS_ERROR monitoring unsupported by running "
			    "kernel; disabled");
		else
			msg(LOG_WARNING,
			    "Failed opening FAN_FS_ERROR fanotify fd (%s)",
			    strerror(errno));
		return -1;
	}

	path = mlist_first(m);
	while (path && fs_error_fd >= 0) {
		int rc = fanotify_fs_error_mark(path);

		if (rc == 0)
			marked++;
		else if (rc == -2) {
			fanotify_fs_error_close();
			break;
		}
		path = mlist_next(m);
	}

	if (fs_error_fd >= 0 && marked == 0) {
		msg(LOG_INFO,
		    "FAN_FS_ERROR monitoring disabled; no watched "
		    "filesystems accepted error marks");
		fanotify_fs_error_close();
	}

	return fs_error_fd;
}
#else
/*
 * fanotify_fs_error_close - no-op for builds without FAN_FS_ERROR headers.
 * Returns nothing.
 */
void fanotify_fs_error_close(void)
{
	fs_error_fd = -1;
}

/*
 * fanotify_fs_error_mark - no-op for builds without FAN_FS_ERROR headers.
 * @path: unused path.
 * Returns -1 because monitoring is unavailable.
 */
int fanotify_fs_error_mark(const char *path)
{
	(void)path;
	return -1;
}

/*
 * fanotify_fs_error_unmark - no-op for builds without FAN_FS_ERROR headers.
 * @path: unused path.
 * Returns nothing.
 */
void fanotify_fs_error_unmark(const char *path)
{
	(void)path;
}

/*
 * fanotify_fs_error_init - report compile-time FAN_FS_ERROR unavailability.
 * @m: unused watched mount list.
 * Returns -1 because monitoring is unavailable.
 */
int fanotify_fs_error_init(mlist *m)
{
	(void)m;
	msg(LOG_INFO,
	    "FAN_FS_ERROR monitoring disabled; kernel headers do not provide "
	    "the required fanotify info records");
	return -1;
}
#endif

/*
 * fanotify_fs_error_fd - return filesystem error notification fd.
 * Returns a fanotify fd when monitoring is active, or -1 when disabled.
 */
int fanotify_fs_error_fd(void)
{
	return fs_error_fd;
}

/*
 * fanotify_fs_error_handle_event - process one FAN_FS_ERROR metadata record.
 * @metadata: fanotify event metadata from the kernel.
 * Returns 1 when the event was consumed, 0 otherwise.
 */
int fanotify_fs_error_handle_event(
		const struct fanotify_event_metadata *metadata)
{
#if FAPOLICYD_HAVE_FANOTIFY_FS_ERROR
	if (metadata == NULL || (metadata->mask & FAN_FS_ERROR) == 0)
		return 0;

	record_fs_error_event(metadata);
	return 1;
#else
	(void)metadata;
	return 0;
#endif
}

/*
 * fanotify_fs_error_handle_events - read filesystem health fanotify events.
 * Returns nothing.
 */
void fanotify_fs_error_handle_events(void)
{
	const struct fanotify_event_metadata *metadata;
	struct fanotify_event_metadata buf[FANOTIFY_FS_ERROR_BUFFER_SIZE];
	ssize_t len = -2;

	if (fs_error_fd < 0)
		return;

	while (len < 0) {
		do {
			len = read(fs_error_fd, (void *)buf, sizeof(buf));
		} while (len == -1 && errno == EINTR && stop == false);
		if (len == -1 && errno != EAGAIN) {
			msg(LOG_ERR, "Error receiving fanotify_event (%s)",
			    strerror(errno));
			return;
		}
		if (stop)
			return;
	}

	metadata = (const struct fanotify_event_metadata *)buf;
	while (FAN_EVENT_OK(metadata, len)) {
		if (metadata->vers != FANOTIFY_METADATA_VERSION) {
			msg(LOG_ERR, "Mismatch of fanotify metadata version");
			exit(1);
		}

		fanotify_fs_error_handle_event(metadata);
		metadata = FAN_EVENT_NEXT(metadata, len);
	}
}
