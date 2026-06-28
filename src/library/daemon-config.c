/*
 * daemon-config.c - This is a config file parser
 *
 * Copyright 2018-22 Red Hat Inc.
 * All Rights Reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Authors:
 *   Steve Grubb <sgrubb@redhat.com>
 *   Radovan Sroka <rsroka@redhat.com>
 *
 */

#include "config.h"
#include "daemon-config.h"
#include "message.h"
#include "file.h"
#include "database.h"
#include "decision-defer.h"
#include "decision-event.h"
#include "lru.h"
#include "queue.h"

#include <stdio.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <grp.h>
#include <sys/resource.h>
#include "paths.h"

/*
 * Leave room for daemon-owned descriptors outside queued fanotify permission
 * event fds: fanotify, timer/signal machinery, pid and mount files, trust
 * database files, syslog, and short-lived proc/config opens. The current fixed
 * set is smaller, so 64 is a conservative reserve for validation.
 */
#define DAEMON_CONFIG_FD_RESERVE 64
/*
 * Fixed worker allocations should stay a minority of available memory. Use a
 * quarter of physical memory or RLIMIT_AS as an early rejection threshold while
 * leaving space for variable cache payloads, LMDB maps, libraries, and the OS.
 */
#define DAEMON_CONFIG_MEMORY_BUDGET_PERCENT 25
/*
 * Extra per-worker allowance for context state that is not represented by the
 * cache, queue, and defer-array formulas below. This covers current small
 * fields plus future per-worker helper handles and metric padding.
 */
#define DAEMON_CONFIG_WORKER_FIXED_OVERHEAD 16384ULL

/* Local prototypes */
struct nv_pair
{
	const char *name;
	const char *value;
};

struct kw_pair
{
	const char *name;
	int (*parser)(const struct nv_pair *, int, conf_t *);
};

struct nv_list
{
	const char *name;
	int option;
};

static char *get_line(FILE *f, char *buf, unsigned size, int *lineno,
		const char *file);
static int nv_split(char *buf, struct nv_pair *nv);
static const struct kw_pair *kw_lookup(const char *val);
static int permissive_parser(const struct nv_pair *nv, int line,
		conf_t *config);
static int nice_val_parser(const struct nv_pair *nv, int line,
		conf_t *config);
static int q_size_parser(const struct nv_pair *nv, int line,
		conf_t *config);
static int decision_threads_parser(const struct nv_pair *nv, int line,
		conf_t *config);
static int uid_parser(const struct nv_pair *nv, int line,
		conf_t *config);
static int gid_parser(const struct nv_pair *nv, int line,
		conf_t *config);
static int detailed_report_parser(const struct nv_pair *nv, int line,
		conf_t *config);
static int db_max_size_parser(const struct nv_pair *nv, int line,
		conf_t *config);
static int subj_cache_size_parser(const struct nv_pair *nv, int line,
		conf_t *config);
static int obj_cache_size_parser(const struct nv_pair *nv, int line,
		conf_t *config);
static int do_stat_report_parser(const struct nv_pair *nv, int line,
		conf_t *config);
static int watch_fs_parser(const struct nv_pair *nv, int line,
		conf_t *config);
static int ignore_mounts_parser(const struct nv_pair *nv, int line,
		conf_t *config);
static int trust_parser(const struct nv_pair *nv, int line,
			   conf_t *config);
static int integrity_parser(const struct nv_pair *nv, int line,
		conf_t *config);
static int syslog_format_parser(const struct nv_pair *nv, int line,
		conf_t *config);
static int rpm_sha256_only_parser(const struct nv_pair *nv, int line,
		conf_t *config);
static int fs_mark_parser(const struct nv_pair *nv, int line,
		conf_t *config);
static int report_interval_parser(const struct nv_pair *nv, int line,
		conf_t *config);
static int reset_strategy_parser(const struct nv_pair *nv, int line,
		conf_t *config);
static int timing_collection_parser(const struct nv_pair *nv, int line,
		conf_t *config);

static const struct kw_pair keywords[] =
{
  {"permissive",	permissive_parser },
  {"nice_val",		nice_val_parser },
  {"q_size",		q_size_parser },
  {"decision_threads",	decision_threads_parser },
  {"uid",		uid_parser },
  {"gid",		gid_parser },
  {"detailed_report",	detailed_report_parser },
  {"db_max_size",	db_max_size_parser },
  {"subj_cache_size",	subj_cache_size_parser },
  {"obj_cache_size",	obj_cache_size_parser },
  {"do_stat_report",	do_stat_report_parser },
  {"watch_fs",		watch_fs_parser },
  {"ignore_mounts",	ignore_mounts_parser },
  {"trust",		trust_parser },
  {"integrity",		integrity_parser },
  {"syslog_format",	syslog_format_parser },
  {"rpm_sha256_only", rpm_sha256_only_parser},
  {"allow_filesystem_mark",	fs_mark_parser },
  {"report_interval",	report_interval_parser },
  {"reset_strategy",	reset_strategy_parser },
  {"timing_collection",	timing_collection_parser },
  { NULL,		NULL }
};

/*
 * Set everything to its default value
*/
static void clear_daemon_config(conf_t *config)
{
	config->permissive = 0;
	config->nice_val = 10;
	config->q_size = 800;
	config->decision_threads = 1;
	config->uid = 0;
	config->gid = 0;
	config->do_stat_report = 1;
	config->detailed_report = 1;
	config->db_max_size = get_default_db_max_size();
	config->do_auto_db_sizing = true;
	config->subj_cache_size = 4099;
	config->obj_cache_size = 8191;
	config->watch_fs = strdup("ext4,xfs,tmpfs");
	config->ignore_mounts = NULL;
#ifdef USE_RPM
	config->trust = strdup("rpmdb,file");
#else
	config->trust = strdup("file");
#endif
	config->integrity = IN_NONE;
	config->syslog_format =
		strdup("rule,dec,perm,auid,pid,exe,:,path,ftype");
	config->rpm_sha256_only = 0;
	config->allow_filesystem_mark = 0;
	config->report_interval = 0;
	config->reset_strategy = RESET_NEVER;
	config->timing_collection = TIMING_COLLECTION_OFF;
}

int load_daemon_config(conf_t *config)
{
	int fd, lineno = 1;
	FILE *f;
	char buf[8192];

	clear_daemon_config(config);

	/* open the file */
	fd = open(CONFIG_FILE, O_RDONLY|O_NOFOLLOW);
	if (fd < 0) {
		if (errno != ENOENT) {
			msg(LOG_ERR, "Error opening config file (%s)",
				strerror(errno));
			return 1;
		}
		msg(LOG_WARNING,
			"Config file %s doesn't exist, skipping", CONFIG_FILE);
		return validate_daemon_config(config);
	}

	/* Make into FILE struct and read line by line */
	f = fdopen(fd, "rm");
	if (f == NULL) {
		msg(LOG_ERR, "Error - fdopen failed (%s)",
			strerror(errno));
		close(fd);
		return 1;
	}

	while (get_line(f,  buf, sizeof(buf), &lineno, CONFIG_FILE)) {
		// convert line into name-value pair
		const struct kw_pair *kw;
		struct nv_pair nv;
		int rc = nv_split(buf, &nv);
		switch (rc) {
			case 0: // fine
				break;
			case 1: // not the right number of tokens.
				msg(LOG_ERR,
				"Wrong number of arguments for line %d in %s",
					lineno, CONFIG_FILE);
				break;
			case 2: // no '=' sign
				msg(LOG_ERR,
					"Missing equal sign for line %d in %s",
					lineno, CONFIG_FILE);
				break;
			default: // something else went wrong...
				msg(LOG_ERR, "Unknown error for line %d in %s",
					lineno, CONFIG_FILE);
				break;
		}
		if (nv.name == NULL) {
			lineno++;
			continue;
		}
		if (nv.value == NULL) {
			fclose(f);
			msg(LOG_ERR, "Not processing any more lines in %s",
				CONFIG_FILE);
			return 1;
		}

		/* identify keyword or error */
		kw = kw_lookup(nv.name);
		if (kw->name == NULL) {
			msg(LOG_ERR, "Unknown keyword \"%s\" in line %d of %s",
				nv.name, lineno, CONFIG_FILE);
			fclose(f);
			return 1;
		} else {
			/* dispatch to keyword's local parser */
			rc = kw->parser(&nv, lineno, config);
			if (rc != 0) {
				fclose(f);
				return 1; // local parser puts message out
			}
		}

		lineno++;
	}

	fclose(f);
	return validate_daemon_config(config);
}

static char *get_line(FILE *f, char *buf, unsigned size, int *lineno,
	const char *file)
{
	int too_long = 0;

	while (fgets_unlocked(buf, size, f)) {
		/* remove newline */
		char *ptr = strchr(buf, 0x0a);
		if (ptr) {
			if (!too_long) {
				*ptr = 0;
				return buf;
			}
			// Reset and start with the next line
			too_long = 0;
			*lineno = *lineno + 1;
		} else {
			if (!too_long) {
				if (feof(f)) {
					// last line without trailing newline
					return buf;
				}
				// If a line is too long skip it.
				// Only output 1 warning
				msg(LOG_ERR, "Skipping line %d in %s: too long",
					*lineno, file);
			}
			too_long = 1;
		}
	}
	return NULL;
}

static char *_strsplit(char *s)
{
        static char *str = NULL;
        char *ptr;

        if (s)
                str = s;
        else {
                if (str == NULL)
                        return NULL;
                str++;
        }
retry:
        ptr = strchr(str, ' ');
        if (ptr) {
                if (ptr == str) {
                        str++;
                        goto retry;
                }
                s = str;
                *ptr = 0;
                str = ptr;
                return s;
        } else {
                s = str;
                str = NULL;
                if (*s == 0)
                        return NULL;
                return s;
        }
}

static int nv_split(char *buf, struct nv_pair *nv)
{
	/* Get the name part */
	char *ptr;

	nv->name = NULL;
	nv->value = NULL;
	ptr = _strsplit(buf);
	if (ptr == NULL)
		return 0; /* If there's nothing, go to next line */
	if (ptr[0] == '#')
		return 0; /* If there's a comment, go to next line */
	nv->name = ptr;

	/* Check for a '=' */
	ptr = _strsplit(NULL);
	if (ptr == NULL)
		return 1;
	if (strcmp(ptr, "=") != 0)
		return 2;

	/* get the value */
	ptr = _strsplit(NULL);
	if (ptr == NULL)
		return 1;
	nv->value = ptr;

	/* Make sure there's nothing else */
	ptr = _strsplit(NULL);
	if (ptr) {
		/* Allow one option, but check that there's not 2 */
		ptr = _strsplit(NULL);
		if (ptr)
			return 1;
	}

	/* Everything is OK */
	return 0;
}

static const struct kw_pair *kw_lookup(const char *val)
{
	int i = 0;
	while (keywords[i].name != NULL) {
		if (strcmp(keywords[i].name, val) == 0)
			break;
		i++;
	}
	return &keywords[i];
}

void free_daemon_config(conf_t *config)
{
	free((void*)config->watch_fs);
	free((void*)config->ignore_mounts);
	free((void*)config->trust);
	free((void*)config->syslog_format);
}

/*
 * daemon_config_lmdb_reader_limit - compute LMDB reader slots to reserve.
 * @config: daemon configuration to inspect.
 *
 * Returns the reader slots needed for decision workers plus maintenance
 * readers, or 0 if the configured worker count exceeds the daemon's supported
 * maximum. CPU-count validation belongs in validate_daemon_config(); reader
 * sizing only needs a non-overflowing daemon-supported worker count.
 */
unsigned int daemon_config_lmdb_reader_limit(const conf_t *config)
{
	unsigned int threads = 1;

	if (config && config->decision_threads)
		threads = config->decision_threads;
	if (threads > DAEMON_CONFIG_DECISION_THREADS_MAX)
		return 0;

	return threads + DAEMON_CONFIG_LMDB_MAINTENANCE_READERS;
}

/*
 * u64_add_overflow - checked uint64_t addition.
 * @total: accumulator updated on success.
 * @value: value to add.
 *
 * Returns 0 on success and 1 when the sum would overflow.
 */
static int u64_add_overflow(uint64_t *total, uint64_t value)
{
	if (*total > UINT64_MAX - value)
		return 1;

	*total += value;
	return 0;
}

/*
 * u64_mul_overflow - checked uint64_t multiplication.
 * @left: first factor.
 * @right: second factor.
 * @result: product written on success.
 *
 * Returns 0 on success and 1 when the product would overflow.
 */
static int u64_mul_overflow(uint64_t left, uint64_t right, uint64_t *result)
{
	if (left != 0 && right > UINT64_MAX / left)
		return 1;

	*result = left * right;
	return 0;
}

/*
 * decision_defer_capacity_estimate - match defer array sizing policy.
 * @subj_cache_size: configured subject cache slots.
 *
 * Returns the number of deferred events one worker would preallocate.
 */
static unsigned int decision_defer_capacity_estimate(
		unsigned int subj_cache_size)
{
	unsigned int capacity = subj_cache_size / DECISION_DEFER_RATIO;

	if (capacity < DECISION_DEFER_MIN)
		capacity = DECISION_DEFER_MIN;
	return capacity;
}

/*
 * lru_memory_estimate - estimate fixed memory for one LRU cache.
 * @slots: configured LRU slots.
 *
 * Returns bytes allocated before per-entry subject/object attributes.
 */
static int lru_memory_estimate(unsigned int slots, uint64_t *bytes)
{
	uint64_t slot_bytes;

	if (u64_mul_overflow(slots, sizeof(QNode) + sizeof(QNode *),
			     &slot_bytes))
		return 1;

	*bytes = sizeof(Queue) + sizeof(Hash) + slot_bytes;
	return 0;
}

/*
 * worker_memory_estimate - estimate fixed memory per future worker.
 * @config: daemon configuration being validated.
 * @bytes: destination for the estimated bytes.
 *
 * Returns 0 on success and 1 when arithmetic overflows.
 */
static int worker_memory_estimate(const conf_t *config, uint64_t *bytes)
{
	uint64_t total = DAEMON_CONFIG_WORKER_FIXED_OVERHEAD;
	uint64_t value;
	unsigned int defer_capacity;
	uint64_t defer_entry_size;

	if (lru_memory_estimate(config->subj_cache_size, &value) ||
	    u64_add_overflow(&total, value))
		return 1;
	if (lru_memory_estimate(config->obj_cache_size, &value) ||
	    u64_add_overflow(&total, value))
		return 1;

	if (u64_mul_overflow(config->q_size, sizeof(decision_event_t),
			     &value) ||
	    u64_add_overflow(&total, sizeof(struct queue) + value))
		return 1;

	defer_capacity = decision_defer_capacity_estimate(
		config->subj_cache_size);
	defer_entry_size = sizeof(decision_event_t) +
		(2 * sizeof(uint64_t)) + (2 * sizeof(unsigned int)) +
		sizeof(int) + 16;
	if (u64_mul_overflow(defer_capacity, defer_entry_size, &value) ||
	    u64_add_overflow(&total, value))
		return 1;

	*bytes = total;
	return 0;
}

/*
 * effective_nofile_limit - estimate startup file descriptor capacity.
 * @limit_out: destination for the limit, or UINT64_MAX when unlimited.
 *
 * The daemon raises RLIMIT_NOFILE to at least DAEMON_CONFIG_MIN_NOFILE during
 * startup, so validation uses that startup target rather than the pre-start
 * soft limit.
 *
 * Returns 0 on success and 1 when getrlimit fails.
 */
static int effective_nofile_limit(uint64_t *limit_out)
{
	struct rlimit limit;

	if (getrlimit(RLIMIT_NOFILE, &limit)) {
		msg(LOG_ERR, "Cannot inspect RLIMIT_NOFILE: %s",
		    strerror(errno));
		return 1;
	}

	if (limit.rlim_max == RLIM_INFINITY) {
		*limit_out = UINT64_MAX;
		return 0;
	}

	*limit_out = limit.rlim_max;
	if (*limit_out < DAEMON_CONFIG_MIN_NOFILE)
		*limit_out = DAEMON_CONFIG_MIN_NOFILE;
	return 0;
}

/*
 * memory_budget - estimate a fixed-allocation budget for workers.
 *
 * Returns a byte budget based on physical memory and RLIMIT_AS, or 0 when no
 * meaningful memory ceiling can be inspected.
 */
static uint64_t memory_budget(void)
{
	struct rlimit limit;
	uint64_t budget = 0;
	long pages, page_size;

	pages = sysconf(_SC_PHYS_PAGES);
	page_size = sysconf(_SC_PAGESIZE);
	if (pages > 0 && page_size > 0 &&
	    (uint64_t)pages <= UINT64_MAX / (uint64_t)page_size) {
		uint64_t physical = (uint64_t)pages * (uint64_t)page_size;

		budget = (physical / 100) *
			DAEMON_CONFIG_MEMORY_BUDGET_PERCENT;
	}

	if (getrlimit(RLIMIT_AS, &limit) == 0 &&
	    limit.rlim_cur != RLIM_INFINITY) {
		uint64_t as_budget = ((uint64_t)limit.rlim_cur / 100) *
			DAEMON_CONFIG_MEMORY_BUDGET_PERCENT;

		if (budget == 0 || as_budget < budget)
			budget = as_budget;
	}

	return budget;
}

/*
 * validate_decision_threads - validate the future worker count.
 * @config: daemon configuration being validated.
 *
 * Returns 0 when the configured count fits the daemon's fixed worker limits
 * and host resource limits, otherwise 1.
 */
static int validate_decision_threads(const conf_t *config)
{
	unsigned int threads, readers;
	uint64_t fd_limit, fd_needed, per_worker, memory_needed, budget;
	long cpus;

	threads = config->decision_threads;
	if (threads == 0) {
		msg(LOG_ERR, "decision_threads must be at least 1");
		return 1;
	}
	if (threads > DAEMON_CONFIG_DECISION_THREADS_MAX) {
		msg(LOG_ERR,
		    "decision_threads %u exceeds the maximum of %u",
		    threads, DAEMON_CONFIG_DECISION_THREADS_MAX);
		return 1;
	}

	cpus = sysconf(_SC_NPROCESSORS_ONLN);
	if (cpus < 1) {
		msg(LOG_ERR, "Cannot determine online CPU count");
		return 1;
	}
	if (threads > (unsigned long)cpus) {
		msg(LOG_ERR,
		    "decision_threads %u exceeds online CPU count %ld",
		    threads, cpus);
		return 1;
	}

	readers = daemon_config_lmdb_reader_limit(config);
	if (readers == 0 || readers > DAEMON_CONFIG_LMDB_MAX_READERS) {
		msg(LOG_ERR,
		    "decision_threads %u requires %u LMDB readers, max is %u",
		    threads, readers, DAEMON_CONFIG_LMDB_MAX_READERS);
		return 1;
	}

	if (effective_nofile_limit(&fd_limit))
		return 1;
	if (u64_mul_overflow(config->q_size, threads, &fd_needed) ||
	    u64_add_overflow(&fd_needed, DAEMON_CONFIG_FD_RESERVE)) {
		msg(LOG_ERR, "decision_threads file descriptor estimate "
		    "overflowed");
		return 1;
	}
	if (fd_needed > fd_limit) {
		msg(LOG_ERR,
		    "decision_threads %u with q_size %u needs about %llu "
		    "file descriptors, limit is %llu",
		    threads, config->q_size,
		    (unsigned long long)fd_needed,
		    (unsigned long long)fd_limit);
		return 1;
	}

	if (worker_memory_estimate(config, &per_worker) ||
	    u64_mul_overflow(per_worker, threads, &memory_needed)) {
		msg(LOG_ERR, "decision_threads memory estimate overflowed");
		return 1;
	}
	budget = memory_budget();
	if (budget && memory_needed > budget) {
		msg(LOG_ERR,
		    "decision_threads %u needs about %llu MiB fixed worker "
		    "memory, budget is %llu MiB",
		    threads,
		    (unsigned long long)(memory_needed / (1024 * 1024)),
		    (unsigned long long)(budget / (1024 * 1024)));
		return 1;
	}

	return 0;
}

/*
 * validate_daemon_config - validate cross-field daemon configuration.
 * @config: daemon configuration populated from defaults and fapolicyd.conf.
 *
 * Returns 0 when the configuration is accepted, otherwise 1.
 */
int validate_daemon_config(const conf_t *config)
{
	if (config == NULL)
		return 1;

	return validate_decision_threads(config);
}

static int unsigned_int_parser(unsigned *i, const char *str, int line)
{
	const char *ptr = str;
	unsigned int j;

	/* check that all chars are numbers */
	for (j=0; ptr[j]; j++) {
		if (!isdigit((unsigned char)ptr[j])) {
			msg(LOG_ERR,
				"Value %s should only be numbers - line %d",
				str, line);
			return 1;
		}
	}

	/* convert to unsigned long */
	errno = 0;
	j = strtoul(str, NULL, 10);
	if (errno) {
		msg(LOG_ERR,
			"Error converting string to a number (%s) - line %d",
			strerror(errno), line);
		return 1;
	}
	*i = j;
	return 0;
}

static int permissive_parser(const struct nv_pair *nv, int line,
                conf_t *config)
{
	int rc = unsigned_int_parser(&(config->permissive), nv->value, line);
	if (rc == 0 && config->permissive > 1) {
		msg(LOG_WARNING,
			"permissive value reset to 1 - line %d", line);
		config->permissive = 1;
	}
	return rc;
}

static int nice_val_parser(const struct nv_pair *nv, int line,
		conf_t *config)
{
	int rc = unsigned_int_parser(&(config->nice_val), nv->value, line);
	if (rc == 0 && config->nice_val > 20) {
		msg(LOG_WARNING,
			"Error, nice_val is larger than 20 - line %d",
			line);
		rc = 1;
	}
	return rc;
}

static int q_size_parser(const struct nv_pair *nv, int line,
		conf_t *config)
{
	int rc = unsigned_int_parser(&(config->q_size), nv->value, line);
	if (rc == 0 && config->q_size > 10480)
		msg(LOG_WARNING,
			"q_size might be unnecessarily large - line %d", line);
	return rc;
}

/*
 * decision_threads_parser - parse configured decision worker count.
 * @nv: name/value pair describing the option.
 * @line: line number where the option was found.
 * @config: configuration structure to update.
 *
 * Returns 0 on success and 1 when the value is not a positive integer.
 */
static int decision_threads_parser(const struct nv_pair *nv, int line,
		conf_t *config)
{
	int rc = unsigned_int_parser(&(config->decision_threads),
				     nv->value, line);
	if (rc == 0 && config->decision_threads == 0) {
		msg(LOG_ERR, "decision_threads must be at least 1 - line %d",
		    line);
		return 1;
	}
	return rc;
}

static int uid_parser(const struct nv_pair *nv, int line,
		conf_t *config)
{
	uid_t uid = 0;
	gid_t gid = 0;

	if (isdigit((unsigned char)nv->value[0])) {
		errno = 0;
		uid = strtoul(nv->value, NULL, 10);
		if (errno) {
			msg(LOG_ERR,
			"Error converting user value - line %d", line);
			return 1;
		}
		gid = uid;
	} else {
		struct passwd *pw = getpwnam(nv->value);
		if (pw == NULL) {
			msg(LOG_ERR, "user %s is unknown - line %d",
				nv->value, line);
			return 1;
		}
		uid = pw->pw_uid;
		gid = pw->pw_gid;
		endpwent();
	}
	config->uid = uid;
	config->gid = gid;
	return 0;
}

static int gid_parser(const struct nv_pair *nv, int line,
		conf_t *config)
{
	gid_t gid = 0;

	if (isdigit((unsigned char)nv->value[0])) {
		errno = 0;
		gid = strtoul(nv->value, NULL, 10);
		if (errno) {
			msg(LOG_ERR,
			"Error converting group value - line %d", line);
			return 1;
		}
	} else {
		struct group *gr ;
		gr = getgrnam(nv->value);
		if (gr == NULL) {
			msg(LOG_ERR, "group %s is unknown - line %d",
					nv->value, line);
			return 1;
		}
		gid = gr->gr_gid;
		endgrent();
	}
	config->gid = gid;
	return 0;
}

static int detailed_report_parser(const struct nv_pair *nv, int line,
		conf_t *config)
{
	return unsigned_int_parser(&(config->detailed_report), nv->value, line);
}

static int db_max_size_parser(const struct nv_pair *nv, int line,
		conf_t *config)
{
	unsigned int db_max_size = config->db_max_size;

	// "auto" keeps utilization-based sizing enabled. A numeric value is an
	// explicit administrator override and keeps the legacy fixed MiB limit.
	if (strcmp(nv->value, "auto") == 0) {
		config->db_max_size = get_default_db_max_size();
		config->do_auto_db_sizing = true;
		return 0;
	}

	if (unsigned_int_parser(&db_max_size, nv->value, line))
		return 1;

	config->db_max_size = db_max_size;
	config->do_auto_db_sizing = false;
	return 0;
}

static int subj_cache_size_parser(const struct nv_pair *nv, int line,
		conf_t *config)
{
	int rc=unsigned_int_parser(&(config->subj_cache_size), nv->value, line);
	if (rc == 0 && config->subj_cache_size > 16384)
		msg(LOG_WARNING,
		    "subj_cache_size might be unnecessarily large - line %d",
			 line);
	return rc;
}

static int obj_cache_size_parser(const struct nv_pair *nv, int line,
		conf_t *config)
{
	int rc=unsigned_int_parser(&(config->obj_cache_size), nv->value, line);
	if (rc == 0 && config->obj_cache_size > 32768)
		msg(LOG_WARNING,
		    "obj_cache_size might be unnecessarily large - line %d",
			line);
	return rc;
}

static int do_stat_report_parser(const struct nv_pair *nv, int line,
		conf_t *config)
{
	int rc=unsigned_int_parser(&(config->do_stat_report), nv->value, line);
	if (rc == 0 && config->do_stat_report > 2) {
		msg(LOG_WARNING,
			"do_stat_report value reset to 1 - line %d", line);
		config->do_stat_report = 1;
	}
	return rc;
}


static int watch_fs_parser(const struct nv_pair *nv, int line,
		conf_t *config)
{
	free((void *)config->watch_fs);
	config->watch_fs = strdup(nv->value);
	if (config->watch_fs)
		return 0;
	msg(LOG_ERR, "Could not store value line %d", line);
	return 1;
}

/*
 * ignore_mounts_parser - store ignore_mounts configuration setting.
 * @nv: name/value pair describing the option.
 * @line: line number where the option was found.
 * @config: configuration structure to update.
 * Returns 0 on success and 1 when memory cannot be allocated.
 */
static int ignore_mounts_parser(const struct nv_pair *nv, int line,
		conf_t *config)
{
	free((void *)config->ignore_mounts);
	config->ignore_mounts = strdup(nv->value);
	if (config->ignore_mounts)
		return 0;
	msg(LOG_ERR, "Could not store value line %d", line);
	return 1;
}

static int report_interval_parser(const struct nv_pair *nv, int line,
		conf_t *config)
{
	return unsigned_int_parser(&(config->report_interval), nv->value, line);
}

static const struct nv_list reset_strategies[] =
{
  {"never",	RESET_NEVER },
  {"auto",	RESET_AUTO },
  {"manual",	RESET_MANUAL },
  { NULL,	0 }
};

/*
 * reset_strategy_parser - parse metrics reset strategy.
 * @nv: name/value pair describing the option.
 * @line: line number where the option was found.
 * @config: configuration structure to update.
 * Returns 0 on success and 1 when the value is unknown.
 */
static int reset_strategy_parser(const struct nv_pair *nv, int line,
		conf_t *config)
{
	for (int i = 0; reset_strategies[i].name != NULL; i++) {
		if (strcasecmp(nv->value, reset_strategies[i].name) == 0) {
			config->reset_strategy = reset_strategies[i].option;
			return 0;
		}
	}

	msg(LOG_ERR, "Option %s not found - line %d", nv->value, line);
	return 1;
}

static const struct nv_list timing_collections[] =
{
  {"off",	TIMING_COLLECTION_OFF },
  {"manual",	TIMING_COLLECTION_MANUAL },
  { NULL,	0 }
};

/*
 * timing_collection_parser - parse timing collection control mode.
 * @nv: name/value pair describing the option.
 * @line: line number where the option was found.
 * @config: configuration structure to update.
 * Returns 0 on success and 1 when the value is unknown.
 */
static int timing_collection_parser(const struct nv_pair *nv, int line,
		conf_t *config)
{
	for (int i = 0; timing_collections[i].name != NULL; i++) {
		if (strcasecmp(nv->value, timing_collections[i].name) == 0) {
			config->timing_collection = timing_collections[i].option;
			return 0;
		}
	}

	msg(LOG_ERR, "Option %s not found - line %d", nv->value, line);
	return 1;
}


static int trust_parser(const struct nv_pair *nv, int line,
			   conf_t *config)
{
	free((void *)config->trust);
	config->trust = strdup(nv->value);
	if (config->trust)
		return 0;
	msg(LOG_ERR, "Could not store value line %d", line);
	return 1;
}


static const struct nv_list integrity_schemes[] =
{
  {"none",   IN_NONE   },
  {"size",   IN_SIZE   },
  {"ima",    IN_IMA    },
  {"sha256", IN_SHA256 },
  { NULL,  0 }
};

static int integrity_parser(const struct nv_pair *nv, int line,
		conf_t *config)
{
	for (int i=0; integrity_schemes[i].name != NULL; i++) {
		if (strcasecmp(nv->value, integrity_schemes[i].name) == 0) {
			config->integrity = integrity_schemes[i].option;
			if (config->integrity == IN_IMA) {
				int fd = open("/bin/sh", O_RDONLY);
				if (fd >= 0) {
					char sha[FILE_DIGEST_STRING_MAX];
					file_hash_alg_t alg;

					int rc = get_ima_hash(fd, &alg, sha);
					close(fd);
					if (rc == 0) {
						msg(LOG_ERR,
  "IMA integrity checking selected, but the extended attributes can't be read");
						return 1;
					}
				} else {
					msg(LOG_ERR,
	    "IMA integrity checking selected, but can't test the shell");
					return 1;
				}
			}
			return 0;
		}
	}
	msg(LOG_ERR, "Option %s not found - line %d", nv->value, line);
	return 1;
}

const char *lookup_integrity(unsigned value)
{
	if (value > 3)
		return NULL;

	return integrity_schemes[value].name;
}

/*
 * lookup_reset_strategy - return the reset strategy name.
 * @value: reset_strategy_t value to describe.
 * Returns the strategy name, or NULL when the value is unknown.
 */
const char *lookup_reset_strategy(unsigned value)
{
	if (value > RESET_MANUAL)
		return NULL;

	return reset_strategies[value].name;
}

/*
 * lookup_timing_collection - return the timing collection mode name.
 * @value: timing_collection_t value to describe.
 * Returns the timing mode name, or NULL when the value is unknown.
 */
const char *lookup_timing_collection(unsigned value)
{
	if (value > TIMING_COLLECTION_MANUAL)
		return NULL;

	return timing_collections[value].name;
}

static int syslog_format_parser(const struct nv_pair *nv, int line,
		conf_t *config)
{
	free((void *)config->syslog_format);
	config->syslog_format = strdup(nv->value);
	if (config->syslog_format)
		return 0;
	msg(LOG_ERR, "Could not store value line %d", line);
	return 1;
}


static int rpm_sha256_only_parser(const struct nv_pair *nv, int line,
                conf_t *config)
{
	int rc = 0;
#ifndef USE_RPM
	msg(LOG_WARNING, "rpm_sha256_only: fapolicyd was not built with rpm support, ignoring" );
#else
	rc = unsigned_int_parser(&(config->rpm_sha256_only), nv->value, line);
	if (rc == 0 && config->rpm_sha256_only > 1) {
		msg(LOG_WARNING,
			"rpm_sha256_only value reset to 0 - line %d", line);
		config->rpm_sha256_only = 0;
	}
#endif

	return rc;
}


static int fs_mark_parser(const struct nv_pair *nv, int line,
		conf_t *config)
{
	int rc = 0;
#if defined HAVE_DECL_FAN_MARK_FILESYSTEM && HAVE_DECL_FAN_MARK_FILESYSTEM != 0
	rc = unsigned_int_parser(&(config->allow_filesystem_mark),
				 nv->value, line);

	if (rc == 0 && config->allow_filesystem_mark > 1) {
		msg(LOG_WARNING,
			"allow_filesystem_mark value reset to 0 - line %d",
			line);
		config->allow_filesystem_mark = 0;
	}
#else
	msg(LOG_WARNING,
	    "allow_filesystem_mark is unsupported on this kernel - ignoring");
#endif

	return rc;
}
