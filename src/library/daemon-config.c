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

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <grp.h>
#include "paths.h"

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

static const struct kw_pair keywords[] =
{
  {"permissive",	permissive_parser },
  {"nice_val",		nice_val_parser },
  {"q_size",		q_size_parser },
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
	config->uid = 0;
	config->gid = 0;
	config->do_stat_report = 1;
	config->detailed_report = 1;
	config->db_max_size = 100;
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
}

int load_daemon_config(conf_t *config)
{
	int fd, lineno = 1;
	FILE *f;
	char buf[160];

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
		return 0;
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
	return 0;
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

static int unsigned_int_parser(unsigned *i, const char *str, int line)
{
	const char *ptr = str;
	unsigned int j;

	/* check that all chars are numbers */
	for (j=0; ptr[j]; j++) {
		if (!isdigit(ptr[j])) {
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

static int uid_parser(const struct nv_pair *nv, int line,
		conf_t *config)
{
	uid_t uid = 0;
	gid_t gid = 0;

	if (isdigit(nv->value[0])) {
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

	if (isdigit(nv->value[0])) {
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
	return unsigned_int_parser(&(config->db_max_size), nv->value, line);
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
					char sha[65];

					int rc = get_ima_hash(fd, sha);
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
