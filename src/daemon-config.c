/*
 * daemon-config.c - This is a config file parser
 *
 * Copyright 2018 Red Hat Inc., Durham, North Carolina.
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
 * 
 */

#include "config.h"
#include "daemon-config.h"
#include "message.h"
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <grp.h>

#define CONFIG_FILE "/etc/fapolicyd/fapolicyd.conf"

/* Local prototypes */
struct nv_pair
{
	const char *name;
	const char *value;
};

struct kw_pair 
{
	const char *name;
	int (*parser)(struct nv_pair *, int, struct daemon_conf *);
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
static int permissive_parser(struct nv_pair *nv, int line, 
		struct daemon_conf *config);
static int nice_val_parser(struct nv_pair *nv, int line,
		struct daemon_conf *config);
static int q_size_parser(struct nv_pair *nv, int line,
		struct daemon_conf *config);
static int uid_parser(struct nv_pair *nv, int line,
		struct daemon_conf *config);
static int gid_parser(struct nv_pair *nv, int line,
		struct daemon_conf *config);
static int detailed_report_parser(struct nv_pair *nv, int line,
		struct daemon_conf *config);
static int db_max_size_parser(struct nv_pair *nv, int line,
		struct daemon_conf *config);
static int subj_cache_size_parser(struct nv_pair *nv, int line,
		struct daemon_conf *config);
static int obj_cache_size_parser(struct nv_pair *nv, int line,
		struct daemon_conf *config);
static int do_stat_report_parser(struct nv_pair *nv, int line,
		struct daemon_conf *config);

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
  { NULL,		NULL }
};

/*
 * Set everything to its default value
*/
void clear_daemon_config(struct daemon_conf *config)
{
	config->permissive = 0;
	config->nice_val = 10;
	config->q_size = 1024;
	config->uid = 0;
	config->gid = 0;
	config->do_stat_report = 1;
	config->detailed_report = 1;
	config->db_max_size = 100;
	config->subj_cache_size = 1024;
	config->obj_cache_size = 4096;
}

int load_daemon_config(struct daemon_conf *config)
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
			// If a line is too long skip it.
			// Only output 1 warning
			if (!too_long)
				msg(LOG_ERR, "Skipping line %d in %s: too long",
					*lineno, file);
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
		if (strcasecmp(keywords[i].name, val) == 0)
			break;
		i++;
	}
	return &keywords[i];
}
 
void free_daemon_config(struct daemon_conf *config)
{
//	free((void*)config->file);
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

static int permissive_parser(struct nv_pair *nv, int line,
                struct daemon_conf *config)
{
	int rc = unsigned_int_parser(&(config->permissive), nv->value, line);
	if (rc == 0 && config->permissive > 1) {
		msg(LOG_WARNING,
			"permissive value reset to 1 - line %d", line);
		config->permissive = 1;
	}
	return rc;
}

static int nice_val_parser(struct nv_pair *nv, int line,
		struct daemon_conf *config)
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
static int q_size_parser(struct nv_pair *nv, int line,
		struct daemon_conf *config)
{
	int rc = unsigned_int_parser(&(config->q_size), nv->value, line);
	if (rc == 0 && config->q_size > 10480)
		msg(LOG_WARNING,
			"q_size might be unnecessarily large - line %d", line);
	return rc;
}

static int uid_parser(struct nv_pair *nv, int line,
		struct daemon_conf *config)
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

static int gid_parser(struct nv_pair *nv, int line,
		struct daemon_conf *config)
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

static int detailed_report_parser(struct nv_pair *nv, int line,
		struct daemon_conf *config)
{
	return unsigned_int_parser(&(config->detailed_report), nv->value, line);
}

static int db_max_size_parser(struct nv_pair *nv, int line,
		struct daemon_conf *config)
{
	return unsigned_int_parser(&(config->db_max_size), nv->value, line);
}

static int subj_cache_size_parser(struct nv_pair *nv, int line,
		struct daemon_conf *config)
{
	int rc=unsigned_int_parser(&(config->subj_cache_size), nv->value, line);
	if (rc == 0 && config->subj_cache_size > 16384)
		msg(LOG_WARNING,
		    "subj_cache_size might be unnecessarily large - line %d",
			 line);
	return rc;
}

static int obj_cache_size_parser(struct nv_pair *nv, int line,
		struct daemon_conf *config)
{
	int rc=unsigned_int_parser(&(config->obj_cache_size), nv->value, line);
	if (rc == 0 && config->obj_cache_size > 32768)
		msg(LOG_WARNING,
		    "obj_cache_size might be unnecessarily large - line %d",
			line);
	return rc;
}

static int do_stat_report_parser(struct nv_pair *nv, int line,
		struct daemon_conf *config)
{
	int rc=unsigned_int_parser(&(config->do_stat_report), nv->value, line);
	if (rc == 0 && config->do_stat_report > 2) {
		msg(LOG_WARNING,
			"do_stat_report value reset to 1 - line %d", line);
		config->do_stat_report = 1;
	}
	return rc;
}

