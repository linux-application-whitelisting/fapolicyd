/*
 * policy.h - Header file for policy.c
 * Copyright (c) 2016,2020 Red Hat
 * All Rights Reserved.
 *
 * This software may be freely redistributed and/or modified under the
 * terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; see the file COPYING. If not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor
 * Boston, MA 02110-1335, USA.
 *
 * Authors:
 *   Steve Grubb <sgrubb@redhat.com>
 */

#ifndef POLICY_HEADER
#define POLICY_HEADER

#include <sys/fanotify.h>
#include "event.h"

#define RULES_FILE "/etc/fapolicyd/fapolicyd.rules"

#ifdef USE_AUDIT
#if HAVE_DECL_FAN_AUDIT
#define AUDIT FAN_AUDIT
#else
#define AUDIT 0x0010
#define FAN_ENABLE_AUDIT 0x00000040
#endif
#else
#define AUDIT 0x0
#endif

#define SYSLOG 0x0020
#define FAN_RESPONSE_MASK FAN_ALLOW|FAN_DENY|FAN_AUDIT

typedef enum {
	NO_OPINION = 0,
	ALLOW = FAN_ALLOW,
	DENY = FAN_DENY,
	#ifdef USE_AUDIT
	ALLOW_AUDIT = FAN_ALLOW | AUDIT,
	DENY_AUDIT = FAN_DENY | AUDIT,
	#endif
	ALLOW_SYSLOG = FAN_ALLOW | SYSLOG,
	DENY_SYSLOG = FAN_DENY | SYSLOG,
	ALLOW_LOG = FAN_ALLOW | AUDIT | SYSLOG,
	DENY_LOG = FAN_DENY | AUDIT | SYSLOG
} decision_t;

extern int debug;
extern int permissive;

int dec_name_to_val(const char *name);
int load_config(const conf_t *config);
int reload_config(const conf_t *config);
decision_t process_event(event_t *e);
void make_policy_decision(const struct fanotify_event_metadata *metadata,
						int fd, uint64_t mask);
unsigned long getAllowed(void);
unsigned long getDenied(void);
void policy_no_audit(void);
void destroy_config(void);

#endif

