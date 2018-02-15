/*
 * policy.h - Header file for policy.c
 * Copyright (c) 2016 Red Hat Inc., Durham, North Carolina.
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

#define CONFIG_FILE "/etc/fapolicyd/fapolicyd.rules"

#ifdef USE_AUDIT
#if HAVE_DECL_FAN_AUDIT
#define AUDIT FAN_AUDIT
#else
#define AUDIT 0x10
#define FAN_ENABLE_AUDIT 0x00000040
#endif
#else
#define AUDIT 0x0
#endif

typedef enum { NO_OPINION = 0, ALLOW = FAN_ALLOW, DENY = FAN_DENY,
#ifdef USE_AUDIT
ALLOW_AUDIT = FAN_ALLOW | AUDIT, DENY_AUDIT = FAN_DENY | AUDIT
#endif
} decision_t;

extern int debug;
extern int permissive;

int dec_name_to_val(const char *name);
const char *dec_val_to_name(unsigned int v);
int load_config(void);
int reload_config(void);
decision_t process_event(event_t *e);
void policy_no_audit(void);
void destroy_config(void);

#endif
