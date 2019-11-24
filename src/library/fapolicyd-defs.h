/*
* fapolicyd-defs.h - Header file for defines & enums that cause loops
* Copyright (c) 2019 Red Hat Inc.
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

#ifndef FAPOLICYD_DEFS_HEADER
#define FAPOLICYD_DEFS_HEADER

typedef enum { OPEN_ACC, EXEC_ACC , ANY_ACC } access_t;
typedef enum { RULE_FMT_ORIG, RULE_FMT_COLON } rformat_t;

#endif
