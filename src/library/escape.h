/*
 * escape.h - Header file for escaping capability
 * Copyright (c) 2021 Red Hat Inc.
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
 *   Radovan Sroka <rsroka@redhat.com>
 */

#ifndef ESCAPE_H
#define ESCAPE_H

#include "gcc-attributes.h"

enum {
	WHITESPACES,
	EVERYTHING
};

char *escape(const char *input, int mode) MALLOCLIKE;
char *unescape(const char *input) MALLOCLIKE;

#endif

