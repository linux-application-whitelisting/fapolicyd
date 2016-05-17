/*
 * object-attr.c - abstract object attribute access
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
 * Free Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * Authors:
 *   Steve Grubb <sgrubb@redhat.com>
 */

#include "config.h"
#include <stddef.h>	// For NULL
#include <strings.h>
#include "object-attr.h"

static const nv_t table[] = {
{	ALL_OBJ, 	"all" },
{	PATH, 		"path" },
{	ODIR, 		"dir" },
{	DEVICE,		"device" },
{	FTYPE,		"ftype" },
{	SHA256HASH,	"sha256hash" },
{	FMODE,		"mode" },
};

#define MAX_OBJECTS (sizeof(table)/sizeof(table[0]))

int obj_name_to_val(const char *name)
{
	unsigned int i = 0;
	while (i < MAX_OBJECTS) {
		if (strcasecmp(name, table[i].name) == 0)
			return table[i].value;
		i++;
	}
	return -1;
}

const char *obj_val_to_name(unsigned int v)
{
	if (v < MAX_OBJECTS)
		return table[v].name;

	return NULL;
}

