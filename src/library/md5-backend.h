/*
 * md5-backend.h - header file for md5-backend.c
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
 *   Stephen Tridgell
 *   Matt Jolly <Matt.Jolly@footclan.ninja>
 */
#include <uthash.h>

#include "fapolicyd-backend.h"

struct _hash_record {
  const char *key;
  UT_hash_handle hh;
};

static const int kMaxKeyLength = 4096;
static const int kMd5HexSize = 32;

int add_file_to_backend_by_md5(const char *path,
							const char *expected_md5,
							struct _hash_record **hashtable,
							trust_src_t trust_src,
							backend *dstbackend);
