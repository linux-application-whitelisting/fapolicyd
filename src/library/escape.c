/*
 * escape.c - Source file for escaping capability
 * Copyright (c) 2021,23 Red Hat Inc.
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

#include "config.h"
#include "escape.h"

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>

#include "message.h"

static const char sh_set[] = "\"'`$\\!()| ";
/*
 * this function checks whether escaping is needed and if yes
 * it returns positive value and this value represents the size
 * of the string after escaping
 */
size_t check_escape_shell(const char *input)
{
	const char *p = input;
	size_t size = 0, cnt = 0;

	while (*p) {
		// \000
		if (*p < 32)
			cnt += 4;
		// \\ \/
		else if (strchr(sh_set, *p))
			cnt += 2;
		// non escaped char
		else
			cnt++;
		p++;
		size++;
	}
	// if no escaped char
	if (cnt == size)
		return 0;

	return cnt;
}

#define MAX_SIZE 8192
char *escape_shell(const char *input, const size_t expected_size)
{
	char *escape_buffer;

	if(!input)
		return NULL;

	if (expected_size >= MAX_SIZE)
		return NULL;

	escape_buffer = malloc(expected_size + 1);
	if (escape_buffer == NULL)
		return NULL;

	size_t len = strlen(input);

	unsigned int i = 0, j = 0;
	while (i < len) {
		if ((unsigned char)input[i] < 32) {
			escape_buffer[j++] = ('\\');
			escape_buffer[j++] = ('0' + ((input[i] & 0300) >> 6));
			escape_buffer[j++] = ('0' + ((input[i] & 0070) >> 3));
			escape_buffer[j++] = ('0' + (input[i] & 0007));
		} else if (strchr(sh_set, input[i])) {
			escape_buffer[j++] = ('\\');
			escape_buffer[j++] = input[i];
		} else
			escape_buffer[j++] = input[i];
		i++;
	}
	escape_buffer[j] = '\0';	/* terminate string */

	return escape_buffer;
}

#define isoctal(a) (((a) & ~7) == '0')
void unescape_shell(char *s, const size_t len)
{
	size_t sz = 0;
	char *buf = s;

	while (*s) {
		if (*s == '\\' && sz + 3 < len && isoctal(s[1]) &&
		    isoctal(s[2]) && isoctal(s[3])) {

			*buf++ = 64*(s[1] & 7) + 8*(s[2] & 7) + (s[3] & 7);
			s += 4;
			sz += 4;
		} else if (*s == '\\' && sz + 2 < len) {
			*buf++ = s[1];
			s += 2;
			sz += 2;
		} else {
			*buf++ = *s++;
			sz++;
		}
	}
	*buf = '\0';
}

#define IS_HEX(X) (isxdigit(X) > 0 && !(islower(X) > 0))

static char asciiHex2Bits(char X)
{
	char base = 0;
	if (X >= '0' && X <= '9') {
		base = '0';
	} else if (X >= 'A' && X <= 'F') {
		base = 'A' - 10;
  }
	return (X - base) & 0X00FF;
}

// unescape old format of a trust file
// it makes code backwards compatible
char *unescape(const char *input)
{
	char buffer[4096 + 1] = {0};
	size_t input_len = strlen(input);
	size_t pos = 0;

	for (size_t i = 0; i < input_len; i++ ) {
		if (input[i] == '%') {

			if (i+2 < input_len && (IS_HEX(input[i+1]) && IS_HEX(input[i+2])) ) {
				char c = asciiHex2Bits(input[i+1]);
				char d = asciiHex2Bits(input[i+2]);

				if (pos >=(sizeof(buffer) - 1))
					return NULL;

				buffer[pos++] = (c << 4) + d;
				i += 2;

			} else {

				msg(LOG_WARNING, "Input %s does not have a valid escape sequence, "
					"unable to unescape, copying char by char", input);

				// if not vaid sequence, copy char by char
				if (pos >=(sizeof(buffer) - 1))
					return NULL;

				buffer[pos++] = input[i];

			}

		} else {

			if (pos >=(sizeof(buffer) - 1))
				return NULL;

			buffer[pos++] = input[i];
		}
	}

	return strdup(buffer);
}
