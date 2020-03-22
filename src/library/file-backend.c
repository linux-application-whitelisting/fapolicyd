/*
 * file-backend.c - file backend
 * Copyright (c) 2020 Red Hat Inc., Durham, North Carolina.
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
 *    Steve Grubb <sgrubb@redhat.com>
 */

#include "config.h"

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <ftw.h>
#include "message.h"
#include "file.h"

#include "fapolicyd-backend.h"
#include "llist.h"
#include "file-backend.h"

#define FILE_PATH "/etc/fapolicyd/fapolicyd.trust"
#define BUFFER_SIZE 4096+1+1+1+10+1+64+1
#define FILE_READ_FORMAT  "%4096s %lu %64s"	// path size SHA256
#define FILE_WRITE_FORMAT "%s %lu %s\n"		// path size SHA256

static int file_init_backend(void);
static int file_load_list(void);
static int file_destroy_backend(void);

backend file_backend =
{
	"file",
	file_init_backend,
	file_load_list,
	file_destroy_backend,
	{ 0, 0, NULL },
};


static int file_load_list(void)
{
	FILE *file;
	char buffer[BUFFER_SIZE];

	msg(LOG_DEBUG, "Loading file backend");
	list_empty(&file_backend.list);

	file = fopen(FILE_PATH, "r");
	if (!file) {
		msg(LOG_ERR, "Cannot open %s", FILE_PATH);
		return 1;
	}

	while (fgets(buffer, BUFFER_SIZE, file)) {
		char name[4097], sha[65], *index, *data;
		unsigned long sz;
		int verified = 0;

		if (iscntrl(buffer[0]) || buffer[0] == '#')
			continue;

		if (sscanf(buffer, FILE_READ_FORMAT, name, &sz, sha) != 3) {
			msg(LOG_WARNING, "Can't parse %s", buffer);
			fclose(file);
			return 1;
		}

		if (asprintf(&data, DATA_FORMAT, verified, sz, sha) == -1)
			data = NULL;

		index = strdup(name);

		//msg(LOG_INFO, "GGG: %s, %s", index, data);
		if (index && data)
			list_append(&file_backend.list, index, data);

		//free(data);
	}

	fclose(file);
	return 0;
}


static int file_init_backend(void)
{
	list_init(&file_backend.list);
	return 0;
}


static int file_destroy_backend(void)
{
	list_empty(&file_backend.list);
	return 0;
}

static list_t add_list;
// Returns 1 on error and 0 otherwise
static int check_file(const char *fpath,
                const struct stat *sb,
                int typeflag_unused __attribute__ ((unused)),
                struct FTW *s_unused __attribute__ ((unused)))
{
        int ret = FTW_CONTINUE;

        if (S_ISREG(sb->st_mode) == 0)
                return ret;

	list_append(&add_list, strdup(fpath), NULL);
	return ret;
}


/*
 * This function will append a path string to the file trust database.
 * it returns 0 on success, -1 on error, and 1 if a duplicate is found.
 */
int file_append(const char *path)
{
	FILE *f;
	int fd, count;
	char *hash, *line, buffer[BUFFER_SIZE];
	struct stat sb;
	list_item_t *lptr;

	set_message_mode(MSG_STDERR, DBG_NO);
	f = fopen(FILE_PATH, "r+");
	if (f == NULL) {
		msg(LOG_ERR, "Cannot open %s", FILE_PATH);
		return -1;
	}

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		msg(LOG_ERR, "Cannot open %s", path);
		goto err_out2;
	}

	if (fstat(fd, &sb)) {
		msg(LOG_ERR, "Cannot stat %s", path);
		goto err_out;
	}

	// get the list of files ready to use
	list_init(&add_list);
	close(fd);

	if (S_ISDIR(sb.st_mode)) {
		// Build big list
		nftw(path, check_file, 1024, FTW_PHYS);
	} else
		list_append(&add_list, strdup(path), NULL);

	// Scan the file and look for a duplicate
	while (fgets(buffer, BUFFER_SIZE, f)) {
		char thash[65], tpath[4097];
		long unsigned size;

		if (iscntrl(buffer[0]) || buffer[0] == '#')
			continue;

		if (sscanf(buffer, FILE_READ_FORMAT, tpath, &size, thash) != 3){
			msg(LOG_WARNING, "Can't parse %s", buffer);
			close(fd);
			fclose(f);
			list_empty(&add_list);
			return 1;
		}
		if (list_contains(&add_list, tpath))
			list_remove(&add_list, tpath);
	}

	if (add_list.count == 0) {
		msg(LOG_ERR,
			"After removing duplicates, there is nothing to add");
		close(fd);
		fclose(f);
		list_empty(&add_list);
		return 1;
	}

	// No duplicate, make sure we are at the end
	if (!feof(f))
		fseek(f, 0, SEEK_END);

	// Iterate the list an put each one to disk.
	for (lptr = list_get_first(&add_list); lptr != NULL; lptr = lptr->next){
		path = (char *)lptr->index;
		fd = open(path, O_RDONLY);
		if (fd < 0) {
			msg(LOG_ERR, "Cannot open %s", path);
			goto err_out2;
		}

		if (fstat(fd, &sb)) {
			msg(LOG_ERR, "Cannot stat %s", path);
			goto err_out;
		}
		// Get the size
		if (fstat(fd, &sb)) {
			msg(LOG_ERR, "Cannot stat %s", path);
			goto err_out;
		}

		// Get the hash
		hash = get_hash_from_fd(fd);

		// Format the output
		count = asprintf(&line, FILE_WRITE_FORMAT, path,
						sb.st_size, hash);
		if (count < 0) {
			msg(LOG_ERR, "Cannot format entry for %s", path);
			free(hash);
			goto err_out;
		}

		// Write it to disk
		if (fwrite(line, count, 1, f) != 1) {
			msg(LOG_ERR, "failed writing to %s\n", FILE_PATH);
			free(line);
			free(hash);
			goto err_out;
		}
		free(line);
		free(hash);
		close(fd);
	}
	fclose(f);
	list_empty(&add_list);

	return 0;
err_out:
	close(fd);
err_out2:
	fclose(f);
	list_empty(&add_list);

	return -1;
}


const char *header1 = "# This file contains a list of trusted files\n";
const char *header2 = "#\n";
const char *header3 = "#  FULL PATH        SIZE                             SHA256\n";
const char *header4 = "# /home/user/my-ls 157984 61a9960bf7d255a85811f4afcac51067b8f2e4c75e21cf4f2af95319d4ed1b87\n";

/*
 * This function will delete a path string from the file trust database.
 * It does this by matching all occurrances so that a directory may be
 * passed an all parts of it get deleted. It returns 0 on success, 1 on error.
 */
int file_delete(const char *path)
{
	FILE *f;
	list_t *list = &file_backend.list;
	list_item_t *lptr, *prev = NULL;
	size_t len = strlen(path), hlen;
	int found = 0;

	set_message_mode(MSG_STDERR, DBG_NO);
	if (file_load_list())
		return 1;

	for (lptr = list_get_first(list); lptr != NULL; lptr = lptr->next) {
		if (strncmp(lptr->index, path, len) == 0) {
			found = 1;
			if (prev)
				prev->next = lptr->next;
			else
				list->first = NULL;

			list->count--;
			list_destroy_item(&lptr);
			if (prev)
				lptr = prev;
			else
				break;
		}
		prev = lptr;
	}

	if (!found) {
		msg(LOG_ERR, "%s is not in the trust database", path);
		list_empty(list);
		return 1;
	}

	// Now write everything back out
	f = fopen(FILE_PATH, "w");
	if (f == NULL) {
		msg(LOG_ERR, "Cannot delete %s", path);
		list_empty(list);
		return 1;
	}

	hlen = strlen(header1);
	fwrite(header1, hlen, 1, f);
	hlen = strlen(header2);
	fwrite(header2, hlen, 1, f);
	hlen = strlen(header3);
	fwrite(header3, hlen, 1, f);
	hlen = strlen(header4);
	fwrite(header4, hlen, 1, f);
	for (lptr = list_get_first(list); lptr != NULL; lptr = lptr->next) {
		char buf[BUFFER_SIZE+1];
		char *str = (char *)(lptr->data);
		hlen = snprintf(buf, sizeof(buf), "%s %s\n",
				(char *)lptr->index, &str[2]);
		fwrite(buf, hlen, 1, f);
	}
	fclose(f);
	list_empty(list);

	return 0;
}

