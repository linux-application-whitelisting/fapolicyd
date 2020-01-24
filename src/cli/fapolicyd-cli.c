/*
 * fapolicy-cli.c - CLI tool for fapolicyd
 * Copyright (c) 2016,2018 Red Hat Inc., Durham, North Carolina.
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


#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

const char * usage =
"Fapolicyd CLI Tool\n\n"
"-h\t--help\t\tPrints this help message\n"
"-u\t--update\t\tNotifies fapolicyd to perform update of database\n"
;

const char * _pipe = "/run/fapolicyd/fapolicyd.fifo";

int main(int argc, const char *argv[])
{
    if (argc == 1) {
        fprintf(stderr, "Too few arguments\n\n");
        fprintf(stderr, "%s", usage);
        return 1;
    }

    if (argc > 2) {
        fprintf(stderr, "Too many arguments\n\n");
        fprintf(stderr, "%s", usage);
        return 1;
    }

    if ((strcmp(argv[1], "-h") == 0) || (strcmp(argv[1], "--help") == 0)) {
        printf("%s", usage);
        return 0;
    } else if ((strcmp(argv[1], "-u") == 0) || (strcmp(argv[1], "--update") == 0)) {
        int fd = -1;
        struct stat s;

        fd = open(_pipe, O_WRONLY);
        if (fd == -1) {
            fprintf(stderr, "Open: %s -> %s\n", _pipe, strerror(errno));
            return 1;
        }

        if (stat(_pipe, &s) == -1) {
            fprintf(stderr, "Stat: %s -> %s\n", _pipe, strerror(errno));
            close(fd);
            return 1;
        } else {
            if (!S_ISFIFO(s.st_mode)) {
                fprintf(stderr, "File: %s exists but it is not a pipe!\n", _pipe);
                close(fd);
                return 1;
            }
            // we will require pipe to have 0660 permissions
            if (!(
		 (s.st_mode & S_IRUSR) &&
                 (s.st_mode & S_IWUSR) &&
                !(s.st_mode & S_IXUSR) &&

                 (s.st_mode & S_IRGRP) &&
                 (s.st_mode & S_IWGRP) &&
                !(s.st_mode & S_IXGRP) &&

                !(s.st_mode & S_IROTH) &&
                !(s.st_mode & S_IWOTH) &&
                !(s.st_mode & S_IXOTH)
                )) {
              fprintf(stderr, "File: %s has 0%d%d%d instead of 0660 \n"
                      , _pipe
                      ,
                       ((s.st_mode & S_IRUSR) ? 4 : 0) +
                       ((s.st_mode & S_IWUSR) ? 2 : 0) +
                       ((s.st_mode & S_IXUSR) ? 1 : 0)
                      ,
                       ((s.st_mode & S_IRGRP) ? 4 : 0) +
                       ((s.st_mode & S_IWGRP) ? 2 : 0) +
                       ((s.st_mode & S_IXGRP) ? 1 : 0)
                      ,
                       ((s.st_mode & S_IROTH) ? 4 : 0) +
                       ((s.st_mode & S_IWOTH) ? 2 : 0) +
                       ((s.st_mode & S_IXOTH) ? 1 : 0)
                      );
              close(fd);
              return 1;
            }
        }

        ssize_t ret = write(fd, "1", 2);

        if (ret == -1) {
            fprintf(stderr, "Write: %s -> %s\n", _pipe, strerror(errno));
            close(fd);
            return 1;
        }

        if (close(fd)) {
            fprintf(stderr, "Close: %s -> %s\n", _pipe, strerror(errno));
            return 1;
        }

        printf("Fapolicyd was notified\n");

    } else {
        fprintf(stderr, "Unexpected argument -> %s\n\n", argv[1]);
        printf("%s", usage);
        return 1;
    }
    return 0;
}
