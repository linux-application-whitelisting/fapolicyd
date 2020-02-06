/*
 * fapolicy-cli.c - CLI tool for fapolicyd
 * Copyright (c) 2019,2020 Red Hat Inc.
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
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#include "policy.h"

const char * usage =
"Fapolicyd CLI Tool\n\n"
"-h\t--help\t\tPrints this help message\n"
"-l\t--list\t\tPrints a list of the daemon's rules with numbers\n"
"-u\t--update\t\tNotifies fapolicyd to perform update of database\n"
;

const char * _pipe = "/run/fapolicyd/fapolicyd.fifo";

static char *get_line(FILE *f, char *buf, unsigned size, unsigned *lineno)
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
                fprintf(stderr, "Skipping line %u: too long\n", *lineno);
                    too_long = 1;
        }
    }
    return NULL;
}


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

    } else if ((strcmp(argv[1], "-l") == 0)||(strcmp(argv[1], "--list") == 0)){
        unsigned count = 1, lineno = 0;
        char buf[160];
        FILE *f = fopen(RULES_FILE, "rm");
        if (f == NULL) {
            fprintf(stderr, "Cannot open rules file (%s)\n", strerror(errno));
            return 1;
        }
        while (get_line(f, buf, sizeof(buf), &lineno)) {
            char *str = buf;
            lineno++;
            while (*str) {
                if (!isblank(*str))
                    break;
                str++;
            }
            if (*str == 0) // blank line
                continue;
            if (*str == '#') //comment line
                continue;
            printf("%u. %s\n", count, buf);
            count++;
        }
        fclose(f);
    } else {
        fprintf(stderr, "Unexpected argument -> %s\n\n", argv[1]);
        printf("%s", usage);
        return 1;
    }
    return 0;
}
