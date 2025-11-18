/*
 * file_filter_test.c - ensure filter_prune_list handles basic lists
 */

#include "filter.h"
#include "llist.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FILTER_CONF TEST_BASE "/src/tests/fixtures/filter-minimal.conf"

static int has_path(list_t *list, const char *path)
{
        for (list_item_t *lptr = list->first; lptr; lptr = lptr->next) {
                if (strcmp(lptr->index, path) == 0)
                        return 1;
        }
        return 0;
}

int main(void)
{
        list_t list;

        list_init(&list);
        if (list_append(&list, strdup("/usr/bin/allowed"), NULL) ||
            list_append(&list, strdup("/usr/bin/skipped"), NULL) ||
            list_append(&list, strdup("/var/log/public/info"), NULL) ||
            list_append(&list, strdup("/var/log/blocked.log"), NULL) ||
            list_append(&list, strdup("/usr/share/example.tmp"), NULL)) {
                fprintf(stderr, "[ERROR:1] unable to build list\n");
                list_empty(&list);
                return 1;
        }

        if (filter_prune_list(&list, FILTER_CONF)) {
                fprintf(stderr, "[ERROR:2] filter_prune_list failed\n");
                list_empty(&list);
                return 2;
        }

        if (list.count != 2) {
                fprintf(stderr, "[ERROR:3] expected 2 entries, got %ld\n",
                        list.count);
                list_empty(&list);
                return 3;
        }

        if (!has_path(&list, "/usr/bin/allowed")) {
                fprintf(stderr, "[ERROR:4] allowed binary missing\n");
                list_empty(&list);
                return 4;
        }

        if (!has_path(&list, "/var/log/public/info")) {
                fprintf(stderr, "[ERROR:5] allowed log entry missing\n");
                list_empty(&list);
                return 5;
        }

        list_empty(&list);
        return 0;
}
