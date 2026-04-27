#include <stdio.h>
#include <stdlib.h>
#include <error.h>
#include "attr-sets.h"

/*
 * main - exercise registry-owned and standalone attr set APIs
 * Returns 0 on success, exits with error on failure.
 */
int main(void)
{
	attr_sets_t *sets;
	attr_sets_entry_t *first;
	attr_sets_entry_t *set;
	attr_sets_entry_t *standalone;
	char name[32];

	sets = attr_sets_create();
	if (!sets)
		error(1, 0, "attr_sets_create failed");

	if (attr_set_create("bad", 0) != NULL)
		error(1, 0, "attr_set_create accepted invalid type");
	if (attr_sets_find(sets, "bad") != NULL)
		error(1, 0, "invalid set inserted");

	first = attr_set_create("uids", UNSIGNED);
	if (!first)
		error(1, 0, "attr_set_create failed");
	if (attr_set_append_int(first, 1000))
		error(1, 0, "attr_set_append_int failed");
	if (attr_set_append_int(first, -1) == 0)
		error(1, 0, "unsigned set accepted negative value");
	if (attr_sets_add(sets, first))
		error(1, 0, "attr_sets_add failed");
	if (attr_sets_find(sets, "uids") != first)
		error(1, 0, "attr_sets_find returned wrong set");

	for (int i = 0; i < 128; i++) {
		snprintf(name, sizeof(name), "set%d", i);
		set = attr_set_create(name, STRING);
		if (!set)
			error(1, 0, "attr_set_create resize case failed");
		if (attr_set_append_str(set, name))
			error(1, 0, "attr_set_append_str resize case failed");
		if (attr_sets_add(sets, set))
			error(1, 0, "attr_sets_add resize case failed");
	}
	if (!attr_set_check_int(first, 1000))
		error(1, 0, "registry resize invalidated set pointer");

	standalone = attr_set_create(NULL, STRING);
	if (!standalone)
		error(1, 0, "standalone attr_set_create failed");
	if (attr_set_append_str(standalone, "/usr/bin/"))
		error(1, 0, "standalone append failed");
	if (!attr_set_check_str(standalone, "/usr/bin/"))
		error(1, 0, "standalone exact check failed");
	if (!attr_set_check_pstr(standalone, "/usr/bin/bash"))
		error(1, 0, "standalone prefix check failed");
	if (attr_set_append_str(standalone, "/usr/bin/") == 0)
		error(1, 0, "duplicate string accepted");
	attr_set_destroy(standalone);

	attr_sets_destroy(sets);
	return 0;
}
