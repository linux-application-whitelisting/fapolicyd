#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <grp.h>
#include <limits.h>
#include <error.h>
#include "attr-sets.h"
#include "process.h"

int main(void)
{
	int res, num, i, check_intersect = 0;
	gid_t gid, gids[NGROUPS_MAX];
	attr_sets_entry_t *groups = get_gid_set_from_pid(getpid());

	gid = getgid();
	res = check_int_attr_set(groups, gid);
	if (!res)
		error(1, 0, "Group %d not found", gid);

	num = getgroups(NGROUPS_MAX, gids);
	if (num < 0)
		error(1, 0, "Too many groups");

	for (i = 0; i<num; i++) {
		if (gids[i] == gid)
			check_intersect = 1;
		printf("Checking for %u...", gids[i]);
		res = check_int_attr_set(groups, gids[i]);
		if (!res)
			error(1, 0, "Group %u not found", gids[i]);
		printf("found\n");
	}

	// Now a negative test
	res = check_int_attr_set(groups, 5);
	if (res)
		error(1, 0, "Found unexpected group");

	if (check_intersect) {
		printf("Doing Negative AVL intersection\n");
		attr_sets_entry_t *g = init_standalone_set(INT);
		append_int_attr_set(g, 5);
		append_int_attr_set(g, 7);
		res = avl_intersection(&(g->tree), &(groups->tree));
		if (res)
			error(1, 0, "Negative AVL intersection failed");

		printf("Doing Positive AVL intersection\n");
		append_int_attr_set(g, gid);
		res = avl_intersection(&(g->tree), &(groups->tree));
		if (!res)
			error(1, 0, "Positive AVL intersection failed");
	}

	destroy_attr_set(groups);
	free(groups);

	return 0;
}
