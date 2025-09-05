#include <stdio.h>
#include <stdlib.h>
#include <error.h>
#include "attr-sets.h"

/*
 * main - ensure invalid type values are rejected
 * Returns 0 on success, exits with error on failure
 */
int main(void)
{
	int ret;
	size_t idx = 5;
	
	ret = init_attr_sets();
	if (ret)
		error(1, 0, "init_attr_sets failed");
	
	ret = add_attr_set("bad", 0, &idx);
	if (ret == 0)
		error(1, 0, "add_attr_set accepted invalid type");
	if (idx != 5)
		error(1, 0, "index modified on invalid type");
	
	if (search_attr_set_by_name("bad") != 0)
		error(1, 0, "invalid set inserted");
	
	destroy_attr_sets();
	return 0;
}
