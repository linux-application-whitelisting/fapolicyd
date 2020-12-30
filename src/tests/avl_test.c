#include <stdio.h>
#include <stdlib.h>
#include <error.h>
#include "avl.h"

typedef struct _avl_int_data {
        avl avl;
        int num;
} avl_int_data_t;

static avl_tree tree;

static int intcmp_cb(void *a, void *b)
{
        return ((avl_int_data_t *)a)->num - ((avl_int_data_t *)b)->num;
}

int append(int num)
{
	avl_int_data_t *data = malloc(sizeof(avl_int_data_t));
	data->num = num;
	avl *ret = avl_insert(&tree, (avl *)data);
	if (ret != (avl *)data) {
		free(data);
		return 1;
	}
	return 0;
}

int node_remove(int num)
{
	avl_int_data_t node, *n;
	node.num = num;

	n = (avl_int_data_t *)avl_remove(&tree, (avl *)&node);
	if (n) {
		if (n->num != num)
			error(1, 0, "Remove wrong item %d looking for %d",
			     n->num, num);
		else {
			free(n);
			return 0;
		}

	} else
		error(1, 0, "Remove didn't find %d", num);

	return 0;
}

// https://stackoverflow.com/questions/3955680/how-to-check-if-my-avl-tree-implementation-is-correct
int main(void)
{
	avl_int_data_t *node;

	avl_init(&tree, intcmp_cb);

	append(2);
	append(1);

	// force a 1L rotation
	append(3);
	node = (avl_int_data_t *)tree.root;
	if (node->num != 2)
		error(1, 0, "tree not balanced 1");

	// pop the top off to force a rebalance
	node_remove(2);
	node = (avl_int_data_t *)tree.root;
	if (node->num != 3)
		error(1, 0, "tree not balanced 2");

	node_remove(1);
	append(2);
	// tree should be 3-2, then add a 1 to force a 1R rotation
	append(1);
	node = (avl_int_data_t *)tree.root;
	if (node->num != 2)
		error(1, 0, "tree not balanced 3");

	node_remove(3);
	node_remove(2);
	append(3);
	// tree should be 1-3, now force a 2L rotation
	append(2);
	node = (avl_int_data_t *)tree.root;
	if (node->num != 2)
		error(1, 0, "tree not balanced 4");

	node_remove(1);
	node_remove(2);
	append(1);
	// tree should be 3-1, now force a 2R rotation
	append(2);
	node = (avl_int_data_t *)tree.root;
	if (node->num != 2)
		error(1, 0, "tree not balanced 5");

	node_remove(1);
	node_remove(2);
	node_remove(3);
	if (tree.root != NULL)
		error(1, 0, "root not NULL when tree should be empty 1");

	// Now let's test the iterator functions
	append(2);
	append(5);
	append(1);
	append(4);
	append(3);

	int i = 1;
	avl_iterator k;
	for (node = (avl_int_data_t *)avl_first(&k, &tree); node;
	     node = (avl_int_data_t *)avl_next(&k)) {
		if (node->num != i)
			error(1, 0, "Iteration expected %d, got %d",
			      i, node->num);
		else
			printf("Iterator %d\n", node->num);
		i++;
	}

	node_remove(1);
	node_remove(2);
	node_remove(3);
	node_remove(4);
	node_remove(5);

	if (tree.root != NULL)
		error(1, 0, "root not NULL when tree should be empty 2");

	return 0;
}

