#include <stdio.h>
#include <stdlib.h>
#include <error.h>
#include "avl.h"

typedef struct _avl_int_data {
	avl_t avl;
	int num;
} avl_int_data_t;

static avl_tree_t tree;
static avl_tree_t tree2;

static int intcmp_cb(void *a, void *b)
{
	return ((avl_int_data_t *)a)->num - ((avl_int_data_t *)b)->num;
}

/*
 * destroy_tree - remove all nodes from an AVL tree
 * @t: tree to empty
 */
static void destroy_tree(avl_tree_t *t)
{
	avl_t *cur;

	while ((cur = t->root) != NULL) {
		avl_int_data_t *tmp;

		tmp = (avl_int_data_t *)avl_remove(t, cur);
		free(tmp);
	}
}

int append(int num)
{
	avl_int_data_t *data = malloc(sizeof(avl_int_data_t));
	if (data == NULL)
		return 0;
	data->num = num;
	avl_t *ret = avl_insert(&tree, (avl_t *)data);
	if (ret != (avl_t *)data) {
		free(data);
		return 1;
	}
	return 0;
}

int append2(int num)
{
	avl_int_data_t *data = malloc(sizeof(avl_int_data_t));
	if (!data)
		return 0;
	data->num = num;
	avl_t *ret = avl_insert(&tree2, (avl_t *)data);
	if (ret != (avl_t *)data) {
		free(data);
		return 1;
	}
	return 0;
}

int node_remove(int num)
{
	avl_int_data_t node, *n;
	node.num = num;

	n = (avl_int_data_t *)avl_remove(&tree, (avl_t *)&node);
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

static int count_cb(void *entry, void *data)
{
	(void)entry; (void)data;
	return 1;
}

static void test_search(void)
{
	avl_int_data_t *res;
	avl_int_data_t tmp;
	avl_init(&tree, intcmp_cb);

	append(10);
	append(20);
	append(15);

	tmp.num = 20;
	res = (avl_int_data_t *)avl_search(&tree, (avl_t *)&tmp);
	if (!res || res->num != 20)
		error(1, 0, "avl_search failed to find 20");

	tmp.num = 99;
	res = (avl_int_data_t *)avl_search(&tree, (avl_t *)&tmp);
	if (res)
		error(1, 0, "avl_search incorrectly found 99");

	destroy_tree(&tree);
}

static void test_duplicates(void)
{
	int ret;
	avl_init(&tree, intcmp_cb);

	ret = append(5);
	if (ret != 0)
		error(1, 0, "append(5) failed");
	ret = append(5);
	if (ret != 1)
		error(1, 0, "append(5) duplicate not detected");

	int count = avl_traverse(&tree, count_cb, NULL);
	if (count != 1)
		error(1, 0, "duplicate insert created %d nodes (expected 1)", count);

	destroy_tree(&tree);
}

static void test_traverse_count(void)
{
	avl_init(&tree, intcmp_cb);
	append(1); append(2); append(3); append(4); append(5);

	int count = avl_traverse(&tree, count_cb, NULL);
	if (count != 5)
		error(1, 0, "avl_traverse returned %d (expected 5)", count);

	destroy_tree(&tree);
}

static void test_intersection(void)
{
	avl_init(&tree,  intcmp_cb);
	avl_init(&tree2, intcmp_cb);

	append(1); append(2); append(3);

	append2(3); append2(4); append2(5);

	if (!avl_intersection(&tree, &tree2))
		error(1, 0, "avl_intersection failed to detect common element");

	destroy_tree(&tree2);
	avl_init(&tree2, intcmp_cb);
	if (avl_intersection(&tree, &tree2))
		error(1, 0, "avl_intersection false positive on empty second tree");

	destroy_tree(&tree);
	if (avl_intersection(&tree, &tree2))
		error(1, 0, "avl_intersection false positive on two empty trees");

	destroy_tree(&tree2);
}

static void test_iterator_null(void)
{
	avl_init(&tree, intcmp_cb);

	if (avl_first(NULL, &tree) != NULL)
		error(1, 0, "avl_first(NULL,…) should return NULL");

	if (avl_next(NULL) != NULL)
		error(1, 0, "avl_next(NULL) should return NULL");

	destroy_tree(&tree);
}

/* https://stackoverflow.com/questions/3955680/how-to-check-if-my-avl-tree-implementation-is-correct */
int main(void)
{
	avl_int_data_t *node;
	int i;
	avl_iterator k;

	avl_init(&tree, intcmp_cb);

	append(2);
	append(1);

	/* force a 1L rotation */
	append(3);
	node = (avl_int_data_t *)tree.root;
	if (node->num != 2)
		error(1, 0, "tree not balanced 1");

	/* pop the top off to force a rebalance */
	node_remove(2);
	node = (avl_int_data_t *)tree.root;
	if (node->num != 3)
		error(1, 0, "tree not balanced 2");

	node_remove(1);
	append(2);
	/* tree should be 3-2, then add a 1 to force a 1R rotation */
	append(1);
	node = (avl_int_data_t *)tree.root;
	if (node->num != 2)
		error(1, 0, "tree not balanced 3");

	node_remove(3);
	node_remove(2);
	append(3);
	/* tree should be 1-3, now force a 2L rotation */
	append(2);
	node = (avl_int_data_t *)tree.root;
	if (node->num != 2)
		error(1, 0, "tree not balanced 4");

	node_remove(1);
	node_remove(2);
	append(1);
	/* tree should be 3-1, now force a 2R rotation */
	append(2);
	node = (avl_int_data_t *)tree.root;
	if (node->num != 2)
		error(1, 0, "tree not balanced 5");

	node_remove(1);
	node_remove(2);
	node_remove(3);
	if (tree.root != NULL)
		error(1, 0, "root not NULL when tree should be empty 1");

	/* Now let's test the iterator functions */
	append(2);
	append(5);
	append(1);
	append(4);
	append(3);

	i = 1;
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

	test_search();
	test_duplicates();
	test_traverse_count();
	test_intersection();
	test_iterator_null();

	destroy_tree(&tree);
	destroy_tree(&tree2);

	return 0;
}

