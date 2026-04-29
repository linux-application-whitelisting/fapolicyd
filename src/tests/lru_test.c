#include <error.h>
#include <stdlib.h>
#include "lru.h"

static unsigned int cleaned;

static void cleanup_item(void *item)
{
	if (item)
		cleaned++;
}

static void attach_item(QNode *node, int value)
{
	int *data;

	data = malloc(sizeof(int));
	if (data == NULL)
		error(1, 0, "malloc failed");
	*data = value;
	node->item = data;
}

static void test_reuse_after_evict(void)
{
	Queue *queue;
	QNode *first;
	QNode *second;

	cleaned = 0;
	queue = init_lru(3, cleanup_item, "reuse", NULL);
	if (queue == NULL)
		error(1, 0, "init_lru failed");

	first = check_lru_cache(queue, 0);
	if (first == NULL)
		error(1, 0, "check_lru_cache returned NULL");
	attach_item(first, 1);

	lru_evict(queue, 0);
	if (cleaned != 1)
		error(1, 0, "cleanup count %u does not match expected 1", cleaned);

	second = check_lru_cache(queue, 0);
	if (second != first)
		error(1, 0, "QNode was not reused after eviction");
	if (second->uses != 1)
		error(1, 0, "QNode uses was not reset on reuse");

	attach_item(second, 2);
	destroy_lru(queue);
}

static void test_pool_exhaustion(void)
{
	Queue *queue;
	QNode *first;
	QNode *second;
	QNode *reused;

	cleaned = 0;
	queue = init_lru(2, cleanup_item, "exhaust", NULL);
	if (queue == NULL)
		error(1, 0, "init_lru failed");

	first = check_lru_cache(queue, 0);
	if (first == NULL)
		error(1, 0, "check_lru_cache returned NULL for key 0");
	attach_item(first, 10);

	second = check_lru_cache(queue, 1);
	if (second == NULL)
		error(1, 0, "check_lru_cache returned NULL for key 1");
	attach_item(second, 20);

	if (queue->free_list != NULL)
		error(1, 0, "free list not empty after filling cache");

	lru_evict(queue, 1);
	if (cleaned != 1)
		error(1, 0, "cleanup count %u does not match expected 1", cleaned);

	reused = check_lru_cache(queue, 1);
	if (reused != second)
		error(1, 0, "QNode not reused after pool exhaustion");
	if (queue->count != 2)
		error(1, 0, "queue count incorrect after reuse");

	attach_item(reused, 30);
	destroy_lru(queue);
}

/*
 * test_metrics_reset - verify reset snapshots preserve cache occupancy.
 */
static void test_metrics_reset(void)
{
	struct lru_metrics metrics;
	Queue *queue;
	QNode *first;

	queue = init_lru(1, cleanup_item, "metrics", NULL);
	if (queue == NULL)
		error(1, 0, "init_lru failed");

	first = check_lru_cache(queue, 0);
	if (first == NULL)
		error(1, 0, "check_lru_cache returned NULL");
	attach_item(first, 40);
	check_lru_cache(queue, 0);

	lru_metrics_snapshot(queue, &metrics, 1);
	if (metrics.count != 1 || metrics.total != 1)
		error(1, 0, "metrics reset changed cache state");
	if (metrics.hits != 1 || metrics.misses != 1)
		error(1, 0, "metrics reset snapshot lost cache counters");

	lru_metrics_snapshot(queue, &metrics, 0);
	if (metrics.count != 1 || metrics.hits != 0 || metrics.misses != 0)
		error(1, 0, "metrics reset did not clear counters only");

	destroy_lru(queue);
}

int main(void)
{
	test_reuse_after_evict();
	test_pool_exhaustion();
	test_metrics_reset();
	return 0;
}
