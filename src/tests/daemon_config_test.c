/*
 * daemon_config_test.c - daemon configuration validation tests
 */
#include "config.h"
#include <error.h>
#include <stddef.h>

#include "daemon-config.h"

#define CHECK(expr, code, msg) \
	do { \
		if (!(expr)) \
			error(1, 0, "%s", msg); \
	} while (0)

/*
 * minimal_config - build a small valid config for resource validation.
 * @cfg: destination config to initialize.
 *
 * Returns nothing.
 */
static void minimal_config(conf_t *cfg)
{
	cfg->q_size = 1;
	cfg->decision_threads = 1;
	cfg->subj_cache_size = 16;
	cfg->obj_cache_size = 16;
}

/*
 * main - verify decision_threads bounds and LMDB reader sizing.
 * Returns 0 on success. Exits with error() on test failure.
 */
int main(void)
{
	conf_t cfg = { 0 };

	CHECK(daemon_config_lmdb_reader_limit(NULL) ==
	      1 + DAEMON_CONFIG_LMDB_MAINTENANCE_READERS, 1,
	      "[ERROR:1] default LMDB reader limit is wrong");
	CHECK(daemon_config_lmdb_reader_limit(&cfg) ==
	      1 + DAEMON_CONFIG_LMDB_MAINTENANCE_READERS, 2,
	      "[ERROR:2] zeroed config LMDB reader limit is wrong");

	minimal_config(&cfg);
	CHECK(validate_daemon_config(&cfg) == 0, 3,
	      "[ERROR:3] minimal valid config was rejected");

	cfg.decision_threads = 0;
	CHECK(validate_daemon_config(&cfg) != 0, 4,
	      "[ERROR:4] zero decision_threads was accepted");

	minimal_config(&cfg);
	cfg.decision_threads = DAEMON_CONFIG_DECISION_THREADS_MAX + 1;
	CHECK(validate_daemon_config(&cfg) != 0, 5,
	      "[ERROR:5] oversized decision_threads was accepted");
	CHECK(daemon_config_lmdb_reader_limit(&cfg) == 0, 6,
	      "[ERROR:6] oversized LMDB reader limit was accepted");

	cfg.decision_threads = DAEMON_CONFIG_DECISION_THREADS_MAX;
	CHECK(daemon_config_lmdb_reader_limit(&cfg) ==
	      DAEMON_CONFIG_LMDB_MAX_READERS, 7,
	      "[ERROR:7] max LMDB reader limit is wrong");

	return 0;
}
