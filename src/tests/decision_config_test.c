/*
 * decision_config_test.c - decision config generation tests
 */
#include "config.h"
#include <error.h>
#include <stddef.h>

#include "decision-config.h"

#define CHECK(expr, code, msg) \
	do { \
		if (!(expr)) \
			error(1, 0, "%s", msg); \
	} while (0)

/*
 * main - verify decision config generations are immutable while pinned.
 * Returns 0 on success. Exits with error() on test failure.
 */
int main(void)
{
	conf_t config = {
		.permissive = 0,
		.integrity = IN_NONE,
	};
	const struct decision_config *pinned;
	unsigned int first_generation;
	unsigned int second_generation;

	CHECK(decision_config_generation(NULL) == 0, 1,
	      "[ERROR:1] default generation is not zero");

	CHECK(decision_config_publish(&config) == 0, 2,
	      "[ERROR:2] first publish failed");
	pinned = decision_config_pin();
	first_generation = decision_config_generation(pinned);
	CHECK(first_generation != 0, 3,
	      "[ERROR:3] first published generation is zero");
	CHECK(decision_config_permissive(pinned) == 0, 4,
	      "[ERROR:4] pinned permissive mode is wrong");
	CHECK(decision_config_integrity(pinned) == IN_NONE, 5,
	      "[ERROR:5] pinned integrity mode is wrong");
	CHECK(decision_config_rpm_sha256_only(pinned) == 0, 15,
	      "[ERROR:15] pinned rpm_sha256_only flag is wrong");

	config.permissive = 1;
	config.integrity = IN_SHA256;
	config.rpm_sha256_only = 1;
	CHECK(decision_config_publish(&config) == 0, 6,
	      "[ERROR:6] second publish failed");
	second_generation = decision_config_active_generation();
	CHECK(second_generation > first_generation, 7,
	      "[ERROR:7] generation did not advance");

	CHECK(decision_config_generation(NULL) == first_generation, 8,
	      "[ERROR:8] current generation ignored thread pin");
	CHECK(decision_config_permissive(NULL) == 0, 9,
	      "[ERROR:9] pinned permissive mode was mutated");
	CHECK(decision_config_integrity(NULL) == IN_NONE, 10,
	      "[ERROR:10] pinned integrity mode was mutated");
	CHECK(decision_config_rpm_sha256_only(NULL) == 0, 16,
	      "[ERROR:16] pinned rpm_sha256_only flag was mutated");

	decision_config_unpin(pinned);
	CHECK(decision_config_generation(NULL) == second_generation, 11,
	      "[ERROR:11] current generation did not unpin");
	CHECK(decision_config_permissive(NULL) == 1, 12,
	      "[ERROR:12] active permissive mode is wrong");
	CHECK(decision_config_integrity(NULL) == IN_SHA256, 13,
	      "[ERROR:13] active integrity mode is wrong");
	CHECK(decision_config_rpm_sha256_only(NULL) == 1, 17,
	      "[ERROR:17] active rpm_sha256_only flag is wrong");

	decision_config_destroy();
	CHECK(decision_config_generation(NULL) == 0, 14,
	      "[ERROR:14] destroy did not restore default generation");

	return 0;
}
