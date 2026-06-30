/*
 * rpm_backend_test.c - verify rpm backend loader failure handling
 */

#include "config.h"

#include <error.h>
#include <stdatomic.h>
#include <string.h>
#include <unistd.h>

#include "fapolicyd-backend.h"

extern backend rpm_backend;
extern atomic_int rpm_loader_pid;

#define CHECK(expr, code, msg) \
	do { \
		if (!(expr)) \
			error(code, 0, "%s", msg); \
	} while (0)

/*
 * true_path - find a harmless helper that exits without sending an fd.
 * Returns an executable path, or NULL when none is available.
 */
static const char *true_path(void)
{
	if (access("/bin/true", X_OK) == 0)
		return "/bin/true";
	if (access("/usr/bin/true", X_OK) == 0)
		return "/usr/bin/true";
	return NULL;
}

/*
 * main - run rpm loader IPC failure coverage.
 * Returns 0 on success. Exits with error() on test failure.
 */
int main(void)
{
	const char *path = true_path();
	conf_t cfg;
	int rc;

	if (path == NULL)
		return 77;

	memset(&cfg, 0, sizeof(cfg));
	rpm_backend.memfd = -1;
	rpm_backend.entries = -1;

	CHECK(atomic_load(&rpm_loader_pid) == -1, 10,
	      "[ERROR:10] rpm_loader_pid not -1 before load");

	rc = rpm_backend_load_from_path_for_tests(&cfg, path);
	CHECK(rc != 0, 1, "[ERROR:1] rpm IPC failure returned success");
	CHECK(rpm_backend.memfd == -1, 2,
	      "[ERROR:2] failed rpm load published a memfd");
	CHECK(rpm_backend.entries == -1, 3,
	      "[ERROR:3] failed rpm load published entries");
	CHECK(atomic_load(&rpm_loader_pid) == -1, 4,
	      "[ERROR:4] rpm_loader_pid not cleared after failed load");

	return 0;
}
