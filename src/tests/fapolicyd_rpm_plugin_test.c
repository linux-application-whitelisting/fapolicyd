/* fapolicyd_rpm_plugin_test.c - RPM plugin migration regression tests */

#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../plugin/fapolicyd-rpm-plugin.c"

/* Create a mode-correct FIFO and hold its read side open. */
static int create_fifo_reader(const char *path)
{
	int fd;

	if (mkfifo(path, 0660))
		error(1, errno, "mkfifo %s", path);
	if (chmod(path, 0660))
		error(1, errno, "chmod %s", path);
	fd = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
	if (fd < 0)
		error(1, errno, "open reader %s", path);
	return fd;
}

/* Verify that the new endpoint is preferred and the legacy one is fallback. */
static void test_endpoint_selection(void)
{
	char tmpdir[] = "/tmp/fapolicyd-rpm-plugin-XXXXXX";
	char primary[256];
	char legacy[256];
	struct fapolicyd_data state = {
		.fd = -1,
		.primary_fifo_path = primary,
		.legacy_fifo_path = legacy,
	};
	int primary_reader = -1;
	int legacy_reader = -1;

	if (mkdtemp(tmpdir) == NULL)
		error(1, errno, "mkdtemp");
	snprintf(primary, sizeof(primary), "%s/current.fifo", tmpdir);
	snprintf(legacy, sizeof(legacy), "%s/legacy.fifo", tmpdir);

	legacy_reader = create_fifo_reader(legacy);
	if (connect_fifo(&state) || state.fd < 0 ||
	    strcmp(state.connected_path, legacy))
		error(1, 0, "legacy endpoint was not used as fallback");
	close_fifo(&state);

	primary_reader = create_fifo_reader(primary);
	if (connect_fifo(&state) || state.fd < 0 ||
	    strcmp(state.connected_path, primary))
		error(1, 0, "current endpoint was not preferred");
	close_fifo(&state);

	/* A present current endpoint must never activate the legacy plugin. */
	close(primary_reader);
	primary_reader = -1;
	if (connect_fifo(&state) != ENXIO || state.fd >= 0)
		error(1, 0, "legacy endpoint used while current endpoint exists");

	close(legacy_reader);
	unlink(primary);
	unlink(legacy);
	rmdir(tmpdir);
}

/* Verify that a full nonblocking FIFO fails instead of busy looping. */
static void test_full_fifo(void)
{
	struct fapolicyd_data state = {
		.fd = -1,
		.connected_path = "test pipe",
	};
	char data[4096] = { 0 };
	int pipefd[2];
	ssize_t n;

	if (pipe(pipefd))
		error(1, errno, "pipe");
	if (fcntl(pipefd[1], F_SETFL, O_NONBLOCK))
		error(1, errno, "fcntl");

	state.fd = pipefd[1];
	do {
		n = write(state.fd, data, sizeof(data));
	} while (n >= 0);
	if (errno != EAGAIN)
		error(1, errno, "filling nonblocking pipe");

	alarm(2);
	if (write_fifo(&state, "x") != RPMRC_FAIL)
		error(1, 0, "full FIFO write unexpectedly succeeded");
	alarm(0);
	close(pipefd[0]);
	close(pipefd[1]);
}

int main(void)
{
	test_endpoint_selection();
	test_full_fifo();
	return EXIT_SUCCESS;
}
