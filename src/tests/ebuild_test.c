#include <errno.h>
#include <fcntl.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "backend-manager.h"
#include "conf.h"
#include "message.h"

// Mock globals required by backend
atomic_bool stop = 0;
unsigned int debug_mode = 0;

// Helper to create directories
void create_dir(const char *path) {
	if (mkdir(path, 0755) != 0 && errno != EEXIST) {
	perror("mkdir");
	exit(1);
	}
}

// Helper to write file content
void write_file(const char *path, const char *content) {
	FILE *fp = fopen(path, "w");
	if (!fp) {
	perror("fopen");
	exit(1);
	}
	fprintf(fp, "%s", content);
	fclose(fp);
}

// Helper to create a dummy installed file
void create_dummy_file(const char *path) {
	FILE *fp = fopen(path, "w");
	if (!fp) {
	perror("fopen dummy");
	exit(1);
	}
	fprintf(fp,
		  "test content"); // Matches the MD5 9473fdd0d880a43c21b7778d34872157
	fclose(fp);
}

// Helper to create a package
void create_package(const char *vdb_path, const char *category,
					const char *package, const char *version,
					const char *installed_file_path) {
	char path[1024];

	// Create category dir
	snprintf(path, sizeof(path), "%s/%s", vdb_path, category);
	if (mkdir(path, 0755) != 0 && errno != EEXIST) {
	perror("mkdir category");
	exit(1);
	}

	// Create package dir
	snprintf(path, sizeof(path), "%s/%s/%s-%s", vdb_path, category, package,
			version);
	create_dir(path);

	// Create metadata
	char file_path[2048];
	snprintf(file_path, sizeof(file_path), "%s/SLOT", path);
	write_file(file_path, "0\n");

	snprintf(file_path, sizeof(file_path), "%s/repository", path);
	write_file(file_path, "gentoo\n");

	// Create CONTENTS
	snprintf(file_path, sizeof(file_path), "%s/CONTENTS", path);
	char contents[2048];
	// Using the MD5 for "test content" -> 9473fdd0d880a43c21b7778d34872157
	snprintf(contents, sizeof(contents),
		   "obj %s 9473fdd0d880a43c21b7778d34872157 1234567890\n",
		   installed_file_path);
	write_file(file_path, contents);
}

int main(void) {
	char vdb_path[] = "/tmp/fapolicyd_ebuild_test_XXXXXX";
	if (!mkdtemp(vdb_path)) {
	perror("mkdtemp");
	return 1;
	}

	printf("Using VDB path: %s\n", vdb_path);
	setenv("FAPOLICYD_VDB_PATH", vdb_path, 1);

	// Create dummy files
	char file1[] = "/tmp/fapolicyd_test_1_XXXXXX";
	char file2[] = "/tmp/fapolicyd_test_2_XXXXXX";
	char file3[] = "/tmp/fapolicyd_test_3_XXXXXX";

	int fd;
	if ((fd = mkstemp(file1)) != -1)
	close(fd);
	if ((fd = mkstemp(file2)) != -1)
	close(fd);
	if ((fd = mkstemp(file3)) != -1)
	close(fd);

	create_dummy_file(file1);
	create_dummy_file(file2);
	create_dummy_file(file3);

	// Create packages
	create_package(vdb_path, "app-test", "pkg-one", "1.0", file1);
	create_package(vdb_path, "app-test", "pkg-two", "1.0", file2);
	create_package(vdb_path, "sys-test", "pkg-three", "2.0", file3);

	// Initialize backend
	set_message_mode(MSG_STDERR, DBG_YES);
	conf_t conf;
	conf.trust = "ebuilddb";

	backend_init(&conf);
	if (backend_load(&conf)) {
	fprintf(stderr, "Failed to load backend\n");
	return 1;
	}

	backend_entry *entry = backend_get_first();
	if (!entry || !entry->backend) {
	fprintf(stderr, "No backend found\n");
	return 1;
	}

	// We expect 3 entries because we added 3 unique files
	if (entry->backend->entries != 3) {
	fprintf(stderr, "Expected 3 entries, got %ld\n", entry->backend->entries);
	return 1;
	}

	printf("Test passed!\n");

	// Cleanup
	backend_close();
	unlink(file1);
	unlink(file2);
	unlink(file3);

	char cmd[1024];
	snprintf(cmd, sizeof(cmd), "rm -rf %s", vdb_path);
	system(cmd);

	return 0;
}
