/* Exercise the production directory walk against private trust fragments. */
#include "config.h"
#include "paths.h"
#include "trust-file.h"
#undef TRUST_FILE_PATH
#undef TRUST_DIR_PATH
#define TRUST_FILE_PATH "primary"
#define TRUST_DIR_PATH "fragments/"
#include "../library/trust-file.c"

/* Write the given fixture text and report any I/O error. */
static int write_fixture(const char *file, const char *text)
{
	FILE *f = fopen(file, "w");
	if (!f)
		return -1;
	int failed = fputs(text, f) == EOF;
	return fclose(f) || failed ? -1 : 0;
}

int main(void)
{
	char directory[] = "/tmp/fapolicyd-walk-XXXXXX";
	const char digest[] =
		"0000000000000000000000000000000000000000000000000000000000000000";
	char records[256];
	char updated_prefix[32];
	list_t list;
	int rc = 1;

	if (!mkdtemp(directory) || chdir(directory) || mkdir("fragments", 0700))
		return 1;
	snprintf(records, sizeof(records), "item1 0 %s\nitem2 0 %s\n",
		 digest, digest);
	/* Reloading the file tags each measured one-byte entry as SRC_FILE_DB. */
	snprintf(updated_prefix, sizeof(updated_prefix), "%u 1 ",
		 (unsigned int)SRC_FILE_DB);
	if (write_fixture("item1", "a") || write_fixture("item2", "b") ||
	    write_fixture("primary", records) ||
	    write_fixture("fragments/bad", "malformed\n"))
		goto out;

	/* Two primary edits must not hide the subsequent callback error. */
	if (trust_file_update_path_all("item", false) >= 0)
		goto out;
	list_init(&list);
	if (trust_file_load("primary", &list, -1) || list.count != 2 ||
	    strncmp(list.first->data, updated_prefix, strlen(updated_prefix)) ||
	    strncmp(list.last->data, updated_prefix, strlen(updated_prefix))) {
		list_empty(&list);
		goto out;
	}
	list_empty(&list);
	if (trust_file_delete_path_all("item") >= 0)
		goto out;
	if (!trust_file_load("primary", &list, -1) && !list.count)
		rc = 0;
	list_empty(&list);
out:
	unlink("fragments/bad");
	unlink("primary");
	unlink("item1");
	unlink("item2");
	rmdir("fragments");
	rmdir(directory);
	if (rc)
		fprintf(stderr, "bulk trust edits lost a fragment error\n");
	return rc;
}
