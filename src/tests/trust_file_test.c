/* Verify that failed trust additions leave an existing fragment intact. */
#include "config.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "llist.h"
#include "message.h"
#include "trust-file.h"

/*
 * add_path - prepare one path as the CLI does before calling append.
 * @list: destination list.
 * @path: filesystem path to add.
 * Returns 0 on success, 1 on allocation failure.
 */
static int add_path(list_t *list, const char *path)
{
	char *copy = strdup(path);

	if (copy == NULL)
		return 1;
	if (list_append(list, copy, NULL)) {
		free(copy);
		return 1;
	}
	return 0;
}

int main(void)
{
	char directory[] = "/tmp/fapolicyd-trust-file-XXXXXX";
	char fragment[256], input[256], contents[32];
	struct stat st, original;
	list_t pending, loaded;
	FILE *f;
	int rc = 1;

	set_message_mode(MSG_STDERR, DBG_NO);
	if (mkdtemp(directory) == NULL)
		return 1;
	if (snprintf(fragment, sizeof(fragment), "%s/trust", directory) >=
	    (int)sizeof(fragment) ||
	    snprintf(input, sizeof(input), "%s/input", directory) >=
	    (int)sizeof(input))
		goto out;
	f = fopen(fragment, "w");
	if (f == NULL)
		goto out;
	int failed = fputs("# retained\n", f) == EOF;
	if (fclose(f) == EOF || failed)
		goto out;
	if (chmod(fragment, 0640) < 0)
		goto out;
	if (stat(fragment, &original) < 0)
		goto out;

	list_init(&pending);
	if (add_path(&pending, input))
		goto clear_pending;
	/* The CLI can find a file and then lose it before hashing it. */
	if (trust_file_append(fragment, &pending) != 1)
		goto clear_pending;
	list_empty(&pending);
	f = fopen(fragment, "r");
	if (f == NULL)
		goto out;
	failed = fgets(contents, sizeof(contents), f) == NULL ||
		strcmp(contents, "# retained\n") != 0;
	if (fclose(f) == EOF || failed)
		goto out;

	f = fopen(input, "w");
	if (f == NULL)
		goto out;
	failed = fputs("payload\n", f) == EOF;
	if (fclose(f) == EOF || failed)
		goto out;
	list_init(&pending);
	if (add_path(&pending, input))
		goto clear_pending;
	if (trust_file_append(fragment, &pending) != 0)
		goto clear_pending;
	list_empty(&pending);
	if (stat(fragment, &st) < 0 || (st.st_mode & 0777) != 0640 ||
	    st.st_uid != original.st_uid || st.st_gid != original.st_gid)
		goto out;
	list_init(&loaded);
	if (trust_file_load(fragment, &loaded, -1) != 0 ||
	    loaded.count != 1 || strcmp(loaded.first->index, input) != 0) {
		list_empty(&loaded);
		goto out;
	}
	list_empty(&loaded);
	if (unlink(fragment) < 0)
		goto out;
	list_init(&pending);
	if (add_path(&pending, input))
		goto clear_pending;
	if (trust_file_append(fragment, &pending) != 0)
		goto clear_pending;
	list_empty(&pending);
	if (stat(fragment, &st) < 0 || (st.st_mode & 0777) != 0644)
		goto out;
	rc = 0;
	goto out;

clear_pending:
	list_empty(&pending);
out:
	unlink(input);
	unlink(fragment);
	rmdir(directory);
	if (rc)
		fprintf(stderr, "trust_file_append preservation test failed: %s\n",
			strerror(errno));
	return rc;
}
