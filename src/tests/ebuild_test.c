#include <stdio.h>              // for NULL
#include <string.h>             // for strcmp
#include <syslog.h>             // for LOG_ERR, LOG_INFO
#include "backend-manager.h"    // for backend_close, backend_get_first, bac...
#include "conf.h"               // for conf_t
#include "fapolicyd-backend.h"  // for backend
#include "message.h"            // for msg, set_message_mode, DBG_YES, MSG_S...

int main(int argc, char* const argv[]) {
	set_message_mode(MSG_STDERR, DBG_YES);

	conf_t conf;
	conf.trust = "ebuilddb";
	backend_init(&conf);
	backend_load(&conf);

	msg(LOG_INFO, "Done loading.");

	backend_entry* ebuilddb_entry = backend_get_first();
	backend* ebuilddb = NULL;
	if (ebuilddb_entry != NULL) {
		ebuilddb = ebuilddb_entry->backend;
	} else {
		msg(LOG_ERR, "ERROR: No backends registered.");
	}
	if (ebuilddb == NULL) {
		msg(LOG_ERR, "ERROR: ebuilddb not registered");
	}
	if (strcmp(conf.trust, ebuilddb->name) != 0) {
		msg(LOG_ERR, "ERROR: ebuilddb bad name");
	}

	backend_close();

	return 0;
}
