#include <stddef.h>
#include <string.h>
#include <stdatomic.h>

#include "backend-manager.h"
#include "conf.h"
#include "config.h"
#include "message.h"

#ifdef USE_RPM
unsigned int debug_mode;
#endif
atomic_bool stop;

int main(int argc, char* const argv[]) {
  set_message_mode(MSG_STDERR, DBG_YES);

  conf_t conf;
  conf.trust = "debdb";
  backend_init(&conf);
  backend_load(&conf);

  msg(LOG_INFO, "\nDone loading.");

  backend_entry* debdb_entry = backend_get_first();
  backend* debdb = NULL;
  if (debdb_entry != NULL) {
    debdb = debdb_entry->backend;
  } else {
    msg(LOG_ERR, "ERROR: No backends registered.");
  }
  if (debdb == NULL) {
    msg(LOG_ERR, "ERROR: debdb not registered");
  }
  if (strcmp(conf.trust, debdb->name) != 0) {
    msg(LOG_ERR, "ERROR: debdb bad name");
  }

  backend_close();

  return 0;
}
