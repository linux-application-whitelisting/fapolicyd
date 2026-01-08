/*
 * test-stubs.c - provide globals needed by libfapolicyd for unit tests
 *
 * This file supplies minimal definitions of globals referenced by the
 * library so that standalone tests can link without pulling in the daemon
 * or CLI entry points.
 */

#include <stdatomic.h>

#include "conf.h"

atomic_bool stop;
unsigned int debug_mode;
conf_t config;
