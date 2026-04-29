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
atomic_bool run_stats;
atomic_uint signal_report_requests;
atomic_uint signal_report_reset_requests;
atomic_int signal_report_reset_request_pid;
atomic_int signal_report_reset_request_uid;
unsigned int debug_mode;
conf_t config;
