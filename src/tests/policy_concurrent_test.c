/*
 * policy_concurrent_test.c - verify concurrent policy reads are local
 *
 * The test publishes one immutable policy snapshot, then evaluates the same
 * late-matching rule from several threads.  The daemon still serializes
 * decisions today, but read-side rule iteration must not depend on the
 * mutable llist cursor before worker threads can be introduced.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <error.h>
#include <pthread.h>
#include <sched.h>
#include <stdbool.h>
#include <stdatomic.h>

#include "conf.h"
#include "policy.h"
#include "subject.h"
#include "object.h"
#include "event.h"
#include "message.h"

#define WORKER_COUNT		32
#define ITERATIONS		1000
#define NO_OPINION_RULES	64
#define POLICY_BUFSIZE		8192
#define TARGET_AUID		4242
#define TARGET_PATH		"/tmp/fapolicyd-concurrent-target"

extern atomic_bool stop;

static atomic_bool start_workers;
static atomic_uint failures;

/*
 * make_policy_text - build a policy with a late matching deny rule
 * @buf: destination buffer for newline-separated rules.
 * @buflen: size of @buf.
 * Returns nothing. Exits on overflow because the test fixture is invalid.
 */
static void make_policy_text(char *buf, size_t buflen)
{
	size_t off = 0;
	int len;
	unsigned int i;

	for (i = 0; i < NO_OPINION_RULES; i++) {
		len = snprintf(buf + off, buflen - off,
			       "allow perm=any auid=%u : path=/no/match/%u\n",
			       i, i);
		if (len < 0 || (size_t)len >= buflen - off)
			error(1, 0, "policy buffer overflow");
		off += (size_t)len;
	}

	len = snprintf(buf + off, buflen - off,
		       "deny perm=any auid=%u : path=%s\n",
		       TARGET_AUID, TARGET_PATH);
	if (len < 0 || (size_t)len >= buflen - off)
		error(1, 0, "policy buffer overflow");
}

/*
 * load_test_policy - publish the policy used by reader threads
 * @void: no arguments are required.
 * Returns nothing. Exits if policy loading fails.
 */
static void load_test_policy(void)
{
	conf_t cfg = { .syslog_format = "rule,dec,perm,:,path" };
	char policy[POLICY_BUFSIZE];
	FILE *f;
	int rc;

	make_policy_text(policy, sizeof(policy));
	f = fmemopen(policy, strlen(policy), "r");
	if (!f)
		error(1, errno, "fmemopen failed");

	rc = load_rules_from_stream(&cfg, f);
	fclose(f);
	if (rc)
		error(1, 0, "policy load failed");
}

/*
 * prep_event - allocate and populate an event for policy evaluation
 * @e: event to initialize.
 * Returns nothing. Exits on allocation failure.
 */
static void prep_event(event_t *e)
{
	subject_attr_t sattr = { .type = AUID, .uval = TARGET_AUID };
	object_attr_t oattr = { .type = PATH, .o = strdup(TARGET_PATH) };

	memset(e, 0, sizeof(*e));
	e->type = FAN_OPEN_PERM;
	e->s = malloc(sizeof(s_array));
	e->o = malloc(sizeof(o_array));
	if (!e->s || !e->o || !oattr.o)
		error(1, errno, "event allocation failed");

	subject_create(e->s);
	object_create(e->o);

	e->s->info = calloc(1, sizeof(struct proc_info));
	if (!e->s->info)
		error(1, errno, "proc_info allocation failed");

	if (subject_add(e->s, &sattr))
		error(1, 0, "subject_add failed");
	if (object_add(e->o, &oattr))
		error(1, 0, "object_add failed");
}

/*
 * free_event - release memory allocated by prep_event()
 * @e: event to clear.
 * Returns nothing.
 */
static void free_event(event_t *e)
{
	subject_clear(e->s);
	object_clear(e->o);
	free(e->s);
	free(e->o);
}

/*
 * reader_thread - repeatedly evaluate the active policy snapshot
 * @arg: unused pthread argument.
 * Return: NULL.
 */
static void *reader_thread(void *arg)
{
	unsigned int i;

	(void)arg;

	while (!atomic_load_explicit(&start_workers, memory_order_acquire))
		sched_yield();

	for (i = 0; i < ITERATIONS; i++) {
		event_t e;
		decision_t decision;

		prep_event(&e);
		decision = process_event(&e);
		if (decision != DENY || e.num != NO_OPINION_RULES + 1)
			atomic_fetch_add_explicit(&failures, 1,
						  memory_order_relaxed);
		free_event(&e);
	}

	return NULL;
}

/*
 * main - exercise concurrent read-only rule evaluation
 * @void: no arguments are required.
 * Returns 0 on success. Exits with error() on test failure.
 */
int main(void)
{
	pthread_t workers[WORKER_COUNT];
	unsigned int i;
	unsigned int failed;
	int rc;

	set_message_mode(MSG_STDERR, DBG_NO);
	load_test_policy();

	for (i = 0; i < WORKER_COUNT; i++) {
		rc = pthread_create(&workers[i], NULL, reader_thread, NULL);
		if (rc)
			error(1, rc, "pthread_create failed");
	}

	atomic_store_explicit(&start_workers, true, memory_order_release);

	for (i = 0; i < WORKER_COUNT; i++) {
		rc = pthread_join(workers[i], NULL);
		if (rc)
			error(1, rc, "pthread_join failed");
	}

	failed = atomic_load_explicit(&failures, memory_order_relaxed);
	if (failed)
		error(1, 0, "%u concurrent decisions failed", failed);

	atomic_store(&stop, true);
	destroy_rules();
	return 0;
}
