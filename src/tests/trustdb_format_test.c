// Copyright 2024 Red Hat
// SPDX-License-Identifier: GPL-2.0-or-later

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include "fapolicyd-backend.h"

int main(void)
{
	const char *digest =
	"68879112e7d8a66c61178c409b07d1233270bcf2375d2ea029ca68f3552846563426b625f946c478c37b910373c44a0b89c08b9897885e9b135b11a6db604550";
	char data[TRUSTDB_DATA_BUFSZ];
	char parsed_digest[FILE_DIGEST_STRING_MAX];
	unsigned int tsource;
	off_t size;
	int written;

	written = snprintf(data, sizeof(data), DATA_FORMAT, SRC_RPM, (off_t)9400,
			 digest);
	if (written < 0 || written >= (int)sizeof(data))
		return 1;

	if (sscanf(data, DATA_FORMAT, &tsource, &size, parsed_digest) != 3)
		return 1;

	if (strcmp(digest, parsed_digest))
		return 1;

	return 0;
}
