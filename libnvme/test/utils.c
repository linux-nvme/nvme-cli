// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 *
 * Common test utilities.
 *
 * Copyright (c) 2022 Code Construct
 */

#include <err.h>
#include <stdlib.h>
#include <unistd.h>

#include "utils.h"

FILE *test_setup_log(void)
{
	FILE *fd;

	fd = tmpfile();
	if (!fd)
		err(EXIT_FAILURE, "can't create temporary file for log buf");

	return fd;
}

void test_close_log(FILE *fd)
{
	fclose(fd);
}

void test_print_log_buf(FILE *logfd)
{
	char buf[4096];
	int rc;

	if (!ftell(logfd))
		return;

	rewind(logfd);

	printf("--- begin test output\n");

	while (!feof(logfd) && !ferror(logfd)) {
		size_t rlen, wlen, wpos;

		rlen = fread(buf, 1, sizeof(buf), logfd);
		if (rlen <= 0)
			break;

		for (wpos = 0; wpos < rlen;) {
			wlen = fwrite(buf + wpos, 1, rlen - wpos, stdout);
			if (wlen == 0)
				break;
			wpos += wlen;
		}

		if (feof(logfd) || ferror((logfd)))
			break;
	}

	printf("--- end test output\n");
	rewind(logfd);
	rc = ftruncate(fileno(logfd), 0);
	if (rc)
		printf("failed to truncate log buf; further output may be invalid\n");
}

