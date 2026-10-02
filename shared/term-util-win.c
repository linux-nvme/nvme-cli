// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 SUSE Software Solutions
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */
#include <conio.h>
#include <errno.h>
#include <io.h>
#include <stdio.h>
#include <string.h>

#include "term-util.h"

static char pass_buf[1024];

static char *read_line(void)
{
	size_t len;

	if (!fgets(pass_buf, sizeof(pass_buf), stdin))
		return NULL;

	len = strcspn(pass_buf, "\r\n");
	pass_buf[len] = '\0';

	return pass_buf;
}

char *shr_getpass(const char *prompt)
{
	size_t len = 0;
	int c;

	fputs(prompt, stderr);
	fflush(stderr);

	if (!_isatty(_fileno(stdin)))
		return read_line();

	for (;;) {
		c = _getch();
		if (c == '\r' || c == '\n')
			break;
		if (c == 3) {
			/* Ctrl-C */
			fputc('\n', stderr);
			errno = EINTR;
			return NULL;
		}
		if (c == 0 || c == 0xe0) {
			/* function or arrow key, skip its second code */
			_getch();
			continue;
		}
		if (c == '\b') {
			if (len)
				len--;
			continue;
		}
		if (len < sizeof(pass_buf) - 1)
			pass_buf[len++] = c;
	}
	pass_buf[len] = '\0';
	fputc('\n', stderr);

	return pass_buf;
}
