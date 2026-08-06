// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 SUSE Software Solutions
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include <sig-util.h>

static bool check_bool(const char *name, bool got)
{
	printf(" - %s [%s]\n", name, got ? "PASS" : "FAIL");
	return got;
}

static bool test_sigint(void)
{
	bool pass = true;
	int ret;

	printf("test_sigint:\n");

	ret = shr_install_sigint_handler();
	pass &= check_bool("handler installs successfully", ret == 0);
	pass &= check_bool("flag starts clear", !shr_sigint_received);

	raise(SIGINT);
	pass &= check_bool("flag set after SIGINT is raised", shr_sigint_received);

	signal(SIGINT, SIG_DFL);

	return pass;
}

static bool test_sigwinch(void)
{
	bool pass = true;
	int ret;

	printf("test_sigwinch:\n");

	ret = shr_install_sigwinch_handler();
	pass &= check_bool("handler installs successfully", ret == 0);
	pass &= check_bool("flag starts clear", !shr_sigwinch_received);

	raise(SIGWINCH);
	pass &= check_bool("flag set after SIGWINCH is raised", shr_sigwinch_received);

	signal(SIGWINCH, SIG_DFL);

	return pass;
}

int main(void)
{
	bool pass = true;

	pass &= test_sigint();
	pass &= test_sigwinch();

	fflush(stdout);
	exit(pass ? EXIT_SUCCESS : EXIT_FAILURE);
}
