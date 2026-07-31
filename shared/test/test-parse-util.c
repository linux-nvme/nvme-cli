// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include <parse-util.h>

static bool check_bool(const char *value, int want_ret, bool want_out)
{
	bool out = false;
	int ret;

	ret = shr_parse_bool(value, &out);
	if (ret != want_ret || (!ret && out != want_out)) {
		printf(" - \"%s\": got ret=%d out=%d, want ret=%d out=%d [FAIL]\n",
		       value, ret, out, want_ret, want_out);
		return false;
	}

	printf(" - \"%s\" [PASS]\n", value);
	return true;
}

static bool test_accepted_spellings(void)
{
	bool pass = true;

	printf("test_accepted_spellings:\n");

	pass &= check_bool("1", 0, true);
	pass &= check_bool("yes", 0, true);
	pass &= check_bool("y", 0, true);
	pass &= check_bool("true", 0, true);
	pass &= check_bool("t", 0, true);
	pass &= check_bool("on", 0, true);

	pass &= check_bool("0", 0, false);
	pass &= check_bool("no", 0, false);
	pass &= check_bool("n", 0, false);
	pass &= check_bool("false", 0, false);
	pass &= check_bool("f", 0, false);
	pass &= check_bool("off", 0, false);

	return pass;
}

static bool test_case_insensitive(void)
{
	bool pass = true;

	printf("test_case_insensitive:\n");

	pass &= check_bool("YES", 0, true);
	pass &= check_bool("True", 0, true);
	pass &= check_bool("ON", 0, true);
	pass &= check_bool("NO", 0, false);
	pass &= check_bool("False", 0, false);
	pass &= check_bool("OFF", 0, false);

	return pass;
}

static bool test_rejected(void)
{
	bool pass = true;

	printf("test_rejected:\n");

	pass &= check_bool("maybe", -EINVAL, false);
	pass &= check_bool("", -EINVAL, false);
	pass &= check_bool("2", -EINVAL, false);
	pass &= check_bool("yesplease", -EINVAL, false);

	return pass;
}

int main(void)
{
	bool pass = true;

	pass &= test_accepted_spellings();
	pass &= test_case_insensitive();
	pass &= test_rejected();

	fflush(stdout);
	exit(pass ? EXIT_SUCCESS : EXIT_FAILURE);
}
