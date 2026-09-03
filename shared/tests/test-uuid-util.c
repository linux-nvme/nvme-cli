// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of nvme-cli.
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <shared/uuid-util.h>

static bool check_str(const char *name, const char *got, const char *want)
{
	bool eq = got && !strcmp(got, want);

	if (eq) {
		printf(" - %s [PASS]\n", name);
		return true;
	}

	printf(" - %s: got \"%s\", want \"%s\" [FAIL]\n", name, got ? got : "(null)", want);
	return false;
}

static bool test_uuid_to_string(void)
{
	bool pass = true;
	unsigned char uuid[SHR_UUID_LEN] = {
		0x1b, 0x4e, 0x28, 0xba, 0x2f, 0xa1, 0x11, 0xd2,
		0x88, 0x3f, 0x00, 0x16, 0xd3, 0xcc, 0xa4, 0x27,
	};

	printf("test_uuid_to_string:\n");

	pass &= check_str("canonical uuid", shr_uuid_to_string(uuid),
			   "1b4e28ba-2fa1-11d2-883f-0016d3cca427");

	return pass;
}

static bool check_valid(const char *str, bool want)
{
	bool got = shr_uuid_str_valid(str);

	if (got == want) {
		printf(" - \"%s\" [PASS]\n", str ? str : "(null)");
		return true;
	}

	printf(" - \"%s\": got %s, want %s [FAIL]\n", str ? str : "(null)",
	       got ? "valid" : "invalid", want ? "valid" : "invalid");
	return false;
}

static bool test_uuid_str_valid(void)
{
	bool pass = true;

	printf("test_uuid_str_valid:\n");

	pass &= check_valid(NULL, false);
	pass &= check_valid("", false);
	pass &= check_valid("1b4e28ba-2fa1-11d2-883f-0016d3cca427", true);
	pass &= check_valid("1B4E28BA-2FA1-11D2-883F-0016D3CCA427", true);
	pass &= check_valid("1b4e28ba2fa111d2883f0016d3cca427", false);
	pass &= check_valid("1b4e28ba-2fa1-11d2-883f-0016d3cca42", false);
	pass &= check_valid("1b4e28ba-2fa1-11d2-883f-0016d3cca4277", false);
	pass &= check_valid("1b4e28ba-2fa1-11d2-883f-0016d3cca42g", false);
	pass &= check_valid("1b4e28ba:2fa1-11d2-883f-0016d3cca427", false);

	return pass;
}

static bool test_fw_to_string(void)
{
	bool pass = true;
	char printable[8] = "1B2C3D4E";
	char with_junk[8] = { 0x00, 0x20, 0x21, 0x7e, 0x7f, (char)0xff, 'X', 'Y' };

	printf("test_fw_to_string:\n");

	pass &= check_str("printable revision", shr_fw_to_string(printable), "1B2C3D4E");
	pass &= check_str("non-printable replaced with '.'", shr_fw_to_string(with_junk),
			   "..!~..XY");

	return pass;
}

int main(void)
{
	bool pass = true;

	pass &= test_uuid_to_string();
	pass &= test_uuid_str_valid();
	pass &= test_fw_to_string();

	fflush(stdout);
	exit(pass ? EXIT_SUCCESS : EXIT_FAILURE);
}
