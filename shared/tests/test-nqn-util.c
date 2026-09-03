// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of nvme-cli.
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <shared/nqn-util.h>

#define UUID_NQN "nqn.2014-08.org.nvmexpress:uuid:"

static bool check(const char *nqn, bool want)
{
	bool got = shr_nqn_valid(nqn);

	if (got == want) {
		printf(" - \"%s\" [PASS]\n", nqn ? nqn : "(null)");
		return true;
	}

	printf(" - \"%s\": got %s, want %s [FAIL]\n", nqn ? nqn : "(null)",
	       got ? "valid" : "invalid", want ? "valid" : "invalid");
	return false;
}

static bool test_nqn_valid(void)
{
	char too_long[SHR_NQN_MAX_LEN + 8];
	bool pass = true;

	printf("test_nqn_valid:\n");

	pass &= check(NULL, false);
	pass &= check("", false);
	pass &= check("nqn.", false);

	/* UUID format */
	pass &= check(UUID_NQN "f81d4fae-7dec-11d0-a765-00a0c91e6bf6", true);
	pass &= check(UUID_NQN "F81D4FAE-7DEC-11D0-A765-00A0C91E6BF6", true);
	pass &= check(UUID_NQN "abc-123", false);
	pass &= check(UUID_NQN "f81d4fae7dec11d0a76500a0c91e6bf6", false);
	pass &= check(UUID_NQN "f81d4fae-7dec-11d0-a765-00a0c91e6bfg", false);
	pass &= check(UUID_NQN, false);

	/* Domain format */
	pass &= check("nqn.2014-08.com.example:nvme:nvm-subsystem-sn-d78432", true);
	pass &= check("nqn.2014-08.org.nvmexpress.discovery", true);
	pass &= check("nqn.2014-08.org.nvmexpress:host-a", true);

	/* Real-world names that must keep working */
	pass &= check("nqn.1988-11.com.dell:PowerSANxxx:01:"
		      "20210225100113-454f73093ceb4847a7bdfc6e34ae8e28", true);
	pass &= check("nqn.1988-11.com.dell:starfleet", true);
	pass &= check("nqn.1988-11.com.dell:klingons", true);

	/* Malformed */
	pass &= check("qn.2014-08.com.example:host", false);
	pass &= check("nqn.201408.com.example:host", false);
	pass &= check("nqn.2014-0x.com.example:host", false);
	pass &= check("nqn.2014-08com.example:host", false);
	pass &= check("nqn.2014-08.", false);
	pass &= check("nqn.2014-00.com.example:host", false);
	pass &= check("nqn.2014-13.com.example:host", false);
	pass &= check("nqn.2014-08.com.example:host name", false);
	pass &= check("nqn.2014-08.com.example:host\n", false);
	pass &= check("nqn.2014-08.com.example:h\x7fst", false);

	memset(too_long, 'a', sizeof(too_long) - 1);
	too_long[sizeof(too_long) - 1] = '\0';
	memcpy(too_long, "nqn.2014-08.", strlen("nqn.2014-08."));
	pass &= check(too_long, false);

	return pass;
}

static bool check_hostid(const char *hostid, bool want)
{
	bool got = shr_hostid_valid(hostid);

	if (got == want) {
		printf(" - \"%s\" [PASS]\n", hostid ? hostid : "(null)");
		return true;
	}

	printf(" - \"%s\": got %s, want %s [FAIL]\n", hostid ? hostid : "(null)",
	       got ? "valid" : "invalid", want ? "valid" : "invalid");
	return false;
}

static bool test_hostid_valid(void)
{
	bool pass = true;

	printf("test_hostid_valid:\n");

	pass &= check_hostid(NULL, false);
	pass &= check_hostid("", false);
	pass &= check_hostid("1b4e28ba-2fa1-11d2-883f-0016d3cca427", true);
	pass &= check_hostid("00000000-0000-0000-0000-000000000000", false);
	pass &= check_hostid("00000000-0000-0000-0000-000000000001", true);
	pass &= check_hostid("ffffffff-ffff-ffff-ffff-ffffffffffff", true);
	pass &= check_hostid("abc-123", false);

	return pass;
}

int main(void)
{
	bool pass = true;

	pass &= test_nqn_valid();
	pass &= test_hostid_valid();

	fflush(stdout);
	exit(pass ? EXIT_SUCCESS : EXIT_FAILURE);
}
