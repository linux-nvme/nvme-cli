// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 SUSE Software Solutions
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <crypto-util.h>

static bool check_hex(const char *name, const unsigned char *got, size_t got_len,
		       const char *want_hex)
{
	char buf[128] = { 0 };
	size_t i;

	if (!got) {
		printf(" - %s: got NULL [FAIL]\n", name);
		return false;
	}

	for (i = 0; i < got_len; i++)
		snprintf(buf + i * 2, 3, "%02x", got[i]);

	if (!strcmp(buf, want_hex)) {
		printf(" - %s [PASS]\n", name);
		return true;
	}

	printf(" - %s: got %s, want %s [FAIL]\n", name, buf, want_hex);
	return false;
}

static bool test_md5(void)
{
	unsigned char *hash;
	bool pass = true;

	printf("test_md5:\n");

	hash = shr_md5((unsigned char *)"abc", 3);
	pass &= check_hex("md5(\"abc\")", hash, 16, "900150983cd24fb0d6963f7d28e17f72");
	free(hash);

	hash = shr_md5((unsigned char *)"", 0);
	pass &= check_hex("md5(\"\")", hash, 16, "d41d8cd98f00b204e9800998ecf8427e");
	free(hash);

	return pass;
}

static bool test_hmac_sha256(void)
{
	static const char *msg = "The quick brown fox jumps over the lazy dog";
	unsigned char *hash;
	bool pass = true;

	printf("test_hmac_sha256:\n");

	hash = shr_hmac_sha256((unsigned char *)msg, strlen(msg),
				(unsigned char *)"key", 3);
	pass &= check_hex("hmac_sha256(msg, \"key\")", hash, 32,
			   "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8");
	free(hash);

	return pass;
}

int main(void)
{
	bool pass = true;

	unsigned char *probe = shr_md5((unsigned char *)"x", 1);

	if (!probe) {
		printf("OpenSSL support unavailable, skipping\n");
		exit(77);
	}
	free(probe);

	pass &= test_md5();
	pass &= test_hmac_sha256();

	fflush(stdout);
	exit(pass ? EXIT_SUCCESS : EXIT_FAILURE);
}
