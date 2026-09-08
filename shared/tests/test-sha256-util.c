// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 *
 * SHA-256 vectors are from FIPS 180-2. HMAC-SHA256 vectors are from
 * RFC 4231.
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <shared/sha256-util.h>

static bool check(const char *name, const unsigned char *got,
		  const char *want_hex)
{
	char buf[2 * SHR_SHA256_DIGEST_SIZE + 1] = {};
	size_t i;

	for (i = 0; i < SHR_SHA256_DIGEST_SIZE; i++)
		snprintf(buf + i * 2, 3, "%02x", got[i]);

	if (!strcmp(buf, want_hex)) {
		printf(" - %s [PASS]\n", name);
		return true;
	}

	printf(" - %s: got %s, want %s [FAIL]\n", name, buf, want_hex);

	return false;
}

static bool test_sha256(void)
{
	unsigned char out[SHR_SHA256_DIGEST_SIZE];
	char long_input[200];
	bool pass = true;

	printf("test_sha256:\n");

	shr_sha256("", 0, out);
	pass &= check("empty", out,
		      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

	shr_sha256("abc", 3, out);
	pass &= check("abc", out,
		      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

	/* Spans two blocks. */
	shr_sha256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56,
		   out);
	pass &= check("two blocks", out,
		      "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");

	memset(long_input, 'a', sizeof(long_input));
	shr_sha256(long_input, sizeof(long_input), out);
	pass &= check("200 bytes", out,
		      "c2a908d98f5df987ade41b5fce213067efbcc21ef2240212a41e54b5e7c28ae5");

	return pass;
}

static bool test_sha256_incremental(void)
{
	unsigned char out[SHR_SHA256_DIGEST_SIZE];
	struct shr_sha256_ctx ctx;

	printf("test_sha256_incremental:\n");

	/* Feeding the same input in pieces must give the same digest. */
	shr_sha256_init(&ctx);
	shr_sha256_update(&ctx, "a", 1);
	shr_sha256_update(&ctx, "b", 1);
	shr_sha256_update(&ctx, "c", 1);
	shr_sha256_final(&ctx, out);

	return check("abc in three calls", out,
		     "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

static bool test_hmac_sha256(void)
{
	unsigned char out[SHR_SHA256_DIGEST_SIZE];
	unsigned char key[131];
	bool pass = true;

	printf("test_hmac_sha256:\n");

	memset(key, 0x0b, 20);
	shr_hmac_sha256_raw(key, 20, "Hi There", 8, out);
	pass &= check("RFC 4231 case 1", out,
		      "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");

	shr_hmac_sha256_raw("Jefe", 4, "what do ya want for nothing?", 28, out);
	pass &= check("RFC 4231 case 2", out,
		      "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");

	/* Key longer than the block size, so it is hashed first. */
	memset(key, 0xaa, sizeof(key));
	shr_hmac_sha256_raw(key, sizeof(key),
			    "Test Using Larger Than Block-Size Key - Hash Key First",
			    54, out);
	pass &= check("RFC 4231 case 6", out,
		      "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");

	return pass;
}

int main(void)
{
	bool pass = true;

	pass &= test_sha256();
	pass &= test_sha256_incremental();
	pass &= test_hmac_sha256();

	fflush(stdout);
	exit(pass ? EXIT_SUCCESS : EXIT_FAILURE);
}
