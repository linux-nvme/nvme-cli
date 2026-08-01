// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <ccan/array_size/array_size.h>

#include <base64.h>

struct vector {
	const char *raw;
	const char *encoded;
};

/* RFC 4648 section 10 test vectors. */
static const struct vector vectors[] = {
	{ "", "" },
	{ "f", "Zg==" },
	{ "fo", "Zm8=" },
	{ "foo", "Zm9v" },
	{ "foob", "Zm9vYg==" },
	{ "fooba", "Zm9vYmE=" },
	{ "foobar", "Zm9vYmFy" },
};

static bool test_known_vectors(void)
{
	size_t i;
	bool pass = true;

	printf("test_known_vectors:\n");

	for (i = 0; i < ARRAY_SIZE(vectors); i++) {
		char encoded[64] = { 0 };
		unsigned char decoded[64] = { 0 };
		int raw_len = (int)strlen(vectors[i].raw);
		int enc_str_len = (int)strlen(vectors[i].encoded);
		int enc_len, dec_len;

		enc_len = shr_base64_encode(
			(const unsigned char *)vectors[i].raw,
			raw_len, encoded);
		if (enc_len != enc_str_len ||
		    memcmp(encoded, vectors[i].encoded, enc_len)) {
			printf(" - encode(\"%s\") [FAIL]\n", vectors[i].raw);
			pass = false;
			continue;
		}

		dec_len = shr_base64_decode(vectors[i].encoded, enc_str_len,
					    decoded);
		if (dec_len != raw_len ||
		    memcmp(decoded, vectors[i].raw, dec_len)) {
			printf(" - decode(\"%s\") [FAIL]\n",
			       vectors[i].encoded);
			pass = false;
			continue;
		}
	}

	if (pass)
		printf(" - all RFC 4648 vectors round-trip [PASS]\n");

	return pass;
}

static bool test_invalid_input_rejected(void)
{
	unsigned char decoded[64];
	bool pass = true;

	printf("test_invalid_input_rejected:\n");

	if (shr_base64_decode("not valid base64!", 18, decoded) >= 0) {
		printf(" - decode of non-base64 input [FAIL]\n");
		pass = false;
	} else {
		printf(" - decode of non-base64 input rejected [PASS]\n");
	}

	if (shr_base64_decode("Zm9vYmFy", -4, decoded) >= 0) {
		printf(" - decode of a negative length [FAIL]\n");
		pass = false;
	} else {
		printf(" - decode of a negative length rejected [PASS]\n");
	}

	return pass;
}

/* Inputs that must be rejected. */
static const char * const rejected[] = {
	"Zm9v=YmFy",		/* '=' in the middle */
	"Zm9v====YmFy",		/* ... keeping the group alignment */
	"====Zm9vYmFy",		/* '=' at the front */
	"Zm9vYmFy====",		/* more padding than a group can hold */
	"====",
	"Zg===",
	"Zm9v==",		/* padding on a complete group */
	"Zh==",			/* the trailing bits are not zero */
	"Zm9vYmF=",
	"Zm9vYg",		/* padding omitted */
	"Zm9vYmE",
	"AAAAAAA",		/* ... and the trailing bits are zero */
	"Zm9vY",		/* a single leftover character */
};

static bool test_padding_rules(void)
{
	unsigned char decoded[64];
	bool pass = true;
	size_t i;

	printf("test_padding:\n");

	for (i = 0; i < ARRAY_SIZE(rejected); i++) {
		if (shr_base64_decode(rejected[i], strlen(rejected[i]),
				      decoded) >= 0) {
			printf(" - decode(\"%s\") not rejected [FAIL]\n",
			       rejected[i]);
			pass = false;
		}
	}
	if (pass)
		printf(" - malformed padding rejected [PASS]\n");

	return pass;
}

int main(void)
{
	bool pass = true;

	pass &= test_known_vectors();
	pass &= test_invalid_input_rejected();
	pass &= test_padding_rules();

	fflush(stdout);
	exit(pass ? EXIT_SUCCESS : EXIT_FAILURE);
}
