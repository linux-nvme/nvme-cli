// SPDX-License-Identifier: LGPL-2.1-or-later
/**
 * This file is part of libnvme.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <ccan/array_size/array_size.h>

#include <libnvme.h>

static int test_rc;

/* Each of these used to yield a secret the caller never gave. */
static const struct {
	const char *unit;
	size_t times;
	const char *tail;
} rejected[] = {
	{ "g0", 32, "" },	/* a stray character, on an even offset */
	{ "0g", 32, "" },	/* and on an odd one, which was skipped */
	{ "-1", 32, "" },	/* a sign, which read as 0xff */
	{ "+1", 32, "" },
	{ " f", 32, "" },	/* whitespace, skipped without being counted */
	{ "f ", 32, "" },
	{ "\t1", 32, "" },
	{ " ", 63, "f" },	/* one digit built all 32 bytes */
	{ "ab", 31, "a" },	/* one character short of the length */
};

static const struct {
	const char *unit;
	size_t times;
	size_t key_len;
	unsigned char expect;
} accepted[] = {
	{ "0f", 32, 32, 0x0f },
	{ "AB", 32, 32, 0xab },	/* upper case is a hexadecimal digit too */
	{ "ab", 48, 48, 0xab },
	{ "ab", 48, 32, 0xab },	/* longer than key_len is still truncated */
};

/*
 * A 'pin:' secret is the concatenation of SHA-256(pin || counter) blocks,
 * where the counter starts at zero, advances once per block and is encoded
 * as four big endian bytes. Every length therefore extends the shorter
 * ones, so a single 64 byte expansion covers all three cases.
 */
static const char pin_secret[] = "pin:1234";

static const unsigned char pin_expansion[64] = {
	0xf7, 0x00, 0x98, 0x55, 0x0a, 0x83, 0xbc, 0x00,
	0xe3, 0x18, 0x86, 0x68, 0xea, 0xaf, 0xef, 0xd9,
	0x27, 0xe6, 0x5d, 0x9a, 0xaa, 0x90, 0xd6, 0xbd,
	0x4d, 0xcb, 0xd8, 0xbb, 0xde, 0xcb, 0xcb, 0x74,
	0x6a, 0x3a, 0x48, 0x57, 0x67, 0x20, 0x48, 0xe9,
	0x1b, 0x35, 0x9b, 0xae, 0x1d, 0xe4, 0xbb, 0xa9,
	0x17, 0xe2, 0x00, 0x5f, 0xac, 0x88, 0x19, 0xe4,
	0x0c, 0x16, 0x8e, 0xe0, 0x4e, 0xd3, 0xe8, 0x0b,
};

static const size_t key_lengths[] = { 32, 48, 64 };

static char *build(const char *unit, size_t times, const char *tail)
{
	size_t unit_len = strlen(unit);
	char *secret = malloc(unit_len * times + strlen(tail) + 1);
	size_t i;

	if (!secret)
		exit(EXIT_FAILURE);

	for (i = 0; i < times; i++)
		memcpy(secret + i * unit_len, unit, unit_len);
	memcpy(secret + unit_len * times, tail, strlen(tail) + 1);

	return secret;
}

static void reject_test(struct libnvme_global_ctx *ctx, const char *secret)
{
	unsigned char *raw_secret = NULL;
	int ret;

	printf("test libnvmf_create_raw_secret rejects '%s'\n", secret);

	ret = libnvmf_create_raw_secret(ctx, secret, 32, &raw_secret);
	if (ret >= 0) {
		test_rc = 1;
		printf("ERROR: '%s' was accepted\n", secret);
		free(raw_secret);
	}
}

static void accept_test(struct libnvme_global_ctx *ctx, const char *secret,
			size_t key_len, unsigned char expect)
{
	unsigned char *raw_secret = NULL;
	int ret;
	size_t i;

	printf("test libnvmf_create_raw_secret takes %zu bytes of 0x%02x\n",
	       key_len, expect);

	ret = libnvmf_create_raw_secret(ctx, secret, key_len, &raw_secret);
	if (ret) {
		test_rc = 1;
		printf("ERROR: libnvmf_create_raw_secret() failed with %d\n",
		       ret);
		return;
	}

	for (i = 0; i < key_len; i++) {
		if (raw_secret[i] == expect)
			continue;

		test_rc = 1;
		printf("ERROR: byte %zu is 0x%02x, expected 0x%02x\n",
		       i, raw_secret[i], expect);
		break;
	}

	free(raw_secret);
}

static void pin_test(struct libnvme_global_ctx *ctx, size_t key_len)
{
	unsigned char *raw_secret;
	int ret;

	printf("test libnvmf_create_raw_secret '%s' key_len %zu\n",
	       pin_secret, key_len);

	ret = libnvmf_create_raw_secret(ctx, pin_secret, key_len, &raw_secret);
	if (ret) {
		if (ret == -ENOTSUP)
			return;
		test_rc = 1;
		printf("ERROR: libnvmf_create_raw_secret() failed with %d\n",
		       ret);
		return;
	}

	if (memcmp(pin_expansion, raw_secret, key_len)) {
		test_rc = 1;
		printf("ERROR: unexpected expansion for key_len %zu\n",
		       key_len);
		goto out;
	}

	/*
	 * The counter used to be reset on every iteration, which made each
	 * block a copy of the first one. Guard the property directly.
	 */
	if (key_len > 32 &&
	    !memcmp(raw_secret, raw_secret + 32, key_len - 32)) {
		test_rc = 1;
		printf("ERROR: block repeats the first one for key_len %zu\n",
		       key_len);
	}

out:
	free(raw_secret);
}

int main(void)
{
	struct libnvme_global_ctx *ctx = libnvme_create_global_ctx();
	char *secret;
	int i;

	libnvme_set_logging_file(ctx, stdout);

	for (i = 0; i < ARRAY_SIZE(rejected); i++) {
		secret = build(rejected[i].unit, rejected[i].times,
			       rejected[i].tail);
		reject_test(ctx, secret);
		free(secret);
	}

	for (i = 0; i < ARRAY_SIZE(accepted); i++) {
		secret = build(accepted[i].unit, accepted[i].times, "");
		accept_test(ctx, secret, accepted[i].key_len,
			    accepted[i].expect);
		free(secret);
	}

	for (i = 0; i < ARRAY_SIZE(key_lengths); i++)
		pin_test(ctx, key_lengths[i]);

	libnvme_free_global_ctx(ctx);

	return test_rc ? EXIT_FAILURE : EXIT_SUCCESS;
}
