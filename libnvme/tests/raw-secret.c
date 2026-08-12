// SPDX-License-Identifier: LGPL-2.1-or-later
/**
 * This file is part of libnvme.
 */

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

	libnvme_free_global_ctx(ctx);

	return test_rc ? EXIT_FAILURE : EXIT_SUCCESS;
}
