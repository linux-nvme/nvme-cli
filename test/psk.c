// SPDX-License-Identifier: LGPL-2.1-or-later
/**
 * This file is part of libnvme.
 * Copyright (c) 2024 Daniel Wagner, SUSE Software Solutions
 */

#include "nvme/linux.h"
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include <ccan/array_size/array_size.h>

#include <libnvme.h>

static int test_rc;

struct test_data {
	const unsigned char configured_psk[48];
	size_t psk_length;
	unsigned char version;
	unsigned char hmac;
	const char *exported_psk;
};

static struct test_data test_data[] = {
	{ { 0x55, 0x12, 0xDB, 0xB6,
	    0x73, 0x7D, 0x01, 0x06,
	    0xF6, 0x59, 0x75, 0xB7,
	    0x73, 0xDF, 0xB0, 0x11,
	    0xFF, 0xC3, 0x44, 0xBC,
	    0xF4, 0x42, 0xE2, 0xDD,
	    0x6D, 0x8B, 0xC4, 0x87,
	    0x0B, 0x5D, 0x5B, 0x03},
	  32, 1, NVME_HMAC_ALG_NONE,
	  "NVMeTLSkey-1:00:VRLbtnN9AQb2WXW3c9+wEf/DRLz0QuLdbYvEhwtdWwNf9LrZ:" },
	{ { 0x55, 0x12, 0xDB, 0xB6,
	    0x73, 0x7D, 0x01, 0x06,
	    0xF6, 0x59, 0x75, 0xB7,
	    0x73, 0xDF, 0xB0, 0x11,
	    0xFF, 0xC3, 0x44, 0xBC,
	    0xF4, 0x42, 0xE2, 0xDD,
	    0x6D, 0x8B, 0xC4, 0x87,
	    0x0B, 0x5D, 0x5B, 0x03},
	  32, 1, NVME_HMAC_ALG_SHA2_256,
	  "NVMeTLSkey-1:01:VRLbtnN9AQb2WXW3c9+wEf/DRLz0QuLdbYvEhwtdWwNf9LrZ:" },
	{ { 0x55, 0x12, 0xDB, 0xB6,
	    0x73, 0x7D, 0x01, 0x06,
	    0xF6, 0x59, 0x75, 0xB7,
	    0x73, 0xDF, 0xB0, 0x11,
	    0xFF, 0xC3, 0x44, 0xBC,
	    0xF4, 0x42, 0xE2, 0xDD,
	    0x6D, 0x8B, 0xC4, 0x87,
	    0x0B, 0x5D, 0x5B, 0x03,
	    0xFF, 0xC3, 0x44, 0xBC,
	    0xF4, 0x42, 0xE2, 0xDD,
	    0x6D, 0x8B, 0xC4, 0x87,
	    0x0B, 0x5D, 0x5B, 0x03},
	  48, 1, NVME_HMAC_ALG_SHA2_384,
	  "NVMeTLSkey-1:02:VRLbtnN9AQb2WXW3c9+wEf/DRLz0QuLdbYvEhwtdWwP/w0S89ELi3W2LxIcLXVsDn8kXZQ==:" },
};

static void check_str(const char *exp, const char *res)
{
	if (!strcmp(res, exp))
		return;

	printf("ERROR: got '%s', expected '%s'\n", res, exp);

	test_rc = 1;
}

static void export_test(struct test_data *test)
{
	char *psk;

	if (test->version != 1 ||
	    !(test->hmac == NVME_HMAC_ALG_SHA2_256 ||
	      test->hmac == NVME_HMAC_ALG_SHA2_384))
		return;

	printf("test nvme_export_tls_key hmac %d %s\n",
	       test->hmac, test->exported_psk);

	psk = nvme_export_tls_key(test->configured_psk, test->psk_length);
	if (!psk) {
		test_rc = 1;
		printf("ERROR: nvme_export_tls_key() failed with %d\n", errno);
		return;
	}
	check_str(test->exported_psk, psk);
	free(psk);
}

static void import_test(struct test_data *test)
{
	unsigned char *psk;
	int psk_length;
	unsigned int hmac;

	if (test->version != 1 ||
	    !(test->hmac == NVME_HMAC_ALG_SHA2_256 ||
	      test->hmac == NVME_HMAC_ALG_SHA2_384))
		return;

	printf("test nvme_import_tls_key hmac %d %s\n",
	       test->hmac, test->exported_psk);

	psk = nvme_import_tls_key(test->exported_psk, &psk_length, &hmac);
	if (!psk) {
		test_rc = 1;
		printf("ERROR: nvme_import_tls_key() failed with %d\n", errno);
		return;
	}

	if (test->hmac != hmac) {
		test_rc = 1;
		printf("ERROR: hmac parsing failed\n");
		goto out;
	}

	if (test->psk_length != psk_length) {
		test_rc = 1;
		printf("ERROR: length parsing failed\n");
		goto out;
	}
	if (memcmp(test->configured_psk, psk, psk_length)) {
		test_rc = 1;
		printf("ERROR: parsing psk failed\n");
	}

out:
	free(psk);
}

static void export_versioned_test(struct test_data *test)
{
	char *psk;

	if (test->version != 1)
		return;

	printf("test nvme_export_tls_key_versioned hmac %d %s\n",
	       test->hmac, test->exported_psk);

	psk = nvme_export_tls_key_versioned(test->version, test->hmac,
					    test->configured_psk,
					    test->psk_length);
	if (!psk) {
		test_rc = 1;
		printf("ERROR: nvme_export_tls_key_versioned() failed with %d\n",
		       errno);
		return;
	}

	check_str(test->exported_psk, psk);

	free(psk);
}

static void import_versioned_test(struct test_data *test)
{
	unsigned char *psk;
	unsigned char version;
	unsigned char hmac;
	size_t psk_length;

	if (test->version != 1)
		return;

	printf("test nvme_import_tls_key_versioned hmac %d %s\n",
	       test->hmac, test->exported_psk);

	psk = nvme_import_tls_key_versioned(test->exported_psk, &version,
					    &hmac, &psk_length);
	if (!psk) {
		test_rc = 1;
		printf("ERROR: nvme_import_tls_key_versioned() failed with %d\n",
		       errno);
		return;
	}

	if (test->version != version) {
		test_rc = 1;
		printf("ERROR: version parsing failed\n");
		goto out;
	}

	if (test->hmac != hmac) {
		test_rc = 1;
		printf("ERROR: hmac parsing failed\n");
		goto out;
	}

	if (test->psk_length != psk_length) {
		test_rc = 1;
		printf("ERROR: length parsing failed\n");
		goto out;
	}

	if (memcmp(test->configured_psk, psk, psk_length)) {
		test_rc = 1;
		printf("ERROR: parsing psk failed\n");
	}

out:
	free(psk);
}

int main(void)
{
	for (int i = 0; i < ARRAY_SIZE(test_data); i++)
		export_test(&test_data[i]);

	for (int i = 0; i < ARRAY_SIZE(test_data); i++)
		import_test(&test_data[i]);

	for (int i = 0; i < ARRAY_SIZE(test_data); i++)
		export_versioned_test(&test_data[i]);

	for (int i = 0; i < ARRAY_SIZE(test_data); i++)
		import_versioned_test(&test_data[i]);

	return test_rc ? EXIT_FAILURE : EXIT_SUCCESS;
}
