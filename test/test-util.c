/**
 SPDX-License-Identifier: LGPL-2.1-or-later

 This file is part of libnvme.
 Copyright (c) 2023 Dell Inc.

 Authors: Martin Belanger <Martin.Belanger@dell.com>
*/

/**
 * In this file we test private and public functions found in
 * "src/nvme/util.c". Note that the source files are included
 * directly because the private functions are not available from
 * the libnvme.so.
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <netdb.h>
#include <string.h>

#include "nvme/log.c"		/* to resolve __nvme_msg() */
#include "nvme/util.c"

static size_t safe_strlen(const char *p) {
	return p ? strlen(p) : strlen("null");
}

static bool test_nvme_get_version(enum nvme_version type, const char * exp_str) {
	const char * str;
	str = nvme_get_version(type);
	return !strcmp(str, exp_str);
}

static bool test_ipaddrs_eq() {
	int test_success = true;
	static const char *x = "1.1.1.1";
	struct {
		const char *a;
		const char *b;
		bool  exp_result;
	} addrs[] = {
		{"192.168.56.101", "192.168.56.101", true},
		{"2001:0db8:0000:0000:0000:ff00:0042:8329", "2001:0db8::ff00:0042:8329", true},
		{NULL, NULL, true},
		{x, x, true},
		{"::ffff:192.168.56.101", "::ffff:192.168.56.101", true},
		{"::ffff:192.168.56.101", "192.168.56.101", true},
		{"192.168.56.101", "::ffff:192.168.56.101", true},
		{"::ffff:192.168.56.222", "192.168.56.101", false},
		{"192.168.56.101", "::ffff:192.168.56.222", false},
		{"1.2.3.4", "192.168.56.101", false},
		{"!@#$", "192.168.56.101", false},
		{"192.168.56.101", "!@#$", false},
		{"2001:0db8:0001:0000:0000:ff00:0042:8329", "2001:0db8::ff00:0042:8329", false},
		{"2001:0db8:0001:0000:0000:ff00:0042:8329", NULL, false},
	};

	size_t i;
	size_t n = sizeof(addrs) / sizeof(addrs[0]);
	size_t longest_a = 0, longest_b = 0;

	for (i = 0; i < n; i++) {
		size_t l;
		l = safe_strlen(addrs[i].a);
		if (l > longest_a) longest_a = l;
		l = safe_strlen(addrs[i].b);
		if (l > longest_b) longest_b = l;
	}

	for (i = 0; i < n; i++) {
		bool result = nvme_ipaddrs_eq(addrs[i].a, addrs[i].b);
		bool pass = result == addrs[i].exp_result;
		int pad_a = longest_a - safe_strlen(addrs[i].a);
		int pad_b = longest_b - safe_strlen(addrs[i].b);
		printf("%s %*.*s %s %*.*s  -> %-10s  %s\n",
		       addrs[i].a ? addrs[i].a : "null",
		       pad_a, pad_a, "",
		       addrs[i].b ? addrs[i].b : "null",
		       pad_b, pad_b, "",
		       result ? "equal/same" : "different",
		       pass ? "[PASS]" : "[FAIL]");

		if (!pass)
			test_success = false;
	}

	return test_success;
}

static bool test_nvme_id_ns_flbas_to_lbaf_inuse() {
	const __u8 flbas[] = {
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
			0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
			0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
			0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
			0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
			0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
			0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
			0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
			0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
			0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
			0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
			0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
			0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F,
			0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
			0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F,
		   };
	const __u8 inuse[] = {
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
			0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
			0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
			0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
			0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
			0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
			0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
			0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
			0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
			0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
			0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
			0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
			0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
		  };
	__u8 test_in_use;
	bool result, test_success = true;

	for (int i = 0; i < sizeof(flbas); i++) {
		nvme_id_ns_flbas_to_lbaf_inuse(flbas[i], &test_in_use);
		result = (test_in_use == inuse[i] ? true : false);
		printf("flbas = 0x%02x, inuse = 0x%02x (expect = 0x%02x) %s\n",
			flbas[i], test_in_use, inuse[i],
			result ? "[PASS]" : "[FAIL]");
		if (!result)
			test_success = false;
	}
	return test_success;
}

int main(int argc, char *argv[]) {
	int exit_val = EXIT_SUCCESS;
	bool pass;

	printf("\n------------------------------------------------------------------------------\n");
	pass = test_nvme_get_version(NVME_VERSION_PROJECT, PROJECT_VERSION);
	printf("nvme_get_version(NVME_VERSION_PROJECT) %s\n", pass ? "[PASS]" : "[FAIL]");
	if (!pass)
		exit_val = EXIT_FAILURE;

	printf("\n------------------------------------------------------------------------------\n");
	pass = test_nvme_get_version(NVME_VERSION_GIT, GIT_VERSION);
	printf("nvme_get_version(NVME_VERSION_GIT) %s\n", pass ? "[PASS]" : "[FAIL]");
	if (!pass)
		exit_val = EXIT_FAILURE;

	printf("\n------------------------------------------------------------------------------\n");
	pass = test_nvme_get_version(-1, "n/a");
	printf("nvme_get_version(-1) %s\n", pass ? "[PASS]" : "[FAIL]");
	if (!pass)
		exit_val = EXIT_FAILURE;

	printf("\n------------------------------------------------------------------------------\n");
	pass = test_ipaddrs_eq();
	printf("nvme_ipaddrs_eq() %s", pass ? "[PASS]" : "[FAIL]");
	if (!pass)
		exit_val = EXIT_FAILURE;

	printf("\n------------------------------------------------------------------------------\n");
	pass = test_nvme_id_ns_flbas_to_lbaf_inuse();
	printf("nvme_id_ns_flbas_to_lbaf_inuse() %s\n", pass ? "[PASS]" : "[FAIL]");
	if (!pass)
		exit_val = EXIT_FAILURE;

	exit(exit_val);
}
