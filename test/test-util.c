/**
 SPDX-License-Identifier: LGPL-2.1-or-later

 This file is part of libnvme.
 Copyright (c) 2023 Dell Inc.

 Authors: Martin Belanger <Martin.Belanger@dell.com>
*/

/**
 * In this file we test private functions found in
 * "src/nvme/util.c". Note that the source files are included
 * directly because the private functions are not available from
 * the libnvme.so.
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <netdb.h>
#include <string.h>

#include "nvme/cleanup.c"	/* to resolve cleanup_charp() */
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
		{"::ffff:192.168.56.222", "192.168.56.101", false},
		{"1.2.3.4", "192.168.56.101", false},
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
		bool result = ipaddrs_eq(addrs[i].a, addrs[i].b);
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
	printf("ipaddrs_eq() %s", pass ? "[PASS]" : "[FAIL]");
	if (!pass)
		exit_val = EXIT_FAILURE;

	exit(exit_val);
}
