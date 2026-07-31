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

#include <array-util.h>

static bool test_ptrarray_append(void)
{
	struct shr_ptrarray a = { 0 };
	int items[20];
	size_t i;
	bool pass = true;

	printf("test_ptrarray_append:\n");

	/* Cross the initial capacity (8) at least twice to exercise growth. */
	for (i = 0; i < 20; i++) {
		items[i] = (int)i;
		if (shr_ptrarray_append(&a, &items[i]) < 0) {
			printf(" - append %zu [FAIL]\n", i);
			pass = false;
		}
	}

	if (a.len != 20) {
		printf(" - len after 20 appends: got %zu, want 20 [FAIL]\n",
		       a.len);
		pass = false;
	} else {
		printf(" - len after 20 appends [PASS]\n");
	}

	for (i = 0; i < 20; i++) {
		if (*(int *)a.items[i] != (int)i) {
			printf(" - items[%zu] mismatch [FAIL]\n", i);
			pass = false;
		}
	}

	/* NULL-terminator idiom: append every real item, then NULL last. */
	if (shr_ptrarray_append(&a, NULL) < 0) {
		printf(" - append trailing NULL [FAIL]\n");
		pass = false;
	} else if (a.items[a.len - 1] != NULL) {
		printf(" - trailing NULL not stored [FAIL]\n");
		pass = false;
	} else {
		printf(" - NULL-terminator idiom [PASS]\n");
	}

	shr_ptrarray_free(&a);
	if (a.items != NULL || a.len != 0 || a.cap != 0) {
		printf(" - free() resets to zeroed state [FAIL]\n");
		pass = false;
	} else {
		printf(" - free() resets to zeroed state [PASS]\n");
	}

	return pass;
}

/*
 * Type-checked wrapper round-trip. The actual type-checking guarantee
 * (a mismatched pointer type fails to compile) can't be exercised at
 * runtime; it was verified manually with a scratch program that swapped
 * in a wrong type and confirmed -Wincompatible-pointer-types.
 */
struct thing {
	int x;
};

SHR_PTRARRAY_DEFINE(thing_list, struct thing)

static bool test_ptrarray_define(void)
{
	struct thing_list list = { 0 };
	struct thing a = { 1 }, b = { 2 };
	bool pass = true;

	printf("test_ptrarray_define:\n");

	if (thing_list_append(&list, &a) < 0 ||
	    thing_list_append(&list, &b) < 0) {
		printf(" - append [FAIL]\n");
		pass = false;
	} else if (list.len != 2 || list.items[0]->x != 1 ||
		   list.items[1]->x != 2) {
		printf(" - round-trip values [FAIL]\n");
		pass = false;
	} else {
		printf(" - round-trip values [PASS]\n");
	}

	thing_list_free(&list);
	if (list.items != NULL || list.len != 0) {
		printf(" - free() resets to zeroed state [FAIL]\n");
		pass = false;
	} else {
		printf(" - free() resets to zeroed state [PASS]\n");
	}

	return pass;
}

int main(void)
{
	bool pass = true;

	pass &= test_ptrarray_append();
	pass &= test_ptrarray_define();

	fflush(stdout);
	exit(pass ? EXIT_SUCCESS : EXIT_FAILURE);
}
