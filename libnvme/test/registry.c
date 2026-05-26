// SPDX-License-Identifier: LGPL-2.1-or-later
/**
 * This file is part of libnvme.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 * Authors: Martin Belanger <martin.belanger@dell.com>
 *
 * Unit tests for the NVMe controller ownership registry (registry.c).
 */

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <nvme/registry.h>

/* Internal — not exported in registry.h; declared here for testing. */
int libnvmf_registry_create(int instance, const char *owner);

/*
 * Strong override of the __libnvme_weak registry_dir() in registry.c.
 * Redirects all registry I/O to a per-run temp directory instead of
 * /run/nvme/registry, so tests run unprivileged and don't touch the system.
 */
static char registry_tmpdir[256];

const char *registry_dir(void)
{
	return registry_tmpdir;
}

/**
 * test_create - libnvmf_registry_create() must write a JSON file containing
 * the "device" and "owner" fields and return 0.
 */
static bool test_create(void)
{
	bool pass = true;
	char *value;
	int ret;

	printf("\ntest_create:\n");

	ret = libnvmf_registry_create(3, "stas");
	if (ret) {
		printf(" - create returned %d, expected 0 [FAIL]\n", ret);
		return false;
	}
	printf(" - create returned 0 [PASS]\n");

	ret = libnvmf_registry_retrieve("nvme3", "device", &value);
	if (ret) {
		printf(" - retrieve 'device' returned %d [FAIL]\n", ret);
		pass = false;
	} else if (strcmp(value, "nvme3") != 0) {
		printf(" - 'device' is '%s', expected 'nvme3' [FAIL]\n", value);
		free(value);
		pass = false;
	} else {
		printf(" - 'device' field is correct [PASS]\n");
		free(value);
	}

	ret = libnvmf_registry_retrieve("nvme3", "owner", &value);
	if (ret) {
		printf(" - retrieve 'owner' returned %d [FAIL]\n", ret);
		pass = false;
	} else if (strcmp(value, "stas") != 0) {
		printf(" - 'owner' is '%s', expected 'stas' [FAIL]\n", value);
		free(value);
		pass = false;
	} else {
		printf(" - 'owner' field is correct [PASS]\n");
		free(value);
	}

	libnvmf_registry_delete("nvme3");
	return pass;
}

/**
 * test_create_overwrite - Re-creating an entry for the same device must replace
 * the old entry, not merge with it.  Instance recycling makes old entries stale.
 */
static bool test_create_overwrite(void)
{
	bool pass = true;
	char *value;
	int ret;

	printf("\ntest_create_overwrite:\n");

	ret = libnvmf_registry_create(5, "old-owner");
	if (ret) {
		printf(" - first create returned %d [FAIL]\n", ret);
		return false;
	}

	ret = libnvmf_registry_create(5, "new-owner");
	if (ret) {
		printf(" - second create returned %d [FAIL]\n", ret);
		libnvmf_registry_delete("nvme5");
		return false;
	}
	printf(" - second create returned 0 [PASS]\n");

	ret = libnvmf_registry_retrieve("nvme5", "owner", &value);
	if (ret) {
		printf(" - retrieve 'owner' returned %d [FAIL]\n", ret);
		pass = false;
	} else if (strcmp(value, "new-owner") != 0) {
		printf(" - 'owner' is '%s', expected 'new-owner' [FAIL]\n",
		       value);
		free(value);
		pass = false;
	} else {
		printf(" - old entry replaced by new owner [PASS]\n");
		free(value);
	}

	libnvmf_registry_delete("nvme5");
	return pass;
}

/**
 * test_retrieve - libnvmf_registry_retrieve() must return -ENOENT for a
 * device that has no registry entry, and -ENOENT for a missing key.
 */
static bool test_retrieve(void)
{
	bool pass = true;
	char *value;
	int ret;

	printf("\ntest_retrieve:\n");

	/* Missing device */
	ret = libnvmf_registry_retrieve("nvme99", "owner", &value);
	if (ret != -ENOENT) {
		printf(" - retrieve missing device returned %d, expected -ENOENT [FAIL]\n",
		       ret);
		pass = false;
	} else {
		printf(" - retrieve missing device returns -ENOENT [PASS]\n");
	}

	/* Known device, missing key */
	ret = libnvmf_registry_create(4, "nbft");
	if (ret) {
		printf(" - create returned %d [FAIL]\n", ret);
		return false;
	}

	ret = libnvmf_registry_retrieve("nvme4", "no-such-key", &value);
	if (ret != -ENOENT) {
		printf(" - retrieve missing key returned %d, expected -ENOENT [FAIL]\n",
		       ret);
		pass = false;
	} else {
		printf(" - retrieve missing key returns -ENOENT [PASS]\n");
	}

	libnvmf_registry_delete("nvme4");
	return pass;
}

/**
 * test_update - libnvmf_registry_update() must create a new entry when none
 * exists, update an existing field, and preserve unrelated fields.
 */
static bool test_update(void)
{
	bool pass = true;
	char *value;
	int ret;

	printf("\ntest_update:\n");

	/* Create via update when no entry exists */
	ret = libnvmf_registry_update("nvme6", "owner", "discoverd");
	if (ret) {
		printf(" - update on missing entry returned %d [FAIL]\n", ret);
		return false;
	}
	printf(" - update on missing entry returned 0 [PASS]\n");

	ret = libnvmf_registry_retrieve("nvme6", "owner", &value);
	if (ret) {
		printf(" - retrieve after update returned %d [FAIL]\n", ret);
		pass = false;
	} else if (strcmp(value, "discoverd") != 0) {
		printf(" - 'owner' is '%s', expected 'discoverd' [FAIL]\n",
		       value);
		free(value);
		pass = false;
	} else {
		printf(" - 'owner' field written correctly [PASS]\n");
		free(value);
	}

	/* Update overwrites an existing field */
	ret = libnvmf_registry_update("nvme6", "owner", "stas");
	if (ret) {
		printf(" - overwrite update returned %d [FAIL]\n", ret);
		pass = false;
	}

	ret = libnvmf_registry_retrieve("nvme6", "owner", &value);
	if (ret) {
		printf(" - retrieve after overwrite returned %d [FAIL]\n", ret);
		pass = false;
	} else if (strcmp(value, "stas") != 0) {
		printf(" - 'owner' is '%s', expected 'stas' [FAIL]\n", value);
		free(value);
		pass = false;
	} else {
		printf(" - overwrite field is correct [PASS]\n");
		free(value);
	}

	/* Adding a second key preserves the first */
	ret = libnvmf_registry_update("nvme6", "extra", "extra-value");
	if (ret) {
		printf(" - add extra key returned %d [FAIL]\n", ret);
		pass = false;
	}

	ret = libnvmf_registry_retrieve("nvme6", "owner", &value);
	if (ret) {
		printf(" - retrieve 'owner' after adding extra key returned %d [FAIL]\n",
		       ret);
		pass = false;
	} else {
		printf(" - 'owner' preserved after adding extra key [PASS]\n");
		free(value);
	}

	libnvmf_registry_delete("nvme6");
	return pass;
}

/**
 * test_delete - libnvmf_registry_delete() must remove the entry and return
 * -ENOENT when called again on the same device.
 */
static bool test_delete(void)
{
	bool pass = true;
	int ret;

	printf("\ntest_delete:\n");

	ret = libnvmf_registry_create(7, "stas");
	if (ret) {
		printf(" - create returned %d [FAIL]\n", ret);
		return false;
	}

	ret = libnvmf_registry_delete("nvme7");
	if (ret) {
		printf(" - delete returned %d, expected 0 [FAIL]\n", ret);
		pass = false;
	} else {
		printf(" - delete returned 0 [PASS]\n");
	}

	ret = libnvmf_registry_delete("nvme7");
	if (ret != -ENOENT) {
		printf(" - second delete returned %d, expected -ENOENT [FAIL]\n",
		       ret);
		pass = false;
	} else {
		printf(" - second delete returns -ENOENT [PASS]\n");
	}

	return pass;
}

int main(int argc, char *argv[])
{
	char tmpl[] = "/tmp/nvme-registry-test-XXXXXX";
	bool pass = true;
	char *dir;

	dir = mkdtemp(tmpl);
	if (!dir) {
		perror("mkdtemp");
		return EXIT_FAILURE;
	}

	/* Point the weak registry_dir() override at our temp directory. */
	snprintf(registry_tmpdir, sizeof(registry_tmpdir), "%s", dir);

	pass &= test_create();
	pass &= test_create_overwrite();
	pass &= test_retrieve();
	pass &= test_update();
	pass &= test_delete();

	/* Best-effort cleanup; rmdir fails if any test leaked a file. */
	rmdir(registry_tmpdir);

	fflush(stdout);
	exit(pass ? EXIT_SUCCESS : EXIT_FAILURE);
}
