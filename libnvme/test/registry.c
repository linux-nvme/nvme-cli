// SPDX-License-Identifier: LGPL-2.1-or-later
/**
 * This file is part of libnvme.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 * Authors: Martin Belanger <martin.belanger@dell.com>
 *
 * Unit tests for the NVMe controller ownership registry (registry.c).
 * Covers CRUD operations, stale-entry skipping, iteration, and concurrent
 * access from multiple processes.
 */

#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <nvme/registry.h>

/* Internal — not in registry.h; called from the connect path in production. */
int libnvmf_registry_create_instance(int instance, const char *owner);

static char tmpdir[256];

static void setup_tmpdir(void)
{
	const char *base = getenv("TMPDIR") ? getenv("TMPDIR") : "/tmp";

	snprintf(tmpdir, sizeof(tmpdir), "%s/nvme-registry-test-XXXXXX", base);
	assert(mkdtemp(tmpdir) != NULL);
	setenv("NVME_REGISTRY_DIR", tmpdir, 1);
}

static void cleanup_tmpdir(void)
{
	/*
	 * Remove any remaining device directories, then the tmpdir itself.
	 * Best-effort: test isolation matters more than perfect cleanup.
	 */
	struct dirent *de;
	DIR *d;

	d = opendir(tmpdir);
	if (!d)
		return;
	while ((de = readdir(d)) != NULL) {
		if (de->d_name[0] != '.')
			libnvmf_registry_delete(de->d_name);
	}
	closedir(d);
	rmdir(tmpdir);
}

static bool test_create(void)
{
	char *value = NULL;
	bool pass = true;
	int ret;

	printf("test_create:\n");

	ret = libnvmf_registry_create_instance(3, "stas");
	if (ret) {
		printf(" - create returned %d [FAIL]\n", ret);
		return false;
	}

	ret = libnvmf_registry_retrieve("nvme3", "owner", &value);
	if (ret || !value) {
		printf(" - retrieve after create returned %d [FAIL]\n", ret);
		pass = false;
		goto out;
	}
	if (strcmp(value, "stas") != 0) {
		printf(" - expected 'stas', got '%s' [FAIL]\n", value);
		pass = false;
	} else {
		printf(" - owner='%s' [PASS]\n", value);
	}

out:
	free(value);
	libnvmf_registry_delete("nvme3");
	return pass;
}

static bool test_update_and_retrieve(void)
{
	char *value = NULL;
	bool pass = true;
	int ret;

	printf("test_update_and_retrieve:\n");

	/* Create entry via update (no prior entry). */
	ret = libnvmf_registry_update("nvme5", "owner", "nbft");
	if (ret) {
		printf(" - initial update returned %d [FAIL]\n", ret);
		return false;
	}

	ret = libnvmf_registry_retrieve("nvme5", "owner", &value);
	if (ret || !value || strcmp(value, "nbft") != 0) {
		printf(" - expected 'nbft', got '%s' ret=%d [FAIL]\n",
		       value ? value : "(null)", ret);
		pass = false;
		goto out;
	}
	printf(" - initial owner='%s' [PASS]\n", value);
	free(value);
	value = NULL;

	/* Steal ownership. */
	ret = libnvmf_registry_update("nvme5", "owner", "stas");
	if (ret) {
		printf(" - steal update returned %d [FAIL]\n", ret);
		pass = false;
		goto out;
	}

	ret = libnvmf_registry_retrieve("nvme5", "owner", &value);
	if (ret || !value || strcmp(value, "stas") != 0) {
		printf(" - expected 'stas' after steal, got '%s' ret=%d [FAIL]\n",
		       value ? value : "(null)", ret);
		pass = false;
	} else {
		printf(" - stolen owner='%s' [PASS]\n", value);
	}

out:
	free(value);
	libnvmf_registry_delete("nvme5");
	return pass;
}

static bool test_delete(void)
{
	char *value = NULL;
	bool pass = true;
	int ret;

	printf("test_delete:\n");

	libnvmf_registry_update("nvme7", "owner", "stas");

	ret = libnvmf_registry_delete("nvme7");
	if (ret) {
		printf(" - delete returned %d [FAIL]\n", ret);
		return false;
	}

	ret = libnvmf_registry_retrieve("nvme7", "owner", &value);
	if (ret != -ENOENT) {
		printf(" - expected -ENOENT after delete, got %d [FAIL]\n", ret);
		pass = false;
	} else {
		printf(" - retrieve after delete returns -ENOENT [PASS]\n");
	}

	free(value);

	/* Deleting a non-existent entry must return -ENOENT. */
	ret = libnvmf_registry_delete("nvme7");
	if (ret != -ENOENT) {
		printf(" - double-delete expected -ENOENT, got %d [FAIL]\n", ret);
		pass = false;
	} else {
		printf(" - double-delete returns -ENOENT [PASS]\n");
	}

	return pass;
}

static bool test_retrieve_missing(void)
{
	char *value = NULL;
	int ret;

	printf("test_retrieve_missing:\n");

	ret = libnvmf_registry_retrieve("nvme99", "owner", &value);
	free(value);

	if (ret != -ENOENT) {
		printf(" - expected -ENOENT for unregistered device, got %d [FAIL]\n", ret);
		return false;
	}
	printf(" - unregistered device returns -ENOENT [PASS]\n");
	return true;
}

struct for_each_result {
	char devices[8][32];
	int count;
};

static void collect_device(const char *device, void *user_data)
{
	struct for_each_result *r = user_data;

	if (r->count < 8)
		snprintf(r->devices[r->count++], sizeof(r->devices[0]),
			 "%s", device);
}

static bool test_device_for_each(void)
{
	struct for_each_result result = { .count = 0 };
	bool pass = true;
	int ret;

	printf("test_device_for_each:\n");

	/*
	 * Create two entries.  device_for_each skips entries whose /dev/nvmeN
	 * node is absent, so both will be skipped here — we are only testing
	 * that the function runs without error and skips gracefully.
	 */
	libnvmf_registry_update("nvme1", "owner", "stas");
	libnvmf_registry_update("nvme2", "owner", "nbft");

	ret = libnvmf_registry_device_for_each(collect_device, &result);
	if (ret) {
		printf(" - for_each returned %d [FAIL]\n", ret);
		pass = false;
	} else {
		printf(" - for_each returned 0, visited %d live entries [PASS]\n",
		       result.count);
	}

	libnvmf_registry_delete("nvme1");
	libnvmf_registry_delete("nvme2");
	return pass;
}

struct attr_result {
	char keys[8][64];
	char values[8][64];
	int count;
};

static void collect_attr(const char *attr, const char *value, void *user_data)
{
	struct attr_result *r = user_data;

	if (r->count < 8) {
		snprintf(r->keys[r->count], sizeof(r->keys[0]), "%s", attr);
		snprintf(r->values[r->count], sizeof(r->values[0]), "%s", value);
		r->count++;
	}
}

static bool test_attr_for_each(void)
{
	struct attr_result result = { .count = 0 };
	bool pass = true;
	int ret;

	printf("test_attr_for_each:\n");

	libnvmf_registry_update("nvme4", "owner", "stas");
	libnvmf_registry_update("nvme4", "extra", "hello");

	ret = libnvmf_registry_attr_for_each("nvme4", collect_attr, &result);
	if (ret) {
		printf(" - attr_for_each returned %d [FAIL]\n", ret);
		pass = false;
		goto out;
	}
	if (result.count != 2) {
		printf(" - expected 2 attrs, got %d [FAIL]\n", result.count);
		pass = false;
	} else {
		printf(" - found %d attrs [PASS]\n", result.count);
	}

	/* attr_for_each on non-existent device must return -ENOENT. */
	ret = libnvmf_registry_attr_for_each("nvme99", collect_attr, &result);
	if (ret != -ENOENT) {
		printf(" - missing device expected -ENOENT, got %d [FAIL]\n", ret);
		pass = false;
	} else {
		printf(" - missing device returns -ENOENT [PASS]\n");
	}

out:
	libnvmf_registry_delete("nvme4");
	return pass;
}

static bool test_null_args(void)
{
	char *value = NULL;
	bool pass = true;
	int ret;

	printf("test_null_args:\n");

#define CHECK(expr, expected, label) do {				\
	ret = (expr);							\
	if (ret != (expected)) {					\
		printf(" - %-44s expected %d, got %d [FAIL]\n",	\
		       (label), (expected), ret);			\
		pass = false;						\
	} else {							\
		printf(" - %-44s [PASS]\n", (label));			\
	}								\
} while (0)

	/* retrieve: any NULL parameter */
	CHECK(libnvmf_registry_retrieve(NULL, "owner", &value),
	      -EINVAL, "retrieve(NULL, attr, &value)");
	CHECK(libnvmf_registry_retrieve("nvme3", NULL, &value),
	      -EINVAL, "retrieve(device, NULL, &value)");
	CHECK(libnvmf_registry_retrieve("nvme3", "owner", NULL),
	      -EINVAL, "retrieve(device, attr, NULL)");

	/* update: NULL device or NULL attr; NULL value is remove-attr, not an error */
	CHECK(libnvmf_registry_update(NULL, "owner", "stas"),
	      -EINVAL, "update(NULL, attr, value)");
	CHECK(libnvmf_registry_update("nvme3", NULL, "stas"),
	      -EINVAL, "update(device, NULL, value)");

	/* delete: NULL device */
	CHECK(libnvmf_registry_delete(NULL),
	      -EINVAL, "delete(NULL)");

	/* device_for_each: NULL callback */
	CHECK(libnvmf_registry_device_for_each(NULL, NULL),
	      -EINVAL, "device_for_each(NULL, user_data)");

	/* attr_for_each: NULL device or NULL callback */
	CHECK(libnvmf_registry_attr_for_each(NULL, collect_attr, NULL),
	      -EINVAL, "attr_for_each(NULL, cback, user_data)");
	CHECK(libnvmf_registry_attr_for_each("nvme3", NULL, NULL),
	      -EINVAL, "attr_for_each(device, NULL, user_data)");

#undef CHECK

	free(value);
	return pass;
}

/*
 * test_parallel_writes - Atomic write protocol must prevent corruption under
 * concurrent access.  Ten child processes repeatedly update the same attribute
 * concurrently.  The value read after all exit must be one of the written
 * values — never a partial or garbled string.
 */
static bool test_parallel_writes(void)
{
	char *value = NULL;
	int status;
	bool pass;
	int i;

	printf("test_parallel_writes:\n");

	libnvmf_registry_update("nvme10", "owner", "parent");

#define NPROCS 10
	pid_t pids[NPROCS];
	char owner[16];

	for (i = 0; i < NPROCS; i++) {
		pids[i] = fork();
		assert(pids[i] >= 0);
		if (pids[i] == 0) {
			snprintf(owner, sizeof(owner), "child%d", i);
			for (int j = 0; j < 200; j++)
				libnvmf_registry_update("nvme10", "owner", owner);
			exit(0);
		}
	}

	for (i = 0; i < NPROCS; i++)
		waitpid(pids[i], &status, 0);

	libnvmf_registry_retrieve("nvme10", "owner", &value);

	pass = false;
	for (i = 0; i < NPROCS; i++) {
		snprintf(owner, sizeof(owner), "child%d", i);
		if (value && strcmp(value, owner) == 0) {
			pass = true;
			break;
		}
	}

	if (pass)
		printf(" - final owner='%s', well-formed [PASS]\n", value);
	else
		printf(" - final owner='%s', corrupted [FAIL]\n",
		       value ? value : "(null)");

	free(value);
	libnvmf_registry_delete("nvme10");
	return pass;
}

int main(int argc, char *argv[])
{
	bool pass = true;

	setup_tmpdir();

	pass &= test_create();
	pass &= test_update_and_retrieve();
	pass &= test_delete();
	pass &= test_retrieve_missing();
	pass &= test_device_for_each();
	pass &= test_attr_for_each();
	pass &= test_null_args();
	pass &= test_parallel_writes();

	cleanup_tmpdir();

	fflush(stdout);
	exit(pass ? EXIT_SUCCESS : EXIT_FAILURE);
}
