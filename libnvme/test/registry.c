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

#include <nvme/lib.h>
#include <nvme/registry.h>

/* Internal — not in registry.h; called from the connect path in production. */
int libnvmf_registry_create_instance(struct libnvme_global_ctx *ctx,
				     int instance, const char *owner);

static char tmpdir[256];
static char regdir[280]; /* <tmpdir>/registry -- where entries actually live */

static void setup_tmpdir(struct libnvme_global_ctx *ctx)
{
	/*
	 * /tmp is required: libnvme confines the test base dir to /tmp, so the
	 * test directory must live there (not under an arbitrary $TMPDIR).
	 */
	snprintf(tmpdir, sizeof(tmpdir), "/tmp/nvme-registry-test-XXXXXX");
	assert(mkdtemp(tmpdir) != NULL);
	snprintf(regdir, sizeof(regdir), "%s/registry", tmpdir);
	assert(libnvme_set_test_base_dir(ctx, tmpdir) == 0);
}

static void cleanup_tmpdir(struct libnvme_global_ctx *ctx)
{
	/*
	 * Remove any remaining device directories, then the dirs themselves.
	 * Best-effort: test isolation matters more than perfect cleanup.
	 */
	struct dirent *de;
	DIR *d;

	d = opendir(regdir);
	if (d) {
		while ((de = readdir(d)) != NULL) {
			if (de->d_name[0] != '.')
				libnvmf_registry_delete(ctx, de->d_name);
		}
		closedir(d);
	}
	rmdir(regdir);
	rmdir(tmpdir);
}

static bool test_create(struct libnvme_global_ctx *ctx)
{
	char *value = NULL;
	bool pass = true;
	int ret;

	printf("test_create:\n");

	ret = libnvmf_registry_create_instance(ctx, 3, "stas");
	if (ret) {
		printf(" - create returned %d [FAIL]\n", ret);
		return false;
	}

	ret = libnvmf_registry_retrieve(ctx, "nvme3", "owner", &value);
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

	/*
	 * create_instance also stamps the entry with /sys/kernel/uevent_seqnum
	 * for the udev cleanup rule.  It is best-effort, so only verify
	 * it looks like a number when present rather than requiring it.
	 */
	free(value);
	value = NULL;
	ret = libnvmf_registry_retrieve(ctx, "nvme3", "seqnum", &value);
	if (ret == 0 && value) {
		char *end;

		strtoull(value, &end, 10);
		if (*value && *end == '\0') {
			printf(" - seqnum='%s' [PASS]\n", value);
		} else {
			printf(" - seqnum='%s' not numeric [FAIL]\n", value);
			pass = false;
		}
	}

	/*
	 * The entry is built in a temp dir and rename()'d into place; confirm
	 * no leftover ".nvmeN.tmp.*" dir remains after a successful create.
	 */
	{
		struct dirent *de;
		bool leftover = false;
		DIR *d = opendir(regdir);

		if (d) {
			while ((de = readdir(d)) != NULL) {
				if (strstr(de->d_name, ".tmp.")) {
					printf(" - leftover '%s' [FAIL]\n",
					       de->d_name);
					leftover = true;
				}
			}
			closedir(d);
		}
		if (leftover)
			pass = false;
		else
			printf(" - no leftover temp dir [PASS]\n");
	}

out:
	free(value);
	libnvmf_registry_delete(ctx, "nvme3");

	return pass;
}

static bool test_update_and_retrieve(struct libnvme_global_ctx *ctx)
{
	char *value = NULL;
	bool pass = true;
	int ret;

	printf("test_update_and_retrieve:\n");

	/* Create entry via update (no prior entry). */
	ret = libnvmf_registry_update(ctx, "nvme5", "owner", "nbft");
	if (ret) {
		printf(" - initial update returned %d [FAIL]\n", ret);
		return false;
	}

	ret = libnvmf_registry_retrieve(ctx, "nvme5", "owner", &value);
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
	ret = libnvmf_registry_update(ctx, "nvme5", "owner", "stas");
	if (ret) {
		printf(" - steal update returned %d [FAIL]\n", ret);
		pass = false;
		goto out;
	}

	ret = libnvmf_registry_retrieve(ctx, "nvme5", "owner", &value);
	if (ret || !value || strcmp(value, "stas") != 0) {
		printf(" - expected 'stas' after steal, got '%s' ret=%d [FAIL]\n",
		       value ? value : "(null)", ret);
		pass = false;
	} else {
		printf(" - stolen owner='%s' [PASS]\n", value);
	}

out:
	free(value);
	libnvmf_registry_delete(ctx, "nvme5");
	return pass;
}

static bool test_special_chars(struct libnvme_global_ctx *ctx)
{
	/*
	 * Attribute values are free-form text -- only device and attribute
	 * names are validated, never the value.  Verify a value with spaces,
	 * double quotes, an apostrophe and punctuation round-trips
	 * byte-for-byte.
	 */
	const char *special = "ACME Corp \"prod\" team's box !@#%";
	char *value = NULL;
	bool pass = true;
	int ret;

	printf("test_special_chars:\n");

	ret = libnvmf_registry_update(ctx, "nvme5", "owner", special);
	if (ret) {
		printf(" - update returned %d [FAIL]\n", ret);
		return false;
	}

	ret = libnvmf_registry_retrieve(ctx, "nvme5", "owner", &value);
	if (ret || !value || strcmp(value, special) != 0) {
		printf(" - expected '%s', got '%s' ret=%d [FAIL]\n",
		       special, value ? value : "(null)", ret);
		pass = false;
	} else {
		printf(" - round-trip '%s' [PASS]\n", value);
	}

	free(value);
	libnvmf_registry_delete(ctx, "nvme5");
	return pass;
}

static bool test_delete(struct libnvme_global_ctx *ctx)
{
	char *value = NULL;
	bool pass = true;
	int ret;

	printf("test_delete:\n");

	ret = libnvmf_registry_update(ctx, "nvme7", "owner", "stas");
	if (ret) {
		printf(" - setup update failed: %d [FAIL]\n", ret);
		return false;
	}

	ret = libnvmf_registry_delete(ctx, "nvme7");
	if (ret) {
		printf(" - delete returned %d [FAIL]\n", ret);
		return false;
	}

	ret = libnvmf_registry_retrieve(ctx, "nvme7", "owner", &value);
	if (ret != -ENOENT) {
		printf(" - expected -ENOENT after delete, got %d [FAIL]\n", ret);
		pass = false;
	} else {
		printf(" - retrieve after delete returns -ENOENT [PASS]\n");
	}

	free(value);

	/* Deleting a non-existent entry must return -ENOENT. */
	ret = libnvmf_registry_delete(ctx, "nvme7");
	if (ret != -ENOENT) {
		printf(" - double-delete expected -ENOENT, got %d [FAIL]\n", ret);
		pass = false;
	} else {
		printf(" - double-delete returns -ENOENT [PASS]\n");
	}

	return pass;
}

static bool test_retrieve_missing(struct libnvme_global_ctx *ctx)
{
	char *value = NULL;
	int ret;

	printf("test_retrieve_missing:\n");

	ret = libnvmf_registry_retrieve(ctx, "nvme99", "owner", &value);
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

static bool test_device_for_each(struct libnvme_global_ctx *ctx)
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
	if (libnvmf_registry_update(ctx, "nvme1", "owner", "stas") ||
	    libnvmf_registry_update(ctx, "nvme2", "owner", "nbft")) {
		printf(" - setup update failed [FAIL]\n");
		return false;
	}

	ret = libnvmf_registry_device_for_each(ctx, collect_device, &result);
	if (ret) {
		printf(" - for_each returned %d [FAIL]\n", ret);
		pass = false;
	} else {
		printf(" - for_each returned 0, visited %d live entries [PASS]\n",
		       result.count);
	}

	libnvmf_registry_delete(ctx, "nvme1");
	libnvmf_registry_delete(ctx, "nvme2");
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

static bool test_attr_for_each(struct libnvme_global_ctx *ctx)
{
	struct attr_result result = { .count = 0 };
	bool pass = true;
	int ret;

	printf("test_attr_for_each:\n");

	if (libnvmf_registry_update(ctx, "nvme4", "owner", "stas") ||
	    libnvmf_registry_update(ctx, "nvme4", "extra", "hello")) {
		printf(" - setup update failed [FAIL]\n");
		pass = false;
		goto out;
	}

	ret = libnvmf_registry_attr_for_each(ctx, "nvme4", collect_attr,
					     &result);
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
	ret = libnvmf_registry_attr_for_each(ctx, "nvme99", collect_attr,
					     &result);
	if (ret != -ENOENT) {
		printf(" - missing device expected -ENOENT, got %d [FAIL]\n", ret);
		pass = false;
	} else {
		printf(" - missing device returns -ENOENT [PASS]\n");
	}

out:
	libnvmf_registry_delete(ctx, "nvme4");

	return pass;
}

static bool test_null_args(struct libnvme_global_ctx *ctx)
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

	/* NULL ctx is rejected by every public API */
	CHECK(libnvmf_registry_retrieve(NULL, "nvme3", "owner", &value),
	      -EINVAL, "retrieve(NULL ctx)");
	CHECK(libnvmf_registry_attr_equal(NULL, "nvme3", "owner", "stas"),
	      -EINVAL, "attr_equal(NULL ctx)");
	CHECK(libnvmf_registry_update(NULL, "nvme3", "owner", "stas"),
	      -EINVAL, "update(NULL ctx)");
	CHECK(libnvmf_registry_delete(NULL, "nvme3"),
	      -EINVAL, "delete(NULL ctx)");
	CHECK(libnvmf_registry_device_for_each(NULL, collect_device, NULL),
	      -EINVAL, "device_for_each(NULL ctx)");
	CHECK(libnvmf_registry_attr_for_each(NULL, "nvme3", collect_attr, NULL),
	      -EINVAL, "attr_for_each(NULL ctx)");

	/* retrieve: any NULL parameter */
	CHECK(libnvmf_registry_retrieve(ctx, NULL, "owner", &value),
	      -EINVAL, "retrieve(NULL, attr, &value)");
	CHECK(libnvmf_registry_retrieve(ctx, "nvme3", NULL, &value),
	      -EINVAL, "retrieve(device, NULL, &value)");
	CHECK(libnvmf_registry_retrieve(ctx, "nvme3", "owner", NULL),
	      -EINVAL, "retrieve(device, attr, NULL)");

	/* update: NULL device or NULL attr; NULL value is remove-attr, not an error */
	CHECK(libnvmf_registry_update(ctx, NULL, "owner", "stas"),
	      -EINVAL, "update(NULL, attr, value)");
	CHECK(libnvmf_registry_update(ctx, "nvme3", NULL, "stas"),
	      -EINVAL, "update(device, NULL, value)");

	/* delete: NULL device */
	CHECK(libnvmf_registry_delete(ctx, NULL),
	      -EINVAL, "delete(NULL)");

	/* device_for_each: NULL callback */
	CHECK(libnvmf_registry_device_for_each(ctx, NULL, NULL),
	      -EINVAL, "device_for_each(NULL, user_data)");

	/* attr_for_each: NULL device or NULL callback */
	CHECK(libnvmf_registry_attr_for_each(ctx, NULL, collect_attr, NULL),
	      -EINVAL, "attr_for_each(NULL, cback, user_data)");
	CHECK(libnvmf_registry_attr_for_each(ctx, "nvme3", NULL, NULL),
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
static bool test_parallel_writes(struct libnvme_global_ctx *ctx)
{
	char *value = NULL;
	int status;
	bool pass;
	int i;

	printf("test_parallel_writes:\n");

	libnvmf_registry_update(ctx, "nvme10", "owner", "parent");

#define NPROCS 10
	pid_t pids[NPROCS];
	char owner[16];

	for (i = 0; i < NPROCS; i++) {
		pids[i] = fork();
		assert(pids[i] >= 0);
		if (pids[i] == 0) {
			snprintf(owner, sizeof(owner), "child%d", i);
			for (int j = 0; j < 200; j++)
				libnvmf_registry_update(ctx, "nvme10", "owner",
							owner);
			exit(0);
		}
	}

	for (i = 0; i < NPROCS; i++)
		waitpid(pids[i], &status, 0);

	libnvmf_registry_retrieve(ctx, "nvme10", "owner", &value);

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
	libnvmf_registry_delete(ctx, "nvme10");
	return pass;
}

int main(int argc, char *argv[])
{
	struct libnvme_global_ctx *ctx;
	bool pass = true;

	ctx = libnvme_create_global_ctx();
	libnvme_set_logging_file(ctx, stdout);
	libnvme_set_logging_level(ctx, LIBNVME_LOG_DEBUG_VERBOSE, false, false);

	setup_tmpdir(ctx);

	pass &= test_create(ctx);
	pass &= test_update_and_retrieve(ctx);
	pass &= test_special_chars(ctx);
	pass &= test_delete(ctx);
	pass &= test_retrieve_missing(ctx);
	pass &= test_device_for_each(ctx);
	pass &= test_attr_for_each(ctx);
	pass &= test_null_args(ctx);
	pass &= test_parallel_writes(ctx);

	cleanup_tmpdir(ctx);

	libnvme_free_global_ctx(ctx);

	fflush(stdout);
	exit(pass ? EXIT_SUCCESS : EXIT_FAILURE);
}
