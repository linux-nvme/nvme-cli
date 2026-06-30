// SPDX-License-Identifier: LGPL-2.1-or-later
/**
 * This file is part of libnvme.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 * Authors: Martin Belanger <martin.belanger@dell.com>
 *
 * Unit tests for the NVMe-oF exclusion list (exclusion.c).  Covers the file
 * mode policy (0644, /etc/nvme convention), the read/write round-trip, and the
 * optimistic-concurrency (version token / -ESTALE) save protocol.
 */

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <nvme/lib.h>
#include <nvme/exclusion.h>
#include <nvme/tid.h>

static char tmpdir[256];

static void setup_tmpdir(struct libnvme_global_ctx *ctx)
{
	/* libnvme confines the test base dir to /tmp, so it lives there. */
	snprintf(tmpdir, sizeof(tmpdir), "/tmp/nvme-exclusion-test-XXXXXX");
	assert(mkdtemp(tmpdir) != NULL);
	assert(libnvme_set_test_base_dir(ctx, tmpdir) == 0);
}

static void cleanup_tmpdir(struct libnvme_global_ctx *ctx)
{
	char dropin[512];

	libnvmf_exclusion_delete(ctx, "list");
	libnvmf_exclusion_delete(ctx, "fresh");
	snprintf(dropin, sizeof(dropin), "%s/exclusions.conf.d", tmpdir);
	rmdir(dropin);
	rmdir(tmpdir);
}

/* Return the permission bits of a named drop-in list's file, or 0 if absent. */
static unsigned conf_mode(const char *name)
{
	char path[512];
	struct stat st;

	snprintf(path, sizeof(path), "%s/exclusions.conf.d/%s.conf",
		 tmpdir, name);
	if (stat(path, &st) < 0)
		return 0;
	return st.st_mode & 07777;
}

struct counter {
	int count;
};

static void count_entry(const char *entry, void *user_data)
{
	(void)entry;
	((struct counter *)user_data)->count++;
}

static int entry_count(struct libnvme_global_ctx *ctx, const char *name)
{
	struct counter c = { 0 };

	libnvmf_exclusion_entry_for_each(ctx, name, count_entry, &c);
	return c.count;
}

static bool test_mode_policy(struct libnvme_global_ctx *ctx)
{
	bool pass = true;
	int ret;

	printf("test_mode_policy:\n");

	ret = libnvmf_exclusion_create(ctx, "list");
	if (ret || conf_mode("list") != 0644) {
		printf(" - create ret=%d mode=%04o (want 0644) [FAIL]\n",
		       ret, conf_mode("list"));
		pass = false;
	} else {
		printf(" - create -> 0644 [PASS]\n");
	}

	ret = libnvmf_exclusion_add(ctx, "list", "transport=tcp;traddr=1.2.3.4");
	if (ret || conf_mode("list") != 0644) {
		printf(" - add ret=%d mode=%04o (want 0644) [FAIL]\n",
		       ret, conf_mode("list"));
		pass = false;
	} else {
		printf(" - add preserves 0644 [PASS]\n");
	}

	return pass;
}

static bool test_read_write_roundtrip(struct libnvme_global_ctx *ctx)
{
	char *text = NULL;
	uint64_t ver = 0;
	bool pass = true;
	int ret;

	printf("test_read_write_roundtrip:\n");

	ret = libnvmf_exclusion_read(ctx, "list", &text, &ver);
	if (ret || !text || !ver) {
		printf(" - read ret=%d ver=%llu [FAIL]\n", ret,
		       (unsigned long long)ver);
		free(text);
		return false;
	}
	printf(" - read text (%zu bytes), ver=%llu [PASS]\n",
	       strlen(text), (unsigned long long)ver);

	/* Append an entry to the buffer and write it back with the read version. */
	{
		char buf[4096];

		snprintf(buf, sizeof(buf), "%sexclusion = transport=rdma\n", text);
		ret = libnvmf_exclusion_write(ctx, "list", buf, ver);
	}
	if (ret || conf_mode("list") != 0644) {
		printf(" - write ret=%d mode=%04o [FAIL]\n", ret, conf_mode("list"));
		pass = false;
	} else if (entry_count(ctx, "list") != 2) {
		printf(" - expected 2 entries, got %d [FAIL]\n", entry_count(ctx, "list"));
		pass = false;
	} else {
		printf(" - write back (version matched) -> 2 entries, 0644 [PASS]\n");
	}

	free(text);
	return pass;
}

static bool test_stale_rejected(struct libnvme_global_ctx *ctx)
{
	char *text = NULL;
	uint64_t ver = 0;
	bool pass = true;
	int ret;

	printf("test_stale_rejected:\n");

	ret = libnvmf_exclusion_read(ctx, "list", &text, &ver);
	assert(ret == 0);

	/* First write changes the file; @ver is now stale. */
	ret = libnvmf_exclusion_write(ctx, "list",
				      "[exclusions]\nexclusion = transport=tcp\n", ver);
	if (ret) {
		printf(" - first write ret=%d [FAIL]\n", ret);
		free(text);
		return false;
	}

	/* Second write with the same (now stale) version must be refused. */
	ret = libnvmf_exclusion_write(ctx, "list",
				      "[exclusions]\nexclusion = transport=fc\n", ver);
	if (ret != -ESTALE) {
		printf(" - stale write ret=%d (want -ESTALE=%d) [FAIL]\n",
		       ret, -ESTALE);
		pass = false;
	} else {
		printf(" - stale version rejected with -ESTALE [PASS]\n");
	}

	free(text);
	return pass;
}

static bool test_invalid_entry_rejected(struct libnvme_global_ctx *ctx)
{
	char *text = NULL;
	uint64_t ver = 0;
	bool pass = true;
	int ret;

	printf("test_invalid_entry_rejected:\n");

	ret = libnvmf_exclusion_read(ctx, "list", &text, &ver);
	assert(ret == 0);

	ret = libnvmf_exclusion_write(ctx, "list",
				      "[exclusions]\nexclusion = boguskey=x\n", ver);
	if (ret != -EINVAL) {
		printf(" - invalid write ret=%d (want -EINVAL=%d) [FAIL]\n",
		       ret, -EINVAL);
		pass = false;
	} else {
		printf(" - invalid entry rejected with -EINVAL [PASS]\n");
	}

	free(text);
	return pass;
}

static bool test_missing_then_create(struct libnvme_global_ctx *ctx)
{
	char *text = NULL;
	uint64_t ver = 123; /* must be overwritten to 0 */
	bool pass = true;
	int ret;

	printf("test_missing_then_create:\n");

	ret = libnvmf_exclusion_read(ctx, "fresh", &text, &ver);
	if (ret || !text || text[0] != '\0' || ver != 0) {
		printf(" - read-missing ret=%d ver=%llu text=%p [FAIL]\n",
		       ret, (unsigned long long)ver, (void *)text);
		free(text);
		return false;
	}
	printf(" - missing list reads as empty, ver=0 [PASS]\n");
	free(text);

	/* Writing with version 0 ("expect absent") creates it at 0644. */
	ret = libnvmf_exclusion_write(ctx, "fresh",
				      "[exclusions]\nexclusion = transport=tcp\n", 0);
	if (ret || conf_mode("fresh") != 0644) {
		printf(" - create-via-write ret=%d mode=%04o [FAIL]\n",
		       ret, conf_mode("fresh"));
		pass = false;
	} else {
		printf(" - write(version=0) creates list at 0644 [PASS]\n");
	}

	return pass;
}

static void noop_list(const char *name, void *user_data)
{
	(void)name;
	(void)user_data;
}

static void noop_entry(const char *entry, void *user_data)
{
	(void)entry;
	(void)user_data;
}

static bool test_null_args(struct libnvme_global_ctx *ctx)
{
	char *text = NULL;
	uint64_t ver = 0;
	bool pass = true;
	int ret;

	printf("test_null_args:\n");

	/* NULL ctx is rejected by every public API. */
	if (libnvmf_exclusion_create(NULL, "list") != -EINVAL) {
		printf(" - create(NULL ctx) [FAIL]\n"); pass = false;
	}
	if (libnvmf_exclusion_delete(NULL, "list") != -EINVAL) {
		printf(" - delete(NULL ctx) [FAIL]\n"); pass = false;
	}
	if (libnvmf_exclusion_add(NULL, "list", "transport=tcp") != -EINVAL) {
		printf(" - add(NULL ctx) [FAIL]\n"); pass = false;
	}
	if (libnvmf_exclusion_remove(NULL, "list", "transport=tcp") != -EINVAL) {
		printf(" - remove(NULL ctx) [FAIL]\n"); pass = false;
	}
	if (libnvmf_exclusion_read(NULL, "list", &text, &ver) != -EINVAL) {
		printf(" - read(NULL ctx) [FAIL]\n"); pass = false;
	}
	if (libnvmf_exclusion_write(NULL, "list", "", 0) != -EINVAL) {
		printf(" - write(NULL ctx) [FAIL]\n"); pass = false;
	}
	if (libnvmf_exclusion_list_for_each(NULL, noop_list, NULL) != -EINVAL) {
		printf(" - list_for_each(NULL ctx) [FAIL]\n"); pass = false;
	}
	if (libnvmf_exclusion_entry_for_each(NULL, "list", noop_entry, NULL) != -EINVAL) {
		printf(" - entry_for_each(NULL ctx) [FAIL]\n"); pass = false;
	}
	if (libnvmf_exclusion_match(NULL, NULL) != false) {
		printf(" - match(NULL ctx) [FAIL]\n"); pass = false;
	}
	if (libnvmf_exclusion_entry_valid(NULL, "transport=tcp") != false) {
		printf(" - entry_valid(NULL ctx) [FAIL]\n"); pass = false;
	}

	/* NULL name selects the main list -- a valid target, not an error. */
	ret = libnvmf_exclusion_read(ctx, NULL, &text, &ver);
	if (ret != 0) {
		printf(" - read(NULL name) reads main list [FAIL]\n");
		pass = false;
	}
	free(text);
	text = NULL;
	ret = libnvmf_exclusion_read(ctx, "list", NULL, &ver);
	if (ret != -EINVAL) {
		printf(" - read(NULL text) [FAIL]\n");
		pass = false;
	}
	ret = libnvmf_exclusion_write(ctx, "list", NULL, 0);
	if (ret != -EINVAL) {
		printf(" - write(NULL text) [FAIL]\n");
		pass = false;
	}

	if (pass)
		printf(" - NULL arguments rejected [PASS]\n");
	return pass;
}

/*
 * Matching: an entry excludes a controller when every field the entry sets
 * matches (minimal / subset match); a difference in any set field, or a
 * malformed entry, does not match.
 */
static bool test_match(struct libnvme_global_ctx *ctx)
{
	struct libnvmf_tid *tid;
	bool pass = true;
	int ret;

	printf("test_match:\n");

	ret = libnvmf_exclusion_add(ctx, "matchlist",
				    "transport=tcp;traddr=9.9.9.9;nqn=nqn.a");
	if (ret) {
		printf(" - add failed: %d [FAIL]\n", ret);
		return false;
	}

	/*
	 * A TID matching all of the entry's fields -- plus an extra trsvcid the
	 * entry does not constrain -- is excluded (subset match).
	 */
	tid = libnvmf_tid_from_fields("tcp", "9.9.9.9", "4420", "nqn.a",
				      NULL, NULL, NULL, NULL);
	if (libnvmf_exclusion_match(ctx, tid)) {
		printf(" - subset match → excluded [PASS]\n");
	} else {
		printf(" - subset match → excluded [FAIL]\n");
		pass = false;
	}
	libnvmf_tid_free(tid);

	/* A difference in one constrained field (subsysnqn) → not excluded. */
	tid = libnvmf_tid_from_fields("tcp", "9.9.9.9", "4420", "nqn.other",
				      NULL, NULL, NULL, NULL);
	if (!libnvmf_exclusion_match(ctx, tid)) {
		printf(" - different subsysnqn → not excluded [PASS]\n");
	} else {
		printf(" - different subsysnqn → not excluded [FAIL]\n");
		pass = false;
	}
	libnvmf_tid_free(tid);

	libnvmf_exclusion_delete(ctx, "matchlist");
	return pass;
}

/*
 * Section semantics: entries count only inside [exclusions].  Writing is
 * strict (a stray entry or malformed header is rejected); reading is
 * fail-safe (anything outside the section is skipped, foreign sections are
 * ignored); add repairs a hand-made file that lacks the header.
 */
static bool test_section_semantics(struct libnvme_global_ctx *ctx)
{
	char path[512];
	bool pass = true;
	FILE *f;
	int ret;

	printf("test_section_semantics:\n");

	/* A write with an entry before any section header must be refused. */
	ret = libnvmf_exclusion_write(ctx, "sect",
				      "exclusion = transport=tcp\n", 0);
	if (ret != -EINVAL) {
		printf(" - stray entry ret=%d (want -EINVAL) [FAIL]\n", ret);
		pass = false;
	} else {
		printf(" - entry outside [exclusions] rejected [PASS]\n");
	}

	/* A malformed section header must be refused. */
	ret = libnvmf_exclusion_write(ctx, "sect",
				      "[exclusions\nexclusion = transport=tcp\n", 0);
	if (ret != -EINVAL) {
		printf(" - malformed header ret=%d (want -EINVAL) [FAIL]\n", ret);
		pass = false;
	} else {
		printf(" - malformed section header rejected [PASS]\n");
	}

	/* A foreign section is reserved for the future: accepted, ignored. */
	ret = libnvmf_exclusion_write(ctx, "sect",
				      "[exclusions]\n"
				      "exclusion = transport=tcp;traddr=8.8.8.8\n"
				      "[future]\n"
				      "somekey = x\n", 0);
	if (ret || entry_count(ctx, "sect") != 1) {
		printf(" - foreign section ret=%d count=%d [FAIL]\n",
		       ret, entry_count(ctx, "sect"));
		pass = false;
	} else {
		printf(" - foreign section ignored, 1 entry counted [PASS]\n");
	}

	/* A hand-made file without the header: entries are ignored... */
	snprintf(path, sizeof(path), "%s/exclusions.conf.d/hand.conf", tmpdir);
	f = fopen(path, "w");
	assert(f);
	fputs("exclusion = transport=fc\n", f);
	fclose(f);
	if (entry_count(ctx, "hand") != 0) {
		printf(" - sectionless file count=%d (want 0) [FAIL]\n",
		       entry_count(ctx, "hand"));
		pass = false;
	} else {
		printf(" - sectionless entries skipped on read [PASS]\n");
	}

	/* ...and add repairs the file by opening the section first. */
	ret = libnvmf_exclusion_add(ctx, "hand", "transport=rdma");
	if (ret || entry_count(ctx, "hand") != 1) {
		printf(" - add-to-sectionless ret=%d count=%d [FAIL]\n",
		       ret, entry_count(ctx, "hand"));
		pass = false;
	} else {
		printf(" - add injects [exclusions] before appending [PASS]\n");
	}

	libnvmf_exclusion_delete(ctx, "sect");
	libnvmf_exclusion_delete(ctx, "hand");
	return pass;
}

int main(void)
{
	struct libnvme_global_ctx *ctx;
	bool pass = true;

	ctx = libnvme_create_global_ctx();

	setup_tmpdir(ctx);

	pass &= test_match(ctx);
	pass &= test_mode_policy(ctx);
	pass &= test_read_write_roundtrip(ctx);
	pass &= test_stale_rejected(ctx);
	pass &= test_invalid_entry_rejected(ctx);
	pass &= test_missing_then_create(ctx);
	pass &= test_section_semantics(ctx);
	pass &= test_null_args(ctx);

	cleanup_tmpdir(ctx);

	libnvme_free_global_ctx(ctx);

	fflush(stdout);
	exit(pass ? EXIT_SUCCESS : EXIT_FAILURE);
}
