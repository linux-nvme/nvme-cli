// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <shared/fs-util.h>
#include <shared/machine-id-util.h>

/* Fixed application ID, so the expected value below stays reproducible. */
static const unsigned char app_id[SHR_UUID_LEN] = {
	0x85, 0x3c, 0x32, 0x20, 0xca, 0x64, 0x4d, 0xad,
	0xa0, 0x6f, 0x1d, 0xc7, 0x52, 0xe3, 0x22, 0x63
};

static bool write_machine_id(const char *path, const char *content)
{
	FILE *f = fopen(path, "wb");

	if (!f)
		return false;

	fputs(content, f);
	fclose(f);

	return true;
}

static bool check(const char *path, const char *name, const char *content,
		  int want_ret, const char *want_uuid)
{
	unsigned char out[SHR_UUID_LEN] = {};
	char got_uuid[2 * SHR_UUID_LEN + 1] = {};
	size_t i;
	int ret;

	if (!write_machine_id(path, content)) {
		printf(" - %s: cannot write %s [FAIL]\n", name, path);
		return false;
	}

	ret = shr_machine_id_app_specific(path, app_id, out);
	if (ret != want_ret) {
		printf(" - %s: got %d, want %d [FAIL]\n", name, ret, want_ret);
		return false;
	}

	if (!want_uuid) {
		printf(" - %s [PASS]\n", name);
		return true;
	}

	for (i = 0; i < SHR_UUID_LEN; i++)
		snprintf(got_uuid + i * 2, 3, "%02x", out[i]);

	if (strcmp(got_uuid, want_uuid)) {
		printf(" - %s: got %s, want %s [FAIL]\n", name, got_uuid,
		       want_uuid);
		return false;
	}

	printf(" - %s [PASS]\n", name);

	return true;
}

/*
 * The derivation was checked against systemd on a live machine:
 *
 *   systemd-id128 machine-id --app-specific=853c3220-ca64-4dad-a06f-1dc752e32263
 *
 * produced the same value as this code reading the same /etc/machine-id. The
 * vector below uses a fixed machine ID instead, so the test does not depend
 * on the machine it runs on.
 */
static bool test_known_answer(const char *path)
{
	printf("test_known_answer:\n");

	return check(path, "known answer",
		     "3d1b2f4c5e6a7b8c9d0e1f2a3b4c5d6e\n", 0,
		     "122333a935f5474d9a824507e71c4fb1");
}

static bool test_accepted(const char *path)
{
	bool pass = true;

	printf("test_accepted:\n");

	/* systemd writes the ID without a trailing newline in some images. */
	pass &= check(path, "no trailing newline",
		      "3d1b2f4c5e6a7b8c9d0e1f2a3b4c5d6e", 0,
		      "122333a935f5474d9a824507e71c4fb1");
	pass &= check(path, "uppercase digits",
		      "3D1B2F4C5E6A7B8C9D0E1F2A3B4C5D6E\n", 0,
		      "122333a935f5474d9a824507e71c4fb1");

	return pass;
}

static bool test_rejected(const char *path)
{
	unsigned char out[SHR_UUID_LEN];
	bool pass = true;

	printf("test_rejected:\n");

	pass &= check(path, "empty file", "", -EINVAL, NULL);
	pass &= check(path, "uninitialized", "uninitialized\n", -EINVAL, NULL);
	pass &= check(path, "too short", "3d1b2f4c\n", -EINVAL, NULL);
	pass &= check(path, "not hexadecimal",
		      "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz\n", -EINVAL, NULL);
	pass &= check(path, "all zeros",
		      "00000000000000000000000000000000\n", -EINVAL, NULL);

	unlink(path);
	if (shr_machine_id_app_specific(path, app_id, out) != -ENOENT) {
		printf(" - missing file: wrong error [FAIL]\n");
		pass = false;
	} else {
		printf(" - missing file [PASS]\n");
	}

	return pass;
}

int main(void)
{
	char path[] = "nvme-machine-id-XXXXXX";
	bool pass = true;
	int fd;

	fd = shr_mkstemp(path);
	if (fd < 0) {
		printf("cannot create a temporary file\n");
		exit(EXIT_FAILURE);
	}
	close(fd);

	pass &= test_known_answer(path);
	pass &= test_accepted(path);
	pass &= test_rejected(path);

	unlink(path);

	fflush(stdout);
	exit(pass ? EXIT_SUCCESS : EXIT_FAILURE);
}
