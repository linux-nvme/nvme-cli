// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 SUSE LLC
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <shared/cleanup-util.h>
#include <shared/fs-util.h>
#include <shared/pci-util.h>

static bool write_file(const char *path, const void *buf, size_t len)
{
	FILE *f = fopen(path, "wb");

	if (!f)
		return false;

	if (len && fwrite(buf, 1, len, f) != len) {
		fclose(f);
		return false;
	}

	fclose(f);
	return true;
}

static bool test_read_write32(const char *dir)
{
	char path[PATH_MAX];
	uint32_t val;
	int fd;
	int ret;
	bool pass = true;

	snprintf(path, sizeof(path), "%s/config", dir);
	if (!write_file(path, "\x00\x00\x00\x00\x00\x00\x00\x00", 8)) {
		printf(" - setup: cannot write %s [FAIL]\n", path);
		return false;
	}

	fd = open(path, O_RDWR);
	if (fd < 0) {
		printf(" - setup: cannot open %s [FAIL]\n", path);
		return false;
	}

	ret = shr_pci_config_write32(fd, 0, 0x01020304);
	if (ret) {
		printf(" - write at offset 0: got %d [FAIL]\n", ret);
		pass = false;
	}

	ret = shr_pci_config_read32(fd, 0, &val);
	if (ret || val != 0x01020304) {
		printf(" - read back at offset 0: ret=%d val=%#x [FAIL]\n",
		       ret, val);
		pass = false;
	} else {
		printf(" - read back at offset 0 [PASS]\n");
	}

	ret = shr_pci_config_write32(fd, 4, 0xaabbccdd);
	ret |= shr_pci_config_read32(fd, 4, &val);
	if (ret || val != 0xaabbccdd) {
		printf(" - read back at offset 4: ret=%d val=%#x [FAIL]\n",
		       ret, val);
		pass = false;
	} else {
		printf(" - read back at offset 4 [PASS]\n");
	}

	/* Writing offset 0 must not disturb offset 4, and vice versa. */
	ret = shr_pci_config_read32(fd, 0, &val);
	if (ret || val != 0x01020304) {
		printf(" - offset 0 unaffected by offset 4's write [FAIL]\n");
		pass = false;
	} else {
		printf(" - offset 0 unaffected by offset 4's write [PASS]\n");
	}

	ret = shr_pci_config_read32(fd, 100, &val);
	if (ret != -EIO) {
		printf(" - read past EOF: got %d, want -EIO [FAIL]\n", ret);
		pass = false;
	} else {
		printf(" - read past EOF [PASS]\n");
	}

	close(fd);

	ret = shr_pci_config_read32(-1, 0, &val);
	if (ret != -EBADF) {
		printf(" - read on a closed fd: got %d, want -EBADF [FAIL]\n",
		       ret);
		pass = false;
	} else {
		printf(" - read on a closed fd [PASS]\n");
	}

	return pass;
}

/*
 * Builds a config-space blob with a chain of extended capabilities,
 * terminating the list, and returns its length.
 */
static size_t build_ext_caps(unsigned char *buf, size_t buf_len,
			     const uint16_t *cap_ids, size_t n)
{
	size_t offset = 0x100;
	size_t i;

	memset(buf, 0, buf_len);
	for (i = 0; i < n; i++) {
		size_t next = (i + 1 < n) ? offset + 4 : 0;
		uint32_t header = cap_ids[i] | (1 << 16) |
				  ((uint32_t)next << 20);

		buf[offset + 0] = header & 0xff;
		buf[offset + 1] = (header >> 8) & 0xff;
		buf[offset + 2] = (header >> 16) & 0xff;
		buf[offset + 3] = (header >> 24) & 0xff;
		offset += 4;
	}

	return offset;
}

static bool test_find_ext_cap(const char *dir)
{
	char path[PATH_MAX];
	unsigned char buf[0x100 + 4 * 4] = {0};
	uint16_t chain[] = {0x0005, 0x0001, 0x0003};
	size_t len;
	int fd;
	int ret;
	bool pass = true;

	len = build_ext_caps(buf, sizeof(buf), chain, 3);

	snprintf(path, sizeof(path), "%s/config-caps", dir);
	if (!write_file(path, buf, len)) {
		printf(" - setup: cannot write %s [FAIL]\n", path);
		return false;
	}

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		printf(" - setup: cannot open %s [FAIL]\n", path);
		return false;
	}

	ret = shr_pci_find_ext_cap(fd, 0x0005);
	if (ret != 0x100) {
		printf(" - first entry: got %d, want 0x100 [FAIL]\n", ret);
		pass = false;
	} else {
		printf(" - first entry [PASS]\n");
	}

	ret = shr_pci_find_ext_cap(fd, 0x0003);
	if (ret != 0x100 + 8) {
		printf(" - last entry: got %#x, want %#x [FAIL]\n",
		       ret, 0x100 + 8);
		pass = false;
	} else {
		printf(" - last entry [PASS]\n");
	}

	ret = shr_pci_find_ext_cap(fd, 0x00ff);
	if (ret != -ENOENT) {
		printf(" - absent capability: got %d, want -ENOENT [FAIL]\n",
		       ret);
		pass = false;
	} else {
		printf(" - absent capability [PASS]\n");
	}

	close(fd);

	/* An empty capability list (all zero) reports -ENOENT too, not a
	 * false match on capability ID 0.
	 */
	snprintf(path, sizeof(path), "%s/config-empty", dir);
	memset(buf, 0, sizeof(buf));
	if (!write_file(path, buf, 0x100 + 4)) {
		printf(" - setup: cannot write %s [FAIL]\n", path);
		return false;
	}

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		printf(" - setup: cannot open %s [FAIL]\n", path);
		return false;
	}

	ret = shr_pci_find_ext_cap(fd, 0x0000);
	if (ret != -ENOENT) {
		printf(" - empty list: got %d, want -ENOENT [FAIL]\n", ret);
		pass = false;
	} else {
		printf(" - empty list [PASS]\n");
	}

	close(fd);

	return pass;
}

static bool test_open_class_config(const char *dir)
{
	__cleanup_free char *class_dir = NULL;
	__cleanup_free char *pci_dir = NULL;
	__cleanup_free char *device_link = NULL;
	__cleanup_free char *config_path = NULL;
	int fd;
	bool pass = true;

	/* Mirror a sysfs class directory: <class_dir>/device symlinks to
	 * the PCI device directory, which holds the "config" attribute --
	 * the same layout /sys/class/nvme/<ctrl> has in real sysfs.
	 */
	if (asprintf(&class_dir, "%s/class_dir", dir) < 0 ||
	    asprintf(&pci_dir, "%s/pci_dir", dir) < 0 ||
	    asprintf(&device_link, "%s/device", class_dir) < 0 ||
	    asprintf(&config_path, "%s/config", pci_dir) < 0) {
		printf(" - setup: out of memory [FAIL]\n");
		return false;
	}

	if (mkdir(class_dir, 0700) || mkdir(pci_dir, 0700)) {
		printf(" - setup: cannot create directories [FAIL]\n");
		return false;
	}
	if (symlink("../pci_dir", device_link)) {
		printf(" - setup: cannot create %s [FAIL]\n", device_link);
		return false;
	}
	if (!write_file(config_path, "\xef\xbe\xad\xde", 4)) {
		printf(" - setup: cannot write %s [FAIL]\n", config_path);
		return false;
	}

	fd = shr_pci_open_class_config(class_dir, O_RDONLY);
	if (fd < 0) {
		printf(" - open via class dir: got %d [FAIL]\n", fd);
		pass = false;
	} else {
		uint32_t val;
		int ret = shr_pci_config_read32(fd, 0, &val);

		if (ret || val != 0xdeadbeef) {
			printf(" - class dir content: ret=%d val=%#x [FAIL]\n",
			       ret, val);
			pass = false;
		} else {
			printf(" - open via class dir [PASS]\n");
		}
		close(fd);
	}

	fd = shr_pci_open_class_config("/no/such/class/dir", O_RDONLY);
	if (fd != -ENOENT) {
		printf(" - missing class dir: got %d, want -ENOENT [FAIL]\n",
		       fd);
		pass = false;
	} else {
		printf(" - missing class dir [PASS]\n");
	}

	return pass;
}

int main(void)
{
	char dir[] = "nvme-pci-util-test-XXXXXX";
	bool pass = true;

	if (!mkdtemp(dir)) {
		printf("cannot create a temporary directory\n");
		exit(EXIT_FAILURE);
	}

	pass &= test_read_write32(dir);
	pass &= test_find_ext_cap(dir);
	pass &= test_open_class_config(dir);

	shr_rmdir_recursive(dir);

	fflush(stdout);
	exit(pass ? EXIT_SUCCESS : EXIT_FAILURE);
}
