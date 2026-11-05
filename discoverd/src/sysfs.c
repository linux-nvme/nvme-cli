// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 SUSE LLC
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <shared/cleanup-util.h>
#include <shared/io-util.h>
#include <shared/string-util.h>

#include "sysfs.h"

/* A sysfs attribute fits in one page. */
#define SYSFS_ATTR_MAX 4096

static char *sysfs_root;

int sysfs_set_root(const char *dir)
{
	char *dup = NULL;

	if (dir) {
		dup = strdup(dir);
		if (!dup)
			return -ENOMEM;
	}

	free(sysfs_root);
	sysfs_root = dup;

	return 0;
}

char *sysfs_path(const char *path)
{
	char *p;

	if (asprintf(&p, "%s%s", sysfs_root ? sysfs_root : "", path) < 0)
		return NULL;

	return p;
}

char *sysfs_nvme_path(const char *devname)
{
	char *p;

	if (asprintf(&p, "%s/sys/class/nvme/%s",
		     sysfs_root ? sysfs_root : "", devname) < 0)
		return NULL;

	return p;
}

char *sysfs_nvme_attr(const char *devname, const char *attr)
{
	__cleanup_free char *dir = sysfs_nvme_path(devname);
	__cleanup_free char *path = NULL;
	char buf[SYSFS_ATTR_MAX];
	ssize_t n;
	int fd;

	if (!dir || asprintf(&path, "%s/%s", dir, attr) < 0)
		return NULL;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return NULL;

	n = shr_read_full(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n < 0)
		return NULL;

	// sd_device_get_sysattr_value() drops the trailing newlines too.
	while (n > 0 && buf[n - 1] == '\n')
		n--;
	buf[n] = '\0';

	return strdup(buf);
}

/*
 * Extract a named field from a comma-separated "key=value,..." string such
 * as the address sysattr: "traddr=192.0.2.1,trsvcid=4420,src_addr=10.0.0.1".
 * Returns an allocated string on success, NULL if not found.
 */
static char *extract_addr_field(const char *address, const char *key)
{
	char search[64];
	const char *p, *end;
	size_t len;

	if (!address || !key)
		return NULL;

	snprintf(search, sizeof(search), "%s=", key);
	p = strstr(address, search);
	if (!p)
		return NULL;

	p += strlen(search);
	end = strchr(p, ',');
	len = end ? (size_t)(end - p) : strlen(p);
	if (!len)
		return NULL;

	return strndup(p, len);
}

struct libnvmf_tid *tid_from_sysfs(const char *devname, bool *is_dc)
{
	__cleanup_free char *transport = NULL, *address = NULL;
	__cleanup_free char *subsysnqn = NULL, *hostnqn = NULL;
	__cleanup_free char *hostid = NULL, *host_iface = NULL;
	__cleanup_free char *cntrltype = NULL;
	__cleanup_free char *traddr = NULL, *trsvcid = NULL;
	__cleanup_free char *host_traddr = NULL;
	struct libnvmf_tid *t = NULL;

	if (is_dc)
		*is_dc = false;

	transport = sysfs_nvme_attr(devname, "transport");
	address = sysfs_nvme_attr(devname, "address");
	subsysnqn = sysfs_nvme_attr(devname, "subsysnqn");
	if (!transport || !address || !subsysnqn)
		return NULL;

	hostnqn = sysfs_nvme_attr(devname, "hostnqn");
	hostid = sysfs_nvme_attr(devname, "hostid");
	host_iface = sysfs_nvme_attr(devname, "host_iface");
	cntrltype = sysfs_nvme_attr(devname, "cntrltype");

	traddr = extract_addr_field(address, "traddr");
	trsvcid = extract_addr_field(address, "trsvcid");

	// host_traddr may appear as "src_addr" in some kernels; try both
	host_traddr = extract_addr_field(address, "host_traddr");
	if (!host_traddr)
		host_traddr = extract_addr_field(address, "src_addr");

	if (traddr) {
		bool dc = shr_streq0(cntrltype, "discovery");

		t = tid_new(transport, traddr, trsvcid, subsysnqn,
			    host_traddr, host_iface, hostnqn, hostid, dc);
		if (is_dc)
			*is_dc = dc;
	}

	return t;
}
