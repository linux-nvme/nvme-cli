// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "cleanup.h"
#include "compiler-attributes.h"
#include "private.h"
#include "registry.h"

static const char *registry_dir(void)
{
	static const char *dir;

	if (!dir) {
		const char *env = getenv("NVME_REGISTRY_DIR");

		dir = env ? env : "/run/nvme/registry";
	}
	return dir;
}

static int ensure_registry_dir(void)
{
	if (mkdir(registry_dir(), 0755) == 0 || errno == EEXIST)
		return 0;
	if (errno != ENOENT)
		return -errno;

	/* Parent /run/nvme missing; create it then retry. */
	if (mkdir("/run/nvme", 0755) < 0 && errno != EEXIST)
		return -errno;
	if (mkdir(registry_dir(), 0755) < 0 && errno != EEXIST)
		return -errno;
	return 0;
}

static int ensure_device_dir(const char *device)
{
	char path[256];
	int ret;

	ret = ensure_registry_dir();
	if (ret)
		return ret;

	if (snprintf(path, sizeof(path), "%s/%s", registry_dir(), device) >=
	    (int)sizeof(path))
		return -ENAMETOOLONG;

	/* EEXIST is success: two concurrent creates race to the same result. */
	if (mkdir(path, 0755) < 0 && errno != EEXIST)
		return -errno;
	return 0;
}

static bool valid_device(const char *device)
{
	const char *p;

	if (!device || strncmp(device, "nvme", 4) != 0)
		return false;
	p = device + 4;
	if (!*p)
		return false;
	for (; *p; p++) {
		if (*p < '0' || *p > '9')
			return false;
	}
	return true;
}

static bool valid_attr(const char *attr)
{
	const char *p;

	if (!attr || !*attr)
		return false;
	for (p = attr; *p; p++) {
		if ((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
		    (*p >= '0' && *p <= '9') || *p == '_' || *p == '-')
			continue;
		return false;
	}
	return true;
}

/*
 * Write @value atomically to the attribute file @attr inside @dir_path.
 *
 * Protocol:
 *   mkostemp ->  <dir_path>/<attr>.tmp.XXXXXX  (random name, O_CLOEXEC)
 *   fchmod   ->  0644
 *   write    ->  value + newline
 *   fsync    ->  tmp file
 *   rename   ->  <dir_path>/<attr>
 *   fsync    ->  directory
 *
 * mkostemp() atomically creates the tmp file with a random suffix, preventing
 * both name prediction and TOCTOU races on the tmp file itself.
 */
static int write_attr_atomic(int dir_fd, const char *dir_path,
			     const char *attr, const char *value)
{
	char tmp_path[512];
	char final_path[512];
	int fd, ret;

	if (!valid_attr(attr))
		return -EINVAL;

	if (snprintf(tmp_path, sizeof(tmp_path), "%s/%s.tmp.XXXXXX",
		     dir_path, attr) >= (int)sizeof(tmp_path))
		return -ENAMETOOLONG;

	if (snprintf(final_path, sizeof(final_path), "%s/%s",
		     dir_path, attr) >= (int)sizeof(final_path))
		return -ENAMETOOLONG;

	if (!value) {
		if (unlinkat(dir_fd, attr, 0) < 0 && errno != ENOENT)
			return -errno;
		fsync(dir_fd);
		return 0;
	}

	fd = mkstemp(tmp_path);
	if (fd < 0)
		return -errno;
	fcntl(fd, F_SETFD, FD_CLOEXEC);

	/* mkstemp() creates with 0600; open to the registry world. */
	fchmod(fd, 0644);

	ret = write(fd, value, strlen(value));
	if (ret < 0) {
		ret = -errno;
		goto err;
	}
	ret = write(fd, "\n", 1);
	if (ret < 0) {
		ret = -errno;
		goto err;
	}
	if (fsync(fd) < 0) {
		ret = -errno;
		goto err;
	}
	close(fd);
	fd = -1;

	if (rename(tmp_path, final_path) < 0) {
		ret = -errno;
		unlink(tmp_path);
		return ret;
	}

	/* Flush the rename to stable storage. */
	fsync(dir_fd);
	return 0;

err:
	close(fd);
	unlink(tmp_path);
	return ret;
}

/*
 * libnvmf_registry_create_instance - Write a registry entry for a freshly connected
 * controller.  Internal; called from the connect path in fabrics.c once the
 * kernel returns instance=N.  Always overwrites any pre-existing entry:
 * instance recycling means an old nvmeN/ directory is stale by definition.
 */
int libnvmf_registry_create_instance(int instance, const char *owner)
{
	char device[32];
	char dir_path[256];
	int dir_fd, ret;

	snprintf(device, sizeof(device), "nvme%d", instance);

	/*
	 * Delete any stale entry unconditionally before creating the new one.
	 * Instance recycling means an old nvmeN/ directory is stale by
	 * definition — any attributes left over from the previous owner (e.g.
	 * a private attribute written via libnvmf_registry_update()) must not
	 * leak into the new entry.  Ignore errors: ENOENT is the common case.
	 */
	libnvmf_registry_delete(device);

	ret = ensure_device_dir(device);
	if (ret)
		return ret;

	if (snprintf(dir_path, sizeof(dir_path), "%s/%s",
		     registry_dir(), device) >= (int)sizeof(dir_path))
		return -ENAMETOOLONG;

	dir_fd = open(dir_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (dir_fd < 0)
		return -errno;

	ret = write_attr_atomic(dir_fd, dir_path, "owner", owner);
	close(dir_fd);
	return ret;
}

int libnvmf_registry_delete_instance(int instance)
{
	char device[32];
	int ret;

	snprintf(device, sizeof(device), "nvme%d", instance);
	ret = libnvmf_registry_delete(device);
	return (ret == -ENOENT) ? 0 : ret;
}

__libnvme_public int libnvmf_registry_retrieve(const char *device,
					       const char *attr, char **value)
{
	char path[256];
	char buf[4096];
	ssize_t n;
	int fd;

	if (!device || !attr || !value)
		return -EINVAL;
	if (!valid_device(device))
		return -EINVAL;

	if (snprintf(path, sizeof(path), "%s/%s/%s",
		     registry_dir(), device, attr) >= (int)sizeof(path))
		return -ENAMETOOLONG;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno;

	n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n < 0)
		return -errno;
	if (n == 0)
		return -ENOENT;

	/* Strip trailing newline. */
	while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r'))
		n--;
	buf[n] = '\0';

	*value = strdup(buf);
	return *value ? 0 : -ENOMEM;
}

__libnvme_public int libnvmf_registry_update(const char *device,
					     const char *attr, const char *value)
{
	char dir_path[256];
	int dir_fd, ret;

	if (!device || !valid_device(device))
		return -EINVAL;

	ret = ensure_device_dir(device);
	if (ret)
		return ret;

	if (snprintf(dir_path, sizeof(dir_path), "%s/%s",
		     registry_dir(), device) >= (int)sizeof(dir_path))
		return -ENAMETOOLONG;

	dir_fd = open(dir_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (dir_fd < 0)
		return -errno;

	ret = write_attr_atomic(dir_fd, dir_path, attr, value);
	close(dir_fd);
	return ret;
}

__libnvme_public int libnvmf_registry_delete(const char *device)
{
	char path[256];
	struct dirent *de;
	int dir_fd, ret = 0;
	DIR *d;

	if (!device || !valid_device(device))
		return -EINVAL;

	if (snprintf(path, sizeof(path), "%s/%s",
		     registry_dir(), device) >= (int)sizeof(path))
		return -ENAMETOOLONG;

	d = opendir(path);
	if (!d)
		return -errno;

	dir_fd = dirfd(d);
	while ((de = readdir(d)) != NULL) {
		if (de->d_name[0] == '.')
			continue;
		if (unlinkat(dir_fd, de->d_name, 0) < 0 && errno != ENOENT)
			ret = -errno;
	}
	closedir(d);

	if (ret)
		return ret;

	if (rmdir(path) < 0 && errno != ENOENT)
		return -errno;
	return 0;
}

__libnvme_public int libnvmf_registry_device_for_each(
		void (*cback)(const char *device, void *user_data),
		void *user_data)
{
	char dev_path[NAME_MAX + 6]; /* "/dev/" + name + NUL */
	struct dirent *de;
	DIR *d;

	if (!cback)
		return -EINVAL;

	d = opendir(registry_dir());
	if (!d) {
		if (errno == ENOENT)
			return 0;
		return -errno;
	}

	while ((de = readdir(d)) != NULL) {
		if (de->d_name[0] == '.')
			continue;

		/*
		 * Only visit directories.  Use stat() as a fallback when
		 * d_type is DT_UNKNOWN (e.g. on some network filesystems).
		 */
		if (de->d_type != DT_DIR) {
			if (de->d_type != DT_UNKNOWN)
				continue;
			char full[512];
			struct stat st;

			snprintf(full, sizeof(full), "%s/%s",
				 registry_dir(), de->d_name);
			if (stat(full, &st) < 0 || !S_ISDIR(st.st_mode))
				continue;
		}

		/* Stale-entry check: skip if the device node is gone. */
		snprintf(dev_path, sizeof(dev_path), "/dev/%s", de->d_name);
		if (access(dev_path, F_OK) != 0)
			continue;

		cback(de->d_name, user_data);
	}
	closedir(d);
	return 0;
}

__libnvme_public int libnvmf_registry_attr_for_each(
		const char *device,
		void (*cback)(const char *attr, const char *value, void *user_data),
		void *user_data)
{
	char dir_path[256];
	struct dirent *de;
	int dir_fd;
	DIR *d;

	if (!device || !cback)
		return -EINVAL;
	if (!valid_device(device))
		return -EINVAL;

	if (snprintf(dir_path, sizeof(dir_path), "%s/%s",
		     registry_dir(), device) >= (int)sizeof(dir_path))
		return -ENAMETOOLONG;

	d = opendir(dir_path);
	if (!d)
		return -errno;

	dir_fd = dirfd(d);
	while ((de = readdir(d)) != NULL) {
		char buf[4096];
		ssize_t n;
		int fd;

		if (de->d_name[0] == '.')
			continue;
		/* Skip in-flight tmp files from concurrent writers. */
		if (strstr(de->d_name, ".tmp."))
			continue;

		fd = openat(dir_fd, de->d_name, O_RDONLY | O_CLOEXEC);
		if (fd < 0)
			continue; /* device may have been removed concurrently */

		n = read(fd, buf, sizeof(buf) - 1);
		close(fd);
		if (n <= 0)
			continue;

		while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r'))
			n--;
		buf[n] = '\0';

		cback(de->d_name, buf, user_data);
	}
	closedir(d);
	return 0;
}
