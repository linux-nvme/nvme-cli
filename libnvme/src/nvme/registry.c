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

/*
 * Return the root directory of the registry.  In production this is always
 * "/run/nvme/registry".  The NVME_REGISTRY_DIR override exists solely for unit
 * testing: it lets the test suite run against a throwaway directory under /tmp
 * instead of the production location.  The result is cached on first use.
 */
static const char *registry_dir(void)
{
	static char buf[256];
	static const char *dir;

	if (!dir) {
		const char *env = getenv("NVME_REGISTRY_DIR");

		/*
		 * NVME_REGISTRY_DIR is a test-only override.  The registry
		 * path drives mkdir, writes and a recursive delete, so an
		 * attacker who can inject it into a privileged process must
		 * not redirect those to an arbitrary location.  Confine the
		 * override to /tmp and reject ".." traversal; anything else
		 * falls back to the production directory.
		 *
		 * Copy into a static buffer: getenv()'s pointer can be
		 * invalidated by a later setenv()/putenv().  Truncation is
		 * harmless -- a too-long test path simply won't resolve, and a
		 * malicious value is both truncated and rejected above.
		 */
		if (env && strncmp(env, "/tmp/", 5) == 0 &&
		    !strstr(env, "..")) {
			snprintf(buf, sizeof(buf), "%s", env);
			dir = buf;
		} else {
			dir = "/run/nvme/registry";
		}
	}
	return dir;
}

/*
 * Build "<registry_dir>/<device>" (when @attr is NULL) or
 * "<registry_dir>/<device>/<attr>".  Returns a newly allocated string the
 * caller must free, or NULL on allocation failure.
 */
static char *registry_path(const char *device, const char *attr)
{
	char *path = NULL;
	int n;

	if (attr)
		n = asprintf(&path, "%s/%s/%s", registry_dir(), device, attr);
	else
		n = asprintf(&path, "%s/%s", registry_dir(), device);
	return n < 0 ? NULL : path;
}

/* mkdir -p: create @path and any missing parents. */
static int mkdir_p(const char *path, mode_t mode)
{
	__cleanup_free char *tmp = strdup(path);
	size_t len;
	char *p;

	if (!tmp)
		return -ENOMEM;
	len = strlen(tmp);
	if (len && tmp[len - 1] == '/')
		tmp[len - 1] = '\0';

	for (p = tmp + 1; *p; p++) {
		if (*p != '/')
			continue;
		*p = '\0';
		if (mkdir(tmp, mode) < 0 && errno != EEXIST)
			return -errno;
		*p = '/';
	}
	if (mkdir(tmp, mode) < 0 && errno != EEXIST)
		return -errno;
	return 0;
}

static int ensure_device_dir(const char *device)
{
	__cleanup_free char *path = NULL;
	int ret;

	ret = mkdir_p(registry_dir(), 0755);
	if (ret)
		return ret;

	path = registry_path(device, NULL);
	if (!path)
		return -ENOMEM;

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

static int write_all(int fd, const char *buf, size_t len)
{
	while (len) {
		ssize_t w = write(fd, buf, len);

		if (w < 0) {
			if (errno == EINTR)
				continue;
			return -errno;
		}
		if (w == 0)
			return -EIO;
		buf += w;
		len -= w;
	}
	return 0;
}

/*
 * read() up to @count bytes into @buf, retrying on EINTR.  Returns the number
 * of bytes read (possibly short, at EOF) or a negative errno.
 */
static ssize_t read_full(int fd, char *buf, size_t count)
{
	size_t off = 0;

	while (off < count) {
		ssize_t r = read(fd, buf + off, count - off);

		if (r < 0) {
			if (errno == EINTR)
				continue;
			return -errno;
		}
		if (r == 0)
			break;
		off += r;
	}
	return off;
}

/*
 * Read the attribute file open at @fd into a newly allocated, NUL-terminated
 * string with the trailing newline stripped.  On success sets *out (the caller
 * frees) and returns 0.  Returns -ENOENT for an empty file, or a negative
 * errno on failure.
 */
static int read_attr_fd(int fd, char **out)
{
	struct stat st;
	char *val;
	ssize_t n;

	if (fstat(fd, &st) < 0)
		return -errno;
	if (st.st_size == 0)
		return -ENOENT;

	val = malloc(st.st_size + 1);
	if (!val)
		return -ENOMEM;

	n = read_full(fd, val, st.st_size);
	if (n < 0) {
		free(val);
		return n;
	}

	while (n > 0 && (val[n - 1] == '\n' || val[n - 1] == '\r'))
		n--;
	val[n] = '\0';
	*out = val;
	return 0;
}

/*
 * Write @value atomically to the attribute file @attr inside @dir_path.
 *
 * Protocol:
 *   mkostemp ->  <dir_path>/<attr>.tmp.XXXXXX  (random name, O_CLOEXEC)
 *   fchmod   ->  0644
 *   write    ->  value + newline
 *   rename   ->  <dir_path>/<attr>
 *   fsync    ->  directory
 *
 * mkostemp() atomically creates the tmp file with a random suffix, preventing
 * both name prediction and TOCTOU races on the tmp file itself.  Builds without
 * _GNU_SOURCE fall back to mkstemp() + fcntl(FD_CLOEXEC) (see below).  A NULL
 * @value removes the attribute.
 */
static int write_attr_atomic(int dir_fd, const char *dir_path,
			     const char *attr, const char *value)
{
	__cleanup_free char *tmp_path = NULL;
	__cleanup_free char *final_path = NULL;
	int fd, ret;

	if (!valid_attr(attr))
		return -EINVAL;

	if (!value) {
		if (unlinkat(dir_fd, attr, 0) < 0 && errno != ENOENT)
			return -errno;
		fsync(dir_fd);
		return 0;
	}

	if (asprintf(&final_path, "%s/%s", dir_path, attr) < 0)
		return -ENOMEM;
	if (asprintf(&tmp_path, "%s/%s.tmp.XXXXXX", dir_path, attr) < 0)
		return -ENOMEM;

	/*
	 * mkostemp() sets O_CLOEXEC atomically but its glibc declaration is
	 * gated behind _GNU_SOURCE; fall back to mkstemp() + fcntl() where
	 * _GNU_SOURCE is not defined (e.g. the musl-style CI build).
	 */
#ifdef _GNU_SOURCE
	fd = mkostemp(tmp_path, O_CLOEXEC);
	if (fd < 0)
		return -errno;
#else
	fd = mkstemp(tmp_path);
	if (fd < 0)
		return -errno;
	if (fcntl(fd, F_SETFD, FD_CLOEXEC) < 0) {
		ret = -errno;
		goto err;
	}
#endif

	/* the temp file is created with 0600; open it to the registry world. */
	if (fchmod(fd, 0644) < 0) {
		ret = -errno;
		goto err;
	}

	ret = write_all(fd, value, strlen(value));
	if (ret)
		goto err;
	ret = write_all(fd, "\n", 1);
	if (ret)
		goto err;
	close(fd);

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
 * Open the directory for @device (creating it if needed) and write @attr=@value
 * atomically.  Shared by the create and update paths.
 */
static int write_device_attr(const char *device, const char *attr,
			     const char *value)
{
	__cleanup_free char *dir_path = NULL;
	int dir_fd, ret;

	ret = ensure_device_dir(device);
	if (ret)
		return ret;

	dir_path = registry_path(device, NULL);
	if (!dir_path)
		return -ENOMEM;

	dir_fd = open(dir_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (dir_fd < 0)
		return -errno;

	ret = write_attr_atomic(dir_fd, dir_path, attr, value);
	close(dir_fd);
	return ret;
}

/*
 * libnvmf_registry_create_instance - Write a registry entry for a freshly
 * connected controller.  Internal; called from the connect path in fabrics.c
 * once the kernel returns instance=N.  Always overwrites any pre-existing
 * entry: instance recycling means an old nvmeN/ directory is stale by
 * definition.
 */
int libnvmf_registry_create_instance(struct libnvme_global_ctx *ctx,
				     int instance, const char *owner)
{
	char device[32];

	snprintf(device, sizeof(device), "nvme%d", instance);

	/*
	 * Delete any stale entry unconditionally before creating the new one.
	 * Instance recycling means an old nvmeN/ directory is stale by
	 * definition — any attributes left over from the previous owner (e.g.
	 * a private attribute written via libnvmf_registry_update()) must not
	 * leak into the new entry.  Ignore errors: ENOENT is the common case.
	 */
	libnvmf_registry_delete(ctx, device);

	return write_device_attr(device, "owner", owner);
}

int libnvmf_registry_delete_instance(struct libnvme_global_ctx *ctx,
				     int instance)
{
	char device[32];
	int ret;

	snprintf(device, sizeof(device), "nvme%d", instance);
	ret = libnvmf_registry_delete(ctx, device);
	return (ret == -ENOENT) ? 0 : ret;
}

__libnvme_public int libnvmf_registry_retrieve(struct libnvme_global_ctx *ctx,
					       const char *device,
					       const char *attr, char **value)
{
	__cleanup_free char *path = NULL;
	int fd, ret;

	if (!ctx)
		return -EINVAL;
	if (!device || !attr || !value)
		return -EINVAL;
	if (!valid_device(device))
		return -EINVAL;

	path = registry_path(device, attr);
	if (!path)
		return -ENOMEM;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno;

	ret = read_attr_fd(fd, value);
	close(fd);
	return ret;
}

__libnvme_public int libnvmf_registry_attr_equal(struct libnvme_global_ctx *ctx,
						 const char *device,
						 const char *attr,
						 const char *value)
{
	char *stored = NULL;
	int rc;

	if (!ctx)
		return -EINVAL;

	rc = libnvmf_registry_retrieve(ctx, device, attr, &stored);
	if (rc < 0 && rc != -ENOENT)
		return rc;
	if (!stored)
		rc = value ? 1 : 0;
	else
		rc = (value && !strcmp(stored, value)) ? 0 : 1;
	free(stored);
	return rc;
}

__libnvme_public int libnvmf_registry_update(struct libnvme_global_ctx *ctx,
					     const char *device,
					     const char *attr, const char *value)
{
	if (!ctx)
		return -EINVAL;
	if (!device || !valid_device(device))
		return -EINVAL;

	return write_device_attr(device, attr, value);
}

__libnvme_public int libnvmf_registry_delete(struct libnvme_global_ctx *ctx,
					     const char *device)
{
	__cleanup_free char *path = NULL;
	struct dirent *de;
	int dir_fd, ret = 0;
	DIR *d;

	if (!ctx)
		return -EINVAL;
	if (!device || !valid_device(device))
		return -EINVAL;

	path = registry_path(device, NULL);
	if (!path)
		return -ENOMEM;

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
		struct libnvme_global_ctx *ctx,
		void (*callback)(const char *device, void *user_data),
		void *user_data)
{
	char dev_path[NAME_MAX + 6]; /* "/dev/" + name + NUL */
	struct dirent *de;
	DIR *d;

	if (!ctx)
		return -EINVAL;
	if (!callback)
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
			struct stat st;

			if (de->d_type != DT_UNKNOWN)
				continue;
			/*
			 * Resolve relative to the open directory rather than
			 * building an absolute path: avoids a fixed-size path
			 * buffer (and the format-truncation it invites).
			 */
			if (fstatat(dirfd(d), de->d_name, &st, 0) < 0 ||
			    !S_ISDIR(st.st_mode))
				continue;
		}

		/* Stale-entry check: skip if the device node is gone. */
		snprintf(dev_path, sizeof(dev_path), "/dev/%s", de->d_name);
		if (access(dev_path, F_OK) != 0)
			continue;

		callback(de->d_name, user_data);
	}
	closedir(d);
	return 0;
}

__libnvme_public int libnvmf_registry_attr_for_each(
		struct libnvme_global_ctx *ctx,
		const char *device,
		void (*callback)(const char *attr, const char *value,
				 void *user_data),
		void *user_data)
{
	__cleanup_free char *dir_path = NULL;
	struct dirent *de;
	int dir_fd;
	DIR *d;

	if (!ctx)
		return -EINVAL;
	if (!device || !callback)
		return -EINVAL;
	if (!valid_device(device))
		return -EINVAL;

	dir_path = registry_path(device, NULL);
	if (!dir_path)
		return -ENOMEM;

	d = opendir(dir_path);
	if (!d)
		return -errno;

	dir_fd = dirfd(d);
	while ((de = readdir(d)) != NULL) {
		__cleanup_free char *val = NULL;
		int fd, rc;

		if (de->d_name[0] == '.')
			continue;
		/* Skip in-flight tmp files from concurrent writers. */
		if (strstr(de->d_name, ".tmp."))
			continue;

		fd = openat(dir_fd, de->d_name, O_RDONLY | O_CLOEXEC);
		if (fd < 0)
			continue; /* device may have been removed concurrently */

		rc = read_attr_fd(fd, &val);
		close(fd);
		if (rc == 0)
			callback(de->d_name, val, user_data);
	}
	closedir(d);
	return 0;
}
