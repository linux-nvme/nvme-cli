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
#include "private-fabrics.h"
#include "registry.h"

#define REGISTRY_DIR_DEFAULT RUNDIR "/nvme/registry"

/*
 * Root directory of the registry.  In production this is REGISTRY_DIR_DEFAULT.
 * A ctx test sandbox (libnvme_set_test_base_dir())
 * reroots it to <test_base_dir>/registry; that path is built once and cached in
 * a static.  The cache is safe because the sandbox is a single-process test
 * feature (see the matching note in exclusion.c): a process is either
 * all-production or all-test, so the first call fixes the value for the run.
 */
static const char *registry_dir(struct libnvme_global_ctx *ctx)
{
	static const char *cache;
	static char buf[PATH_MAX];
	int n;

	if (cache)
		return cache;
	if (!ctx->test_base_dir) {
		cache = REGISTRY_DIR_DEFAULT;
		return cache;
	}
	/* Sandbox: test_base_dir is a validated /tmp path; always fits. */
	n = snprintf(buf, sizeof(buf), "%s/registry", ctx->test_base_dir);
	cache = (n > 0 && (size_t)n < sizeof(buf)) ? buf : REGISTRY_DIR_DEFAULT;
	return cache;
}

/*
 * Build "<registry_dir>/<device>" (when @attr is NULL) or
 * "<registry_dir>/<device>/<attr>".  Returns a newly allocated string the
 * caller must free, or NULL on allocation failure.
 */
static char *registry_path(struct libnvme_global_ctx *ctx, const char *device,
			   const char *attr)
{
	char *path = NULL;
	int n;

	if (attr)
		n = asprintf(&path, "%s/%s/%s", registry_dir(ctx),
			     device, attr);
	else
		n = asprintf(&path, "%s/%s", registry_dir(ctx), device);
	return n < 0 ? NULL : path;
}

static int ensure_device_dir(struct libnvme_global_ctx *ctx, const char *device)
{
	__cleanup_free char *path = NULL;
	int ret;

	ret = libnvmf_mkdir_p(registry_dir(ctx), 0755);
	if (ret)
		return ret;

	path = registry_path(ctx, device, NULL);
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
 * Write @value atomically to the attribute file @attr inside @dir_path; a NULL
 * @value removes the attribute.
 *
 * Atomicity comes from never mutating the live file in place: @value is
 * written to a temp file that is then rename(2)'d onto @attr. rename(2) is an
 * atomic replace within a filesystem, so a concurrent reader always sees
 * either the complete old file or the complete new one -- never a half-written
 * value, and with no locking. The directory fsync makes the rename durable
 * across a crash. The random temp name and O_CLOEXEC from libnvmf_mkstemp() are
 * secondary: they prevent name prediction / TOCTOU on the temp file and avoid
 * leaking the fd across an exec.
 *
 * Steps: mkstemp <attr>.tmp.XXXXXX -> fchmod 0644 -> write @value -> rename
 * onto <attr> -> fsync directory.
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

	fd = libnvmf_mkstemp(tmp_path);
	if (fd < 0)
		return fd;

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
static int write_device_attr(struct libnvme_global_ctx *ctx, const char *device,
			     const char *attr, const char *value)
{
	__cleanup_free char *dir_path = NULL;
	int dir_fd, ret;

	ret = ensure_device_dir(ctx, device);
	if (ret)
		return ret;

	dir_path = registry_path(ctx, device, NULL);
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
 * Read the kernel's global uevent sequence number from
 * /sys/kernel/uevent_seqnum.  This monotonic counter is used to stamp a
 * registry entry at connect time so the udev REMOVE rule can tell a stale
 * entry apart from a recycled-and-live one without relying on event ordering
 * (see 70-nvmf-registry.rules).  Returns a newly allocated decimal string the
 * caller must free, or NULL on any failure -- the stamp is best-effort, and a
 * missing stamp simply makes the rule fall back to its device-existence guard.
 */
static char *read_uevent_seqnum(void)
{
	char buf[32];
	ssize_t n;
	int fd;

	fd = open("/sys/kernel/uevent_seqnum", O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return NULL;
	n = read_full(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n <= 0)
		return NULL;

	/* Strip the trailing newline the kernel appends. */
	while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r'))
		n--;
	if (n == 0)
		return NULL;
	buf[n] = '\0';

	return strdup(buf);
}

/*
 * Remove a registry entry directory and its (flat) attribute files.  Shared by
 * libnvmf_registry_delete() and the create_instance() error/cleanup paths.
 * Returns 0 on success, -ENOENT if @path does not exist, or a negative errno.
 */
static int delete_dir(const char *path)
{
	struct dirent *de;
	int dir_fd, ret = 0;
	DIR *d;

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

/*
 * Atomically remove a *visible* registry entry: rename it to a hidden sibling
 * so it vanishes from observers in a single step, then purge the renamed copy
 * at leisure.  This keeps a reader (nvme registry list, another orchestrator)
 * from ever seeing a half-emptied entry.  Returns 0 on success, -ENOENT if
 * @path does not exist, or a negative errno.
 *
 * The udev REMOVE rule deletes entries with a plain "rm -rf", which is not
 * atomic; this guarantee therefore covers only library-driven deletes.
 */
static int delete_dir_atomic(struct libnvme_global_ctx *ctx, const char *path)
{
	__cleanup_free char *trash = NULL;

	if (asprintf(&trash, "%s/.trash.XXXXXX", registry_dir(ctx)) < 0)
		return -ENOMEM;
	if (!mkdtemp(trash))
		return -errno;

	/*
	 * rename() is the atomic check-and-act: don't pre-check existence (a
	 * TOCTOU on @path) — just attempt the move.  If @path is absent (the
	 * common case, e.g. no stale entry to replace) it fails with ENOENT and
	 * we drop the empty temp dir we created.
	 */
	if (rename(path, trash) < 0) {
		int ret = -errno;

		rmdir(trash);
		return ret;
	}
	return delete_dir(trash);
}

/*
 * libnvmf_registry_create_instance - Write a registry entry for a freshly
 * connected controller.  Internal; called from the connect path in fabrics.c
 * once the kernel returns instance=N.  Always overwrites any pre-existing
 * entry: instance recycling means an old nvmeN/ directory is stale by
 * definition.
 *
 * The entry is built in a temporary directory and rename()'d into place, so it
 * is only ever observed complete or absent — never as a directory that exists
 * but is missing its seqnum stamp.  Without this, the udev REMOVE rule could
 * read a just-created entry between the mkdir and the seqnum write, see no
 * stamp, and delete the live entry the library is still populating.
 */
int libnvmf_registry_create_instance(struct libnvme_global_ctx *ctx,
				     int instance, const char *owner)
{
	__cleanup_free char *tmp_dir = NULL;
	__cleanup_free char *final_path = NULL;
	__cleanup_free char *seqnum = NULL;
	char device[32];
	int dir_fd, ret;

	snprintf(device, sizeof(device), "nvme%d", instance);

	final_path = registry_path(ctx, device, NULL);
	if (!final_path)
		return -ENOMEM;

	/* The registry root must exist before mkdtemp() can run inside it. */
	ret = libnvmf_mkdir_p(registry_dir(ctx), 0755);
	if (ret)
		return ret;

	if (asprintf(&tmp_dir, "%s/.%s.tmp.XXXXXX",
		     registry_dir(ctx), device) < 0)
		return -ENOMEM;
	if (!mkdtemp(tmp_dir))
		return -errno;

	/* mkdtemp() creates it 0700; widen to the registry world. */
	if (chmod(tmp_dir, 0755) < 0) {
		ret = -errno;
		goto err;
	}

	dir_fd = open(tmp_dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (dir_fd < 0) {
		ret = -errno;
		goto err;
	}

	/*
	 * Stamp the entry with the current uevent sequence number for the udev
	 * REMOVE rule (see read_uevent_seqnum()).  Best-effort: a missing stamp
	 * just makes the rule fall back to its device-existence guard, so don't
	 * fail the create over it.
	 */
	seqnum = read_uevent_seqnum();
	if (seqnum)
		write_attr_atomic(dir_fd, tmp_dir, "seqnum", seqnum);

	ret = write_attr_atomic(dir_fd, tmp_dir, "owner", owner);
	close(dir_fd);
	if (ret)
		goto err;

	/*
	 * Reveal the fully-populated entry atomically.  Instance recycling
	 * means any pre-existing nvmeN/ is stale, so remove it first: rename()
	 * onto a non-empty directory fails.
	 */
	delete_dir_atomic(ctx, final_path);
	if (rename(tmp_dir, final_path) < 0) {
		ret = -errno;
		goto err;
	}
	return 0;

err:
	delete_dir(tmp_dir);	/* best-effort: don't leak the temp directory */
	return ret;
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

	path = registry_path(ctx, device, attr);
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

	return write_device_attr(ctx, device, attr, value);
}

__libnvme_public int libnvmf_registry_delete(struct libnvme_global_ctx *ctx,
					     const char *device)
{
	__cleanup_free char *path = NULL;

	if (!ctx)
		return -EINVAL;
	if (!device || !valid_device(device))
		return -EINVAL;

	path = registry_path(ctx, device, NULL);
	if (!path)
		return -ENOMEM;

	return delete_dir_atomic(ctx, path);
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

	d = opendir(registry_dir(ctx));
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

	dir_path = registry_path(ctx, device, NULL);
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
