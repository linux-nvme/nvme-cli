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
#include <libgen.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <json.h>

#include "cleanup.h"
#include "compiler-attributes.h"
#include "private.h"
#include "registry.h"

static DEFINE_CLEANUP_FUNC(cleanup_json_object, struct json_object *,
			    json_object_put)
#define __cleanup_json	__cleanup(cleanup_json_object)

/*
 * __libnvme_weak allows test binaries to override this function with a strong
 * definition that returns a temporary directory, redirecting all registry I/O
 * away from /run/nvme/registry without any runtime conditionals in production
 * code.
 */
__libnvme_weak const char *registry_dir(void)
{
	return "/run/nvme/registry";
}

static int ensure_registry_dir(void)
{
	__cleanup_free char *dir_copy = NULL;

	if (mkdir(registry_dir(), 0755) == 0 || errno == EEXIST)
		return 0;
	if (errno != ENOENT)
		return -errno;

	/* Parent directory is missing; create it then retry. */
	dir_copy = strdup(registry_dir());
	if (!dir_copy)
		return -ENOMEM;
	if (mkdir(dirname(dir_copy), 0755) < 0 && errno != EEXIST)
		return -errno;
	if (mkdir(registry_dir(), 0755) < 0 && errno != EEXIST)
		return -errno;
	return 0;
}

static int write_json_atomic(struct json_object *root, const char *path)
{
	__cleanup_free char *tmp_path = NULL;
	int fd, dir_fd, ret;

	if (asprintf(&tmp_path, "%s.XXXXXX", path) < 0)
		return -ENOMEM;

	fd = mkstemp(tmp_path);
	if (fd < 0)
		return -errno;

	fchmod(fd, 0644);

	ret = json_object_to_fd(fd, root,
				JSON_C_TO_STRING_PRETTY |
				JSON_C_TO_STRING_NOSLASHESCAPE);
	if (ret < 0) {
		close(fd);
		unlink(tmp_path);
		return -EIO;
	}

	if (write(fd, "\n", 1) < 0) {
		ret = -errno;
		close(fd);
		unlink(tmp_path);
		return ret;
	}

	if (fsync(fd) < 0) {
		ret = -errno;
		close(fd);
		unlink(tmp_path);
		return ret;
	}
	close(fd);

	if (rename(tmp_path, path) < 0) {
		ret = -errno;
		unlink(tmp_path);
		return ret;
	}

	dir_fd = open(registry_dir(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (dir_fd >= 0) {
		fsync(dir_fd);
		close(dir_fd);
	}

	return 0;
}

/*
 * libnvmf_registry_create - Write a new registry entry for a freshly
 * connected controller.  Internal; called from the connect path in fabrics.c
 * once the kernel returns instance=N.  Always overwrites any pre-existing
 * entry: instance recycling means an old nvmeN.json is stale by definition.
 */
int libnvmf_registry_create(int instance, const char *owner)
{
	int ret;
	char device[32];
	__cleanup_free char *path = NULL;
	__cleanup_json struct json_object *root = NULL;

	snprintf(device, sizeof(device), "nvme%d", instance);

	ret = ensure_registry_dir();
	if (ret)
		return ret;

	if (asprintf(&path, "%s/%s.json", registry_dir(), device) < 0)
		return -ENOMEM;

	root = json_object_new_object();
	if (!root)
		return -ENOMEM;

	json_object_object_add(root, "device",
			       json_object_new_string(device));
	json_object_object_add(root, "owner",
			       json_object_new_string(owner));

	return write_json_atomic(root, path);
}

__libnvme_public int libnvmf_registry_retrieve(const char *device,
					       const char *key, char **value)
{
	__cleanup_free char *path = NULL;
	__cleanup_json struct json_object *root = NULL;
	struct json_object *val_obj;
	const char *str;

	if (asprintf(&path, "%s/%s.json", registry_dir(), device) < 0)
		return -ENOMEM;

	root = json_object_from_file(path);
	if (!root)
		return -ENOENT;

	if (!json_object_object_get_ex(root, key, &val_obj))
		return -ENOENT;

	str = json_object_get_string(val_obj);
	if (!str)
		return -ENOENT;

	*value = strdup(str);
	return *value ? 0 : -ENOMEM;
}

__libnvme_public int libnvmf_registry_update(const char *device,
					     const char *key, const char *value)
{
	__cleanup_free char *path = NULL;
	__cleanup_json struct json_object *root = NULL;
	int ret;

	ret = ensure_registry_dir();
	if (ret)
		return ret;

	if (asprintf(&path, "%s/%s.json", registry_dir(), device) < 0)
		return -ENOMEM;

	root = json_object_from_file(path);
	if (!root) {
		root = json_object_new_object();
		if (!root)
			return -ENOMEM;
		json_object_object_add(root, "device",
				       json_object_new_string(device));
	}

	json_object_object_add(root, key, json_object_new_string(value));

	return write_json_atomic(root, path);
}

__libnvme_public int libnvmf_registry_delete(const char *device)
{
	__cleanup_free char *path = NULL;

	if (asprintf(&path, "%s/%s.json", registry_dir(), device) < 0)
		return -ENOMEM;

	if (unlink(path) < 0)
		return -errno;

	return 0;
}

__libnvme_public int libnvmf_registry_for_each(
		void (*cback)(const char *device, const char *owner,
			      void *user_data),
		void *user_data)
{
	char dev_path[64];
	char device[32];
	struct dirent *de;
	DIR *d;

	d = opendir(registry_dir());
	if (!d) {
		if (errno == ENOENT)
			return 0;
		return -errno;
	}

	while ((de = readdir(d)) != NULL) {
		char *owner = NULL;
		size_t stem_len;
		char *dot;

		if (de->d_name[0] == '.')
			continue;
		dot = strrchr(de->d_name, '.');
		if (!dot || strcmp(dot, ".json") != 0)
			continue;
		stem_len = dot - de->d_name;
		if (stem_len >= sizeof(device))
			continue;
		memcpy(device, de->d_name, stem_len);
		device[stem_len] = '\0';

		snprintf(dev_path, sizeof(dev_path), "/dev/%s", device);
		if (access(dev_path, F_OK) != 0)
			continue;

		libnvmf_registry_retrieve(device, "owner", &owner);
		cback(device, owner, user_data);
		free(owner);
	}
	closedir(d);
	return 0;
}
