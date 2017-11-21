/*
 * Copyright (C) 2017 Red Hat, Inc.
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; If not, see <http://www.gnu.org/licenses/>.
 *
 * Author: Gris Ge <fge@redhat.com>
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
/* ^ For strerror_r() */
#endif

#include <sys/types.h>
#include <dirent.h>
#include <errno.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <limits.h>

#include <libnvme/libnvme.h>

#include "sysfs.h"
#include "utils.h"
#include "ptr_array.h"

#define _SYSFS_NVME_CLASS_PATH		"/sys/class/nvme"
#define _NVME_DEV_PATH_REGEX		\
	"^/dev/nvme[0-9]\\{1,\\}\\(n[0-9]\\{1,\\}\\)\\{0,1\\}$"

int _nvme_ctrl_dev_paths_get(const char ***dev_paths, uint32_t *count,
			     char *err_msg)
{
	int rc = NVME_OK;
	DIR *dir = NULL;
	struct dirent *dp = NULL;
	int errno_save = 0;
	const char *nvme_ctrl_name = NULL;
	char *dev_path = NULL;
	struct ptr_array *pa = NULL;
	char *tmp_str = NULL;
	uint32_t i = 0;

	assert(dev_paths != NULL);
	assert(count != NULL);

	*dev_paths = NULL;
	*count = 0;

	pa = ptr_array_new(0);
	if (pa == NULL) {
		_nvme_err_msg_set(err_msg, "No memory");
		rc = NVME_ERR_NO_MEMORY;
		goto out;
	}

	dir = opendir(_SYSFS_NVME_CLASS_PATH);
	if (dir == NULL) {
		errno_save = errno;
		if (errno_save != ENOENT) {
			rc = NVME_ERR_BUG;
			_nvme_err_msg_set(err_msg, "Cannot open %s: error %d",
					  _SYSFS_NVME_CLASS_PATH, errno_save);
		}
		goto out;
	}

	do {
		dp = readdir(dir);
		if (dp == NULL)
			break;
		nvme_ctrl_name = dp->d_name;
		if ((nvme_ctrl_name == NULL) ||
		    (strlen(nvme_ctrl_name) == 0) ||
		    (nvme_ctrl_name[0] == '.'))
			continue;
		dev_path = (char *)
			malloc(sizeof(char) * (strlen(nvme_ctrl_name) +
					       strlen("/dev/") + 1));
		_alloc_null_check(err_msg, dev_path, rc, out);
		sprintf(dev_path, "/dev/%s", nvme_ctrl_name);
		/* Check whether /dev/nvme0 exists */
		if (access(dev_path, F_OK) != 0) {
			free(dev_path);
			continue;
		}
		if (ptr_array_insert(pa, dev_path) != 0 ) {
			free(dev_path);
			rc = NVME_ERR_NO_MEMORY;
			_nvme_err_msg_set(err_msg, "NO MEMORY");
			goto out;
		}
	} while(dp != NULL);


out:
	if (dir != NULL)
		closedir(dir);

	if (rc == NVME_OK) {
		if (ptr_array_extract(pa, (void ***) dev_paths, count) != 0) {
			rc = NVME_ERR_NO_MEMORY;
			_nvme_err_msg_set(err_msg, "NO MEMORY");
		}
	} else {
		ptr_array_for_each(pa, i, tmp_str)
			free(tmp_str);
	}
	ptr_array_free(pa);
	return rc;
}

void _nvme_ctrl_dev_paths_free(const char **dev_paths, uint32_t count)
{
	uint32_t i = 0;

	if ((count == 0) || (dev_paths == NULL))
		return;

	for (i = 0; i < count; ++i)
		free((char *) dev_paths[i]);
	free(dev_paths);
}
