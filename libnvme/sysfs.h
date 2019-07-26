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

#ifndef _NVME_SYSFS_H_
#define _NVME_SYSFS_H_

#include <stdint.h>

#include "ptr_array.h"

int _nvme_ctrl_dev_paths_get(const char ***dev_paths, uint32_t *count,
			     char *err_msg);

void _nvme_ctrl_dev_paths_free(const char **dev_paths, uint32_t count);

#endif	/* End of _NVME_SYSFS_H_ */
