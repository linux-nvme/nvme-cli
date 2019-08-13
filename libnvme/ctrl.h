/*
 * Copyright (C) 2017-2019 Red Hat, Inc.
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

#ifndef _NVME_CTRL_H_
#define _NVME_CTRL_H_

#include <libnvme/libnvme.h>

int _nvme_ctrl_get_by_fd(int fd, struct nvme_ctrl **cnt,
			 const char *dev_path, char *err_msg);

#endif	/* End of _NVME_CTRL_H_ */
