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

#ifndef _NVME_IOCTL_H_
#define _NVME_IOCTL_H_

#include <linux/nvme_ioctl.h>

#define _NVME_ADMIN_CMD_IDENTIFY_DATA_LEN		4096

int _nvme_ioctl_fd_open(const char *nvme_path, int *fd, char *err_msg);

/*
 * buff should be char[_NVME_ADMIN_CMD_IDENTIFY_DATA_LEN];
 */
int _nvme_ioctl_identify(int fd, uint8_t *buff, uint32_t cdw10, uint32_t nsid,
			 char *err_msg);

#endif	/* End of _NVME_IOCTL_H_ */
