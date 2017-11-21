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

#include <libnvme/libnvme.h>
#include <stdlib.h>
#include <assert.h>
#include <linux/types.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <linux/nvme_ioctl.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "utils.h"
#include "ioctl.h"

#define _NVME_ADMIN_CMD_IDENTIFY			0x06

static void _nvme_admin_cmd_init(struct nvme_admin_cmd *admin_cmd,
				 uint8_t *buff, uint32_t data_len);

static int _nvme_ioctl_admin_cmd(int fd, struct nvme_admin_cmd *admin_cmd,
				 char *err_msg);

static void _nvme_admin_cmd_init(struct nvme_admin_cmd *admin_cmd,
				 uint8_t *buff, uint32_t data_len)
{
	memset(admin_cmd, 0, sizeof(struct nvme_admin_cmd));
	memset(buff, 0, data_len);

	admin_cmd->opcode = _NVME_ADMIN_CMD_IDENTIFY;
	admin_cmd->addr = (__u64) buff;
	admin_cmd->data_len = (__u32) data_len;
}

static int _nvme_ioctl_admin_cmd(int fd, struct nvme_admin_cmd *admin_cmd,
				 char *err_msg)
{
	int rc = NVME_OK;
	int ioctl_rc = 0;

	ioctl_rc = ioctl(fd, NVME_IOCTL_ADMIN_CMD, admin_cmd);
	if (ioctl_rc != 0) {
		rc = NVME_ERR_BUG;
		_nvme_err_msg_set(err_msg, "BUG: _nvme_ioctl_admin_cmd(): "
				  "ioctl return %d", ioctl_rc);
	}
	return rc;
}

int _nvme_ioctl_fd_open(const char *nvme_path, int *fd, char *err_msg)
{
	int rc = NVME_OK;
	int errno_save = 0;

	assert(nvme_path != NULL);
	assert(strlen(nvme_path) != 0);
	assert(fd != NULL);

	*fd = open(nvme_path, O_RDONLY);
	if (*fd < 0) {
		errno_save = errno;
		if (errno_save == EACCES) {
			_nvme_err_msg_set(err_msg, "Failed to open %s: "
					  "permission deny", nvme_path);
			rc = NVME_ERR_PERMISSION_DENY;
		} else {
			_nvme_err_msg_set(err_msg, "Failed to open %s: %d",
					  nvme_path, errno_save);
			rc = NVME_ERR_BUG;
		}
	}
	return rc;
}

int _nvme_ioctl_identify(int fd, uint8_t *buff, uint32_t cdw10, uint32_t nsid,
			 char *err_msg)
{
	struct nvme_admin_cmd admin_cmd;
	int rc = NVME_OK;

	_nvme_admin_cmd_init(&admin_cmd, buff,
			     _NVME_ADMIN_CMD_IDENTIFY_DATA_LEN);
	admin_cmd.nsid = (__u32) nsid;
	admin_cmd.cdw10 = (__u32) cdw10;
	_good(_nvme_ioctl_admin_cmd(fd, &admin_cmd, err_msg), rc, out);

out:
	if (rc != NVME_OK) {
		memset(buff, 0, _NVME_ADMIN_CMD_IDENTIFY_DATA_LEN);
	}
	return rc;

}
