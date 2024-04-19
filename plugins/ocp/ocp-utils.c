// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2022-2024 Solidigm.
 *
 * Author: leonardo.da.cunha@solidigm.com
 */

#include <unistd.h>
#include <errno.h>
#include "ocp-utils.h"

const unsigned char ocp_uuid[NVME_UUID_LEN] = {
	0xc1, 0x94, 0xd5, 0x5b, 0xe0, 0x94, 0x47, 0x94, 0xa2, 0x1d,
	0x29, 0x99, 0x8f, 0x56, 0xbe, 0x6f };

int ocp_find_uuid_index(struct nvme_id_uuid_list *uuid_list, __u8 *index)
{
	int i = nvme_uuid_find(uuid_list, ocp_uuid);

	*index = 0;
	if (i > 0)
		*index = i;
	else
		return -errno;

	return 0;
}

int ocp_get_uuid_index(struct nvme_dev *dev, __u8 *index)
{
	struct nvme_id_uuid_list uuid_list;
	int err = nvme_identify_uuid(dev_fd(dev), &uuid_list);

	*index = 0;
	if (err)
		return err;

	return ocp_find_uuid_index(&uuid_list, index);
}
