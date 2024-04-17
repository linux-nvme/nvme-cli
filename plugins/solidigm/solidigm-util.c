// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2023-2024 Solidigm.
 *
 * Author: leonardo.da.cunha@solidigm.com
 */

#include <errno.h>
#include "solidigm-util.h"

const unsigned char solidigm_uuid[NVME_UUID_LEN] = {
	0x96, 0x19, 0x58, 0x6e, 0xc1, 0x1b, 0x43, 0xad,
	0xaa, 0xaa, 0x65, 0x41, 0x87, 0xf6, 0xbb, 0xb2
};

int sldgm_find_uuid_index(struct nvme_id_uuid_list *uuid_list, __u8 *index)
{
	int i = nvme_uuid_find(uuid_list, solidigm_uuid);

	*index = 0;
	if (i > 0)
		*index = i;
	else
		return -errno;

	return 0;
}

int sldgm_get_uuid_index(struct nvme_dev *dev, __u8 *index)
{
	struct nvme_id_uuid_list uuid_list;
	int err = nvme_identify_uuid(dev_fd(dev), &uuid_list);

	*index = 0;
	if (err)
		return err;

	return sldgm_find_uuid_index(&uuid_list, index);
}
