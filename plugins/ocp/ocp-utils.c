// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2022 Solidigm.
 *
 * Author: leonardo.da.cunha@solidigm.com
 */

#include "ocp-utils.h"

const unsigned char ocp_uuid[NVME_UUID_LEN] = {
	0xc1, 0x94, 0xd5, 0x5b, 0xe0, 0x94, 0x47, 0x94, 0xa2, 0x1d,
	0x29, 0x99, 0x8f, 0x56, 0xbe, 0x6f };

int ocp_get_uuid_index(struct nvme_dev *dev, int *index)
{
	struct nvme_id_uuid_list uuid_list;
	int err = nvme_identify_uuid(dev_fd(dev), &uuid_list);

	*index = 0;
	if (err)
		return err;

	for (int i = 0; i < NVME_ID_UUID_LIST_MAX; i++) {
		if (memcmp(ocp_uuid, &uuid_list.entry[i].uuid, NVME_UUID_LEN) == 0) {
			*index = i + 1;
			break;
		}
	}
	return err;
}
