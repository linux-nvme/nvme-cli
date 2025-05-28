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

int sldgm_get_uuid_index(struct nvme_transport_handle *hdl, __u8 *index)
{
	struct nvme_id_uuid_list uuid_list;
	int err = nvme_identify_uuid(hdl, &uuid_list);

	*index = 0;
	if (err)
		return err;

	return sldgm_find_uuid_index(&uuid_list, index);
}

int sldgm_dynamic_telemetry(struct nvme_transport_handle *hdl, bool create,
			    bool ctrl, bool log_page, __u8 mtds,
			    enum nvme_telemetry_da da,
			    struct nvme_telemetry_log **log_buffer,
			    size_t *log_buffer_size)
{
	size_t max_data_tx = (1 << mtds) * NVME_LOG_PAGE_PDU_SIZE;
	int err;

	do {
		err = nvme_get_telemetry_log(hdl, create, ctrl, log_page, max_data_tx, da,
					     log_buffer, log_buffer_size);
		max_data_tx /= 2;
		create = false;
	} while (err == -EPERM && max_data_tx >= NVME_LOG_PAGE_PDU_SIZE);
	return err;
}
