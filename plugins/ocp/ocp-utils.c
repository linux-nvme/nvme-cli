// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2022-2024 Solidigm.
 *
 * Author: leonardo.da.cunha@solidigm.com
 */

#include <unistd.h>
#include <errno.h>
#include "util/types.h"
#include "ocp-nvme.h"
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

int ocp_get_uuid_index(struct nvme_transport_handle *hdl, __u8 *index)
{
	struct nvme_id_uuid_list uuid_list;
	int err;

	*index = 0;

	err = nvme_identify_uuid_list(hdl, &uuid_list);
	if (err)
		return err;

	return ocp_find_uuid_index(&uuid_list, index);
}

int ocp_get_log_simple(struct nvme_transport_handle *hdl,
		       enum ocp_dssd_log_id lid, __u32 len, void *log)
{
	struct nvme_get_log_args args = {
		.log = log,
		.args_size = sizeof(args),
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.lid = (enum nvme_cmd_get_log_lid)lid,
		.len = len,
		.nsid = NVME_NSID_ALL,
		.lsi = NVME_LOG_LSI_NONE,
		.lsp = NVME_LOG_LSP_NONE,
	};

	ocp_get_uuid_index(hdl, &args.uuidx);

	return nvme_get_log_page(hdl, NVME_LOG_PAGE_PDU_SIZE, &args);
}
