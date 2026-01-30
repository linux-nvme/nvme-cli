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
#include "types.h"

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
	struct nvme_passthru_cmd cmd;
	__u8 uidx;

	ocp_get_uuid_index(hdl, &uidx);
	nvme_init_get_log(&cmd, NVME_NSID_ALL, (enum nvme_cmd_get_log_lid) lid,
			   NVME_CSI_NVM, log, len);
	cmd.cdw14 |= NVME_FIELD_ENCODE(uidx,
				       NVME_LOG_CDW14_UUID_SHIFT,
				       NVME_LOG_CDW14_UUID_MASK);

	return nvme_get_log(hdl, &cmd, false, NVME_LOG_PAGE_PDU_SIZE);
}

bool ocp_is_tcg_activity_event(struct nvme_persistent_event_entry *pevent_entry_head,
			       __u16 el, __u16 vsil)
{
	struct nvme_vs_event_desc *vs_desc =
		(struct nvme_vs_event_desc *)(pevent_entry_head + 1);

	return pevent_entry_head->etype == NVME_PEL_VENDOR_SPECIFIC_EVENT &&
	       pevent_entry_head->ehl == 0x15 && vsil == 0x04 && el == 0x30 &&
	       le16_to_cpu(vs_desc->vsec) == 0x01 &&
	       le16_to_cpu(vs_desc->vsedl) == 0x26 &&
	       vs_desc->vsedt == NVME_PEL_VSEDT_BINARY;
}
