/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2022-2024 Solidigm.
 *
 * Author: leonardo.da.cunha@solidigm.com
 */
#include <stdbool.h>

#include <libnvme.h>

/*
 * UUID assigned for OCP.
 */
extern const unsigned char ocp_uuid[NVME_UUID_LEN];

/**
 * ocp_get_uuid_index() - Get OCP UUID index
 * @dev:	nvme device
 * @index:	integer pointer to here to save the index
 *
 * Return: Zero if nvme device has UUID list identify page, or positive result of get uuid list
 *         or negative POSIX error code otherwise.
 */
int ocp_get_uuid_index(struct libnvme_transport_handle *hdl, __u8 *index);

/**
 * ocp_find_uuid_index() - Find OCP UUID index in UUID list
 * @uuid_list:	uuid_list retrieved from Identify UUID List (CNS 0x17)
 * @index:	integer pointer to here to save the index
 *
 * Return: Zero if nvme device has UUID list log page, Negative POSIX error code otherwise.
 */
int ocp_find_uuid_index(struct nvme_id_uuid_list *uuid_list, __u8 *index);

/**
 * ocp_get_log_simple() - Get an OCP log page in one transfer
 * @hdl:	nvme transport handle
 * @lid:	OCP log page identifier
 * @len:	length of @log in bytes
 * @log:	buffer to receive the log page
 * @uuid:	look the OCP UUID index up and request the page with it; when
 *		false the page is requested with UUID index 0, which is what
 *		OCP 1.0 devices and devices misreporting their UUID list need
 *
 * Return: Zero on success, negative POSIX error code or NVMe status otherwise.
 */
int ocp_get_log_simple(struct libnvme_transport_handle *hdl, enum ocp_dssd_log_id lid, __u32 len,
		       void *log, bool uuid);

/**
 * ocp_is_tcg_activity_event() - Determine if persistent event is TCG activity event
 * @pevent_entry_head:	persistent event entry head pointer
 * @el:			Event Length
 * @vsil:		Vendor Specific Information Length
 *
 * Return: true if TCG activity event, false otherwise.
 */
bool ocp_is_tcg_activity_event(struct nvme_persistent_event_entry *pevent_entry_head,
			       __u16 el, __u16 vsil);
