/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2022-2024 Solidigm.
 *
 * Author: leonardo.da.cunha@solidigm.com
 */
#include "nvme.h"

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
int ocp_get_uuid_index(struct nvme_transport_handle *hdl, __u8 *index);

/**
 * ocp_find_uuid_index() - Find OCP UUID index in UUID list
 * @uuid_list:	uuid_list retrieved from Identify UUID List (CNS 0x17)
 * @index:	integer pointer to here to save the index
 *
 * Return: Zero if nvme device has UUID list log page, Negative POSIX error code otherwise.
 */
int ocp_find_uuid_index(struct nvme_id_uuid_list *uuid_list, __u8 *index);

int ocp_get_log_simple(struct nvme_transport_handle *hdl, enum ocp_dssd_log_id lid, __u32 len, void *log);
