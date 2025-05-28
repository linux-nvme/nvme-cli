/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2023-2024 Solidigm.
 *
 * Author: leonardo.da.cunha@solidigm.com
 */

#include "nvme.h"

int sldgm_find_uuid_index(struct nvme_id_uuid_list *uuid_list, __u8 *index);
int sldgm_get_uuid_index(struct nvme_transport_handle *hdl, __u8 *index);
int sldgm_dynamic_telemetry(struct nvme_transport_handle *hdl, bool create, bool ctrl, bool log_page, __u8 mtds,
			    enum nvme_telemetry_da da, struct nvme_telemetry_log **log_buffer,
			    size_t *log_buffer_size);
