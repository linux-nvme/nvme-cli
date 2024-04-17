/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2023-2024 Solidigm.
 *
 * Author: leonardo.da.cunha@solidigm.com
 */

#include "nvme.h"

#define DRIVER_MAX_TX_256K (256 * 1024)

int sldgm_find_uuid_index(struct nvme_id_uuid_list *uuid_list, __u8 *index);
int sldgm_get_uuid_index(struct nvme_dev *dev, __u8 *index);
