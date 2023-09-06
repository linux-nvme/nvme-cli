/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2023 Solidigm.
 *
 * Author: leonardo.da.cunha@solidigm.com
 */

#include "nvme.h"

#define DRIVER_MAX_TX_256K (256 * 1024)

__u8 solidigm_get_vu_uuid_index(struct nvme_dev *dev);
