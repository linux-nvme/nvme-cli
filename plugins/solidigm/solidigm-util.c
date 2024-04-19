// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2023 Solidigm.
 *
 * Author: leonardo.da.cunha@solidigm.com
 */

#include "plugins/ocp/ocp-utils.h"
#include "solidigm-util.h"

__u8 solidigm_get_vu_uuid_index(struct nvme_dev *dev)
{
	int ocp_uuid_index = 0;

	if (ocp_get_uuid_index(dev, &ocp_uuid_index) == 0)
		if (ocp_uuid_index == 2)
			return 1;

	return 0;
}
