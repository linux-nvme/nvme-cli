/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2022 Solidigm.
 *
 * Author: leonardo.da.cunha@solidigm.com
 */

#include "nvme.h"

/**
 * ocp_get_uuid_index() - Get OCP UUID index
 * @dev:	nvme device
 * @index:	integer pointer to here to save the index
 * @result:	The command completion result from CQE dword0
 *
 * Return: Zero if nvme device has UUID list log page, or result of get uuid list otherwise.
 */
int ocp_get_uuid_index(struct nvme_dev *dev, int *index);

int ocp_clear_feature(int argc, char **argv, const char *desc, const __u8 fid);
