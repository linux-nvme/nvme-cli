// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Definitions for the NVM Express interface: libnvme/libnvme-mi device
 * wrappers.
 */

#ifndef _NVME_WRAP_H
#define _NVME_WRAP_H

#include "nvme.h"

int nvme_cli_identify(struct nvme_dev *dev, struct nvme_identify_args *args);
int nvme_cli_identify_ctrl(struct nvme_dev *dev, struct nvme_id_ctrl *ctrl);

#endif /* _NVME_WRAP_H */
