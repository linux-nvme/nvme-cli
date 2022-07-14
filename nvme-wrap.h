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
int nvme_cli_identify_ns(struct nvme_dev *dev, __u32 nsid,
			 struct nvme_id_ns *ns);
int nvme_cli_identify_allocated_ns(struct nvme_dev *dev, __u32 nsid,
				   struct nvme_id_ns *ns);
int nvme_cli_identify_active_ns_list(struct nvme_dev *dev, __u32 nsid,
				     struct nvme_ns_list *list);
int nvme_cli_identify_allocated_ns_list(struct nvme_dev *dev, __u32 nsid,
					struct nvme_ns_list *list);

int nvme_cli_get_features(struct nvme_dev *dev,
			  struct nvme_get_features_args *args);

#endif /* _NVME_WRAP_H */
