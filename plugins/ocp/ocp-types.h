/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef OCP_TYPES_H
#define OCP_TYPES_H

#define OCP_GET(value, name) NVME_GET(value, OCP_##name)
#define OCP_SET(value, name) NVME_SET(value, OCP_##name)

enum nvme_ocp_enable_ieee1667_silo {
	NVME_OCP_ENABLE_IEEE1667_SILO_SHIFT	= 31,
	NVME_OCP_ENABLE_IEEE1667_SILO_MASK	= 1,
};

#endif /* OCP_TYPES_H */
