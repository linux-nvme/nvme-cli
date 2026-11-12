/* SPDX-License-Identifier: GPL-2.0-or-later */
#pragma once

#define OCP_GET(value, name) NVME_GET(value, OCP_##name)
#define OCP_SET(value, name) NVME_SET(value, OCP_##name)

enum nvme_ocp_enable_ieee1667_silo {
	NVME_OCP_ENABLE_IEEE1667_SILO_SHIFT	= 31,
	NVME_OCP_ENABLE_IEEE1667_SILO_MASK	= 1,
};

enum nvme_ocp_erri_entry_flags {
	NVME_OCP_ERRI_ENTRY_ENABLE_SHIFT	= 0,
	NVME_OCP_ERRI_ENTRY_ENABLE_MASK		= 1,
	NVME_OCP_ERRI_ENTRY_SINGLE_SHIFT	= 1,
	NVME_OCP_ERRI_ENTRY_SINGLE_MASK		= 1,
};
