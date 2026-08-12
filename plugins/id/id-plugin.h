/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * This file is part of nvme-cli.
 *
 * Copyright (c) 2014-2015, Intel Corporation.
 * Copyright (c) 2026 SUSE Software Solutions
 *
 * Authors: Keith Busch <kbusch@kernel.org>
 *          Daniel Wagner <dwagner@suse.com>
 */

#undef CMD_INC_FILE
#define CMD_INC_FILE plugins/id/id-plugin

#if !defined(ID_PLUGIN) || defined(CMD_HEADER_MULTI_READ)
#define ID_PLUGIN

#include "cmd.h"

PLUGIN(NAME_CORE("id", "Send NVMe Identify commands, show the results", NVME_VERSION),
	COMMAND_LIST(
		ENTRY("ctrl", "Send NVMe Identify Controller", id_ctrl)
		ENTRY("ns", "Send NVMe Identify Namespace, display structure", id_ns)
		ENTRY("ns-granularity", "Send NVMe Identify Namespace Granularity List, display structure",
		      id_ns_granularity)
		ENTRY("ns-lba-format", "Send NVMe Identify Namespace for the specified LBA Format index, "
		      "display structure", id_ns_lba_format)
		ENTRY("ns-list", "Send NVMe Identify List, display structure", list_ns)
		ENTRY("ctrl-list", "Send NVMe Identify Controller List, display structure", list_ctrl)
		ENTRY("nvm-ctrl", "Send NVMe Identify Controller NVM Command Set, display structure",
		      nvm_id_ctrl)
		ENTRY("nvm-ns", "Send NVMe Identify Namespace NVM Command Set, display structure", nvm_id_ns)
		ENTRY("nvm-ns-lba-format", "Send NVMe Identify Namespace NVM Command Set for the specified "
		      "LBA Format index, display structure", nvm_id_ns_lba_format)
		ENTRY("primary-ctrl-caps", "Send NVMe Identify Primary Controller Capabilities",
		      primary_ctrl_caps)
		ENTRY("secondary-ctrl-list", "List Secondary Controllers associated with a Primary Controller",
		      list_secondary_ctrl)
		ENTRY("ns-ind", "I/O Command Set Independent Identify Namespace", cmd_set_independent_id_ns)
		ENTRY("ns-descs", "Send NVMe Namespace Descriptor List, display structure", ns_descs)
		ENTRY("nvmset", "Send NVMe Identify NVM Set List, display structure", id_nvmset)
		ENTRY("uuid", "Send NVMe Identify UUID List, display structure", id_uuid)
		ENTRY("iocs", "Send NVMe Identify I/O Command Set, display structure", id_iocs)
		ENTRY("domain", "Send NVMe Identify Domain List, display structure", id_domain)
		ENTRY("endgrp-list", "Send NVMe Identify Endurance Group List, display structure",
		      id_endurance_grp_list)
	)
);

#endif

#include "define_cmd.h"
