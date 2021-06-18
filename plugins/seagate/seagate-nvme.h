/*
 * Do NOT modify or remove this copyright and license
 *
 * Copyright (c) 2017-2018 Seagate Technology LLC and/or its Affiliates, All Rights Reserved
 *
 * ******************************************************************************************
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * \file seagate-nvme.h
 * \brief This file defines the functions and macros to make building a nvme-cli seagate plug-in.
 */

#undef CMD_INC_FILE
#define CMD_INC_FILE plugins/seagate/seagate-nvme

#if !defined(SEAGATE_NVME) || defined(CMD_HEADER_MULTI_READ)
#define SEAGATE_NVME

#include "cmd.h"

PLUGIN(NAME("seagate", "Seagate vendor specific extensions", NVME_VERSION),
	COMMAND_LIST(
		ENTRY("vs-temperature-stats", "Retrieve Seagate temperature statistics ",          temp_stats)
		ENTRY("vs-log-page-sup",      "Retrieve Seagate Supported Log-pages Information ", log_pages_supp)
		ENTRY("vs-smart-add-log",     "Retrieve Seagate extended-SMART Information ",      vs_smart_log)
		ENTRY("vs-pcie-stats",        "Retrieve Seagate PCIe error statistics ",           vs_pcie_error_log)
		ENTRY("clear-pcie-correctable-errors", "Clear Seagate PCIe error statistics  ",    vs_clr_pcie_correctable_errs)
		ENTRY("get-host-tele",       "Retrieve Seagate Host-Initiated Telemetry ",         get_host_tele)
		ENTRY("get-ctrl-tele",       "Retrieve Seagate Controller-Initiated Telemetry ",   get_ctrl_tele)
		ENTRY("vs-internal-log",     "Retrieve Seagate Controller-Initiated Telemetry in binary format",  vs_internal_log)
		ENTRY("plugin-version",      "Shows Seagate plugin's version information ",        seagate_plugin_version)
	)
);

#endif
#include "define_cmd.h"
