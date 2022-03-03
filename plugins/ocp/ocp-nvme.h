/*
 * Copyright (C) 2022 Meta Platforms, Inc.
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of  MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * Authors: Arthur Shau <arthurshau@fb.com>,
 *          Wei Zhang <wzhang@fb.com>,
 *   	    Venkat Ramesh <venkatraghavan@fb.com>
 */
#undef CMD_INC_FILE
#define CMD_INC_FILE plugins/ocp/ocp-nvme

#if !defined(OCP_NVME) || defined(CMD_HEADER_MULTI_READ)
#define OCP_NVME

#include "cmd.h"

PLUGIN(NAME("ocp", "OCP cloud SSD extensions", NVME_VERSION),
    COMMAND_LIST(
        ENTRY("smart-add-log", "Retrieve extended SMART Information", ocp_smart_add_log)
        ENTRY("latency-monitor-log", "Get Latency Monitor Log Page", ocp_latency_monitor_log)
    )
);

#endif

#include "define_cmd.h"
