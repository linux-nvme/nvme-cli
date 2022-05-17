/*
 * Copyright (c) 2022 Solidigm.
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
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA  02110-1301, USA.
 *
 *   Author: leonardo.da.cunha@solidigm.com
 */

#undef CMD_INC_FILE
#define CMD_INC_FILE plugins/solidigm/solidigm-nvme

#if !defined(SOLIDIGM_NVME) || defined(CMD_HEADER_MULTI_READ)
#define SOLIDIGM_NVME

#include "cmd.h"

#define SOLIDIGM_PLUGIN_VERSION "0.1"

PLUGIN(NAME("solidigm", "Solidigm vendor specific extensions", SOLIDIGM_PLUGIN_VERSION),
	COMMAND_LIST(
		ENTRY("smart-log-add", "Retrieve Solidigm SMART Log", get_additional_smart_log)
	)
);

#endif

#include "define_cmd.h"
