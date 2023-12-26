/* SPDX-License-Identifier: GPL-2.0-or-later */
#undef CMD_INC_FILE
#define CMD_INC_FILE plugins/zns/zns

#if !defined(ZNS_NVME) || defined(CMD_HEADER_MULTI_READ)
#define ZNS_NVME

#include "cmd.h"

PLUGIN(NAME("zns", "Zoned Namespace Command Set", NVME_VERSION),
	COMMAND_LIST(
		ENTRY("list", "List all NVMe devices with Zoned Namespace Command Set support", list)
		ENTRY("id-ctrl", "Send NVMe Identify Zoned Namespace Controller, display structure", id_ctrl)
		ENTRY("id-ns", "Send NVMe Identify Zoned Namespace Namespace, display structure", id_ns)
		ENTRY("report-zones", "Report zones associated to a Zoned Namespace", report_zones)
		ENTRY("reset-zone", "Reset one or more zones", reset_zone)
		ENTRY("close-zone", "Close one or more zones", close_zone)
		ENTRY("finish-zone", "Finish one or more zones", finish_zone)
		ENTRY("open-zone", "Open one or more zones", open_zone)
		ENTRY("offline-zone", "Offline one or more zones", offline_zone)
		ENTRY("set-zone-desc", "Attach zone descriptor extension data to a zone", set_zone_desc)
		ENTRY("zrwa-flush-zone", "Flush LBAs associated with a ZRWA to a zone.", zrwa_flush_zone)
		ENTRY("changed-zone-list", "Retrieve the changed zone list log", changed_zone_list)
		ENTRY("zone-mgmt-recv", "Send the zone management receive command", zone_mgmt_recv)
		ENTRY("zone-mgmt-send", "Send the zone management send command", zone_mgmt_send)
		ENTRY("zone-append", "Append data and metadata (if applicable) to a zone", zone_append)
	)
);

#endif

#include "define_cmd.h"
