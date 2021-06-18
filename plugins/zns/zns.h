#undef CMD_INC_FILE
#define CMD_INC_FILE plugins/zns/zns

#if !defined(ZNS_NVME) || defined(CMD_HEADER_MULTI_READ)
#define ZNS_NVME

#include "cmd.h"

PLUGIN(NAME("zns", "Zoned Namespace Command Set", NVME_VERSION),
	COMMAND_LIST(
		ENTRY("id-ctrl", "Retrieve ZNS controller identification", id_ctrl)
		ENTRY("id-ns", "Retrieve ZNS namespace identification", id_ns)
		ENTRY("zone-mgmt-recv", "Sends the zone management receive command", zone_mgmt_recv)
		ENTRY("zone-mgmt-send", "Sends the zone management send command", zone_mgmt_send)
		ENTRY("report-zones", "Retrieve the Report Zones report", report_zones)
		ENTRY("close-zone", "Closes one or more zones", close_zone)
		ENTRY("finish-zone", "Finishes one or more zones", finish_zone)
		ENTRY("open-zone", "Opens one or more zones", open_zone)
		ENTRY("reset-zone", "Resets one or more zones", reset_zone)
		ENTRY("offline-zone", "Offlines one or more zones", offline_zone)
		ENTRY("set-zone-desc", "Attaches zone descriptor extension data", set_zone_desc)
		ENTRY("zone-append", "Writes data and metadata (if applicable), appended to the end of the requested zone", zone_append)
		ENTRY("changed-zone-list", "Retrieves the changed zone list log", changed_zone_list)
	)
);

#endif

#include "define_cmd.h"

