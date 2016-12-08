#undef CMD_INC_FILE
#define CMD_INC_FILE nvme-builtin

#if !defined(NVME_BUILTIN) || defined(CMD_HEADER_MULTI_READ)
#define NVME_BUILTIN

#include "cmd.h"

COMMAND_LIST(
	ENTRY("list", "List all NVMe devices and namespaces on machine", list)
	ENTRY("id-ctrl", "Send NVMe Identify Controller", id_ctrl)
	ENTRY("id-ns", "Send NVMe Identify Namespace, display structure", id_ns)
	ENTRY("list-ns", "Send NVMe Identify List, display structure", list_ns)
	ENTRY("create-ns", "Creates a namespace with the provided parameters", create_ns)
	ENTRY("delete-ns", "Deletes a namespace from the controller", delete_ns)
	ENTRY("attach-ns", "Attaches a namespace to requested controller(s)", attach_ns)
	ENTRY("detach-ns", "Detaches a namespace from requested controller(s)", detach_ns)
	ENTRY("list-ctrl", "Send NVMe Identify Controller List, display structure", list_ctrl)
	ENTRY("get-ns-id", "Retrieve the namespace ID of opened block device", get_ns_id)
	ENTRY("get-log", "Generic NVMe get log, returns log in raw format", get_log)
	ENTRY("fw-log", "Retrieve FW Log, show it", get_fw_log)
	ENTRY("smart-log", "Retrieve SMART Log, show it", get_smart_log)
	ENTRY("error-log", "Retrieve Error Log, show it", get_error_log)
	ENTRY("get-feature", "Get feature and show the resulting value", get_feature)
	ENTRY("set-feature", "Set a feature and show the resulting value", set_feature)
	ENTRY("format", "Format namespace with new block format", format)
	ENTRY("fw-activate", "Activate new firmware slot", fw_activate)
	ENTRY("fw-download", "Download new firmware", fw_download)
	ENTRY("admin-passthru", "Submit arbitrary admin command, return results", admin_passthru)
	ENTRY("io-passthru", "Submit an arbitrary IO command, return results", io_passthru)
	ENTRY("security-send", "Submit a Security Send command, return results", sec_send)
	ENTRY("security-recv", "Submit a Security Receive command, return results", sec_recv)
	ENTRY("resv-acquire", "Submit a Reservation Acquire, return results", resv_acquire)
	ENTRY("resv-register", "Submit a Reservation Register, return results", resv_register)
	ENTRY("resv-release", "Submit a Reservation Release, return results", resv_release)
	ENTRY("resv-report", "Submit a Reservation Report, return results", resv_report)
	ENTRY("dsm", "Submit a Data Set Management command, return results", dsm)
	ENTRY("flush", "Submit a Flush command, return results", flush)
	ENTRY("compare", "Submit a Compare command, return results", compare)
	ENTRY("read", "Submit a read command, return results", read_cmd)
	ENTRY("write", "Submit a write command, return results", write_cmd)
	ENTRY("write-zeroes", "Submit a write zeroes command, return results", write_zeroes)
	ENTRY("write-uncor", "Submit a write uncorrectable command, return results", write_uncor)
	ENTRY("reset", "Resets the controller", reset)
	ENTRY("subsystem-reset", "Resets the controller", subsystem_reset)
	ENTRY("show-regs", "Shows the controller registers. Requires admin character device", show_registers)
	ENTRY("discover", "Discover NVMeoF subsystems", discover_cmd)
	ENTRY("connect-all", "Discover and Connect to NVMeoF subsystems", connect_all_cmd)
	ENTRY("connect", "Connect to NVMeoF subsystem", connect_cmd)
	ENTRY("disconnect", "Disconnect from NVMeoF subsystem", disconnect_cmd)
);

#endif

#include "define_cmd.h"
