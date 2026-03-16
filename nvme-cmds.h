/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * This file is part of libnvme.
 * Copyright (c) 2020 Western Digital Corporation or its affiliates.
 *
 * Authors: Keith Busch <keith.busch@wdc.com>
 *	    Chaitanya Kulkarni <chaitanya.kulkarni@wdc.com>
 *	    Daniel Wagner <dwagner@suse.de>
 */

#ifndef NVME_CMDS
#define NVME_CMDS

#include <nvme/cmds.h>
#include <nvme/ioctl.h>
#include <nvme/types.h>

/**
 * nvme_flush() - Send an nvme flush command
 * @hdl:	Transport handle
 * @nsid:	Namespace identifier
 *
 * The Flush command requests that the contents of volatile write cache be made
 * non-volatile.
 *
 * Return: 0 on success, the nvme command status if a response was
 * received (see &enum nvme_status_field) or a negative error otherwise.
 */
static inline int nvme_flush(struct nvme_transport_handle *hdl, __u32 nsid)
{
	struct nvme_passthru_cmd cmd = {};

	cmd.opcode = nvme_cmd_flush;
	cmd.nsid = nsid;

	return nvme_submit_io_passthru(hdl, &cmd);
}

/**
 * nvme_identify() - Submit a generic Identify command
 * @hdl:	Transport handle for the controller.
 * @nsid:	Namespace ID (if applicable to the requested CNS).
 * @csi:	Command Set Identifier.
 * @cns:	Identify Controller or Namespace Structure (CNS) value,
 *		specifying the type of data to be returned.
 * @data:	Pointer to the buffer where the identification data will
 *		be stored.
 * @len:	Length of the data buffer in bytes.
 *
 * The generic wrapper for submitting an Identify command, allowing the host
 * to specify any combination of Identify parameters.
 *
 * Return: 0 on success, the NVMe command status on error, or a negative
 * errno otherwise.
 */
static inline int
nvme_identify(struct nvme_transport_handle *hdl, __u32 nsid, enum nvme_csi csi,
		enum nvme_identify_cns cns, void *data, __u32 len)
{
	struct nvme_passthru_cmd cmd;

	nvme_init_identify(&cmd, nsid, csi, cns, data, len);

	return nvme_submit_admin_passthru(hdl, &cmd);
}

/**
 * nvme_identify_ctrl() - Submit an Identify Controller command
 * @hdl:	Transport handle for the controller.
 * @id:		Pointer to the buffer (&struct nvme_id_ctrl) where the
 *		controller identification data will be stored upon
 *		successful completion.
 *
 * Submits the Identify Controller command to retrieve the controller's
 * capabilities and configuration data.
 *
 * Return: 0 on success, the NVMe command status on error, or a negative
 * errno otherwise.
 */
static inline int
nvme_identify_ctrl(struct nvme_transport_handle *hdl,
		struct nvme_id_ctrl *id)
{
	struct nvme_passthru_cmd cmd;

	nvme_init_identify_ctrl(&cmd, id);

	return nvme_submit_admin_passthru(hdl, &cmd);
}

/**
 * nvme_identify_active_ns_list() - Submit an Identify Active Namespace
 * List command
 * @hdl:	Transport handle for the controller.
 * @nsid:	The Namespace ID to query
 * @ns_list:	Pointer to the buffer (&struct nvme_ns_list) where the
 *		active namespace list will be stored.
 *
 * Submits the Identify command to retrieve a list of active Namespace IDs.
 *
 * Return: 0 on success, the NVMe command status on error, or a negative
 * errno otherwise.
 */
static inline int
nvme_identify_active_ns_list(struct nvme_transport_handle *hdl,
		__u32 nsid, struct nvme_ns_list *ns_list)
{
	struct nvme_passthru_cmd cmd;

	nvme_init_identify_active_ns_list(&cmd, nsid, ns_list);

	return nvme_submit_admin_passthru(hdl, &cmd);
}

/**
 * nvme_identify_ns() - Submit an Identify Namespace command
 * @hdl:	Transport handle for the controller.
 * @nsid:	The Namespace ID to identify.
 * @ns:		Pointer to the buffer (&struct nvme_id_ns) where the namespace
 *		identification data will be stored.
 *
 * Submits the Identify command to retrieve the Namespace Identification
 * data structure for a specified namespace.
 *
 * Return: 0 on success, the NVMe command status on error, or a negative
 * errno otherwise.
 */

static inline int
nvme_identify_ns(struct nvme_transport_handle *hdl,
		__u32 nsid, struct nvme_id_ns *ns)
{
	struct nvme_passthru_cmd cmd;

	nvme_init_identify_ns(&cmd, nsid, ns);

	return nvme_submit_admin_passthru(hdl, &cmd);
}

/**
 * nvme_identify_csi_ns() - Submit a CSI-specific Identify Namespace command
 * @hdl:	Transport handle for the controller.
 * @nsid:	The Namespace ID to identify.
 * @csi:	The Command Set Identifier
 * @uidx:	The UUID Index for the command.
 * @id_ns:	Pointer to the buffer (@struct nvme_nvm_id_ns) where the
 *		CSI-specific namespace identification data will be stored.
 *
 * Submits the Identify command to retrieve Namespace Identification data
 * specific to a Command Set Identifier (CSI).
 *
 * Return: 0 on success, the NVMe command status on error, or a negative
 * errno otherwise.
 */
static inline int
nvme_identify_csi_ns(struct nvme_transport_handle *hdl, __u32 nsid,
		enum nvme_csi csi, __u8 uidx, struct nvme_nvm_id_ns *id_ns)
{
	struct nvme_passthru_cmd cmd;

	nvme_init_identify_csi_ns(&cmd, nsid, csi, uidx, id_ns);

	return nvme_submit_admin_passthru(hdl, &cmd);
}

/**
 * nvme_identify_uuid_list() - Submit an Identify UUID List command
 * @hdl:	Transport handle for the controller.
 * @uuid_list:	Pointer to the buffer (&struct nvme_id_uuid_list) where the
 *		UUID list will be stored.
 *
 * Submits the Identify command to retrieve a list of UUIDs associated
 * with the controller.
 *
 * Return: 0 on success, the NVMe command status on error, or a negative
 * errno otherwise.
 */
static inline int
nvme_identify_uuid_list(struct nvme_transport_handle *hdl,
		struct nvme_id_uuid_list *uuid_list)
{
	struct nvme_passthru_cmd cmd;

	nvme_init_identify_uuid_list(&cmd, uuid_list);

	return nvme_submit_admin_passthru(hdl, &cmd);
}

/**
 * nvme_identify_csi_ns_user_data_format() - Submit an Identify CSI Namespace
 * User Data Format command
 * @hdl:	Transport handle for the controller.
 * @csi:	Command Set Identifier.
 * @fidx:	Format Index, specifying which format entry to return.
 * @uidx:	The UUID Index for the command.
 * @data:	Pointer to the buffer where the format data will be stored.
 *
 * Submits the Identify command to retrieve a CSI-specific Namespace User
 * Data Format data structure.
 *
 * Return: 0 on success, the NVMe command status on error, or a negative
 * errno otherwise.
 */
static inline int
nvme_identify_csi_ns_user_data_format(struct nvme_transport_handle *hdl,
		enum nvme_csi csi, __u16 fidx, __u8 uidx, void *data)
{
	struct nvme_passthru_cmd cmd;

	nvme_init_identify_csi_ns_user_data_format(&cmd, csi, fidx, uidx, data);

	return nvme_submit_admin_passthru(hdl, &cmd);
}

/**
 * nvme_identify_ns_granularity() - Submit an Identify Namespace Granularity
 * List command
 * @hdl:	Transport handle for the controller.
 * @gr_list:	Pointer to the buffer (&struct nvme_id_ns_granularity_list)
 *		where the granularity list will be stored.
 *
 * Submits the Identify command to retrieve the Namespace Granularity List.
 *
 * Return: 0 on success, the NVMe command status on error, or a negative
 * errno otherwise.
 */
static inline int
nvme_identify_ns_granularity(struct nvme_transport_handle *hdl,
		struct nvme_id_ns_granularity_list *gr_list)
{
	struct nvme_passthru_cmd cmd;

	nvme_init_identify_ns_granularity(&cmd, gr_list);

	return nvme_submit_admin_passthru(hdl, &cmd);
}

/**
 * nvme_identify_ns_descs_list() - Submit an Identify Namespace ID Descriptor
 * List command
 * @hdl:	Transport handle for the controller.
 * @nsid:	The Namespace ID to query.
 * @descs:	Pointer to the buffer (&struct nvme_ns_id_desc) where the
 *		descriptor list will be stored.
 *
 * Submits the Identify command to retrieve the Namespace ID Descriptor List
 * for a specified namespace.
 *
 * Return: 0 on success, the NVMe command status on error, or a negative
 * errno otherwise.
 */
static inline int
nvme_identify_ns_descs_list(struct nvme_transport_handle *hdl,
		__u32 nsid, struct nvme_ns_id_desc *descs)
{
	struct nvme_passthru_cmd cmd;

	nvme_init_identify_ns_descs_list(&cmd, nsid, descs);

	return nvme_submit_admin_passthru(hdl, &cmd);
}

/**
 * nvme_zns_identify_ns() - Submit a ZNS-specific Identify Namespace command
 * @hdl:	Transport handle for the controller.
 * @nsid:	The Namespace ID to identify.
 * @data:	Pointer to the buffer (&struct nvme_zns_id_ns) where the ZNS
 *		namespace identification data will be stored.
 *
 * Submits the Identify command to retrieve the Zoned Namespace (ZNS)
 * specific identification data structure for a specified namespace.
 *
 * Return: 0 on success, the NVMe command status on error, or a negative
 * errno otherwise.
 */
static inline int
nvme_zns_identify_ns(struct nvme_transport_handle *hdl,
		__u32 nsid, struct nvme_zns_id_ns *data)
{
	struct nvme_passthru_cmd cmd;

	nvme_init_zns_identify_ns(&cmd, nsid, data);

	return nvme_submit_admin_passthru(hdl, &cmd);
}

/**
 * nvme_get_log_simple() - Retrieve a log page using default parameters
 * @hdl:	Transport handle for the controller.
 * @lid:	Log Identifier, specifying the log page to retrieve
 *		(@enum nvme_cmd_get_log_lid).
 * @data:	Pointer to the buffer where the log page data will be stored.
 * @len:	Length of the data buffer in bytes.
 *
 * Submits the Get Log Page command using the common settings:
 * NVME\_NSID\_ALL, Retain Asynchronous Event (RAE) set to false,
 * and assuming the NVM Command Set.
 *
 * Return: 0 on success, the NVMe command status on error, or a negative
 * errno otherwise.
 */
static inline int
nvme_get_log_simple(struct nvme_transport_handle *hdl,
		enum nvme_cmd_get_log_lid lid, void *data, __u32 len)
{
	struct nvme_passthru_cmd cmd;

	nvme_init_get_log(&cmd, NVME_NSID_ALL, lid, NVME_CSI_NVM, data, len);

	return nvme_get_log(hdl, &cmd, false, NVME_LOG_PAGE_PDU_SIZE);
}

/**
 * nvme_get_log_supported_log_pages() - Retrieve the Supported Log Pages
 * Log Page
 * @hdl:	Transport handle for the controller.
 * @log:	Pointer to the buffer (@struct nvme_supported_log_pages) where
 *		the log page data will be stored.
 *
 * Submits the Get Log Page command specifically for the Supported Log Pages
 * Log.
 *
 * Return: 0 on success, the NVMe command status on error, or a negative
 * errno otherwise.
 */
static inline int
nvme_get_log_supported_log_pages(struct nvme_transport_handle *hdl,
		struct nvme_supported_log_pages *log)
{
	struct nvme_passthru_cmd cmd;

	nvme_init_get_log(&cmd, NVME_NSID_ALL, NVME_LOG_LID_SUPPORTED_LOG_PAGES,
		NVME_CSI_NVM, log, sizeof(*log));

	return nvme_get_log(hdl, &cmd, false, sizeof(*log));
}


/**
 * nvme_get_log_error() - Retrieve the Error Information Log Page
 * @hdl:	Transport handle for the controller.
 * @nsid:	Namespace ID to request the log for (usually NVME_NSID_ALL).
 * @nr_entries:	The maximum number of error log entries to retrieve.
 * @err_log:	Pointer to the buffer (array of @struct nvme_error_log_page)
 *		where the log page data will be stored.
 *
 * This log page describes extended error information for a command that
 * completed with error, or may report an error that is not specific to a
 * particular command. The total size requested is determined by
 * @nr_entries * sizeof(@struct nvme_error_log_page).
 *
 * Return: 0 on success, the NVMe command status on error, or a negative
 * errno otherwise.
 */
static inline int
nvme_get_log_error(struct nvme_transport_handle *hdl, __u32 nsid,
		unsigned int nr_entries, struct nvme_error_log_page *err_log)
{
	struct nvme_passthru_cmd cmd;
	size_t len = sizeof(*err_log) * nr_entries;

	nvme_init_get_log(&cmd, nsid, NVME_LOG_LID_ERROR,
		NVME_CSI_NVM, err_log, len);

	return nvme_get_log(hdl, &cmd, false, len);
}

/**
 * nvme_get_log_fw_slot() - Retrieve the Firmware Slot Information Log Page
 * @hdl:	Transport handle for the controller.
 * @nsid:	Namespace ID to request the log for (use NVME_NSID_ALL).
 * @fw_log:	Pointer to the buffer (@struct nvme_firmware_slot) where the log
 *		page data will be stored.
 *
 * This log page describes the firmware revision stored in each firmware slot
 * supported. The firmware revision is indicated as an ASCII string. The log
 * page also indicates the active slot number.
 *
 * This command is typically issued for the controller scope, thus using
 * NVME_NSID_ALL.
 *
 * Return: 0 on success, the NVMe command status on error, or a negative
 * errno otherwise.
 */
static inline int
nvme_get_log_fw_slot(struct nvme_transport_handle *hdl, __u32 nsid,
		struct nvme_firmware_slot *fw_log)
{
	struct nvme_passthru_cmd cmd;

	nvme_init_get_log(&cmd, nsid, NVME_LOG_LID_FW_SLOT,
		NVME_CSI_NVM, fw_log, sizeof(*fw_log));

	return nvme_get_log(hdl, &cmd, false, sizeof(*fw_log));
}

/**
 * nvme_get_log_changed_ns_list() - Retrieve the Namespace Change Log Page
 * @hdl:	Transport handle for the controller.
 * @nsid:	Namespace ID to request the log for (use NVME_NSID_ALL).
 * @ns_log:	Pointer to the buffer (@struct nvme_ns_list) where the log
 *		page data will be stored.
 *
 * This log page describes namespaces attached to this controller that have
 * changed since the last time the namespace was identified, been added, or
 * deleted.
 *
 * This command is typically issued for the controller scope, thus using
 * NVME_NSID_ALL. The Retain Asynchronous Event (RAE) is true to retain
 * asynchronous events associated with the log page
 *
 * Return: 0 on success, the NVMe command status on error, or a negative
 * errno otherwise.
 */
static inline int
nvme_get_log_changed_ns_list(struct nvme_transport_handle *hdl, __u32 nsid,
		struct nvme_ns_list *ns_log)
{
	struct nvme_passthru_cmd cmd;

	nvme_init_get_log(&cmd, nsid, NVME_LOG_LID_CHANGED_NS,
		NVME_CSI_NVM, ns_log, sizeof(*ns_log));

	return nvme_get_log(hdl, &cmd, true, sizeof(*ns_log));
}

/**
 * nvme_get_log_cmd_effects() - Retrieve the Command Effects Log Page
 * @hdl:	Transport handle for the controller.
 * @csi:	Command Set Identifier for the requested log page.
 * @effects_log:Pointer to the buffer (@struct nvme_cmd_effects_log) where the
 *		log page data will be stored.
 *
 * This log page describes the commands that the controller supports and the
 * effects of those commands on the state of the NVM subsystem.
 *
 * It automatically sets the Log Identifier (LID) and Retain Asynchronous
 * Event (RAE) to false. This command is typically issued for the controller
 * scope, thus using NVME_NSID_ALL.
 *
 * Return: 0 on success, the NVMe command status on error, or a negative
 * errno otherwise.
 */
static inline int
nvme_get_log_cmd_effects(struct nvme_transport_handle *hdl,
		enum nvme_csi csi, struct nvme_cmd_effects_log *effects_log)
{
	struct nvme_passthru_cmd cmd;
	size_t len = sizeof(*effects_log);

	nvme_init_get_log_cmd_effects(&cmd, csi, effects_log);

	return nvme_get_log(hdl, &cmd, false, len);
}

/**
 * nvme_get_log_device_self_test() - Retrieve the Device Self-Test Log Page
 * @hdl:	Transport handle for the controller.
 * @log:	Pointer to the buffer (@struct nvme_self_test_log) where the log
 *		page data will be stored.
 *
 * This log page indicates the status of an in-progress self-test and the
 * percent complete of that operation, and the results of the previous 20
 * self-test operations.
 *
 * It automatically sets the Log Identifier (LID) and Retain Asynchronous
 * Event (RAE) to false. This command is typically issued for the controller
 * scope, thus using NVME_NSID_ALL.
 *
 * Return: 0 on success, the NVMe command status on error, or a negative
 * errno otherwise.
 */
static inline int
nvme_get_log_device_self_test(struct nvme_transport_handle *hdl,
		struct nvme_self_test_log *log)
{
	struct nvme_passthru_cmd cmd;
	size_t len = sizeof(*log);

	nvme_init_get_log(&cmd, NVME_NSID_ALL, NVME_LOG_LID_DEVICE_SELF_TEST,
		NVME_CSI_NVM, log, len);

	return nvme_get_log(hdl, &cmd, false, len);
}

/**
 * nvme_get_log_create_telemetry_host_mcda() - Create the Host Initiated
 * Telemetry Log
 * @hdl:	Transport handle for the controller.
 * @mcda:	Maximum Created Data Area. Specifies the maximum amount of data
 *		that may be returned by the controller.
 * @log:	Pointer to the buffer (@struct nvme_telemetry_log) where the log
 *		page data will be stored.
 *
 * Submits the Get Log Page command to initiate the creation of a Host Initiated
 * Telemetry Log. It sets the Log Identifier (LID) to Telemetry Host and
 * includes the Maximum Created Data Area (MCDA) in the Log Specific Parameter
 * (LSP) field along with the Create bit.
 *
 * It automatically sets Retain Asynchronous Event (RAE) to false.
 *
 * Return: 0 on success, the NVMe command status on error, or a negative
 * errno otherwise.
 */
static inline int
nvme_get_log_create_telemetry_host_mcda(struct nvme_transport_handle *hdl,
		enum nvme_telemetry_da mcda, struct nvme_telemetry_log *log)
{
	struct nvme_passthru_cmd cmd;

	nvme_init_get_log_create_telemetry_host_mcda(&cmd, mcda, log);

	return nvme_get_log(hdl, &cmd, false, sizeof(*log));
}

/**
 * nvme_get_log_create_telemetry_host() - Create the Host Initiated Telemetry
 * Log (Controller Determined Size)
 * @hdl:	Transport handle for the controller.
 * @log:	Pointer to the buffer (@struct nvme_telemetry_log) where the log
 *		page data will be stored.
 *
 * Submits the Get Log Page command to initiate the creation of a Host Initiated
 * Telemetry Log. This is a convenience wrapper that automatically uses the
 * Controller Determined size for the Maximum Created Data Area (MCDA).
 *
 * It automatically sets Retain Asynchronous Event (RAE) to false.
 *
 * Return: 0 on success, the NVMe command status on error, or a negative
 * errno otherwise.
 */
static inline int
nvme_get_log_create_telemetry_host(struct nvme_transport_handle *hdl,
		struct nvme_telemetry_log *log)
{
	struct nvme_passthru_cmd cmd;

	nvme_init_get_log_create_telemetry_host(&cmd, log);

	return nvme_get_log(hdl, &cmd, false, sizeof(*log));
}

/**
 * nvme_get_log_telemetry_host() - Retrieve the Host-Initiated
 * Telemetry Log Page (Retain)
 * @hdl:	Transport handle for the controller.
 * @lpo:	Offset (in bytes) into the telemetry data to start the
 *		retrieval.
 * @log:	Pointer to the buffer where the log page data will be stored.
 * @len:	Length of the buffer provided in @log.
 *
 * Submits the Get Log Page command to retrieve a previously captured
 * Host-Initiated Telemetry Log, starting at a specified offset (@lpo). The Log
 * Specific Parameter (LSP) field is set to indicate the capture should be
 * retained (not deleted after read).
 *
 * It automatically sets the Log Identifier (LID) and Retain Asynchronous Event
 * (RAE) to false.
 *
 * Return: 0 on success, the NVMe command status on error, or a negative
 * errno otherwise.
 */
static inline int
nvme_get_log_telemetry_host(struct nvme_transport_handle *hdl,
		__u64 lpo, void *log, __u32 len)
{
	struct nvme_passthru_cmd cmd;

	nvme_init_get_log_telemetry_host(&cmd, lpo, log, len);

	return nvme_get_log(hdl, &cmd, false, len);
}

/**
 * nvme_get_log_telemetry_ctrl() - Retrieve the Controller-Initiated
 * Telemetry Log Page
 * @hdl:	Transport handle for the controller.
 * @rae:	Retain asynchronous events
 * @lpo:	Offset (in bytes) into the telemetry data to start the
 *		retrieval.
 * @log:	Pointer to the buffer where the log page data will be stored.
 * @len:	Length of the buffer provided in @log.
 *
 * Submits the Get Log Page command specifically for the Controller-Initiated
 * Telemetry Log, allowing retrieval of data starting at a specified offset
 * (@lpo).
 *
 * It automatically sets the Log Identifier (LID).
 *
 * Return: 0 on success, the NVMe command status on error, or a negative
 * errno otherwise.
 */
static inline int
nvme_get_log_telemetry_ctrl(struct nvme_transport_handle *hdl, bool rae,
		__u64 lpo, void *log, __u32 len)
{
	struct nvme_passthru_cmd cmd;

	nvme_init_get_log_telemetry_ctrl(&cmd, lpo, log, len);

	return nvme_get_log(hdl, &cmd, rae, len);
}

/**
 * nvme_get_log_endurance_group() - Retrieve the Endurance Group Log Page
 * @hdl:	Transport handle for the controller.
 * @endgid:	Starting Endurance Group Identifier (ENDGID) to return in
 *		the list.
 * @log:	Pointer to the buffer (@struct nvme_endurance_group_log) where
 *		the log page data will be stored.
 *
 * This log page indicates if an Endurance Group Event has occurred for a
 * particular Endurance Group. The ENDGID is placed in the Log Specific
 * Identifier (LSI) field of the Get Log Page command.
 *
 * It automatically sets the Log Identifier (LID) and Retain Asynchronous
 * Event (RAE) to false. This command is typically issued for the controller
 * scope, thus using NVME_NSID_NONE.
 *
 * Return: 0 on success, the NVMe command status on error, or a negative
 * errno otherwise.
 */
static inline int
nvme_get_log_endurance_group(struct nvme_transport_handle *hdl,
		__u16 endgid, struct nvme_endurance_group_log *log)
{
	struct nvme_passthru_cmd cmd;

	nvme_init_get_log_endurance_group(&cmd, endgid, log);

	return nvme_get_log(hdl, &cmd, false, sizeof(*log));
}

/**
 * nvme_get_log_predictable_lat_nvmset() - Retrieve the Predictable Latency
 * Per NVM Set Log Page
 * @hdl:	Transport handle for the controller.
 * @nvmsetid:	The NVM Set Identifier (NVMSETID) for which to retrieve the log.
 * @log:	Pointer to the buffer (@struct nvme_nvmset_predictable_lat_log)
 *		where the log page data will be stored.
 *
 * Submits the Get Log Page command specifically for the Predictable Latency Per
 * NVM Set Log. The NVMSETID is placed in the Log Specific Identifier (LSI)
 * field of the command.
 *
 * It automatically sets the Log Identifier (LID) and Retain Asynchronous
 * Event (RAE) to false. This command is typically issued for the controller
 * scope, thus using NVME_NSID_NONE.
 *
 * Return: 0 on success, the NVMe command status on error, or a negative
 * errno otherwise.
 */
static inline int
nvme_get_log_predictable_lat_nvmset(struct nvme_transport_handle *hdl,
		__u16 nvmsetid, struct nvme_nvmset_predictable_lat_log *log)
{
	struct nvme_passthru_cmd cmd;

	nvme_init_get_log_predictable_lat_nvmset(&cmd, nvmsetid, log);

	return nvme_get_log(hdl, &cmd, false, sizeof(*log));
}

/**
 * nvme_get_log_predictable_lat_event() - Retrieve the Predictable Latency Event
 * Aggregate Log Page
 * @hdl:	Transport handle for the controller.
 * @rae:	Retain asynchronous events
 * @lpo:	Offset (in bytes) into the log page data to start the retrieval.
 * @log:	Pointer to the buffer where the log page data will be stored.
 * @len:	Length of the buffer provided in @log.
 *
 * Submits the Get Log Page command specifically for the Predictable Latency
 * Event Aggregate Log, allowing retrieval of data starting at a specified
 * offset (@lpo).
 *
 * It automatically sets the Log Identifier (LID) to
 * NVME_LOG_LID_PREDICTABLE_LAT_AGG.
 *
 * Return: 0 on success, the NVMe command status on error, or a negative
 * errno otherwise.
 */
static inline int
nvme_get_log_predictable_lat_event(struct nvme_transport_handle *hdl,
		bool rae, __u64 lpo, void *log, __u32 len)
{
	struct nvme_passthru_cmd cmd;

	nvme_init_get_log_predictable_lat_event(&cmd, lpo, log, len);

	return nvme_get_log(hdl, &cmd, rae, len);
}

/**
 * nvme_get_log_fdp_configurations() - Retrieve the Flexible Data Placement
 * (FDP) Configurations Log Page
 * @hdl:	Transport handle for the controller.
 * @egid:	Endurance Group Identifier (EGID) to return in the
 *		list (used in LSI).
 * @lpo:	Offset (in bytes) into the log page data to start the retrieval.
 * @log:	Pointer to the buffer where the log page data will be stored.
 * @len:	Length of the buffer provided in @log.
 *
 * Submits the Get Log Page command specifically for the FDP Configurations Log.
 * The EGID is placed in the Log Specific Identifier (LSI) field.
 *
 * It automatically sets the Log Identifier (LID) and Retain Asynchronous
 * Event (RAE) to false. This command is typically issued for the controller
 * scope, thus using NVME_NSID_NONE.
 *
 * Return: 0 on success, the NVMe command status on error, or a negative
 * errno otherwise.
 */
static inline int
nvme_get_log_fdp_configurations(struct nvme_transport_handle *hdl,
		__u16 egid, __u64 lpo, void *log, __u32 len)
{
	struct nvme_passthru_cmd cmd;

	nvme_init_get_log_fdp_configurations(&cmd, egid, lpo, log, len);

	return nvme_get_log(hdl, &cmd, false, len);
}

/**
 * nvme_get_log_reclaim_unit_handle_usage() - Retrieve the FDP Reclaim Unit
 * Handle (RUH) Usage Log Page
 * @hdl:	Transport handle for the controller.
 * @egid:	Endurance Group Identifier (EGID) (used in LSI).
 * @lpo:	Offset (in bytes) into the log page data to start the retrieval.
 * @log:	Pointer to the buffer where the log page data will be stored.
 * @len:	Length of the buffer provided in @log.
 *
 * Submits the Get Log Page command specifically for the FDP Reclaim Unit Handle
 * Usage Log. The EGID is placed in the Log Specific Identifier (LSI) field.
 *
 * It automatically sets the Log Identifier (LID) and Retain Asynchronous
 * Event (RAE) to false. This command is typically issued for the controller
 * scope, thus using NVME_NSID_NONE.
 *
 * Return: 0 on success, the NVMe command status on error, or a negative
 * errno otherwise.
 */
static inline int
nvme_get_log_reclaim_unit_handle_usage(struct nvme_transport_handle *hdl,
		__u16 egid, __u64 lpo, void *log, __u32 len)
{
	struct nvme_passthru_cmd cmd;

	nvme_init_get_log_reclaim_unit_handle_usage(&cmd, egid, lpo, log, len);

	return nvme_get_log(hdl, &cmd, false, len);
}

/**
 * nvme_get_log_fdp_stats() - Retrieve the Flexible Data Placement (FDP)
 * Statistics Log Page
 * @hdl:	Transport handle for the controller.
 * @egid:	Endurance Group Identifier (EGID) (used in LSI).
 * @lpo:	Offset (in bytes) into the log page data to start the retrieval.
 * @log:	Pointer to the buffer where the log page data will be stored.
 * @len:	Length of the buffer provided in @log.
 *
 * Submits the Get Log Page command specifically for the FDP Statistics Log.
 * The EGID is placed in the Log Specific Identifier (LSI) field.
 *
 * It automatically sets the Log Identifier (LID) and Retain Asynchronous
 * Event (RAE) to false. This command is typically issued for the controller
 * scope, thus using NVME_NSID_NONE.
 *
 * Return: 0 on success, the NVMe command status on error, or a negative
 * errno otherwise.
 */
static inline int
nvme_get_log_fdp_stats(struct nvme_transport_handle *hdl,
		__u16 egid, __u64 lpo, void *log, __u32 len)
{
	struct nvme_passthru_cmd cmd;

	nvme_init_get_log_fdp_stats(&cmd, egid, lpo, log, len);

	return nvme_get_log(hdl, &cmd, false, len);
}

/**
 * nvme_get_log_fdp_events() - Retrieve the Flexible Data Placement (FDP)
 * Events Log Page
 * @hdl:	Transport handle for the controller.
 * @egid:	Endurance Group Identifier (EGID) (used in LSI).
 * @host_events:Whether to report host-initiated events (true) or
 *		controller-initiated events (false).
 * @lpo:	Offset (in bytes) into the log page data to start the retrieval.
 * @log:	Pointer to the buffer where the log page data will be stored.
 * @len:	Length of the buffer provided in @log.
 *
 * Submits the Get Log Page command specifically for the FDP Events Log.
 * The EGID is placed in the Log Specific Identifier (LSI) field, and the
 * @host_events flag is used to set the Log Specific Parameter (LSP) field.
 *
 * It automatically sets the Log Identifier (LID) and Retain Asynchronous
 * Event (RAE) to false. This command is typically issued for the controller
 * scope, thus using NVME_NSID_NONE.
 *
 * Return: 0 on success, the NVMe command status on error, or a negative
 * errno otherwise.
 */
static inline int
nvme_get_log_fdp_events(struct nvme_transport_handle *hdl,
		__u16 egid, bool host_events, __u64 lpo, void *log, __u32 len)
{
	struct nvme_passthru_cmd cmd;

	nvme_init_get_log_fdp_events(&cmd, egid, host_events, lpo, log, len);

	return nvme_get_log(hdl, &cmd, false, len);
}

/**
 * nvme_get_log_ana() - Retrieve the Asymmetric Namespace Access (ANA) Log Page
 * @hdl:	Transport handle for the controller.
 * @rae:	Retain asynchronous events
 * @lsp:	Log specific parameter, see &enum nvme_get_log_ana_lsp.
 * @lpo:	Offset (in bytes) into the log page data to start the retrieval.
 * @log:	Pointer to the buffer where the log page data will be stored.
 * @len:	Length of the buffer provided in @log.
 *
 * This log consists of a header describing the log and descriptors containing
 * the ANA information for groups that contain namespaces attached to the
 * controller. The @lsp parameter is placed in the Log Specific Parameter field
 * of the command.
 *
 * See &struct nvme_ana_log for the definition of the returned structure.
 *
 * It automatically sets the Log Identifier (LID) to NVME_LOG_LID_ANA.
 *
 * Return: 0 on success, the NVMe command status on error, or a negative
 * errno otherwise.
 */
static inline int
nvme_get_log_ana(struct nvme_transport_handle *hdl, bool rae,
		 enum nvme_log_ana_lsp lsp, __u64 lpo, void *log, __u32 len)
{
	struct nvme_passthru_cmd cmd;

	nvme_init_get_log_ana(&cmd, lsp, lpo, log, len);

	return nvme_get_log(hdl, &cmd, rae, len);
}

/**
 * nvme_get_log_ana_groups() - Retrieve the Asymmetric Namespace Access (ANA)
 * Groups Only Log Page
 * @hdl:	Transport handle for the controller.
 * @rae:	Retain asynchronous events
 * @log:	Pointer to the buffer (@struct nvme_ana_log) where the log page
 *		data will be stored.
 * @len:	Length of the buffer provided in @log.
 *
 * This function retrieves only the ANA Group Descriptors by setting the Log
 * Specific Parameter (LSP) field to NVME_LOG_ANA_LSP_RGO_GROUPS_ONLY. It is a
 * convenience wrapper around nvme_get_log_ana, using a Log Page Offset (LPO) of
 * 0.
 *
 * See &struct nvme_ana_log for the definition of the returned structure.
 *
 * Return: 0 on success, the NVMe command status on error, or a negative
 * errno otherwise.
 */
static inline int
nvme_get_log_ana_groups(struct nvme_transport_handle *hdl, bool rae,
		struct nvme_ana_log *log, __u32 len)
{
	return nvme_get_log_ana(hdl, rae, NVME_LOG_ANA_LSP_RGO_GROUPS_ONLY,
		0, log, len);
}

/**
 * nvme_get_log_lba_status() - Retrieve the LBA Status Log Page
 * @hdl:	Transport handle for the controller.
 * @rae:	Retain asynchronous events
 * @lpo:	Offset (in bytes) into the log page data to start the retrieval.
 * @log:	Pointer to the buffer where the log page data will be stored.
 * @len:	Length of the buffer provided in @log.
 *
 * Submits the Get Log Page command specifically for the LBA Status Log.
 *
 * It automatically sets the Log Identifier (LID) to NVME_LOG_LID_LBA_STATUS.
 *
 * Return: 0 on success, the NVMe command status on error, or a negative
 * errno otherwise.
 */
static inline int
nvme_get_log_lba_status(struct nvme_transport_handle *hdl,
		bool rae, __u64 lpo, void *log, __u32 len)
{
	struct nvme_passthru_cmd cmd;

	nvme_init_get_log_lba_status(&cmd, lpo, log, len);

	return nvme_get_log(hdl, &cmd, rae, len);
}

/**
 * nvme_get_log_endurance_grp_evt() - Retrieve the Endurance Group Event
 * Aggregate Log Page
 * @hdl:	Transport handle for the controller.
 * @rae:	Retain asynchronous events
 * @lpo:	Offset (in bytes) into the log page data to start the retrieval.
 * @log:	Pointer to the buffer where the log page data will be stored.
 * @len:	Length of the buffer provided in @log.
 *
 * Submits the Get Log Page command specifically for the Endurance Group Event
 * Aggregate Log, allowing retrieval of data starting at a specified offset
 * (@lpo).
 *
 * It automatically sets the Log Identifier (LID) to
 * NVME_LOG_LID_ENDURANCE_GRP_EVT.
 *
 * Return: 0 on success, the NVMe command status on error, or a negative
 * errno otherwise.
 */
static inline int
nvme_get_log_endurance_grp_evt(struct nvme_transport_handle *hdl,
		bool rae, __u64 lpo, void *log, __u32 len)
{
	struct nvme_passthru_cmd cmd;

	nvme_init_get_log_endurance_grp_evt(&cmd, lpo, log, len);

	return nvme_get_log(hdl, &cmd, rae, len);
}

/**
 * nvme_get_log_fid_supported_effects() - Retrieve the Feature Identifiers
 * Supported and Effects Log Page
 * @hdl:	Transport handle for the controller.
 * @csi:	Command set identifier, see &enum nvme_csi for known values
 * @log:	Pointer to the buffer (@struct nvme_fid_supported_effects_log)
 *		where the log page data will be stored.
 *
 * Submits the Get Log Page command specifically for the Feature Identifiers
 * Supported and Effects Log. It automatically sets the Log Identifier (LID).
 *
 * Return: 0 on success, the NVMe command status on error, or a negative
 * errno otherwise.
 */
static inline int
nvme_get_log_fid_supported_effects(struct nvme_transport_handle *hdl,
		enum nvme_csi csi, struct nvme_fid_supported_effects_log *log)
{
	struct nvme_passthru_cmd cmd;

	nvme_init_get_log_fid_supported_effects(&cmd, csi, log);

	return nvme_get_log(hdl, &cmd, false, sizeof(*log));
}

/**
 * nvme_get_log_mi_cmd_supported_effects() - Retrieve the Management Interface
 * (MI) Commands Supported and Effects Log Page
 * @hdl:	Transport handle for the controller.
 * @log:	Pointer to the buffer
 *		(@struct nvme_mi_cmd_supported_effects_log) where the log page
 *		data will be stored.
 *
 * Submits the Get Log Page command specifically for the MI Commands Supported
 * and Effects Log. It automatically sets the Log Identifier (LID). This command
 * is typically issued with a namespace ID of 0xFFFFFFFF (NVME_NSID_NONE).
 *
 * Return: 0 on success, the NVMe command status on error, or a negative
 * errno otherwise.
 */
static inline int
nvme_get_log_mi_cmd_supported_effects(struct nvme_transport_handle *hdl,
		struct nvme_mi_cmd_supported_effects_log *log)
{
	struct nvme_passthru_cmd cmd;

	nvme_init_get_log_mi_cmd_supported_effects(&cmd, log);

	return nvme_get_log(hdl, &cmd, false, sizeof(*log));
}

/**
 * nvme_get_log_boot_partition() - Retrieve the Boot Partition Log Page
 * @hdl:	Transport handle for the controller.
 * @lsp:	The Log Specific Parameter (LSP) field for this Log
 *		Identifier (LID).
 * @part:	Pointer to the buffer (@struct nvme_boot_partition) where
 *		the log page data will be stored.
 * @len:	Length of the buffer provided in @part.
 *
 * Submits the Get Log Page command specifically for the Boot Partition Log.
 * The LSP field is set based on the @lsp parameter.
 *
 * It automatically sets the Log Identifier (LID) to
 * NVME_LOG_LID_BOOT_PARTITION.
 *
 * Return: 0 on success, the NVMe command status on error, or a negative
 * errno otherwise.
 */
static inline int
nvme_get_log_boot_partition(struct nvme_transport_handle *hdl,
		__u8 lsp, struct nvme_boot_partition *part, __u32 len)
{
	struct nvme_passthru_cmd cmd;

	nvme_init_get_log_boot_partition(&cmd, lsp, part, len);

	return nvme_get_log(hdl, &cmd, false, len);
}

/**
 * nvme_get_log_rotational_media_info() - Retrieve the Rotational Media
 * Information Log Page
 * @hdl:	Transport handle for the controller.
 * @endgid:	The Endurance Group Identifier (ENDGID) to retrieve the
 *		log for (used in LSI).
 * @log:	Pointer to the buffer (@struct nvme_rotational_media_info_log)
 *		where the log page data will be stored.
 * @len:	Length of the buffer provided in @log.
 *
 * Submits the Get Log Page command specifically for the Rotational Media
 * Information Log. The ENDGID is placed in the Log Specific Identifier (LSI)
 * field of the command.
 *
 * It automatically sets the Log Identifier (LID) and Retain Asynchronous
 * Event (RAE) to false. This command is typically issued for the controller
 * scope, thus using NVME_NSID_NONE.
 *
 * Return: 0 on success, the NVMe command status on error, or a negative
 * errno otherwise.
 */
static inline int
nvme_get_log_rotational_media_info(struct nvme_transport_handle *hdl,
		__u16 endgid, struct nvme_rotational_media_info_log *log,
		__u32 len)
{
	struct nvme_passthru_cmd cmd;

	nvme_init_get_log_rotational_media_info(&cmd, endgid, log, len);

	return nvme_get_log(hdl, &cmd, false, len);
}

/**
 * nvme_get_log_dispersed_ns_participating_nss() - Retrieve the Dispersed
 * Namespace Participating NVM Subsystems Log Page
 * @hdl:	Transport handle for the controller.
 * @nsid:	Namespace ID to request the log for.
 * @log:	Pointer to the buffer
 *		(@struct nvme_dispersed_ns_participating_nss_log)
 *		where the log page data will be stored.
 * @len:	Length of the buffer provided in @log.
 *
 * Submits the Get Log Page command specifically for the Dispersed Namespace
 * Participating NVM Subsystems Log. It automatically sets the Log Identifier
 * (LID) and Retain Asynchronous Event (RAE) to false.
 *
 * Return: 0 on success, the NVMe command status on error, or a negative
 * errno otherwise.
 */
static inline int
nvme_get_log_dispersed_ns_participating_nss(struct nvme_transport_handle *hdl,
		__u32 nsid, struct nvme_dispersed_ns_participating_nss_log *log,
		__u32 len)
{
	struct nvme_passthru_cmd cmd;

	nvme_init_get_log_dispersed_ns_participating_nss(&cmd, nsid, log, len);

	return nvme_get_log(hdl, &cmd, false, len);
}

/**
 * nvme_get_log_mgmt_addr_list() - Retrieve the Management Address List Log Page
 * @hdl:	Transport handle for the controller.
 * @log:	Pointer to the buffer (@struct nvme_mgmt_addr_list_log) where
 *		the log page data will be stored.
 * @len:	Length of the buffer provided in @log.
 *
 * Submits the Get Log Page command specifically for the Management Address List
   Log.
 *
 * It automatically sets the Log Identifier (LID) to
 * NVME_LOG_LID_MGMT_ADDR_LIST, Retain Asynchronous Event (RAE) to false, and
 * uses NVME_NSID_NONE.
 *
 * Return: 0 on success, the NVMe command status on error, or a negative
 * errno otherwise.
 */
static inline int
nvme_get_log_mgmt_addr_list(struct nvme_transport_handle *hdl,
		struct nvme_mgmt_addr_list_log *log, __u32 len)
{
	struct nvme_passthru_cmd cmd;

	nvme_init_get_log_mgmt_addr_list(&cmd, log, len);

	return nvme_get_log(hdl, &cmd, false, len);
}

/**
 * nvme_get_log_phy_rx_eom() - Retrieve the Physical Interface Receiver Eye
 * Opening Measurement Log Page
 * @hdl:	Transport handle for the controller.
 * @lsp:	Log Specific Parameter (LSP), which controls the action
 *		and measurement quality.
 * @controller:	Target Controller ID (used in LSI).
 * @log:	Pointer to the buffer (@struct nvme_phy_rx_eom_log) where
 *		the log page data will be stored.
 * @len:	Length of the buffer provided in @log.
 *
 * Submits the Get Log Page command specifically for the Physical Interface
 * Receiver Eye Opening Measurement Log. The Controller ID is placed in the
 * Log Specific Identifier (LSI) field.
 *
 * It automatically sets the Log Identifier (LID) to NVME_LOG_LID_PHY_RX_EOM,
 * and Retain Asynchronous Event (RAE) to false. This command is typically
 * issued for the controller scope, thus using NVME_NSID_NONE.
 *
 * Return: 0 on success, the NVMe command status on error, or a negative
 * errno otherwise.
 */
static inline int
nvme_get_log_phy_rx_eom(struct nvme_transport_handle *hdl,
		__u8 lsp, __u16 controller, struct nvme_phy_rx_eom_log *log,
		__u32 len)
{
	struct nvme_passthru_cmd cmd;

	nvme_init_get_log_phy_rx_eom(&cmd, lsp, controller, log, len);

	return nvme_get_log(hdl, &cmd, false, len);
}

/**
 * nvme_get_log_reachability_groups() - Retrieve the Reachability Groups
 * Log Page
 * @hdl:	Transport handle for the controller.
 * @nsid:	Namespace ID to request the log for.
 * @rgo:	Return Groups Only. Set to true to return only the Reachability
 *		Group Descriptors.
 * @log:	Pointer to the buffer (@struct nvme_reachability_groups_log)
 *		where the log page data will be stored.
 * @len:	Length of the buffer provided in @log.
 *
 * Submits the Get Log Page command specifically for the Reachability Groups
 * Log. The @rgo parameter is placed in the Log Specific Parameter (LSP) field.
 *
 * It automatically sets the Log Identifier (LID) to
 * NVME_LOG_LID_REACHABILITY_GROUPS.
 *
 * Return: 0 on success, the NVMe command status on error, or a negative
 * errno otherwise.
 */
static inline int
nvme_get_log_reachability_groups(struct nvme_transport_handle *hdl,
		__u32 nsid, bool rgo, struct nvme_reachability_groups_log *log,
		__u32 len)
{
	struct nvme_passthru_cmd cmd;

	nvme_init_get_log_reachability_groups(&cmd, rgo, log, len);

	return nvme_get_log(hdl, &cmd, false, len);
}

/**
 * nvme_get_log_reachability_associations() - Retrieve the Reachability
 * Associations Log Page
 * @hdl:	Transport handle for the controller.
 * @rae:	Retain asynchronous events
 * @rao:	Return Associations Only. Set to true to return only the
 *		Reachability Association Descriptors.
 * @log:	Pointer to the buffer
 *		(@struct nvme_reachability_associations_log) where the log
 *		page data will be stored.
 * @len:	Length of the buffer provided in @log.
 *
 * Submits the Get Log Page command specifically for the Reachability
 * Associations Log. The @rao parameter is placed in the Log Specific Parameter
 * (LSP) field.
 *
 * It automatically sets the Log Identifier (LID) to
 * NVME_LOG_LID_REACHABILITY_ASSOCIATIONS.
 *
 * Return: 0 on success, the NVMe command status on error, or a negative
 * errno otherwise.
 */
static inline int
nvme_get_log_reachability_associations(struct nvme_transport_handle *hdl,
		bool rae, bool rao,
		struct nvme_reachability_associations_log *log, __u32 len)
{
	struct nvme_passthru_cmd cmd;

	nvme_init_get_log_reachability_associations(&cmd, rao, log, len);

	return nvme_get_log(hdl, &cmd, rae, len);
}

/**
 * nvme_get_log_changed_alloc_ns_list() - Retrieve the Changed Allocated
 * Namespace List Log Page
 * @hdl:	Transport handle for the controller.
 * @log:	Pointer to the buffer (@struct nvme_ns_list) where the log page
 *		data will be stored.
 * @len:	Length of the buffer provided in @log.
 *
 * Submits the Get Log Page command specifically for the Changed Allocated
 * Namespace List Log.
 *
 * It automatically sets the Log Identifier (LID) to
 * NVME_LOG_LID_CHANGED_ALLOC_NS_LIST.
 *
 * Return: 0 on success, the NVMe command status on error, or a negative
 * errno otherwise.
 */
static inline int
nvme_get_log_changed_alloc_ns_list(struct nvme_transport_handle *hdl,
		struct nvme_ns_list *log, __u32 len)
{
	struct nvme_passthru_cmd cmd;

	nvme_init_get_log_changed_ns(&cmd, log);

	return nvme_get_log(hdl, &cmd, true, len);
}

/**
 * nvme_get_log_discovery() - Retrieve the Discovery Log Page
 * @hdl:	Transport handle for the controller.
 * @lpo:	Offset (in bytes) into the log page data to start the retrieval.
 * @log:	Pointer to the buffer where the log page data will be stored.
 * @len:	Length of the buffer provided in @log.
 *
 * Submits the Get Log Page command specifically for the Discovery Log.
 * Supported only by NVMe-oF Discovery controllers, returning discovery records.
 *
 * It automatically sets the Log Identifier (LID) to NVME_LOG_LID_DISCOVERY.
 *
 * Return: 0 on success, the NVMe command status on error, or a negative
 * errno otherwise.
 */
static inline int
nvme_get_log_discovery(struct nvme_transport_handle *hdl,
		__u64 lpo, __u32 len, void *log)
{
	struct nvme_passthru_cmd cmd;

	nvme_init_get_log_discovery(&cmd, lpo, log, len);

	return nvme_get_log(hdl, &cmd, false, len);
}

/**
 * nvme_get_log_host_discovery() - Retrieve the Host Discovery Log Page
 * @hdl:	Transport handle for the controller.
 * @rae:	Retain asynchronous events
 * @allhoste:	All Host Entries. Set to true to report all host entries.
 * @log:	Pointer to the buffer (@struct nvme_host_discover_log)
 *		where the log page data will be stored.
 * @len:	Length of the buffer provided in @log.
 *
 * Submits the Get Log Page command specifically for the Host Discovery Log.
 * The @allhoste parameter is placed in the Log Specific Parameter (LSP) field.
 *
 * It automatically sets the Log Identifier (LID) to
 * NVME_LOG_LID_HOST_DISCOVERY.
 *
 * Return: 0 on success, the NVMe command status on error, or a negative
 * errno otherwise.
 */
static inline int
nvme_get_log_host_discovery(struct nvme_transport_handle *hdl,
			   bool rae, bool allhoste,
			   struct nvme_host_discover_log *log, __u32 len)
{
	struct nvme_passthru_cmd cmd;

	nvme_init_get_log_host_discovery(&cmd, allhoste, log, len);

	return nvme_get_log(hdl, &cmd, false, len);
}

/**
 * nvme_get_log_ave_discovery() - Retrieve the Asynchronous Event
 * Group (AVE) Discovery Log Page
 * @hdl:	Transport handle for the controller.
 * @rae:	Retain asynchronous events
 * @log:	Pointer to the buffer (@struct nvme_ave_discover_log) where
 *		the log page data will be stored.
 * @len:	Length of the buffer provided in @log.
 *
 * Submits the Get Log Page command specifically for the Asynchronous Event
 * Group (AVE) Discovery Log. It automatically sets the Log Identifier (LID).
 *
 * Return: 0 on success, the NVMe command status on error, or a negative
 * errno otherwise.
 */
static inline int
nvme_get_log_ave_discovery(struct nvme_transport_handle *hdl,
		bool rae, struct nvme_ave_discover_log *log, __u32 len)
{
	struct nvme_passthru_cmd cmd;

	nvme_init_get_log_ave_discovery(&cmd, log, len);

	return nvme_get_log(hdl, &cmd, rae, len);
}

/**
 * nvme_get_log_pull_model_ddc_req() - Retrieve the Pull Model DDC Request
 * Log Page
 * @hdl:	Transport handle for the controller.
 * @rae:	Retain asynchronous events
 * @log:	Pointer to the buffer (@struct nvme_pull_model_ddc_req_log)
 *		where the log page data will be stored.
 * @len:	Length of the buffer provided in @log.
 *
 * Submits the Get Log Page command specifically for the Pull Model DDC Request
 * Log. It automatically sets the Log Identifier (LID).
 *
 * Return: 0 on success, the NVMe command status on error, or a negative
 * errno otherwise.
 */
static inline int
nvme_get_log_pull_model_ddc_req(struct nvme_transport_handle *hdl,
		bool rae, struct nvme_pull_model_ddc_req_log *log, __u32 len)
{
	struct nvme_passthru_cmd cmd;

	nvme_init_get_log_pull_model_ddc_req(&cmd, log, len);

	return nvme_get_log(hdl, &cmd, rae, len);
}

/**
 * nvme_get_log_media_unit_stat() - Retrieve the Media Unit Status Log Page
 * @hdl:	Transport handle for the controller.
 * @domid:	The Domain Identifier (DOMID) selection, if supported
 *		(used in LSI).
 * @mus:	Pointer to the buffer (@struct nvme_media_unit_stat_log)
 *		where the log page data will be stored.
 *
 * Submits the Get Log Page command specifically for the Media Unit Status Log.
 * The DOMID is placed in the Log Specific Identifier (LSI) field of the
 * command.
 *
 * It automatically sets the Log Identifier (LID) to
 * NVME_LOG_LID_MEDIA_UNIT_STATUS, and Retain Asynchronous Event (RAE) to false.
 * This command is typically issued for the controller scope, thus using
 * NVME_NSID_NONE.
 *
 * Return: 0 on success, the NVMe command status on error, or a negative
 * errno otherwise.
 */
static inline int
nvme_get_log_media_unit_stat(struct nvme_transport_handle *hdl,
		__u16 domid, struct nvme_media_unit_stat_log *mus)
{
	struct nvme_passthru_cmd cmd;

	nvme_init_get_log_media_unit_stat(&cmd, domid, mus);

	return nvme_get_log(hdl, &cmd, false, sizeof(*mus));
}

/**
 * nvme_get_log_support_cap_config_list() - Retrieve the Supported Capacity
 * Configuration List Log Page
 * @hdl:	Transport handle for the controller.
 * @domid:	The Domain Identifier (DOMID) selection, if
 *		supported (used in LSI).
 * @cap:	Pointer to the buffer
 *		(@struct nvme_supported_cap_config_list_log) where the log
 *		page data will be stored.
 *
 * Submits the Get Log Page command specifically for the Supported Capacity
 * Configuration List Log. The DOMID is placed in the Log Specific Identifier
 * (LSI) field of the command.
 *
 * It automatically sets the Log Identifier (LID) to
 * NVME_LOG_LID_SUPPORTED_CAP_CONFIG_LIST, and Retain Asynchronous Event (RAE)
 * to false. This command is typically issued for the controller scope, thus
 * using NVME_NSID_NONE.
 *
 * Return: 0 on success, the NVMe command status on error, or a negative
 * errno otherwise.
 */
static inline int
nvme_get_log_support_cap_config_list(struct nvme_transport_handle *hdl,
		__u16 domid, struct nvme_supported_cap_config_list_log *cap)
{
	struct nvme_passthru_cmd cmd;

	nvme_init_get_log_support_cap_config_list(&cmd, domid, cap);

	return nvme_get_log(hdl, &cmd, false, sizeof(*cap));
}

/**
 * nvme_get_log_reservation() - Retrieve the Reservation Notification Log Page
 * @hdl:	Transport handle for the controller.
 * @log:	Pointer to the buffer (@struct nvme_resv_notification_log)
 *		where the log page data will be stored.
 *
 * Submits the Get Log Page command specifically for the Reservation
 * Notification Log. It automatically sets the Log Identifier (LID).
 *
 * Return: 0 on success, the NVMe command status on error, or a negative
 * errno otherwise.
 */
static inline int
nvme_get_log_reservation(struct nvme_transport_handle *hdl,
		struct nvme_resv_notification_log *log)
{
	struct nvme_passthru_cmd cmd;

	nvme_init_get_log_reservation(&cmd, log);

	return nvme_get_log(hdl, &cmd, false, sizeof(*log));
}

/**
 * nvme_get_log_sanitize() - Retrieve the Sanitize Status Log Page
 * @hdl:	Transport handle for the controller.
 * @rae:	Retain asynchronous events
 * @log:	Pointer to the buffer (@struct nvme_sanitize_log_page)
 *		where the log page data will be stored.
 *
 * Submits the Get Log Page command specifically for the Sanitize Status Log.
 * The log page reports sanitize operation time estimates and information about
 * the most recent sanitize operation.
 *
 * It automatically sets the Log Identifier (LID) to NVME_LOG_LID_SANITIZE.
 *
 * Return: 0 on success, the NVMe command status on error, or a negative
 * errno otherwise.
 */
static inline int
nvme_get_log_sanitize(struct nvme_transport_handle *hdl,
		bool rae, struct nvme_sanitize_log_page *log)
{
	struct nvme_passthru_cmd cmd;

	nvme_init_get_log_sanitize(&cmd, log);

	return nvme_get_log(hdl, &cmd, rae, sizeof(*log));
}

/**
 * nvme_get_log_zns_changed_zones() - Retrieve the ZNS Changed Zones Log Page
 * @hdl:	Transport handle for the controller.
 * @nsid:	Namespace ID to request the log for.
 * @rae:	Retain asynchronous events
 * @log:	Pointer to the buffer (@struct nvme_zns_changed_zone_log)
 *		where the log page data will be stored.
 *
 * Submits the Get Log Page command specifically for the ZNS Changed Zones Log.
 * This log lists zones that have changed state due to an exceptional event.
 *
 * It automatically sets the Log Identifier (LID) to
 * NVME_LOG_LID_ZNS_CHANGED_ZONES.
 *
 * Return: 0 on success, the NVMe command status on error, or a negative
 * errno otherwise.
 */
static inline int
nvme_get_log_zns_changed_zones(struct nvme_transport_handle *hdl,
		__u32 nsid, bool rae, struct nvme_zns_changed_zone_log *log)
{
	struct nvme_passthru_cmd cmd;

	nvme_init_get_log_zns_changed_zones(&cmd, nsid, log);

	return nvme_get_log(hdl, &cmd, rae, sizeof(*log));
}

/**
 * nvme_get_log_persistent_event() - Retrieve the Persistent Event Log Page
 * @hdl:	Transport handle for the controller.
 * @action:	Action the controller should take during processing this
 *		command, see &enum nvme_pevent_log_action (used in LSP).
 * @pevent_log:	Pointer to the buffer where the log page data will be stored.
 * @len:	Length of the buffer provided in @pevent_log.
 *
 * Submits the Get Log Page command specifically for the Persistent Event Log.
 * The @action parameter is placed in the Log Specific Parameter (LSP) field.
 *
 * It automatically sets the Log Identifier (LID) to
 * NVME_LOG_LID_PERSISTENT_EVENT and Retain Asynchronous Event (RAE) to false.
 *
 * Return: 0 on success, the NVMe command status on error, or a negative
 * errno otherwise.
 */
static inline int
nvme_get_log_persistent_event(struct nvme_transport_handle *hdl,
		enum nvme_pevent_log_action action, void *pevent_log, __u32 len)
{
	struct nvme_passthru_cmd cmd;

	nvme_init_get_log_persistent_event(&cmd, action, pevent_log, len);

	/*
	 * Call the generic log execution function.
	 * The data length is determined by the 'len' parameter.
	 */
	return nvme_get_log(hdl, &cmd, false, len);
}

/**
 * nvme_get_log_lockdown() - Retrieve the Command and Feature Lockdown Log Page
 * @hdl:	Transport handle for the controller.
 * @cnscp:	Contents and Scope (CNSCP) of Command and Feature
 *		Identifier Lists (used in LSP).
 * @log:	Pointer to the buffer (@struct nvme_lockdown_log) where the log
 *		page data will be stored.
 *
 * Submits the Get Log Page command specifically for the Command and Feature
 * Lockdown Log. The @cnscp parameter is placed in the Log Specific Parameter
 * (LSP) field.
 *
 * It automatically sets the Log Identifier (LID) to
 * NVME_LOG_LID_CMD_AND_FEAT_LOCKDOWN and Retain Asynchronous Event (RAE) to
 * false.
 *
 * Return: 0 on success, the NVMe command status on error, or a negative
 * errno otherwise.
 */
static inline int
nvme_get_log_lockdown(struct nvme_transport_handle *hdl,
		__u8 cnscp, struct nvme_lockdown_log *log)
{
	struct nvme_passthru_cmd cmd;

	nvme_init_get_log_lockdown(&cmd, cnscp, log);

	return nvme_get_log(hdl, &cmd, false, sizeof(*log));
}

/**
 * nvme_get_log_smart() - Retrieve the SMART / Health Information Log Page
 * @hdl:	Transport handle for the controller.
 * @nsid:	Namespace ID to request the log for.
 * @smart_log:	Pointer to the buffer (@struct nvme_smart_log) where the log
 *		page data will be stored.
 *
 * Submits the Get Log Page command specifically for the SMART / Health
 * Information Log. It automatically sets the Log Identifier (LID) and
 * Retain Asynchronous Event (RAE) to false.
 *
 * Return: 0 on success, the NVMe command status on error, or a negative
 * errno otherwise.
 */
static inline int
nvme_get_log_smart(struct nvme_transport_handle *hdl,
		__u32 nsid, struct nvme_smart_log *smart_log)
{
	struct nvme_passthru_cmd cmd;

	nvme_init_get_log_smart(&cmd, nsid, smart_log);

	return nvme_get_log(hdl, &cmd, false, NVME_LOG_PAGE_PDU_SIZE);
}


/**
 * nvme_set_features() - Submit a generic Set Features command
 * @hdl:	Transport handle for the controller.
 * @nsid:	Namespace ID	sto apply the feature to.
 * @fid:	Feature Identifier (FID) to be set.
 * @sv:		Save Value (SV): If true, the feature value persists
 *		across power states.
 * @cdw11:	Command Dword 11 parameter (feature-specific).
 * @cdw12:	Command Dword 12 parameter (feature-specific).
 * @cdw13:	Command Dword 13 parameter (feature-specific).
 * @uidx:	UUID Index (UIDX) for the command, encoded into cdw14
 * @cdw15:	Command Dword 15 parameter (feature-specific).
 * @data:	Pointer to the data buffer to transfer (if applicable).
 * @len:	Length of the data buffer in bytes.
 * @result:	The command completion result (CQE dword0) on success.
 *
 * Submits the Set Features command, allowing all standard command
 * fields (cdw11-cdw15) and data buffer fields to be specified directly.
 *
 * Return: 0 on success, the NVMe command status on error, or a negative
 * errno otherwise.
 */
static inline int
nvme_set_features(struct nvme_transport_handle *hdl, __u32 nsid, __u8 fid,
		bool sv, __u32 cdw11, __u32 cdw12, __u32 cdw13, __u8 uidx,
		__u32 cdw15, void *data, __u32 len, __u64 *result)
{
	struct nvme_passthru_cmd cmd;
	int err;

	nvme_init_set_features(&cmd, fid, sv);
	cmd.nsid = nsid;
	cmd.cdw11 = cdw11;
	cmd.cdw12 = cdw12;
	cmd.cdw13 = cdw13;
	cmd.cdw14 = NVME_FIELD_ENCODE(uidx,
				      NVME_SET_FEATURES_CDW14_UUID_SHIFT,
				      NVME_SET_FEATURES_CDW14_UUID_MASK);
	cmd.cdw15 = cdw15;
	cmd.data_len = len;
	cmd.addr = (__u64)(uintptr_t)data;

	err = nvme_submit_admin_passthru(hdl, &cmd);
	if (result)
		*result = cmd.result;
	return err;
}

/**
 * nvme_set_features_simple() - Submit a Set Features command using only cdw11
 * @hdl:	Transport handle for the controller.
 * @nsid:	Namespace ID to apply the feature to.
 * @fid:	Feature Identifier (FID) to be set.
 * @sv:		Save Value (SV): If true, the feature value persists across
 *		power states.
 * @cdw11:	Command Dword 11 parameter (feature-specific value).
 * @result:	The command completion result (CQE dword0) on success.
 *
 * Submits the Set Features command for features that only require
 * parameters in cdw11.
 *
 * Return: 0 on success, the NVMe command status on error, or a negative
 * errno otherwise.
 */
static inline int
nvme_set_features_simple(struct nvme_transport_handle *hdl,
		__u32 nsid, __u8 fid, bool sv, __u32 cdw11, __u64 *result)
{
	struct nvme_passthru_cmd cmd;
	int err;

	nvme_init_set_features(&cmd, fid, sv);
	cmd.nsid = nsid;
	cmd.cdw11 = cdw11;

	err = nvme_submit_admin_passthru(hdl, &cmd);
	if (result)
		*result = cmd.result;
	return err;
}

/**
 * nvme_get_features() - Submit a Get Features command
 * @hdl:	Transport handle for the controller.
 * @nsid:	Namespace ID, if applicable
 * @fid:	Feature identifier, see &enum nvme_features_id
 * @sel:	Select which type of attribute to return,
 *		see &enum nvme_get_features_sel
 * @cdw11:	Feature specific command dword11 field
 * @uidx:	UUID Index for differentiating vendor specific encoding
 * @data:	User address of feature data, if applicable
 * @len:	Length of feature data, if applicable, in bytes
 * @result:	The command completion result (CQE dword0) on success.
 *
 * Return: 0 on success, the NVMe command status on error, or a negative
 * errno otherwise.
 */
static inline int
nvme_get_features(struct nvme_transport_handle *hdl, __u32 nsid,
		__u8 fid, enum nvme_get_features_sel sel,
		__u32 cdw11, __u8 uidx, void *data,
		__u32 len, __u64 *result)
{
	struct nvme_passthru_cmd cmd;
	int err;

	nvme_init_get_features(&cmd, fid, sel);

	cmd.nsid = nsid;
	cmd.cdw11 = cdw11;
	cmd.cdw14 = NVME_FIELD_ENCODE(uidx,
			NVME_GET_FEATURES_CDW14_UUID_SHIFT,
			NVME_GET_FEATURES_CDW14_UUID_MASK);
	cmd.data_len = len;
	cmd.addr = (__u64)(uintptr_t)data;

	err = nvme_submit_admin_passthru(hdl, &cmd);
	if (result)
		*result = cmd.result;
	return err;
}

/**
 * nvme_get_features_simple() - Submit a simple Get Features command
 * @hdl:	Transport handle for the controller.
 * @fid:	Feature Identifier (FID) to be retrieved.
 * @sel:	Select (SEL), specifying which feature value
 *		to return (&struct nvme_get_features_sel).
 * @result:	The command completion result (CQE dword0) on success.
 *
 * Submits the Get Features command for features that only require parameters in
 * the CQE dword0 and do not need any parameters in cdw11 through cdw15.
 *
 * Return: 0 on success, the NVMe command status on error, or a negative
 * errno otherwise.
 */
static inline int
nvme_get_features_simple(struct nvme_transport_handle *hdl, __u8 fid,
		enum nvme_get_features_sel sel, __u64 *result)
{
	struct nvme_passthru_cmd cmd;
	int err;

	nvme_init_get_features(&cmd, fid, sel);

	err = nvme_submit_admin_passthru(hdl, &cmd);
	if (result)
		*result = cmd.result;
	return err;
}


#endif /* NVME_CMDS */
