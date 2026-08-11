/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * This file is part of libnvme.
 * Copyright (c) 2020 Western Digital Corporation or its affiliates.
 *
 * Authors: Keith Busch <keith.busch@wdc.com>
 *	    Chaitanya Kulkarni <chaitanya.kulkarni@wdc.com>
 *	    Daniel Wagner <dwagner@suse.de>
 */
#pragma once

#include <nvme/ioctl.h>
#include <nvme/nvme-cmds.h>

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
nvme_identify(struct libnvme_transport_handle *hdl, __u32 nsid, enum nvme_csi csi,
		enum nvme_identify_cns cns, void *data, __u32 len)
{
	struct libnvme_passthru_cmd cmd;

	nvme_init_identify(&cmd, nsid, csi, cns, data, len);

	return libnvme_exec_admin_passthru(hdl, &cmd);
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
nvme_identify_ctrl(struct libnvme_transport_handle *hdl,
		struct nvme_id_ctrl *id)
{
	struct libnvme_passthru_cmd cmd;

	nvme_init_identify_ctrl(&cmd, id);

	return libnvme_exec_admin_passthru(hdl, &cmd);
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
nvme_identify_ns(struct libnvme_transport_handle *hdl,
		__u32 nsid, struct nvme_id_ns *ns)
{
	struct libnvme_passthru_cmd cmd;

	nvme_init_identify_ns(&cmd, nsid, ns);

	return libnvme_exec_admin_passthru(hdl, &cmd);
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
nvme_identify_uuid_list(struct libnvme_transport_handle *hdl,
		struct nvme_id_uuid_list *uuid_list)
{
	struct libnvme_passthru_cmd cmd;

	nvme_init_identify_uuid_list(&cmd, uuid_list);

	return libnvme_exec_admin_passthru(hdl, &cmd);
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
nvme_identify_ns_descs_list(struct libnvme_transport_handle *hdl,
		__u32 nsid, struct nvme_ns_id_desc *descs)
{
	struct libnvme_passthru_cmd cmd;

	nvme_init_identify_ns_descs_list(&cmd, nsid, descs);

	return libnvme_exec_admin_passthru(hdl, &cmd);
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
nvme_get_log_simple(struct libnvme_transport_handle *hdl,
		enum nvme_cmd_get_log_lid lid, void *data, __u32 len)
{
	struct libnvme_passthru_cmd cmd;

	nvme_init_get_log(&cmd, NVME_NSID_ALL, lid, NVME_CSI_NVM, data, len);

	return libnvme_get_log(hdl, &cmd, false, NVME_LOG_PAGE_PDU_SIZE);
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
nvme_get_log_error(struct libnvme_transport_handle *hdl, __u32 nsid,
		unsigned int nr_entries, struct nvme_error_log_page *err_log)
{
	struct libnvme_passthru_cmd cmd;
	size_t len = sizeof(*err_log) * nr_entries;

	nvme_init_get_log(&cmd, nsid, NVME_LOG_LID_ERROR,
		NVME_CSI_NVM, err_log, len);

	return libnvme_get_log(hdl, &cmd, false, len);
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
nvme_get_log_fw_slot(struct libnvme_transport_handle *hdl, __u32 nsid,
		struct nvme_firmware_slot *fw_log)
{
	struct libnvme_passthru_cmd cmd;

	nvme_init_get_log(&cmd, nsid, NVME_LOG_LID_FW_SLOT,
		NVME_CSI_NVM, fw_log, sizeof(*fw_log));

	return libnvme_get_log(hdl, &cmd, false, sizeof(*fw_log));
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
nvme_get_log_cmd_effects(struct libnvme_transport_handle *hdl,
		enum nvme_csi csi, struct nvme_cmd_effects_log *effects_log)
{
	struct libnvme_passthru_cmd cmd;
	size_t len = sizeof(*effects_log);

	nvme_init_get_log_cmd_effects(&cmd, csi, effects_log);

	return libnvme_get_log(hdl, &cmd, false, len);
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
nvme_get_log_device_self_test(struct libnvme_transport_handle *hdl,
		struct nvme_self_test_log *log)
{
	struct libnvme_passthru_cmd cmd;
	size_t len = sizeof(*log);

	nvme_init_get_log(&cmd, NVME_NSID_ALL, NVME_LOG_LID_DEVICE_SELF_TEST,
		NVME_CSI_NVM, log, len);

	return libnvme_get_log(hdl, &cmd, false, len);
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
nvme_get_log_telemetry_host(struct libnvme_transport_handle *hdl,
		__u64 lpo, void *log, __u32 len)
{
	struct libnvme_passthru_cmd cmd;

	nvme_init_get_log_telemetry_host(&cmd, lpo, log, len);

	return libnvme_get_log_dynamic_chunk(hdl, &cmd, false, len);
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
nvme_get_log_telemetry_ctrl(struct libnvme_transport_handle *hdl, bool rae,
		__u64 lpo, void *log, __u32 len)
{
	struct libnvme_passthru_cmd cmd;

	nvme_init_get_log_telemetry_ctrl(&cmd, lpo, log, len);

	return libnvme_get_log_dynamic_chunk(hdl, &cmd, rae, len);
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
nvme_get_log_persistent_event(struct libnvme_transport_handle *hdl,
		enum nvme_pevent_log_action action, void *pevent_log, __u32 len)
{
	struct libnvme_passthru_cmd cmd;

	nvme_init_get_log_persistent_event(&cmd, action, pevent_log, len);

	/*
	 * Call the generic log execution function.
	 * The data length is determined by the 'len' parameter.
	 */
	return libnvme_get_log_dynamic_chunk(hdl, &cmd, false, len);
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
nvme_get_log_smart(struct libnvme_transport_handle *hdl,
		__u32 nsid, struct nvme_smart_log *smart_log)
{
	struct libnvme_passthru_cmd cmd;

	nvme_init_get_log_smart(&cmd, nsid, smart_log);

	return libnvme_get_log(hdl, &cmd, false, NVME_LOG_PAGE_PDU_SIZE);
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
nvme_set_features(struct libnvme_transport_handle *hdl, __u32 nsid, __u8 fid,
		bool sv, __u32 cdw11, __u32 cdw12, __u32 cdw13, __u8 uidx,
		__u32 cdw15, void *data, __u32 len, __u64 *result)
{
	struct libnvme_passthru_cmd cmd;
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

	err = libnvme_exec_admin_passthru(hdl, &cmd);
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
nvme_set_features_simple(struct libnvme_transport_handle *hdl,
		__u32 nsid, __u8 fid, bool sv, __u32 cdw11, __u64 *result)
{
	struct libnvme_passthru_cmd cmd;
	int err;

	nvme_init_set_features(&cmd, fid, sv);
	cmd.nsid = nsid;
	cmd.cdw11 = cdw11;

	err = libnvme_exec_admin_passthru(hdl, &cmd);
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
nvme_get_features(struct libnvme_transport_handle *hdl, __u32 nsid,
		__u8 fid, enum nvme_get_features_sel sel,
		__u32 cdw11, __u8 uidx, void *data,
		__u32 len, __u64 *result)
{
	struct libnvme_passthru_cmd cmd;
	int err;

	nvme_init_get_features(&cmd, fid, sel);

	cmd.nsid = nsid;
	cmd.cdw11 = cdw11;
	cmd.cdw14 = NVME_FIELD_ENCODE(uidx,
			NVME_GET_FEATURES_CDW14_UUID_SHIFT,
			NVME_GET_FEATURES_CDW14_UUID_MASK);
	cmd.data_len = len;
	cmd.addr = (__u64)(uintptr_t)data;

	err = libnvme_exec_admin_passthru(hdl, &cmd);
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
nvme_get_features_simple(struct libnvme_transport_handle *hdl, __u8 fid,
		enum nvme_get_features_sel sel, __u64 *result)
{
	struct libnvme_passthru_cmd cmd;
	int err;

	nvme_init_get_features(&cmd, fid, sel);

	err = libnvme_exec_admin_passthru(hdl, &cmd);
	if (result)
		*result = cmd.result;
	return err;
}
