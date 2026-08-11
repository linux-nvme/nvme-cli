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
