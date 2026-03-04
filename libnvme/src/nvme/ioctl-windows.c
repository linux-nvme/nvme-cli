// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2025 Micron Technology, Inc.
 *
 * Authors: Broc Going <bgoing@micron.com>
 *
 * Windows-specific implementations of ioctl-based functions.
 */

#include "ioctl.h"
#include "private.h"
#include "types.h"

#include <windows.h>
#include <winioctl.h>
#include <errno.h>
#include <ntddscsi.h>
#include <stdbool.h>
#include <stdlib.h>

/* Definitions not yet included in mingw's winerror.h */
#define STG_E_FIRMWARE_SLOT_INVALID      _HRESULT_TYPEDEF_(0x80030208L)
#define STG_E_FIRMWARE_IMAGE_INVALID     _HRESULT_TYPEDEF_(0x80030209L)

static int get_last_error_as_errno(void)
{
	DWORD error = GetLastError();

	/* Convert Windows error to errno */
	switch (error) {
	case ERROR_INVALID_PARAMETER:
		return -EINVAL;
	case ERROR_NOT_SUPPORTED:
		return -ENOTSUP;
	case ERROR_INSUFFICIENT_BUFFER:
		return -ENOMEM;
	case ERROR_IO_DEVICE:
		return -EIO;
	case STG_E_FIRMWARE_IMAGE_INVALID:
		return -EILSEQ;
	case STG_E_FIRMWARE_SLOT_INVALID:
		return -EINVAL;
	default:
		return -EIO;
	}
}

static int get_errno_from_storage_protocol_status(DWORD status)
{
	switch (status) {
	case STORAGE_PROTOCOL_STATUS_SUCCESS:
		return 0;
	case STORAGE_PROTOCOL_STATUS_PENDING:
		return -EAGAIN;
	case STORAGE_PROTOCOL_STATUS_ERROR:
		return -EIO;
	case STORAGE_PROTOCOL_STATUS_INVALID_REQUEST:
		return -EINVAL;
	case STORAGE_PROTOCOL_STATUS_NO_DEVICE:
		return -ENODEV;
	case STORAGE_PROTOCOL_STATUS_BUSY:
		return -EBUSY;
	case STORAGE_PROTOCOL_STATUS_DATA_OVERRUN:
		return -E2BIG;
	case STORAGE_PROTOCOL_STATUS_INSUFFICIENT_RESOURCES:
		return -ENOMEM;
	case STORAGE_PROTOCOL_STATUS_THROTTLED_REQUEST:
		return -EIO;
	case STORAGE_PROTOCOL_STATUS_NOT_SUPPORTED:
		return -ENOTSUP;
	default:
		return -EIO;
	}
}

int nvme_subsystem_reset(struct nvme_transport_handle *hdl)
{
	(void)hdl;
	return -ENOTSUP;
}

int nvme_ctrl_reset(struct nvme_transport_handle *hdl)
{
	(void)hdl;
	return -ENOTSUP;
}

int nvme_ns_rescan(struct nvme_transport_handle *hdl)
{
	(void)hdl;
	return -ENOTSUP;
}

int nvme_get_nsid(struct nvme_transport_handle *hdl, __u32 *nsid)
{
	(void)hdl;
	(void)nsid;
	return -ENOTSUP;
}

int nvme_submit_io_passthru(struct nvme_transport_handle *hdl,
		struct nvme_passthru_cmd *cmd)
{
	(void)hdl;
	(void)cmd;
	return -ENOTSUP;
}

static int nvme_submit_storage_protocol_command(
		struct nvme_transport_handle *hdl,
		struct nvme_passthru_cmd *cmd)
{
	PSTORAGE_PROTOCOL_COMMAND protocol_command = NULL;
	ULONG buffer_len = 0;
	ULONG returned_len = 0;
	BOOL result = FALSE;
	PUCHAR buffer = NULL;
	void *user_data;
	int err = 0;
	bool is_read = false;
	bool is_write = false;

	user_data = hdl->submit_entry(hdl, cmd);
	if (hdl->ctx->dry_run)
		goto out;

	if (hdl->fd == INVALID_HANDLE_VALUE || hdl->fd == NULL) {
		err = -EBADF;
		goto out;
	}

	if (cmd->data_len > 0 && !cmd->addr) {
		err = -EINVAL;
		goto out;
	}

	/*
	 * Get the Data Transfer Direction (DTD) from the opcode:
	 * 00b = No data transfer
	 * 01b = Host to Controller Transfer
	 * 10b = Controller to Host Transfer
	 * 11b = Bi-Directional Transfer
	 */
	is_write = cmd->opcode & 0x1;
	is_read = cmd->opcode & 0x2;

	/* Bi-directional transfers not supported */
	if (is_read && is_write) {
		err = -ENOTSUP;
		goto out;
	}

	/* Allocate buffer for STORAGE_PROTOCOL_COMMAND + NVME command + data */
	buffer_len = FIELD_OFFSET(STORAGE_PROTOCOL_COMMAND, Command) +
		STORAGE_PROTOCOL_COMMAND_LENGTH_NVME +
		(cmd->data_len > 0 ? cmd->data_len : 0);

	buffer = (PUCHAR)malloc(buffer_len);
	if (!buffer) {
		err = -ENOMEM;
		goto out;
	}

	ZeroMemory(buffer, buffer_len);

	protocol_command = (PSTORAGE_PROTOCOL_COMMAND)buffer;

	protocol_command->Version = STORAGE_PROTOCOL_STRUCTURE_VERSION;
	protocol_command->Length = sizeof(STORAGE_PROTOCOL_COMMAND);
	protocol_command->ProtocolType = ProtocolTypeNvme;
	protocol_command->Flags = STORAGE_PROTOCOL_COMMAND_FLAG_ADAPTER_REQUEST;
	protocol_command->CommandLength = STORAGE_PROTOCOL_COMMAND_LENGTH_NVME;
	protocol_command->ErrorInfoLength = 0;
	protocol_command->TimeOutValue = (cmd->timeout_ms > 0) ?
		((cmd->timeout_ms + 999) / 1000) : 10; /* Round up to seconds */

	protocol_command->CommandSpecific =
		STORAGE_PROTOCOL_SPECIFIC_NVME_ADMIN_COMMAND;
	memcpy(protocol_command->Command, cmd,
		STORAGE_PROTOCOL_COMMAND_LENGTH_NVME);

	if (cmd->addr && cmd->data_len > 0 && is_read) {
		protocol_command->DataFromDeviceTransferLength = cmd->data_len;
		protocol_command->DataFromDeviceBufferOffset =
			FIELD_OFFSET(STORAGE_PROTOCOL_COMMAND, Command) +
			STORAGE_PROTOCOL_COMMAND_LENGTH_NVME;
	} else if (cmd->addr && cmd->data_len > 0 && is_write) {
		protocol_command->DataToDeviceTransferLength = cmd->data_len;
		protocol_command->DataToDeviceBufferOffset =
			FIELD_OFFSET(STORAGE_PROTOCOL_COMMAND, Command) +
			STORAGE_PROTOCOL_COMMAND_LENGTH_NVME;
		memcpy((PUCHAR)buffer + protocol_command->DataToDeviceBufferOffset,
			(void *)(uintptr_t)cmd->addr, cmd->data_len);
	}

	do {
		err = 0;
		result = DeviceIoControl(hdl->fd,
					IOCTL_STORAGE_PROTOCOL_COMMAND,
					buffer,
					buffer_len,
					buffer,
					buffer_len,
					&returned_len,
					NULL);
		if (result && protocol_command->ReturnStatus == STORAGE_PROTOCOL_STATUS_SUCCESS)
			break;

		if (!result)
			err = get_last_error_as_errno();
		else
			err = get_errno_from_storage_protocol_status(
				protocol_command->ReturnStatus);
	} while (hdl->decide_retry(hdl, cmd, err));

	if (err)
		goto out_free_buffer;

	/* Copy the returned data to the user's buffer */
	if (cmd->addr && cmd->data_len > 0 && is_read) {
		memcpy((void *)(uintptr_t)cmd->addr,
			(PUCHAR)buffer + protocol_command->DataFromDeviceBufferOffset,
			cmd->data_len);
	}

	/* Copy the completion queue entry (CQE) DW0-1 into cmd->result. */
	memcpy(&cmd->result, &protocol_command->FixedProtocolReturnData,
		sizeof(cmd->result));

out_free_buffer:
	free(buffer);
out:
	hdl->submit_exit(hdl, cmd, err, user_data);
	return err;
}

static int nvme_submit_admin_get_log_page(struct nvme_transport_handle *hdl,
		struct nvme_passthru_cmd *cmd)
{
	PSTORAGE_PROPERTY_QUERY query = NULL;
	PSTORAGE_PROTOCOL_SPECIFIC_DATA protocol_data = NULL;
	STORAGE_PROTOCOL_DATA_SUBVALUE_GET_LOG_PAGE protocol_data_subval = { 0 };
	ULONG buffer_len = 0;
	ULONG returned_len = 0;
	BOOL result = FALSE;
	PUCHAR buffer = NULL;
	__u32 csi;
	void *user_data;
	int err = 0;

	user_data = hdl->submit_entry(hdl, cmd);
	if (hdl->ctx->dry_run)
		goto out;

	if (hdl->fd == INVALID_HANDLE_VALUE || hdl->fd == NULL) {
		err = -EBADF;
		goto out;
	}

	/* Command Set Indicator values other than NVME_CSI_NVM not supported */
	csi = NVME_FIELD_DECODE(cmd->cdw14,
				NVME_LOG_CDW14_CSI_SHIFT,
				NVME_LOG_CDW14_CSI_MASK);
	if (csi != NVME_CSI_NVM) {
		err = -ENOTSUP;
		goto out;
	}

	buffer_len = FIELD_OFFSET(STORAGE_PROPERTY_QUERY, AdditionalParameters) +
		sizeof(STORAGE_PROTOCOL_SPECIFIC_DATA) + cmd->data_len;

	buffer = (PUCHAR)malloc(buffer_len);
	if (!buffer) {
		err = -ENOMEM;
		goto out;
	}

	ZeroMemory(buffer, buffer_len);

	query = (PSTORAGE_PROPERTY_QUERY)buffer;
	protocol_data = (PSTORAGE_PROTOCOL_SPECIFIC_DATA)query->AdditionalParameters;

	/*
	 * Use StorageDeviceProtocolSpecificProperty for log pages.
	 * Per Windows documentation, this queries device/namespace
	 * protocol-specific properties.
	 */
	query->PropertyId = StorageDeviceProtocolSpecificProperty;
	query->QueryType = PropertyStandardQuery;

	protocol_data->ProtocolType = ProtocolTypeNvme;
	protocol_data->DataType = NVMeDataTypeLogPage;

	protocol_data->ProtocolDataRequestValue = NVME_FIELD_DECODE(cmd->cdw10,
					NVME_LOG_CDW10_LID_SHIFT,
					NVME_LOG_CDW10_LID_MASK);

	protocol_data->ProtocolDataRequestSubValue = cmd->cdw12;	/* LPO[31:0]  */
	protocol_data->ProtocolDataRequestSubValue2 = cmd->cdw13;	/* LPO[63:32] */

	protocol_data->ProtocolDataRequestSubValue3 = NVME_FIELD_DECODE(cmd->cdw11,
					NVME_LOG_CDW11_LSI_SHIFT,
					NVME_LOG_CDW11_LSI_MASK);

	protocol_data_subval.RetainAsynEvent = NVME_FIELD_DECODE(cmd->cdw10,
					NVME_LOG_CDW10_RAE_SHIFT,
					NVME_LOG_CDW10_RAE_MASK);
	protocol_data_subval.LogSpecificField = NVME_FIELD_DECODE(cmd->cdw10,
					NVME_LOG_CDW10_LSP_SHIFT,
					NVME_LOG_CDW10_LSP_MASK);
	protocol_data->ProtocolDataRequestSubValue4 = protocol_data_subval.AsUlong;

	protocol_data->ProtocolDataOffset = sizeof(STORAGE_PROTOCOL_SPECIFIC_DATA);
	protocol_data->ProtocolDataLength = cmd->data_len;

	do {
		err = 0;
		result = DeviceIoControl(hdl->fd,
					IOCTL_STORAGE_QUERY_PROPERTY,
					buffer,
					buffer_len,
					buffer,
					buffer_len,
					&returned_len,
					NULL);
		if (result)
			break;
		err = get_last_error_as_errno();
	} while (hdl->decide_retry(hdl, cmd, err));

	if (err)
		goto out_free_buffer;

	/* Copy the returned log page data to the user's buffer */
	if (cmd->addr && cmd->data_len > 0) {
		memcpy((void *)(uintptr_t)cmd->addr,
			(PUCHAR)protocol_data + protocol_data->ProtocolDataOffset,
			min(protocol_data->ProtocolDataLength, cmd->data_len));
	}

	/* Only 32-bits of return data. Assuming CQE DW0. */
	cmd->result = protocol_data->FixedProtocolReturnData;

out_free_buffer:
	free(buffer);
out:
	hdl->submit_exit(hdl, cmd, err, user_data);
	return err;
}

static int nvme_submit_admin_identify(struct nvme_transport_handle *hdl,
		struct nvme_passthru_cmd *cmd)
{
	PSTORAGE_PROPERTY_QUERY query = NULL;
	PSTORAGE_PROTOCOL_SPECIFIC_DATA protocol_data = NULL;
	ULONG buffer_len = 0;
	ULONG returned_len = 0;
	BOOL result = FALSE;
	PUCHAR buffer = NULL;
	__u32 cns;
	__u32 csi;
	void *user_data;
	int err = 0;

	user_data = hdl->submit_entry(hdl, cmd);
	if (hdl->ctx->dry_run)
		goto out;

	if (hdl->fd == INVALID_HANDLE_VALUE || hdl->fd == NULL) {
		err = -EBADF;
		goto out;
	}

	/*
	 * From Windows STORAGE_PROTOCOL_NVME_DATA_TYPE documentation
	 * for NVMeDataTypeIdentify:
	 * "ProtocolDataRequestValue will be NVME_IDENTIFY_CNS_CONTROLLER for
	 * adapter or NVME_IDENTIFY_CNS_SPECIFIC_NAMESPACE for namespace."
	 * Other CNS values are not supported.
	 */
	cns = NVME_FIELD_DECODE(cmd->cdw10,
				NVME_IDENTIFY_CDW10_CNS_SHIFT,
				NVME_IDENTIFY_CDW10_CNS_MASK);
	if (cns != NVME_IDENTIFY_CNS_CTRL && cns != NVME_IDENTIFY_CNS_NS) {
		err = -ENOTSUP;
		goto out;
	}

	/* Command Set Indicator values other than NVME_CSI_NVM not supported */
	csi = NVME_FIELD_DECODE(cmd->cdw11,
				NVME_IDENTIFY_CDW11_CSI_SHIFT,
				NVME_IDENTIFY_CDW11_CSI_MASK);
	if (csi != NVME_CSI_NVM) {
		err = -ENOTSUP;
		goto out;
	}

	buffer_len = FIELD_OFFSET(STORAGE_PROPERTY_QUERY, AdditionalParameters) +
		sizeof(STORAGE_PROTOCOL_SPECIFIC_DATA) + cmd->data_len;

	buffer = (PUCHAR)malloc(buffer_len);
	if (!buffer) {
		err = -ENOMEM;
		goto out;
	}

	ZeroMemory(buffer, buffer_len);

	query = (PSTORAGE_PROPERTY_QUERY)buffer;
	protocol_data = (PSTORAGE_PROTOCOL_SPECIFIC_DATA)query->AdditionalParameters;

	/*
	 * NOTE: If testing fails with Identify Specific Namespace, try
	 * StorageDeviceProtocolSpecificProperty for that cns.
	 */
	query->PropertyId = StorageAdapterProtocolSpecificProperty;

	protocol_data->ProtocolType = ProtocolTypeNvme;
	protocol_data->DataType = NVMeDataTypeIdentify;

	protocol_data->ProtocolDataRequestValue = cns;
	protocol_data->ProtocolDataRequestSubValue = cmd->nsid;
	protocol_data->ProtocolDataOffset = sizeof(STORAGE_PROTOCOL_SPECIFIC_DATA);
	protocol_data->ProtocolDataLength = cmd->data_len;

	do {
		err = 0;
		result = DeviceIoControl(hdl->fd,
					IOCTL_STORAGE_QUERY_PROPERTY,
					buffer,
					buffer_len,
					buffer,
					buffer_len,
					&returned_len,
					NULL);
		if (result)
			break;
		err = get_last_error_as_errno();
	} while (hdl->decide_retry(hdl, cmd, err));

	if (err)
		goto out_free_buffer;

	/* Copy the returned data to the user's buffer */
	if (cmd->addr && cmd->data_len > 0) {
		memcpy((void *)(uintptr_t)cmd->addr,
			(char *)protocol_data + protocol_data->ProtocolDataOffset,
			min(protocol_data->ProtocolDataLength, cmd->data_len));
	}

	/* Only 32-bits of return data. Assuming CQE DW0. */
	cmd->result = protocol_data->FixedProtocolReturnData;

out_free_buffer:
	free(buffer);
out:
	hdl->submit_exit(hdl, cmd, err, user_data);
	return err;
}

static int nvme_submit_admin_set_features(struct nvme_transport_handle *hdl,
		struct nvme_passthru_cmd *cmd)
{
	PSTORAGE_PROPERTY_SET set_property = NULL;
	PSTORAGE_PROTOCOL_SPECIFIC_DATA_EXT protocol_data = NULL;
	ULONG buffer_len = 0;
	ULONG returned_len = 0;
	BOOL result = FALSE;
	PUCHAR buffer = NULL;
	void *user_data;
	int err = 0;

	user_data = hdl->submit_entry(hdl, cmd);
	if (hdl->ctx->dry_run)
		goto out;

	if (hdl->fd == INVALID_HANDLE_VALUE || hdl->fd == NULL) {
		err = -EBADF;
		goto out;
	}

	buffer_len = FIELD_OFFSET(STORAGE_PROPERTY_SET, AdditionalParameters) +
		sizeof(STORAGE_PROTOCOL_SPECIFIC_DATA_EXT) + cmd->data_len;

	buffer = (PUCHAR)malloc(buffer_len);
	if (!buffer) {
		err = -ENOMEM;
		goto out;
	}

	ZeroMemory(buffer, buffer_len);

	set_property = (PSTORAGE_PROPERTY_SET)buffer;
	protocol_data = (PSTORAGE_PROTOCOL_SPECIFIC_DATA_EXT)set_property->AdditionalParameters;

	set_property->PropertyId = StorageAdapterProtocolSpecificProperty;
	set_property->SetType = PropertyStandardSet;

	protocol_data->ProtocolType = ProtocolTypeNvme;
	protocol_data->DataType = NVMeDataTypeFeature;

	/*
	 * Map NVMe Set Features command DWORDs to protocol data fields.
	 * STORAGE_PROTOCOL_SPECIFIC_DATA_EXT values for NVMeDataTypeFeature
	 * are documented in the STORAGE_PROTOCOL_NVME_DATA_TYPE enumeration.
	 */
	protocol_data->ProtocolDataValue = cmd->cdw10;
	protocol_data->ProtocolDataSubValue = cmd->cdw11;
	protocol_data->ProtocolDataSubValue2 = cmd->cdw12;
	protocol_data->ProtocolDataSubValue3 = cmd->cdw13;
	protocol_data->ProtocolDataSubValue4 = cmd->cdw14;
	protocol_data->ProtocolDataSubValue5 = cmd->cdw15;

	protocol_data->ProtocolDataOffset = sizeof(STORAGE_PROTOCOL_SPECIFIC_DATA_EXT);
	protocol_data->ProtocolDataLength = cmd->data_len;

	/* Copy input data if present */
	if (cmd->addr && cmd->data_len > 0) {
		memcpy((PUCHAR)protocol_data + protocol_data->ProtocolDataOffset,
			(void *)(uintptr_t)cmd->addr,
			cmd->data_len);
	}

	do {
		err = 0;
		result = DeviceIoControl(hdl->fd,
					IOCTL_STORAGE_SET_PROPERTY,
					buffer,
					buffer_len,
					buffer,
					buffer_len,
					&returned_len,
					NULL);
		if (result)
			break;
		err = get_last_error_as_errno();
	} while (hdl->decide_retry(hdl, cmd, err));

	if (err)
		goto out_free_buffer;

	/* Only 32-bits of return data. Assuming CQE DW0. */
	cmd->result = protocol_data->FixedProtocolReturnData;

out_free_buffer:
	free(buffer);
out:
	hdl->submit_exit(hdl, cmd, err, user_data);
	return err;
}

static int nvme_submit_admin_get_features(struct nvme_transport_handle *hdl,
		struct nvme_passthru_cmd *cmd)
{
	PSTORAGE_PROPERTY_QUERY query = NULL;
	PSTORAGE_PROTOCOL_SPECIFIC_DATA protocol_data = NULL;
	ULONG buffer_len = 0;
	ULONG returned_len = 0;
	BOOL result = FALSE;
	PUCHAR buffer = NULL;
	void *user_data;
	int err = 0;

	user_data = hdl->submit_entry(hdl, cmd);
	if (hdl->ctx->dry_run)
		goto out;

	if (hdl->fd == INVALID_HANDLE_VALUE || hdl->fd == NULL) {
		err = -EBADF;
		goto out;
	}

	buffer_len = FIELD_OFFSET(STORAGE_PROPERTY_QUERY, AdditionalParameters) +
		sizeof(STORAGE_PROTOCOL_SPECIFIC_DATA) + cmd->data_len;

	buffer = (PUCHAR)malloc(buffer_len);
	if (!buffer) {
		err = -ENOMEM;
		goto out;
	}

	ZeroMemory(buffer, buffer_len);

	query = (PSTORAGE_PROPERTY_QUERY)buffer;
	protocol_data = (PSTORAGE_PROTOCOL_SPECIFIC_DATA)query->AdditionalParameters;

	query->PropertyId = StorageAdapterProtocolSpecificProperty;
	query->QueryType = PropertyStandardQuery;

	protocol_data->ProtocolType = ProtocolTypeNvme;
	protocol_data->DataType = NVMeDataTypeFeature;

	/*
	 * Map NVMe Get Features command DWORDs to protocol data fields.
	 * STORAGE_PROTOCOL_SPECIFIC_DATA values for Get Features are documented
	 * in the STORAGE_PROTOCOL_NVME_DATA_TYPE enumeration documentation.
	 */
	protocol_data->ProtocolDataRequestValue = cmd->cdw10;
	protocol_data->ProtocolDataRequestSubValue = cmd->cdw11;
	protocol_data->ProtocolDataRequestSubValue2 = cmd->cdw12;
	protocol_data->ProtocolDataRequestSubValue3 = cmd->cdw13;
	protocol_data->ProtocolDataRequestSubValue4 = cmd->cdw14;

	protocol_data->ProtocolDataOffset = sizeof(STORAGE_PROTOCOL_SPECIFIC_DATA);
	protocol_data->ProtocolDataLength = cmd->data_len;

	do {
		err = 0;
		result = DeviceIoControl(hdl->fd,
					IOCTL_STORAGE_QUERY_PROPERTY,
					buffer,
					buffer_len,
					buffer,
					buffer_len,
					&returned_len,
					NULL);
		if (result)
			break;
		err = get_last_error_as_errno();
	} while (hdl->decide_retry(hdl, cmd, err));

	if (err)
		goto out_free_buffer;

	/* Copy the returned data to the user's buffer if present */
	if (cmd->addr && cmd->data_len > 0) {
		memcpy((void *)(uintptr_t)cmd->addr,
			(PUCHAR)protocol_data + protocol_data->ProtocolDataOffset,
			min(protocol_data->ProtocolDataLength, cmd->data_len));
	}

	/* Only 32-bits of return data. Assuming CQE DW0. */
	cmd->result = protocol_data->FixedProtocolReturnData;

out_free_buffer:
	free(buffer);
out:
	hdl->submit_exit(hdl, cmd, err, user_data);
	return err;
}

#ifndef STORAGE_HW_FIRMWARE_REQUEST_FLAG_CONTROLLER

/*
 * Definitions for values and types not yet included in mingw's winioctl.h.
 * Values found in the 10.0.26100.0 Windows SDK winioctl.h.
 */

#define STORAGE_HW_FIRMWARE_REQUEST_FLAG_CONTROLLER    0x00000001

/* Activate the existing firmware immediately without controller reset. */
#define STORAGE_HW_FIRMWARE_REQUEST_FLAG_SWITCH_TO_FIRMWARE_WITHOUT_RESET 0x10000000
/* Replace existing firmware and activate with controller reset. */
#define STORAGE_HW_FIRMWARE_REQUEST_FLAG_REPLACE_AND_SWITCH_UPON_RESET 0x20000000
/* Replace the existing firmware. Not activated. */
#define STORAGE_HW_FIRMWARE_REQUEST_FLAG_REPLACE_EXISTING_IMAGE      0x40000000
/* Activate the existing firmware with a controller reset. */
#define STORAGE_HW_FIRMWARE_REQUEST_FLAG_SWITCH_TO_EXISTING_FIRMWARE 0x80000000

typedef struct _STORAGE_HW_FIRMWARE_ACTIVATE {
	DWORD   Version;
	DWORD   Size;

	DWORD   Flags;
	BYTE    Slot;
	BYTE    Reserved0[3];
} STORAGE_HW_FIRMWARE_ACTIVATE, *PSTORAGE_HW_FIRMWARE_ACTIVATE;

typedef struct _STORAGE_HW_FIRMWARE_DOWNLOAD {
	DWORD       Version;
	DWORD       Size;

	DWORD       Flags;
	BYTE        Slot;
	BYTE        Reserved[3];

	DWORDLONG   Offset;
	DWORDLONG   BufferSize;

	BYTE        ImageBuffer[ANYSIZE_ARRAY];
} STORAGE_HW_FIRMWARE_DOWNLOAD, *PSTORAGE_HW_FIRMWARE_DOWNLOAD;

#endif

static int nvme_submit_admin_fw_commit(struct nvme_transport_handle *hdl,
		struct nvme_passthru_cmd *cmd)
{
	PSTORAGE_HW_FIRMWARE_ACTIVATE firmware_activate = NULL;
	ULONG buffer_len = 0;
	ULONG returned_len = 0;
	BOOL result = FALSE;
	__u8 commit_action;
	void *user_data;
	int err = 0;

	user_data = hdl->submit_entry(hdl, cmd);
	if (hdl->ctx->dry_run)
		goto out;

	if (hdl->fd == INVALID_HANDLE_VALUE || hdl->fd == NULL) {
		err = -EBADF;
		goto out;
	}

	buffer_len = sizeof(STORAGE_HW_FIRMWARE_ACTIVATE);

	firmware_activate = (PSTORAGE_HW_FIRMWARE_ACTIVATE)malloc(buffer_len);
	if (!firmware_activate) {
		err = -ENOMEM;
		goto out;
	}

	ZeroMemory(firmware_activate, buffer_len);

	firmware_activate->Version = sizeof(STORAGE_HW_FIRMWARE_ACTIVATE);
	firmware_activate->Size = sizeof(STORAGE_HW_FIRMWARE_ACTIVATE);
	firmware_activate->Slot = NVME_FIELD_DECODE(cmd->cdw10,
			NVME_FW_COMMIT_CDW10_FS_SHIFT,
			NVME_FW_COMMIT_CDW10_FS_MASK);

	/* For NVMe devices, the target is the controller */
	firmware_activate->Flags = STORAGE_HW_FIRMWARE_REQUEST_FLAG_CONTROLLER;

	/* Set additional flags based on the commit action */
	commit_action = NVME_FIELD_DECODE(cmd->cdw10,
		NVME_FW_COMMIT_CDW10_CA_SHIFT,
		NVME_FW_COMMIT_CDW10_CA_MASK);

	switch (commit_action) {
	case 0: /* Replace, no activate */
		firmware_activate->Flags |=
			STORAGE_HW_FIRMWARE_REQUEST_FLAG_REPLACE_EXISTING_IMAGE;
		break;
	case 1: /* Replace and activate at next reset */
		firmware_activate->Flags |=
			STORAGE_HW_FIRMWARE_REQUEST_FLAG_REPLACE_AND_SWITCH_UPON_RESET;
		break;
	case 2: /* Activate the current firmware at next reset */
		firmware_activate->Flags |=
			STORAGE_HW_FIRMWARE_REQUEST_FLAG_SWITCH_TO_EXISTING_FIRMWARE;
		break;
	case 3: /* Activate the current firmware immediately without reset */
		firmware_activate->Flags |=
			STORAGE_HW_FIRMWARE_REQUEST_FLAG_SWITCH_TO_FIRMWARE_WITHOUT_RESET;
		break;
	}

	do {
		err = 0;
		result = DeviceIoControl(hdl->fd,
					IOCTL_STORAGE_FIRMWARE_ACTIVATE,
					firmware_activate,
					buffer_len,
					NULL,
					0,
					&returned_len,
					NULL);
		if (result)
			break;
		err = get_last_error_as_errno();
	} while (hdl->decide_retry(hdl, cmd, err));

	if (err)
		goto out_free_buffer;

	/* FW Commit doesn't return result data */
	cmd->result = 0;

out_free_buffer:
	free(firmware_activate);
out:
	hdl->submit_exit(hdl, cmd, err, user_data);
	return err;
}

static int nvme_submit_admin_fw_download(struct nvme_transport_handle *hdl,
		struct nvme_passthru_cmd *cmd)
{
	PSTORAGE_HW_FIRMWARE_DOWNLOAD firmware_download = NULL;
	ULONG buffer_len = 0;
	ULONG returned_len = 0;
	BOOL result = FALSE;
	PUCHAR buffer = NULL;
	void *user_data;
	int err = 0;

	user_data = hdl->submit_entry(hdl, cmd);
	if (hdl->ctx->dry_run)
		goto out;

	if (hdl->fd == INVALID_HANDLE_VALUE || hdl->fd == NULL) {
		err = -EBADF;
		goto out;
	}

	/*
	 * Allocate buffer for STORAGE_HW_FIRMWARE_DOWNLOAD structure.
	 * The structure contains the firmware image data inline at the end.
	 */
	buffer_len = FIELD_OFFSET(STORAGE_HW_FIRMWARE_DOWNLOAD, ImageBuffer)
			+ cmd->data_len;

	buffer = (PUCHAR)malloc(buffer_len);
	if (!buffer) {
		err = -ENOMEM;
		goto out;
	}

	ZeroMemory(buffer, buffer_len);

	firmware_download = (PSTORAGE_HW_FIRMWARE_DOWNLOAD)buffer;
	firmware_download->Version = sizeof(STORAGE_HW_FIRMWARE_DOWNLOAD);
	firmware_download->Size = buffer_len;

	/*
	 * The NVMe command uses DWORD counts for size and offset.
	 * The Windows API uses byte counts, so convert accordingly.
	 * See ioctl.h/nvme_init_fw_download for encoding details.
	 */
	firmware_download->BufferSize = (DWORDLONG)(cmd->cdw10 + 1) << 2;
	firmware_download->Offset = (DWORDLONG)cmd->cdw11 << 2;

	/*
	 * Assuming we need the CONTROLLER flag.
	 * TODO: Do we need to use the LAST_SEGMENT flag?
	 * If so, we will need a way to communicate in the cmd struct
	 * whether this is the last segment.
	 */
	firmware_download->Flags = STORAGE_HW_FIRMWARE_REQUEST_FLAG_CONTROLLER;

	/*
	 * Assuming that slot is not used for NVMe devices since it is not
	 * part of the NVMe FW Download command. Setting to 0.
	 * TODO: If needed, we will need a way to communicate it in the
	 * cmd struct. If not needed, just remove this setting completely.
	 */
	firmware_download->Slot = 0;

	if (cmd->addr && cmd->data_len > 0) {
		memcpy(firmware_download->ImageBuffer,
			(void *)(uintptr_t)cmd->addr,
			cmd->data_len);
	}

	do {
		err = 0;
		result = DeviceIoControl(hdl->fd,
					IOCTL_STORAGE_FIRMWARE_DOWNLOAD,
					buffer,
					buffer_len,
					NULL,
					0,
					&returned_len,
					NULL);
		if (result)
			break;
		err = get_last_error_as_errno();
	} while (hdl->decide_retry(hdl, cmd, err));

	if (err)
		goto out_free_buffer;

	/* Firmware download doesn't return result data */
	cmd->result = 0;

out_free_buffer:
	free(buffer);
out:
	hdl->submit_exit(hdl, cmd, err, user_data);
	return err;
}

/* SCSI operation code for sanitize command - from ddk/scsi.h */
#define SCSIOP_SANITIZE 0x48

static int nvme_submit_admin_format_nvm_user_data_erase(
		struct nvme_transport_handle *hdl,
		struct nvme_passthru_cmd *cmd)
{
	/*
	 * User Data Erase: Use IOCTL_SCSI_PASS_THROUGH with SCSIOP_SANITIZE
	 * to erase user data. The sanitize operation erases all user data,
	 * with the contents being indeterminate after erase.
	 */
	PSCSI_PASS_THROUGH pass_through = NULL;
	ULONG buffer_len = 0;
	ULONG returned_len = 0;
	BOOL result = FALSE;
	PUCHAR buffer = NULL;
	void *user_data;
	int err = 0;

	user_data = hdl->submit_entry(hdl, cmd);
	if (hdl->ctx->dry_run)
		goto out;

	if (hdl->fd == INVALID_HANDLE_VALUE || hdl->fd == NULL) {
		err = -EBADF;
		goto out;
	}

	/* Allocate buffer for SCSI_PASS_THROUGH */
	buffer_len = sizeof(SCSI_PASS_THROUGH);
	buffer = (PUCHAR)malloc(buffer_len);
	if (!buffer) {
		err = -ENOMEM;
		goto out;
	}

	ZeroMemory(buffer, buffer_len);

	pass_through = (PSCSI_PASS_THROUGH)buffer;
	pass_through->Length = sizeof(SCSI_PASS_THROUGH);
	pass_through->CdbLength = 6;
	pass_through->DataIn = SCSI_IOCTL_DATA_UNSPECIFIED;
	pass_through->DataTransferLength = 0;
	pass_through->TimeOutValue = (cmd->timeout_ms > 0) ?
		((cmd->timeout_ms + 999) / 1000) : 300;
	pass_through->DataBufferOffset = 0;

	/*
	 * Build the Sanitize CDB (6 bytes)
	 * Byte 0: Operation code (0x48)
	 * Byte 1: Service Action + Immediate bit
	 *   Bits 7-5: Reserved
	 *   Bits 4-3: Service action
	 *     00 = Block Erase
	 *     01 = Crypto Scramble
	 *     10 = Overwrite
	 *   Bit 2: Ancillary (reserved)
	 *   Bit 1: IMMED (Immediate)
	 *   Bit 0: Reserved
	 * Bytes 2-5: Reserved
	 *
	 * For NVMe User Data Erase, use Block Erase (service action 00)
	 */
	pass_through->Cdb[0] = SCSIOP_SANITIZE;
	pass_through->Cdb[1] = 0x00; /* Block Erase, non-immediate */
	pass_through->Cdb[2] = 0;    /* Reserved */
	pass_through->Cdb[3] = 0;    /* Reserved */
	pass_through->Cdb[4] = 0;    /* Reserved */
	pass_through->Cdb[5] = 0;    /* Reserved */

	do {
		err = 0;
		result = DeviceIoControl(hdl->fd,
				IOCTL_SCSI_PASS_THROUGH,
				buffer,
				buffer_len,
				buffer,
				buffer_len,
				&returned_len,
				NULL);
		if (result)
			break;

		if (!result)
			err = get_last_error_as_errno();
		else
			err = -EIO;
	} while (hdl->decide_retry(hdl, cmd, err));

	if (err)
		goto out_free_buffer;

	cmd->result = 0;

out_free_buffer:
	free(buffer);
out:
	hdl->submit_exit(hdl, cmd, err, user_data);
	return err;
}

static int nvme_submit_admin_format_nvm_crypto_erase(
		struct nvme_transport_handle *hdl,
		struct nvme_passthru_cmd *cmd)
{
	BOOL result = FALSE;
	ULONG returned_len = 0;
	void *user_data;
	int err = 0;

	user_data = hdl->submit_entry(hdl, cmd);
	if (hdl->ctx->dry_run)
		goto out;

	if (hdl->fd == INVALID_HANDLE_VALUE || hdl->fd == NULL) {
		err = -EBADF;
		goto out;
	}

	do {
		err = 0;
		result = DeviceIoControl(hdl->fd,
				IOCTL_STORAGE_REINITIALIZE_MEDIA,
				NULL,
				0,
				NULL,
				0,
				&returned_len,
				NULL);
		if (result)
			break;
		err = get_last_error_as_errno();
	} while (hdl->decide_retry(hdl, cmd, err));

	cmd->result = 0;

out:
	hdl->submit_exit(hdl, cmd, err, user_data);
	return err;
}

static int nvme_submit_admin_format_nvm(struct nvme_transport_handle *hdl,
		struct nvme_passthru_cmd *cmd)
{
	__u8 ses;

	/* Namespace-specific format is not supported on Windows */
	if (cmd->nsid != NVME_NSID_ALL)
		return -ENOTSUP;

	/*
	 * Extract the Secure Erase Settings (SES) from CDW10 and call the
	 * appropriate implementation based on the requested erase type.
	 */
	ses = NVME_FIELD_DECODE(cmd->cdw10,
			NVME_FORMAT_CDW10_SES_SHIFT,
			NVME_FORMAT_CDW10_SES_MASK);

	/*
	 * Per Microsoft StorNVMe documentation:
	 * - SES=0 (No Erase): Not supported on Windows
	 * - SES=1 (User Data Erase): Use IOCTL_SCSI_PASS_THROUGH with SANITIZE
	 * - SES=2 (Cryptographic Erase): Use IOCTL_STORAGE_REINITIALIZE_MEDIA
	 */
	switch (ses) {
	case NVME_FORMAT_SES_NONE:
		return -ENOTSUP;	/* Not supported on Windows */
	case NVME_FORMAT_SES_USER_DATA_ERASE:
		return nvme_submit_admin_format_nvm_user_data_erase(hdl, cmd);
	case NVME_FORMAT_SES_CRYPTO_ERASE:
		return nvme_submit_admin_format_nvm_crypto_erase(hdl, cmd);
	default:
		return -EINVAL;
	}
}

/* SCSI operation codes for security commands - from ddk/scsi.h */
#define SCSIOP_SECURITY_PROTOCOL_IN      0xA2
#define SCSIOP_SECURITY_PROTOCOL_OUT     0xB5

static int nvme_submit_admin_security_send_receive(
		struct nvme_transport_handle *hdl,
		struct nvme_passthru_cmd *cmd)
{
	PSCSI_PASS_THROUGH pass_through = NULL;
	ULONG buffer_len = 0;
	ULONG returned_len = 0;
	BOOL result = FALSE;
	PUCHAR buffer = NULL;
	void *user_data;
	int err = 0;
	bool is_send = (cmd->opcode == nvme_admin_security_send);

	user_data = hdl->submit_entry(hdl, cmd);
	if (hdl->ctx->dry_run)
		goto out;

	if (hdl->fd == INVALID_HANDLE_VALUE || hdl->fd == NULL) {
		err = -EBADF;
		goto out;
	}

	/* Allocate buffer for SCSI_PASS_THROUGH + data */
	buffer_len = sizeof(SCSI_PASS_THROUGH) + cmd->data_len;
	buffer = (PUCHAR)malloc(buffer_len);
	if (!buffer) {
		err = -ENOMEM;
		goto out;
	}

	ZeroMemory(buffer, buffer_len);

	pass_through = (PSCSI_PASS_THROUGH)buffer;
	pass_through->Length = sizeof(SCSI_PASS_THROUGH);
	pass_through->CdbLength = 12;
	pass_through->DataIn = is_send ? SCSI_IOCTL_DATA_OUT : SCSI_IOCTL_DATA_IN;
	pass_through->DataTransferLength = cmd->data_len;
	pass_through->TimeOutValue = (cmd->timeout_ms > 0) ?
		((cmd->timeout_ms + 999) / 1000) : 30;
	pass_through->DataBufferOffset = sizeof(SCSI_PASS_THROUGH);

	if (is_send && cmd->data_len > 0) {
		memcpy(buffer + pass_through->DataBufferOffset,
			(void *)(uintptr_t)cmd->addr, cmd->data_len);
	}

	/*
	 * Build the Security Protocol CDB (12 bytes)
	 * Per SPC-4: Security Protocol In/Out CDB is 12 bytes:
	 * Byte 0: Operation code (0xA2/0xB5)
	 * Byte 1: Security Protocol (SECP)
	 * Byte 2-3: Security Protocol Specific (SPSP)
	 * Byte 4: Reserved
	 * Byte 5: NSSF (NVMe Security Specific Field)
	 * Byte 6-9: Allocation Length (big-endian)
	 * Byte 10-11: Reserved
	 */
	pass_through->Cdb[0] = is_send ?
		SCSIOP_SECURITY_PROTOCOL_OUT : SCSIOP_SECURITY_PROTOCOL_IN;
	pass_through->Cdb[1] = NVME_FIELD_DECODE(cmd->cdw10,
			NVME_SECURITY_SECP_SHIFT,
			NVME_SECURITY_SECP_MASK);
	pass_through->Cdb[2] = NVME_FIELD_DECODE(cmd->cdw10,
			NVME_SECURITY_SPSP1_SHIFT,
			NVME_SECURITY_SPSP1_MASK);
	pass_through->Cdb[3] = NVME_FIELD_DECODE(cmd->cdw10,
			NVME_SECURITY_SPSP0_SHIFT,
			NVME_SECURITY_SPSP0_MASK);
	pass_through->Cdb[4] = 0;  /* Reserved */
	pass_through->Cdb[5] = NVME_FIELD_DECODE(cmd->cdw10,
			NVME_SECURITY_NSSF_SHIFT,
			NVME_SECURITY_NSSF_MASK);
	/* Transfer/Allocation length (CDW11) in big-endian */
	pass_through->Cdb[6] = (cmd->cdw11 >> 24) & 0xFF;
	pass_through->Cdb[7] = (cmd->cdw11 >> 16) & 0xFF;
	pass_through->Cdb[8] = (cmd->cdw11 >> 8) & 0xFF;
	pass_through->Cdb[9] = cmd->cdw11 & 0xFF;
	pass_through->Cdb[10] = 0; /* Reserved */
	pass_through->Cdb[11] = 0; /* Reserved */

	do {
		err = 0;
		result = DeviceIoControl(hdl->fd,
				IOCTL_SCSI_PASS_THROUGH,
				buffer,
				buffer_len,
				buffer,
				buffer_len,
				&returned_len,
				NULL);
		if (result && !pass_through->ScsiStatus)
			break;

		if (!result)
			err = get_last_error_as_errno();
		else
			err = -EIO;
	} while (hdl->decide_retry(hdl, cmd, err));

	if (err)
		goto out_free_buffer;

	/* Copy returned data to user buffer if this was a receive */
	if (!is_send && cmd->addr && cmd->data_len > 0) {
		memcpy((void *)(uintptr_t)cmd->addr,
			buffer + pass_through->DataBufferOffset,
			pass_through->DataTransferLength);
		cmd->data_len = pass_through->DataTransferLength;
	}

	/* No result data returned by command. */
	cmd->result = 0;

out_free_buffer:
	free(buffer);
out:
	hdl->submit_exit(hdl, cmd, err, user_data);
	return err;
}

/*
 * Windows only supports a subset of NVMe admin command calls from user space
 * and uses different IOCTLs for different commands instead of a single
 * passthru interface.
 * Passthru is supported using IOCTL_STORAGE_PROTOCOL_COMMAND,
 * but only for VU commands and a small subset of admin commands.
 * For supported commands and a mapping to the required IOCTLs, see:
 * https://learn.microsoft.com/en-us/windows-hardware/drivers/storage/stornvme-command-set-support
 */
int nvme_submit_admin_passthru(struct nvme_transport_handle *hdl,
		struct nvme_passthru_cmd *cmd)
{
	if (!hdl || !cmd)
		return -EINVAL;

	if (hdl->type != NVME_TRANSPORT_HANDLE_TYPE_DIRECT)
		return -ENOTSUP;

	/* VU commands */
	if (cmd->opcode >= 0xC0 && cmd->opcode <= 0xFF)
		return nvme_submit_storage_protocol_command(hdl, cmd);

	switch (cmd->opcode) {
	case nvme_admin_get_log_page:
		return nvme_submit_admin_get_log_page(hdl, cmd);
	case nvme_admin_identify:
		return nvme_submit_admin_identify(hdl, cmd);
	case nvme_admin_set_features:
		return nvme_submit_admin_set_features(hdl, cmd);
	case nvme_admin_get_features:
		return nvme_submit_admin_get_features(hdl, cmd);
	case nvme_admin_fw_commit:
		return nvme_submit_admin_fw_commit(hdl, cmd);
	case nvme_admin_fw_download:
		return nvme_submit_admin_fw_download(hdl, cmd);
	case nvme_admin_dev_self_test:
		return nvme_submit_storage_protocol_command(hdl, cmd);
	case nvme_admin_format_nvm:
		return nvme_submit_admin_format_nvm(hdl, cmd);
	case nvme_admin_security_send:
	case nvme_admin_security_recv:
		return nvme_submit_admin_security_send_receive(hdl, cmd);
	case nvme_admin_sanitize_nvm:
		return nvme_submit_storage_protocol_command(hdl, cmd);
	default:
		return -ENOTSUP;
	}
}
