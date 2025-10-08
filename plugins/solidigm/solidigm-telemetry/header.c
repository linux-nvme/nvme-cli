// SPDX-License-Identifier: MIT
/*
 * Copyright (c) 2022 Solidigm.
 *
 * Author: leonardo.da.cunha@solidigm.com
 */

#include "common.h"
#include "header.h"

bool sldm_uint8_array_to_string(const uint8_t *data_ptr, uint32_t array_size,
				 struct json_object **str_obj)
{
	if (!data_ptr || !str_obj) {
		if (str_obj)
			*str_obj = json_object_new_string("Error: Invalid parameters");
		return false;
	}

	// Calculate actual string length (stopping at null terminator if found)
	size_t actual_length = 0;
	bool is_ascii = true;

	for (actual_length = 0; actual_length < array_size; actual_length++) {
		if (data_ptr[actual_length] == '\0')
			break;
		// Check if character is ASCII printable (0x20-0x7E) or common whitespace
		// (0x09, 0x0A, 0x0D)
		if (!((data_ptr[actual_length] >= 0x20 && data_ptr[actual_length] <= 0x7E) ||
		      data_ptr[actual_length] == 0x09 || data_ptr[actual_length] == 0x0A ||
		      data_ptr[actual_length] == 0x0D)) {
			is_ascii = false;
		}
	}

	// Check if there is data after the null terminator
	bool has_data_after_terminator = false;

	for (size_t i = actual_length; i < array_size; i++) {
		if (data_ptr[i] != '\0') {
			has_data_after_terminator = true;
			// Also check ASCII for data after null terminator
			if (!((data_ptr[i] >= 0x20 && data_ptr[i] <= 0x7E) ||
			      data_ptr[i] == 0x09 || data_ptr[i] == 0x0A ||
			      data_ptr[i] == 0x0D)) {
				is_ascii = false;
			}
			break;
		}
	}

	// If there is data after the terminator, use the whole array_size
	size_t string_length = has_data_after_terminator ? array_size : actual_length;

	// Create JSON string directly from the data
	*str_obj = json_object_new_string_len((const char *)data_ptr, string_length);

	// Return true only if data is ASCII and no data after null terminator
	return is_ascii && !has_data_after_terminator;
}

#pragma pack(push, reason_indentifier, 1)
struct reason_indentifier_1_0 {
	uint16_t versionMajor;
	uint16_t versionMinor;
	uint32_t reasonCode;		//! 0 denotes no issue. All other values denote a potential issue.
	char DriveStatus[20];		//! Drive Status String (for example: "Healthy", "*BAD_CONTEXT_2020")
	char FirmwareVersion[12];	//! Similar to IdentifyController.FR
	char BootloaderVersion[12];	//! Bootloader version string
	char SerialNumber[20];		//! Device serial number
	uint8_t Reserved[56];		//! Reserved for future usage
};
static_assert(sizeof(const struct reason_indentifier_1_0) ==
	      MEMBER_SIZE(struct nvme_telemetry_log, rsnident),
	      "Size mismatch for reason_indentifier_1_0");

struct reason_indentifier_1_1 {
	uint16_t versionMajor;
	uint16_t versionMinor;
	uint32_t reasonCode;		//! 0 denotes no issue. All other values denote a potential issue.
	char DriveStatus[20];		//! Drive Status String (for example: "Healthy", "*BAD_CONTEXT_2020")
	char FirmwareVersion[12];	//! Similar to IdentifyController.FR
	char BootloaderVersion[12];	//! Bootloader version string
	char SerialNumber[20];		//! Device serial number
	uint64_t OemDataMapOffset;	//! Customer Data Map Object Log Offset
	uint8_t TelemetryMajorVersion;	//! Shadow of version in TOC
	uint8_t TelemetryMinorVersion;	//! Shadow of version in TOC
	uint8_t Reserved[46];		//! Reserved for future usage
};
static_assert(sizeof(const struct reason_indentifier_1_1) ==
	      MEMBER_SIZE(struct nvme_telemetry_log, rsnident),
	      "Size mismatch for reason_indentifier_1_1");

struct reason_indentifier_1_2 {
	uint16_t versionMajor;
	uint16_t versionMinor;
	uint32_t reasonCode;		//! 0 denotes no issue. All other values denote a potential issue.
	char DriveStatus[20];		//! Drive Status String (for example: "Healthy", "*BAD_CONTEXT_2020")
	uint8_t Reserved1[24];		//! pad over Fields removed from version 1.1
	char SerialNumber[20];		//! Device serial number
	uint64_t OemDataMapOffset;	//! Customer Data Map Object Log Offset
	uint8_t TelemetryMajorVersion;	//! Shadow of version in TOC
	uint8_t TelemetryMinorVersion;	//! Shadow of version in TOC
	uint8_t ProductFamilyId;
	uint8_t Reserved2[5];		//! Reserved for future usage
	uint8_t DualPortReserved[40];	//! Reserved for dual port
};
static_assert(sizeof(const struct reason_indentifier_1_2) ==
	      MEMBER_SIZE(struct nvme_telemetry_log, rsnident),
	      "Size mismatch for reason_indentifier_1_2");

struct reason_identifier_ocp_2_5 {
	char errorId[64];
	char fileId[8];
	uint16_t lineNum;
	union {
		struct {
			uint8_t validLineNum:1;
			uint8_t validFileId:1;
			uint8_t validErrorId:1;
			uint8_t validVuExtension:1;
			uint8_t reservedBits:4;
		};
		uint8_t raw;
	} validFlags;
	uint8_t reserved[21];
	uint8_t vuExtension[32];
};
static_assert(sizeof(const struct reason_identifier_ocp_2_5) ==
	      MEMBER_SIZE(struct nvme_telemetry_log, rsnident),
	      "Size mismatch for reason_identifier_ocp_2_5");

#pragma pack(pop, reason_indentifier)

static void telemetry_log_reason_id_parse1_0_ext(const struct telemetry_log *tl,
						 struct json_object *reason_id)
{
	const struct reason_indentifier_1_0 *ri;
	struct json_object *reserved = NULL;
	struct json_object *firmware_str_obj = NULL;
	struct json_object *bootloader_str_obj = NULL;
	struct json_object *serial_str_obj = NULL;

	ri = (struct reason_indentifier_1_0 *) tl->log->rsnident;
	sldm_uint8_array_to_string((const uint8_t *)ri->FirmwareVersion,
				   sizeof(ri->FirmwareVersion), &firmware_str_obj);
	json_object_object_add(reason_id, "firmwareVersion", firmware_str_obj);
	sldm_uint8_array_to_string((const uint8_t *)ri->BootloaderVersion,
				   sizeof(ri->BootloaderVersion), &bootloader_str_obj);
	json_object_object_add(reason_id, "bootloaderVersion", bootloader_str_obj);
	sldm_uint8_array_to_string((const uint8_t *)ri->SerialNumber,
				   sizeof(ri->SerialNumber), &serial_str_obj);
	json_object_object_add(reason_id, "serialNumber", serial_str_obj);

	sldm_uint8_array_to_string((const uint8_t *)ri->Reserved,
				   sizeof(ri->Reserved), &reserved);
	json_object_object_add(reason_id, "reserved", reserved);
}

static void telemetry_log_reason_id_parse1_1_ext(const struct telemetry_log *tl,
						 struct json_object *reason_id)
{
	const struct reason_indentifier_1_1 *ri;
	struct json_object *reserved = NULL;
	struct json_object *firmware_str_obj2 = NULL;
	struct json_object *bootloader_str_obj2 = NULL;
	struct json_object *serial_str_obj2 = NULL;

	ri = (struct reason_indentifier_1_1 *) tl->log->rsnident;
	sldm_uint8_array_to_string((const uint8_t *)ri->FirmwareVersion,
				   sizeof(ri->FirmwareVersion), &firmware_str_obj2);
	json_object_object_add(reason_id, "firmwareVersion", firmware_str_obj2);
	sldm_uint8_array_to_string((const uint8_t *)ri->BootloaderVersion,
				   sizeof(ri->BootloaderVersion), &bootloader_str_obj2);
	json_object_object_add(reason_id, "bootloaderVersion", bootloader_str_obj2);
	sldm_uint8_array_to_string((const uint8_t *)ri->SerialNumber,
				   sizeof(ri->SerialNumber), &serial_str_obj2);
	json_object_object_add(reason_id, "serialNumber", serial_str_obj2);
	json_object_add_value_uint64(reason_id, "oemDataMapOffset",
				   le64_to_cpu(ri->OemDataMapOffset));
	json_object_add_value_uint(reason_id, "telemetryMajorVersion",
				   le16_to_cpu(ri->TelemetryMajorVersion));
	json_object_add_value_uint(reason_id, "telemetryMinorVersion",
				   le16_to_cpu(ri->TelemetryMinorVersion));

	sldm_uint8_array_to_string((const uint8_t *)ri->Reserved,
				   sizeof(ri->Reserved), &reserved);
	json_object_object_add(reason_id, "reserved", reserved);
}

static void telemetry_log_reason_id_parse1_2_ext(const struct telemetry_log *tl,
						 struct json_object *reason_id)
{
	const struct reason_indentifier_1_2 *ri;
	struct json_object *dp_reserved = NULL;
	struct json_object *reserved = NULL;
	struct json_object *serial_str_obj3 = NULL;

	ri = (struct reason_indentifier_1_2 *) tl->log->rsnident;

	sldm_uint8_array_to_string((const uint8_t *)ri->SerialNumber,
				   sizeof(ri->SerialNumber), &serial_str_obj3);
	json_object_object_add(reason_id, "serialNumber", serial_str_obj3);
	json_object_add_value_uint64(reason_id, "oemDataMapOffset",
				     le64_to_cpu(ri->OemDataMapOffset));
	json_object_add_value_uint(reason_id, "telemetryMajorVersion",
				   le16_to_cpu(ri->TelemetryMajorVersion));
	json_object_add_value_uint(reason_id, "telemetryMinorVersion",
				   le16_to_cpu(ri->TelemetryMinorVersion));
	json_object_add_value_uint(reason_id, "productFamilyId", ri->ProductFamilyId);

	sldm_uint8_array_to_string((const uint8_t *)ri->Reserved2,
				   sizeof(ri->Reserved2), &reserved);
	json_object_object_add(reason_id, "reserved2", reserved);

	sldm_uint8_array_to_string((const uint8_t *)ri->DualPortReserved,
				   sizeof(ri->DualPortReserved), &dp_reserved);
	json_object_object_add(reason_id, "dualPortReserved", dp_reserved);
}
static void telemetry_log_reason_id_parse_ocp_2_5(const struct telemetry_log *tl,
						 struct json_object *reason_id)
{
	const struct reason_identifier_ocp_2_5 *ri;
	struct json_object *reserved = NULL;
	struct json_object *vu_extension = NULL;
	struct json_object *error_str_obj = NULL;
	struct json_object *file_str_obj = NULL;

	ri = (struct reason_identifier_ocp_2_5 *) tl->log->rsnident;

	sldm_uint8_array_to_string((const uint8_t *)ri->errorId,
				   sizeof(ri->errorId), &error_str_obj);
	json_object_object_add(reason_id, "errorId", error_str_obj);
	sldm_uint8_array_to_string((const uint8_t *)ri->fileId,
				   sizeof(ri->fileId), &file_str_obj);
	json_object_object_add(reason_id, "fileId", file_str_obj);
	json_object_add_value_uint(reason_id, "lineNum", le16_to_cpu(ri->lineNum));
	json_object_add_value_uint(reason_id, "validLineNum", ri->validFlags.validLineNum);
	json_object_add_value_uint(reason_id, "validFileId", ri->validFlags.validFileId);
	json_object_add_value_uint(reason_id, "validErrorId", ri->validFlags.validErrorId);
	json_object_add_value_uint(reason_id, "validVuExtension", ri->validFlags.validVuExtension);

	sldm_uint8_array_to_string((const uint8_t *)ri->reserved,
				   sizeof(ri->reserved), &reserved);
	json_object_object_add(reason_id, "reserved", reserved);

	sldm_uint8_array_to_string((const uint8_t *)ri->vuExtension,
				   sizeof(ri->vuExtension), &vu_extension);
	json_object_object_add(reason_id, "vuExtension", vu_extension);
}

static void solidigm_telemetry_log_reason_id_parse(const struct telemetry_log *tl, struct json_object *reason_id)
{
	const struct reason_indentifier_1_0 *ri1_0 =
		(struct reason_indentifier_1_0 *) tl->log->rsnident;
	uint16_t version_major = le16_to_cpu(ri1_0->versionMajor);
	uint16_t version_minor = le16_to_cpu(ri1_0->versionMinor);
	struct json_object *drive_status_obj = NULL;

	if (tl->is_ocp) {
		telemetry_log_reason_id_parse_ocp_2_5(tl, reason_id);
		return;
	}

	json_object_add_value_uint(reason_id, "versionMajor", version_major);
	json_object_add_value_uint(reason_id, "versionMinor", version_minor);
	json_object_add_value_uint(reason_id, "reasonCode", le32_to_cpu(ri1_0->reasonCode));
	sldm_uint8_array_to_string((const uint8_t *)ri1_0->DriveStatus,
				   sizeof(ri1_0->DriveStatus), &drive_status_obj);
	json_object_add_value_object(reason_id, "driveStatus", drive_status_obj);

	if (version_major == 1) {
		switch (version_minor) {
		case 0:
			telemetry_log_reason_id_parse1_0_ext(tl, reason_id);
			break;
		case 1:
			telemetry_log_reason_id_parse1_1_ext(tl, reason_id);
			break;
		default:
			telemetry_log_reason_id_parse1_2_ext(tl, reason_id);
			break;
		}
	}
}

bool solidigm_telemetry_log_header_parse(const struct telemetry_log *tl)
{
	const struct nvme_telemetry_log *log;
	struct json_object *ieee_oui_id = NULL;
	struct json_object *reason_id;
	struct json_object *header;

	if (tl->log_size < sizeof(const struct nvme_telemetry_log)) {
		SOLIDIGM_LOG_WARNING("Telemetry log too short.");
		return false;
	}

	header = json_create_object();

	json_object_object_add(tl->root, "telemetryHeader", header);
	log = tl->log;

	json_object_add_value_uint(header, "logIdentifier", log->lpi);
	ieee_oui_id = json_create_array();

	json_object_object_add(header, "ieeeOuiIdentifier", ieee_oui_id);
	for (int i = 0; i < sizeof(log->ieee); i++) {
		struct json_object *val = json_object_new_int(log->ieee[i]);

		json_object_array_add(ieee_oui_id, val);
	}
	json_object_add_value_uint(header, "dataArea1LastBlock", log->dalb1);
	json_object_add_value_uint(header, "dataArea2LastBlock", log->dalb2);
	json_object_add_value_uint(header, "dataArea3LastBlock", log->dalb3);
	json_object_add_value_uint(header, "dataArea4LastBlock", log->dalb4);
	json_object_add_value_uint(header, "hostInitiatedDataGeneration", log->hostdgn);
	json_object_add_value_uint(header, "controllerInitiatedDataAvailable", log->ctrlavail);
	json_object_add_value_uint(header, "controllerInitiatedDataGeneration", log->ctrldgn);

	reason_id = json_create_object();
	json_object_add_value_object(header, "reasonIdentifier", reason_id);
	solidigm_telemetry_log_reason_id_parse(tl, reason_id);

	return true;
}
