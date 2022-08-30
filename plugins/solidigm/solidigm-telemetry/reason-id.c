// SPDX-License-Identifier: MIT-0
/*
 * Copyright (c) 2022 Solidigm.
 *
 * Author: leonardo.da.cunha@solidigm.com
 */

#include "common.h"
#include "reason-id.h"

#pragma pack(push, reason_indentifier, 1)
struct reason_indentifier_1_0
{
	uint16_t versionMajor;
	uint16_t versionMinor;
	uint32_t reasonCode;        //! 0 denotes no issue. All other values denote a potential issue.
	char DriveStatus[20];       //! Drive Status String (for example: "Healthy", "*BAD_CONTEXT_2020")
	char FirmwareVersion[12];   //! Similar to IdentifyController.FR
	char BootloaderVersion[12]; //! Bootloader version string
	char SerialNumber[20];      //! Device serial number	
	uint8_t Reserved[56];       //! Reserved for future usage
};

struct reason_indentifier_1_1
{
	uint16_t versionMajor;
	uint16_t versionMinor;
	uint32_t reasonCode;        //! 0 denotes no issue. All other values denote a potential issue.
	char DriveStatus[20];       //! Drive Status String (for example: "Healthy", "*BAD_CONTEXT_2020")
	char FirmwareVersion[12];   //! Similar to IdentifyController.FR
	char BootloaderVersion[12]; //! Bootloader version string
	char SerialNumber[20];      //! Device serial number
	uint64_t OemDataMapOffset;	//! Customer Data Map Object Log Offset
	uint8_t TelemetryMajorVersion; //! Shadow of version in TOC
	uint8_t TelemetryMinorVersion; //! Shadow of version in TOC
	uint8_t Reserved[46];       //! Reserved for future usage
};

struct reason_indentifier_1_2
{
	uint16_t versionMajor;
	uint16_t versionMinor;
	uint32_t reasonCode;        //! 0 denotes no issue. All other values denote a potential issue.
	char DriveStatus[20];       //! Drive Status String (for example: "Healthy", "*BAD_CONTEXT_2020")
	uint8_t Reserved1[24];		//! pad over Fields removed from version 1.1
	char SerialNumber[20];      //! Device serial number		
	uint64_t OemDataMapOffset;	//! Customer Data Map Object Log Offset
	uint8_t TelemetryMajorVersion; //! Shadow of version in TOC
	uint8_t TelemetryMinorVersion; //! Shadow of version in TOC
	uint8_t ProductFamilyId;
	uint8_t Reserved2[5];       //! Reserved for future usage
	uint8_t DualPortReserved[40];  //! Reserved for dual port
};
#pragma pack(pop, reason_indentifier)

static void telemetry_log_reason_id_parse1_0_ext(struct telemetry_log *tl, json_object *reason_id)
{
	const struct reason_indentifier_1_0 *ri = (struct reason_indentifier_1_0 *) tl->log->rsnident;
	json_object_object_add(reason_id, "FirmwareVersion", json_object_new_string_len(ri->FirmwareVersion, sizeof(ri->FirmwareVersion)));
	json_object_object_add(reason_id, "BootloaderVersion", json_object_new_string_len(ri->BootloaderVersion, sizeof(ri->BootloaderVersion)));
	json_object_object_add(reason_id, "SerialNumber", json_object_new_string_len(ri->SerialNumber, sizeof(ri->SerialNumber)));
	json_object *reserved = json_create_array();
	json_object_add_value_array(reason_id, "Reserved", reserved);
	for ( int i=0; i < sizeof(ri->Reserved); i++) {
		json_object *val = json_object_new_int(ri->Reserved[i]);
		json_object_array_add(reserved, val);
	}
}

static void telemetry_log_reason_id_parse1_1_ext(struct telemetry_log *tl, json_object *reason_id)
{
	const struct reason_indentifier_1_1 *ri = (struct reason_indentifier_1_1 *) tl->log->rsnident;
	json_object_object_add(reason_id, "FirmwareVersion", json_object_new_string_len(ri->FirmwareVersion, sizeof(ri->FirmwareVersion)));
	json_object_object_add(reason_id, "BootloaderVersion", json_object_new_string_len(ri->BootloaderVersion, sizeof(ri->BootloaderVersion)));
	json_object_object_add(reason_id, "SerialNumber", json_object_new_string_len(ri->SerialNumber, sizeof(ri->SerialNumber)));
	json_object_add_value_uint64(reason_id, "OemDataMapOffset", le64_to_cpu(ri->OemDataMapOffset));
	json_object_add_value_uint(reason_id, "TelemetryMajorVersion", le16_to_cpu(ri->TelemetryMajorVersion));
	json_object_add_value_uint(reason_id, "TelemetryMinorVersion", le16_to_cpu(ri->TelemetryMinorVersion));
	json_object *reserved = json_create_array();
	json_object_add_value_array(reason_id, "Reserved", reserved);
	for ( int i=0; i < sizeof(ri->Reserved); i++) {
		json_object *val = json_object_new_int(ri->Reserved[i]);
		json_object_array_add(reserved, val);
	}
}

static void telemetry_log_reason_id_parse1_2_ext(struct telemetry_log *tl, json_object *reason_id)
{
	const struct reason_indentifier_1_2 *ri = (struct reason_indentifier_1_2 *) tl->log->rsnident;
	json_object_object_add(reason_id, "SerialNumber", json_object_new_string_len(ri->SerialNumber, sizeof(ri->SerialNumber)));
	json_object_add_value_uint64(reason_id, "OemDataMapOffset", le64_to_cpu(ri->OemDataMapOffset));
	json_object_add_value_uint(reason_id, "TelemetryMajorVersion", le16_to_cpu(ri->TelemetryMajorVersion));
	json_object_add_value_uint(reason_id, "TelemetryMinorVersion", le16_to_cpu(ri->TelemetryMinorVersion));
	json_object_add_value_uint(reason_id, "ProductFamilyId", ri->ProductFamilyId);
	json_object *reserved = json_create_array();
	json_object_add_value_array(reason_id, "Reserved2", reserved);
	for ( int i=0; i < sizeof(ri->Reserved2); i++) {
		json_object *val = json_object_new_int(ri->Reserved2[i]);
		json_object_array_add(reserved, val);
	}
	json_object *dp_reserved = json_create_array();
	json_object_add_value_array(reason_id, "DualPortReserved", dp_reserved);
	for ( int i=0; i < sizeof(ri->DualPortReserved); i++) {
		json_object *val =  json_object_new_int(ri->DualPortReserved[i]);
		json_object_array_add(dp_reserved, val);
	}
}

void solidigm_telemetry_log_reason_id_parse(struct telemetry_log *tl)
{
	json_object *reason_id = json_create_object();
	struct reason_indentifier_1_0 * ri1_0 = (struct reason_indentifier_1_0 *) tl->log->rsnident;
	__u16 version_major = le16_to_cpu(ri1_0->versionMajor);
	__u16 version_minor = le16_to_cpu(ri1_0->versionMinor);
	json_object_add_value_object(tl->root, "reason_identifier", reason_id);
	json_object_add_value_uint(reason_id, "versionMajor", version_major);
	json_object_add_value_uint(reason_id, "versionMinor", version_minor);
	json_object_add_value_uint(reason_id, "reasonCode", le32_to_cpu(ri1_0->reasonCode));
	json_object_object_add(reason_id, "DriveStatus", json_object_new_string_len(ri1_0->DriveStatus, sizeof(ri1_0->DriveStatus)));
	if (version_major == 1) {
		switch (version_minor){
			case 0:
				telemetry_log_reason_id_parse1_0_ext(tl, reason_id);
				break;
			case 1:
				telemetry_log_reason_id_parse1_1_ext(tl, reason_id);
				break;
			default:
				telemetry_log_reason_id_parse1_2_ext(tl, reason_id);
		}
	}
}
