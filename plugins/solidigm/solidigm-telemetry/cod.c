// SPDX-License-Identifier: MIT
/*
 * Copyright (c) 2022 Solidigm.
 *
 * Author: leonardo.da.cunha@solidigm.com
 */
#include "common.h"
#include "cod.h"

const char *oemDataMapDesc[] = {
	"Media Read Count", //Uid 0x00
	"Host Read count",  //Uid 0x01
	"Media Write Count",  //Uid 0x02
	"Host Write Count",  //Uid 0x03
	"Device Model", // 0x04
	"Serial Number", // 0x05
	"Firmware Revision", // 0x06
	"Drive Status", // 0x07
	"Minimum Temperature", // 0x08
	"Maximum Temperature", // 0x09
	"Power Loss Protection Status", // 0x0a
	"Lifetime Unsafe Shutdown Count", // 0x0b
	"Lifetime Power Cycle Count", // 0x0c
	"Minimum Read Latency", // 0x0d
	"Maximum Read Latency", // 0x0e
	"Average Read Latency", // 0x0f
	"Minimum Write Latency", // 0x10
	"Maximum Write Latency", // 0x11
	"Average Write Latency", // 0x12
	"Grown Defects Count", // 0x13
	"DQS Recovery Count", // 0x14
	"Program Fail Count", // 0x15
	"Erase Fail Count",  // 0x16
	"Defrag Writes in Progress Count",  // 0x17
	"Total Defrag Writes Count",  // 0x18
	"Max Die Offline Number",  // 0x19
	"Current Die Offline Number",  // 0x1A
	"XOR Enable Status",  // 0x1B
	"Media Life Used",  // 0x1C
	"Uncorrectable Error Count",  // 0x1D
	"Current Wear Range Delta", // 0x1E
	"Read Errors Corrected by XOR", // 0x1F
	"Background Data Refresh", // 0x20
	"Pmic Vin History Data 1 Min", // 0x21
	"Pmic Vin History Data 1 Max", // 0x22
	"Pmic Vin History Data 1 Avg", // 0x23
	"Pmic Vin History Data 2 Min", // 0x24
	"Pmic Vin History Data 2 Max", // 0x25
	"Pmic Vin History Data 2 Avg", // 0x26
	"Pmic Vin History Data Total Readings", // 0x27
	"All Time Current Max Wear Level", // 0x28
	"Media Wear Remaining", // 0x29
	"Total Non-Defrag Writes",  // 0x2A
	"Number of sectors relocated in reaction to an error" //Uid 0x2B = 43
};

static const char * getOemDataMapDescription(__u32 id)
{
	if (id < (sizeof(oemDataMapDesc) / sizeof(oemDataMapDesc[0]))) {
		return oemDataMapDesc[id];
	}
	return "unknown";
}

#define OEMSIGNATURE 0x504D4443

#pragma pack(push, cod, 1)
struct cod_header
{
	uint32_t versionMajor;
	uint32_t versionMinor;
	uint32_t Signature;      //!Fixed signature value (0x504D4443) for identification and validation
	uint32_t MapSizeInBytes; //!Total size of the map data structure in bytes
	uint32_t EntryCount;     //!Total number of entries in the entry list
	uint8_t Reserved[12];
};

struct cod_item
{
	uint32_t DataFieldMapUid;       //!The data field unique identifier value
	uint32_t reserved1 : 8;
	uint32_t dataFieldType : 8;
	uint32_t issigned : 1;
	uint32_t bigEndian : 1;
	uint32_t dataInvalid : 1;
	uint32_t reserved2 : 13;
	uint32_t DataFieldSizeInBytes;
	uint8_t Reserved1[4];
	uint64_t DataFieldOffset;
	uint8_t Reserved2[8];
};

struct cod_map
{
	struct cod_header header;
	struct cod_item items[];
};

#pragma pack(pop, cod)

void solidigm_telemetry_log_cod_parse(struct telemetry_log *tl)
{
	enum cod_field_type
	{
		INTEGER,
		FLOAT,
		STRING,
		TWO_BYTE_ASCII,
		FOUR_BYTE_ASCII,

		UNKNOWN = 0xFF,
	};
	json_object *telemetry_header = NULL;
	json_object *COD_offset = NULL;
	json_object *reason_id = NULL;

	if (!json_object_object_get_ex(tl->root, "telemetryHeader", &telemetry_header))
		return;
	if (!json_object_object_get_ex(telemetry_header, "reasonIdentifier", &reason_id))
		return;
	if  (!json_object_object_get_ex(reason_id, "OemDataMapOffset", &COD_offset))
		return;

	__u64 offset = json_object_get_int(COD_offset);

	if  (offset ==  0) {
		return;
	}

	if ((offset + sizeof(struct cod_header)) > tl->log_size) {
		SOLIDIGM_LOG_WARNING("Warning: COD map header out of bounds.");
		return;
	}

	const struct cod_map *data = (struct cod_map *) (((__u8 *)tl->log ) + offset);

	uint32_t signature = be32_to_cpu(data->header.Signature);
	if ( signature != OEMSIGNATURE){
		SOLIDIGM_LOG_WARNING("Warning: Unsupported COD data signature %x!", signature);
		return;
	}
	if ((offset + data->header.MapSizeInBytes) > tl->log_size){
		SOLIDIGM_LOG_WARNING("Warning: COD map data out of bounds.");
		return;
	}

	json_object *cod = json_create_object();
	json_object_object_add(tl->root, "cod", cod);

	for (int i =0 ; i < data->header.EntryCount; i++) {
		if ((offset + sizeof(struct cod_header) + (i + 1) * sizeof(struct cod_item)) >
		tl->log_size){
			SOLIDIGM_LOG_WARNING("Warning: COD data out of bounds at item %d!", i);
			return;
		}
		struct cod_item item = data->items[i];
		if (item.DataFieldOffset + item.DataFieldOffset > tl->log_size) {
			continue;
		}
		if (item.dataInvalid) {
			continue;
		}
		uint8_t *val = ((uint8_t *)tl->log )+ item.DataFieldOffset;
		const char *key =  getOemDataMapDescription(item.DataFieldMapUid);
		switch(item.dataFieldType){
			case(INTEGER):
				if (item.issigned) {
					json_object_object_add(cod, key,
						json_object_new_int64(le64_to_cpu(*(uint64_t *)val)));
				} else {
					json_object_add_value_uint64(cod, key, le64_to_cpu(*(uint64_t *)val));
				}
				break;
			case(FLOAT):
				json_object_add_value_float(cod, key, *(float *) val);
				break;
			case(STRING):
				json_object_object_add(cod, key,
					json_object_new_string_len((const char *)val, item.DataFieldSizeInBytes));
				break;
			case(TWO_BYTE_ASCII):
				json_object_object_add(cod, key,
					json_object_new_string_len((const char *)val,2));
				break;
			case(FOUR_BYTE_ASCII):
				json_object_object_add(cod, key,
					json_object_new_string_len((const char *)val, 4));
				break;
			default:
				SOLIDIGM_LOG_WARNING("Warning: Unknown COD field type (%d)", item.DataFieldMapUid);
				
		}
	}
}
