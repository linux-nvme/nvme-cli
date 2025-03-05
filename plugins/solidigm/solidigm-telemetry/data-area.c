// SPDX-License-Identifier: MIT
/*
 * Copyright (c) 2022 Solidigm.
 *
 * Author: leonardo.da.cunha@solidigm.com
 */

#include "common.h"
#include "header.h"
#include "cod.h"
#include "data-area.h"
#include "config.h"
#include "nlog.h"
#include <ctype.h>

#define SIGNED_INT_PREFIX "int"
#define BITS_IN_BYTE 8

#define MAX_WARNING_SIZE 1024
#define MAX_ARRAY_RANK 16
#define NLOG_HEADER_ID 101


static void reverse_string(char *buff, size_t len)
{
	char *start = buff;
	char *end = buff + len - 1;
	char temp;

	while (end > start) {
		temp = *end;
		*end = *start;
		*start = temp;
		start++;
		end--;
	}
}

static bool telemetry_log_get_value(const struct telemetry_log *tl,
				    uint64_t offset_bit, uint32_t size_bit,
				    bool is_signed, struct json_object **val_obj)
{
	uint32_t offset_bit_from_byte;
	uint32_t additional_size_byte;
	uint32_t offset_byte;
	uint64_t val;

	if (!size_bit) {
		char err_msg[MAX_WARNING_SIZE];

		snprintf(err_msg, MAX_WARNING_SIZE,
			 "Value with size_bit=0 not supported.");
		*val_obj = json_object_new_string(err_msg);

		return false;
	}
	additional_size_byte = (size_bit - 1) ? (size_bit - 1) / BITS_IN_BYTE : 0;
	offset_byte = (uint32_t)offset_bit / BITS_IN_BYTE;

	if (offset_byte > (tl->log_size - additional_size_byte)) {
		char err_msg[MAX_WARNING_SIZE];

		snprintf(err_msg, MAX_WARNING_SIZE,
			"Value offset greater than binary size (%u > %zu).",
			 offset_byte, tl->log_size);
		*val_obj = json_object_new_string(err_msg);

		return false;
	}

	offset_bit_from_byte = (uint32_t) (offset_bit - ((uint64_t)offset_byte * BITS_IN_BYTE));

	if ((size_bit + offset_bit_from_byte) > (sizeof(uint64_t) * BITS_IN_BYTE)) {
		char err_msg[MAX_WARNING_SIZE];

		snprintf(err_msg, MAX_WARNING_SIZE,
		    "Value crossing 64 bit, byte aligned boundary, not supported. size_bit=%u, offset_bit_from_byte=%u.",
		    size_bit, offset_bit_from_byte);
		*val_obj = json_object_new_string(err_msg);

		return false;
	}

	val = *(uint64_t *)(((char *)tl->log) + offset_byte);
	val >>= offset_bit_from_byte;
	if (size_bit < 64)
		val &= (1ULL << size_bit) - 1;
	if (is_signed) {
		if (val >> (size_bit - 1))
			val |= (0ULL - 1) << size_bit;
		*val_obj = json_object_new_int64(val);
	} else {
		*val_obj = json_object_new_uint64(val);
	}

	return true;
}

static int telemetry_log_structure_parse(const struct telemetry_log *tl,
					 struct json_object *struct_def,
					 uint64_t parent_offset_bit,
					 struct json_object *output,
					 struct json_object *metadata)
{
	struct json_object *obj_arraySizeArray = NULL;
	struct json_object *obj = NULL;
	struct json_object *obj_memberList;
	struct json_object *major_dimension = NULL;
	struct json_object *sub_output;
	bool is_enumeration = false;
	bool has_member_list;
	const char *type = "";
	const char *name;
	size_t array_rank;
	uint64_t offset_bit;
	uint32_t size_bit;
	uint64_t linear_array_pos_bit;
	uint32_t array_size_dimension[MAX_ARRAY_RANK];

	if (!json_object_object_get_ex(struct_def, "name", &obj)) {
		SOLIDIGM_LOG_WARNING("Warning: Structure definition missing property 'name': %s",
				     json_object_to_json_string(struct_def));
		return  -1;
	}

	name = json_object_get_string(obj);

	if (metadata) {
		json_object_get(obj);
		json_object_object_add(metadata, "objName", obj);
	}

	if (json_object_object_get_ex(struct_def, "type", &obj))
		type = json_object_get_string(obj);

	if (!json_object_object_get_ex(struct_def, "offsetBit", &obj)) {
		SOLIDIGM_LOG_WARNING(
		    "Warning: Structure definition missing property 'offsetBit': %s",
		    json_object_to_json_string(struct_def));
		return  -1;
	}

	offset_bit = json_object_get_uint64(obj);

	if (!json_object_object_get_ex(struct_def, "sizeBit", &obj)) {
		SOLIDIGM_LOG_WARNING(
		    "Warning: Structure definition missing property 'sizeBit': %s",
		    json_object_to_json_string(struct_def));
		return  -1;
	}

	size_bit = (uint32_t)json_object_get_uint64(obj);

	if (json_object_object_get_ex(struct_def, "enum", &obj))
		is_enumeration = json_object_get_boolean(obj);

	has_member_list = json_object_object_get_ex(struct_def,
						    "memberList",
						    &obj_memberList);

	if (!json_object_object_get_ex(struct_def, "arraySize",
				       &obj_arraySizeArray)) {
		SOLIDIGM_LOG_WARNING(
		    "Warning: Structure definition missing property 'arraySize': %s",
		    json_object_to_json_string(struct_def));
		return  -1;
	}

	array_rank = json_object_array_length(obj_arraySizeArray);
	if (!array_rank) {
		SOLIDIGM_LOG_WARNING(
		    "Warning: Structure property 'arraySize' don't support flexible array: %s",
		    json_object_to_json_string(struct_def));
		return -1;
	}
	if (array_rank > MAX_ARRAY_RANK) {
		SOLIDIGM_LOG_WARNING(
		    "Warning: Structure property 'arraySize' don't support more than %d dimensions: %s",
		    MAX_ARRAY_RANK, json_object_to_json_string(struct_def));
		return -1;
	}

	for (size_t i = 0; i < array_rank; i++) {
		struct json_object *dimension = json_object_array_get_idx(obj_arraySizeArray, i);

		array_size_dimension[i] = json_object_get_int(dimension);
		major_dimension = dimension;
	}
	if (array_rank > 1) {
		uint32_t linear_pos_per_index = array_size_dimension[0];
		uint32_t prev_index_offset_bit = 0;
		struct json_object *dimension_output;

		for (unsigned int i = 1; i < (array_rank - 1); i++)
			linear_pos_per_index *= array_size_dimension[i];

		dimension_output = json_create_array();
		if (json_object_get_type(output) == json_type_array)
			json_object_array_add(output, dimension_output);
		else
			json_object_add_value_array(output, name, dimension_output);

		/*
		 * Make sure major_dimension object will not be
		 * deleted from memory when deleted from array
		 */
		json_object_get(major_dimension);
		json_object_array_del_idx(obj_arraySizeArray, array_rank - 1, 1);

		for (unsigned int i = 0 ; i < array_size_dimension[0]; i++) {
			struct json_object *sub_array = json_create_array();
			uint64_t offset;

			offset = parent_offset_bit + prev_index_offset_bit;

			json_object_array_add(dimension_output, sub_array);
			telemetry_log_structure_parse(tl, struct_def,
						      offset, sub_array, NULL);
			prev_index_offset_bit += linear_pos_per_index * size_bit;
		}

		json_object_array_put_idx(obj_arraySizeArray, array_rank - 1,
					  major_dimension);

		return 0;
	}

	linear_array_pos_bit = 0;
	sub_output = output;

	if (array_size_dimension[0] > 1) {
		sub_output = json_create_array();
		if (json_object_get_type(output) == json_type_array)
			json_object_array_add(output, sub_output);
		else
			json_object_add_value_array(output, name, sub_output);
	}

	for (uint32_t j = 0; j < array_size_dimension[0]; j++) {
		if (is_enumeration || !has_member_list) {
			bool is_signed = !strncmp(type, SIGNED_INT_PREFIX, sizeof(SIGNED_INT_PREFIX)-1);
			struct json_object *val_obj;
			uint64_t offset;

			offset = parent_offset_bit + offset_bit + linear_array_pos_bit;
			if (telemetry_log_get_value(tl, offset, size_bit, is_signed, &val_obj)) {
				if (array_size_dimension[0] > 1)
					json_object_array_put_idx(sub_output, j, val_obj);
				else
					json_object_object_add(sub_output, name, val_obj);
			} else {
				SOLIDIGM_LOG_WARNING(
				    "Warning: %s From property '%s', array index %u, structure definition: %s",
				    json_object_get_string(val_obj), name, j,
				    json_object_to_json_string(struct_def));
				json_free_object(val_obj);
			}
		} else {
			struct json_object *sub_sub_output = json_create_object();
			int num_members;

			if (array_size_dimension[0] > 1)
				json_object_array_put_idx(sub_output, j, sub_sub_output);
			else
				json_object_add_value_object(sub_output, name, sub_sub_output);

			num_members = json_object_array_length(obj_memberList);
			for (int k = 0; k < num_members; k++) {
				struct json_object *member = json_object_array_get_idx(obj_memberList, k);
				uint64_t offset;

				offset = parent_offset_bit + offset_bit + linear_array_pos_bit;
				telemetry_log_structure_parse(tl, member, offset,
							      sub_sub_output, NULL);
			}
		}
		linear_array_pos_bit += size_bit;
	}
	return 0;
}

static int telemetry_log_data_area_get_offset(const struct telemetry_log *tl,
					      enum nvme_telemetry_da da,
					      uint32_t *offset, uint32_t *size)
{
	uint32_t offset_blocks = 1;
	uint32_t last_block = tl->log->dalb1;
	uint32_t last;

	switch (da) {
	case NVME_TELEMETRY_DA_1:
		offset_blocks = 1;
		last_block = tl->log->dalb1;
		break;
	case NVME_TELEMETRY_DA_2:
		offset_blocks = tl->log->dalb1 + 1;
		last_block = tl->log->dalb2;
		break;
	case NVME_TELEMETRY_DA_3:
		offset_blocks = tl->log->dalb2 + 1;
		last_block = tl->log->dalb3;
		break;
	case NVME_TELEMETRY_DA_4:
		offset_blocks = tl->log->dalb3 + 1;
		last_block = tl->log->dalb4;
		break;
	default:
		return -1;
	}

	*offset = offset_blocks * NVME_LOG_TELEM_BLOCK_SIZE;
	last = (last_block + 1) * NVME_LOG_TELEM_BLOCK_SIZE;
	*size = last - *offset;
	if ((*offset > tl->log_size) || (last > tl->log_size) || (last <= *offset)) {
		SOLIDIGM_LOG_WARNING("Warning: Data Area %d don't fit this Telemetry log.", da);
		return -1;
	}

	return 0;
}

static int telemetry_log_nlog_parse(const struct telemetry_log *tl, struct json_object *formats,
				    uint64_t nlog_file_offset,	uint64_t nlog_size,
				    struct json_object *output, struct json_object *metadata)
{
	/* boundary check */
	if (tl->log_size < (nlog_file_offset + nlog_size)) {
		const char *name = "";
		int media_bank = -1;
		struct json_object *jobj;

		if (json_object_object_get_ex(metadata, "objName", &jobj))
			name = json_object_get_string(jobj);
		if (json_object_object_get_ex(metadata, "mediaBankId", &jobj))
			media_bank = json_object_get_int(jobj);
		SOLIDIGM_LOG_WARNING("%s:%d do not fit this log dump.", name, media_bank);
		return -1;
	}
	return solidigm_nlog_parse(((char *) tl->log) + nlog_file_offset,
				   nlog_size, formats, metadata, output);
}

struct toc_item {
	uint32_t OffsetBytes;
	uint32_t ContentSizeBytes;
};

struct data_area_header {
	uint8_t versionMajor;
	uint8_t versionMinor;
	uint16_t TableOfContentsCount;
	uint32_t DataAreaSize;
	uint8_t Reserved[8];
};

struct table_of_contents {
	struct data_area_header header;
	struct toc_item items[];
};

struct telemetry_object_header {
	uint16_t versionMajor;
	uint16_t versionMinor;
	uint32_t Token;
	uint8_t CoreId;
	uint8_t Reserved[3];
};

static void telemetry_log_data_area_toc_parse(const struct telemetry_log *tl,
					      enum nvme_telemetry_da da,
					      struct json_object *toc_array,
					      struct json_object *tele_obj_array)
{

	const struct telemetry_object_header *header;
	const struct table_of_contents *toc;
	char *payload;
	uint32_t da_offset;
	uint32_t da_size;
	struct json_object *nlog_formats;

	if (telemetry_log_data_area_get_offset(tl, da, &da_offset, &da_size))
		return;

	toc = (struct table_of_contents *)(((char *)tl->log) + da_offset);
	payload = (char *) tl->log;
	nlog_formats = solidigm_config_get_nlog_formats(tl->configuration);

	for (int i = 0; i < toc->header.TableOfContentsCount; i++) {
		struct json_object *structure_definition = NULL;
		struct json_object *toc_item;
		uint32_t obj_offset;
		bool has_struct;
		const char *nlog_name = NULL;
		uint32_t header_offset = sizeof(const struct telemetry_object_header);

		if ((char *)&toc->items[i] >
		    (((char *)toc) + da_size - sizeof(const struct toc_item))) {
			SOLIDIGM_LOG_WARNING(
			    "Warning: Data Area %d, Table of Contents item %d crossed Data Area size.",
			    da, i);
			return;
		}

		obj_offset = toc->items[i].OffsetBytes;
		if ((obj_offset + sizeof(const struct telemetry_object_header)) > da_size) {
			SOLIDIGM_LOG_WARNING(
			    "Warning: Data Area %d, item %d data, crossed Data Area size.", da, i);
			continue;
		}

		toc_item = json_create_object();
		json_object_array_add(toc_array, toc_item);
		json_object_add_value_uint(toc_item, "dataArea", da);
		json_object_add_value_uint(toc_item, "dataAreaIndex", i);
		json_object_add_value_uint(toc_item, "dataAreaOffset", obj_offset);
		json_object_add_value_uint(toc_item, "fileOffset", obj_offset + da_offset);
		json_object_add_value_uint(toc_item, "size", toc->items[i].ContentSizeBytes);

		header = (const struct telemetry_object_header *) (payload + da_offset + obj_offset);
		json_object_add_value_uint(toc_item, "telemMajor", header->versionMajor);
		json_object_add_value_uint(toc_item, "telemMinor", header->versionMinor);
		json_object_add_value_uint(toc_item, "objectId", header->Token);
		json_object_add_value_uint(toc_item, "mediaBankId", header->CoreId);

		has_struct = solidigm_config_get_struct_by_token_version(tl->configuration,
									 header->Token,
									 header->versionMajor,
									 header->versionMinor,
									 &structure_definition);
		if (!has_struct) {
			if (!nlog_formats)
				continue;
			nlog_name = solidigm_config_get_nlog_obj_name(tl->configuration,
									header->Token);
			if (!nlog_name)
				continue;

			// NLOGs have different parser from other Telemetry objects
			has_struct = solidigm_config_get_struct_by_token_version(tl->configuration,
				NLOG_HEADER_ID,
				header->versionMajor,
				header->versionMinor,
				&structure_definition);
		}
		struct json_object *tele_obj_item = json_create_object();

		json_object_array_add(tele_obj_array, tele_obj_item);
		json_object_get(toc_item);
		json_object_add_value_object(tele_obj_item, "metadata", toc_item);
		struct json_object *parsed_struct = json_create_object();

		json_object_add_value_object(tele_obj_item, "objectData", parsed_struct);
		struct json_object *obj_hasTelemObjHdr = NULL;
		uint64_t object_file_offset;

		if (json_object_object_get_ex(structure_definition,
						"hasTelemObjHdr",
						&obj_hasTelemObjHdr)) {
			bool hasHeader = json_object_get_boolean(obj_hasTelemObjHdr);

			if (hasHeader)
				header_offset = 0;
		}
		object_file_offset = ((uint64_t)da_offset) + obj_offset + header_offset;
		if (has_struct) {
			telemetry_log_structure_parse(tl, structure_definition,
						BITS_IN_BYTE * object_file_offset,
						parsed_struct, toc_item);
		}
		// NLOGs have different parser from other Telemetry objects
		if (nlog_name) {
			if (has_struct) {
				struct json_object *header_sizeBits = NULL;
				struct json_object *header_nlogSelect = NULL;
				struct json_object *header_nlogName = NULL;

				if (json_object_object_get_ex(structure_definition, "sizeBit",
							      &header_sizeBits))
					header_offset = json_object_get_int(header_sizeBits) /
							BITS_IN_BYTE;
				// Overwrite nlogName with correct type
				if (json_object_object_get_ex(parsed_struct, "nlogSelect",
				    &header_nlogSelect) &&
				    json_object_object_get_ex(header_nlogSelect, "nlogName",
				    &header_nlogName)) {
					int nlogName = json_object_get_int(header_nlogName);
					char *name = (char *)&nlogName;

					reverse_string(name, sizeof(uint32_t));
					json_object_object_add(header_nlogSelect, "nlogName",
						json_object_new_string_len(name,
									   sizeof(uint32_t)));
				}
			}
			// Overwrite the object name
			json_object_object_add(toc_item, "objName",
					       json_object_new_string(nlog_name));

			telemetry_log_nlog_parse(tl, nlog_formats,
						 object_file_offset + header_offset,
						 toc->items[i].ContentSizeBytes - header_offset,
						 parsed_struct, toc_item);
		}
	}
}

void solidigm_telemetry_log_da1_check_ocp(struct telemetry_log *tl)
{
	const uint64_t ocp_telemetry_uuid[] = {0xBC73719D87E64EFA, 0xBA560A9C3043424C};
	const uint64_t *log_uuid = (uint64_t *) &tl->log->data_area[16];

	tl->is_ocp = tl->log_size >= (&tl->log->data_area[32] - (uint8_t *) tl->log) &&
		log_uuid[0] == ocp_telemetry_uuid[0] && log_uuid[1] == ocp_telemetry_uuid[1];
}

int solidigm_telemetry_log_data_areas_parse(struct telemetry_log *tl,
					    enum nvme_telemetry_da last_da)
{
	struct json_object *tele_obj_array = json_create_array();
	struct json_object *toc_array = json_create_array();

	solidigm_telemetry_log_da1_check_ocp(tl);
	solidigm_telemetry_log_header_parse(tl);
	solidigm_telemetry_log_cod_parse(tl);
	if (tl->configuration) {
		enum nvme_telemetry_da first_da = NVME_TELEMETRY_DA_1;

		if (tl->is_ocp)
			first_da = NVME_TELEMETRY_DA_3;

		json_object_add_value_array(tl->root, "tableOfContents", toc_array);
		json_object_add_value_array(tl->root, "telemetryObjects", tele_obj_array);

		for (enum nvme_telemetry_da da = first_da; da <= last_da; da++)
			telemetry_log_data_area_toc_parse(tl, da, toc_array, tele_obj_array);
	}
	return 0;
}
