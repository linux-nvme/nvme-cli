// SPDX-License-Identifier: MIT
/*
 * Copyright (c) 2022 Solidigm.
 *
 * Author: leonardo.da.cunha@solidigm.com
 */

#include "common.h"
#include "data-area.h"
#include "config.h"
#include <ctype.h>

#define SIGNED_INT_PREFIX "int"
#define BITS_IN_BYTE 8

#define MAX_WARNING_SIZE 1024

static bool telemetry_log_get_value(const struct telemetry_log *tl,
				    uint32_t offset_bit, uint32_t size_bit,
				    bool is_signed, json_object **val_obj)
{
	uint32_t offset_bit_from_byte;
	uint32_t additional_size_byte;
	uint32_t offset_byte;
	uint32_t val;

	if (size_bit == 0) {
		char err_msg[MAX_WARNING_SIZE];

		snprintf(err_msg, MAX_WARNING_SIZE,
			 "Value with size_bit=0 not supported.");
		*val_obj = json_object_new_string(err_msg);

		return false;
	}
	additional_size_byte = (size_bit - 1) ? (size_bit - 1) / BITS_IN_BYTE : 0;
	offset_byte = offset_bit / BITS_IN_BYTE;

	if (offset_byte > (tl->log_size - additional_size_byte)) {
		char err_msg[MAX_WARNING_SIZE];

		snprintf(err_msg, MAX_WARNING_SIZE,
			"Value offset greater than binary size (%u > %zu).",
			 offset_byte, tl->log_size);
		*val_obj = json_object_new_string(err_msg);

		return false;
	}

	offset_bit_from_byte = offset_bit - (offset_byte * BITS_IN_BYTE);

	if ((size_bit + offset_bit_from_byte) > (sizeof(uint64_t) * BITS_IN_BYTE)) {
		char err_msg[MAX_WARNING_SIZE];

		snprintf(err_msg, MAX_WARNING_SIZE,
			 "Value crossing 64 bit, byte aligned bounday, "
			 "not supported. size_bit=%u, offset_bit_from_byte=%u.",
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
			val |= -1ULL << size_bit;
		*val_obj = json_object_new_int64(val);
	} else {
		*val_obj = json_object_new_uint64(val);
	}

	return true;
}

static int telemetry_log_structure_parse(const struct telemetry_log *tl,
					 json_object *struct_def,
					 size_t parent_offset_bit,
					 json_object *output,
					 json_object *metadata)
{
	json_object *obj_arraySizeArray = NULL;
	json_object *obj = NULL;
	json_object *obj_memberList;
	json_object *major_dimension;
	json_object *sub_output;
	bool is_enumeration = false;
	bool has_member_list;
	const char *type = "";
	const char *name;
	size_t array_rank;
	size_t offset_bit;
	size_t size_bit;
	uint32_t linear_array_pos_bit;

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
		SOLIDIGM_LOG_WARNING("Warning: Structure definition missing "
				     "property 'offsetBit': %s",
				     json_object_to_json_string(struct_def));
		return  -1;
	}

	offset_bit = json_object_get_uint64(obj);

	if (!json_object_object_get_ex(struct_def, "sizeBit", &obj)) {
		SOLIDIGM_LOG_WARNING("Warning: Structure definition missing "
				     "property 'sizeBit': %s",
				     json_object_to_json_string(struct_def));
		return  -1;
	}

	size_bit = json_object_get_uint64(obj);

	if (json_object_object_get_ex(struct_def, "enum", &obj))
		is_enumeration = json_object_get_boolean(obj);

	has_member_list = json_object_object_get_ex(struct_def,
						    "memberList",
						    &obj_memberList);

	if (!json_object_object_get_ex(struct_def, "arraySize",
				       &obj_arraySizeArray)) {
		SOLIDIGM_LOG_WARNING("Warning: Structure definition missing "
				     "property 'arraySize': %s",
				     json_object_to_json_string(struct_def));
		return  -1;
	}

	array_rank = json_object_array_length(obj_arraySizeArray);
	if (array_rank == 0) {
		SOLIDIGM_LOG_WARNING("Warning: Structure property 'arraySize' "
				     "don't support flexible array: %s",
				     json_object_to_json_string(struct_def));
		return -1;
	}
	uint32_t array_size_dimension[array_rank];

	for (size_t i = 0; i < array_rank; i++) {
		json_object *dimension = json_object_array_get_idx(obj_arraySizeArray, i);

		array_size_dimension[i] = json_object_get_uint64(dimension);
		major_dimension = dimension;
	}
	if (array_rank > 1) {
		uint32_t linear_pos_per_index = array_size_dimension[0];
		uint32_t prev_index_offset_bit = 0;
		json_object *dimension_output;

		for (int i = 1; i < (array_rank - 1); i++)
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

		for (int i = 0 ; i < array_size_dimension[0]; i++) {
			json_object *sub_array = json_create_array();
			size_t offset;

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
			json_object *val_obj;
			size_t offset;

			offset = parent_offset_bit + offset_bit + linear_array_pos_bit;
			if (telemetry_log_get_value(tl, offset, size_bit, is_signed, &val_obj)) {
				if (array_size_dimension[0] > 1)
					json_object_array_put_idx(sub_output, j, val_obj);
				else
					json_object_object_add(sub_output, name, val_obj);
			} else {
				SOLIDIGM_LOG_WARNING("Warning: %s From property '%s', "
						     "array index %u, structure definition: %s",
						     json_object_get_string(val_obj),
						     name, j, json_object_to_json_string(struct_def));
				json_free_object(val_obj);
			}
		} else {
			json_object *sub_sub_output = json_object_new_object();
			int num_members;

			if (array_size_dimension[0] > 1)
				json_object_array_put_idx(sub_output, j, sub_sub_output);
			else
				json_object_add_value_object(sub_output, name, sub_sub_output);

			num_members = json_object_array_length(obj_memberList);
			for (int k = 0; k < num_members; k++) {
				json_object *member = json_object_array_get_idx(obj_memberList, k);
				size_t offset;

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
					      json_object *toc_array,
					      json_object *tele_obj_array)
{

	const struct telemetry_object_header *header;
	const struct table_of_contents *toc;
	char *payload;
	uint32_t da_offset;
	uint32_t da_size;

	if (telemetry_log_data_area_get_offset(tl, da, &da_offset, &da_size))
		return;

	toc = (struct table_of_contents *)(((char *)tl->log) + da_offset);
	payload = (char *) tl->log;

	for (int i = 0; i < toc->header.TableOfContentsCount; i++) {
		json_object *structure_definition = NULL;
		json_object *toc_item;
		uint32_t obj_offset;
		bool has_struct;

		if ((char *)&toc->items[i] > (((char *)toc) + da_size - sizeof(const struct toc_item))) {
			SOLIDIGM_LOG_WARNING("Warning: Data Area %d, "
					     "Table of Contents item %d "
					     "crossed Data Area size.", da, i);
			return;
		}

		obj_offset = toc->items[i].OffsetBytes;
		if ((obj_offset + sizeof(const struct telemetry_object_header)) > da_size) {
			SOLIDIGM_LOG_WARNING("Warning: Data Area %d, item %d "
					     "data, crossed Data Area size.", da, i);
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

		has_struct = solidigm_config_get_by_token_version(tl->configuration,
							          header->Token,
								  header->versionMajor,
								  header->versionMinor,
								  &structure_definition);

		if (has_struct) {
			json_object *tele_obj_item = json_create_object();

			json_object_array_add(tele_obj_array, tele_obj_item);
			json_object_get(toc_item);
			json_object_add_value_object(tele_obj_item, "metadata", toc_item);
			json_object *parsed_struct = json_object_new_object();

			json_object_add_value_object(tele_obj_item, "objectData", parsed_struct);
			json_object *obj_hasTelemObjHdr = NULL;
			uint32_t header_offset = sizeof(const struct telemetry_object_header);
			uint32_t file_offset;

			if (json_object_object_get_ex(structure_definition,
						      "hasTelemObjHdr",
						       &obj_hasTelemObjHdr)) {
				bool hasHeader = json_object_get_boolean(obj_hasTelemObjHdr);

				if (hasHeader)
					header_offset = 0;
			}

			file_offset = da_offset + obj_offset + header_offset;
			telemetry_log_structure_parse(tl, structure_definition,
						      BITS_IN_BYTE * file_offset,
						      parsed_struct, toc_item);
		}
	}
}

int solidigm_telemetry_log_data_areas_parse(const struct telemetry_log *tl,
					    enum nvme_telemetry_da last_da)
{
	json_object *tele_obj_array = json_create_array();
	json_object *toc_array = json_create_array();

	json_object_add_value_array(tl->root, "tableOfContents", toc_array);
	json_object_add_value_array(tl->root, "telemetryObjects", tele_obj_array);

	for (enum nvme_telemetry_da da = NVME_TELEMETRY_DA_1; da <= last_da; da++)
		telemetry_log_data_area_toc_parse(tl, da, toc_array, tele_obj_array);

	return 0;
}
