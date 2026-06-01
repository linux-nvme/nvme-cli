// SPDX-License-Identifier: MIT
/*
 * Copyright (c) 2025 Solidigm.
 *
 * Author: leonardo.da.cunha@solidigm.com
 */

#include "common.h"
#include "telemetry-log.h"
#include "config.h"
#include "tracker.h"
#include "skht.h"
#include "util/json.h"
#include "data-area.h"
#include "debug-info.h"

static char *json_byte_array_to_string(struct json_object *array)
{
	size_t len = json_object_array_length(array);
	char *str = malloc(len + 1);

	if (!str)
		return NULL;
	for (size_t i = 0; i < len; i++)
		str[i] = (char)json_object_get_int(
				json_object_array_get_idx(array, i));
	str[len] = '\0';
	return str;
}

void sldm_telemetry_check_for_skhT(struct telemetry_log *tl)
{
	const uint32_t expected_signature = 0x54686B73; // "skhT" in little-endian
	const uint32_t da2_offset =
		((uint32_t)(tl->log->dalb1 + 1) * NVME_LOG_TELEM_BLOCK_SIZE);
	const uint32_t da3_offset =
		((uint32_t)(tl->log->dalb2 + 1) * NVME_LOG_TELEM_BLOCK_SIZE);

	tl->skhT_offset = 0;
	if (!tl->is_ocp) {
		// Basic bounds checking
		if (tl->log_size >= (da2_offset + sizeof(uint32_t))) {
			// Read the first 4 bytes as the signature
			uint32_t signature =
				*(uint32_t *)((char *)tl->log + da2_offset);

			if (signature == expected_signature)
				tl->skhT_offset = da2_offset;
		}
		return;
	}
	// For OCP drives, the signature is located after the segment headers
	// in Data Area 3
	if (tl->log_size >= (da3_offset + sizeof(uint32_t))) {
		uint32_t num_segments =
			*(uint32_t *)((char *)tl->log + da3_offset);
		// check if num_segments is greater than 0 and less than a
		// reasonable limit to avoid overflow
		if (num_segments == 0 || num_segments > 1000)
			return;
		uint16_t segment_header_size = ((num_segments - 1) / 10 + 1) *
						NVME_LOG_TELEM_BLOCK_SIZE;

		if (tl->log_size >=
		    (da3_offset + segment_header_size + sizeof(uint32_t))) {
			uint32_t signature = *(uint32_t *)((char *)tl->log +
					     da3_offset + segment_header_size);

			if (signature == expected_signature)
				tl->skhT_offset =
					da3_offset + segment_header_size;
		}
	}
}

void sldm_telemetry_skhT_parse(struct telemetry_log *tl)
{
	uint32_t header_offset = tl->skhT_offset;
	struct json_object *hynix_header_def = NULL;
	bool has_struct = false;
	struct json_object *build_info_def = NULL;
	bool has_build_info = false;
	struct json_object *size_bit_obj = NULL;
	uint32_t hynix_header_size_bits = 0;
	uint32_t build_info_offset = header_offset;

	// Basic validation
	if (tl->log_size < header_offset) {
		SOLIDIGM_LOG_WARNING(
			"Warning: skhT header offset is beyond telemetry log size.");
		return;
	}

	// Use only the dynamic structure from configuration
	has_struct = sldm_config_get_struct_by_key_version(tl->configuration,
							   "HynixHeader", SKT_VER_MAJOR,
							   SKT_VER_MINOR, &hynix_header_def);

	if (!has_struct || !hynix_header_def) {
		SOLIDIGM_LOG_WARNING(
			"Warning: HynixHeader structure definition not found in configuration");
		return;
	}

	// Parse HynixHeader directly into tl->root
	if (sldm_telemetry_structure_parse(tl, hynix_header_def,
				header_offset * NUM_BITS_IN_BYTE,
					tl->root, NULL) != 0) {
		SOLIDIGM_LOG_WARNING("Failed to parse HynixHeader structure");
		return;
	}

	// Now add BuildInfo parsing
	has_build_info = sldm_config_get_struct_by_key_version(tl->configuration,
							       "BuildInfo", SKT_VER_MAJOR,
							       SKT_VER_MINOR, &build_info_def);

	if (!has_build_info || !build_info_def) {
		SOLIDIGM_LOG_WARNING(
			"Warning: BuildInfo structure definition not found in configuration");
		return;
	}

	// Get HynixHeader size from structure definition
	if (json_object_object_get_ex(hynix_header_def, "sizeBit", &size_bit_obj)) {
		hynix_header_size_bits = json_object_get_int(size_bit_obj);
		// Convert bits to bytes and add to offset
		build_info_offset += (hynix_header_size_bits / NUM_BITS_IN_BYTE);
	} else {
		SOLIDIGM_LOG_WARNING(
			"Warning: sizeBit not found in HynixHeader structure definition");
		return;
	}

	// Parse BuildInfo directly into tl->root
	if (sldm_telemetry_structure_parse(tl, build_info_def,
				build_info_offset * NUM_BITS_IN_BYTE,
					tl->root, NULL) != 0) {
		SOLIDIGM_LOG_WARNING("Failed to parse BuildInfo structure");
		return;
	}
}

void sldm_telemetry_sktT_segment_parse(struct telemetry_log *tl,
					struct json_object *toc_array,
					struct json_object *tele_obj_array)
{
	uint32_t da3_offset = (tl->log->dalb2 + 1) * NVME_LOG_TELEM_BLOCK_SIZE;
	struct json_object *segment_header_definition = NULL;
	struct json_object *segment_header_obj = NULL;
	struct json_object *num_segments_obj = NULL;
	struct json_object *descriptors_obj = NULL;
	uint32_t num_segments = 0;

	// Basic validation
	if (tl->log_size < da3_offset) {
		SOLIDIGM_LOG_WARNING("Warning: Data Area 3 offset is beyond telemetry log size.");
		return;
	}

	// Get the SegmentHeader structure definition from configuration
	if (!sldm_config_get_struct_by_key_version(tl->configuration,
						   "SegmentHeader", SKT_VER_MAJOR, SKT_VER_MINOR,
						   &segment_header_definition)) {
		SOLIDIGM_LOG_WARNING(
			"Warning: SegmentHeader structure definition not found in configuration.");
		return;
	}

	// Parse the segment header using the dynamic structure definition
	if (sldm_telemetry_structure_parse(tl, segment_header_definition,
					   da3_offset * NUM_BITS_IN_BYTE,
					   tl->root, NULL) != 0 ||
		!json_object_object_get_ex(tl->root, "SegmentHeader", &segment_header_obj)) {
		SOLIDIGM_LOG_WARNING("Warning: Dynamic parsing of SegmentHeader failed");
		return;
	}

	// Get the number of segments from the parsed JSON object
	if (!json_object_object_get_ex(segment_header_obj, "nNumSegment", &num_segments_obj)) {
		SOLIDIGM_LOG_WARNING(
			"Warning: nNumSegment field not found in parsed SegmentHeader");
		return;
	}

	num_segments = json_object_get_int(num_segments_obj);

	// Get the descriptors array from the parsed JSON object
	if (!json_object_object_get_ex(segment_header_obj, "Descriptors", &descriptors_obj)) {
		SOLIDIGM_LOG_WARNING(
			"Warning: Descriptors array not found in parsed SegmentHeader");
		return;
	}

	for (uint32_t i = 0; i < num_segments; i++) {
		struct json_object *descriptor = json_object_new_object();
		struct json_object *descriptor_obj = NULL;
		struct json_object *offset_obj = NULL;
		struct json_object *size_obj = NULL;
		struct json_object *description_obj = NULL;
		uint32_t offset = 0;
		uint32_t size = 0;
		char *description_str = NULL;

		// Get segment info from the parsed JSON structure
		descriptor_obj = json_object_array_get_idx(descriptors_obj, i);
		if (json_object_array_length(descriptors_obj) <= i || !descriptor_obj) {
			SOLIDIGM_LOG_WARNING(
				"Warning: Segment %d not found in descriptors array", i);
			json_object_put(descriptor);
			continue;
		}

		if (json_object_object_get_ex(descriptor_obj, "nOffset", &offset_obj))
			offset = json_object_get_int(offset_obj);
		else {
			SOLIDIGM_LOG_WARNING("Warning: nOffset not found for segment %d", i);
			json_object_put(descriptor);
			continue;
		}

		if (json_object_object_get_ex(descriptor_obj, "nSize", &size_obj))
			size = json_object_get_int(size_obj);
		else {
			SOLIDIGM_LOG_WARNING("Warning: nSize not found for segment %d", i);
			json_object_put(descriptor);
			continue;
		}

		// Get the description for this segment
		if (json_object_object_get_ex(descriptor_obj,
					      "nDescription",
					      &description_obj)) {
			if (json_object_get_type(description_obj) ==
			    json_type_array) {
				description_str =
					json_byte_array_to_string(
						description_obj);
				/* replace json array with string in output
				 * for better readability
				 */
				json_object_object_add(descriptor_obj,
						       "nDescription",
						       json_object_new_string(
							description_str));
			}
		} else {
			SOLIDIGM_LOG_WARNING(
				"nDescription not found for segment %d", i);
			json_object_put(descriptor);
			continue;
		}

		struct json_object *type_name_obj = NULL;

		if (json_object_object_get_ex(descriptor_obj, "nTypeName",
					      &type_name_obj) &&
		    json_object_get_type(type_name_obj) == json_type_array) {
			char *type_name_alloc =
				json_byte_array_to_string(type_name_obj);

			json_object_object_add(descriptor_obj, "nTypeName",
					       json_object_new_string(
							type_name_alloc));
			free(type_name_alloc);
		}

		if (description_str == 0) {
			SOLIDIGM_LOG_WARNING(
				"Warning: nDescription is NULL for segment %d",
				i);
			json_object_put(descriptor);
			continue;
		}

		// check if descriptions starts with "TRACKER_DATA"
		if (strncmp(description_str, "TRACKER_DATA",
				sizeof("TRACKER_DATA") - 1) == 0) {
			struct json_object *tracker_obj = json_object_new_object();

			json_object_object_add(tl->root, description_str, tracker_obj);
			// parse the tracker data
			sldm_tracker_parse(tl, NVME_LOG_TELEM_BLOCK_SIZE + offset,
					size, tracker_obj);
		}
		if (strncmp(description_str, "UART_LOG_INFO",
				sizeof("UART_LOG_INFO") - 1) == 0) {
			json_object_object_add(tl->root, description_str,
				json_object_new_string(
						(char *)tl->log + NVME_LOG_TELEM_BLOCK_SIZE
						+ offset));
		}
		if (strncmp(description_str, "DEBUG_INFO",
				sizeof("DEBUG_INFO") - 1) == 0) {
			struct json_object *debug_info_obj = json_object_new_object();

			json_object_object_add(tl->root, description_str, debug_info_obj);
			sldm_debug_info_parse(tl, NVME_LOG_TELEM_BLOCK_SIZE + offset,
					size, debug_info_obj);
		}
		free(description_str);
	}
}
