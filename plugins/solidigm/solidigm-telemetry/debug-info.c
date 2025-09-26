// SPDX-License-Identifier: MIT
/*
 * Copyright (c) 2025 Solidigm.
 *
 * Author: leonardo.da.cunha@solidigm.com
 */

#include "debug-info.h"
#include "common.h"
#include "config.h"
#include "data-area.h"
#include "skht.h"
#include "tracker.h"
#include "uart-log.h"
#include "util/json.h"
#include <string.h>

#define DEBUG_INFO_SIGNATURE 0x54321234 /* "ST21" */
#define MAX_DEBUG_INFO_CORES 255

enum debug_info_id {
	DEBUG_INFO_ID_UART_LOG				= 3,
	DEBUG_INFO_ID_TRACKER_INFO			= 6,
	DEBUG_INFO_ID_TRACKER_BUFFER		= 7,
	DEBUG_INFO_ID_TRACKER_CONTEXT		= 8,
};

int sldm_debug_info_parse(struct telemetry_log *tl, uint32_t offset, uint32_t size,
			   struct json_object *output)
{
	struct json_object *debug_info_blk_header_def = NULL;
	struct json_object *debug_info_header_def = NULL;
	struct json_object *debug_info_seg_header_def = NULL;
	struct json_object *cores_array = NULL;
	struct json_object *segments_array = NULL;
	uint64_t current_offset_bit;
	uint32_t current_offset_byte;
	int counter = 0;
	int err = 0;

	if (!tl || !tl->configuration || !output) {
		SOLIDIGM_LOG_WARNING("Invalid parameters for debug info parsing");
		return -1;
	}

	if (offset + size > tl->log_size) {
		SOLIDIGM_LOG_WARNING("Debug info data exceeds log size");
		return -1;
	}

	/* Get structure definitions from configuration */
	if (!sldm_config_get_struct_by_key_version(tl->configuration,
						    "DebugInfoBlkHeader_t",
						    SKT_VER_MAJOR, SKT_VER_MINOR,
						    &debug_info_blk_header_def)) {
		SOLIDIGM_LOG_WARNING("DebugInfoBlkHeader_t structure not found in config");
		return -1;
	}

	if (!sldm_config_get_struct_by_key_version(tl->configuration,
						    "DebugInfoHeader_t",
						    SKT_VER_MAJOR, SKT_VER_MINOR,
						    &debug_info_header_def)) {
		SOLIDIGM_LOG_WARNING("DebugInfoHeader_t structure not found in config");
		return -1;
	}

	if (!sldm_config_get_struct_by_key_version(tl->configuration,
						    "DebugInfoSegHeader_t",
						    SKT_VER_MAJOR, SKT_VER_MINOR,
						    &debug_info_seg_header_def)) {
		SOLIDIGM_LOG_WARNING("DebugInfoSegHeader_t structure not found in config");
		return -1;
	}

	/* Parse Debug Info Block Header */
	current_offset_bit = offset * 8;
	err = sldm_telemetry_structure_parse(tl, debug_info_blk_header_def,
					     current_offset_bit, output, NULL);
	if (err) {
		SOLIDIGM_LOG_WARNING("Failed to parse DebugInfoBlkHeader_t");
		return err;
	}

	/* Get the size of DebugInfoBlkHeader_t to move to the next structure */
	struct json_object *blk_header_size_obj = NULL;

	if (json_object_object_get_ex(debug_info_blk_header_def, "sizeBit",
				      &blk_header_size_obj)) {
		uint32_t blk_header_size_bits = json_object_get_int(blk_header_size_obj);

		current_offset_bit += blk_header_size_bits;
	} else {
		SOLIDIGM_LOG_WARNING("Cannot determine DebugInfoBlkHeader_t size");
		return -1;
	}

	/* Create arrays for cores and segments */
	cores_array = json_create_array();
	segments_array = json_create_array();
	json_object_add_value_array(output, "Cores", cores_array);
	json_object_add_value_array(output, "Segments", segments_array);

	/* Parse Debug Info Headers for each core */
	current_offset_byte = (uint32_t)(current_offset_bit / 8);

	while (current_offset_byte < (offset + size) && counter < MAX_DEBUG_INFO_CORES) {
		uint64_t core_offset_bit = current_offset_bit;
		struct json_object *core_debug_info = json_create_object();
		struct json_object *signature_obj = NULL;
		uint32_t debug_signature = 0;
		uint32_t total_bytes = 0;
		uint32_t num_segments = 0;
		uint32_t core_id = 0;

		/* Check if we have enough space for the debug info header */
		if (current_offset_byte + sizeof(uint32_t) > (offset + size)) {
			json_free_object(core_debug_info);
			break;
		}

		/* Parse DebugInfoHeader_t */
		err = sldm_telemetry_structure_parse(tl, debug_info_header_def,
						     current_offset_bit,
						     core_debug_info, NULL);
		if (err) {
			SOLIDIGM_LOG_WARNING("Failed to parse DebugInfoHeader_t for core %d",
					     counter);
			json_free_object(core_debug_info);
			break;
		}

		/* Validate signature */
		struct json_object *debug_info_header_obj = NULL;

		if (json_object_object_get_ex(core_debug_info, "DebugInfoHeader_t",
					      &debug_info_header_obj) &&
		    json_object_object_get_ex(debug_info_header_obj, "nSignature",
					      &signature_obj)) {
			debug_signature = json_object_get_int(signature_obj);
		}

		if (debug_signature != DEBUG_INFO_SIGNATURE) {
			json_free_object(core_debug_info);
			break;
		}

		/* Get total bytes and number of segments */
		struct json_object *total_bytes_obj = NULL;
		struct json_object *num_segments_obj = NULL;
		struct json_object *core_id_obj = NULL;

		if (json_object_object_get_ex(debug_info_header_obj, "nTotalBytes",
					      &total_bytes_obj))
			total_bytes = json_object_get_int(total_bytes_obj);

		if (json_object_object_get_ex(debug_info_header_obj, "nNumSegments",
					      &num_segments_obj))
			num_segments = json_object_get_int(num_segments_obj);

		if (json_object_object_get_ex(debug_info_header_obj, "nCoreId",
					      &core_id_obj))
			core_id = json_object_get_int(core_id_obj);

		/* Add core info to the cores array */
		json_object_array_add(cores_array, core_debug_info);

		/* Move to the position after DebugInfoHeader_t */
		struct json_object *header_size_obj = NULL;

		if (json_object_object_get_ex(debug_info_header_def, "sizeBit",
					      &header_size_obj)) {
			uint32_t header_size_bits = json_object_get_int(header_size_obj);

			current_offset_bit += header_size_bits;
			current_offset_byte = (uint32_t)(current_offset_bit / 8);
		} else {
			SOLIDIGM_LOG_WARNING("Cannot determine DebugInfoHeader_t size");
			break;
		}

		/* Parse segment headers for this core */
		for (uint32_t seg = 0; seg < num_segments && seg < 16; seg++) {
			struct json_object *tracker_info = NULL;
			struct json_object *debug_info_uart_log = NULL;
			struct json_object *segment_info = json_create_object();
			char *tracker_log_name = NULL;

			/* Check bounds */
			if (current_offset_byte >= (offset + size)) {
				json_free_object(segment_info);
				break;
			}

			/* Parse DebugInfoSegHeader_t */
			err = sldm_telemetry_structure_parse(tl,
							     debug_info_seg_header_def,
							     current_offset_bit,
							     segment_info, NULL);
			if (err) {
				SOLIDIGM_LOG_WARNING(
					"Failed to parse DebugInfoSegHeader_t for core %d, seg %d",
					core_id, seg);
				json_free_object(segment_info);
				break;
			}

			/* Add core and segment identifiers */
			json_object_add_value_uint(segment_info, "CoreId", core_id);
			json_object_add_value_uint(segment_info, "SegmentIndex", seg);

			/* Add segment to segments array */
			json_object_array_add(segments_array, segment_info);

			/* Move to next segment header */
			struct json_object *seg_header_size_obj = NULL;

			if (json_object_object_get_ex(debug_info_seg_header_def,
						      "sizeBit",
						      &seg_header_size_obj)) {
				uint32_t seg_header_size_bits;

				seg_header_size_bits = json_object_get_int(seg_header_size_obj);
				current_offset_bit += seg_header_size_bits;
				current_offset_byte = (uint32_t)(current_offset_bit / 8);
			} else {
				SOLIDIGM_LOG_WARNING("Cannot determine DebugInfoHeader_t size");
				json_free_object(segment_info);
				break;
			}
			// Get DebugInfoSegHeader_t size for logging
			struct json_object *debug_info_seg_header_obj = NULL;
			struct json_object *size_obj = NULL;
			uint32_t debug_info_seg_size = 0;

			if (json_object_object_get_ex(segment_info, "DebugInfoSegHeader_t",
							&debug_info_seg_header_obj) &&
				json_object_object_get_ex(debug_info_seg_header_obj, "nSize",
							&size_obj)) {
				debug_info_seg_size = json_object_get_int(size_obj);
			} else {
				SOLIDIGM_LOG_WARNING("Cannot determine DebugInfoSegHeader_t size");
				json_free_object(segment_info);
				break;
			}

			struct json_object *id_obj = NULL;
			uint32_t debug_info_seg_id = 0;

			if (json_object_object_get_ex(debug_info_seg_header_obj, "nId",
						       &id_obj)) {
				debug_info_seg_id = json_object_get_int(id_obj);
			} else {
				SOLIDIGM_LOG_WARNING("Cannot determine DebugInfoSegHeader_t id");
				json_free_object(segment_info);
				break;
			}
			switch (debug_info_seg_id) {
			case DEBUG_INFO_ID_UART_LOG:
				debug_info_uart_log = json_create_object();
				if (!debug_info_uart_log) {
					SOLIDIGM_LOG_WARNING(
						"Failed to create JSON object for UART log");
					json_free_object(segment_info);
					break;
				}
				sldm_parse_cd_uart_log(tl, current_offset_byte,
						       debug_info_seg_size,
						       debug_info_uart_log);
				json_object_object_add(segment_info, "DebugInfoUartLog",
						       debug_info_uart_log);
				break;
			case DEBUG_INFO_ID_TRACKER_INFO:
				tracker_log_name = "TrackerInfo";
			case DEBUG_INFO_ID_TRACKER_BUFFER:
				if (!tracker_log_name)
					tracker_log_name = "TrackerBuffer";
			case DEBUG_INFO_ID_TRACKER_CONTEXT:
				if (!tracker_log_name)
					tracker_log_name = "TrackerContext";

				tracker_info = json_create_object();
				if (!tracker_info) {
					SOLIDIGM_LOG_WARNING(
						"Failed to create JSON object for tracker info");
					json_free_object(segment_info);
					break;
				}
				sldm_tracker_parse(tl, current_offset_byte,
						   debug_info_seg_size, tracker_info);

				// Add tracker info to segment
				json_object_object_add(segment_info, tracker_log_name,
						       tracker_info);
				break;
			}

			current_offset_bit += debug_info_seg_size * 8;
			current_offset_byte = (uint32_t)(current_offset_bit / 8);
		}

		/* Move to the next core based on total_bytes */
		if (total_bytes > 0) {
			current_offset_bit = core_offset_bit + total_bytes * 8;
			current_offset_byte = (uint32_t)(current_offset_bit / 8);
		}

		counter++;
		if (counter >= MAX_DEBUG_INFO_CORES) {
			SOLIDIGM_LOG_WARNING("Attempted to parse debug info for %d cores.",
					     counter);
			break;
		}
	}
	return 0;
}
