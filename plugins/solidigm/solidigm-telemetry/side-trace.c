// SPDX-License-Identifier: MIT
/*
 * Copyright (c) 2026 Solidigm.
 *
 * Author: leonardo.da.cunha@solidigm.com
 */

#include "common.h"
#include "telemetry-log.h"
#include "side-trace.h"
#include "data-area.h"
#include "header.h"
#include "config.h"
#include <ctype.h>
#include <string.h>

#define NUM_BITS_IN_BYTE 8
#define SIDETRACE_BLOCK_SIZE 256
#define SIDETRACE_PAYLOAD_OFFSET 32
#define SIDETRACE_STACK_SIZE_MAX 224
#define SIDETRACE_EMPTY_TOKEN 0xFFFF

/* Side trace parsing context */
struct side_trace_parser_context {
	const struct telemetry_log *tl;
	uint64_t file_offset;
	uint32_t size_bytes;
	struct json_object *output;
	struct json_object *metadata;
};

static struct json_object *find_nested_object_with_field(
					struct json_object *parent,
					const char *field_name)
{
	struct json_object *nested_obj = NULL;

	json_object_object_foreach(parent, key, val) {
		(void)key; /* Suppress unused variable warning */
		struct json_object *test_obj;

		if (json_object_object_get_ex(val, field_name, &test_obj)) {
			nested_obj = val;
			break;
		}
	}

	return nested_obj;
}

static bool extract_header_fields(struct json_object *nested_obj,
				    uint8_t *major_rev,
				    uint8_t *minor_rev,
				    uint16_t *token_id)
{
	struct json_object *jobj;
	bool found_any = false;

	if (json_object_object_get_ex(nested_obj, "majorRev", &jobj)) {
		*major_rev = (uint8_t) json_object_get_uint64(jobj);
		found_any = true;
	}

	if (json_object_object_get_ex(nested_obj, "minorRev", &jobj)) {
		*minor_rev = (uint8_t) json_object_get_uint64(jobj);
		found_any = true;
	}

	if (json_object_object_get_ex(nested_obj, "tokenId", &jobj)) {
		*token_id = (uint16_t) json_object_get_uint64(jobj);
		found_any = true;
	}

	return found_any;
}

static bool parse_header_structure(struct json_object *temp_obj,
				     uint8_t *major_rev,
				     uint8_t *minor_rev,
				     uint16_t *token_id,
				     uint8_t *payload_size)
{
	struct json_object *header_struct_obj, *common_obj;

	/* First navigate through the "trimmedSideTraceBufferEntryHeader"
	 * top-level key
	 */
	if (!json_object_object_get_ex(temp_obj,
				       "trimmedSideTraceBufferEntryHeader",
				       &header_struct_obj))
		return false;

	/* Look for the "common" substructure within the header structure */
	if (json_object_object_get_ex(header_struct_obj, "common",
				      &common_obj)) {
		/* Search within "common" for the nested structure that
		 * contains our fields
		 */
		struct json_object *nested_obj =
			find_nested_object_with_field(common_obj, "majorRev");

		if (nested_obj)
			extract_header_fields(nested_obj, major_rev,
					      minor_rev, token_id);
	}

	/* Also look for payload size field dynamically */
	struct json_object *payload_size_obj;

	if (json_object_object_get_ex(header_struct_obj, "payloadSize",
				      &payload_size_obj))
		*payload_size = (uint8_t)
				json_object_get_uint64(payload_size_obj);

	return true;
}

static int parse_side_trace_entry(struct side_trace_parser_context *ctx,
				  uint64_t offset_bytes, int entry_count,
				  struct json_object *entries_array)
{
	const uint8_t *data_ptr;
	struct json_object *entry_obj, *header_obj;
	struct json_object *structure_definition = NULL;
	bool has_struct = false;
	uint8_t major_rev = 0, minor_rev = 0;
	uint16_t token_id = 0;
	/* Store header_struct for token enum lookup */
	struct json_object *token_header_struct = NULL;
	int ret = 0;
	uint8_t payload_size = 0;  /* Initialize payload size */
	uint32_t header_size = 0;  /* Initialize header size */

	if (offset_bytes + SIDETRACE_BLOCK_SIZE > ctx->tl->log_size) {
		SOLIDIGM_LOG_WARNING(
			"Side trace entry %d exceeds log size",
			entry_count);
		return -1;
	}

	data_ptr = (const uint8_t *)ctx->tl->log + ctx->file_offset +
		   offset_bytes;

	/* First try to get the header structure to read basic header info */
	struct json_object *header_struct = NULL;
	bool has_header = sldm_config_get_struct_by_key_version(
					ctx->tl->configuration,
							"trimmedSideTraceBufferEntryHeader",
							8, 8, &header_struct);

	/* Calculate header size from struct definition's sizeBit field */
	if (has_header && header_struct) {
		struct json_object *size_bit_obj;

		if (json_object_object_get_ex(header_struct, "sizeBit",
					      &size_bit_obj))
			header_size = (uint32_t)
				json_object_get_uint64(size_bit_obj) /
				NUM_BITS_IN_BYTE;
		/* Store header_struct for token enum lookup */
		token_header_struct = header_struct;

		/* Use dynamic parsing to extract header fields */
		struct json_object *temp_obj = json_object_new_object();
		int parse_ret = sldm_telemetry_structure_parse(
						ctx->tl, header_struct,
						NUM_BITS_IN_BYTE *
						(ctx->file_offset +
							offset_bytes),
						temp_obj, NULL);

		if (parse_ret == 0)
			parse_header_structure(temp_obj, &major_rev,
					       &minor_rev, &token_id,
					       &payload_size);

		json_object_put(temp_obj);
	}

	if (token_id == SIDETRACE_EMPTY_TOKEN) {
		/* Skip empty entries */
		return 0;
	}

	/* Check if token_id is valid by attempting enum lookup */
	const char *token_name = "UNKNOWN_TOKEN";

	if (token_header_struct) {
		token_name = sldm_get_enum_label_by_value(
						token_header_struct,
						"tokenId", token_id);
		if (strncmp(token_name, UNKNOWN_ENUM_VALUE,
			    strlen(UNKNOWN_ENUM_VALUE)) == 0) {
			/* Invalid token, stop processing */
			return 1; /* Signal end of valid entries */
		}
	}

	entry_obj = json_object_new_object();

	/* Add entry metadata */
	json_object_add_value_uint(entry_obj, "entryNumber", entry_count);
	json_object_add_value_uint64(entry_obj, "offsetBytes", offset_bytes);

	/* Use already discovered token name */
	json_object_object_add(entry_obj, "tokenName",
			       json_object_new_string(token_name));

	/* Determine which structure definition to use based on major
	 * revision
	 */
	if (major_rev >= 128) {
		/* Trimmed entry - use preparsed header structure */
		json_object_object_add(entry_obj, "entryType",
			json_object_new_string("trimmed"));
		if (has_header && header_struct) {
			structure_definition = header_struct;
			has_struct = true;
		}
	} else {
		/* Full entry */
		json_object_object_add(entry_obj, "entryType",
				       json_object_new_string("full"));
		has_struct = sldm_config_get_struct_by_key_version(
						ctx->tl->configuration,
						"sideTraceBufferEntry",
						6, 0, &structure_definition);
	}

	if (has_struct && structure_definition) {
		/* Parse using dynamic structure definition */
		header_obj = json_object_new_object();
		json_object_object_add(entry_obj, "parsedData", header_obj);

		ret = sldm_telemetry_structure_parse(
						ctx->tl, structure_definition,
						NUM_BITS_IN_BYTE *
						(ctx->file_offset +
							offset_bytes),
						header_obj, NULL);
		if (ret < 0)
			SOLIDIGM_LOG_WARNING(
				"Failed to parse side trace structure for entry %d",
				entry_count);

		/* Add raw payload data array for additional analysis */
		if (major_rev >= 128) {
			/* For trimmed entries, add payload data */
			if (header_size > 0 &&
			    (offset_bytes + header_size) < ctx->size_bytes) {
				/* payload starts after header */
				uint32_t payload_start = header_size;

				if (payload_size > 0 &&
				    (offset_bytes + payload_start +
				     payload_size) <= ctx->size_bytes) {
					struct json_object *payload_obj =
						json_object_new_object();

					json_object_object_add(entry_obj,
							       "payload",
							       payload_obj);

					struct json_object *raw_array =
						json_create_array();

					json_object_object_add(payload_obj,
							       "rawDataArray",
							       raw_array);

					for (uint8_t i = 0; i < payload_size;
					     i++) {
						json_object_array_add(
							raw_array,
							json_object_new_uint64(
								data_ptr[
								payload_start +
								i]));
					}
				}
			}
		}
		json_object_array_add(entries_array, entry_obj);
	} else
		json_object_put(entry_obj);

	return ret;
}

int sldm_parse_side_trace(const struct telemetry_log *tl,
			     uint64_t file_offset,
			     uint32_t size_bytes,
			     struct json_object *output,
			     struct json_object *metadata)
{
	struct side_trace_parser_context ctx = {
		.tl = tl,
		.file_offset = file_offset,
		.size_bytes = size_bytes,
		.output = output,
		.metadata = metadata
	};

	uint64_t offset_bytes = 0;
	int entry_count = 0;
	int total_entries = 0;

	/* Boundary check */
	if (tl->log_size < (file_offset + size_bytes)) {
		const char *name = "";
		int media_bank = -1;
		struct json_object *jobj;

		if (json_object_object_get_ex(metadata, "objName", &jobj))
			name = json_object_get_string(jobj);
		if (json_object_object_get_ex(metadata, "mediaBankId", &jobj))
			media_bank = json_object_get_int(jobj);

		SOLIDIGM_LOG_WARNING("%s:%d do not fit this log dump.",
				     name, media_bank);
		return -1;
	}

	/* Add parsing metadata */
	json_object_object_add(metadata, "parseType",
			       json_object_new_string("sideTrace"));
	json_object_add_value_uint(metadata, "fileSizeBytes", size_bytes);
	json_object_add_value_uint(metadata, "blockSize", SIDETRACE_BLOCK_SIZE);

	/* Create entries array */
	struct json_object *entries_array = json_create_array();

	/* Parse side trace entries in 256-byte blocks */
	while (offset_bytes < size_bytes) {
		int ret = parse_side_trace_entry(&ctx, offset_bytes,
					     entry_count, entries_array);

		if (ret < 0) {
			/* Error occurred */
			SOLIDIGM_LOG_WARNING(
				"Error parsing side trace entry %d",
				entry_count);
			break;
		} else if (ret > 0) {
			/* End of valid entries */
			break;
		}
		entry_count++;

		offset_bytes += SIDETRACE_BLOCK_SIZE;
	}
	// Replace fwSideTrace only if we have entries
	total_entries = json_object_array_length(entries_array);
	if (total_entries > 0) {
		json_object_object_add(output, "fwSideTrace", entries_array);
		json_object_add_value_uint(metadata, "totalEntriesParsed",
					   total_entries);
	}
	return 0;
}
