// SPDX-License-Identifier: MIT
/*
 * Copyright (c) 2025 Solidigm.
 *
 * Author: leonardo.da.cunha@solidigm.com
 */
#include "common.h"
#include "telemetry-log.h"
#include "util/json.h"
#include "config.h"
#include "data-area.h"
#include "skht.h"

#define TRACKER_CHUNK_SIZE 4096
#define MAX_ARGS 31

#define ABLIST_BUFFER_SIGNATURE 0xab15ab15 // Valid ABLIST

/*
 * All structure information is derived from the JSON configuration file.
 * No static structure definitions are used.
 * The dynamic parsing relies entirely on the structure definitions
 * from the JSON configuration file.
 *
 * The expected JSON structure format from telemetry_log_structure_parse is:
 * { "struct_name": { "field1": value1, "field2": value2, ... } }
 */

// Get string for tracker level
static const char *get_level_string(uint32_t level)
{
	switch (level) {
	case 0: return "DEBUG";
	case 1: return "INFO";
	case 2: return "ERROR";
	case 3: return "CRITICAL";
	default: return "UNKNOWN";
	}
}

// Get tracker entry description from JSON config
static struct json_object *get_tracker_entry_info(struct json_object *config, uint32_t tracker_id)
{
	struct json_object *tracker_obj = NULL;
	struct json_object *entries_obj = NULL;
	struct json_object *entry_obj = NULL;
	char tracker_id_str[16];

	if (!config)
		return NULL;

	// Convert tracker_id to string for JSON key lookup
	snprintf(tracker_id_str, sizeof(tracker_id_str), "%u", tracker_id);

	// Navigate through JSON hierarchy
	if (!json_object_object_get_ex(config, "Tracker", &tracker_obj))
		return NULL;

	if (!json_object_object_get_ex(tracker_obj, "TrackerEntry", &entries_obj))
		return NULL;

	if (!json_object_object_get_ex(entries_obj, tracker_id_str, &entry_obj))
		return NULL;

	return entry_obj;
}

// Get argument description from tracker entry
static const char *get_arg_description(struct json_object *entry_obj, int arg_idx)
{
	char key_name[16];
	struct json_object *desc_obj = NULL;

	// Format key name for argument description
	snprintf(key_name, sizeof(key_name), "descArg%d", arg_idx);

	if (json_object_object_get_ex(entry_obj, key_name, &desc_obj))
		return json_object_get_string(desc_obj);

	return NULL;
}

static uint32_t get_struct_size_from_config(struct json_object *struct_def)
{
	struct json_object *size_bit_obj = NULL;
	uint32_t size_bits = 0;

	if (!struct_def) {
		SOLIDIGM_LOG_WARNING("Cannot get size from NULL structure definition");
		return 0;
	}

	// Get the sizeBit property from the structure definition
	if (json_object_object_get_ex(struct_def, "sizeBit", &size_bit_obj)) {
		size_bits = (uint32_t)json_object_get_uint64(size_bit_obj);
		// Convert from bits to bytes (divide by 8)
		return size_bits / 8;
	}

	SOLIDIGM_LOG_WARNING("Structure definition missing 'sizeBit' property");
	return 0;
}

static void parse_tracker_chunk_json(const struct telemetry_log *tl, uint32_t chunk_offset,
	int chunk_number, struct json_object *entries_array)
{
	struct json_object *ctx_obj = NULL;
	struct json_object *ablist_context_def = NULL;
	struct json_object *ablist_entry_def = NULL;
	struct json_object *tracker_entry_def = NULL;
	uint32_t offset = 0;
	uint32_t signature = 0;
	uint32_t entry_count = 0;
	uint32_t data_start_offset = 0;
	struct json_object *metadata_obj = NULL;
	struct json_object *config = tl->configuration;

	// Get structure definitions from the config - all are required for dynamic parsing
	if (!sldm_config_get_struct_by_key_version(config,
		"ablist_context_t", SKT_VER_MAJOR, SKT_VER_MINOR, &ablist_context_def) ||
		!sldm_config_get_struct_by_key_version(config,
		"ablist_entry_t", SKT_VER_MAJOR, SKT_VER_MINOR, &ablist_entry_def) ||
		!sldm_config_get_struct_by_key_version(config,
		"tracker_entry_t", SKT_VER_MAJOR, SKT_VER_MINOR, &tracker_entry_def)) {

		SOLIDIGM_LOG_WARNING(
			"Required structure definitions missing from config");
		return;
	}

	// Parse the ablist_context_t structure to get context information
	ctx_obj = json_object_new_object();
	metadata_obj = json_object_new_object();

	if (sldm_telemetry_structure_parse(tl, ablist_context_def, chunk_offset * 8,
				     ctx_obj, metadata_obj) != 0) {
		SOLIDIGM_LOG_WARNING("Failed to parse ablist_context_t using dynamic parsing");
		json_object_put(ctx_obj);
		json_object_put(metadata_obj);
		return;
	}

	// Extract fields from the nested object structure
	struct json_object *ablist_context_obj = NULL;

	if (json_object_object_get_ex(ctx_obj, "ablist_context_t", &ablist_context_obj)) {
		// Extract fields from the inner object
		struct json_object *sig_obj = NULL;
		struct json_object *start_offset_obj = NULL;
		struct json_object *count_obj = NULL;

		if (json_object_object_get_ex(ablist_context_obj, "signature", &sig_obj))
			signature = (uint32_t) json_object_get_int64(sig_obj);
		else
			SOLIDIGM_LOG_WARNING(
				"Failed to find 'signature' field in ablist_context_t");

		if (json_object_object_get_ex(ablist_context_obj, "data_start_offset",
					    &start_offset_obj))
			data_start_offset = json_object_get_int(start_offset_obj);
		else
			SOLIDIGM_LOG_WARNING(
				"Failed to find 'data_start_offset' field in ablist_context_t");

		if (json_object_object_get_ex(ablist_context_obj, "entry_count", &count_obj))
			entry_count = json_object_get_int(count_obj);
		else
			SOLIDIGM_LOG_WARNING(
				"Failed to find 'entry_count' field in ablist_context_t");
	} else {
		SOLIDIGM_LOG_WARNING("Nested 'ablist_context_t' object not found in parsed data");
		json_object_put(ctx_obj);
		json_object_put(metadata_obj);
		return;
	}

	json_object_put(ctx_obj);
	json_object_put(metadata_obj);

	// Validate chunk signature
	if (signature != ABLIST_BUFFER_SIGNATURE)
		return;

	offset = data_start_offset;

	// Process all entries in the chunk
	while (offset < TRACKER_CHUNK_SIZE && entry_count > 0) {
		uint32_t next_entry_index = 0;
		struct json_object *entry_json = json_object_new_object();
		struct json_object *entry_metadata = json_object_new_object();
		struct json_object *header_obj = NULL;
		struct json_object *data_obj = NULL;
		uint32_t hash = 0;
		struct json_object *tracker_entry_obj = NULL;
		struct json_object *ablist_entry_obj = NULL;
		struct json_object *next_obj = NULL;
		struct json_object *name_obj = NULL;
		struct json_object *file_obj = NULL;
		struct json_object *line_obj = NULL;
		struct json_object *hash_obj = NULL;
		struct json_object *time_obj = NULL;
		struct json_object *arm_id_obj = NULL;
		struct json_object *level_obj = NULL;
		struct json_object *group_obj = NULL;
		struct json_object *arg_count_obj = NULL;
		struct json_object *args_array = NULL;
		struct json_object *arg_obj;
		uint32_t arg_count = 0;
		// Get the size of ablist_entry_t from configuration
		uint32_t ablist_entry_size = get_struct_size_from_config(ablist_entry_def);

		if (ablist_entry_size == 0) {
			SOLIDIGM_LOG_WARNING(
				"Failed to get size of ablist_entry_t from configuration");
			json_object_put(entry_json);
			json_object_put(entry_metadata);
			return;
		}

		// Parse entry header using ablist_entry_t structure
		header_obj = json_object_new_object();
		if (sldm_telemetry_structure_parse(tl, ablist_entry_def,
			chunk_offset * 8 + offset * 8, header_obj, NULL) != 0) {
			SOLIDIGM_LOG_WARNING(
				"Failed to parse ablist_entry_t at offset %u", offset);
			json_object_put(header_obj);
			json_object_put(entry_json);
			json_object_put(entry_metadata);

			// Skip to next entry if we know where it is, otherwise break
			if (next_entry_index == 0 || next_entry_index >= TRACKER_CHUNK_SIZE)
				break;

			offset = next_entry_index;
			entry_count--;
			continue;
		}

		// Parse entry data using tracker_entry_t structure
		data_obj = json_object_new_object();
		if (sldm_telemetry_structure_parse(tl, tracker_entry_def,
			chunk_offset * 8 + (offset + ablist_entry_size) * 8,
			data_obj, entry_metadata) != 0) {
			SOLIDIGM_LOG_WARNING(
				"Failed to parse tracker_entry_t at offset %u",
				offset + ablist_entry_size);
			json_object_put(header_obj);
			json_object_put(data_obj);
			json_object_put(entry_json);
			json_object_put(entry_metadata);

			// Skip to next entry if we know where it is, otherwise break
			if (next_entry_index == 0 || next_entry_index >= TRACKER_CHUNK_SIZE)
				break;

			offset = next_entry_index;
			entry_count--;
			continue;
		}

		// Get the inner object from header_obj
		if (!json_object_object_get_ex(header_obj,
				"ablist_entry_t", &ablist_entry_obj)) {
			SOLIDIGM_LOG_WARNING(
				"Failed to find ablist_entry_t in parsed header data");
			json_object_put(header_obj);
			json_object_put(data_obj);
			json_object_put(entry_json);
			json_object_put(entry_metadata);

			// Skip to next entry if we know where it is, otherwise break
			if (next_entry_index == 0 || next_entry_index >= TRACKER_CHUNK_SIZE)
				break;

			offset = next_entry_index;
			entry_count--;
			continue;
		}

		// Get next_entry_index from ablist_entry_obj
		if (!json_object_object_get_ex(ablist_entry_obj,
				"next_entry_index", &next_obj)) {
			SOLIDIGM_LOG_WARNING(
				"Failed to find 'next_entry_index' in ablist_entry_t");
			// Continue with next_entry_index = 0 (will likely break)
		} else {
			next_entry_index = json_object_get_int(next_obj);
		}

		// Get the inner object from data_obj - only supporting nested
		// structure format
		if (!json_object_object_get_ex(data_obj,
				"tracker_entry_t", &tracker_entry_obj)) {
			SOLIDIGM_LOG_WARNING(
				"Failed to find tracker_entry_t in parsed data");
			json_object_put(header_obj);
			json_object_put(data_obj);
			json_object_put(entry_json);
			json_object_put(entry_metadata);

			// Skip to next entry if we know where it is, otherwise break
			if (next_entry_index == 0 || next_entry_index >= TRACKER_CHUNK_SIZE)
				break;

			offset = next_entry_index;
			entry_count--;
			continue;
		}

		// Get hash value from tracker_entry_obj
		if (!json_object_object_get_ex(tracker_entry_obj,
				"hash", &hash_obj)) {
			SOLIDIGM_LOG_WARNING(
				"Failed to find 'hash' in tracker_entry_t");
			json_object_put(header_obj);
			json_object_put(data_obj);
			json_object_put(entry_json);
			json_object_put(entry_metadata);

			// Skip to next entry if we know where it is, otherwise break
			if (next_entry_index == 0 || next_entry_index >= TRACKER_CHUNK_SIZE)
				break;

			offset = next_entry_index;
			entry_count--;
			continue;
		}

		hash = json_object_get_int(hash_obj);

		// Get tracker entry info from config
		struct json_object *entry_info = get_tracker_entry_info(config, hash);

		// Handle case where no entry info is found
		if (!entry_info) {
			// Clean up the entry JSON since we won't be adding it to the array
			json_object_put(entry_json);

			// Skip to next entry
			if (next_entry_index == 0 || next_entry_index >= TRACKER_CHUNK_SIZE)
				break;

			offset = next_entry_index;
			entry_count--;
			continue;
		}

		// Get tracker entry info from config
		if (json_object_object_get_ex(entry_info, "idName", &name_obj)) {
			json_object_object_add(entry_json, "name", name_obj);
			json_object_get(name_obj); // Increase ref count
		}
		if (json_object_object_get_ex(entry_info, "file", &file_obj)) {
			json_object_object_add(entry_json, "file", file_obj);
			json_object_get(file_obj); // Increase ref count
		}
		if (json_object_object_get_ex(entry_info, "line", &line_obj)) {
			json_object_object_add(entry_json, "line", line_obj);
			json_object_get(line_obj); // Increase ref count
		}

		// We need to get tracker_entry_obj again for fields
		if (!json_object_object_get_ex(data_obj,
				"tracker_entry_t", &tracker_entry_obj)) {
			// This shouldn't happen as we already checked, but let's be safe
			json_object_put(entry_json);
			json_object_put(header_obj);
			json_object_put(data_obj);
			json_object_put(entry_metadata);

			// Skip to next entry
			if (next_entry_index == 0 || next_entry_index >= TRACKER_CHUNK_SIZE)
				break;

			offset = next_entry_index;
			entry_count--;
			continue;
		}

		if (json_object_object_get_ex(tracker_entry_obj, "time",
					   &time_obj)) {
			json_object_add_value_uint64(entry_json, "time",
				json_object_get_uint64(time_obj));
		}

		if (json_object_object_get_ex(tracker_entry_obj, "arm_id",
					   &arm_id_obj)) {
			json_object_add_value_uint64(entry_json, "arm_id",
				json_object_get_int(arm_id_obj));
		}

		// Re-get the hash obj to add the tracker_id to the JSON
		if (json_object_object_get_ex(tracker_entry_obj, "hash",
					   &hash_obj)) {
			json_object_add_value_uint64(entry_json, "hash",
				json_object_get_int(hash_obj));
		}

		if (json_object_object_get_ex(tracker_entry_obj, "level",
					   &level_obj)) {
			int level = json_object_get_int(level_obj);

			json_object_add_value_uint64(entry_json, "level", level);
			json_object_object_add(entry_json, "level_name",
						   json_object_new_string(get_level_string(level)));

		}

		if (json_object_object_get_ex(tracker_entry_obj, "group",
					   &group_obj)) {
			json_object_add_value_uint64(entry_json, "group",
				json_object_get_int(group_obj));
		}

		if (json_object_object_get_ex(tracker_entry_obj, "arg_count",
					   &arg_count_obj)) {
			arg_count = json_object_get_int(arg_count_obj);
			json_object_add_value_uint(entry_json, "arg_count", arg_count);
		}

		// Add arguments from dynamically parsed data
		arg_obj = json_object_new_object();

		// Get args array
		if (!json_object_object_get_ex(tracker_entry_obj,
				"args", &args_array) || !args_array) {
			// No args or couldn't find args array, add empty arguments object
			json_object_object_add(entry_json, "arguments", arg_obj);
			json_object_array_add(entries_array, entry_json);

			// Clean up allocated objects
			json_object_put(header_obj);
			json_object_put(data_obj);
			json_object_put(entry_metadata);

			// Skip to next entry
			if (next_entry_index == 0 || next_entry_index >= TRACKER_CHUNK_SIZE)
				break;

			offset = next_entry_index;
			entry_count--;
			continue;
		}

		// Process array items if args_array is valid
		int array_len = json_object_array_length(args_array);

		for (uint32_t i = 0; i < arg_count && i < MAX_ARGS
		     && i < (uint32_t)array_len; i++) {
			char arg_key[16] = {0};
			const char *arg_desc = entry_info ?
				get_arg_description(entry_info, i)
				: NULL;
			struct json_object *arg_val =
				json_object_array_get_idx(args_array, i);

			if (!arg_desc) {
				snprintf(arg_key, sizeof(arg_key),
					 "arg%d", i);
				arg_desc = arg_key;
			}

			if (arg_val) {
				uint32_t arg_value =
					json_object_get_int(arg_val);

				json_object_add_value_uint64(arg_obj,
					arg_desc, arg_value);
			}
		}

		// Add arguments and entry to output
		json_object_object_add(entry_json, "arguments", arg_obj);
		json_object_array_add(entries_array, entry_json);
		// Clean up any dynamically allocated objects
		json_object_put(header_obj);
		json_object_put(data_obj);
		json_object_put(entry_metadata);

		// Break if we can't continue
		if (next_entry_index == 0 || next_entry_index >= TRACKER_CHUNK_SIZE)
			break;

		// Move to next entry
		offset = next_entry_index;
		entry_count--;
	}
}

void sldm_tracker_parse(struct telemetry_log *tl, uint32_t offset, uint32_t size,
	struct json_object *tracker_obj)
{
	uint32_t chunks = size / TRACKER_CHUNK_SIZE;
	struct json_object *entries_array = json_object_new_array();

	json_object_add_value_uint(tracker_obj, "offset", offset);
	json_object_add_value_uint(tracker_obj, "size", size);
	json_object_add_value_uint(tracker_obj, "chunks", chunks);

	for (uint32_t i = 0; i < chunks; i++) {
		parse_tracker_chunk_json(tl, offset + (i * TRACKER_CHUNK_SIZE),
			i, entries_array);
	}

	json_object_object_add(tracker_obj, "entries", entries_array);
}
