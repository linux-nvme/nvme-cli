// SPDX-License-Identifier: MIT
/*
 * Copyright (c) 2025 Solidigm.
 *
 * Author: leonardo.da.cunha@solidigm.com
 */

#include "uart-log.h"
#include "common.h"
#include "config.h"
#include "data-area.h"
#include "skht.h"
#include "util/json.h"
#include <stdio.h>
#include <string.h>

static bool parse_uart_entry(struct telemetry_log *tl, uint64_t entry_offset_bit,
			      struct json_object *uart_array)
{
	struct json_object *entry_obj, *header_size_obj;
	struct json_object *header_def, *body_def;
	uint64_t header_size_bits;
	int err;

	/* Get structure definitions from configuration */
	if (!sldm_config_get_struct_by_key_version(tl->configuration, "UartLogBufHeader",
						   SKT_VER_MAJOR, SKT_VER_MINOR, &header_def)) {
		SOLIDIGM_LOG_WARNING("UartLogBufHeader definition not found in configuration");
		return false;
	}

	if (!sldm_config_get_struct_by_key_version(tl->configuration, "UartLogBufBody",
						    SKT_VER_MAJOR, SKT_VER_MINOR, &body_def)) {
		SOLIDIGM_LOG_WARNING("UartLogBufBody definition not found in configuration");
		return false;
	}

	/* Create JSON objects for parsed data */
	entry_obj = json_create_object();
	if (!entry_obj) {
		json_object_put(entry_obj);
		return false;
	}

	/* Extract header size from header definition */
	if (!json_object_object_get_ex(header_def, "sizeBit", &header_size_obj)) {
		SOLIDIGM_LOG_WARNING("sizeBit field not found in UartLogBufHeader definition");
		json_object_put(entry_obj);
		return false;
	}
	header_size_bits = json_object_get_uint64(header_size_obj);

	/* Parse header structure */
	err = sldm_telemetry_structure_parse(tl, header_def, entry_offset_bit,
					     entry_obj, NULL);
	if (err) {
		SOLIDIGM_LOG_WARNING("Failed to parse UART log header");
		json_object_put(entry_obj);
		return false;
	}

	/* Parse body structure (starts after header) */
	err = sldm_telemetry_structure_parse(tl, body_def, entry_offset_bit + header_size_bits,
					     entry_obj, NULL);
	if (err) {
		SOLIDIGM_LOG_WARNING("Failed to parse UART log body");
		json_object_put(entry_obj);
		return false;
	}
	json_object_array_add(uart_array, entry_obj);
	return true;
}

int sldm_parse_cd_uart_log(struct telemetry_log *tl, uint32_t offset, uint32_t size,
			    struct json_object *output)
{
	struct json_object *uart_array = NULL;
	uint32_t num_entries = 0;
	uint64_t entry_offset_bit;
	uint32_t i;

	if (!tl || !output)
		return -EINVAL;

	/* Validate offset and size */
	if (offset >= tl->log_size || size == 0) {
		SOLIDIGM_LOG_WARNING("Invalid UART log offset or size");
		return -EINVAL;
	}

	if (offset + size > tl->log_size)
		size = tl->log_size - offset;

	/* Each UART entry is 192 bytes (1536 bits) */
	num_entries = size / 192;
	if (num_entries == 0) {
		SOLIDIGM_LOG_WARNING("No valid UART log entries found");
		return -EINVAL;
	}

	/* Create JSON array for UART log entries */
	uart_array = json_create_array();
	if (!uart_array) {
		SOLIDIGM_LOG_WARNING("Out of memory");
		return -ENOMEM;
	}

	/* Parse entries using dynamic structure parsing */
	for (i = 0; i < num_entries; i++) {
		entry_offset_bit = (offset + (i * 192)) * 8;  /* Convert to bit offset */
		parse_uart_entry(tl, entry_offset_bit, uart_array);
	}

	/* Add the UART log array to output */
	json_object_object_add(output, "uart_log", uart_array);
	uart_array = NULL; /* Ownership transferred */

	return 0;
}
