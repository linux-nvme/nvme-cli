// SPDX-License-Identifier: MIT
/*
 * Copyright (c) 2023 Solidigm.
 *
 * Author: leonardo.da.cunha@solidigm.com
 */

#include "nlog.h"
#include "config.h"
#include <string.h>
#include <stdio.h>

#define LOG_ENTRY_HEADER_SIZE 1
#define LOG_ENTRY_TIMESTAMP_SIZE 2
#define LOG_ENTRY_NUM_ARGS_MAX 8
#define LOG_ENTRY_NUM_ARGS_MASK 0xF
#define LOG_ENTRY_MAX_SIZE (LOG_ENTRY_HEADER_SIZE + LOG_ENTRY_TIMESTAMP_SIZE + \
			    LOG_ENTRY_NUM_ARGS_MAX)
#define MAX_HEADER_MISMATCH_TRACK 10

static int formats_find(struct json_object *formats, uint32_t val, struct json_object **format)
{
	char hex_header[STR_HEX32_SIZE];

	snprintf(hex_header, STR_HEX32_SIZE, "0x%08X", val);
	return json_object_object_get_ex(formats, hex_header, format);
}

static uint32_t nlog_get_pos(const uint32_t *nlog, const uint32_t nlog_size, int pos)
{
	return nlog[pos % nlog_size];
}

static uint32_t nlog_get_events(const uint32_t *nlog, const uint32_t nlog_size, int start_offset,
	       struct json_object *formats, struct json_object *events, uint32_t *tail_mismatches)
{
	uint32_t event_count = 0;
	int last_bad_header_pos = nlog_size + 1; // invalid nlog offset
	uint32_t tail_count = 0;

	for (int i = nlog_size - start_offset - 1; i >= -start_offset; i--) {
		struct json_object *format = NULL;
		uint32_t header = nlog_get_pos(nlog, nlog_size, i);
		uint32_t num_data;

		if (header == 0 || !formats_find(formats, header, &format)) {
			if (event_count > 0) {
				//check if found circular buffer tail
				if (i != (last_bad_header_pos - 1)) {
					if (tail_mismatches &&
					    (tail_count < MAX_HEADER_MISMATCH_TRACK))
						tail_mismatches[tail_count] = header;
					tail_count++;
				}
				last_bad_header_pos = i;
			}
			continue;
		}
		num_data = header & LOG_ENTRY_NUM_ARGS_MASK;
		if (events) {
			struct json_object *event = json_object_new_array();
			struct json_object *param = json_object_new_array();
			uint32_t val = nlog_get_pos(nlog, nlog_size, i - 1);

			json_object_array_add(events, event);
			json_object_array_add(event, json_object_new_int64(val));
			val = nlog_get_pos(nlog, nlog_size, i - 2);
			json_object_array_add(event, json_object_new_int64(val));
			json_object_array_add(event, json_object_new_int64(header));
			json_object_array_add(event, param);
			for (uint32_t j = 0; j < num_data; j++) {
				val = nlog_get_pos(nlog, nlog_size, i - 3 - j);
				json_object_array_add(param, json_object_new_int64(val));
			}
			json_object_get(format);
			json_object_array_add(event, format);
		}
		i -= 2 + num_data;
		event_count++;
	}
	return tail_count;
}

int solidigm_nlog_parse(const char *buffer, uint64_t buff_size,	struct json_object *formats,
			struct json_object *metadata, struct json_object *output)
{
	uint32_t smaller_tail_count = UINT32_MAX;
	int best_offset = 0;
	uint32_t offset_tail_mismatches[LOG_ENTRY_MAX_SIZE][MAX_HEADER_MISMATCH_TRACK];
	struct json_object *events = json_object_new_array();
	const uint32_t *nlog = (uint32_t *)buffer;
	const uint32_t nlog_size = buff_size / sizeof(uint32_t);

	for (int i = 0; i < LOG_ENTRY_MAX_SIZE; i++) {
		uint32_t tail_count = nlog_get_events(nlog, nlog_size, i, formats, NULL,
						      offset_tail_mismatches[i]);
		if (tail_count < smaller_tail_count) {
			best_offset = i;
			smaller_tail_count = tail_count;
		}
		if (tail_count == 0)
			break;
	}
	if (smaller_tail_count > 1) {
		const char *name = "";
		int media_bank = -1;
		char str_mismatches[(STR_HEX32_SIZE + 1) * MAX_HEADER_MISMATCH_TRACK];
		int pos = 0;
		int show_mismatch_num = smaller_tail_count < MAX_HEADER_MISMATCH_TRACK ?
					smaller_tail_count : MAX_HEADER_MISMATCH_TRACK;
		struct json_object *jobj;

		if (json_object_object_get_ex(metadata, "objName", &jobj))
			name = json_object_get_string(jobj);
		if (json_object_object_get_ex(metadata, "mediaBankId", &jobj))
			media_bank = json_object_get_int(jobj);

		for (int i = 0; i < show_mismatch_num; i++)
			pos += snprintf(&str_mismatches[pos], STR_HEX32_SIZE + 1, "0x%08X ",
				       offset_tail_mismatches[best_offset][i]);

		SOLIDIGM_LOG_WARNING("%s:%d with %d header mismatches ( %s). Configuration file may be missing format headers.",
				      name, media_bank, smaller_tail_count, str_mismatches);
	}
	nlog_get_events(nlog, nlog_size, best_offset, formats, events, NULL);

	json_object_object_add(output, "events", events);
	return 0;
}
