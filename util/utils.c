// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) Micron, Inc 2024.
 *
 * @file: micron-utils.h
 * @brief: This module contains all the utilities needed for other modules.
 * @author: Chaithanya Shoba <ashoba@micron.com>
 */

#include "utils.h"
#include "types.h"
#include "json.h"

int hex_to_int(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	else if (c >= 'A' && c <= 'F')
		return 10 + (c - 'A');
	else if (c >= 'a' && c <= 'f')
		return 10 + (c - 'a');
	else
		return -1; // Invalid character
}

char *hex_to_ascii(const char *hex)
{
	int hex_length = strlen(hex);

	char *text = NULL;

	if (hex_length > 0) {
		int symbol_count;
		int odd_hex_count = hex_length % 2 == 1;

		if (odd_hex_count)
			symbol_count = (hex_length / 2) + 1;
		else
			symbol_count = hex_length / 2;

		text = (char *)malloc(symbol_count + 1); // Allocate memory for the result

		int last_index = hex_length - 1;

		for (int i = last_index; i >= 0; --i) {
			if ((last_index - i) % 2 != 0) {
				int dec = 16 * hex_to_int(hex[i]) + hex_to_int(hex[i + 1]);

				if (odd_hex_count)
					text[i / 2 + 1] = dec;
				else
					text[i / 2] = dec;
			} else if (i == 0) {
				int dec = hex_to_int(hex[0]);

				text[0] = dec;
			}
		}

		text[symbol_count] = '\0'; // Terminate the string
	}

	return text;
}

unsigned char *read_binary_file(char *data_dir_path, const char *bin_path,
				long *buffer_size, int retry_count)
{
	char *file_path = NULL;
	FILE *bin_file = NULL;
	size_t n_data = 0;
	unsigned char *buffer = NULL;

	/* set path */
	if (data_dir_path == NULL) {
		file_path = (char *)bin_path;
	} else {
		/* +2 for the / and null terminator */
		file_path = (char *) calloc(1, strlen(data_dir_path) + strlen(bin_path) + 2);
		if (!file_path)
			return NULL;

		if (strlen(bin_path) != 0)
			sprintf(file_path, "%s/%s", data_dir_path, bin_path);
		else
			sprintf(file_path, "%s", data_dir_path);
	}

	/* open file */
	for (int i = 0; i < retry_count; i++) {
		bin_file = fopen(file_path, "rb");
		if (bin_file != NULL)
			break;
		sleep((unsigned int)(retry_count > 1));
	}

	if (!bin_file) {
		nvme_show_error("\nFailed to open %s", file_path);
		if (file_path != bin_path)
			free(file_path);
		return NULL;
	}

	/* get size */
	fseek(bin_file, 0, SEEK_END);
	*buffer_size = ftell(bin_file);
	fseek(bin_file, 0, SEEK_SET);
	if (*buffer_size <= 0) {
		fclose(bin_file);
		return NULL;
	}

	/* allocate buffer */
	buffer = (unsigned char *)malloc(*buffer_size);
	if (!buffer) {
		nvme_show_result("\nFailed to allocate %ld bytes!", *buffer_size);
		fclose(bin_file);
		return NULL;
	}
	memset(buffer, 0, *buffer_size);

	/* Read data */
	n_data = fread(buffer, 1, *buffer_size, bin_file);

	/* Close file */
	fclose(bin_file);

	/* Validate we read data */
	if (n_data != (size_t)*buffer_size) {
		nvme_show_result("\nFailed to read %ld bytes from %s", *buffer_size, file_path);
		return NULL;
	}

	if (file_path != bin_path)
		free(file_path);
	return buffer;
}

void print_formatted_var_size_str(const char *msg, const __u8 *pdata, size_t data_size, FILE *fp)
{
	char *description_str = NULL;
	char temp_buffer[3] = { 0 };

	/* Allocate 2 chars for each value in the data + 2 bytes for the null terminator */
	description_str = (char *) calloc(1, data_size*2 + 2);

	for (size_t i = 0; i < data_size; ++i) {
		sprintf(temp_buffer, "%02X", pdata[i]);
		strcat(description_str, temp_buffer);
	}

	if (!fp)
		fp = stdout;

	fprintf(fp, "%s: %s\n", msg, description_str);
	free(description_str);
}

void process_field_size_16(int offset, char *sfield, __u8 *buf, char *datastr)
{
	__u64 lval_lo, lval_hi;

	if (strstr(sfield, "GUID")) {
		sprintf(datastr, "0x%"PRIx64"%"PRIx64"",
			le64_to_cpu(*(__u64 *)(&buf[offset + 8])),
			le64_to_cpu(*(__u64 *)(&buf[offset])));
	} else {
		lval_lo = *((__u64 *)(&buf[offset]));
		lval_hi = *((__u64 *)(&buf[offset + 8]));

		if (lval_hi)
			sprintf(datastr, "0x%"PRIx64"%016"PRIx64"",
				le64_to_cpu(lval_hi), le64_to_cpu(lval_lo));
		else
			sprintf(datastr, "0x%"PRIx64"", le64_to_cpu(lval_lo));
	}
}

void process_field_size_8(int offset, char *sfield, __u8 *buf, char *datastr)
{
	__u64 lval_lo;

	if (strstr(sfield, "Boot SSD Spec Version")) {
		sprintf(datastr, "%x.%x.%x.%x",
		le16_to_cpu(*((__u16 *)(&buf[300]))),
		le16_to_cpu(*((__u16 *)(&buf[302]))),
		le16_to_cpu(*((__u16 *)(&buf[304]))),
		le16_to_cpu(*((__u16 *)(&buf[306]))));
	} else if (strstr(sfield, "Firmware Revision")) {
		char buffer[30] = {'\0'};

		lval_lo = *((__u64 *)(&buf[offset]));

		sprintf(buffer, "%"PRIx64, __builtin_bswap64(lval_lo));
		sprintf(datastr, "%s", hex_to_ascii(buffer));
	} else if (strstr(sfield, "Timestamp")) {
		char ts_buf[128];

		lval_lo = *((__u64 *)(&buf[offset]));

		convert_ts(le64_to_cpu(lval_lo), ts_buf);
		sprintf(datastr, "%s", ts_buf);
	} else {
		lval_lo = *((__u64 *)(&buf[offset]));

		sprintf(datastr, "0x%"PRIx64"", le64_to_cpu(lval_lo));
	}
}

void process_field_size_7(int offset, char *sfield, __u8 *buf, char *datastr)
{
	__u8 lval[8] = { 0 };
	__u64 lval_lo;

	/* 7 bytes will be in little-endian format, with last byte as MSB */
	memcpy(&lval[0], &buf[offset], 7);
	memcpy((void *)&lval_lo, lval, 8);
	sprintf(datastr, "0x%"PRIx64"", le64_to_cpu(lval_lo));
}

void process_field_size_6(int offset, char *sfield, __u8 *buf, char *datastr)
{
	__u32 ival;
	__u16 sval;
	__u64 lval_lo;

	if (strstr(sfield, "DSSD Spec Version")) {
		sprintf(datastr, "%x.%x.%x.%x", buf[103],
			le16_to_cpu(*((__u16 *)(&buf[101]))),
			le16_to_cpu(*((__u16 *)(&buf[99]))), buf[98]);
	} else {
		ival = *((__u32 *)(&buf[offset]));
		sval = *((__u16 *)(&buf[offset + 4]));
		lval_lo = (((__u64)sval << 32) | ival);

		sprintf(datastr, "0x%"PRIx64"", le64_to_cpu(lval_lo));
	}
}

void process_field_size_default(int offset, char *sfield, __u8 *buf, int size, char *datastr)
{
	__u8  cval;
	char description_str[256] = "0x";
	char temp_buffer[3] = { 0 };

	for (unsigned char i = 0; i < (unsigned char)size; i++) {
		cval = (buf[offset + i]);

		sprintf(temp_buffer, "%02X", cval);
		strcat(description_str, temp_buffer);
	}
	sprintf(datastr, "%s", description_str);
}

void generic_structure_parser(__u8 *buf, struct request_data *req_data, int field_count,
	struct json_object *stats, __u8 spec, FILE *fp)
{
	int offset = 0;

	for (int field = 0; field < field_count; field++) {
		char datastr[1024] = { 0 };
		char *sfield = req_data[field].field;
		int size = !spec ? req_data[field].size : req_data[field].size2;

		if (!size || sfield == NULL)
			continue;

		switch (size) {
		case FIELD_SIZE_16:
			process_field_size_16(offset, sfield, buf, datastr);
			break;
		case FIELD_SIZE_8:
			process_field_size_8(offset, sfield, buf, datastr);
			break;
		case FIELD_SIZE_7:
			process_field_size_7(offset, sfield, buf, datastr);
			break;
		case FIELD_SIZE_6:
			process_field_size_6(offset, sfield, buf, datastr);
			break;
		case FIELD_SIZE_4:
			sprintf(datastr, "0x%x", le32_to_cpu(*((__u32 *)(&buf[offset]))));
			break;
		case FIELD_SIZE_3:
			sprintf(datastr, "0x%02X%02X%02X",
				buf[offset + 0], buf[offset + 1], buf[offset + 2]);
			break;
		case FIELD_SIZE_2:
			sprintf(datastr, "0x%04x", le16_to_cpu(*((__u16 *)(&buf[offset]))));
			break;
		case FIELD_SIZE_1:
			sprintf(datastr, "0x%02x", buf[offset]);
			break;
		default:
			process_field_size_default(offset, sfield, buf, size, datastr);
			break;
		}
		offset += size;
		/* do not print reserved values */
		if (strstr(sfield, "Reserved"))
			continue;
		if (stats)
			json_object_add_value_string(stats, sfield, datastr);
		else if (fp)
			fprintf(fp, "%-40s : %-4s\n", sfield, datastr);
		else
			printf("%-40s : %-4s\n", sfield, datastr);
	}
}
