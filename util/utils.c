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
#include "cleanup.h"
#include "hex-util.h"

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

char *process_field_size_16(int offset, char *sfield, __u8 *buf)
{
	__u64 lval_lo, lval_hi;
	char *datastr = NULL;

	if (strstr(sfield, "GUID")) {
		if (asprintf(&datastr, "0x%"PRIx64"%"PRIx64"",
			     le64_to_cpu(*(__u64 *)(&buf[offset + 8])),
			     le64_to_cpu(*(__u64 *)(&buf[offset]))) < 0)
			return NULL;
	} else {
		lval_lo = *((__u64 *)(&buf[offset]));
		lval_hi = *((__u64 *)(&buf[offset + 8]));

		if (lval_hi) {
			if (asprintf(&datastr, "0x%"PRIx64"%016"PRIx64"",
				     le64_to_cpu(lval_hi), le64_to_cpu(lval_lo)) < 0)
				return NULL;
		} else {
			if (asprintf(&datastr, "0x%"PRIx64"", le64_to_cpu(lval_lo)) < 0)
				return NULL;
		}
	}
	return datastr;
}

char *process_field_size_8(int offset, char *sfield, __u8 *buf)
{
	__u64 lval_lo;
	char *datastr = NULL;

	if (strstr(sfield, "Boot SSD Spec Version")) {
		if (asprintf(&datastr, "%x.%x.%x.%x",
			     le16_to_cpu(*((__u16 *)(&buf[300]))),
			     le16_to_cpu(*((__u16 *)(&buf[302]))),
			     le16_to_cpu(*((__u16 *)(&buf[304]))),
			     le16_to_cpu(*((__u16 *)(&buf[306])))) < 0)
			return NULL;
	} else if (strstr(sfield, "Firmware Revision")) {
		char buffer[30] = {'\0'};

		lval_lo = *((__u64 *)(&buf[offset]));

		sprintf(buffer, "%"PRIx64, __builtin_bswap64(lval_lo));
		datastr = shr_hex_to_ascii(buffer);
	} else if (strstr(sfield, "Timestamp")) {
		char ts_buf[128];

		lval_lo = *((__u64 *)(&buf[offset]));

		convert_ts(le64_to_cpu(lval_lo), ts_buf);
		datastr = strdup(ts_buf);
	} else {
		lval_lo = *((__u64 *)(&buf[offset]));

		if (asprintf(&datastr, "0x%"PRIx64"", le64_to_cpu(lval_lo)) < 0)
			return NULL;
	}
	return datastr;
}

char *process_field_size_7(int offset, char *sfield, __u8 *buf)
{
	__u8 lval[8] = { 0 };
	__u64 lval_lo;
	char *datastr = NULL;

	/* 7 bytes will be in little-endian format, with last byte as MSB */
	memcpy(&lval[0], &buf[offset], 7);
	memcpy((void *)&lval_lo, lval, 8);
	if (asprintf(&datastr, "0x%"PRIx64"", le64_to_cpu(lval_lo)) < 0)
		return NULL;
	return datastr;
}

char *process_field_size_6(int offset, char *sfield, __u8 *buf)
{
	__u32 ival;
	__u16 sval;
	__u64 lval_lo;
	char *datastr = NULL;

	if (strstr(sfield, "DSSD Spec Version")) {
		if (asprintf(&datastr, "%x.%x.%x.%x", buf[103],
			     le16_to_cpu(*((__u16 *)(&buf[101]))),
			     le16_to_cpu(*((__u16 *)(&buf[99]))), buf[98]) < 0)
			return NULL;
	} else {
		ival = *((__u32 *)(&buf[offset]));
		sval = *((__u16 *)(&buf[offset + 4]));
		lval_lo = (((__u64)sval << 32) | ival);

		if (asprintf(&datastr, "0x%"PRIx64"", le64_to_cpu(lval_lo)) < 0)
			return NULL;
	}
	return datastr;
}

char *process_field_size_default(int offset, char *sfield, __u8 *buf, int size)
{
	/* "0x" prefix + 2 hex chars per byte + null terminator */
	char *datastr = malloc(size * 2 + 3);

	if (!datastr)
		return NULL;

	datastr[0] = '0';
	datastr[1] = 'x';
	for (int i = 0; i < size; i++)
		sprintf(&datastr[2 + i * 2], "%02X", buf[offset + i]);

	return datastr;
}

void generic_structure_parser(__u8 *buf, struct request_data *req_data, int field_count,
	struct json_object *stats, __u8 spec, FILE *fp)
{
	int offset = 0;

	for (int field = 0; field < field_count; field++) {
		__cleanup_free char *datastr = NULL;
		char *sfield = req_data[field].field;
		int size = !spec ? req_data[field].size : req_data[field].size2;

		if (!size || sfield == NULL)
			continue;

		switch (size) {
		case FIELD_SIZE_16:
			datastr = process_field_size_16(offset, sfield, buf);
			break;
		case FIELD_SIZE_8:
			datastr = process_field_size_8(offset, sfield, buf);
			break;
		case FIELD_SIZE_7:
			datastr = process_field_size_7(offset, sfield, buf);
			break;
		case FIELD_SIZE_6:
			datastr = process_field_size_6(offset, sfield, buf);
			break;
		case FIELD_SIZE_4:
			if (asprintf(&datastr, "0x%x",
				     le32_to_cpu(*((__u32 *)(&buf[offset])))) < 0)
				datastr = NULL;
			break;
		case FIELD_SIZE_3:
			if (asprintf(&datastr, "0x%02X%02X%02X",
				     buf[offset + 0], buf[offset + 1],
				     buf[offset + 2]) < 0)
				datastr = NULL;
			break;
		case FIELD_SIZE_2:
			if (asprintf(&datastr, "0x%04x",
				     le16_to_cpu(*((__u16 *)(&buf[offset])))) < 0)
				datastr = NULL;
			break;
		case FIELD_SIZE_1:
			if (asprintf(&datastr, "0x%02x", buf[offset]) < 0)
				datastr = NULL;
			break;
		default:
			datastr = process_field_size_default(offset, sfield, buf, size);
			break;
		}
		offset += size;
		/* do not print reserved values */
		if (strstr(sfield, "Reserved"))
			continue;
		if (datastr) {
			if (stats)
				json_object_add_value_string(stats, sfield, datastr);
			else if (fp)
				fprintf(fp, "%-40s : %-4s\n", sfield, datastr);
			else
				printf("%-40s : %-4s\n", sfield, datastr);
		}
	}
}
