// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) Micron, Inc 2024.
 *
 * @file: utils.h
 * @brief: This module contains all the utilities needed for other modules.
 * @author: Chaithanya Shoba <ashoba@micron.com>
 */

#include "common.h"
#include "nvme-print.h"

/*Request data format*/
struct __packed request_data {
	char *field;
	int  size;
	int  size2;
};

enum field_size {
	FIELD_SIZE_16 = 16,
	FIELD_SIZE_8 = 8,
	FIELD_SIZE_7 = 7,
	FIELD_SIZE_6 = 6,
	FIELD_SIZE_4 = 4,
	FIELD_SIZE_3 = 3,
	FIELD_SIZE_2 = 2,
	FIELD_SIZE_1 = 1
};

/**
 * @brief converts a single hexadecimal character to its integer value.
 *
 * @param hex_char, input hex char
 * @param ts_buf, output time string
 *
 * @return integer value of hexadecimal
 */
int hex_to_int(char c);

/**
 * @brief convert time_t format time to a human readable string
 *
 * @param hex_string, input hex string pointer
 * @param ascii_buffer, output ascii buffer pointer
 *
 * @return nothing
 */
char *hex_to_ascii(const char *hex);

/**
 * @brief convert time_t format time to a human readable string
 *
 * @param data_dir_path, input data directory path pointer
 * @param bin_path, input binary file path pointer
 * @param buffer_size, input buffer size pointer
 * @param retry_count, input retry count
 *
 * @return pointer to binary data buffer
 */
unsigned char *read_binary_file(char *data_dir_path, const char *bin_path, long *buffer_size,
				int retry_count);

/**
 * @brief prints generic structure parser
 *
 * @param buf, input raw log data
 * @param log_page, input format of the data
 * @param field_count, intput log field count
 * @param stats, input json object to add fields
 * @param spec, input ocp spec index
 * @param fp, input file pointer
 *
 * @return 0 success
 */
void generic_structure_parser(__u8 *buf, struct request_data *req_data, int field_count,
			  struct json_object *stats, __u8 spec, FILE *fp);

/**
 * @brief prints raw data to the buffer
 *
 * @param msg, intput buffer to write data
 * @param pdata, input raw data
 * @param data_size, input size of the data
 * @param fp, input file pointer
 *
 * @return 0 success
 */
void print_formatted_var_size_str(const char *msg, const __u8 *pdata, size_t data_size, FILE *fp);

/**
 * @brief prints raw data to the buffer
 *
 * @param offset, intput offset of the param
 * @param sfield, intput field
 * @param buf, input raw data
 * @param datastr, output data buffer
 *
 * @return 0 success
 */
void process_field_size_16(int offset, char *sfield, __u8 *buf, char *datastr);

/**
 * @brief prints raw data to the buffer
 *
 * @param offset, intput offset of the param
 * @param sfield, intput field
 * @param buf, input raw data
 * @param datastr, output data buffer
 *
 * @return 0 success
 */
void process_field_size_8(int offset, char *sfield, __u8 *buf, char *datastr);

/**
 * @brief prints raw data to the buffer
 *
 * @param offset, intput offset of the param
 * @param sfield, intput field
 * @param buf, input raw data
 * @param datastr, output data buffer
 *
 * @return 0 success
 */
void process_field_size_7(int offset, char *sfield, __u8 *buf, char *datastr);

/**
 * @brief prints raw data to the buffer
 *
 * @param offset, intput offset of the param
 * @param sfield, intput field
 * @param buf, input raw data
 * @param datastr, output data buffer
 *
 * @return 0 success
 */
void process_field_size_6(int offset, char *sfield, __u8 *buf, char *datastr);

/**
 * @brief prints raw data to the buffer
 *
 * @param offset, intput offset of the param
 * @param sfield, intput field
 * @param buf, input raw data
 * @param size, input data size
 * @param datastr, output data buffer
 *
 * @return 0 success
 */
void process_field_size_default(int offset, char *sfield, __u8 *buf, int size, char *datastr);
