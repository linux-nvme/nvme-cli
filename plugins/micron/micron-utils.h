// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) Micron, Inc 2024.
 *
 * @file: micron-utils.h
 * @brief: This module contains all the utilities needed for micron nvme plugin
 *         and other micron modules.
 * @author: Chaithanya Shoba <ashoba@micron.com>
 */

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <libgen.h>
#include <stddef.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "common.h"
#include "nvme.h"
#include "libnvme.h"
#include <limits.h>
#include "linux/types.h"
#include "nvme-print.h"
#include "util/cleanup.h"

/* OCP and Vendor specific log data format */
struct __packed micron_vs_logpage {
	char *field;
	int  size; /* FB client spec version 1.0 sizes - M5410 models */
	int  size2; /* FB client spec version 0.7 sizes - M5407 models */
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
 * @brief prints Micron VS log pages
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
void print_micron_vs_logs(__u8 *buf, struct micron_vs_logpage *log_page, int field_count,
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
