/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2017-2018 Western Digital Corporation or its affiliates.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA  02110-1301, USA.
 *
 *   Author: Jeff Lien <jeff.lien@wdc.com>,
 */

#include <stdio.h>
#include <ctype.h>
#include <stdarg.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <assert.h>
#include <time.h>
#include <sys/time.h>
#include <sys/stat.h>

#include <stdbool.h>
#include <string.h>
#include <unistd.h>

/* Create Dir Command Status */
#define WDC_STATUS_SUCCESS                		  			0
#define WDC_STATUS_FAILURE   					 			-1
#define WDC_STATUS_INSUFFICIENT_MEMORY           			-2
#define WDC_STATUS_INVALID_PARAMETER       		 			-3
#define WDC_STATUS_FILE_SIZE_ZERO               			-27
#define WDC_STATUS_UNABLE_TO_WRITE_ALL_DATA 				-34
#define WDC_STATUS_DIR_ALREADY_EXISTS      					-36
#define WDC_STATUS_PATH_NOT_FOUND          					-37
#define WDC_STATUS_CREATE_DIRECTORY_FAILED 					-38
#define WDC_STATUS_DELETE_DIRECTORY_FAILED 					-39
#define WDC_STATUS_UNABLE_TO_OPEN_FILE 						-40
#define WDC_STATUS_UNABLE_TO_OPEN_ZIP_FILE             		-41
#define WDC_STATUS_UNABLE_TO_ARCHIVE_EXCEEDED_FILES_LIMIT  	-256
#define WDC_STATUS_NO_DATA_FILE_AVAILABLE_TO_ARCHIVE  		-271

#define WDC_NVME_FIRMWARE_REV_LEN           9        /* added 1 for end delimiter */
#define WDC_SERIAL_NO_LEN                   20
#define SECONDS_IN_MIN   					60
#define MAX_PATH_LEN       					256

typedef struct _UtilsTimeInfo
{
	unsigned int year;
	unsigned int month;
	unsigned int dayOfWeek;
	unsigned int dayOfMonth;
	unsigned int hour;
	unsigned int minute;
	unsigned int second;
	unsigned int msecs;
	unsigned char isDST; /*0 or 1 */
    int      zone; /* Zone value like +530 or -300 */
} UtilsTimeInfo, *PUtilsTimeInfo;

int wdc_UtilsSnprintf(char *buffer, unsigned int sizeOfBuffer, const char *format, ...);
void wdc_UtilsDeleteCharFromString(char* buffer, int buffSize, char charToRemove);
int wdc_UtilsGetTime(PUtilsTimeInfo timeInfo);
int wdc_UtilsStrCompare(const char *pcSrc, const char *pcDst);
int wdc_UtilsCreateDir(const char *path);
int wdc_WriteToFile(const char *fileName, const char *buffer, unsigned int bufferLen);
void wdc_StrFormat(char *formatter, size_t fmt_sz, char *tofmt, size_t tofmtsz);
bool wdc_CheckUuidListSupport(struct nvme_transport_handle *hdl, struct nvme_id_uuid_list *uuid_list);
