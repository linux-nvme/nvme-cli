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

#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include "wdc-utils.h"

int wdc_UtilsSnprintf(char *buffer, unsigned int sizeOfBuffer, const char *format, ...)
{
    int res = 0;

    va_list vArgs;
    va_start(vArgs, format);
    res = vsnprintf(buffer, sizeOfBuffer, format, vArgs);
    va_end(vArgs);

    return res;
}

void wdc_UtilsDeleteCharFromString(char* buffer, int buffSize, char charToRemove)
{
    int i = 0;
    int count = 0;
    if (!buffer || !buffSize)
    {
        return;
    }

    // Traverse the given string. If current character is not charToRemove, then place it at index count++
    for (i = 0; ((i < buffSize) && (buffer[i] != '\0')); i++)
    {
        if (buffer[i] != charToRemove)
        {
            buffer[count++] = buffer[i];
        }
    }
    buffer[count] = '\0';
}

int wdc_UtilsGetTime(PUtilsTimeInfo timeInfo)
{
	if(!timeInfo)
		return WDC_STATUS_INVALID_PARAMETER;

	time_t currTime;
	struct tm currTimeInfo;

	tzset();
	time(&currTime);
	localtime_r(&currTime, &currTimeInfo);

	timeInfo->year			=  currTimeInfo.tm_year + 1900;
	timeInfo->month			=  currTimeInfo.tm_mon + 1;
	timeInfo->dayOfWeek		=  currTimeInfo.tm_wday;
	timeInfo->dayOfMonth		=  currTimeInfo.tm_mday;
	timeInfo->hour			=  currTimeInfo.tm_hour;
	timeInfo->minute		=  currTimeInfo.tm_min;
	timeInfo->second		=  currTimeInfo.tm_sec;
	timeInfo->msecs			=  0;
	timeInfo->isDST			=  currTimeInfo.tm_isdst;
	timeInfo->zone			= -currTimeInfo.tm_gmtoff / 60;

	return WDC_STATUS_SUCCESS;
}

int wdc_UtilsCreateDir(char *path)
{
    int retStatus;
    int status = WDC_STATUS_SUCCESS;

    if  (!path )
    {
        return WDC_STATUS_INVALID_PARAMETER;
    }

    retStatus = mkdir(path, 0x999);

    if (retStatus < 0)
    {
        if (errno == EEXIST)
        {
            status = WDC_STATUS_DIR_ALREADY_EXISTS;
        }
        else if (errno == ENOENT)
        {
            status = WDC_STATUS_PATH_NOT_FOUND;
        }
        else
        {
            status = WDC_STATUS_CREATE_DIRECTORY_FAILED;
        }
    }

    return status;
}

int wdc_WriteToFile(char *fileName, char *buffer, unsigned int bufferLen)
{
    int          status = WDC_STATUS_SUCCESS;
    FILE         *file;
    size_t       bytesWritten = 0;
    file = fopen(fileName, "ab+");

    if(!file)
    {
        status = WDC_STATUS_UNABLE_TO_OPEN_FILE;
        goto end;
    }

    bytesWritten = fwrite(buffer, 1, bufferLen, file);
    if (bytesWritten != bufferLen)
    {
        status = WDC_STATUS_UNABLE_TO_WRITE_ALL_DATA;
    }

end:
    if(file)
        fclose(file);

    return status;
}

/**
 * Compares the strings ignoring their cases.
 *
 * @param pcSrc Points to a null terminated string for comapring.
 * @param pcDst Points to a null terminated string for comapring.
 *
 * @returns zero if the string matches or
 *          1 if the pcSrc string is lexically higher than pcDst or
 *         -1 if the pcSrc string is lexically lower than pcDst.
 */
int wdc_UtilsStrCompare(char *pcSrc, char *pcDst)
{
    while((toupper(*pcSrc) == toupper(*pcDst)) && (*pcSrc != '\0'))
    {
        pcSrc++;
        pcDst++;
    }

    return *pcSrc - *pcDst;
}

