/*
 * Do NOT modify or remove this copyright and license
 *
 * Copyright (c) 2017-2018 Seagate Technology LLC and/or its Affiliates, All Rights Reserved
 *
 * ******************************************************************************************
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
 * \file seagate-diag.h
 * \brief This file defines the functions and macros to make building a nvme-cli seagate plug-in.
 */


#ifndef SEAGATE_NVME_H
#define SEAGATE_NVME_H

#define SEAGATE_PLUGIN_VERSION_MAJOR 1
#define SEAGATE_PLUGIN_VERSION_MINOR 1 

#define PERSIST_FILE_SIZE    (2764800)
#define ONE_MB               (1048576)  /* (1024 * 1024) */
#define PERSIST_CHUNK        (65536)    /* (1024 * 64) */
#define FOUR_KB               (4096)
 

/***************************
*Supported Log-Pages from FW 
***************************/

typedef struct log_page_map_entry {
   __u32 LogPageID;
   __u32 LogPageSignature;
   __u32 LogPageVersion;
} log_page_map_entry;

#define MAX_SUPPORTED_LOG_PAGE_ENTRIES ((4096 - sizeof(__u32)) / sizeof(log_page_map_entry))

typedef struct log_page_map {
   __u32 NumLogPages;
   log_page_map_entry LogPageEntry[ MAX_SUPPORTED_LOG_PAGE_ENTRIES ];
} log_page_map;
/* EOF Supported Log-Pages from FW */


/***************************
* Extended-SMART Information
***************************/
#pragma pack(1)
#define NUMBER_EXTENDED_SMART_ATTRIBUTES      42

typedef enum _EXTENDED_SMART_VERSION_
{
    EXTENDED_SMART_VERSION_NONE,
    EXTENDED_SMART_VERSION_GEN,
    EXTENDED_SMART_VERSION_VENDOR1,
} EXTENDED_SMART_VERSION;

typedef struct _SmartVendorSpecific
{
   __u8  AttributeNumber;                                      
   __u16 SmartStatus;                                          
   __u8  NominalValue;                                     
   __u8  LifetimeWorstValue;                               
   __u32 Raw0_3;                                                           
   __u8  RawHigh[3];                                               
} SmartVendorSpecific;

typedef struct _EXTENDED_SMART_INFO_T
{
   __u16 Version;                                                                                       
   SmartVendorSpecific vendorData[NUMBER_EXTENDED_SMART_ATTRIBUTES];            
   __u8  vendor_specific_reserved[6];                                                                           
}  EXTENDED_SMART_INFO_T;

typedef struct vendor_smart_attribute_data
{
   __u8  AttributeNumber;         /* 00 */
   __u8  Rsvd[3];                 /* 01 -03 */
   __u32 LSDword;                 /* 04-07 */
   __u32 MSDword;                 /* 08 - 11 */
} vendor_smart_attribute_data;

struct nvme_temetry_log_hdr
{
    __u8        log_id;
    __u8        rsvd1[4];
    __u8        ieee_id[3];
    __le16      tele_data_area1;
    __le16      tele_data_area2;
    __le16      tele_data_area3;
    __u8        rsvd14[368];
    __u8        tele_data_aval;
    __u8        tele_data_gen_num;
    __u8        reason_identifier[128];
};

typedef struct _U128
{
    __u64 LS__u64;
    __u64 MS__u64;
} U128;

typedef struct _vendor_log_page_CF_Attr
{
   __u16      SuperCapCurrentTemperature;        /* 00-01 */
   __u16      SuperCapMaximumTemperature;        /* 02-03 */
   __u8       SuperCapStatus;                    /* 04 */
   __u8       Reserved5to7[3];                   /* 05-07 */
   U128     DataUnitsReadToDramNamespace;      /* 08-23 */
   U128     DataUnitsWrittenToDramNamespace;   /* 24-39 */
   __u64      DramCorrectableErrorCount;         /* 40-47 */
   __u64      DramUncorrectableErrorCount;       /* 48-55 */
}vendor_log_page_CF_Attr;

typedef struct _vendor_log_page_CF
{
   vendor_log_page_CF_Attr      AttrCF;
   __u8                         Vendor_Specific_Reserved[ 456 ];     /* 56-511 */
}vendor_log_page_CF;

#pragma pack()
/* EOF Extended-SMART Information*/


/**************************
* PCIE ERROR INFORMATION
**************************/
typedef struct pcie_error_log_page
{
   __u32   Version;
   __u32   BadDllpErrCnt;
   __u32   BadTlpErrCnt;
   __u32   RcvrErrCnt;
   __u32   ReplayTOErrCnt;
   __u32   ReplayNumRolloverErrCnt;
   __u32   FCProtocolErrCnt;
   __u32   DllpProtocolErrCnt;
   __u32   CmpltnTOErrCnt;
   __u32   RcvrQOverflowErrCnt;
   __u32   UnexpectedCplTlpErrCnt;
   __u32   CplTlpURErrCnt;
   __u32   CplTlpCAErrCnt;
   __u32   ReqCAErrCnt;
   __u32   ReqURErrCnt;
   __u32   EcrcErrCnt;
   __u32   MalformedTlpErrCnt;
   __u32   CplTlpPoisonedErrCnt;
   __u32   MemRdTlpPoisonedErrCnt;
} pcie_error_log_page;
/*EOF PCIE ERROR INFORMATION */

typedef enum
{
   VS_ATTR_SOFT_READ_ERROR_RATE,                /* 0     OFFSET : 02 -13     bytes */
   VS_ATTR_REALLOCATED_SECTOR_COUNT,            /* 1     OFFSET : 14 -25     bytes */
   VS_ATTR_POWER_ON_HOURS,                      /* 2     OFFSET : 26 -37     bytes */
   VS_ATTR_POWER_FAIL_EVENT_COUNT,              /* 3    OFFSET : 38 -49     bytes */
   VS_ATTR_DEVICE_POWER_CYCLE_COUNT,            /* 4    OFFSET : 50 -61     bytes */
   VS_ATTR_GB_ERASED,                           /* 5   OFFSET : 62 -73     bytes */
   VS_ATTR_LIFETIME_DEVSLEEP_EXIT_COUNT,        /* 6    OFFSET : 74 -85     bytes */
   VS_ATTR_LIFETIME_ENTERING_PS4_COUNT,         /* 7   OFFSET : 86 -97     bytes */
   VS_ATTR_LIFETIME_ENTERING_PS3_COUNT,         /* 8   OFFSET : 98 -109   bytes */
   VS_ATTR_RETIRED_BLOCK_COUNT,                 /* 9   OFFSET : 110 -121 bytes */
   VS_ATTR_PROGRAM_FAILURE_COUNT,               /* 10   OFFSET : 122 -133 bytes */
   VS_ATTR_ERASE_FAIL_COUNT,                    /* 11   OFFSET : 134 -145 bytes */
   VS_ATTR_AVG_ERASE_COUNT,                     /* 12    OFFSET : 146 -157 bytes */
   VS_ATTR_UNEXPECTED_POWER_LOSS_COUNT,         /* 13   OFFSET : 158 -169 bytes */
   VS_ATTR_WEAR_RANGE_DELTA,                    /* 14    OFFSET : 170 -181 bytes */
   VS_ATTR_SATA_INTERFACE_DOWNSHIFT_COUNT,      /* 15    OFFSET : 182 -193 bytes */
   VS_ATTR_END_TO_END_CRC_ERROR_COUNT,          /* 16    OFFSET : 194 -205 bytes */
   VS_ATTR_MAX_LIFE_TEMPERATURE,                /* 17   OFFSET : 206 -217 bytes */
   VS_ATTR_UNCORRECTABLE_RAISE_ERRORS,          /* 18    OFFSET : 218 -229 bytes */
   VS_ATTR_DRIVE_LIFE_PROTECTION_STATUS,        /* 19   OFFSET : 230 -241 bytes */
   VS_ATTR_REMAINING_SSD_LIFE,                  /* 20   OFFSET : 242 -253 bytes */
   VS_ATTR_LIFETIME_WRITES_TO_FLASH,            /* 21   OFFSET : 254 -265 bytes */
   VS_ATTR_LIFETIME_WRITES_FROM_HOST,           /* 22   OFFSET : 266 -277 bytes */
   VS_ATTR_LIFETIME_READS_TO_HOST,              /* 23   OFFSET : 278 -289 bytes */
   VS_ATTR_FREE_SPACE,                          /* 24   OFFSET : 290 -301 bytes */
   VS_ATTR_TRIM_COUNT_LSB,                      /* 25  OFFSET : 302 -313 bytes */
   VS_ATTR_TRIM_COUNT_MSB,                      /* 26  OFFSET : 314 -325 bytes */
   VS_ATTR_OP_PERCENTAGE,                       /* 27  OFFSET : 326 -337 bytes */
   VS_ATTR_RAISE_ECC_CORRECTABLE_ERROR_COUNT, 	/* 28  OFFSET : 338 -349 bytes */
   VS_ATTR_UNCORRECTABLE_ECC_ERRORS ,           /* 29  OFFSET : 350 -361 bytes */
   VS_ATTR_LIFETIME_WRITES0_TO_FLASH,           /* 30  362-372 */
   VS_ATTR_LIFETIME_WRITES1_TO_FLASH,           /* 31  374-385 */
   VS_ATTR_LIFETIME_WRITES0_FROM_HOST,          /* 32  386-397 */
   VS_ATTR_LIFETIME_WRITES1_FROM_HOST,          /* 33  398-409 */
   VS_ATTR_LIFETIME_READ0_FROM_HOST,            /* 34  410-421 */
   VS_ATTR_LIFETIME_READ1_FROM_HOST,            /* 35  422-433 */
   VS_ATTR_PCIE_PHY_CRC_ERROR,                  /* 36  434-445 */
   VS_ATTR_BAD_BLOCK_COUNT_SYSTEM,              /* 37  446-457 */
   VS_ATTR_BAD_BLOCK_COUNT_USER,                /* 38  458-469 */
   VS_ATTR_THERMAL_THROTTLING_STATUS,           /* 39  470-481 */
   VS_ATTR_POWER_CONSUMPTION,                   /* 40  482-493 */
   VS_ATTR_MAX_SOC_LIFE_TEMPERATURE,            /* 41  494-505 */

   VS_MAX_ATTR_NUMBER,

} extended_smart_attributes;

/*Smart attribute IDs */

typedef enum
{
   VS_ATTR_ID_SOFT_READ_ERROR_RATE = 1,
   VS_ATTR_ID_REALLOCATED_SECTOR_COUNT  = 5,
   VS_ATTR_ID_POWER_ON_HOURS = 9,
   VS_ATTR_ID_POWER_FAIL_EVENT_COUNT = 11,
   VS_ATTR_ID_DEVICE_POWER_CYCLE_COUNT = 12,
   VS_ATTR_ID_RAW_READ_ERROR_RATE = 13,
   VS_ATTR_ID_GROWN_BAD_BLOCK_COUNT = 40,
   VS_ATTR_ID_END_2_END_CORRECTION_COUNT = 41,
   VS_ATTR_ID_MIN_MAX_WEAR_RANGE_COUNT = 42,
   VS_ATTR_ID_REFRESH_COUNT = 43,
   VS_ATTR_ID_BAD_BLOCK_COUNT_USER = 44,
   VS_ATTR_ID_BAD_BLOCK_COUNT_SYSTEM = 45,
   VS_ATTR_ID_THERMAL_THROTTLING_STATUS = 46,
   VS_ATTR_ID_ALL_PCIE_CORRECTABLE_ERROR_COUNT = 47,
   VS_ATTR_ID_ALL_PCIE_UNCORRECTABLE_ERROR_COUNT = 48,
   VS_ATTR_ID_INCOMPLETE_SHUTDOWN_COUNT = 49,
   VS_ATTR_ID_GB_ERASED_LSB = 100,
   VS_ATTR_ID_GB_ERASED_MSB = 101,
   VS_ATTR_ID_LIFETIME_ENTERING_PS4_COUNT = 102,
   VS_ATTR_ID_LIFETIME_ENTERING_PS3_COUNT = 103,
   VS_ATTR_ID_LIFETIME_DEVSLEEP_EXIT_COUNT = 104,
   VS_ATTR_ID_RETIRED_BLOCK_COUNT = 170,
   VS_ATTR_ID_PROGRAM_FAILURE_COUNT = 171,
   VS_ATTR_ID_ERASE_FAIL_COUNT = 172,
   VS_ATTR_ID_AVG_ERASE_COUNT = 173,
   VS_ATTR_ID_UNEXPECTED_POWER_LOSS_COUNT = 174,
   VS_ATTR_ID_WEAR_RANGE_DELTA = 177,
   VS_ATTR_ID_SATA_INTERFACE_DOWNSHIFT_COUNT = 183,
   VS_ATTR_ID_END_TO_END_CRC_ERROR_COUNT = 184,
   VS_ATTR_ID_UNCORRECTABLE_READ_ERRORS = 188,
   VS_ATTR_ID_MAX_LIFE_TEMPERATURE = 194,
   VS_ATTR_ID_RAISE_ECC_CORRECTABLE_ERROR_COUNT = 195,
   VS_ATTR_ID_UNCORRECTABLE_RAISE_ERRORS = 198,
   VS_ATTR_ID_DRIVE_LIFE_PROTECTION_STATUS = 230,
   VS_ATTR_ID_REMAINING_SSD_LIFE  = 231,
   VS_ATTR_ID_LIFETIME_WRITES_TO_FLASH_LSB = 233,
   VS_ATTR_ID_LIFETIME_WRITES_TO_FLASH_MSB = 234,
   VS_ATTR_ID_LIFETIME_WRITES_FROM_HOST_LSB = 241,
   VS_ATTR_ID_LIFETIME_WRITES_FROM_HOST_MSB = 242,
   VS_ATTR_ID_LIFETIME_READS_TO_HOST_LSB = 243,
   VS_ATTR_ID_LIFETIME_READS_TO_HOST_MSB = 244,
   VS_ATTR_ID_FREE_SPACE = 245,
   VS_ATTR_ID_TRIM_COUNT_LSB = 250,
   VS_ATTR_ID_TRIM_COUNT_MSB = 251,
   VS_ATTR_ID_OP_PERCENTAGE = 252,
   VS_ATTR_ID_MAX_SOC_LIFE_TEMPERATURE = 253,
} smart_attributes_ids;

#define TELEMETRY_BLOCKS_TO_READ       8

void seaget_d_raw(unsigned char *buf, int len, int fd);


#define DP_CLASS_ID_FULL 0

#endif
