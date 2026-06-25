/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef __YMTC_UTILS_H__
#define __YMTC_UTILS_H__

#define SMART_INFO_SIZE     4096

#define YMTC_SMART_LOG_SHIFT    0x3C
#define ID_SIZE                 3
#define NM_SIZE                 2
#define RAW_SIZE                7
#define YMTC_SMART_ITEM_SIZE    (ID_SIZE + NM_SIZE + RAW_SIZE)
#define YMTC_MAX_ITEMS          (SMART_INFO_SIZE / YMTC_SMART_ITEM_SIZE)

typedef unsigned char           u8;

#define YMTC_VENDOR_ID 0x1E49

/*
 * supported models of YMTC plugin; new models should be added at the end.
 * Make sure UNKNOWN_SSD is first in the list !
 */
enum ySSDModel {
	UNKNOWN_SSD = 0,
    PE310,
    PE321,
    PE511,
    PE501,
    PE522,
};


/* Supported Vendor specific feature ids */
#define SI_VD_PROGRAM_FAIL_ID                        0xAB
#define SI_VD_ERASE_FAIL_ID                          0xAC
#define SI_VD_WEARLEVELING_COUNT_ID                  0xAD
#define SI_VD_TEMPT_SINCE_BOOTUP_ID                  0xAF
#define SI_VD_E2E_DECTECTION_COUNT_ID                0xB8

#define SI_VD_PCIE_CRC_ERR_COUNT_ID                  0xC7

#define SI_VD_TIMED_WORKLOAD_MEDIA_WEAR_ID           0xE2
#define SI_VD_TIMED_WORKLOAD_HOST_READ_ID            0xE3
#define SI_VD_TIMED_WORKLOAD_TIMER_ID                0xE4
#define SI_VD_IN_FLIGHT_READ_IO_COUNT_ID             0xE5
#define SI_VD_IN_FLIGHT_WRITE_IO_COUNT_ID            0xE6
#define SI_VD_TEMPT_SINCE_BORN_ID                    0xE7
#define SI_VD_POWER_CONSUMPTION_ID                   0xE8
#define SI_VD_THERMAL_THROTTLE_STATUS_ID             0xEA
#define SI_VD_THERMAL_THROTTLE_TIME_ID               0xEB
#define SI_VD_FEATURE_EC_ID                          0xEC
#define SI_VD_FEATURE_ED_ID                          0xED

#define SI_VD_FEATURE_F0_ID                          0xF0
#define SI_VD_READ_FAIL_ID                           0xF2
#define SI_VD_PLL_LOCK_LOSS_COUNT_ID                 0xF3
#define SI_VD_TOTAL_WRITE_ID                         0xF4
#define SI_VD_HOST_WRITE_ID                          0xF5
#define SI_VD_SYSTEM_AREA_LIFE_LEFT_ID               0xF6
#define SI_VD_NAND_BYTES_READ_ID                     0xF8
#define SI_VD_FIRMWARE_UPDATE_COUNT_ID               0xF9
#define SI_VD_FEATURE_FA_ID                          0xFA
#define SI_VD_DRAM_UECC_COUNT_ID                     0xFB
#define SI_VD_XOR_PASS_COUNT_ID                      0xFC
#define SI_VD_XOR_FAIL_COUNT_ID                      0xFD
#define SI_VD_XOR_INVOKED_COUNT_ID                   0xFE


struct nvme_ymtc_smart_log_item
{
    /* Item identifier */
    u8 id[ID_SIZE];
    /* Normalized value or percentage. In the range from 0 to 100. */
    u8 nmVal[NM_SIZE];
    /* raw value */
    u8 rawVal[RAW_SIZE];
}__attribute__((packed));

struct nvme_ymtc_smart_log
{
    struct nvme_ymtc_smart_log_item itemArr[YMTC_MAX_ITEMS];

    u8 resv[SMART_INFO_SIZE - sizeof(struct nvme_ymtc_smart_log_item) * YMTC_MAX_ITEMS];
};

#endif // __YMTC_UTILS_H__

