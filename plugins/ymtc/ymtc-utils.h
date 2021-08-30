#ifndef __YMTC_UTILS_H__
#define __YMTC_UTILS_H__

#define SMART_INFO_SIZE     4096

#define ID_SIZE                 3
#define NM_SIZE                 2
#define RAW_SIZE                7

typedef unsigned char           u8;

/* Additional smart external ID */
#define SI_VD_PROGRAM_FAIL_ID                        0xAB
#define SI_VD_ERASE_FAIL_ID                          0xAC
#define SI_VD_WEARLEVELING_COUNT_ID                  0xAD
#define SI_VD_E2E_DECTECTION_COUNT_ID                0xB8
#define SI_VD_PCIE_CRC_ERR_COUNT_ID                  0xC7
#define SI_VD_TIMED_WORKLOAD_MEDIA_WEAR_ID           0xE2
#define SI_VD_TIMED_WORKLOAD_HOST_READ_ID            0xE3
#define SI_VD_TIMED_WORKLOAD_TIMER_ID                0xE4
#define SI_VD_THERMAL_THROTTLE_STATUS_ID             0xEA
#define SI_VD_RETRY_BUFF_OVERFLOW_COUNT_ID           0xF0
#define SI_VD_PLL_LOCK_LOSS_COUNT_ID                 0xF3
#define SI_VD_TOTAL_WRITE_ID                         0xF4
#define SI_VD_HOST_WRITE_ID                          0xF5
#define SI_VD_SYSTEM_AREA_LIFE_LEFT_ID               0xF6
#define SI_VD_TOTAL_READ_ID                          0xFA
#define SI_VD_TEMPT_SINCE_BORN_ID                    0xE7
#define SI_VD_POWER_CONSUMPTION_ID                   0xE8
#define SI_VD_TEMPT_SINCE_BOOTUP_ID                  0xAF
#define SI_VD_POWER_LOSS_PROTECTION_ID               0xEC
#define SI_VD_READ_FAIL_ID                           0xF2
#define SI_VD_THERMAL_THROTTLE_TIME_ID               0xEB
#define SI_VD_FLASH_MEDIA_ERROR_ID                   0xED

/* Addtional smart internal ID */
typedef enum
{
    /* smart attr following intel */
    SI_VD_PROGRAM_FAIL = 0, /* 0xAB */
    SI_VD_ERASE_FAIL = 1,   /* 0xAC */
    SI_VD_WEARLEVELING_COUNT = 2,/* 0xAD */
    SI_VD_E2E_DECTECTION_COUNT = 3, /* 0xB8 */
    SI_VD_PCIE_CRC_ERR_COUNT = 4, /* 0xC7, 2 port data in one attribute */
    SI_VD_THERMAL_THROTTLE_STATUS = 8, /* 0xEA */
    SI_VD_TOTAL_WRITE = 11, /* 0xF4, unit is 32MiB */
    SI_VD_HOST_WRITE = 12, /* 0xF5, unit is 32MiB */
    SI_VD_TOTAL_READ = 14, /* 0xFA, unit is 32MiB */

    /* smart attr self defined */
    SI_VD_TEMPT_SINCE_BORN = 15, /* 0xE7 */
    SI_VD_POWER_CONSUMPTION = 16, /* 0xE8 */
    SI_VD_TEMPT_SINCE_BOOTUP = 17, /* 0xAF */
    SI_VD_POWER_LOSS_PROTECTION = 18, /* 0xEC */
    SI_VD_READ_FAIL = 19, /* 0xF2 */
    SI_VD_THERMAL_THROTTLE_TIME = 20, /* 0xEB */
    SI_VD_FLASH_MEDIA_ERROR = 21, /* 0xED */
    NR_SMART_ITEMS,
} si_vendor_smart_item_e;

// Intel Format
struct nvme_ymtc_smart_log_item
{
    /* Item identifier */
    u8 id[ID_SIZE];
    /* Normalized value or percentage. In the range from 0 to 100. */
    u8 nmVal[NM_SIZE];
    /* raw value */
    u8 rawVal[RAW_SIZE];
};

struct nvme_ymtc_smart_log
{
    struct nvme_ymtc_smart_log_item itemArr[NR_SMART_ITEMS];

    u8 resv[SMART_INFO_SIZE - sizeof(struct nvme_ymtc_smart_log_item) * NR_SMART_ITEMS];
};

#endif // __YMTC_UTILS_H__

