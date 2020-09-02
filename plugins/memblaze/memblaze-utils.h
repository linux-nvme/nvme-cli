#ifndef __MEMBLAZE_UTILS_H__
#define __MEMBLAZE_UTILS_H__

#define SMART_INFO_OLD_SIZE     512
#define SMART_INFO_NEW_SIZE     4096

#define ID_SIZE                 3
#define NM_SIZE                 2
#define RAW_SIZE                7

typedef unsigned char           u8;

// Intel Format & new format
/* Raisin Additional smart external ID */
#define RAISIN_SI_VD_PROGRAM_FAIL_ID                        0xAB
#define RAISIN_SI_VD_ERASE_FAIL_ID                          0xAC
#define RAISIN_SI_VD_WEARLEVELING_COUNT_ID                  0xAD
#define RAISIN_SI_VD_E2E_DECTECTION_COUNT_ID                0xB8
#define RAISIN_SI_VD_PCIE_CRC_ERR_COUNT_ID                  0xC7
#define RAISIN_SI_VD_TIMED_WORKLOAD_MEDIA_WEAR_ID           0xE2
#define RAISIN_SI_VD_TIMED_WORKLOAD_HOST_READ_ID            0xE3
#define RAISIN_SI_VD_TIMED_WORKLOAD_TIMER_ID                0xE4
#define RAISIN_SI_VD_THERMAL_THROTTLE_STATUS_ID             0xEA
#define RAISIN_SI_VD_RETRY_BUFF_OVERFLOW_COUNT_ID           0xF0
#define RAISIN_SI_VD_PLL_LOCK_LOSS_COUNT_ID                 0xF3
#define RAISIN_SI_VD_TOTAL_WRITE_ID                         0xF4
#define RAISIN_SI_VD_HOST_WRITE_ID                          0xF5
#define RAISIN_SI_VD_SYSTEM_AREA_LIFE_LEFT_ID               0xF6
#define RAISIN_SI_VD_TOTAL_READ_ID                          0xFA
#define RAISIN_SI_VD_TEMPT_SINCE_BORN_ID                    0xE7
#define RAISIN_SI_VD_POWER_CONSUMPTION_ID                   0xE8
#define RAISIN_SI_VD_TEMPT_SINCE_BOOTUP_ID                  0xAF
#define RAISIN_SI_VD_POWER_LOSS_PROTECTION_ID               0xEC
#define RAISIN_SI_VD_READ_FAIL_ID                           0xF2
#define RAISIN_SI_VD_THERMAL_THROTTLE_TIME_ID               0xEB
#define RAISIN_SI_VD_FLASH_MEDIA_ERROR_ID                   0xED

/* Raisin Addtional smart internal ID */
typedef enum
{
    /* smart attr following intel */
    RAISIN_SI_VD_PROGRAM_FAIL = 0, /* 0xAB */
    RAISIN_SI_VD_ERASE_FAIL = 1,   /* 0xAC */
    RAISIN_SI_VD_WEARLEVELING_COUNT = 2,/* 0xAD */
    RAISIN_SI_VD_E2E_DECTECTION_COUNT = 3, /* 0xB8 */
    RAISIN_SI_VD_PCIE_CRC_ERR_COUNT = 4, /* 0xC7, 2 port data in one attribute */
    RAISIN_SI_VD_TIMED_WORKLOAD_MEDIA_WEAR = 5, /* 0xE2 , unknown definition*/
    RAISIN_SI_VD_TIMED_WORKLOAD_HOST_READ = 6, /* 0xE3 , unknown definition */
    RAISIN_SI_VD_TIMED_WORKLOAD_TIMER = 7, /* 0xE4 , unknown definition */
    RAISIN_SI_VD_THERMAL_THROTTLE_STATUS = 8, /* 0xEA */
    RAISIN_SI_VD_RETRY_BUFF_OVERFLOW_COUNT = 9, /* 0xF0, unknown definition*/
    RAISIN_SI_VD_PLL_LOCK_LOSS_COUNT = 10, /* 0xF3, unknown definition*/
    RAISIN_SI_VD_TOTAL_WRITE = 11, /* 0xF4, unit is 32MiB */
    RAISIN_SI_VD_HOST_WRITE = 12, /* 0xF5, unit is 32MiB */
    RAISIN_SI_VD_SYSTEM_AREA_LIFE_LEFT = 13, /* 0xF6, unknown definition*/
    RAISIN_SI_VD_TOTAL_READ = 14, /* 0xFA, unit is 32MiB */

    /* smart attr self defined */
    RAISIN_SI_VD_TEMPT_SINCE_BORN = 15, /* 0xE7 */
    RAISIN_SI_VD_POWER_CONSUMPTION = 16, /* 0xE8 */
    RAISIN_SI_VD_TEMPT_SINCE_BOOTUP = 17, /* 0xAF */
    RAISIN_SI_VD_POWER_LOSS_PROTECTION = 18, /* 0xEC */
    RAISIN_SI_VD_READ_FAIL = 19, /* 0xF2 */
    RAISIN_SI_VD_THERMAL_THROTTLE_TIME = 20, /* 0xEB */
    RAISIN_SI_VD_FLASH_MEDIA_ERROR = 21, /* 0xED */
    RAISIN_SI_VD_SMART_INFO_ITEMS_MAX,
} RAISIN_si_vendor_smart_item_e;

// Memblaze Format & old format
enum {
    /*0*/TOTAL_WRITE = 0,
    /*1*/TOTAL_READ,
    /*2*/THERMAL_THROTTLE,
    /*3*/TEMPT_SINCE_RESET,
    /*4*/POWER_CONSUMPTION,
    /*5*/TEMPT_SINCE_BOOTUP,
    /*6*/POWER_LOSS_PROTECTION,
    /*7*/WEARLEVELING_COUNT,
    /*8*/HOST_WRITE,
    /*9*/THERMAL_THROTTLE_CNT,
    /*10*/CORRECT_PCIE_PORT0,
    /*11*/CORRECT_PCIE_PORT1,
    /*12*/REBUILD_FAIL,
    /*13*/ERASE_FAIL,
    /*14*/PROGRAM_FAIL,
    /*15*/READ_FAIL,
    /*16*/NR_SMART_ITEMS = RAISIN_SI_VD_SMART_INFO_ITEMS_MAX,
};

// Memblaze Format & old format
#pragma pack(push, 1)
struct nvme_memblaze_smart_log_item {
        __u8 id[3];
        union {
            __u8    __nmval[2];
            __le16  nmval;
        };
        union {
        __u8 rawval[6];
        struct temperature {
        __le16 max;
        __le16 min;
        __le16 curr;
        } temperature;
        struct power {
            __le16 max;
            __le16 min;
            __le16 curr;
        } power;
        struct thermal_throttle_mb {
            __u8 on;
            __u32 count;
        } thermal_throttle;
        struct temperature_p {
            __le16 max;
            __le16 min;
        } temperature_p;
        struct power_loss_protection {
            __u8 curr;
        } power_loss_protection;
        struct wearleveling_count {
            __le16 min;
            __le16 max;
            __le16 avg;
        } wearleveling_count;
        struct thermal_throttle_cnt {
            __u8 active;
            __le32 cnt;
        } thermal_throttle_cnt;
    };
    __u8 resv;
};
#pragma pack(pop)

struct nvme_memblaze_smart_log {
    struct nvme_memblaze_smart_log_item items[NR_SMART_ITEMS];
    u8 resv[SMART_INFO_OLD_SIZE - sizeof(struct nvme_memblaze_smart_log_item) * NR_SMART_ITEMS];
};

// Intel Format & new format
struct nvme_p4_smart_log_item
{
    /* Item identifier */
    u8 id[ID_SIZE];
    /* Normalized value or percentage. In the range from 0 to 100. */
    u8 nmVal[NM_SIZE];
    /* raw value */
    u8 rawVal[RAW_SIZE];
};

struct nvme_p4_smart_log
{
    struct nvme_p4_smart_log_item itemArr[NR_SMART_ITEMS];

    /**
     * change 512 to 4096.
     * because micron's getlogpage request,the size of many commands have changed to 4k.
     * request size > user malloc size,casuing parameters that are closed in momery are dirty.
     */
    u8 resv[SMART_INFO_NEW_SIZE - sizeof(struct nvme_p4_smart_log_item) * NR_SMART_ITEMS];
};

// base
#define DD                           do{ printf("=Memblaze= %s[%d]-%s():\n", __FILE__, __LINE__, __func__); }while(0)
#define DE(str)                      do{ printf("===ERROR!=== %s[%d]-%s():str=%s\n", __FILE__, __LINE__, __func__, \
                                     str); }while(0)
// integer
#define DI(i)                        do{ printf("=Memblaze= %s[%d]-%s():int=%d\n", __FILE__, __LINE__, __func__, \
                                     (int)i); } while(0)
#define DPI(prompt, i)               do{ printf("=Memblaze= %s[%d]-%s():%s=%d\n", __FILE__, __LINE__, __func__, \
                                     prompt, i); }while(0)
#define DAI(prompt, i, arr, max)     do{ printf("=Memblaze= %s[%d]-%s():%s", __FILE__, __LINE__, __func__, prompt); \
                                     for(i=0;i<max;i++) printf(" %d:%d", i, arr[i]); \
                                     printf("\n"); }while(0)
// char
#define DC(c)                        do{ printf("=Memblaze= %s[%d]-%s():char=%c\n", __FILE__, __LINE__, __func__, c); \
                                     }while(0)
#define DPC(prompt, c)               do{ printf("=Memblaze= %s[%d]-%s():%s=%c\n", __FILE__, __LINE__, __func__, \
                                     prompt, c); }while(0)
// address
#define DA(add)                      do{ printf("=Memblaze= %s[%d]-%s():address=0x%08X\n", __FILE__, __LINE__, \
                                     __func__, add); }while(0)
#define DPA(prompt, add)             do{ printf("=Memblaze= %s[%d]-%s():%s=0x%08X\n", __FILE__, __LINE__, __func__, \
                                     prompt, add); }while(0)
// string
#define DS(str)                      do{ printf("=Memblaze= %s[%d]-%s():str=%s\n", __FILE__, __LINE__, __func__, str); \
                                     }while(0)
#define DPS(prompt, str)             do{ printf("=Memblaze= %s[%d]-%s():%s=%s\n", __FILE__, __LINE__, __func__, \
                                     prompt, str); }while(0)
#define DAS(prompt, i, arr, max)     do{ printf("=Memblaze= %s[%d]-%s():%s", __FILE__, __LINE__, __func__, prompt); \
                                     for(i=0;i<max;i++) printf(" %d:%s", i, arr[i]); \
                                     printf("\n"); }while(0)
// array
#define DR(str, k)                   do{ int ip; for(ip=0;ip<k;ip++) if(NULL != argv[ip]) \
                                     printf("=Memblaze= %s[%d]-%s():%d=%s\n", \
                                     __FILE__, __LINE__, __func__, ip, str[ip]); }while(0)
#define DARG                         do{ DPI("argc", argc); \
                                     int ip; for(ip=0;ip<argc;ip++) if(NULL != argv[ip]) \
                                     printf("=Memblaze= %s[%d]-%s():%d=%s\n", \
                                     __FILE__, __LINE__, __func__, ip, argv[ip]); }while(0)

#define fPRINT_PARAM1(format) \
    { \
        do \
        { \
            fprintf(fdi, format);\
            if (print) \
            { \
                printf(format); \
            } \
        } while (0); \
    }

#define fPRINT_PARAM2(format, value) \
    { \
        do \
        { \
            fprintf(fdi, format, value);\
            if (print) \
            { \
                printf(format, value); \
            } \
        } while (0); \
    }

#endif // __MEMBLAZE_UTILS_H__

