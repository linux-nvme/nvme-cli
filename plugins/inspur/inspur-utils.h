/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef __INSPUR_UTILS_H__
#define __INSPUR_UTILS_H__

#define BYTE_OF_64K 65536UL
#define BYTE_OF_32K 32768UL
#define BYTE_OF_16K 16384UL
#define BYTE_OF_4K 4096UL
#define BYTE_OF_512 512UL
#define BYTE_OF_256 256UL
#define BYTE_OF_128 128UL

/* Inspur specific LOG_PAGE_ID */
typedef enum {
    VENDOR_SMART_LOG_PAGE = 0xc0,
} vendor_sepc_log_page_id_e;

#pragma pack(push, 1)
typedef struct r1_am_cap_transtime {
    __u32 cap_trans_time1 : 16;
    __u32 cap_trans_time2 : 16;
} r1_cap_transtime_t;

typedef struct vendor_warning_bit {
    __u32 high_format_fail : 1;
    __u32 low_format_fail : 1;
    __u32 rebuild_fail1 : 1;
    __u32 rebuild_fail2 : 1;
    __u32 rebuild_fail3 : 1;
    __u32 rebuild_fail4 : 1;
    __u32 rebuild_fail5 : 1;
    __u32 rebuild_fail6 : 1;
    __u32 self_test_fail1 : 1;
    __u32 self_test_fail2 : 1;
    __u32 self_test_fail3 : 1;
    __u32 self_test_fail4 : 1;
    __u32 internal_err1 : 1;
    __u32 internal_err2 : 1;
    __u32 internal_err3 : 1;
    __u32 internal_err4 : 1;
    __u32 internal_err5 : 1;
    __u32 internal_err6 : 1;
    __u32 internal_err7 : 1;
    __u32 internal_err8 : 1;
    __u32 internal_err9 : 1;
    __u32 internal_err10 : 1;
    __u32 internal_err11 : 1;
    __u32 internal_err12 : 1;
    __u32 internal_err13 : 1;
    __u32 internal_err14 : 1;
    __u32 internal_err15 : 1;
    __u32 internal_err16 : 1;
    __u32 capacitance_test_fail : 1;
    __u32 IO_read_fail : 1;
    __u32 IO_write_fail : 1;
    __u32 readOnly_after_rebuild : 1;
    __u32 firmware_loss : 1;
    __u32 cap_unsupply : 1;
    __u32 spare_space_warning : 1;
    __u32 lifetime_warning : 1;
    __u32 temp_high_warning : 1;
    __u32 temp_low_warning : 1;
    __u32 mcu_disable : 1;
    __u32 rsv : 25;
} vendor_warning_str;

typedef struct r1_vendor_log_ncm_cout {
    __u32 nand_rd_unc_cnt;
    __u32 nand_rd_srr_cnt;
    __u32 nand_rd_soft_decode_cnt;
    __u32 nand_rd_rebuild_fail_cnt;
    __u32 nand_prg_fail_cnt;
    __u32 nand_eras_fail_cnt;
    __u64 nand_rd_cnt;
    __u64 nand_prg_cnt;
    __u64 nand_eras_cnt;
    __u32 BE_scan_unc_cnt;
    __u32 rebuild_req_cnt;
    __u16 retry_req_cnt;
    __u16 retry_success_cnt;
    __u32 prg_badblk_num;
    __u32 eras_badblk_num;
    __u32 unc_badblk_num;
} r1_vendor_log_nandctl_count_t;

typedef struct r1_wearlvl_vendor_log_count {
    __u32 fbb_count;
    __u32 ebb_count;
    __u32 lbb_count;
    __u32 gc_read_count;
    __u32 gc_write_count;
    __u32 gc_write_fail_count;
    __u32 force_gc_count;
    __u32 avg_pe_count;
    __u32 max_pe_count;
    __u32 free_blk_num1;
    __u32 free_blk_num2;
} r1_wearlvl_vendor_log_count_t;

typedef struct vendor_media_err {
    __u64 lba_err[10];
} vendor_media_err_t;

typedef struct r1_vendor_log_io_err {
    __u32 io_guard_err;
    __u32 io_apptag_err;
    __u32 io_reftag_err;
    __u32 io_dma_linkdown_err;
    __u32 io_dma_disable_err;
    __u32 io_dma_timeout_err;
    __u32 io_dma_fatal_err;
    __u32 io_write_fail_cout;
    __u32 io_read_fail_cout;
    __u32 lba_err[6];
} r1_vendor_log_io_err_t;

typedef struct r1_vendor_log_s {
    __u32 max_power;
    __u32 disk_max_temper;
    __u32 disk_overtemper_cout;
    __u32 ctrl_max_temper;
    __u32 ctrl_overtemper_cout;
    r1_cap_transtime_t cap_transtime;
    __u32 cap_health_state;
    __u32 device_state;
    r1_vendor_log_io_err_t io_err[4];
    union {
        vendor_warning_str detail_warning_bit;
        __u32 detail_warning[2];
    };
    union {
        vendor_warning_str detail_warning_his_bit;
        __u32 detail_warning_his[2];
    };
    __u32 ddr_bit_err_cout;
    __u32 temp_throttle_per;
    __u64 port0_fundamental_reset_cnt;
    __u64 port0_hot_reset_cnt;
    __u64 port0_func_reset_cnt;
    __u64 port0_linkdown_cnt;
    __u64 port0_ctrl_reset_cnt;
    __u64 nand_bytes_written[4];
    __u32 power_info;
    __u32 voltage_info;
    __u32 current_info;
    __u32 current_temp[4];
    __u32 nand_max_temper;
    __u32 nand_overtemper_cout;
    __u32 mcu_data_id;
    __u8 commit_id[16];
    __u32 ces_RcvErr_cnt;
    __u32 ces_BadTlp_cnt;
    __u32 ces_BadDllp_cnt;
    __u32 ces_Rplyover_cnt;
    __u32 ces_RplyTo_cnt;
    __u32 ces_Hlo_cnt;
    __u32 scan_db_err_cnt;
    __u32 db_int_err_cnt;
    __u8 rsvFE[56];
    r1_vendor_log_nandctl_count_t vendor_log_nandctl_cnt[4];
    __u32 temp_ctrl_limit_cnt;
    __u32 temp_ctrl_stop_cnt;
    __u8 rsvncm[216];
    r1_wearlvl_vendor_log_count_t wearlvl_vendor_log_count[4];
    __u8 rsvwlm[512 - sizeof(r1_wearlvl_vendor_log_count_t) * 4 % 512];
    __u32 e2e_check_err_cnt1;
    __u32 e2e_check_err_cnt2;
    __u32 e2e_check_err_cnt3;
    __u32 e2e_check_err_cnt4;
    vendor_media_err_t media_err[4];
    __u8 rsvlkm[176];
} r1_cli_vendor_log_t;
#pragma pack(pop)

#endif // __INSPUR_UTILS_H__
