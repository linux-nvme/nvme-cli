// SPDX-License-Identifier: GPL-2.0-or-later
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>
#include <errno.h>
#include <limits.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>

#include "common.h"
#include "nvme.h"
#include "libnvme.h"
#include "plugin.h"
#include "nvme-print.h"
#include "util/suffix.h"

#define CREATE_CMD
#include "inspur-nvme.h"
#include "inspur-utils.h"

void show_r1_vendor_log(r1_cli_vendor_log_t *vendorlog)
{
	int i = 0;

	if (vendorlog->device_state == 0)
		printf("device_state              : [healthy]\n");
	else
		printf("device_state              : [warning]\n");

	printf("commit id          : %s\n", vendorlog->commit_id);
	printf("mcu data id(mcu)          : 0x%x\n", le32_to_cpu(vendorlog->mcu_data_id));
	printf("power_info(mcu)           : %u mW\n", le32_to_cpu(vendorlog->power_info));
	printf("voltage_info(mcu)         : %u mV\n", le32_to_cpu(vendorlog->voltage_info));
	printf("current_info(mcu)         : %u mA\n", le32_to_cpu(vendorlog->current_info));
	printf("history max_power(mcu)         : %u mW\n", le32_to_cpu(vendorlog->max_power));
	printf("disk_max_temper(mcu)           : %d C\n", le32_to_cpu(vendorlog->disk_max_temper) - 273);
	printf("disk_overtemper_cout(mcu)      : %u\n", le32_to_cpu(vendorlog->disk_overtemper_cout));
	printf("ctrl_max_temper(mcu)           : %d C\n", le32_to_cpu(vendorlog->ctrl_max_temper) - 273);
	printf("ctrl_overtemper_cout(mcu)      : %u\n", le32_to_cpu(vendorlog->ctrl_overtemper_cout));
	printf("nand_max_temper(mcu)           : %d C\n", le32_to_cpu(vendorlog->nand_max_temper) - 273);
	printf("nand_overtemper_cout(mcu)      : %u\n", le32_to_cpu(vendorlog->nand_overtemper_cout));

	for (i = 0; i < 4; i++)
		printf("temperature[%d](mcu)           : %d C\n", i, le32_to_cpu(vendorlog->current_temp[i]) - 273);

	printf("CAP Time from 32v to 27v(mcu)  : %u ms\n", le32_to_cpu(vendorlog->cap_transtime.cap_trans_time1));
	printf("CAP Time from 27v to 10v(mcu)  : %u ms\n", le32_to_cpu(vendorlog->cap_transtime.cap_trans_time2));
	printf("cap_health_state(mcu)          : %u\n", le32_to_cpu(vendorlog->cap_health_state));
	printf("warning bit(mcu)               : 0x%x%08x\n", le32_to_cpu(vendorlog->detail_warning[1]),
	       le32_to_cpu(vendorlog->detail_warning[0]));
	printf("-->high_format_fail       : %x\n", vendorlog->detail_warning_bit.high_format_fail);
	printf("-->low_format_fail        : %x\n", vendorlog->detail_warning_bit.low_format_fail);
	printf("-->current sensor         : %x\n", vendorlog->detail_warning_bit.self_test_fail1);
	printf("-->nand temp sensor       : %x\n", vendorlog->detail_warning_bit.self_test_fail2);
	printf("-->board temp sensor      : %x\n", vendorlog->detail_warning_bit.self_test_fail3);
	printf("-->cntl temp sensor       : %x\n", vendorlog->detail_warning_bit.self_test_fail4);
	printf("-->cap_timer_test_fail    : %x\n", vendorlog->detail_warning_bit.capacitance_test_fail);
	printf("-->readOnly_after_rebuild : %x\n", vendorlog->detail_warning_bit.readOnly_after_rebuild);
	printf("-->firmware_loss          : %x\n", vendorlog->detail_warning_bit.firmware_loss);
	printf("-->cap_self_test          : %x\n", vendorlog->detail_warning_bit.cap_unsupply);
	printf("-->spare_space_warning    : %x\n", vendorlog->detail_warning_bit.spare_space_warning);
	printf("-->lifetime_warning       : %x\n", vendorlog->detail_warning_bit.lifetime_warning);
	printf("-->temp_high_warning      : %x\n", vendorlog->detail_warning_bit.temp_high_warning);
	printf("-->temp_low_warning       : %x\n", vendorlog->detail_warning_bit.temp_low_warning);
	printf("-->mcu_disable(mcu)       : %x\n", vendorlog->detail_warning_bit.mcu_disable);
	printf("warning history bit(mcu)  : 0x%x%08x\n", le32_to_cpu(vendorlog->detail_warning_his[1]),
	       le32_to_cpu(vendorlog->detail_warning_his[0]));
	printf("-->high_format_fail       : %x\n", vendorlog->detail_warning_his_bit.high_format_fail);
	printf("-->low_format_fail        : %x\n", vendorlog->detail_warning_his_bit.low_format_fail);
	printf("-->current sensor         : %x\n", vendorlog->detail_warning_his_bit.self_test_fail1);
	printf("-->nand temp sensor       : %x\n", vendorlog->detail_warning_his_bit.self_test_fail2);
	printf("-->board temp sensor      : %x\n", vendorlog->detail_warning_his_bit.self_test_fail3);
	printf("-->cntl temp sensor       : %x\n", vendorlog->detail_warning_his_bit.self_test_fail4);
	printf("-->cap_timer_test_fail    : %x\n", vendorlog->detail_warning_his_bit.capacitance_test_fail);
	printf("-->readOnly_after_rebuild : %x\n", vendorlog->detail_warning_his_bit.readOnly_after_rebuild);
	printf("-->firmware_loss          : %x\n", vendorlog->detail_warning_his_bit.firmware_loss);
	printf("-->cap_self_test          : %x\n", vendorlog->detail_warning_his_bit.cap_unsupply);
	printf("-->spare_space_warning    : %x\n", vendorlog->detail_warning_his_bit.spare_space_warning);
	printf("-->lifetime_warning       : %x\n", vendorlog->detail_warning_his_bit.lifetime_warning);
	printf("-->temp_high_warning      : %x\n", vendorlog->detail_warning_his_bit.temp_high_warning);
	printf("-->temp_low_warning       : %x\n", vendorlog->detail_warning_his_bit.temp_low_warning);
	printf("-->mcu_disable(mcu)       : %x\n", vendorlog->detail_warning_his_bit.mcu_disable);

	for (i = 0; i < 4; i++)
		printf("[%d]nand_bytes_written        : %" PRIu64 " GB\n", i, le64_to_cpu(vendorlog->nand_bytes_written[i]));

	for (i = 0; i < 4; i++) {
		printf("[%d]io_apptag_err         : %u\n", i, le32_to_cpu(vendorlog->io_err[i].io_apptag_err));
		printf("[%d]io_guard_err          : %u\n", i, le32_to_cpu(vendorlog->io_err[i].io_guard_err));
		printf("[%d]io_reftag_err         : %u\n", i, le32_to_cpu(vendorlog->io_err[i].io_reftag_err));
		printf("[%d]io_read_fail_cout     : %u\n", i, le32_to_cpu(vendorlog->io_err[i].io_read_fail_cout));
		printf("[%d]io_write_fail_cout    : %u\n", i, le32_to_cpu(vendorlog->io_err[i].io_write_fail_cout));
		printf("[%d]io_dma_disable_err    : %u\n", i, le32_to_cpu(vendorlog->io_err[i].io_dma_disable_err));
		printf("[%d]io_dma_fatal_err      : %u\n", i, le32_to_cpu(vendorlog->io_err[i].io_dma_fatal_err));
		printf("[%d]io_dma_linkdown_err   : %u\n", i, le32_to_cpu(vendorlog->io_err[i].io_dma_linkdown_err));
		printf("[%d]io_dma_timeout_err    : %u\n", i, le32_to_cpu(vendorlog->io_err[i].io_dma_timeout_err));
		printf("[%d]lba_err[0]            : %u\n", i, le32_to_cpu(vendorlog->io_err[i].lba_err[0]));
		printf("[%d]lba_err[1]            : %u\n", i, le32_to_cpu(vendorlog->io_err[i].lba_err[1]));
		printf("[%d]lba_err[2]            : %u\n", i, le32_to_cpu(vendorlog->io_err[i].lba_err[2]));
		printf("[%d]lba_err[3]            : %u\n", i, le32_to_cpu(vendorlog->io_err[i].lba_err[3]));
		printf("[%d]lba_err[4]            : %u\n", i, le32_to_cpu(vendorlog->io_err[i].lba_err[4]));
		printf("[%d]lba_err[5]            : %u\n", i, le32_to_cpu(vendorlog->io_err[i].lba_err[5]));
	}

	printf("temp_throttle_per         : %u\n", le32_to_cpu(vendorlog->temp_throttle_per));
	printf("port0_flreset_cnt         : %" PRIu64 "\n", le64_to_cpu(vendorlog->port0_fundamental_reset_cnt));
	printf("port0_hot_reset_cnt       : %" PRIu64 "\n", le64_to_cpu(vendorlog->port0_hot_reset_cnt));
	printf("port0_func_reset_cnt      : %" PRIu64 "\n", le64_to_cpu(vendorlog->port0_func_reset_cnt));
	printf("port0_linkdown_cnt        : %" PRIu64 "\n", le64_to_cpu(vendorlog->port0_linkdown_cnt));
	printf("port0_ctrl_reset_cnt      : %" PRIu64 "\n", le64_to_cpu(vendorlog->port0_ctrl_reset_cnt));
	printf("ces_RcvErr_cnt            : %u\n", le32_to_cpu(vendorlog->ces_RcvErr_cnt));
	printf("ces_BadTlp_cnt            : %u\n", le32_to_cpu(vendorlog->ces_BadTlp_cnt));
	printf("ces_BadDllp_cnt           : %u\n", le32_to_cpu(vendorlog->ces_BadDllp_cnt));
	printf("ces_Rplyover_cnt          : %u\n", le32_to_cpu(vendorlog->ces_Rplyover_cnt));
	printf("ces_RplyTo_cnt            : %u\n", le32_to_cpu(vendorlog->ces_RplyTo_cnt));
	printf("ces_Hlo_cnt               : %u\n", le32_to_cpu(vendorlog->ces_Hlo_cnt));
	printf("scan doorbell err cnt        : %u\n", le32_to_cpu(vendorlog->scan_db_err_cnt));
	printf("doorbell interrupt err cnt   : %u\n", le32_to_cpu(vendorlog->db_int_err_cnt));

	printf("------------ncm-----------------------\n");
	for (i = 0; i < 4; i++) {
		printf("------------part%d-----------------------\n", i);
		printf("[%d]nand_rd_unc_count         : %u\n", i,
		       le32_to_cpu(vendorlog->vendor_log_nandctl_cnt[i].nand_rd_unc_cnt));
		printf("[%d]nand_rd_srr_count         : %u\n", i,
		       le32_to_cpu(vendorlog->vendor_log_nandctl_cnt[i].nand_rd_srr_cnt));
		printf("[%d]nand_rd_sdecode_count     : %u\n", i,
		       le32_to_cpu(vendorlog->vendor_log_nandctl_cnt[i].nand_rd_soft_decode_cnt));
		printf("[%d]nand_rd_rb_fail_count     : %u\n", i,
		       le32_to_cpu(vendorlog->vendor_log_nandctl_cnt[i].nand_rd_rebuild_fail_cnt));
		printf("[%d]nand_prg_fail_count       : %u\n", i,
		       le32_to_cpu(vendorlog->vendor_log_nandctl_cnt[i].nand_prg_fail_cnt));
		printf("[%d]nand_eras_fail_count      : %u\n", i,
		       le32_to_cpu(vendorlog->vendor_log_nandctl_cnt[i].nand_eras_fail_cnt));
		printf("[%d]nand_rd_count             : %" PRIu64 "\n", i,
		       le64_to_cpu(vendorlog->vendor_log_nandctl_cnt[i].nand_rd_cnt));
		printf("[%d]nand_prg_count            : %" PRIu64 "\n", i,
		       le64_to_cpu(vendorlog->vendor_log_nandctl_cnt[i].nand_prg_cnt));
		printf("[%d]nand_eras_count           : %" PRIu64 "\n", i,
		       le64_to_cpu(vendorlog->vendor_log_nandctl_cnt[i].nand_eras_cnt));
		printf("[%d]BE_scan_unc_count         : %u\n", i,
		       le32_to_cpu(vendorlog->vendor_log_nandctl_cnt[i].BE_scan_unc_cnt));
		printf("[%d]rebuild_req_cnt           : %u\n", i,
		       le32_to_cpu(vendorlog->vendor_log_nandctl_cnt[i].rebuild_req_cnt));
		printf("[%d]retry_req_cnt             : %u\n", i,
		       le32_to_cpu(vendorlog->vendor_log_nandctl_cnt[i].retry_req_cnt));
		printf("[%d]retry_success_cnt         : %u\n", i,
		       le32_to_cpu(vendorlog->vendor_log_nandctl_cnt[i].retry_success_cnt));
		printf("[%d]prg_badblk_num            : %u\n", i,
		       le32_to_cpu(vendorlog->vendor_log_nandctl_cnt[i].prg_badblk_num));
		printf("[%d]eras_badblk_num           : %u\n", i,
		       le32_to_cpu(vendorlog->vendor_log_nandctl_cnt[i].eras_badblk_num));
		printf("[%d]read_badblk_num           : %u\n", i,
		       le32_to_cpu(vendorlog->vendor_log_nandctl_cnt[i].unc_badblk_num));
	}

	printf("[%d]temp_ctrl_limit_count         : %u\n", i, le32_to_cpu(vendorlog->temp_ctrl_limit_cnt));
	printf("[%d]temp_ctrl_stop_count          : %u\n", i, le32_to_cpu(vendorlog->temp_ctrl_stop_cnt));
	printf("------------wlm-----------------------\n");
	for (i = 0; i < 4; i++) {
		printf("------------part%d-----------------------\n", i);
		printf("[%d]fbb_count                 : %u\n", i,
		       le32_to_cpu(vendorlog->wearlvl_vendor_log_count[i].fbb_count));
		printf("[%d]ebb_count                 : %u\n", i,
		       le32_to_cpu(vendorlog->wearlvl_vendor_log_count[i].ebb_count));
		printf("[%d]lbb_count                 : %u\n", i,
		       le32_to_cpu(vendorlog->wearlvl_vendor_log_count[i].lbb_count));
		printf("[%d]gc_read_count             : %u\n", i,
		       le32_to_cpu(vendorlog->wearlvl_vendor_log_count[i].gc_read_count));
		printf("[%d]gc_write_count            : %u\n", i,
		       le32_to_cpu(vendorlog->wearlvl_vendor_log_count[i].gc_write_count));
		printf("[%d]gc_write_fail_count       : %u\n", i,
		       le32_to_cpu(vendorlog->wearlvl_vendor_log_count[i].gc_write_fail_count));
		printf("[%d]force_gc_count            : %u\n", i,
		       le32_to_cpu(vendorlog->wearlvl_vendor_log_count[i].force_gc_count));
		printf("[%d]avg_pe_count              : %u\n", i,
		       le32_to_cpu(vendorlog->wearlvl_vendor_log_count[i].avg_pe_count));
		printf("[%d]max_pe_count              : %u\n", i,
		       le32_to_cpu(vendorlog->wearlvl_vendor_log_count[i].max_pe_count));
		printf("[%d]free_blk_num1             : %u\n", i,
		       le32_to_cpu(vendorlog->wearlvl_vendor_log_count[i].free_blk_num1));
		printf("[%d]free_blk_num2             : %u\n", i,
		       le32_to_cpu(vendorlog->wearlvl_vendor_log_count[i].free_blk_num2));
	}

	printf("------------lkm-----------------------\n");
	printf("[%d]e2e_check_err_count1          : %u\n", i, le32_to_cpu(vendorlog->e2e_check_err_cnt1));
	printf("[%d]e2e_check_err_count2          : %u\n", i, le32_to_cpu(vendorlog->e2e_check_err_cnt2));
	printf("[%d]e2e_check_err_count3          : %u\n", i, le32_to_cpu(vendorlog->e2e_check_err_cnt3));
	printf("[%d]e2e_check_err_count4          : %u\n", i, le32_to_cpu(vendorlog->e2e_check_err_cnt4));
}

void show_r1_media_err_log(r1_cli_vendor_log_t *vendorlog)
{
	int i, j;

	for (i = 0; i < 4; i++) {
		printf("DM%d read err lba:\n", i);
		for (j = 0; j < 10; j++)
			printf("[%d]lba : %" PRIu64 "\n", j, le64_to_cpu(vendorlog->media_err[i].lba_err[j]));
	}
}

static int nvme_get_vendor_log(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	char *desc = "Get the Inspur vendor log";
	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	__u8 local_mem[BYTE_OF_4K];
	int err;

	OPT_ARGS(opts) = { OPT_END() };

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	memset(local_mem, 0, BYTE_OF_4K);
	err = nvme_get_log_simple(hdl, (enum nvme_cmd_get_log_lid)VENDOR_SMART_LOG_PAGE,
				  local_mem, sizeof(r1_cli_vendor_log_t));
	if (!err) {
		show_r1_vendor_log((r1_cli_vendor_log_t *)local_mem);
		show_r1_media_err_log((r1_cli_vendor_log_t *)local_mem);
	} else {
		nvme_show_status(err);
	}

	return err;
}
