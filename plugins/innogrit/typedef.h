/* SPDX-License-Identifier: GPL-2.0-or-later */
#define SIZE_4K		4096
#define SIZE_16K	16384

#define NVME_VSC_GET_EVENT_LOG		0xC2
#define NVME_VSC_CLEAN_EVENT_LOG	0xD8
#define NVME_VSC_GET			0xE6
#define VSC_FN_GET_CDUMP		0x08
#define EVLOG_SIG			0x65766C67
#define SRB_SIGNATURE			0x544952474F4E4E49ULL
#define XCLEAN_LINE			"\033[K"

struct evlg_flush_hdr {
	unsigned int signature;
	unsigned int fw_ver[2];
	unsigned int fw_type : 8;
	unsigned int log_type : 8;
	unsigned int project : 16;
	unsigned int trace_cnt;
	unsigned int sout_crc;
	unsigned int reserved[2];
};

struct eventlog {
	unsigned int ms;
	unsigned int param[7];
};

struct eventlog_addindex {
	unsigned int ms;
	unsigned int param[7];
	unsigned int iindex;
};

#pragma pack(push)
#pragma pack(1)
struct vsc_smart_log {
	unsigned short defect_cnt;
	unsigned short slc_spb_cnt;
	unsigned int slc_total_ec_cnt;
	unsigned int slc_max_ec_cnt;
	unsigned int slc_min_ec_cnt;
	unsigned int slc_avg_ec_cnt;
	unsigned int total_ec_cnt;
	unsigned int max_ec_cnt;
	unsigned int min_ec_cnt;
	unsigned int avg_ec_cnt;
	unsigned int mrd_rr_good_cnt;
	unsigned int ard_rr_good_cnt;
	unsigned int preset_cnt;
	unsigned int nvme_reset_cnt;
	unsigned int low_pwr_cnt;
	unsigned int wa;
	unsigned int ps3_entry_cnt;
	u_char highest_temp[4];
	unsigned int weight_ec;
	unsigned int slc_cap_mb;
	unsigned long long nand_page_write_cnt;
	unsigned int program_error_cnt;
	unsigned int erase_error_cnt;
	u_char flash_type;
	u_char reserved2[3];
	unsigned int hs_crc_err_cnt;
	unsigned int reserved3[45];
};
#pragma pack(pop)

struct cdump_pack {
	unsigned int ilenth;
	char fwver[8];
};

struct cdumpinfo {
	unsigned int sig;
	unsigned int ipackcount;
	struct cdump_pack cdumppack[32];
};
