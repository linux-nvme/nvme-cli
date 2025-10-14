/* SPDX-License-Identifier: GPL-2.0-or-later */
#define IG_SUCCESS    (0)
#define IG_UNSUPPORT  (-1)
#define IG_ERROR      (-2)

#define NVME_VSC_GET_EVENT_LOG  0xC2
#define NVME_VSC_GET            0xE6
#define NVME_VSC_TYPE1_GET      0xFE
#define VSC_FN_GET_CDUMP        0x08
#define IGVSC_SIG               0x69677673
#define EVLOG_SIG               0x65766C67
#define SRB_SIGNATURE           0x544952474F4E4E49ULL

#define XCLEAN_LINE	            "\033[K"
#define SIZE_MB		            0x100000

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

struct drvinfo_t {
	unsigned char  signature;
	unsigned char  fw_base;
	unsigned short socid;
	unsigned char  soc_ver[4];
	unsigned char  loader_version[8];
	unsigned char  nand_devids[6];
	unsigned char  ddr_type;
	unsigned char  ddr_size;
	unsigned char  rsvd1[8];
	unsigned char  origin_fw_name[8];
	unsigned long long nand_type;
	unsigned int   board_type[5];
	unsigned short soc_type;
	unsigned char  build_mode;
	unsigned char  rsvd2;
	unsigned int   ftl_build_num;
	unsigned short soc_reg;
	unsigned char  rsvd3[2];
	unsigned int   cur_cpu_clk;
	unsigned int   cur_nf_clk;
	unsigned char  nand_geo[4];
	unsigned int   fw_d2h_info_bit;
	unsigned int   spi_flash_id;
	unsigned char  rom_version[8];
	unsigned char  rsvd4[404];
};

struct cdump_pack {
	unsigned int ilenth;
	char fwver[8];
};

struct cdumpinfo {
	unsigned int sig;
	unsigned int ipackcount;
	struct cdump_pack cdumppack[32];
};
