// SPDX-License-Identifier: GPL-2.0-or-later
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "common.h"
#include "nvme.h"
#include "nvme-print.h"
#include "plugin.h"

#define CREATE_CMD
#include "ibm-nvme.h"

#pragma pack(push, 1)
struct nvme_ibm_log_f0_item {
	__le16 attr;
	union {
		__le64 raw1;
		struct split_raw1 {
			__le32 lower;
			__le32 upper;
		} split_raw1;
	};
	union {
		__le64 raw2;
		struct split_raw2 {
			__le32 lower;
			__le32 upper;
		} split_raw2;
	};
};
#pragma pack(pop)

struct nvme_ibm_additional_smart_log {
	__le16 logid;
	__le16 len;
	struct nvme_ibm_log_f0_item read_err_rate;
	struct nvme_ibm_log_f0_item retired_clk_cnt;
	struct nvme_ibm_log_f0_item power_on_hours;
	struct nvme_ibm_log_f0_item power_cycle_cnt;
	struct nvme_ibm_log_f0_item ecc_rate;
	struct nvme_ibm_log_f0_item mb_erased;
	struct nvme_ibm_log_f0_item unused_rsvd_blk_cnt_percent;
	struct nvme_ibm_log_f0_item progrm_fail_cnt;
	struct nvme_ibm_log_f0_item erase_fail_cnt;
	struct nvme_ibm_log_f0_item drive_life_remain_percent;
	struct nvme_ibm_log_f0_item io_err_det_code_events;
	struct nvme_ibm_log_f0_item reported_uc_errs;
	struct nvme_ibm_log_f0_item drive_temperature;
	struct nvme_ibm_log_f0_item thermal_throt;
	struct nvme_ibm_log_f0_item drive_life_temp;
	struct nvme_ibm_log_f0_item int_raid_correct_err_cnt;
	struct nvme_ibm_log_f0_item ssd_life_used;
	struct nvme_ibm_log_f0_item ssd_life_used_accurate;
	struct nvme_ibm_log_f0_item lifetime_wr_to_flash_mb;
	struct nvme_ibm_log_f0_item lifetime_rd_from_flash_mb;
	struct nvme_ibm_log_f0_item lifetime_wr_from_host_mb;
	struct nvme_ibm_log_f0_item lifetime_rd_to_host_mb;
	struct nvme_ibm_log_f0_item vol_mem_backup_fail;
	struct nvme_ibm_log_f0_item security_wear_indicator;
	struct nvme_ibm_log_f0_item device_pcie_received_errors;
};

static void show_ibm_smart_log(struct nvme_ibm_additional_smart_log *smart, const char *devname)
{
	int i, entries = (sizeof(struct nvme_ibm_additional_smart_log) - 4)
				/ sizeof(struct nvme_ibm_log_f0_item);
	struct nvme_ibm_log_f0_item *entry;

	entry = &smart->read_err_rate;

	printf("Additional IBM Smart Log for NVME device:%s\n", devname);

	for (i = 0; i < entries; i++, entry++) {
		switch (le16_to_cpu(entry->attr)) {
		case 0x0001:
			printf("Total UC Read Errors                : %"PRIu64"\n",
				le64_to_cpu(smart->read_err_rate.raw1));
			printf("Total Reads vs Read Errors          : %"PRIu64"\n",
				le64_to_cpu(smart->read_err_rate.raw2));
			break;
		case 0x0005:
			printf("Total Retired Blks                  : %"PRIu64"\n",
				le64_to_cpu(smart->retired_clk_cnt.raw1));
			break;
		case 0x0009:
			printf("Total Power On Hours                : %"PRIu64"\n",
				le64_to_cpu(smart->power_on_hours.raw1));
			printf("Time since Last P/C(ms)             : %"PRIu64"\n",
				le64_to_cpu(smart->power_on_hours.raw2));
			break;
		case 0x000c:
			printf("Total Number of Power Cycles        : %"PRIu64"\n",
				le64_to_cpu(smart->power_cycle_cnt.raw1));
			break;
		case 0x000d:
			printf("Read (ECC) Errors recov nodelay     : %"PRIu64"\n",
				le64_to_cpu(smart->ecc_rate.raw1));
			printf("Total Reads vs Read Errs nodelay    : %"PRIu64"\n",
				le64_to_cpu(smart->ecc_rate.raw2));
			break;
		case 0x0064:
			printf("Total MB Erased                     : %"PRIu64"\n",
				le64_to_cpu(smart->mb_erased.raw1));
			break;
		case 0x00aa:
			printf("Unused Rsv Blk 100*Cur/Mfg Spares   : %"PRIu64"\n",
				le64_to_cpu(smart->unused_rsvd_blk_cnt_percent.raw1));
			printf("Current Spares                      : %"PRIu32"\n",
				le32_to_cpu(smart->unused_rsvd_blk_cnt_percent.split_raw2.upper));
			printf("Total Spares @ Mfg                  : %"PRIu32"\n",
				le32_to_cpu(smart->unused_rsvd_blk_cnt_percent.split_raw2.lower));
			break;
		case 0x00ab:
			printf("Total Number of Program Fails       : %"PRIu64"\n",
				le64_to_cpu(smart->progrm_fail_cnt.raw1));
			printf("Program fails since Power Cycle     : %"PRIu64"\n",
				le64_to_cpu(smart->progrm_fail_cnt.raw2));
			break;
		case 0x00ac:
			printf("Total Number of Erase Fails         : %"PRIu64"\n",
				le64_to_cpu(smart->erase_fail_cnt.raw1));
			printf("Erase fails since Power Cycle       : %"PRIu64"\n",
				le64_to_cpu(smart->erase_fail_cnt.raw2));
			break;
		case 0x00b1:
			printf("Life remaining percent              : %"PRIu64"\n",
				le64_to_cpu(smart->drive_life_remain_percent.raw1));
			printf("PE Cycles most                      : %"PRIu32"\n",
				le32_to_cpu(smart->drive_life_remain_percent.split_raw2.upper));
			printf("PE Cycles least                     : %"PRIu32"\n",
				le32_to_cpu(smart->drive_life_remain_percent.split_raw2.lower));
			break;
		case 0x00b8:
			printf("Total number of IOEDC               : %"PRIu64"\n",
				le64_to_cpu(smart->io_err_det_code_events.raw1));
			break;
		case 0x00bb:
			printf("Total number of UC Errors           : %"PRIu64"\n",
				le64_to_cpu(smart->reported_uc_errs.raw1));
			break;
		case 0x00be:
			printf("Current Temperature (in C)          : %"PRIu64"\n",
				le64_to_cpu(smart->drive_temperature.raw1));
			printf("Highest Temperature since Power ON  : %"PRIu32"\n",
				le32_to_cpu(smart->drive_temperature.split_raw2.upper));
			printf("Lowest Temperature since Power ON   : %"PRIu32"\n",
				le32_to_cpu(smart->drive_temperature.split_raw2.lower));
			break;
		case 0x00bf:
			printf("Percentage throttled                : %"PRIu64"\n",
				le64_to_cpu(smart->thermal_throt.raw1));
			printf("Thermal throttling starts           : %"PRIu32"\n",
				le32_to_cpu(smart->thermal_throt.split_raw2.upper));
			printf("Thermal throttling stops            : %"PRIu32"\n",
				le32_to_cpu(smart->thermal_throt.split_raw2.lower));
			break;
		case 0x00c2:
			printf("PON Time in mins Highest Temperature: %"PRIu32"\n",
				le32_to_cpu(smart->drive_life_temp.split_raw1.upper));
			printf("PON Time in mins Lowest Temperature : %"PRIu32"\n",
				le32_to_cpu(smart->drive_life_temp.split_raw1.lower));
			printf("Highest Lifetime Temperature (in C) : %"PRIu32"\n",
				le32_to_cpu(smart->drive_life_temp.split_raw2.upper));
			printf("Lowest Lifetime Temperature (in C)  : %"PRIu32"\n",
				le32_to_cpu(smart->drive_life_temp.split_raw2.lower));
			break;
		case 0x00c3:
			printf("Internal RAID Correctable Error     : %"PRIu64"\n",
				le64_to_cpu(smart->int_raid_correct_err_cnt.raw1));
			break;
		case 0x00e7:
			printf("Life used in percentage             : %"PRIu64"\n",
				le64_to_cpu(smart->ssd_life_used.raw1));
			printf("Average PE Cycles of Flash          : %"PRIu64"\n",
				le64_to_cpu(smart->ssd_life_used.raw2));
			break;
		case 0x00e8:
			printf("Accurate Life used in percentage    : %"PRIu64".%"PRIu64"\n",
				le64_to_cpu(smart->ssd_life_used_accurate.raw1)/100,
				le64_to_cpu(smart->ssd_life_used_accurate.raw1)%100);
			break;
		case 0x00e9:
			printf("Lifetime Writes to flash in MB      : %"PRIu64"\n",
				le64_to_cpu(smart->lifetime_wr_to_flash_mb.raw1));
			break;
		case 0x00ea:
			printf("Lifetime Read from flash in MB      : %"PRIu64"\n",
				le64_to_cpu(smart->lifetime_rd_from_flash_mb.raw1));
			break;
		case 0x00f1:
			printf("Lifetime Writes from Host in MB     : %"PRIu64"\n",
				le64_to_cpu(smart->lifetime_wr_from_host_mb.raw1));
			break;
		case 0x00f2:
			printf("Lifetime Read to Host in MB         : %"PRIu64"\n",
				le64_to_cpu(smart->lifetime_rd_to_host_mb.raw1));
			break;
		case 0x00f3:
			printf("Vol. Memory Backup Failures         : %"PRIu64"\n",
				le64_to_cpu(smart->vol_mem_backup_fail.raw1));
			break;
		case 0x00f4:
			printf("Security Wear Indicator             : %"PRIu64"\n",
				le64_to_cpu(smart->security_wear_indicator.raw1));
			break;
		case 0x00f5:
			printf("PCIe Received Errors                : %"PRIu32"\n",
				le32_to_cpu(smart->device_pcie_received_errors.split_raw1.upper));
			printf("PCIe Received Bad TLP               : %"PRIu32"\n",
				le32_to_cpu(smart->device_pcie_received_errors.split_raw1.lower));
			printf("PCIe Received Bad DLLP              : %"PRIu32"\n",
				le32_to_cpu(smart->device_pcie_received_errors.split_raw2.upper));
			printf("PCIe Recd Transitions to Recoveries : %"PRIu32"\n",
				le32_to_cpu(smart->device_pcie_received_errors.split_raw2.lower));
		default:
			break;
		}
	}
}

static int get_ibm_addi_smart_log(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Get IBM specific additional smart log and show it.";
	const char *raw = "Dump output in binary format";

	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	struct nvme_ibm_additional_smart_log smart_log;
	int err;

	struct config {
		bool  raw_binary;
	};

	struct config cfg = {
		.raw_binary = 0,
	};

	NVME_ARGS(opts,
		OPT_FLAG("raw-binary",   'b', &cfg.raw_binary,   raw));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = nvme_get_log_simple(hdl, 0xf0, &smart_log, sizeof(smart_log));

	if (!err) {
		if (!cfg.raw_binary)
			show_ibm_smart_log(&smart_log,
				nvme_transport_handle_get_name(hdl));
		else
			d_raw((unsigned char *)&smart_log, sizeof(smart_log));
	} else if (err > 0)
		nvme_show_status(err);
	else
		nvme_show_error("ibm additional smart log: %s\n", nvme_strerror(errno));

	return err;
}

#pragma pack(push, 1)
struct nvme_ibm_vpd_log {
	char version[4];
	char description[40];
	char masterpn[12];
	char ec[10];
	char fru[12];
	char finalasm[12];
	char fc[4];
	char ccin[4];
	char ibm11s[8];
	char ssid[8];
	char endurance[4];
	char capacity[10];
	char warranty[12];
	char encryption[1];
	char rctt[2];
	char loadid[8];
	char mfgloc[3];
	char ffc[5];
	char iotimeout[2];
	char formattimeout[4];
	char ioqs[4];
	char mediatype[2];
	char mfgsn[20];
	char firmware[8];
	char pad[4];
};
#pragma pack(pop)

#define MEDIATYPE   3
static void show_ibm_vpd_log(struct nvme_ibm_vpd_log *vpd, const char *devname)
{
	struct nvme_ibm_vpd_log vpdlog;
	char *mediatype[MEDIATYPE][2] = {
		{ "00", "NAND TLC" },
		{ "01", "3DXP" },
		{ "02", "LL NAND" }
	};

	printf("IBM VPD for NVME device:%s\n", devname);
	printf("VPD Log Page Version		: %.*s\n", (int)sizeof(vpdlog.version),
			vpd->version);
	printf("Description or ID		: %.*s\n", (int)sizeof(vpdlog.description),
			vpd->description);
	printf("Master Part Number		: %.*s\n", (int)sizeof(vpdlog.masterpn),
			vpd->masterpn);
	printf("EC Level			: %.*s\n", (int)sizeof(vpdlog.ec), vpd->ec);
	printf("FRU Part Number			: %.*s\n", (int)sizeof(vpdlog.fru), vpd->fru);
	printf("Final Assembly PN		: %.*s\n", (int)sizeof(vpdlog.finalasm),
		vpd->finalasm);
	printf("Feature Code			: %.*s\n", (int)sizeof(vpdlog.fc), vpd->fc);
	printf("CCIN				: %.*s\n", (int)sizeof(vpdlog.ccin), vpd->ccin);
	printf("11S Serial Number		: 11S%.*sY%.*s%.*s\n", 7, vpd->masterpn,
			(int)sizeof(vpdlog.mfgloc), vpd->mfgloc, (int)sizeof(vpdlog.ibm11s),
			vpd->ibm11s);
	printf("PCI SSID			: %.*s\n", (int)sizeof(vpdlog.ssid), vpd->ssid);
	printf("Endurance (DWPD)		: %.*s\n", (int)sizeof(vpdlog.endurance),
			vpd->endurance);
	printf("Capacity (GB)			: %.*s\n", (int)sizeof(vpdlog.capacity),
			vpd->capacity);
	printf("Warranty (Peta Bytes Written)	: %.*s\n", (int)sizeof(vpdlog.warranty),
			vpd->warranty);
	printf("Encryption (0=not supported)	: %.*s\n", (int)sizeof(vpdlog.encryption),
			vpd->encryption);
	printf("RCTT				: %.*s\n", (int)sizeof(vpdlog.rctt), vpd->rctt);
	printf("Load ID				: %.*s\n", (int)sizeof(vpdlog.loadid), vpd->loadid);
	printf("MFG Location			: %.*s\n", (int)sizeof(vpdlog.mfgloc),
			vpd->mfgloc);
	printf("FFC				: %.*s\n", (int)sizeof(vpdlog.ffc), vpd->ffc);
	printf("IO Timeout in Seconds		: 0x%.*s\n", (int)sizeof(vpdlog.iotimeout),
			vpd->iotimeout);
	printf("Format Timeout in Seconds	: 0x%.*s\n", (int)sizeof(vpdlog.formattimeout),
			vpd->formattimeout);
	printf("Optimal Number of IO Queues	: 0x%.*s\n", (int)sizeof(vpdlog.ioqs),
			vpd->ioqs);

	for (int i = 0; i < MEDIATYPE; i++) {
		if (!strncmp(mediatype[i][0], vpd->mediatype, (int)sizeof(vpdlog.mediatype)))
			printf("Media Type			: %.*s (%.*s)\n",
				(int)sizeof(mediatype[i][1]), mediatype[i][1],
				(int)sizeof(vpdlog.mediatype), vpd->mediatype);
	}

	printf("Manufacturer Serial Number	: %.*s\n", (int) sizeof(vpdlog.mfgsn), vpd->mfgsn);
	printf("Firmware version		: %.*s\n", (int) sizeof(vpdlog.firmware),
			vpd->firmware);
}

static int get_ibm_vpd_log(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	struct nvme_ibm_vpd_log vpd_log;
	int err;

	const char *desc = "Get IBM vendor specific VPD log";
	const char *raw = "dump output in binary format";

	struct config {
		int   raw_binary;
	};

	struct config cfg = {
		.raw_binary = 0,
	};

	NVME_ARGS(opts,
		OPT_FLAG("raw-binary",   'b', &cfg.raw_binary,   raw));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err < 0)
		return err;

	bzero(&vpd_log, sizeof(vpd_log));
	err = nvme_get_log_simple(hdl, 0xf1, &vpd_log, sizeof(vpd_log));

	if (!err) {
		if (!cfg.raw_binary)
			show_ibm_vpd_log(&vpd_log,
				nvme_transport_handle_get_name(hdl));
		else
			d_raw((unsigned char *)&vpd_log, sizeof(vpd_log));
	} else if (err > 0)
		nvme_show_status(err);
	else
		nvme_show_error("ibm vpd log: %s\n", nvme_strerror(errno));

	return err;
}

#define NVME_VENDOR_SPECIFIC_EVENT	0xde
#define NVME_IBM_CHG_DEF    0x1
#define NVME_IBM_RPT_ERR    0x2

struct ibm_change_def_event {
	__le64	pom;
	__u8	vs1;
	__u8	vs2;
	__u8	dp;
};

struct ibm_reported_err_event {
	__le64	pom;
	__u8	temp;
	__u8	retry_cnt;
	__u8	sc;
	__u8	sct;
	__le64	cmd_specific_info;
	__u8	*cmd;

};

/* persistent event type deh */
struct nvme_pel_ibm_specific_event {
	__le16	vsecode;
	__u8	vsetype;
	__u8	uuid;
	__le16	vsedl;
	__u8	*vse_data;
};

static const char *raw_use = "use binary output";

void nvme_show_ibm_persistent_event_log(void *pevent_log_info,
		__u8 action, __u32 size, const char *devname,
		enum nvme_print_flags flags)
{
	__u32 offset;
	struct nvme_pel_ibm_specific_event *vendor_speci_event;
	struct nvme_persistent_event_log *pevent_log_head;
	struct nvme_persistent_event_entry *pevent_entry_head;
	int human = flags & VERBOSE;
	bool ibm_event = false;
	int i = 0;

	if (flags & BINARY)
		return d_raw((unsigned char *)pevent_log_info, size);

	offset = sizeof(*pevent_log_head);

	printf("Persistent Event Log for device: %s\n", devname);
	printf("Action for Persistent Event Log: %u\n", action);

	if (size >= offset) {
		pevent_log_head = pevent_log_info;
		nvme_show_pel_header(pevent_log_head, human);
	} else {
		printf("No log data can be shown with this log length\n");
		return;
	}

	printf("\n");
	printf(" i=%d tnev=%d\n", i, le32_to_cpu(pevent_log_head->tnev));
	for (i = 0; i < le32_to_cpu(pevent_log_head->tnev); i++) {
		if (offset + sizeof(*pevent_entry_head) >= size)
			break;

		pevent_entry_head = pevent_log_info + offset;
		if ((offset + pevent_entry_head->ehl + 3 +
			le16_to_cpu(pevent_entry_head->el)) >= size)
			break;

		offset += pevent_entry_head->ehl + 3;

		switch (pevent_entry_head->etype) {
		case NVME_VENDOR_SPECIFIC_EVENT:
			printf("\nPersistent Event Entries:\n");
			printf("Event Number: %u\n", i);
			printf("Event Type Field: 0x%X\n", pevent_entry_head->etype);
			printf("Event Type Revision: 0x%X\n", pevent_entry_head->etype_rev);

			vendor_speci_event = pevent_log_info + offset;

			printf("Vendor Specific Event Code: 0x%X\n",
				le16_to_cpu(vendor_speci_event->vsecode));
			printf("Vendor Specific Event Data Type: 0x%X\n",
				vendor_speci_event->vsetype);
			printf("UUID Index: %u\n", vendor_speci_event->uuid);
			printf("VSEDL: %u\n", le16_to_cpu(vendor_speci_event->vsedl));

			if (le16_to_cpu(vendor_speci_event->vsecode) == NVME_IBM_CHG_DEF) {
				struct ibm_change_def_event *change_def;

				change_def = pevent_log_info + offset + 6;
				printf("POM: %"PRIu64"\n", le64_to_cpu(change_def->pom));
				printf("VS1: %u\n", change_def->vs1);
				printf("VS2: %u\n", change_def->vs2);
				printf("DP : %u\n", change_def->dp);
			}

			if (le16_to_cpu(vendor_speci_event->vsecode) == NVME_IBM_RPT_ERR) {
				struct ibm_reported_err_event *report_err;

				report_err = pevent_log_info + offset + 6;
				printf("POM: %"PRIu64"\n", le64_to_cpu(report_err->pom));
				printf("TEMP: %u\n", report_err->temp);
				printf("Retry Count: %u\n", report_err->retry_cnt);
				printf("SC : %u\n", report_err->sc);
				printf("SCT : %u\n", report_err->sct);
				printf("CMD Specific Info: %"PRIu64"\n",
						le64_to_cpu(report_err->cmd_specific_info));
			}
			ibm_event = true;
			printf("\n");
			break;
		default:
			break;
		}
		offset += le16_to_cpu(pevent_entry_head->el);
	}

	if (!ibm_event)
		printf("NO IBM specific persistent events found!\n");
}

static int get_ibm_persistent_event_log(int argc, char **argv,
		struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Retrieve Persistent Event log info for "
		"the given device in either decoded format(default), json or binary.";
	const char *action = "action the controller shall take during "
		"processing this persistent log page command.";
	const char *log_len = "number of bytes to retrieve";
	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	struct nvme_persistent_event_log pevent_log;
	void *pevent_log_info = NULL;
	enum nvme_print_flags flags;
	__u32 log_length = 0;
	int err = 0;

	struct config {
		__u8	action;
		__u32	log_len;
		char	*output_format;
		bool	raw_binary;
	};

	struct config cfg = {
		.action		= 0xff,
		.log_len	= 0,
		.output_format	= "normal",
		.raw_binary	= false,
	};

	NVME_ARGS(opts,
		OPT_BYTE("action",       'a', &cfg.action,        action),
		OPT_UINT("log_len",	 'l', &cfg.log_len,	  log_len),
		OPT_FLAG("raw-binary",   'b', &cfg.raw_binary,    raw_use));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = flags = validate_output_format(cfg.output_format, &flags);
	if (flags < 0)
		return err;

	if (cfg.raw_binary)
		flags = BINARY;

	/* get persistent event log */
	err = nvme_get_log_persistent_event(hdl, NVME_PEVENT_LOG_RELEASE_CTX,
				&pevent_log, sizeof(pevent_log));

	if (err)
		return err;

	memset(&pevent_log, 0, sizeof(pevent_log));

	err = nvme_get_log_persistent_event(hdl, NVME_PEVENT_LOG_EST_CTX_AND_READ,
			&pevent_log, sizeof(pevent_log));
	if (err) {
		fprintf(stderr, "Setting persistent event log read ctx failed (ignored)!\n");
		return err;
	}

	log_length = le64_to_cpu(pevent_log.tll);
	pevent_log_info = nvme_alloc(log_length);
	if (!pevent_log_info) {
		perror("could not alloc buffer for persistent event log page (ignored)!\n");
		return err;
	}

	err = nvme_get_log_persistent_event(hdl, NVME_PEVENT_LOG_READ,
				pevent_log_info, log_length);
	if (!err) {
		nvme_show_ibm_persistent_event_log(pevent_log_info, cfg.action,
				log_length, nvme_transport_handle_get_name(hdl),
				flags);
	}

	return err;
}
