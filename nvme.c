/*
 * nvme.c -- NVM-Express command line utility.
 *
 * Copyright (c) 2014-2015, Intel Corporation.
 *
 * Written by Keith Busch <keith.busch@intel.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/**
 * This program uses NVMe IOCTLs to run native nvme commands to a device.
 */

#include <endian.h>
#include <errno.h>
#include <getopt.h>
#include <fcntl.h>
#include <inttypes.h>
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <math.h>
#ifdef LIBUDEV_EXISTS
#include <libudev.h>
#endif

#include <linux/fs.h>

#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>

#include "linux/nvme.h"
#include "src/argconfig.h"
#include "src/suffix.h"

#define min(x, y) (x) > (y) ? (y) : (x)

static int fd;
static struct stat nvme_stat;
static const char *devicename;

#define COMMAND_LIST \
	ENTRY(LIST, "list", "List all NVMe devices and namespaces on machine", list) \
	ENTRY(ID_CTRL, "id-ctrl", "Send NVMe Identify Controller", id_ctrl) \
	ENTRY(ID_NS, "id-ns", "Send NVMe Identify Namespace, display structure", id_ns) \
	ENTRY(LIST_NS, "list-ns", "Send NVMe Identify List, display structure", list_ns) \
	ENTRY(CREATE_NS, "create-ns", "Creates a namespace with the provided parameters", create_ns) \
	ENTRY(DELETE_NS, "delete-ns", "Deletes a namespace from the controller", delete_ns) \
	ENTRY(ATTACH_NS, "attach-ns", "Attaches a namespace to requested controller(s)", attach_ns) \
	ENTRY(DETACH_NS, "detach-ns", "Detaches a namespace from requested controller(s)", detach_ns) \
	ENTRY(LIST_CTRL, "list-ctrl", "Send NVMe Identify Controller List, display structure", list_ctrl) \
	ENTRY(GET_NS_ID, "get-ns-id", "Retrieve the namespace ID of opened block device", get_ns_id) \
	ENTRY(GET_LOG, "get-log", "Generic NVMe get log, returns log in raw format", get_log) \
	ENTRY(GET_FW_LOG, "fw-log", "Retrieve FW Log, show it", get_fw_log) \
	ENTRY(GET_SMART_LOG, "smart-log", "Retrieve SMART Log, show it", get_smart_log) \
	ENTRY(GET_ADDITIONAL_SMART_LOG, "smart-log-add", "Retrieve additional SMART Log, show it", get_additional_smart_log) \
	ENTRY(GET_ERR_LOG, "error-log", "Retrieve Error Log, show it", get_error_log) \
	ENTRY(GET_FEATURE, "get-feature", "Get feature and show the resulting value", get_feature) \
	ENTRY(SET_FEATURE, "set-feature", "Set a feature and show the resulting value", set_feature) \
	ENTRY(FORMAT, "format", "Format namespace with new block format", format) \
	ENTRY(FW_ACTIVATE, "fw-activate", "Activate new firmware slot", fw_activate) \
	ENTRY(FW_DOWNLOAD, "fw-download", "Download new firmware", fw_download) \
	ENTRY(ADMIN_PASSTHRU, "admin-passthru", "Submit arbitrary admin command, return results", admin_passthru) \
	ENTRY(IO_PASSTHRU, "io-passthru", "Submit an arbitrary IO command, return results", io_passthru) \
	ENTRY(SECURITY_SEND, "security-send", "Submit a Security Send command, return results", sec_send) \
	ENTRY(SECURITY_RECV, "security-recv", "Submit a Security Receive command, return results", sec_recv) \
	ENTRY(RESV_ACQUIRE, "resv-acquire", "Submit a Reservation Acquire, return results", resv_acquire) \
	ENTRY(RESV_REGISTER, "resv-register", "Submit a Reservation Register, return results", resv_register) \
	ENTRY(RESV_RELEASE, "resv-release", "Submit a Reservation Release, return results", resv_release) \
	ENTRY(RESV_REPORT, "resv-report", "Submit a Reservation Report, return results", resv_report) \
	ENTRY(FLUSH, "flush", "Submit a Flush command, return results", flush) \
	ENTRY(COMPARE, "compare", "Submit a Comapre command, return results", compare) \
	ENTRY(READ_CMD, "read", "Submit a read command, return results", read_cmd) \
	ENTRY(WRITE_CMD, "write", "Submit a write command, return results", write_cmd) \
	ENTRY(REGISTERS, "show-regs", "Shows the controller registers. Requires admin character device", show_registers) \
	ENTRY(HELP, "help", "Display this help", help)

#define ENTRY(i, n, h, f) \
static int f(int argc, char **argv);
COMMAND_LIST
#undef ENTRY

enum {
	#define ENTRY(i, n, h, f) i,
	COMMAND_LIST
	#undef ENTRY
	NUM_COMMANDS
};

struct command {
	char *name;
	char *help;
	char *path;
	char *man;
	int (*fn)(int argc, char **argv);
};

struct command commands[] = {
	#define ENTRY(i, n, h, f)\
	{ \
		.name = n, \
		.help = h, \
		.fn = f, \
		.path = "Documentation/nvme-"n".1", \
		.man = "nvme-"n, \
	},
	COMMAND_LIST
	#undef ENTRY
};

static unsigned long long elapsed_utime(struct timeval start_time,
					struct timeval end_time)
{
	unsigned long long ret = (end_time.tv_sec - start_time.tv_sec)*1000000 +
		(end_time.tv_usec - start_time.tv_usec);
	return ret;
}

static void open_dev(const char *dev)
{
	int err;
	devicename = dev;
	fd = open(dev, O_RDONLY);
	if (fd < 0)
		goto perror;

	err = fstat(fd, &nvme_stat);
	if (err < 0)
		goto perror;
	if (!S_ISCHR(nvme_stat.st_mode) && !S_ISBLK(nvme_stat.st_mode)) {
		fprintf(stderr, "%s is not a block or character device\n", dev);
		exit(ENODEV);
	}
	return;
 perror:
	perror(dev);
	exit(errno);
}

static void get_dev(int optind, int argc, char **argv)
{
	if (optind >= argc) {
		errno = EINVAL;
		perror(argv[0]);
		exit(errno);
	}
	open_dev((const char *)argv[optind]);
}

static void show_error_log(struct nvme_error_log_page *err_log, int entries)
{
	int i;

	printf("Error Log Entries for device:%s entries:%d\n", devicename,
								entries);
	printf(".................\n");
	for (i = 0; i < entries; i++) {
		printf(" Entry[%2d]   \n", i);
		printf(".................\n");
		printf("error_count  : %"PRIu64"\n", (uint64_t)le64toh(err_log[i].error_count));
		printf("sqid         : %d\n", err_log[i].sqid);
		printf("cmdid        : %#x\n", err_log[i].cmdid);
		printf("status_field : %#x\n", err_log[i].status_field);
		printf("parm_err_loc : %#x\n", err_log[i].parm_error_location);
		printf("lba          : %#"PRIx64"\n",(uint64_t)le64toh(err_log[i].lba));
		printf("nsid         : %d\n", err_log[i].nsid);
		printf("vs           : %d\n", err_log[i].vs);
		printf(".................\n");
	}
}

static void show_nvme_resv_report(struct nvme_reservation_status *status)
{
	int i, regctl;

	regctl = status->regctl[0] | (status->regctl[1] << 8);

	printf("\nNVME Reservation status:\n\n");
	printf("gen       : %d\n", le32toh(status->gen));
	printf("regctl    : %d\n", regctl);
	printf("rtype     : %d\n", status->rtype);
	printf("ptpls     : %d\n", status->ptpls);

	for (i = 0; i < regctl; i++) {
		printf("regctl[%d] :\n", i);
		printf("  cntlid  : %x\n", le16toh(status->regctl_ds[i].cntlid));
		printf("  rcsts   : %x\n", status->regctl_ds[i].rcsts);
		printf("  hostid  : %"PRIx64"\n", (uint64_t)le64toh(status->regctl_ds[i].hostid));
		printf("  rkey    : %"PRIx64"\n", (uint64_t)le64toh(status->regctl_ds[i].rkey));
	}
	printf("\n");
}

static char *fw_to_string(__u64 fw)
{
	static char ret[9];
	char *c = (char *)&fw;
	int i;

	for (i = 0; i < 8; i++)
		ret[i] = c[i] >= '!' && c[i] <= '~' ? c[i] : '.';
	ret[i] = '\0';
	return ret;
}

static void show_fw_log(struct nvme_firmware_log_page *fw_log)
{
	int i;

	printf("Firmware Log for device:%s\n", devicename);
	printf("afi  : %#x\n", fw_log->afi);
	for (i = 0; i < 7; i++)
		if (fw_log->frs[i])
			printf("frs%d : %#016"PRIx64" (%s)\n", i + 1, (uint64_t)fw_log->frs[i],
						fw_to_string(fw_log->frs[i]));
}

static long double int128_to_double(__u8 *data)
{
	int i;
	long double result = 0;

	for (i = 0; i < 16; i++) {
		result *= 256;
		result += data[15 - i];
	}
	return result;
}

static unsigned long int48_to_long(__u8 *data)
{
	int i;
	long result = 0;

	for (i = 0; i < 6; i++) {
		result *= 256;
		result += data[5 - i];
	}
	return result;
}

static void show_smart_log(struct nvme_smart_log *smart, unsigned int nsid)
{
	/* convert temperature from Kelvin to Celsius */
	unsigned int temperature = ((smart->temperature[1] << 8) |
		smart->temperature[0]) - 273;

	printf("Smart Log for NVME device:%s namespace-id:%x\n", devicename, nsid);
	printf("critical_warning          : %#x\n", smart->critical_warning);
	printf("temperature               : %u C\n", temperature);
	printf("available_spare           : %u%%\n", smart->avail_spare);
	printf("available_spare_threshold : %u%%\n", smart->spare_thresh);
	printf("percentage_used           : %u%%\n", smart->percent_used);
	printf("data_units_read           : %'.0Lf\n",
		int128_to_double(smart->data_units_read));
	printf("data_units_written        : %'.0Lf\n",
		int128_to_double(smart->data_units_written));
	printf("host_read_commands        : %'.0Lf\n",
		int128_to_double(smart->host_reads));
	printf("host_write_commands       : %'.0Lf\n",
		int128_to_double(smart->host_writes));
	printf("controller_busy_time      : %'.0Lf\n",
		int128_to_double(smart->ctrl_busy_time));
	printf("power_cycles              : %'.0Lf\n",
		int128_to_double(smart->power_cycles));
	printf("power_on_hours            : %'.0Lf\n",
		int128_to_double(smart->power_on_hours));
	printf("unsafe_shutdowns          : %'.0Lf\n",
		int128_to_double(smart->unsafe_shutdowns));
	printf("media_errors              : %'.0Lf\n",
		int128_to_double(smart->media_errors));
	printf("num_err_log_entries       : %'.0Lf\n",
		int128_to_double(smart->num_err_log_entries));
}

static void show_additional_smart_log(struct nvme_additional_smart_log *smart, unsigned int nsid)
{
	printf("Additional Smart Log for NVME device:%s namespace-id:%x\n", devicename, nsid);
	printf("key                               normalized raw\n");
	printf("program_fail_count              : %3d%%       %lu\n",
		smart->program_fail_cnt.norm,
		int48_to_long(smart->program_fail_cnt.raw));
	printf("erase_fail_count                : %3d%%       %lu\n",
		smart->erase_fail_cnt.norm,
		int48_to_long(smart->erase_fail_cnt.raw));
	printf("wear_leveling                   : %3d%%       min: %u, max: %u, avg: %u\n",
		smart->wear_leveling_cnt.norm,
		smart->wear_leveling_cnt.wear_level.min,
		smart->wear_leveling_cnt.wear_level.max,
		smart->wear_leveling_cnt.wear_level.avg);
	printf("end_to_end_error_detection_count: %3d%%       %lu\n",
		smart->e2e_err_cnt.norm,
		int48_to_long(smart->e2e_err_cnt.raw));
	printf("crc_error_count                 : %3d%%       %lu\n",
		smart->crc_err_cnt.norm,
		int48_to_long(smart->crc_err_cnt.raw));
	printf("timed_workload_media_wear       : %3d%%       %.3f%%\n",
		smart->timed_workload_media_wear.norm,
		((float)int48_to_long(smart->timed_workload_media_wear.raw)) / 1024);
	printf("timed_workload_host_reads       : %3d%%       %lu%%\n",
		smart->timed_workload_host_reads.norm,
		int48_to_long(smart->timed_workload_host_reads.raw));
	printf("timed_workload_timer            : %3d%%       %lu min\n",
		smart->timed_workload_timer.norm,
		int48_to_long(smart->timed_workload_timer.raw));
	printf("thermal_throttle_status         : %3d%%       %u%%, cnt: %u\n",
		smart->thermal_throttle_status.norm,
		smart->thermal_throttle_status.thermal_throttle.pct,
		smart->thermal_throttle_status.thermal_throttle.count);
	printf("retry_buffer_overflow_count     : %3d%%       %lu\n",
		smart->retry_buffer_overflow_cnt.norm,
		int48_to_long(smart->retry_buffer_overflow_cnt.raw));
	printf("pll_lock_loss_count             : %3d%%       %lu\n",
		smart->pll_lock_loss_cnt.norm,
		int48_to_long(smart->pll_lock_loss_cnt.raw));
	printf("nand_bytes_written              : %3d%%       sectors: %lu\n",
		smart->nand_bytes_written.norm,
		int48_to_long(smart->nand_bytes_written.raw));
	printf("host_bytes_written              : %3d%%       sectors: %lu\n",
		smart->host_bytes_written.norm,
		int48_to_long(smart->host_bytes_written.raw));
}

char* nvme_feature_to_string(int feature)
{
	switch (feature)
	{
	case NVME_FEAT_ARBITRATION:	return "Arbitration";
	case NVME_FEAT_POWER_MGMT:	return "Power Management";
	case NVME_FEAT_LBA_RANGE:	return "LBA Range Type";
	case NVME_FEAT_TEMP_THRESH:	return "Temperature Threshold";
	case NVME_FEAT_ERR_RECOVERY:	return "Error Recovery";
	case NVME_FEAT_VOLATILE_WC:	return "Volatile Write Cache";
	case NVME_FEAT_NUM_QUEUES:	return "Number of Queues";
	case NVME_FEAT_IRQ_COALESCE:	return "Interrupt Coalescing";
	case NVME_FEAT_IRQ_CONFIG: 	return "Interrupt Vector Configuration";
	case NVME_FEAT_WRITE_ATOMIC:	return "Write Atomicity Normal";
	case NVME_FEAT_ASYNC_EVENT:	return "Async Event Configuration";
	case NVME_FEAT_AUTO_PST:	return "Autonomous Power State Transition";
	case NVME_FEAT_HOST_MEM_BUF:	return "Host Memory Buffer";
	case NVME_FEAT_SW_PROGRESS:	return "Software Progress";
	case NVME_FEAT_HOST_ID:	return "Host Identifier";
	case NVME_FEAT_RESV_MASK:	return "Reservation Notification Mask";
	case NVME_FEAT_RESV_PERSIST:	return "Reservation Persistence";
	default:			return "Unknown";
	}
}

char* nvme_select_to_string(int sel)
{
	switch (sel) 
	{ 
	case 0:  return "Current"; 
	case 1:  return "Default"; 
	case 2:  return "Saved"; 
	case 3:  return "Supported capabilities"; 
	default: return "Reserved"; 
	}
}


static const char *nvme_status_to_string(__u32 status)
{
	switch (status & 0x3ff) {
	case NVME_SC_SUCCESS:		return "SUCCESS";
	case NVME_SC_INVALID_OPCODE:	return "INVALID_OPCODE";
	case NVME_SC_INVALID_FIELD:	return "INVALID_FIELD";
	case NVME_SC_CMDID_CONFLICT:	return "CMDID_CONFLICT";
	case NVME_SC_DATA_XFER_ERROR:	return "DATA_XFER_ERROR";
	case NVME_SC_POWER_LOSS:	return "POWER_LOSS";
	case NVME_SC_INTERNAL:		return "INTERNAL";
	case NVME_SC_ABORT_REQ:		return "ABORT_REQ";
	case NVME_SC_ABORT_QUEUE:	return "ABORT_QUEUE";
	case NVME_SC_FUSED_FAIL:	return "FUSED_FAIL";
	case NVME_SC_FUSED_MISSING:	return "FUSED_MISSING";
	case NVME_SC_INVALID_NS:	return "INVALID_NS";
	case NVME_SC_CMD_SEQ_ERROR:	return "CMD_SEQ_ERROR";
	case NVME_SC_LBA_RANGE:		return "LBA_RANGE";
	case NVME_SC_CAP_EXCEEDED:	return "CAP_EXCEEDED";
	case NVME_SC_NS_NOT_READY:	return "NS_NOT_READY";
	case NVME_SC_CQ_INVALID:	return "CQ_INVALID";
	case NVME_SC_QID_INVALID:	return "QID_INVALID";
	case NVME_SC_QUEUE_SIZE:	return "QUEUE_SIZE";
	case NVME_SC_ABORT_LIMIT:	return "ABORT_LIMIT";
	case NVME_SC_ABORT_MISSING:	return "ABORT_MISSING";
	case NVME_SC_ASYNC_LIMIT:	return "ASYNC_LIMIT";
	case NVME_SC_FIRMWARE_SLOT:	return "FIRMWARE_SLOT";
	case NVME_SC_FIRMWARE_IMAGE:	return "FIRMWARE_IMAGE";
	case NVME_SC_INVALID_VECTOR:	return "INVALID_VECTOR";
	case NVME_SC_INVALID_LOG_PAGE:	return "INVALID_LOG_PAGE";
	case NVME_SC_INVALID_FORMAT:	return "INVALID_FORMAT";
	case NVME_SC_BAD_ATTRIBUTES:	return "BAD_ATTRIBUTES";
	case NVME_SC_WRITE_FAULT:	return "WRITE_FAULT";
	case NVME_SC_READ_ERROR:	return "READ_ERROR";
	case NVME_SC_GUARD_CHECK:	return "GUARD_CHECK";
	case NVME_SC_APPTAG_CHECK:	return "APPTAG_CHECK";
	case NVME_SC_REFTAG_CHECK:	return "REFTAG_CHECK";
	case NVME_SC_COMPARE_FAILED:	return "COMPARE_FAILED";
	case NVME_SC_ACCESS_DENIED:	return "ACCESS_DENIED";
	default:			return "Unknown";
	}
}

static int identify(int namespace, void *ptr, __u32 cns)
{
	struct nvme_admin_cmd cmd;

	memset(&cmd, 0, sizeof(cmd));
	cmd.opcode = nvme_admin_identify;
	cmd.nsid = namespace;
	cmd.addr = (unsigned long)ptr;
	cmd.data_len = 4096;
	cmd.cdw10 = cns;
	return ioctl(fd, NVME_IOCTL_ADMIN_CMD, &cmd);
}

static int nvme_get_log(void *log_addr, __u32 data_len, __u32 dw10, __u32 nsid)
{
	struct nvme_admin_cmd cmd;

	memset(&cmd, 0, sizeof(cmd));
	cmd.opcode = nvme_admin_get_log_page;
	cmd.addr = (unsigned long)log_addr;
	cmd.data_len = data_len;
	cmd.cdw10 = dw10;
	cmd.nsid = nsid;
	return ioctl(fd, NVME_IOCTL_ADMIN_CMD, &cmd);
}

static void d_raw(unsigned char *buf, unsigned len)
{
	unsigned i;
	for (i = 0; i < len; i++)
		putchar(*(buf+i));
}

static void d(unsigned char *buf, int len, int width, int group)
{
	int i, offset = 0, line_done = 0;
	char ascii[width + 1];

	printf("     ");
	for (i = 0; i <= 15; i++)
		printf("%3x", i);
	for (i = 0; i < len; i++) {
		line_done = 0;
		if (i % width == 0)
			fprintf(stdout, "\n%04x:", offset);
		if (i % group == 0)
			fprintf(stdout, " %02x", buf[i]);
		else
			fprintf(stdout, "%02x", buf[i]);
		ascii[i % width] = (buf[i] >= '!' && buf[i] <= '~') ? buf[i] : '.';
		if (((i + 1) % width) == 0) {
			ascii[i % width + 1] = '\0';
			fprintf(stdout, " \"%.*s\"", width, ascii);
			offset += width;
			line_done = 1;
		}
	}
	if (!line_done) {
		unsigned b = width - (i % width);
		ascii[i % width + 1] = '\0';
		fprintf(stdout, " %*s \"%.*s\"",
				2 * b + b / group + (b % group ? 1 : 0), "",
				width, ascii);
	}
	fprintf(stdout, "\n");
}

static void show_nvme_id_ctrl_cmic(__u8 cmic)
{
	__u8 rsvd = (cmic & 0xF8) >> 3;
	__u8 sriov = (cmic & 0x4) >> 2;
	__u8 mctl = (cmic & 0x2) >> 1;
	__u8 mp = cmic & 0x1;
	if (rsvd)
		printf("  [7:3] : %#x\tReserved\n", rsvd);
	printf("  [2:2] : %#x\t%s\n", sriov, sriov ? "SR-IOV" : "PCI");
	printf("  [1:1] : %#x\t%s Controller\n",
		mctl, mctl ? "Multi" : "Single");
	printf("  [0:0] : %#x\t%s Port\n", mp, mp ? "Multi" : "Single");
	printf("\n");
}

static void show_nvme_id_ctrl_oaes(__le32 oaes)
{
	__le32 rsvd0 = (oaes & 0xFFFFFE00) >> 9;
	__le32 nace = (oaes & 0x100) >> 8;
	__le32 rsvd1 = oaes & 0xFF;
	if (rsvd0)
		printf(" [31:9] : %#x\tReserved\n", rsvd0);
	printf("  [8:8] : %#x\tNamespace Attribute Changed Event %sSupported\n",
		nace, nace ? "" : "Not ");
	if (rsvd1)
		printf("  [7:0] : %#x\tReserved\n", rsvd1);
	printf("\n");
}

static void show_nvme_id_ctrl_oacs(__le16 oacs)
{
	__le16 rsvd = (oacs & 0xFFF0) >> 4;
	__le16 nsm = (oacs & 0x8) >> 3;
	__le16 fwc = (oacs & 0x4) >> 2;
	__le16 fmt = (oacs & 0x2) >> 1;
	__le16 sec = oacs & 0x1;
	if (rsvd)
		printf(" [15:4] : %#x\tReserved\n", rsvd);
	printf("  [3:3] : %#x\tNS Management and Attachment %sSupported\n",
		nsm, nsm ? "" : "Not ");
	printf("  [2:2] : %#x\tFW Commit and Download %sSupported\n",
		fwc, fwc ? "" : "Not ");
	printf("  [1:1] : %#x\tFormat NVM %sSupported\n",
		fmt, fmt ? "" : "Not ");
	printf("  [0:0] : %#x\tSec. Send and Receive %sSupported\n",
		sec, sec ? "" : "Not ");
	printf("\n");
}

static void show_nvme_id_ctrl_frmw(__u8 frmw)
{
	__u8 rsvd = (frmw & 0xE0) >> 5;
	__u8 fawr = (frmw & 0x10) >> 4;
	__u8 nfws = (frmw & 0xE) >> 1;
	__u8 s1ro = frmw & 0x1;
	if (rsvd)
		printf("  [7:5] : %#x\tReserved\n", rsvd);
	printf("  [4:4] : %#x\tFirmware Activate Without Reset %sSupported\n",
		fawr, fawr ? "" : "Not ");
	printf("  [3:1] : %#x\tNumber of Firmware Slots\n", nfws);
	printf("  [0:0] : %#x\tFirmware Slot 1 Read%s\n",
		s1ro, s1ro ? "-Only" : "/Write");
	printf("\n");
}

static void show_nvme_id_ctrl_lpa(__u8 lpa)
{
	__u8 rsvd = (lpa & 0xFC) >> 2;
	__u8 celp = (lpa & 0x2) >> 1;
	__u8 smlp = lpa & 0x1;
	if (rsvd)
		printf("  [7:2] : %#x\tReserved\n", rsvd);
	printf("  [1:1] : %#x\tCommand Effects Log Page %sSupported\n",
		celp, celp ? "" : "Not ");
	printf("  [0:0] : %#x\tSMART/Health Log Page per NS %sSupported\n",
		smlp, smlp ? "" : "Not ");
	printf("\n");
}

static void show_nvme_id_ctrl_avscc(__u8 avscc)
{
	__u8 rsvd = (avscc & 0xFE) >> 1;
	__u8 fmt = avscc & 0x1;
	if (rsvd)
		printf("  [7:1] : %#x\tReserved\n", rsvd);
	printf("  [0:0] : %#x\tAdmin Vendor Specific Commands uses %s Format\n",
		fmt, fmt ? "NVMe" : "Vendor Specific");
	printf("\n");
}

static void show_nvme_id_ctrl_apsta(__u8 apsta)
{
	__u8 rsvd = (apsta & 0xFE) >> 1;
	__u8 apst = apsta & 0x1;
	if (rsvd)
		printf("  [7:1] : %#x\tReserved\n", rsvd);
	printf("  [0:0] : %#x\tAutonomous Power State Transitions %sSupported\n",
		apst, apst ? "" : "Not ");
	printf("\n");
}

static void show_nvme_id_ctrl_rpmbs(__le32 rpmbs)
{
	__le32 asz = (rpmbs & 0xFF000000) >> 24;
	__le32 tsz = (rpmbs & 0xFF0000) >> 16;
	__le32 rsvd = (rpmbs & 0xFFC0) >> 6;
	__le32 auth = (rpmbs & 0x38) >> 3;
	__le32 rpmb = rpmbs & 0x3;
	printf(" [31:24]: %#x\tAccess Size\n", asz);
	printf(" [23:16]: %#x\tTotal Size\n", tsz);
	if (rsvd)
		printf(" [15:6] : %#x\tReserved\n", rsvd);
	printf("  [5:3] : %#x\tAuthentication Method\n", auth);
	printf("  [2:0] : %#x\tNumber of RPMB Units\n", rpmb);
	printf("\n");
}

static void show_nvme_id_ctrl_sqes(__u8 sqes)
{
	__u8 msqes = (sqes & 0xF0) >> 4;
	__u8 rsqes = sqes & 0xF;
	printf("  [7:4] : %#x\tMax SQ Entry Size (%d)\n", msqes, 1 << msqes);
	printf("  [3:0] : %#x\tMin SQ Entry Size (%d)\n", rsqes, 1 << rsqes);
	printf("\n");
}

static void show_nvme_id_ctrl_cqes(__u8 cqes)
{
	__u8 mcqes = (cqes & 0xF0) >> 4;
	__u8 rcqes = cqes & 0xF;
	printf("  [7:4] : %#x\tMax CQ Entry Size (%d)\n", mcqes, 1 << mcqes);
	printf("  [3:0] : %#x\tMin CQ Entry Size (%d)\n", rcqes, 1 << rcqes);
	printf("\n");
}

static void show_nvme_id_ctrl_oncs(__le16 oncs)
{
	__le16 rsvd = (oncs & 0xFFC0) >> 6;
	__le16 resv = (oncs & 0x20) >> 5;
	__le16 save = (oncs & 0x10) >> 4;
	__le16 wzro = (oncs & 0x8) >> 3;
	__le16 dsms = (oncs & 0x4) >> 2;
	__le16 wunc = (oncs & 0x2) >> 1;
	__le16 cmp = oncs & 0x1;
	if (rsvd)
		printf(" [15:6] : %#x\tReserved\n", rsvd);
	printf("  [5:5] : %#x\tReservations %sSupported\n",
		resv, resv ? "" : "Not ");
	printf("  [4:4] : %#x\tSave and Select %sSupported\n",
		save, save ? "" : "Not ");
	printf("  [3:3] : %#x\tWrite Zeroes %sSupported\n",
		wzro, wzro ? "" : "Not ");
	printf("  [2:2] : %#x\tData Set Management %sSupported\n",
		dsms, dsms ? "" : "Not ");
	printf("  [1:1] : %#x\tWrite Uncorrectable %sSupported\n",
		wunc, wunc ? "" : "Not ");
	printf("  [0:0] : %#x\tCompare %sSupported\n",
		cmp, cmp ? "" : "Not ");
	printf("\n");
}

static void show_nvme_id_ctrl_fuses(__le16 fuses)
{
	__le16 rsvd = (fuses & 0xFE) >> 1;
	__le16 cmpw = fuses & 0x1;
	if (rsvd)
		printf(" [15:1] : %#x\tReserved\n", rsvd);
	printf("  [0:0] : %#x\tFused Compare and Write %sSupported\n",
		cmpw, cmpw ? "" : "Not ");
	printf("\n");
}

static void show_nvme_id_ctrl_fna(__u8 fna)
{
	__u8 rsvd = (fna & 0xF8) >> 3;
	__u8 cese = (fna & 0x4) >> 2;
	__u8 cens = (fna & 0x2) >> 1;
	__u8 fmns = fna & 0x1;
	if (rsvd)
		printf("  [7:3] : %#x\tReserved\n", rsvd);
	printf("  [2:2] : %#x\tCrypto Erase %sSupported as part of Secure Erase\n",
		cese, cese ? "" : "Not ");
	printf("  [1:1] : %#x\tCrypto Erase Applies to %s Namespace(s)\n",
		cens, cens ? "All" : "Single");
	printf("  [0:0] : %#x\tFormat Applies to %s Namespace(s)\n",
		fmns, fmns ? "All" : "Single");
	printf("\n");
}

static void show_nvme_id_ctrl_vwc(__u8 vwc)
{
	__u8 rsvd = (vwc & 0xFE) >> 1;
	__u8 vwcp = vwc & 0x1;
	if (rsvd)
		printf("  [7:3] : %#x\tReserved\n", rsvd);
	printf("  [0:0] : %#x\tVolatile Write Cache %sPresent\n",
		vwcp, vwcp ? "" : "Not ");
	printf("\n");
}

static void show_nvme_id_ctrl_nvscc(__u8 nvscc)
{
	__u8 rsvd = (nvscc & 0xFE) >> 1;
	__u8 fmt = nvscc & 0x1;
	if (rsvd)
		printf("  [7:1] : %#x\tReserved\n", rsvd);
	printf("  [0:0] : %#x\tNVM Vendor Specific Commands uses %s Format\n",
		fmt, fmt ? "NVMe" : "Vendor Specific");
	printf("\n");
}

static void show_nvme_id_ctrl_sgls(__le32 sgls)
{
	__le32 rsvd0 = (sgls & 0xFFF80000) >> 19;
	__le32 sglltb = (sgls & 0x40000) >> 18;
	__le32 bacmdb = (sgls & 0x20000) >> 17;
	__le32 bbs = (sgls & 0x10000) >> 16;
	__le32 rsvd1 = (sgls & 0xFFFE) >> 1;
	__le32 sglsp = sgls & 0x1;
	if (rsvd0)
		printf(" [31:19]: %#x\tReserved\n", rsvd0);
	if (sglsp || (!sglsp && sglltb))
		printf(" [18:18]: %#x\tSGL Length Larger than Buffer %sSupported\n",
			sglltb, sglltb ? "" : "Not ");
	if (sglsp || (!sglsp && bacmdb))
		printf(" [17:17]: %#x\tByte-Aligned Contig. MD Buffer %sSupported\n",
			bacmdb, bacmdb ? "" : "Not ");
	if (sglsp || (!sglsp && bbs))
		printf(" [16:16]: %#x\tSGL Bit-Bucket %sSupported\n",
			bbs, bbs ? "" : "Not ");
	if (rsvd1)
		printf(" [15:1] : %#x\tReserved\n", rsvd1);
	printf("  [0:0] : %#x\tScatter-Gather Lists %sSupported\n",
		sglsp, sglsp ? "" : "Not ");
	printf("\n");
}

static void show_nvme_id_ctrl(struct nvme_id_ctrl *ctrl, int vs, int human)
{
	int i;
	char sn[sizeof(ctrl->sn) + 1];
	char mn[sizeof(ctrl->mn) + 1];
	char fr[sizeof(ctrl->fr) + 1];

	memcpy(sn, ctrl->sn, sizeof(ctrl->sn));
	memcpy(mn, ctrl->mn, sizeof(ctrl->mn));
	memcpy(fr, ctrl->fr, sizeof(ctrl->fr));

	sn[sizeof(ctrl->sn)] = '\0';
	mn[sizeof(ctrl->mn)] = '\0';
	fr[sizeof(ctrl->fr)] = '\0';

	printf("NVME Identify Controller:\n");
	printf("vid     : %#x\n", ctrl->vid);
	printf("ssvid   : %#x\n", ctrl->ssvid);
	printf("sn      : %s\n", sn);
	printf("mn      : %s\n", mn);
	printf("fr      : %s\n", fr);
	printf("rab     : %d\n", ctrl->rab);
	printf("ieee    : %02x%02x%02x\n",
		ctrl->ieee[0], ctrl->ieee[1], ctrl->ieee[2]);
	printf("cmic    : %#x\n", ctrl->cmic);
	if (human)
		show_nvme_id_ctrl_cmic(ctrl->cmic);
	printf("mdts    : %d\n", ctrl->mdts);
	printf("cntlid  : %x\n", ctrl->cntlid);
	printf("ver     : %x\n", ctrl->ver);
	printf("rtd3r   : %x\n", ctrl->rtd3r);
	printf("rtd3e   : %x\n", ctrl->rtd3e);
	printf("oaes    : %#x\n", ctrl->oaes);
	if (human)
		show_nvme_id_ctrl_oaes(ctrl->oaes);
	printf("oacs    : %#x\n", ctrl->oacs);
	if (human)
		show_nvme_id_ctrl_oacs(ctrl->oacs);
	printf("acl     : %d\n", ctrl->acl);
	printf("aerl    : %d\n", ctrl->aerl);
	printf("frmw    : %#x\n", ctrl->frmw);
	if (human)
		show_nvme_id_ctrl_frmw(ctrl->frmw);
	printf("lpa     : %#x\n", ctrl->lpa);
	if (human)
		show_nvme_id_ctrl_lpa(ctrl->lpa);
	printf("elpe    : %d\n", ctrl->elpe);
	printf("npss    : %d\n", ctrl->npss);
	printf("avscc   : %#x\n", ctrl->avscc);
	if (human)
		show_nvme_id_ctrl_avscc(ctrl->avscc);
	printf("apsta   : %#x\n", ctrl->apsta);
	if (human)
		show_nvme_id_ctrl_apsta(ctrl->apsta);
	printf("wctemp  : %d\n", ctrl->wctemp);
	printf("cctemp  : %d\n", ctrl->cctemp);
	printf("mtfa    : %d\n", ctrl->mtfa);
	printf("hmmin   : %d\n", ctrl->hmmin);
	printf("tnvmcap : %.0Lf\n", int128_to_double(ctrl->tnvmcap));
	printf("unvmcap : %.0Lf\n", int128_to_double(ctrl->unvmcap));
	printf("rpmbs   : %#x\n", ctrl->rpmbs);
	if (human)
		show_nvme_id_ctrl_rpmbs(ctrl->rpmbs);
	printf("sqes    : %#x\n", ctrl->sqes);
	if (human)
		show_nvme_id_ctrl_sqes(ctrl->sqes);
	printf("cqes    : %#x\n", ctrl->cqes);
	if (human)
		show_nvme_id_ctrl_cqes(ctrl->cqes);
	printf("nn      : %d\n", ctrl->nn);
	printf("oncs    : %#x\n", ctrl->oncs);
	if (human)
		show_nvme_id_ctrl_oncs(ctrl->oncs);
	printf("fuses   : %#x\n", ctrl->fuses);
	if (human)
		show_nvme_id_ctrl_fuses(ctrl->fuses);
	printf("fna     : %#x\n", ctrl->fna);
	if (human)
		show_nvme_id_ctrl_fna(ctrl->fna);
	printf("vwc     : %#x\n", ctrl->vwc);
	if (human)
		show_nvme_id_ctrl_vwc(ctrl->vwc);
	printf("awun    : %d\n", ctrl->awun);
	printf("awupf   : %d\n", ctrl->awupf);
	printf("nvscc   : %d\n", ctrl->nvscc);
	if (human)
		show_nvme_id_ctrl_nvscc(ctrl->nvscc);
	printf("acwu    : %d\n", ctrl->acwu);
	printf("sgls    : %x\n", ctrl->sgls);
	if (human)
		show_nvme_id_ctrl_sgls(ctrl->sgls);

	for (i = 0; i <= ctrl->npss; i++) {
		printf("ps %4d : mp:%d flags:%x enlat:%d exlat:%d rrt:%d rrl:%d\n"
			"          rwt:%d rwl:%d idlp:%d ips:%x actp:%x ap flags:%x\n",
			i, ctrl->psd[i].max_power, ctrl->psd[i].flags,
			ctrl->psd[i].entry_lat, ctrl->psd[i].exit_lat,
			ctrl->psd[i].read_tput, ctrl->psd[i].read_lat,
			ctrl->psd[i].write_tput, ctrl->psd[i].write_lat,
			ctrl->psd[i].idle_power, ctrl->psd[i].idle_scale,
			ctrl->psd[i].active_power, ctrl->psd[i].active_work_scale);
	}
	if (vs) {
		printf("vs[]:\n");
		d(ctrl->vs, sizeof(ctrl->vs), 16, 1);
	}
}

char* nvme_feature_lba_type_to_string(__u8 type)
{
	switch (type)
	{
	case 0:	return "Reserved";
	case 1:	return "Filesystem";
	case 2:	return "RAID";
	case 3:	return "Cache";
	case 4:	return "Page / Swap file";
	default:
		if (type>=0x05 && type<=0x7f)
			return "Reserved";
		else
			return "Vendor Specific";
	}
}		

static void show_lba_range(struct nvme_lba_range_type *lbrt, int nr_ranges)
{
	int i, j;

	for (i = 0; i <= nr_ranges; i++) {
		printf("type       : %#x - %s\n", lbrt[i].type, nvme_feature_lba_type_to_string(lbrt[i].type));
		printf("attributes : %#x\n", lbrt[i].attributes);
		printf("slba       : %#"PRIx64"\n", (uint64_t)(lbrt[i].slba));
		printf("nlb        : %#"PRIx64"\n", (uint64_t)(lbrt[i].nlb));
		printf("guid       : ");
		for (j = 0; j < 16; j++)
			printf("%02x", lbrt[i].guid[j]);
		printf("\n");
	}
}

static void show_nvme_id_ns_nsfeat(__u8 nsfeat)
{
	__u8 rsvd = (nsfeat & 0xF8) >> 3;
	__u8 dulbe = (nsfeat & 0x4) >> 2;
	__u8 na = (nsfeat & 0x2) >> 1;
	__u8 thin = nsfeat & 0x1;
	if (rsvd)
		printf("  [7:3] : %#x\tReserved\n", rsvd);
	printf("  [2:2] : %#x\tDeallocated or Unwritten Logical Block error %sSupported\n",
		dulbe, dulbe ? "" : "Not ");
	printf("  [1:1] : %#x\tNamespace uses %s\n",
		na, na ? "NAWUN, NAWUPF, and NACWU" : "AWUN, AWUPF, and ACWU");
	printf("  [0:0] : %#x\tThin Provisioning %sSupported\n",
		thin, thin ? "" : "Not ");
	printf("\n");
}

static void show_nvme_id_ns_flbas(__u8 flbas)
{
	__u8 rsvd = (flbas & 0xE0) >> 5;
	__u8 mdedata = (flbas & 0x10) >> 4;
	__u8 lbaf = flbas & 0xF;
	if (rsvd)
		printf("  [7:5] : %#x\tReserved\n", rsvd);
	printf("  [4:4] : %#x\tMetadata Transferred %s\n",
		mdedata, mdedata ? "at End of Data LBA" : "in Separate Contiguous Buffer");
	printf("  [3:0] : %#x\tCurrent LBA Format Selected\n", lbaf);
	printf("\n");
}

static void show_nvme_id_ns_mc(__u8 mc)
{
	__u8 rsvd = (mc & 0xFC) >> 2;
	__u8 mdp = (mc & 0x2) >> 1;
	__u8 extdlba = mc & 0x1;
	if (rsvd)
		printf("  [7:2] : %#x\tReserved\n", rsvd);
	printf("  [1:1] : %#x\tMetadata Pointer %sSupported\n",
		mdp, mdp ? "" : "Not ");
	printf("  [0:0] : %#x\tMetadata as Part of Extended Data LBA %sSupported\n",
		extdlba, extdlba ? "" : "Not ");
	printf("\n");
}

static void show_nvme_id_ns_dpc(__u8 dpc)
{
	__u8 rsvd = (dpc & 0xE0) >> 5;
	__u8 pil8 = (dpc & 0x10) >> 4;
	__u8 pif8 = (dpc & 0x8) >> 3;
	__u8 pit3 = (dpc & 0x4) >> 2;
	__u8 pit2 = (dpc & 0x2) >> 1;
	__u8 pit1 = dpc & 0x1;
	if (rsvd)
		printf("  [7:5] : %#x\tReserved\n", rsvd);
	printf("  [4:4] : %#x\tProtection Information Transferred as Last 8 Bytes of Metadata %sSupported\n",
		pil8, pil8 ? "" : "Not ");
	printf("  [3:3] : %#x\tProtection Information Transferred as First 8 Bytes of Metadata %sSupported\n",
		pif8, pif8 ? "" : "Not ");
	printf("  [2:2] : %#x\tProtection Information Type 3 %sSupported\n",
		pit3, pit3 ? "" : "Not ");
	printf("  [1:1] : %#x\tProtection Information Type 2 %sSupported\n",
		pit2, pit2 ? "" : "Not ");
	printf("  [0:0] : %#x\tProtection Information Type 1 %sSupported\n",
		pit1, pit1 ? "" : "Not ");
	printf("\n");
}

static void show_nvme_id_ns_dps(__u8 dps)
{
	__u8 rsvd = (dps & 0xF0) >> 4;
	__u8 pif8 = (dps & 0x8) >> 3;
	__u8 pit = dps & 0x7;
	if (rsvd)
		printf("  [7:4] : %#x\tReserved\n", rsvd);
	printf("  [3:3] : %#x\tProtection Information is Transferred as %s 8 Bytes of Metadata\n",
		pif8, pif8 ? "First" : "Last");
	printf("  [2:0] : %#x\tProtection Information %s\n", pit,
		pit == 3 ? "Type 3 Enabled" :
		pit == 2 ? "Type 2 Enabled" :
		pit == 1 ? "Type 1 Enabled" :
		pit == 0 ? "Disabled" : "Reserved Enabled");
	printf("\n");
}

static void show_nvme_id_ns_nmic(__u8 nmic)
{
	__u8 rsvd = (nmic & 0xFE) >> 1;
	__u8 mp = nmic & 0x1;
	if (rsvd)
		printf("  [7:1] : %#x\tReserved\n", rsvd);
	printf("  [0:0] : %#x\tNamespace Multipath %sCapable\n",
		mp, mp ? "" : "Not ");
	printf("\n");
}

static void show_nvme_id_ns_rescap(__u8 rescap)
{
	__u8 rsvd = (rescap & 0x80) >> 7;
	__u8 eaar = (rescap & 0x40) >> 6;
	__u8 wear = (rescap & 0x20) >> 5;
	__u8 earo = (rescap & 0x10) >> 4;
	__u8 wero = (rescap & 0x8) >> 3;
	__u8 ea = (rescap & 0x4) >> 2;
	__u8 we = (rescap & 0x2) >> 1;
	__u8 ptpl = rescap & 0x1;
	if (rsvd)
		printf("  [7:7] : %#x\tReserved\n", rsvd);
	printf("  [6:6] : %#x\tExclusive Access - All Registrants %sSupported\n",
		eaar, eaar ? "" : "Not ");
	printf("  [5:5] : %#x\tWrite Exclusive - All Registrants %sSupported\n",
		wear, wear ? "" : "Not ");
	printf("  [4:4] : %#x\tExclusive Access - Registrants Only %sSupported\n",
		earo, earo ? "" : "Not ");
	printf("  [3:3] : %#x\tWrite Exclusive - Registrants Only %sSupported\n",
		wero, wero ? "" : "Not ");
	printf("  [2:2] : %#x\tExclusive Access %sSupported\n",
		ea, ea ? "" : "Not ");
	printf("  [1:1] : %#x\tWrite Exclusive %sSupported\n",
		we, we ? "" : "Not ");
	printf("  [0:0] : %#x\tPersist Through Power Loss %sSupported\n",
		ptpl, ptpl ? "" : "Not ");
	printf("\n");
}

static void show_nvme_id_ns_fpi(__u8 fpi)
{
	__u8 fpis = (fpi & 0x80) >> 7;
	__u8 fpii = fpi & 0x7F;
	printf("  [7:7] : %#x\tFormat Progress Indicator %sSupported\n",
		fpis, fpis ? "" : "Not ");
	if (fpis || (!fpis && fpii))
	printf("  [6:0] : %#x\tFormat Progress Indicator (Remaining %d%%)\n",
		fpii, 100 - fpii);
	printf("\n");
}

static void show_nvme_id_ns(struct nvme_id_ns *ns, int id, int vs, int human)
{
	int i;

	printf("NVME Identify Namespace %d:\n", id);
	printf("nsze    : %#"PRIx64"\n", (uint64_t)le64toh(ns->nsze));
	printf("ncap    : %#"PRIx64"\n", (uint64_t)le64toh(ns->ncap));
	printf("nuse    : %#"PRIx64"\n", (uint64_t)le64toh(ns->nuse));
	printf("nsfeat  : %#x\n", ns->nsfeat);
	if (human)
		show_nvme_id_ns_nsfeat(ns->nsfeat);
	printf("nlbaf   : %d\n", ns->nlbaf);
	printf("flbas   : %#x\n", ns->flbas);
	if (human)
		show_nvme_id_ns_flbas(ns->flbas);
	printf("mc      : %#x\n", ns->mc);
	if (human)
		show_nvme_id_ns_mc(ns->mc);
	printf("dpc     : %#x\n", ns->dpc);
	if (human)
		show_nvme_id_ns_dpc(ns->dpc);
	printf("dps     : %#x\n", ns->dps);
	if (human)
		show_nvme_id_ns_dps(ns->dps);
	printf("nmic    : %#x\n", ns->nmic);
	if (human)
		show_nvme_id_ns_nmic(ns->nmic);
	printf("rescap  : %#x\n", ns->rescap);
	if (human)
		show_nvme_id_ns_rescap(ns->rescap);
	printf("fpi     : %#x\n", ns->fpi);
	if (human)
		show_nvme_id_ns_fpi(ns->fpi);
	printf("nawun   : %d\n", ns->nawun);
	printf("nawupf  : %d\n", ns->nawupf);
	printf("nacwu   : %d\n", ns->nacwu);
	printf("nabsn   : %d\n", ns->nabsn);
	printf("nabo    : %d\n", ns->nabo);
	printf("nabspf  : %d\n", ns->nabspf);
	printf("nvmcap  : %.0Lf\n", int128_to_double(ns->nvmcap));

	printf("nguid   : ");
	for (i = 0; i < 16; i++)
		printf("%02x", ns->nguid[i]);
	printf("\n");

	printf("eui64   : ");
	for (i = 0; i < 8; i++)
		printf("%02x", ns->eui64[i]);
	printf("\n");

	for (i = 0; i <= ns->nlbaf; i++) {
		if (human)
			printf("LBA Format %2d : Metadata Size: %-3d bytes - "
				"Data Size: %-2d bytes - Relative Performance: %#x %s %s\n", i,
				ns->lbaf[i].ms, 1 << ns->lbaf[i].ds, ns->lbaf[i].rp,
				ns->lbaf[i].rp == 3 ? "Degraded" :
				ns->lbaf[i].rp == 2 ? "Good" :
				ns->lbaf[i].rp == 1 ? "Better" : "Best",
				i == (ns->flbas & 0xf) ? "(in use)" : "");
		else
			printf("lbaf %2d : ms:%-3d ds:%-2d rp:%#x %s\n", i,
				ns->lbaf[i].ms, ns->lbaf[i].ds, ns->lbaf[i].rp,
				i == (ns->flbas & 0xf) ? "(in use)" : "");
	}
	if (vs) {
		printf("vs[]:");
		d(ns->vs, sizeof(ns->vs), 16, 1);
	}
}

static int get_smart_log(int argc, char **argv)
{
	struct nvme_smart_log smart_log;
	const char *desc = "smart-log: retrieve SMART log for the given "\
		"device (or optionally, namespace) in either hex-dump "\
		"(default) or binary format.";
	const char *namespace = "(optional) desired namespace";
	const char *raw = "output in binary format";
	int err;

	struct config {
		__u32 namespace_id;
		__u8  raw_binary;
	};
	struct config cfg;

	const struct config defaults = {
		.namespace_id = 0xffffffff,
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"namespace-id", "NUM", CFG_POSITIVE, &defaults.namespace_id, required_argument, namespace},
		{"n",            "NUM", CFG_POSITIVE, &defaults.namespace_id, required_argument, namespace},
		{"raw-binary",   "",    CFG_NONE,     &defaults.raw_binary,   no_argument,       raw},
		{"b",            "",    CFG_NONE,     &defaults.raw_binary,   no_argument,       raw},
		{0}
	};

	argconfig_parse(argc, argv, desc, command_line_options,
			&defaults, &cfg, sizeof(cfg));

	get_dev(1, argc, argv);

	err = nvme_get_log(&smart_log,
		sizeof(smart_log), 0x2 | (((sizeof(smart_log) / 4) - 1) << 16),
		cfg.namespace_id);
	if (!err) {
		if (!cfg.raw_binary)
			show_smart_log(&smart_log, cfg.namespace_id);
		else
			d_raw((unsigned char *)&smart_log, sizeof(smart_log));
	}
	else if (err > 0)
		fprintf(stderr, "NVMe Status:%s(%x)\n",
					nvme_status_to_string(err), err);
	return err;
}

static int get_additional_smart_log(int argc, char **argv)
{
	struct nvme_additional_smart_log smart_log;
	int err;
	char *desc = "Get additional smart log (optionally, "\
		      "for the specified namspace), and show it.";
	const char *namespace = "(optional) desired namespace";
	const char *raw = "dump output in binary format";
	struct config {
		__u32 namespace_id;
		__u8  raw_binary;
	};
	struct config cfg;

	const struct config defaults = {
		.namespace_id = 0xffffffff,
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"namespace-id", "NUM", CFG_POSITIVE, &defaults.namespace_id, required_argument, namespace},
		{"n",            "NUM", CFG_POSITIVE, &defaults.namespace_id, required_argument, namespace},
		{"raw-binary",   "",    CFG_NONE,     &defaults.raw_binary,   no_argument,       raw},
		{"b",            "",    CFG_NONE,     &defaults.raw_binary,   no_argument,       raw},
		{0}
	};
	argconfig_parse(argc, argv, desc, command_line_options,
			&defaults, &cfg, sizeof(cfg));
	get_dev(1, argc, argv);

	err = nvme_get_log(&smart_log,
		sizeof(smart_log), 0xCA | (((sizeof(smart_log) / 4) - 1) << 16),
		cfg.namespace_id);
	if (!err) {
		if (!cfg.raw_binary)
			show_additional_smart_log(&smart_log, cfg.namespace_id);
		else
			d_raw((unsigned char *)&smart_log, sizeof(smart_log));
	}
	else if (err > 0)
		fprintf(stderr, "NVMe Status:%s(%x)\n",
					nvme_status_to_string(err), err);
	return err;
}

static int get_error_log(int argc, char **argv)
{
	const char *desc = "error-log: retrieve specified number of "\
		"error log entries from a given device (or "\
		"namespace) in either hex-dump (default) or binary format.";
	const char *namespace_id = "desired namespace";
	const char *log_entries = "number of entries to retrieve";
	const char *raw_binary = "dump in binary format";
	struct nvme_id_ctrl ctrl;
	int err;

	struct config {
		__u32 namespace_id;
		__u32 log_entries;
		__u8  raw_binary;
	};
	struct config cfg;

	const struct config defaults = {
		.namespace_id = 0xffffffff,
		.log_entries  = 64,
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"namespace-id", "NUM",  CFG_POSITIVE, &defaults.namespace_id, required_argument, namespace_id},
		{"n",            "NUM",  CFG_POSITIVE, &defaults.namespace_id, required_argument, namespace_id},
		{"log-entries",  "NUM",  CFG_POSITIVE, &defaults.log_entries,  required_argument, log_entries},
		{"e",            "NUM",  CFG_POSITIVE, &defaults.log_entries,  required_argument, log_entries},
		{"raw-binary",   "",     CFG_NONE,     &defaults.raw_binary,   no_argument,       raw_binary},
		{"b",            "",     CFG_NONE,     &defaults.raw_binary,   no_argument,       raw_binary},
		{0}
	};

	argconfig_parse(argc, argv, desc, command_line_options,
			&defaults, &cfg, sizeof(cfg));

	get_dev(1, argc, argv);
	if (!cfg.log_entries) {
		fprintf(stderr, "non-zero log-entries is required param\n");
		return EINVAL;
	}
	err = identify(0, &ctrl, 1);
	cfg.log_entries = min(cfg.log_entries, ctrl.elpe + 1);
	if (err) {
		fprintf(stderr, "could not identify controller\n");
		return ENODEV;
	} else {
		struct nvme_error_log_page err_log[cfg.log_entries];
		err = nvme_get_log(err_log,
				   sizeof(err_log), 0x1 | (((sizeof(err_log) / 4) - 1) << 16),
				   cfg.namespace_id);
		if (!err) {
			if (!cfg.raw_binary)
				show_error_log(err_log, cfg.log_entries);
			else
				d_raw((unsigned char *)err_log, sizeof(err_log));
		}
		else if (err > 0)
			fprintf(stderr, "NVMe Status:%s(%x)\n",
						nvme_status_to_string(err), err);
	}
	return err;
}

static int get_fw_log(int argc, char **argv)
{
	const char *desc = "fw-log: retrieve the firmware log for the "\
		"specified device in either hex-dump (default) or binary "\
		"format.";
	const char *raw_binary = "use binary output";
	int err;
	struct nvme_firmware_log_page fw_log;

	struct config {
		__u8  raw_binary;
	};
	struct config cfg;

	const struct config defaults = {
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"raw-binary", "",   CFG_NONE, &defaults.raw_binary,   no_argument,       raw_binary},
		{"b",          "",   CFG_NONE, &defaults.raw_binary,   no_argument,       raw_binary},
		{0}
	};

	argconfig_parse(argc, argv, desc, command_line_options,
			&defaults, &cfg, sizeof(cfg));

	get_dev(1, argc, argv);

	err = nvme_get_log(&fw_log,
			sizeof(fw_log), 0x3 | (((sizeof(fw_log) / 4) - 1) << 16),
			0xffffffff);
	if (!err) {
		if (!cfg.raw_binary)
			show_fw_log(&fw_log);
		else
			d_raw((unsigned char *)&fw_log, sizeof(fw_log));
	}
	else if (err > 0)
		fprintf(stderr, "NVMe Status:%s(%x)\n",
				nvme_status_to_string(err), err);
	else
		perror("fw log");
	return err;
}

static int get_log(int argc, char **argv)
{
	const char *desc = "get-log: retrieve desired number of bytes "\
		"from a given log on a specified device in either "\
		"hex-dump (default) or binary format";
	const char *namespace_id = "desired namespace";
	const char *log_id = "name of log to retrieve";
	const char *log_len = "how many bytes to retrieve";
	const char *raw_binary = "output in raw format";
	int err;

	struct config {
		__u32 namespace_id;
		__u32 log_id;
		__u32 log_len;
		__u8  raw_binary;
	};
	struct config cfg;

	const struct config defaults = {
		.namespace_id = 0,
		.log_id       = 0,
		.log_len      = 0,
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"namespace-id", "NUM",  CFG_POSITIVE, &defaults.namespace_id, required_argument, namespace_id},
		{"n",            "NUM",  CFG_POSITIVE, &defaults.namespace_id, required_argument, namespace_id},
		{"log-id",       "NUM",  CFG_POSITIVE, &defaults.log_id,       required_argument, log_id},
		{"i",            "NUM",  CFG_POSITIVE, &defaults.log_id,       required_argument, log_id},
		{"log-len",      "NUM",  CFG_POSITIVE, &defaults.log_len,      required_argument, log_len},
		{"l",            "NUM",  CFG_POSITIVE, &defaults.log_len,      required_argument, log_len},
		{"raw-binary",   "",     CFG_NONE,     &defaults.raw_binary,   no_argument,       raw_binary},
		{"b",            "",     CFG_NONE,     &defaults.raw_binary,   no_argument,       raw_binary},
		{0}
	};

	argconfig_parse(argc, argv, desc, command_line_options,
			&defaults, &cfg, sizeof(cfg));

	get_dev(1, argc, argv);

	if (!cfg.log_len) {
		fprintf(stderr, "non-zero log-len is required param\n");
		return EINVAL;
	} else {
		unsigned char log[cfg.log_len];

		err = nvme_get_log(log, cfg.log_len, cfg.log_id | (((cfg.log_len / 4) - 1) << 16),
				   cfg.namespace_id);
		if (!err) {
			if (!cfg.raw_binary) {
				printf("Device:%s log-id:%d namespace-id:%#x",
				       devicename, cfg.log_id,
				       cfg.namespace_id);
				d(log, cfg.log_len, 16, 1);
			} else
				d_raw((unsigned char *)log, cfg.log_len);
		} else if (err > 0)
			fprintf(stderr, "NVMe Status:%s(%x)\n",
						nvme_status_to_string(err), err);
		return err;
	}
}

static int list_ctrl(int argc, char **argv)
{
	const char *desc = "list-ctrl: show controller information for the "\
		"given device (and optionally, namespace)";
	const char *controller = "controller to display";
	const char *namespace_id = "optional namespace attached to controller";
	int err, i;
	struct nvme_controller_list *cntlist;

	struct config {
		__u16 cntid;
		__u32 namespace_id;
	};
	struct config cfg;

	const struct config defaults = {
		.cntid = 0,
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"cntid",        "NUM", CFG_SHORT,    &defaults.cntid,        required_argument, controller},
		{"c",            "NUM", CFG_SHORT,    &defaults.cntid,        required_argument, controller},
		{"namespace-id", "NUM", CFG_POSITIVE, &defaults.namespace_id, required_argument, namespace_id},
		{"n",            "NUM", CFG_POSITIVE, &defaults.namespace_id, required_argument, namespace_id},
		{0}
	};

	argconfig_parse(argc, argv, desc, command_line_options,
			&defaults, &cfg, sizeof(cfg));

	get_dev(1, argc, argv);

	if (posix_memalign((void *)&cntlist, getpagesize(), 0x1000))
		return ENOMEM;

	err = identify(cfg.namespace_id, cntlist,
			cfg.cntid << 16 | cfg.namespace_id ? 0x12 : 0x13);
	if (!err) {
		for (i = 0; i < (min(cntlist->num, 2048)); i++)
			printf("[%4u]:%#x\n", i, cntlist->identifier[i]);
	}
	else if (err > 0)
		fprintf(stderr, "NVMe Status:%s(%x) cntid:%d\n",
			nvme_status_to_string(err), err, cfg.cntid);
	return err;
}

static int list_ns(int argc, char **argv)
{
	const char *desc = "list-ns: for the specified device, show the "\
		"namespace list (optionally starting with a given namespace)";
	const char *namespace_id = "namespace to start after";
	const char *all = "show all namespaces in the subsystem, whether attached or inactive";
	int err, i;
	__u32 ns_list[1024];

	struct config {
		__u32 namespace_id;
		__u8  all;
	};
	struct config cfg;

	const struct config defaults = {
		.namespace_id = 0,
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"namespace-id", "NUM",  CFG_POSITIVE, &defaults.namespace_id, required_argument, namespace_id},
		{"n",            "NUM",  CFG_POSITIVE, &defaults.namespace_id, required_argument, namespace_id},
		{"all",          "",     CFG_NONE,     &defaults.all,          no_argument,       all},
		{"a",            "",     CFG_NONE,     &defaults.all,          no_argument,       all},
		{0}
	};

	argconfig_parse(argc, argv, desc, command_line_options,
			&defaults, &cfg, sizeof(cfg));

	get_dev(1, argc, argv);

	err = identify(cfg.namespace_id, ns_list, cfg.all ? 0x10 : 2);
	if (!err) {
		for (i = 0; i < 1024; i++)
			if (ns_list[i])
				printf("[%4u]:%#x\n", i, ns_list[i]);
	}
	else if (err > 0)
		fprintf(stderr, "NVMe Status:%s(%x) NSID:%d\n",
			nvme_status_to_string(err), err, cfg.namespace_id);
	return err;
}

static int delete_ns(int argc, char **argv)
{
	struct nvme_admin_cmd cmd;
	const char *desc = "delete-ns: delete the given namespace by "\
		"sending a namespace management command to "\
		"the given device. All controllers should be detached from "\
		"the namespace prior to namespace deletion. A namespace ID "\
		"becomes inactive when that namespace is detached (or, if "\
		"the namespace is not already inactive, once deleted).";
	const char *namespace_id = "namespace to delete";
	int err;

	struct config {
		__u32	namespace_id;
	};
	struct config cfg;

	const struct config defaults = {
		.namespace_id    = 0,
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"namespace-id",    "NUM",  CFG_POSITIVE, &defaults.namespace_id,    required_argument, namespace_id},
		{"n",               "NUM",  CFG_POSITIVE, &defaults.namespace_id,    required_argument, namespace_id},
		{0}
	};

	argconfig_parse(argc, argv, desc, command_line_options,
			&defaults, &cfg, sizeof(cfg));

	if (!cfg.namespace_id) {
		fprintf(stderr, "%s: namespace-id parameter required\n",
						commands[DELETE_NS].name);
		return EINVAL;
	}
	get_dev(1, argc, argv);

	memset(&cmd, 0, sizeof(cmd));
	cmd.opcode = nvme_admin_ns_mgmt;
	cmd.nsid = cfg.namespace_id;
	cmd.cdw10 = 1;

	err = ioctl(fd, NVME_IOCTL_ADMIN_CMD, &cmd);
	if (!err)
		printf("%s: Success, deleted nsid:%d\n", commands[DELETE_NS].name,
								cfg.namespace_id);
	else if (err > 0)
		fprintf(stderr, "NVMe Status:%s(%x)\n",
					nvme_status_to_string(err), err);
	else
		fprintf(stderr, "system error:(%x)\n", err);
	return err;
}

static int nvme_attach_ns(int argc, char **argv, int attach, const char *desc)
{
	struct nvme_controller_list *cntlist;
	struct nvme_admin_cmd cmd;
	char *name = commands[attach ? ATTACH_NS : DETACH_NS].name;
	int err, i, list[2048];

	const char *namespace_id = "namespace to attach";
	const char *cont = "optional comma-sep controllers list";

	struct config {
		char  *cntlist;
		__u32 namespace_id;
	};
	struct config cfg;

	const struct config defaults = {
		.cntlist = "",
		.namespace_id = 0,
	};
	const struct argconfig_commandline_options command_line_options[] = {
		{"namespace-id",    "NUM",  CFG_POSITIVE, &defaults.namespace_id,    required_argument, namespace_id},
		{"n",               "NUM",  CFG_POSITIVE, &defaults.namespace_id,    required_argument, namespace_id},
		{"controllers",     "LIST", CFG_STRING, &defaults.cntlist,    required_argument, cont},
		{"c",               "LIST", CFG_STRING, &defaults.cntlist,    required_argument, cont},
		{0}
	};

	if (posix_memalign((void *)&cntlist, getpagesize(), 0x1000))
		return ENOMEM;
	memset(cntlist, 0, sizeof(*cntlist));

	argconfig_parse(argc, argv, desc, command_line_options,
			&defaults, &cfg, sizeof(cfg));

	if (!cfg.namespace_id) {
		fprintf(stderr, "%s: namespace-id parameter required\n",
						name);
		return EINVAL;
	}
	cntlist->num = argconfig_parse_comma_sep_array(cfg.cntlist,
					list, 2047);
	for (i = 0; i < cntlist->num; i++)
		cntlist->identifier[i] = htole16((uint16_t)list[i]);

	get_dev(1, argc, argv);

	memset(&cmd, 0, sizeof(cmd));
	cmd.opcode = nvme_admin_ns_attach;
	cmd.addr = (__u64)cntlist;
	cmd.data_len = 4096;
	cmd.nsid = cfg.namespace_id;
	cmd.cdw10 = attach ? 0 : 1;

	err = ioctl(fd, NVME_IOCTL_ADMIN_CMD, &cmd);
	if (!err)
		printf("%s: Success, nsid:%d\n", name, cfg.namespace_id);
	else if (err > 0)
		fprintf(stderr, "NVMe Status:%s(%x)\n",
					nvme_status_to_string(err), err);
	else
		fprintf(stderr, "system error:(%x)\n", err);
	return err;
}

static int attach_ns(int argc, char **argv)
{
	const char *desc = "attach-ns: attach the given namespace to the "\
		"given controller or comma-sep list of controllers. ID of the "\
		"given namespace becomes active upon attachment to a "\
		"controller. A namespace must be attached to a controller "\
		"before IO commands may be directed to that namespace.";
	return nvme_attach_ns(argc, argv, 1, desc);
}

static int detach_ns(int argc, char **argv)
{
	const char *desc = "detach-ns: detach the given namespace from the "\
		"given controller; de-activates the given namespace's ID. A "\
		"namespace must be attached to a controller before IO "\
		"commands may be directed to that namespace.";
	return nvme_attach_ns(argc, argv, 0, desc);
}

static int create_ns(int argc, char **argv)
{
	struct nvme_admin_cmd cmd;
	struct nvme_id_ns *ns;
	const char *desc = "create-ns: send a namespace management command "\
		"to the specified device to create a namespace with the given "\
		"parameters. The next available namespace ID is used for the "\
		"create operation. Note that create-ns does not attach the "\
		"namespace to a controller, the attach-ns command is needed.";
	int err = 0;

	struct config {
		__u64	nsze;
		__u64	ncap;
		__u8	flbas;
		__u8	dps;
		__u8	nmic;
	};
	struct config cfg;

	const struct config defaults = {
	};

	const char *nsze = "size of ns";
	const char *ncap = "capacity of ns";
	const char *flbas = "FLBA size";
	const char *dps = "data protection capabilities";
	const char *nmic = "multipath and sharing capabilities";

	const struct argconfig_commandline_options command_line_options[] = {
		{"nsze",            "NUM", CFG_LONG_SUFFIX, &defaults.nsze,  required_argument, nsze},
		{"s",               "NUM", CFG_LONG_SUFFIX, &defaults.nsze,  required_argument, nsze},
		{"ncap",            "NUM", CFG_LONG_SUFFIX, &defaults.ncap,  required_argument, ncap},
		{"c",               "NUM", CFG_LONG_SUFFIX, &defaults.ncap,  required_argument, ncap},
		{"flbas",           "NUM", CFG_BYTE,        &defaults.flbas, required_argument, flbas},
		{"f",               "NUM", CFG_BYTE,        &defaults.flbas, required_argument, flbas},
		{"dps",             "NUM", CFG_BYTE,        &defaults.dps,   required_argument, dps},
		{"d",               "NUM", CFG_BYTE,        &defaults.dps,   required_argument, dps},
		{"nmic",            "NUM", CFG_BYTE,        &defaults.nmic,  required_argument, nmic},
		{"m",               "NUM", CFG_BYTE,        &defaults.nmic,  required_argument, nmic},
		{0}
	};

	argconfig_parse(argc, argv, desc, command_line_options,
			&defaults, &cfg, sizeof(cfg));

	get_dev(1, argc, argv);

	if (posix_memalign((void *)&ns, getpagesize(), 4096))
		return -ENOMEM;
	memset(ns, 0, sizeof(*ns));
	memset(&cmd, 0, sizeof(cmd));

	ns->nsze  = cfg.nsze;
	ns->ncap  = cfg.ncap;
	ns->flbas = cfg.flbas;
	ns->dps   = cfg.dps;
	ns->nmic  = cfg.nmic;

	cmd.opcode = nvme_admin_ns_mgmt;
	cmd.addr = (unsigned long)ns;
	cmd.data_len = 4096;

	err = ioctl(fd, NVME_IOCTL_ADMIN_CMD, &cmd);
	if (!err)
		printf("%s: Success, created nsid:%d\n", commands[CREATE_NS].name,
								cmd.result);
	else if (err > 0)
		fprintf(stderr, "NVMe Status:%s(%x)\n",
					nvme_status_to_string(err), err);
	return err;
}

static char *nvme_char_from_block(char *block)
{
	char slen[16];
	unsigned len;
	if (strncmp("nvme", block, 4)) {
		fprintf(stderr,"Device %s is not a nvme device.", block);
		exit(-1);
	}
	sscanf(block,"nvme%d", &len);
	sprintf(slen,"%d", len);
	block[4+strlen(slen)] = 0;
	return block;
}

static void get_registers(struct nvme_bar **bar, unsigned char_only)
{
	int pci_fd;
	char *base, path[512];
	void *membase;

	if (char_only && !S_ISCHR(nvme_stat.st_mode)) {
		fprintf(stderr, "%s is not a character device\n", devicename);
		exit(ENODEV);
	}

	base = nvme_char_from_block(basename(devicename));

	sprintf(path, "/sys/class/nvme/%s/device/resource0", base);
	pci_fd = open(path, O_RDONLY);
	if (pci_fd < 0) {
		sprintf(path, "/sys/class/misc/%s/device/resource0", base);
		pci_fd = open(path, O_RDONLY);
	}
	if (pci_fd < 0) {
		fprintf(stderr, "%s did not find a pci resource\n", devicename);
		exit(ENODEV);
	}

	membase = mmap(0, getpagesize(), PROT_READ, MAP_SHARED, pci_fd, 0);
	if (!membase) {
		fprintf(stderr, "%s failed to map\n", devicename);
		exit(ENODEV);
	}
	*bar = membase;
}

struct list_item {
	char                node[1024];
	struct nvme_id_ctrl ctrl;
	int                 nsid;
	struct nvme_id_ns   ns;
	unsigned            block;
	__le32              ver;
};

#ifdef LIBUDEV_EXISTS
/* For pre NVMe 1.2 devices we must get the version from the BAR, not the
 * ctrl_id.*/
static void get_version(struct list_item* list_item)
{
	struct nvme_bar *bar;

	list_item->ver = list_item->ctrl.ver;
	if (list_item->ctrl.ver)
		return;
	get_registers(&bar, 0);
	list_item->ver = bar->vs;
}

static void print_list_item(struct list_item list_item)
{

	double nsze       = list_item.ns.nsze;
	double nuse       = list_item.ns.nuse;
	long long int lba = list_item.ns.lbaf[(list_item.ns.flbas & 0x0f)].ds;

	lba  = (1 << lba);
	nsze *= lba;
	nuse *= lba;

	const char *s_suffix = suffix_si_get(&nsze);
	const char *u_suffix = suffix_si_get(&nuse);
	const char *l_suffix = suffix_binary_get(&lba);

	char usage[128];
	sprintf(usage,"%6.2f %2sB / %6.2f %2sB", nuse, u_suffix,
		nsze, s_suffix);
	char format[128];
	sprintf(format,"%3.0f %2sB + %2d B", (double)lba, l_suffix,
		list_item.ns.lbaf[(list_item.ns.flbas & 0x0f)].ms);
	char version[128];
	sprintf(version,"%d.%d", (list_item.ver >> 16),
		(list_item.ver >> 8) & 0xff);

	fprintf(stdout, "%-16s %-20.20s %-8s %-8d %-26s %-16s %-.8s\n", list_item.node,
		list_item.ctrl.mn, version, list_item.nsid, usage, format, list_item.ctrl.fr);
}

static void print_list_items(struct list_item *list_items, unsigned len)
{
	fprintf(stdout,"%-16s %-20s %-8s %-8s %-26s %-16s %-8s\n",
		"Node","Model","Version","Namepace", "Usage", "Format", "FW Rev");
	fprintf(stdout,"%-16s %-20s %-8s %-8s %-26s %-16s %-8s\n",
            "----------------","--------------------","--------","--------",
            "--------------------------","----------------","--------");
	for (unsigned i=0 ; i<len ; i++)
		print_list_item(list_items[i]);

}
#else
static int list(int argc, char **argv)
{
	fprintf(stderr,"nvme-list: libudev not detected, install and rebuild.\n");
	return -1;
}
#endif

#ifdef LIBUDEV_EXISTS
#define MAX_LIST_ITEMS 256
static int list(int argc, char **argv)
{
	struct udev *udev;
	struct udev_enumerate *enumerate;
	struct udev_list_entry *devices, *dev_list_entry;
	struct udev_device *dev;

	struct list_item list_items[MAX_LIST_ITEMS];
	unsigned count=0;

	udev = udev_new();
	if (!udev) {
		perror("nvme-list: Cannot create udev context.");
		return errno;
	}

	enumerate = udev_enumerate_new(udev);
	udev_enumerate_add_match_subsystem(enumerate, "char");
	udev_enumerate_add_match_subsystem(enumerate, "block");
	udev_enumerate_scan_devices(enumerate);
	devices = udev_enumerate_get_list_entry(enumerate);
	udev_list_entry_foreach(dev_list_entry, devices) {

		const char *path, *node;
		path = udev_list_entry_get_name(dev_list_entry);
		dev  = udev_device_new_from_syspath(udev, path);
		node = udev_device_get_devnode(dev);
		if (strstr(node,"nvme")!=NULL){
			open_dev(node);
			int err = identify(0, &list_items[count].ctrl, 1);
			if (err > 0)
				return err;
			list_items[count].nsid = ioctl(fd, NVME_IOCTL_ID);
			err = identify(list_items[count].nsid,
				       &list_items[count].ns, 0);
			if (err > 0)
				return err;
			strcpy(list_items[count].node, node);
			list_items[count].block = S_ISBLK(nvme_stat.st_mode);
			get_version(&list_items[count]);
			count++;
		}
	}
	udev_enumerate_unref(enumerate);
	udev_unref(udev);

	if (count)
		print_list_items(list_items, count);
	else
		fprintf(stdout,"No NVMe devices detected.\n");

	return 0;
}
#endif

static int id_ctrl(int argc, char **argv)
{
	const char *desc = "id-ctrl: send an Identify Controller command to "\
		"the given device and report information about the specified "\
		"controller in human-readable or "\
		"binary format. Can also return binary vendor-specific "\
		"controller attributes.";
	const char *vendor_specific = "dump binary vendor infos";
	const char *raw_binary = "show infos in binary format";
	const char *human_readable = "show infos in readable format";
	int err;
	struct nvme_id_ctrl ctrl;

	struct config {
		__u8  vendor_specific;
		__u8  raw_binary;
		__u8  human_readable;
	};
	struct config cfg;

	const struct config defaults = {
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"vendor-specific", "", CFG_NONE, &defaults.vendor_specific, no_argument, vendor_specific},
		{"v",               "", CFG_NONE, &defaults.vendor_specific, no_argument, vendor_specific},
		{"raw-binary",      "", CFG_NONE, &defaults.raw_binary,      no_argument, raw_binary},
		{"b",               "", CFG_NONE, &defaults.raw_binary,      no_argument, raw_binary},
		{"human-readable",  "", CFG_NONE, &defaults.human_readable,  no_argument, human_readable},
		{"H",               "", CFG_NONE, &defaults.human_readable,  no_argument, human_readable},
		{0}
	};

	argconfig_parse(argc, argv, desc, command_line_options,
			&defaults, &cfg, sizeof(cfg));

	get_dev(1, argc, argv);

	err = identify(0, &ctrl, 1);
	if (!err) {
		if (cfg.raw_binary)
			d_raw((unsigned char *)&ctrl, sizeof(ctrl));
		else
			show_nvme_id_ctrl(&ctrl, cfg.vendor_specific, cfg.human_readable);
	}
	else if (err > 0)
		fprintf(stderr, "NVMe Status:%s(%x)\n",
				nvme_status_to_string(err), err);

	return err;
}

static int id_ns(int argc, char **argv)
{
	const char *desc = "id-ns: send an Identify Namespace command to the "\
		"given device, returns properties of the specified namespace "\
		"in either human-readable or binary format. Can also return "\
		"binary vendor-specific namespace attributes.";
	const char *vendor_specific = "dump binary vendor infos";
	const char *raw_binary = "show infos in binary format";
	const char *human_readable = "show infos in readable format";
	const char *namespace_id = "name of desired namespace";
	struct nvme_id_ns ns;
	int err;

	struct config {
		__u32 namespace_id;
		__u8  vendor_specific;
		__u8  raw_binary;
		__u8  human_readable;
	};
	struct config cfg;

	const struct config defaults = {
		.namespace_id    = 0,
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"namespace-id",    "NUM", CFG_POSITIVE, &defaults.namespace_id,    required_argument, namespace_id},
		{"n",               "NUM", CFG_POSITIVE, &defaults.namespace_id,    required_argument, namespace_id},
		{"vendor-specific", "",    CFG_NONE,     &defaults.vendor_specific, no_argument,       vendor_specific},
		{"v",               "",    CFG_NONE,     &defaults.vendor_specific, no_argument,       vendor_specific},
		{"raw-binary",      "",    CFG_NONE,     &defaults.raw_binary,      no_argument,       raw_binary},
		{"b",               "",    CFG_NONE,     &defaults.raw_binary,      no_argument,       raw_binary},
		{"human-readable",  "",    CFG_NONE,     &defaults.human_readable,  no_argument,       human_readable},
		{"H",               "",    CFG_NONE,     &defaults.human_readable,  no_argument,       human_readable},
		{0}
	};

	argconfig_parse(argc, argv, desc, command_line_options,
			&defaults, &cfg, sizeof(cfg));

	get_dev(1, argc, argv);

	if (!cfg.namespace_id) {
		if (!S_ISBLK(nvme_stat.st_mode)) {
			fprintf(stderr,
				"%s: non-block device requires namespace-id param\n",
				devicename);
			exit(ENOTBLK);
		}
		cfg.namespace_id = ioctl(fd, NVME_IOCTL_ID);
		if (cfg.namespace_id <= 0) {
			perror(devicename);
			exit(errno);
		}
	}
	err = identify(cfg.namespace_id, &ns, 0);
	if (!err) {
		if (cfg.raw_binary)
			d_raw((unsigned char *)&ns, sizeof(ns));
		else
			show_nvme_id_ns(&ns, cfg.namespace_id, cfg.vendor_specific, cfg.human_readable);
	}
	else if (err > 0)
		fprintf(stderr, "NVMe Status:%s(%x) NSID:%d\n",
			nvme_status_to_string(err), err, cfg.namespace_id);
	return err;
}

static int get_ns_id(int argc, char **argv)
{
	int nsid;

	open_dev(argv[1]);
	if (!S_ISBLK(nvme_stat.st_mode)) {
		fprintf(stderr, "%s: requesting nsid from non-block device\n",
								devicename);
		exit(ENOTBLK);
	}
	nsid = ioctl(fd, NVME_IOCTL_ID);
	if (nsid <= 0) {
		perror(devicename);
		exit(errno);
	}
	printf("%s: namespace-id:%d\n", devicename, nsid);
	return 0;
}

char* nvme_feature_wl_hints_to_string(__u8 wh)
{
	switch (wh)
	{
	case 0:	return "No Workload";
	case 1:	return "Extended Idle Period with a Burst of Random Writes";
	case 2:	return "Heavy Sequential Writes";
	default:	return "Reserved";
	}
}

char* nvme_feature_temp_type_to_string(__u8 type)
{
	switch (type)
	{
	case 0:	return "Over Temperature Threshold";
	case 1:	return "Under Temperature Threshold";
	default:	return "Reserved";
	}
}

char* nvme_feature_temp_sel_to_string(__u8 sel)
{
	switch (sel)
	{
	case 0:	return "Composite Temperature";
	case 1:	return "Temperature Sensor 1";
	case 2:	return "Temperature Sensor 2";
	case 3:	return "Temperature Sensor 3";
	case 4:	return "Temperature Sensor 4";
	case 5:	return "Temperature Sensor 5";
	case 6:	return "Temperature Sensor 6";
	case 7:	return "Temperature Sensor 7";
	case 8:	return "Temperature Sensor 8";
	default:	return "Reserved";
	}
}

static void show_auto_pst(struct nvme_auto_pst *apst)
{
	int i;
		
	fprintf(stdout, "\tAuto PST Entries");
	fprintf(stdout,"\t.................\n");
	for (i = 0; i < 32; i++) {
		fprintf(stdout,"\tEntry[%2d]   \n", i);
		fprintf(stdout,"\t.................\n");
		fprintf(stdout,"\tIdle Time Prior to Transition (ITPT): %u ms\n", (apst[i].data & 0xffffff00) >> 8);
		fprintf(stdout,"\tIdle Transition Power State   (ITPS): %u\n", (apst[i].data & 0x000000f8) >> 3);
		fprintf(stdout,"\t.................\n");
	}
}

static void show_host_mem_buffer (struct nvme_host_mem_buffer *hmb)
{
	fprintf(stdout,"\tHost Memory Descriptor List Entry Count (HMDLEC): %u\n", hmb->hmdlec);
	fprintf(stdout,"\tHost Memory Descriptor List Address     (HMDLAU): %u\n", hmb->hmdlau);
	fprintf(stdout,"\tHost Memory Descriptor List Address     (HMDLAL): %u\n", hmb->hmdlal);
	fprintf(stdout,"\tHost Memory Buffer Size                  (HSIZE): %u\n", hmb->hsize);
}

static void nvme_feature_show_fields(__u32 fid, unsigned int result, unsigned char *buf)
{ 
    __u8 field; 
	uint64_t ull;
	
	switch (fid) 
	{ 
	case NVME_FEAT_ARBITRATION: 
		fprintf(stdout,"\tHigh Priority Weight   (HPW): %u\n", ((result & 0xff000000) >> 24) + 1);
		fprintf(stdout,"\tMedium Priority Weight (MPW): %u\n", ((result & 0x00ff0000) >> 16) + 1); 
		fprintf(stdout,"\tLow Priority Weight    (LPW): %u\n", ((result & 0x0000ff00) >> 8) + 1); 
		fprintf(stdout,"\tArbitration Burst       (AB): %u\n",  1 << (result & 0x00000007));
        break; 
	case NVME_FEAT_POWER_MGMT: 
		field =  (result & 0x000000E0) >> 5; 
		fprintf(stdout,"\tWorkload Hint (WH): %u - %s\n",  field, nvme_feature_wl_hints_to_string(field)); 
		fprintf(stdout,"\tPower State   (PS): %u\n",  result & 0x0000001f); 
		break; 
	case NVME_FEAT_LBA_RANGE: 
		field =  result & 0x0000003f; 
		fprintf(stdout,"\tNumber of LBA Ranges (NUM): %u\n",  field+1);
		show_lba_range((struct nvme_lba_range_type *)buf, field);
		break;                
	case NVME_FEAT_TEMP_THRESH:
		field = (result & 0x00300000) >> 20;
		fprintf(stdout,"\tThreshold Type Select         (THSEL): %u - %s\n", field, nvme_feature_temp_type_to_string(field));
		field = (result & 0x000f0000) >> 16;
		fprintf(stdout,"\tThreshold Temperature Select (TMPSEL): %u - %s\n", field, nvme_feature_temp_sel_to_string(field));
		fprintf(stdout,"\tTemperature Threshold         (TMPTH): %u C\n", (result & 0x0000ffff) - 273);
		break;
	case NVME_FEAT_ERR_RECOVERY:
		fprintf(stdout,"\tDeallocated or Unwritten Logical Block Error Enable (DULBE): %s\n", ((result & 0x00010000) >> 16) ? "Enabled":"Disabled"); 
		fprintf(stdout,"\tTime Limited Error Recovery                          (TLER): %u ms\n", (result & 0x0000ffff) * 100);		 
		break;
	case NVME_FEAT_VOLATILE_WC:
		fprintf(stdout,"\tVolatile Write Cache Enable (WCE): %s\n", (result & 0x00000001) ? "Enabled":"Disabled"); 		 
		break;
	case NVME_FEAT_NUM_QUEUES: 
		fprintf(stdout,"\tNumber of IO Completion Queues Allocated (NCQA): %u\n", ((result & 0xffff0000) >> 16) + 1); 
		fprintf(stdout,"\tNumber of IO Submission Queues Allocated (NSQA): %u\n",  (result & 0x0000ffff) + 1); 
		break; 
	case NVME_FEAT_IRQ_COALESCE: 
		fprintf(stdout,"\tAggregation Time     (TIME): %u ms\n", ((result & 0x0000ff00) >> 8) * 100); 
		fprintf(stdout,"\tAggregation Threshold (THR): %u\n",  (result & 0x000000ff) + 1); 
		break; 
	case NVME_FEAT_IRQ_CONFIG: 
		fprintf(stdout,"\tCoalescing Disable (CD): %s\n", ((result & 0x00010000) >> 16) ? "True":"False"); 
		fprintf(stdout,"\tInterrupt Vector   (IV): %u\n",  result & 0x0000ffff); 
		break; 	
	case NVME_FEAT_WRITE_ATOMIC: 
		fprintf(stdout,"\tDisable Normal (DN): %s\n", (result & 0x00000001) ? "True":"False"); 
		break;	
	case NVME_FEAT_ASYNC_EVENT: 
		fprintf(stdout,"\tFirmware Activation Notices     : %s\n", ((result & 0x00000200) >> 9) ? "Send async event":"Do not send async event");
	    fprintf(stdout,"\tNamespace Attribute Notices     : %s\n", ((result & 0x00000100) >> 8) ? "Send NameSpace Attribute Changed event":"Do not send NameSpace Attribute Changed event");
		fprintf(stdout,"\tSMART / Health Critical Warnings: %s\n", (result & 0x000000ff) ? "Send async event":"Do not send async event"); 
		break;	
	case NVME_FEAT_AUTO_PST: 
		fprintf(stdout,"\tAutonomous Power State Transition Enable (APSTE): %s\n", (result & 0x00000001) ? "Enabled":"Disabled"); 
		show_auto_pst((struct nvme_auto_pst *)buf);
		break;	
	case NVME_FEAT_HOST_MEM_BUF:
		fprintf(stdout,"\tMemory Return       (MR): %s\n", ((result & 0x00000002) >> 1) ? "True":"False");
		fprintf(stdout,"\tEnable Host Memory (EHM): %s\n", (result & 0x00000001) ? "Enabled":"Disabled");
		show_host_mem_buffer((struct nvme_host_mem_buffer *)buf);
		break;
	case NVME_FEAT_SW_PROGRESS:
		fprintf(stdout,"\tPre-boot Software Load Count (PBSLC): %u\n", result & 0x000000ff); 
		break;
	case NVME_FEAT_HOST_ID:
		ull =  buf[7]; ull <<= 8; ull |= buf[6]; ull <<= 8; ull |= buf[5]; ull <<= 8;
		ull |= buf[4]; ull <<= 8; ull |= buf[3]; ull <<= 8; ull |= buf[2]; ull <<= 8; 
		ull |= buf[1]; ull <<= 8; ull |= buf[0];
		fprintf(stdout,"\tHost Identifier (HOSTID):  %" PRIu64 "\n", ull);
		break;
	case NVME_FEAT_RESV_MASK:
		fprintf(stdout,"\tMask Reservation Preempted Notification  (RESPRE): %s\n", ((result & 0x00000008) >> 3) ? "True":"False");
		fprintf(stdout,"\tMask Reservation Released Notification   (RESREL): %s\n", ((result & 0x00000004) >> 2) ? "True":"False");
		fprintf(stdout,"\tMask Registration Preempted Notification (REGPRE): %s\n", ((result & 0x00000002) >> 1) ? "True":"False");  
		break;
	case NVME_FEAT_RESV_PERSIST:
		fprintf(stdout,"\tPersist Through Power Loss (PTPL): %s\n", (result & 0x00000001) ? "True":"False");  
		break;	
	}
}

static int nvme_feature(int opcode, void *buf, int data_len, __u32 fid,
					__u32 nsid, __u32 cdw11, __u32 *result)
{
	int err;
	struct nvme_admin_cmd cmd;

	memset(&cmd, 0, sizeof(cmd));
	cmd.opcode = opcode;
	cmd.nsid = nsid;
	cmd.cdw10 = fid;
	cmd.cdw11 = cdw11;
	cmd.addr = (__u64)buf;
	cmd.data_len = data_len;

	err = ioctl(fd, NVME_IOCTL_ADMIN_CMD, &cmd);
	if (err >= 0 && result)
			*result = cmd.result;
	return err;
}

static int get_feature(int argc, char **argv)
{
	const char *desc = "get-feature: read operating parameters of the "\
		"specified controller. Operating parameters are grouped "\
		"and identified by Feature Identifiers; each Feature "\
		"Identifier contains one or more attributes that may affect "\
		"behaviour of the feature. Each Feature has three possible "\
		"settings: default, saveable, and current. If a Feature is "\
		"saveable, it may be modified by set-feature. Default values "\
		"are vendor-specific and not changeable. Use set-feature to "\
		"change saveable Features.";
	const char *raw_binary = "show infos in binary format";
	const char *namespace_id = "name of desired namespace";
	const char *feature_id = "hexadecimal feature name";
	const char *sel = "[0-3]: curr./default/saved/supp.";
	const char *data_len = "buffer len (if) data is returned";
	const char *cdw11 = "dword 11 for interrupt vector config";
	const char *human_readable = "show infos in readable format";
	int err;
	unsigned int result, cdw10 = 0;
	void *buf = NULL;

	struct config {
		__u32 namespace_id;
		__u32 feature_id;
		__u8  sel;
		__u32 cdw11;
		__u32 data_len;
		__u8  raw_binary;
		__u8  human_readable;
	};
	struct config cfg;

	const struct config defaults = {
		.namespace_id = 0,
		.feature_id   = 0,
		.sel          = 0,
		.cdw11        = 0,
		.data_len     = 0,
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"namespace-id", "NUM",  CFG_POSITIVE, &defaults.namespace_id, required_argument, namespace_id},
		{"n",            "NUM",  CFG_POSITIVE, &defaults.namespace_id, required_argument, namespace_id},
		{"feature-id",   "NUM",  CFG_POSITIVE, &defaults.feature_id,   required_argument, feature_id},
		{"f",            "NUM",  CFG_POSITIVE, &defaults.feature_id,   required_argument, feature_id},
		{"sel",          "NUM",  CFG_BYTE,     &defaults.sel,          required_argument, sel},
		{"s",            "NUM",  CFG_BYTE,     &defaults.sel,          required_argument, sel},
		{"data-len",     "NUM",  CFG_POSITIVE, &defaults.data_len,     required_argument, data_len},
		{"l",            "NUM",  CFG_POSITIVE, &defaults.data_len,     required_argument, data_len},
		{"raw-binary",   "",     CFG_NONE,     &defaults.raw_binary,   no_argument,       raw_binary},
		{"b",            "",     CFG_NONE,     &defaults.raw_binary,   no_argument,       raw_binary},
		{"cdw11",        "NUM",  CFG_POSITIVE, &defaults.cdw11,        required_argument, cdw11},
		{"human-readable",  "",    CFG_NONE,     &defaults.human_readable,  no_argument,       human_readable},		
		{"H",               "", CFG_NONE, &defaults.human_readable,  no_argument, human_readable},
		{0}
	};

	argconfig_parse(argc, argv, desc, command_line_options,
			&defaults, &cfg, sizeof(cfg));

	get_dev(1, argc, argv);

	if (cfg.sel > 7) {
		fprintf(stderr, "invalid 'select' param:%d\n", cfg.sel);
		return EINVAL;
	}
	if (!cfg.feature_id) {
		fprintf(stderr, "feature-id required param\n");
		return EINVAL;
	}
	
	switch (cfg.feature_id)
	{
	case NVME_FEAT_LBA_RANGE:
		cfg.data_len = 4096;
		break;
	case NVME_FEAT_AUTO_PST:
		cfg.data_len = 256;
		break;
	case NVME_FEAT_HOST_MEM_BUF:
		cfg.data_len = 4096;
		break;
	case NVME_FEAT_HOST_ID:
		cfg.data_len = 8;
		break;
	}
	
	if (cfg.data_len)
		buf = malloc(cfg.data_len);

	cdw10 = cfg.sel << 8 | cfg.feature_id;
	err = nvme_feature(nvme_admin_get_features, buf, cfg.data_len, cdw10,
			   cfg.namespace_id, cfg.cdw11, &result);
	if (!err) { 
		printf("get-feature: 0x%02X (%s), %s value: %#08x\n", cfg.feature_id, 
				nvme_feature_to_string(cfg.feature_id), nvme_select_to_string(cfg.sel), result); 
		if (cfg.human_readable)
			nvme_feature_show_fields(cfg.feature_id, result, buf);
		else {
			if (buf) {
				if (!cfg.raw_binary) 
					d(buf, cfg.data_len, 16, 1);
				else
					d_raw(buf, cfg.data_len);
			}
		}
	}
	else if (err > 0)
		fprintf(stderr, "NVMe Status:%s(%x)\n",
				nvme_status_to_string(err), err);
	if (buf)
		free(buf);
	return err;
}

static int fw_download(int argc, char **argv)
{
	const char *desc = "fw-download: copy all or part of a firmware to "\
		"a controller for future update. Optionally, specify how "\
		"many KiB of the firmware to transfer at once (offset will "\
		"start at 0 and automatically adjust based on xfer size "\
		"unless fw is split across multiple files). May be submitted "\
		"while outstanding commands exist on the Admin and IO "\
		"Submission Queues. Activate downloaded firmware with "\
		"fw-activate and reset the device to apply the downloaded firmware.";
	const char *fw = "firmware file (required)";
	const char *xfer = "transfer chunksize limit";
	const char *offset = "starting dword offset, default 0";
	int err, fw_fd = -1;
	unsigned int fw_size;
	struct stat sb;
	struct nvme_admin_cmd cmd;
	void *fw_buf;

	struct config {
		char  *fw;
		__u32 xfer;
		__u32 offset;
	};
	struct config cfg;

	const struct config defaults = {
		.fw     = "",
		.xfer   = 4096,
		.offset = 0,
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"fw",     "FILE", CFG_STRING,   &defaults.fw,     required_argument, fw},
		{"f",      "FILE", CFG_STRING,   &defaults.fw,     required_argument, fw},
		{"xfer",   "NUM",  CFG_POSITIVE, &defaults.xfer,   required_argument, xfer},
		{"x",      "NUM",  CFG_POSITIVE, &defaults.xfer,   required_argument, xfer},
		{"offset", "NUM",  CFG_POSITIVE, &defaults.offset, required_argument, offset},
		{"o",      "NUM",  CFG_POSITIVE, &defaults.offset, required_argument, offset},
		{0}
	};

	argconfig_parse(argc, argv, desc, command_line_options,
			&defaults, &cfg, sizeof(cfg));

	get_dev(1, argc, argv);

	fw_fd = open(cfg.fw, O_RDONLY);
	cfg.offset <<= 2;
	if (fw_fd < 0) {
		fprintf(stderr, "no firmware file provided\n");
		return EINVAL;
	}
	err = fstat(fw_fd, &sb);
	if (err < 0) {
		perror("fstat");
		exit(errno);
	}

	fw_size = sb.st_size;
	if (fw_size & 0x3) {
		fprintf(stderr, "Invalid size:%d for f/w image\n", fw_size);
		return EINVAL;
	}
	if (posix_memalign(&fw_buf, getpagesize(), fw_size)) {
		fprintf(stderr, "No memory for f/w size:%d\n", fw_size);
		return ENOMEM;
	}
	if (cfg.xfer == 0 || cfg.xfer % 4096)
		cfg.xfer = 4096;
	if (read(fw_fd, fw_buf, fw_size) != ((ssize_t)(fw_size)))
		return EIO;

	while (fw_size > 0) {
		cfg.xfer = min(cfg.xfer, fw_size);

		memset(&cmd, 0, sizeof(cmd));
		cmd.opcode   = nvme_admin_download_fw;
		cmd.addr     = (__u64)fw_buf;
		cmd.data_len = cfg.xfer;
		cmd.cdw10    = (cfg.xfer >> 2) - 1;
		cmd.cdw11    = cfg.offset >> 2;

		err = ioctl(fd, NVME_IOCTL_ADMIN_CMD, &cmd);
		if (err < 0) {
			perror("ioctl");
			exit(errno);
		} else if (err != 0) {
			fprintf(stderr, "NVME Admin command error:%s(%x)\n",
					nvme_status_to_string(err), err);
			break;
		}
		fw_buf     += cfg.xfer;
		fw_size    -= cfg.xfer;
		cfg.offset += cfg.xfer;
	}
	if (!err)
		printf("Firmware download success\n");
	return err;
}

static int fw_activate(int argc, char **argv)
{
	const char *desc = "fw-activate: verify downloaded firmware image and "\
		"commit to specific firmware slot. Device is not automatically "\
		"reset following firmware activation. A reset may be issued "\
		"with an 'echo 1 > /sys/class/misc/nvmeX/device/reset'. "\
		"Ensure nvmeX is the device you just activated before reset.";
	const char *slot = "firmware slot to activate";
	const char *action = "[0-2]: replacement action";
	int err;
	struct nvme_admin_cmd cmd;

	struct config {
		__u8 slot;
		__u8 action;
	};
	struct config cfg;

	const struct config defaults = {
		.slot   = 0,
		.action = 0,
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"slot",   "NUM", CFG_BYTE, &defaults.slot,   required_argument, slot},
		{"s",      "NUM", CFG_BYTE, &defaults.slot,   required_argument, slot},
		{"action", "NUM", CFG_BYTE, &defaults.action, required_argument, action},
		{"a",      "NUM", CFG_BYTE, &defaults.action, required_argument, action},
		{0}
	};

	argconfig_parse(argc, argv, desc, command_line_options,
			&defaults, &cfg, sizeof(cfg));

	get_dev(1, argc, argv);

	if (cfg.slot > 7) {
		fprintf(stderr, "invalid slot:%d\n", cfg.slot);
		return EINVAL;
	}
	if (cfg.action > 3) {
		fprintf(stderr, "invalid action:%d\n", cfg.action);
		return EINVAL;
	}

	memset(&cmd, 0, sizeof(cmd));
	cmd.opcode = nvme_admin_activate_fw;
	cmd.cdw10  = (cfg.action << 3) | cfg.slot;

	err = ioctl(fd, NVME_IOCTL_ADMIN_CMD, &cmd);
	if (err < 0)
		perror("ioctl");
	else if (err != 0)
		if (err == NVME_SC_FIRMWARE_NEEDS_RESET)
			printf("Success activating firmware action:%d slot:%d, but a conventional reset is required\n",
			       cfg.action, cfg.slot);
		else
			fprintf(stderr, "NVME Admin command error:%s(%x)\n",
						nvme_status_to_string(err), err);
	else
		printf("Success activating firmware action:%d slot:%d\n",
		       cfg.action, cfg.slot);
	return err;
}

static int show_registers(int argc, char **argv)
{
	int opt, long_index;
	struct nvme_bar *bar;
	static struct option opts[] = {};

	while ((opt = getopt_long(argc, (char **)argv, "", opts,
					&long_index)) != -1);
	get_dev(optind, argc, argv);

	get_registers(&bar, 1);
	printf("cap     : %"PRIx64"\n", (uint64_t)bar->cap);
	printf("version : %x\n", bar->vs);
	printf("intms   : %x\n", bar->intms);
	printf("intmc   : %x\n", bar->intmc);
	printf("cc      : %x\n", bar->cc);
	printf("csts    : %x\n", bar->csts);
	printf("nssr    : %x\n", bar->nssr);
	printf("aqa     : %x\n", bar->aqa);
	printf("asq     : %"PRIx64"\n", (uint64_t)bar->asq);
	printf("acq     : %"PRIx64"\n", (uint64_t)bar->acq);
	printf("cmbloc  : %x\n", bar->cmbloc);
	printf("cmbsz   : %x\n", bar->cmbsz);

	return 0;
}

static int format(int argc, char **argv)
{
	const char *desc = "format: re-format a specified namespace on the "\
		"given device. Can erase all data in namespace (user "\
		"data erase) or delete data encryption key if specified. "\
		"Can also be used to change LBAF such that device may "\
		"disappear from all lists since capacity superficially "\
		"appears to be 0.";
	const char *namespace_id = "name of desired namespace";
	const char *lbaf = "LBA format to apply (req'd)";
	const char *ses = "[0-2]: secure erase";
	const char *pil = "[0-3]: protection info location";
	const char *pi = "[0-1]: protection info off/on";
	const char *ms = "[0-1]: extended format off/on";
	const char *timeout = "timeout value";
	int err;
	struct nvme_admin_cmd cmd;

	struct config {
		__u32 namespace_id;
		__u32 timeout;
		__u8  lbaf;
		__u8  ses;
		__u8  pi;
		__u8  pil;
		__u8  ms;
	};
	struct config cfg;

	const struct config defaults = {
		.namespace_id = 0xffffffff,
		.timeout      = 120000,
		.lbaf         = 0,
		.ses          = 0,
		.pi           = 0,
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"namespace-id", "NUM",  CFG_POSITIVE, &defaults.namespace_id, required_argument, namespace_id},
		{"n",            "NUM",  CFG_POSITIVE, &defaults.namespace_id, required_argument, namespace_id},
		{"timeout",      "NUM",  CFG_POSITIVE, &defaults.timeout,      required_argument, timeout},
		{"t",            "NUM",  CFG_POSITIVE, &defaults.timeout,      required_argument, timeout},
		{"lbaf",         "NUM",  CFG_BYTE,     &defaults.lbaf,         required_argument, lbaf},
		{"l",            "NUM",  CFG_BYTE,     &defaults.lbaf,         required_argument, lbaf},
		{"ses",          "NUM",  CFG_BYTE,     &defaults.ses,          required_argument, ses},
		{"s",            "NUM",  CFG_BYTE,     &defaults.ses,          required_argument, ses},
		{"pi",           "NUM",  CFG_BYTE,     &defaults.pi,           required_argument, pi},
		{"i",            "NUM",  CFG_BYTE,     &defaults.pi,           required_argument, pi},
		{"pil",          "NUM",  CFG_BYTE,     &defaults.pil,          required_argument, pil},
		{"p",            "NUM",  CFG_BYTE,     &defaults.pil,          required_argument, pil},
		{"ms",           "NUM",  CFG_BYTE,     &defaults.ms,           required_argument, ms},
		{"m",            "NUM",  CFG_BYTE,     &defaults.ms,           required_argument, ms},
		{0}
	};

	argconfig_parse(argc, argv, desc, command_line_options,
			&defaults, &cfg, sizeof(cfg));

	get_dev(1, argc, argv);

	if (cfg.ses > 7) {
		fprintf(stderr, "invalid secure erase settings:%d\n", cfg.ses);
		return EINVAL;
	}
	if (cfg.lbaf > 15) {
		fprintf(stderr, "invalid lbaf:%d\n", cfg.lbaf);
		return EINVAL;
	}
	if (cfg.pi > 7) {
		fprintf(stderr, "invalid pi:%d\n", cfg.pi);
		return EINVAL;
	}
	if (S_ISBLK(nvme_stat.st_mode)) {
		cfg.namespace_id = ioctl(fd, NVME_IOCTL_ID);
		if (cfg.namespace_id <= 0) {
			fprintf(stderr,
				"%s: failed to return namespace id\n",
				devicename);
			return errno;
		}
	}

	memset(&cmd, 0, sizeof(cmd));
	cmd.opcode = nvme_admin_format_nvm;
	cmd.nsid   = cfg.namespace_id;
	cmd.cdw10  = (cfg.lbaf << 0) | (cfg.ms << 4) | (cfg.pi << 5) | (cfg.pil << 8) | (cfg.ses << 9);
	cmd.timeout_ms = cfg.timeout;

	err = ioctl(fd, NVME_IOCTL_ADMIN_CMD, &cmd);
	if (err < 0)
		perror("ioctl");
	else if (err != 0)
		fprintf(stderr, "NVME Admin command error:%s(%x)\n",
					nvme_status_to_string(err), err);
	else {
		printf("Success formatting namespace:%x\n", cfg.namespace_id);
		ioctl(fd, BLKRRPART);
	}
	return err;
}

static int set_feature(int argc, char **argv)
{
	const char *desc = "set-feature: modify the saveable/changeable "\
		"current operating parameters of the controller. Operating "\
		"parameters are grouped and identified by Feature "\
		"Identifiers. Feature settings can be applied to the entire "\
		"controller and all associated namespaces, or to only a few "\
		"namespace(s) associated with the controller. Default values "\
		"for each Feature are vendor-specific and may not be modified."\
		"Use get-feature to determine which Features are supported by "\
		"the controller and are saveable/changeable.";
	const char *namespace_id = "desired namespace";
	const char *feature_id = "hex feature name (req'd)";
	const char *data_len = "buffer len (if) data returned";
	const char *data = "optional file (default stdin)";
	const char *value = "new value of feature (req'd)";
	int err;
	unsigned int result;
	void *buf = NULL;
	int fd = STDIN_FILENO;

	struct config {
		char *file;
		__u32 namespace_id;
		__u32 feature_id;
		__u32 value;
		__u32 data_len;
	};
	struct config cfg;

	const struct config defaults = {
		.file         = "",
		.namespace_id = 0,
		.feature_id   = 0,
		.value        = 0,
		.data_len     = 0,
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"namespace-id", "NUM",  CFG_POSITIVE, &defaults.namespace_id, required_argument, namespace_id},
		{"n",            "NUM",  CFG_POSITIVE, &defaults.namespace_id, required_argument, namespace_id},
		{"feature-id",   "NUM",  CFG_POSITIVE, &defaults.feature_id,   required_argument, feature_id},
		{"f",            "NUM",  CFG_POSITIVE, &defaults.feature_id,   required_argument, feature_id},
		{"value",        "NUM",  CFG_POSITIVE, &defaults.value,        required_argument, value},
		{"v",            "NUM",  CFG_POSITIVE, &defaults.value,        required_argument, value},
		{"data-len",     "NUM",  CFG_POSITIVE, &defaults.data_len,     required_argument, data_len},
		{"l",            "NUM",  CFG_POSITIVE, &defaults.data_len,     required_argument, data_len},
		{"data",         "FILE", CFG_STRING,   &defaults.file,         required_argument, data},
		{"d",            "FILE", CFG_STRING,   &defaults.file,         required_argument, data},
		{0}
	};

	argconfig_parse(argc, argv, desc, command_line_options,
			&defaults, &cfg, sizeof(cfg));

	get_dev(1, argc, argv);

	if (cfg.value == -1) {
		fprintf(stderr, "feature value required param\n");
		return EINVAL;
	}
	if (!cfg.feature_id) {
		fprintf(stderr, "feature-id required param\n");
		return EINVAL;
	}
	if (cfg.feature_id == NVME_FEAT_LBA_RANGE)
		cfg.data_len = 4096;
	if (cfg.data_len)
		buf = malloc(cfg.data_len);
	if (buf) {
		if (strlen(cfg.file)) {
			fd = open(cfg.file, O_RDONLY);
			if (fd <= 0) {
				fprintf(stderr, "no firmware file provided\n");
				return -EINVAL;
			}
		}
		if (read(fd, (void *)buf, cfg.data_len) < 0) {
			fprintf(stderr, "failed to read data buffer from input file\n");
			return EINVAL;
		}
	}

	err = nvme_feature(nvme_admin_set_features, buf, cfg.data_len, cfg.feature_id,
			   cfg.namespace_id, cfg.value, &result);
	if (!err) {
		printf("set-feature:%d(%s), value:%#08x\n", cfg.feature_id,
			nvme_feature_to_string(cfg.feature_id), result);
		if (buf) {
			if (cfg.feature_id == NVME_FEAT_LBA_RANGE)
				show_lba_range((struct nvme_lba_range_type *)buf,
								result);
			else
				d(buf, cfg.data_len, 16, 1);
		}
	}
	else if (err > 0)
		fprintf(stderr, "NVMe Status:%s(%x)\n",
				nvme_status_to_string(err), err);
	if (buf)
		free(buf);
	return err;
}

static int sec_send(int argc, char **argv)
{
	struct stat sb;
	struct nvme_admin_cmd cmd;
	const char *desc = "security-send: transfer security protocol data to "\
		"a controller. Security Receives for the same protocol should be "\
		"performed after Security Sends. The security protocol field "\
		"associates Security Sends (security-send) and Security Receives "\
		"(security-recv).";
	const char *file = "transfer payload";
	const char *secp = "security protocol (cf. SPC-4)";
	const char *spsp = "security-protocol-specific (cf. SPC-4)";
	const char *tl = "transfer length (cf. SPC-4)";
	int err, sec_fd = -1;
	void *sec_buf;
	unsigned int sec_size;

	struct config {
		char  *file;
		__u8  secp;
		__u16 spsp;
		__u32 tl;
	};
	struct config cfg;

	const struct config defaults = {
		.file = "",
		.secp = 0,
		.spsp = 0,
		.tl   = 0,
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"file",       "FILE",  CFG_STRING,   &defaults.file,       required_argument, file},
		{"f",          "FILE",  CFG_STRING,   &defaults.file,       required_argument, file},
		{"secp",       "NUM",   CFG_BYTE,     &defaults.secp,       required_argument, secp},
		{"p",          "NUM",   CFG_BYTE,     &defaults.secp,       required_argument, secp},
		{"spsp",       "NUM",   CFG_SHORT,    &defaults.spsp,       required_argument, spsp},
		{"s",          "NUM",   CFG_SHORT,    &defaults.spsp,       required_argument, spsp},
		{"tl",         "NUM",   CFG_POSITIVE, &defaults.tl,         required_argument, tl},
		{"t",          "NUM",   CFG_POSITIVE, &defaults.tl,         required_argument, tl},
		{0}
	};

	argconfig_parse(argc, argv, desc, command_line_options,
			&defaults, &cfg, sizeof(cfg));

	get_dev(1, argc, argv);

	sec_fd = open(cfg.file, O_RDONLY);
	if (sec_fd < 0) {
		fprintf(stderr, "no firmware file provided\n");
		return EINVAL;
	}
	err = fstat(sec_fd, &sb);
	if (err < 0) {
		perror("fstat");
		return errno;
	}
	sec_size = sb.st_size;
	if (posix_memalign(&sec_buf, getpagesize(), sec_size)) {
		fprintf(stderr, "No memory for security size:%d\n", sec_size);
		return ENOMEM;
	}

	memset(&cmd, 0, sizeof(cmd));
	cmd.opcode   = nvme_admin_security_send;
	cmd.cdw10    = cfg.secp << 24 | cfg.spsp << 8;
	cmd.cdw11    = cfg.tl;
	cmd.data_len = sec_size;
	cmd.addr     = (__u64)sec_buf;

	err = ioctl(fd, NVME_IOCTL_ADMIN_CMD, &cmd);
	if (err < 0)
		return errno;
	else if (err != 0)
		fprintf(stderr, "NVME Security Send Command Error:%d\n", err);
	else
		printf("NVME Security Send Command Success:%d\n", cmd.result);
	return err;
}

static int flush(int argc, char **argv)
{
	struct nvme_passthru_cmd cmd;
	const char *desc = "flush: commit data and metadata associated with "\
	"given namespaces to nonvolatile media. Applies to all commands "\
	"finished before the flush was submitted. Additional data may also be "\
	"flushed by the controller, from any namespace, depending on controller and "\
	"associated namespace status.";
	const char *namespace_id = "name of desired namespace";
	int err;

	struct config {
		__u32 namespace_id;
	};
	struct config cfg;

	const struct config defaults = {
		.namespace_id = 0xffffffff,
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"namespace-id", "NUM",  CFG_POSITIVE,    &defaults.namespace_id, required_argument, namespace_id},
		{"n",            "NUM",  CFG_POSITIVE,    &defaults.namespace_id, required_argument, namespace_id},
		{0}
	};

	argconfig_parse(argc, argv, desc, command_line_options,
			&defaults, &cfg, sizeof(cfg));

	get_dev(1, argc, argv);

	memset(&cmd, 0, sizeof(cmd));
	cmd.opcode = nvme_cmd_flush;
	cmd.nsid   = cfg.namespace_id;

	err = ioctl(fd, NVME_IOCTL_IO_CMD, &cmd);
	if (err < 0)
		return errno;
	else if (err != 0)
		fprintf(stderr, "NVME IO command error:%s(%x)\n",
				nvme_status_to_string(err), err);
	else
		printf("NVMe Flush: success\n");
	return 0;
}

static int resv_acquire(int argc, char **argv)
{
	struct nvme_passthru_cmd cmd;
	const char *desc = "resv-acquire: obtain a reservation on a given "\
		"namespace. Only one reservation is allowed at a time on a "\
		"given namespace, though multiple controllers may register "\
		"with that namespace. Namespace reservation will abort with "\
		"status Reservation Conflict if the given namespace is "\
		"already reserved.";
	const char *namespace_id = "name of desired namespace";
	const char *crkey = "current reservation key";
	const char *prkey = "pre-empt reservation key";
	const char *rtype = "hex reservation type";
	const char *racqa = "reservation acquiry action";
	const char *iekey = "ignore existing res. key";
	int err;
	__u64 payload[2];

	struct config {
		__u32 namespace_id;
		__u64 crkey;
		__u64 prkey;
		__u8  rtype;
		__u8  racqa;
		__u8  iekey;
	};
	struct config cfg;

	const struct config defaults = {
		.namespace_id = 0,
		.crkey        = 0,
		.prkey        = 0,
		.rtype        = 0,
		.racqa        = 0,
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"namespace-id", "NUM",  CFG_POSITIVE,    &defaults.namespace_id, required_argument, namespace_id},
		{"n",            "NUM",  CFG_POSITIVE,    &defaults.namespace_id, required_argument, namespace_id},
		{"crkey",        "NUM",  CFG_LONG_SUFFIX, &defaults.crkey,        required_argument, crkey},
		{"c",            "NUM",  CFG_LONG_SUFFIX, &defaults.crkey,        required_argument, crkey},
		{"prkey",        "NUM",  CFG_LONG_SUFFIX, &defaults.prkey,        required_argument, prkey},
		{"p",            "NUM",  CFG_LONG_SUFFIX, &defaults.prkey,        required_argument, prkey},
		{"rtype",        "NUM",  CFG_BYTE,        &defaults.rtype,        required_argument, rtype},
		{"t",            "NUM",  CFG_BYTE,        &defaults.rtype,        required_argument, rtype},
		{"racqa",        "NUM",  CFG_BYTE,        &defaults.racqa,        required_argument, racqa},
		{"a",            "NUM",  CFG_BYTE,        &defaults.racqa,        required_argument, racqa},
		{"iekey",        "",     CFG_NONE,        &defaults.iekey,        no_argument,       iekey},
		{"i",            "",     CFG_NONE,        &defaults.iekey,        no_argument,       iekey},
		{0}
	};

	argconfig_parse(argc, argv, desc, command_line_options,
			&defaults, &cfg, sizeof(cfg));

	get_dev(1, argc, argv);

	if (!cfg.namespace_id) {
		if (!S_ISBLK(nvme_stat.st_mode)) {
			fprintf(stderr,
				"%s: non-block device requires namespace-id param\n",
				devicename);
			exit(ENOTBLK);
		}
		cfg.namespace_id = ioctl(fd, NVME_IOCTL_ID);
		if (cfg.namespace_id <= 0) {
			fprintf(stderr,
				"%s: failed to return namespace id\n",
				devicename);
			return errno;
		}
	}
	if (cfg.racqa > 7) {
		fprintf(stderr, "invalid racqa:%d\n", cfg.racqa);
		return EINVAL;
	}

	payload[0] = cfg.crkey;
	payload[1] = cfg.prkey;

	memset(&cmd, 0, sizeof(cmd));
	cmd.opcode   = nvme_cmd_resv_acquire;
	cmd.nsid     = cfg.namespace_id;
	cmd.cdw10    = cfg.rtype << 8 | cfg.iekey << 3 | cfg.racqa;
	cmd.addr     = (__u64)payload;
	cmd.data_len = sizeof(payload);

	err = ioctl(fd, NVME_IOCTL_IO_CMD, &cmd);
	if (err < 0)
		return errno;
	else if (err != 0)
		fprintf(stderr, "NVME IO command error:%04x\n", err);
	else
		printf("NVME Reservation Acquire success\n");
	return 0;
}

static int resv_register(int argc, char **argv)
{
	struct nvme_passthru_cmd cmd;
	const char *desc = "resv-register: register, de-register, or "\
		"replace a controller's reservation on a given namespace. "\
		"Only one reservation at a time is allowed on any namespace.";
	const char *namespace_id = "name of desired namespace";
	const char *crkey = "current reservation key";
	const char *iekey = "ignore existing res. key";
	const char *nrkey = "new reservation key";
	const char *rrega = "reservation registration action";
	const char *cptpl = "change persistence through power loss setting";
	int err;
	__u64 payload[2];

	struct config {
		__u32 namespace_id;
		__u64 crkey;
		__u64 nrkey;
		__u8  rrega;
		__u8  cptpl;
		__u8  iekey;
	};
	struct config cfg;

	const struct config defaults = {
		.namespace_id = 0,
		.crkey        = 0,
		.nrkey        = 0,
		.rrega        = 0,
		.cptpl        = 0,
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"namespace-id", "NUM",  CFG_POSITIVE,    &defaults.namespace_id, required_argument, namespace_id},
		{"n",            "NUM",  CFG_POSITIVE,    &defaults.namespace_id, required_argument, namespace_id},
		{"crkey",        "NUM",  CFG_LONG_SUFFIX, &defaults.crkey,        required_argument, crkey},
		{"c",            "NUM",  CFG_LONG_SUFFIX, &defaults.crkey,        required_argument, crkey},
		{"nrkey",        "NUM",  CFG_LONG_SUFFIX, &defaults.nrkey,        required_argument, nrkey},
		{"k",            "NUM",  CFG_LONG_SUFFIX, &defaults.nrkey,        required_argument, nrkey},
		{"rrega",        "NUM",  CFG_BYTE,        &defaults.rrega,        required_argument, rrega},
		{"r",            "NUM",  CFG_BYTE,        &defaults.rrega,        required_argument, rrega},
		{"cptpl",        "NUM",  CFG_BYTE,        &defaults.cptpl,        required_argument, cptpl},
		{"p",            "NUM",  CFG_BYTE,        &defaults.cptpl,        required_argument, cptpl},
		{"iekey",        "",     CFG_NONE,        &defaults.iekey,        no_argument,       iekey},
		{"i",            "",     CFG_NONE,        &defaults.iekey,        no_argument,       iekey},
		{0}
	};

	argconfig_parse(argc, argv, desc, command_line_options,
			&defaults, &cfg, sizeof(cfg));

	get_dev(1, argc, argv);

	if (!cfg.namespace_id) {
		if (!S_ISBLK(nvme_stat.st_mode)) {
			fprintf(stderr,
				"%s: non-block device requires namespace-id param\n",
				devicename);
			exit(ENOTBLK);
		}
		cfg.namespace_id = ioctl(fd, NVME_IOCTL_ID);
		if (cfg.namespace_id <= 0) {
			fprintf(stderr,
				"%s: failed to return namespace id\n",
				devicename);
			return errno;
		}
	}
	if (cfg.cptpl > 3) {
		fprintf(stderr, "invalid cptpl:%d\n", cfg.cptpl);
		return EINVAL;
	}

	payload[0] = cfg.crkey;
	payload[1] = cfg.nrkey;

	memset(&cmd, 0, sizeof(cmd));
	cmd.opcode   = nvme_cmd_resv_register;
	cmd.nsid     = cfg.namespace_id;
	cmd.cdw10    = cfg.cptpl << 30 | cfg.iekey << 3 | cfg.rrega;
	cmd.addr     = (__u64)payload;
	cmd.data_len = sizeof(payload);

	err = ioctl(fd, NVME_IOCTL_IO_CMD, &cmd);
	if (err < 0)
		return errno;
	else if (err != 0)
		fprintf(stderr, "NVME IO command error:%04x\n", err);
	else
		printf("NVME Reservation  success\n");
	return 0;
}

static int resv_release(int argc, char **argv)
{
	struct nvme_passthru_cmd cmd;
	const char *desc = "resv-release: releases reservation held on a "\
		"namespace by the given controller. If rtype != current reser"\
		"vation type, release fails. If the given controller holds no "\
		"reservation on the namespace/is not the namespace's current "\
		"reservation holder, the release command completes with no "\
		"effect. If the reservation type is not Write Exclusive or "\
		"Exclusive Access, all registrants on the namespace except "\
		"the issuing controller are notified.";
	const char *namespace_id = "desired namespace";
	const char *crkey = "current reservation key";
	const char *iekey = "ignore existing res. key";
	const char *rtype = "hex reservation type";
	const char *rrela = "reservation release action";
	int err;

	struct config {
		__u32 namespace_id;
		__u64 crkey;
		__u8  rtype;
		__u8  rrela;
		__u8  iekey;
	};
	struct config cfg;

	const struct config defaults = {
		.namespace_id = 0,
		.crkey        = 0,
		.rtype        = 0,
		.rrela        = 0,
		.iekey        = 0,
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"namespace-id", "NUM",  CFG_POSITIVE,    &defaults.namespace_id, required_argument, namespace_id},
		{"n",            "NUM",  CFG_POSITIVE,    &defaults.namespace_id, required_argument, namespace_id},
		{"crkey",        "NUM",  CFG_LONG_SUFFIX, &defaults.crkey,        required_argument, crkey},
		{"c",            "NUM",  CFG_LONG_SUFFIX, &defaults.crkey,        required_argument, crkey},
		{"rtype",        "NUM",  CFG_BYTE,        &defaults.rtype,        required_argument, rtype},
		{"t",            "NUM",  CFG_BYTE,        &defaults.rtype,        required_argument, rtype},
		{"rrela",        "NUM",  CFG_BYTE,        &defaults.rrela,        required_argument, rrela},
		{"a",            "NUM",  CFG_BYTE,        &defaults.rrela,        required_argument, rrela},
		{"iekey",        "NUM",  CFG_BYTE,        &defaults.iekey,        required_argument, iekey},
		{"i",            "NUM",  CFG_BYTE,        &defaults.iekey,        required_argument, iekey},
		{0}
	};

	argconfig_parse(argc, argv, desc, command_line_options,
			&defaults, &cfg, sizeof(cfg));

	get_dev(1, argc, argv);

	if (!cfg.namespace_id) {
		if (!S_ISBLK(nvme_stat.st_mode)) {
			fprintf(stderr,
				"%s: non-block device requires namespace-id param\n",
				devicename);
			exit(ENOTBLK);
		}
		cfg.namespace_id = ioctl(fd, NVME_IOCTL_ID);
		if (cfg.namespace_id <= 0) {
			fprintf(stderr,
				"%s: failed to return namespace id\n",
				devicename);
			return errno;
		}
	}
	if (cfg.iekey > 1) {
		fprintf(stderr, "invalid iekey:%d\n", cfg.iekey);
		return EINVAL;
	}
	if (cfg.rrela > 7) {
		fprintf(stderr, "invalid rrela:%d\n", cfg.rrela);
		return EINVAL;
	}

	memset(&cmd, 0, sizeof(cmd));
	cmd.opcode   = nvme_cmd_resv_release;
	cmd.nsid     = cfg.namespace_id;
	cmd.cdw10    = cfg.rtype << 8 | cfg.iekey << 3 | cfg.rrela;
	cmd.addr     = (__u64)&cfg.crkey;
	cmd.data_len = sizeof(cfg.crkey);

	err = ioctl(fd, NVME_IOCTL_IO_CMD, &cmd);
	if (err < 0)
		return errno;
	else if (err != 0)
		fprintf(stderr, "NVME IO command error:%04x\n", err);
	else
		printf("NVME Reservation Register success\n");
	return 0;
}

static int resv_report(int argc, char **argv)
{
	struct nvme_passthru_cmd cmd;
	const char *desc = "resv-report: returns Reservation Status data "\
		"structure describing any existing reservations on and the "\
		"status of a given namespace. Namespace Reservation Status "\
		"depends on the number of controllers registered for that "\
		"namespace.";
	const char *namespace_id = "name of desired namespace";
	const char *numd = "number of dwords to transfer";
	const char *raw_binary = "dump output in binary format";

	int err;
	struct nvme_reservation_status *status;

	struct config {
		__u32 namespace_id;
		__u32 numd;
		__u8  raw_binary;
	};
	struct config cfg;

	const struct config defaults = {
		.namespace_id = 0,
		.numd         = 0,
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"namespace-id", "NUM",  CFG_POSITIVE, &defaults.namespace_id, required_argument, namespace_id},
		{"n",            "NUM",  CFG_POSITIVE, &defaults.namespace_id, required_argument, namespace_id},
		{"numd",         "NUM",  CFG_POSITIVE, &defaults.numd,         required_argument, numd},
		{"d",            "NUM",  CFG_POSITIVE, &defaults.numd,         required_argument, numd},
		{"raw-binary",   "",     CFG_NONE,     &defaults.raw_binary,   no_argument,       raw_binary},
		{"b",            "",     CFG_NONE,     &defaults.raw_binary,   no_argument,       raw_binary},
		{0}
	};

	argconfig_parse(argc, argv, desc, command_line_options,
			&defaults, &cfg, sizeof(cfg));

	get_dev(1, argc, argv);

	if (!cfg.namespace_id) {
		if (!S_ISBLK(nvme_stat.st_mode)) {
			fprintf(stderr,
				"%s: non-block device requires namespace-id param\n",
				devicename);
			exit(ENOTBLK);
		}
		cfg.namespace_id = ioctl(fd, NVME_IOCTL_ID);
		if (cfg.namespace_id <= 0) {
			fprintf(stderr,
				"%s: failed to return namespace id\n",
				devicename);
			return errno;
		}
	}
	if (!cfg.numd || cfg.numd > (0x1000 >> 2))
		cfg.numd = 0x1000 >> 2;

	if (posix_memalign((void **)&status, getpagesize(), cfg.numd << 2)) {
		fprintf(stderr, "No memory for resv report:%d\n", cfg.numd << 2);
		return ENOMEM;
	}

	memset(&cmd, 0, sizeof(cmd));
	cmd.opcode   = nvme_cmd_resv_report;
	cmd.nsid     = cfg.namespace_id;
	cmd.cdw10    = cfg.numd;
	cmd.addr     = (__u64)status;
	cmd.data_len = cfg.numd << 2;

	err = ioctl(fd, NVME_IOCTL_IO_CMD, &cmd);
	if (err < 0)
		return errno;
	else if (err != 0)
		fprintf(stderr, "NVME IO command error:%04x\n", err);
	else {
		if (!cfg.raw_binary) {
			printf("NVME Reservation Report success\n");
			show_nvme_resv_report(status);
		} else
			d_raw((unsigned char *)status, cfg.numd << 2);
	}
	return 0;
}

static int submit_io(int opcode, char *command, const char *desc,
		     int argc, char **argv)
{
	struct nvme_user_io io;
	struct timeval start_time, end_time;
	void *buffer, *mbuffer = NULL;
	int err = 0, dfd = opcode & 1 ? STDIN_FILENO : STDOUT_FILENO;

	const char *start_block = "64-bit addr of first block to access";
	const char *block_count = "number of blocks on device to access";
	const char *data_size = "size of data in bytes";
	const char *metadata_size = "size of metadata in bytes";
	const char *ref_tag = "reference tag (for end to end PI)";
	const char *data = "file";
	const char *prinfo = "PI and check field";
	const char *app_tag_mask = "app tag mask (for end to end PI)";
	const char *app_tag = "app tag (for end to end PI)";
	const char *limited_retry = "limit num. media access attempts";
	const char *latency = "output latency statistics";
	const char *force = "return data before command completes";
	const char *show = "show command before sending";
	const char *dry = "show command instead of sending";

	struct config {
		__u64 start_block;
		__u16 block_count;
		__u32 data_size;
		__u32 metadata_size;
		__u32 ref_tag;
		char  *data;
		__u8  prinfo;
		__u8  app_tag_mask;
		__u32 app_tag;
		__u8  limited_retry;
		__u8  force_unit_access;
		__u8  show;
		__u8  dry_run;
		__u8  latency;
	};
	struct config cfg;

	const struct config defaults = {
		.start_block     = 0,
		.block_count     = 0,
		.data_size       = 0,
		.metadata_size   = 0,
		.ref_tag         = 0,
		.data            = "",
		.prinfo          = 0,
		.app_tag_mask    = 0,
		.app_tag         = 0,
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"start-block",       "NUM",  CFG_LONG_SUFFIX, &defaults.start_block,       required_argument, start_block},
		{"s",                 "NUM",  CFG_LONG_SUFFIX, &defaults.start_block,       required_argument, start_block},
		{"block-count",       "NUM",  CFG_SHORT,       &defaults.block_count,       required_argument, block_count},
		{"c",                 "NUM",  CFG_SHORT,       &defaults.block_count,       required_argument, block_count},
		{"data-size",         "NUM",  CFG_LONG_SUFFIX, &defaults.data_size,         required_argument, data_size},
		{"z",                 "NUM",  CFG_LONG_SUFFIX, &defaults.data_size,         required_argument, data_size},
		{"metadata-size",     "NUM",  CFG_LONG_SUFFIX, &defaults.metadata_size,     required_argument, metadata_size},
		{"y",                 "NUM",  CFG_LONG_SUFFIX, &defaults.metadata_size,     required_argument, metadata_size},
		{"ref-tag",           "NUM",  CFG_POSITIVE,    &defaults.ref_tag,           required_argument, ref_tag},
		{"r",                 "NUM",  CFG_POSITIVE,    &defaults.ref_tag,           required_argument, ref_tag},
		{"data",              "FILE", CFG_STRING,      &defaults.data,              required_argument, data},
		{"d",                 "FILE", CFG_STRING,      &defaults.data,              required_argument, data},
		{"prinfo",            "NUM",  CFG_BYTE,        &defaults.prinfo,            required_argument, prinfo},
		{"p",                 "NUM",  CFG_BYTE,        &defaults.prinfo,            required_argument, prinfo},
		{"app-tag-mask",      "NUM",  CFG_BYTE,        &defaults.app_tag_mask,      required_argument, app_tag_mask},
		{"m",                 "NUM",  CFG_BYTE,        &defaults.app_tag_mask,      required_argument, app_tag_mask},
		{"app-tag",           "NUM",  CFG_POSITIVE,    &defaults.app_tag,           required_argument, app_tag},
		{"a",                 "NUM",  CFG_POSITIVE,    &defaults.app_tag,           required_argument, app_tag},
		{"limited-retry",     "",     CFG_NONE,        &defaults.limited_retry,     no_argument,       limited_retry},
		{"l",                 "",     CFG_NONE,        &defaults.limited_retry,     no_argument,       limited_retry},
		{"force-unit-access", "",     CFG_NONE,        &defaults.force_unit_access, no_argument,       force},
		{"f",                 "",     CFG_NONE,        &defaults.force_unit_access, no_argument,       force},
		{"show-command",      "",     CFG_NONE,        &defaults.show,              no_argument,       show},
		{"v",                 "",     CFG_NONE,        &defaults.show,              no_argument,       show},
		{"dry-run",           "",     CFG_NONE,        &defaults.dry_run,           no_argument,       dry},
		{"w",                 "",     CFG_NONE,        &defaults.dry_run,           no_argument,       dry},
		{"latency",           "",     CFG_NONE,        &defaults.latency,           no_argument,       latency},
		{"t",                 "",     CFG_NONE,        &defaults.latency,           no_argument,       latency},
		{0}
	};

	argconfig_parse(argc, argv, desc, command_line_options,
			&defaults, &cfg, sizeof(cfg));

	memset(&io, 0, sizeof(io));

	io.slba    = cfg.start_block;
	io.nblocks = cfg.block_count;
	io.reftag  = cfg.ref_tag;
	io.appmask = cfg.app_tag_mask;
	io.apptag  = cfg.app_tag;
	if (cfg.prinfo > 0xf)
		return EINVAL;
	io.control |= (cfg.prinfo << 10);
	if (cfg.limited_retry)
		io.control |= NVME_RW_LR;
	if (cfg.force_unit_access)
		io.control |= NVME_RW_FUA;
	if (strlen(cfg.data)){
		if (opcode & 1)
			dfd = open(cfg.data, O_RDONLY);
		else
			dfd = open(cfg.data, O_WRONLY | O_CREAT,
				   S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP| S_IROTH);
		if (dfd < 0) {
			perror(cfg.data);
			return EINVAL;
		}
	}
	get_dev(1, argc, argv);

	if (!cfg.data_size)	{
		fprintf(stderr, "data size not provided\n");
		return EINVAL;
	}
	buffer = malloc(cfg.data_size);
	if (cfg.metadata_size)
		mbuffer = malloc(cfg.metadata_size);
	if ((opcode & 1) && read(dfd, (void *)buffer, cfg.data_size) < 0) {
		fprintf(stderr, "failed to read data buffer from input file\n");
		return EINVAL;
	}
	if ((opcode & 1) && cfg.metadata_size && read(dfd, (void *)mbuffer, cfg.metadata_size) < 0) {
		fprintf(stderr, "failed to read meta-data buffer from input file\n");
		return EINVAL;
	}

	io.opcode = opcode;
	io.addr   = (__u64)buffer;
	if (cfg.metadata_size)
		io.metadata = (__u64)mbuffer;
	if (cfg.show) {
		printf("opcode       : %02x\n" , io.opcode);
		printf("flags        : %02x\n" , io.flags);
		printf("control      : %04x\n" , io.control);
		printf("nblocks      : %04x\n" , io.nblocks);
		printf("rsvd         : %04x\n" , io.rsvd);
		printf("metadata     : %p\n"   , (void *)io.metadata);
		printf("addr         : %p\n"   , (void *)io.addr);
		printf("sbla         : %p\n"   , (void *)io.slba);
		printf("dsmgmt       : %08x\n" , io.dsmgmt);
		printf("reftag       : %08x\n" , io.reftag);
		printf("apptag       : %04x\n" , io.apptag);
		printf("appmask      : %04x\n" , io.appmask);
		if (cfg.dry_run)
			goto free_and_return;
	}

	gettimeofday(&start_time, NULL);
	err = ioctl(fd, NVME_IOCTL_SUBMIT_IO, &io);
	gettimeofday(&end_time, NULL);
	if (cfg.latency)
		fprintf(stdout, " latency: %s: %llu us\n",
			command, elapsed_utime(start_time, end_time));
	if (err < 0)
		perror("ioctl");
	else if (err)
		printf("%s:%s(%04x)\n", command, nvme_status_to_string(err), err);
	else {
		if (!(opcode & 1) && write(dfd, (void *)buffer, cfg.data_size) < 0) {
			fprintf(stderr, "failed to write buffer to output file\n");
			return EINVAL;
		} else
			printf("%s: success\n", command);
	}
 free_and_return:
	free(buffer);
	if (cfg.metadata_size)
		free(mbuffer);
    return err;
}

static int compare(int argc, char **argv)
{
	const char *desc = "compare: diff specified logical blocks on "\
		"device with specified data buffer; return failure if buffer "\
		"and block(s) are dissimilar";
	return submit_io(nvme_cmd_compare, "compare", desc, argc, argv);
}

static int read_cmd(int argc, char **argv)
{
	const char *desc = "read: copy specified logical blocks on the given "\
		"device to specified data buffer (default buffer is stdout).";
	return submit_io(nvme_cmd_read, "read", desc, argc, argv);
}

static int write_cmd(int argc, char **argv)
{
	const char *desc = "write: copy from provided data buffer (default "\
		"buffer is stdin) to specified logical blocks on the given "\
		"device.";
	return submit_io(nvme_cmd_write, "write", desc, argc, argv);
}

static int sec_recv(int argc, char **argv)
{
	const char *desc = "security-recv: obtain results of one or more "\
		"previously submitted security-sends. Results, and association "\
		"between Security Send and Receive, depend on the security "\
		"protocol field as they are defined by the security protocol "\
		"used. A Security Receive must follow a Security Send made with "\
		"the same security protocol.";
	const char *size = "size of buffer (prints to stdout on success)";
	const char *secp = "security protocol (cf. SPC-4)";
	const char *spsp = "security-protocol-specific (cf. SPC-4)";
	const char *al = "allocation length (cf. SPC-4)";
	const char *raw_binary = "dump output in binary format";
	int err;
	struct nvme_admin_cmd cmd;
	void *sec_buf = NULL;

	struct config {
		__u32 size;
		__u8  secp;
		__u16 spsp;
		__u32 al;
		__u8  raw_binary;
	};
	struct config cfg;

	const struct config defaults = {
		.size = 0,
		.secp = 0,
		.spsp = 0,
		.al   = 0,
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"size",       "NUM",  CFG_POSITIVE, &defaults.size,       required_argument, size},
		{"x",          "NUM",  CFG_POSITIVE, &defaults.size,       required_argument, size},
		{"secp",       "NUM",  CFG_BYTE,     &defaults.secp,       required_argument, secp},
		{"p",          "NUM",  CFG_BYTE,     &defaults.secp,       required_argument, secp},
		{"spsp",       "NUM",  CFG_SHORT,    &defaults.spsp,       required_argument, spsp},
		{"s",          "NUM",  CFG_SHORT,    &defaults.spsp,       required_argument, spsp},
		{"al",         "NUM",  CFG_POSITIVE, &defaults.al,         required_argument, al},
		{"t",          "NUM",  CFG_POSITIVE, &defaults.al,         required_argument, al},
		{"raw-binary", "",     CFG_NONE,     &defaults.raw_binary, no_argument,       raw_binary},
		{"b",          "",     CFG_NONE,     &defaults.raw_binary, no_argument,       raw_binary},
		{0}
	};

	argconfig_parse(argc, argv, desc, command_line_options,
			&defaults, &cfg, sizeof(cfg));

	get_dev(1, argc, argv);

	if (cfg.size) {
		if (posix_memalign(&sec_buf, getpagesize(), cfg.size)) {
			fprintf(stderr, "No memory for security size:%d\n",
								cfg.size);
			return ENOMEM;
		}
	}
	memset(&cmd, 0, sizeof(cmd));
	cmd.opcode   = nvme_admin_security_recv;
	cmd.cdw10    = cfg.secp << 24 | cfg.spsp << 8;
	cmd.cdw11    = cfg.al;
	cmd.data_len = cfg.size;
	cmd.addr     = (__u64)sec_buf;

	err = ioctl(fd, NVME_IOCTL_ADMIN_CMD, &cmd);
	if (err < 0)
		return errno;
	else if (err != 0)
		fprintf(stderr, "NVME Security Receive Command Error:%d\n",
									err);
	else {
		if (!cfg.raw_binary) {
			printf("NVME Security Receive Command Success:%d\n",
							cmd.result);
			d(sec_buf, cfg.size, 16, 1);
		} else if (cfg.size)
			d_raw((unsigned char *)&sec_buf, cfg.size);
	}
	return err;
}

static int nvme_passthru(int argc, char **argv, int ioctl_cmd)
{
	int err, wfd = STDIN_FILENO;
	const char *desc = "[io/admin]-passthru: send a user-specified IO or "\
		"admin command to the specified device via IOCTL passthrough, "\
		"return results";
	struct nvme_passthru_cmd cmd;

	struct config {
		__u8  opcode;
		__u8  flags;
		__u16 rsvd;
		__u32 namespace_id;
		__u32 data_len;
		__u32 metadata_len;
		__u32 timeout;
		__u32 cdw2;
		__u32 cdw3;
		__u32 cdw10;
		__u32 cdw11;
		__u32 cdw12;
		__u32 cdw13;
		__u32 cdw14;
		__u32 cdw15;
		char  *input_file;
		__u8  raw_binary;
		__u8  show_command;
		__u8  dry_run;
		__u8  read;
		__u8  write;
	};
	struct config cfg;

	const struct config defaults = {
		.opcode       = 0,
		.flags        = 0,
		.rsvd         = 0,
		.namespace_id = 0,
		.data_len     = 0,
		.metadata_len = 0,
		.timeout      = 0,
		.cdw2         = 0,
		.cdw3         = 0,
		.cdw10        = 0,
		.cdw11        = 0,
		.cdw12        = 0,
		.cdw13        = 0,
		.cdw14        = 0,
		.cdw15        = 0,
		.input_file   = "",
	};

	const char *opcode = "hex opcode (required)";
	const char *flags = "command flags";
	const char *rsvd = "value for reserved field";
	const char *namespace_id = "desired namespace";
	const char *data_len = "data I/O length (bytes)";
	const char *metadata_len = "metadata seg. length (bytes)";
	const char *timeout = "timeout value";
	const char *cdw2 = "command dword 2 value";
	const char *cdw3 = "command dword 3 value";
	const char *cdw10 = "command dword 10 value";
	const char *cdw11 = "command dword 11 value";
	const char *cdw12 = "command dword 12 value";
	const char *cdw13 = "command dword 13 value";
	const char *cdw14 = "command dword 14 value";
	const char *cdw15 = "command dword 15 value";
	const char *input = "write/send file (default stdin)";
	const char *raw_binary = "dump output in binary format";
	const char *show = "print command before sending";
	const char *dry = "show command instead of sending";
	const char *re = "set dataflow direction to receive";
	const char *wr = "set dataflow direction to send";

	const struct argconfig_commandline_options command_line_options[] = {
		{"opcode",       "NUM",  CFG_BYTE,     &defaults.opcode,       required_argument, opcode},
		{"o",            "NUM",  CFG_BYTE,     &defaults.opcode,       required_argument, opcode},
		{"flags",        "NUM",  CFG_BYTE,     &defaults.flags,        required_argument, flags},
		{"f",            "NUM",  CFG_BYTE,     &defaults.flags,        required_argument, flags},
		{"rsvd",         "NUM",  CFG_SHORT,    &defaults.rsvd,         required_argument, rsvd},
		{"R",            "NUM",  CFG_SHORT,    &defaults.rsvd,         required_argument, rsvd},
		{"namespace-id", "NUM",  CFG_POSITIVE, &defaults.namespace_id, required_argument, namespace_id},
		{"n",            "NUM",  CFG_POSITIVE, &defaults.namespace_id, required_argument, namespace_id},
		{"data-len",     "NUM",  CFG_POSITIVE, &defaults.data_len,     required_argument, data_len},
		{"l",            "NUM",  CFG_POSITIVE, &defaults.data_len,     required_argument, data_len},
		{"metadata-len", "NUM",  CFG_POSITIVE, &defaults.metadata_len, required_argument, metadata_len},
		{"m",            "NUM",  CFG_POSITIVE, &defaults.metadata_len, required_argument, metadata_len},
		{"timeout",      "NUM",  CFG_POSITIVE, &defaults.timeout,      required_argument, timeout},
		{"t",            "NUM",  CFG_POSITIVE, &defaults.timeout,      required_argument, timeout},
		{"cdw2",         "NUM",  CFG_POSITIVE, &defaults.cdw2,         required_argument, cdw2},
		{"2",            "NUM",  CFG_POSITIVE, &defaults.cdw2,         required_argument, cdw2},
		{"cdw3",         "NUM",  CFG_POSITIVE, &defaults.cdw3,         required_argument, cdw3},
		{"3",            "NUM",  CFG_POSITIVE, &defaults.cdw3,         required_argument, cdw3},
		{"cdw10",        "NUM",  CFG_POSITIVE, &defaults.cdw10,        required_argument, cdw10},
		{"4",            "NUM",  CFG_POSITIVE, &defaults.cdw10,        required_argument, cdw10},
		{"cdw11",        "NUM",  CFG_POSITIVE, &defaults.cdw11,        required_argument, cdw11},
		{"5",            "NUM",  CFG_POSITIVE, &defaults.cdw11,        required_argument, cdw11},
		{"cdw12",        "NUM",  CFG_POSITIVE, &defaults.cdw12,        required_argument, cdw12},
		{"6",            "NUM",  CFG_POSITIVE, &defaults.cdw12,        required_argument, cdw12},
		{"cdw13",        "NUM",  CFG_POSITIVE, &defaults.cdw13,        required_argument, cdw13},
		{"7",            "NUM",  CFG_POSITIVE, &defaults.cdw13,        required_argument, cdw13},
		{"cdw14",        "NUM",  CFG_POSITIVE, &defaults.cdw14,        required_argument, cdw14},
		{"8",            "NUM",  CFG_POSITIVE, &defaults.cdw14,        required_argument, cdw14},
		{"cdw15",        "NUM",  CFG_POSITIVE, &defaults.cdw15,        required_argument, cdw15},
		{"9",            "NUM",  CFG_POSITIVE, &defaults.cdw15,        required_argument, cdw15},
		{"input-file",   "FILE", CFG_STRING,   &defaults.input_file,   required_argument, input},
		{"i",            "FILE", CFG_STRING,   &defaults.input_file,   required_argument, input},
		{"raw-binary",   "",     CFG_NONE,     &defaults.raw_binary,   no_argument,       raw_binary},
		{"b",            "",     CFG_NONE,     &defaults.raw_binary,   no_argument,       raw_binary},
		{"show-command", "",     CFG_NONE,     &defaults.show_command, no_argument,       show},
		{"s",            "",     CFG_NONE,     &defaults.show_command, no_argument,       show},
		{"dry-run",      "",     CFG_NONE,     &defaults.dry_run,      no_argument,       dry},
		{"d",            "",     CFG_NONE,     &defaults.dry_run,      no_argument,       dry},
		{"read",         "",     CFG_NONE,     &defaults.read,         no_argument,       re},
		{"r",            "",     CFG_NONE,     &defaults.read,         no_argument,       re},
		{"write",        "",     CFG_NONE,     &defaults.write,        no_argument,       wr},
		{"w",            "",     CFG_NONE,     &defaults.write,        no_argument,       wr},
		{0}
	};

	memset(&cmd, 0, sizeof(cmd));
	argconfig_parse(argc, argv, desc, command_line_options,
			&defaults, &cfg, sizeof(cfg));

	cmd.cdw2         = cfg.cdw2;
	cmd.cdw3         = cfg.cdw3;
	cmd.cdw10        = cfg.cdw10;
	cmd.cdw11        = cfg.cdw11;
	cmd.cdw12        = cfg.cdw12;
	cmd.cdw13        = cfg.cdw13;
	cmd.cdw14        = cfg.cdw14;
	cmd.cdw15        = cfg.cdw15;
	cmd.opcode       = cfg.opcode;
	cmd.flags        = cfg.flags;
	cmd.rsvd1        = cfg.rsvd;
	cmd.nsid         = cfg.namespace_id;
	cmd.data_len     = cfg.data_len;
	cmd.metadata_len = cfg.metadata_len;
	cmd.timeout_ms   = cfg.timeout;
	if (strlen(cfg.input_file)){
		wfd = open(cfg.input_file, O_RDONLY,
			   S_IRUSR | S_IRGRP | S_IROTH);
		if (wfd < 0) {
			perror(cfg.input_file);
			return EINVAL;
		}
	}
	get_dev(1, argc, argv);
	if (cmd.metadata_len)
		cmd.metadata = (__u64)malloc(cmd.metadata_len);
	if (cmd.data_len) {
		cmd.addr = (__u64)malloc(cmd.data_len);
		if (!cfg.read && !cfg.write) {
			fprintf(stderr, "data direction not given\n");
			return EINVAL;
		}
		if (cfg.read && cfg.write) {
			fprintf(stderr, "command can't be both read and write\n");
			return EINVAL;
		}
		if (cfg.write) {
			if (read(wfd, (void *)cmd.addr, cmd.data_len) < 0) {
				fprintf(stderr, "failed to read write buffer\n");
				return EINVAL;
			}
		}
	}
	if (cfg.show_command) {
		printf("opcode       : %02x\n", cmd.opcode);
		printf("flags        : %02x\n", cmd.flags);
		printf("rsvd1        : %04x\n", cmd.rsvd1);
		printf("nsid         : %08x\n", cmd.nsid);
		printf("cdw2         : %08x\n", cmd.cdw2);
		printf("cdw3         : %08x\n", cmd.cdw3);
		printf("data_len     : %08x\n", cmd.data_len);
		printf("metadata_len : %08x\n", cmd.metadata_len);
		printf("addr         : %p\n",   (void *)cmd.addr);
		printf("metadata     : %p\n",   (void *)cmd.metadata);
		printf("cdw10        : %08x\n", cmd.cdw10);
		printf("cdw11        : %08x\n", cmd.cdw11);
		printf("cdw12        : %08x\n", cmd.cdw12);
		printf("cdw13        : %08x\n", cmd.cdw13);
		printf("cdw14        : %08x\n", cmd.cdw14);
		printf("cdw15        : %08x\n", cmd.cdw15);
		printf("timeout_ms   : %08x\n", cmd.timeout_ms);
		if (cfg.dry_run)
			return 0;
	}
	err = ioctl(fd, ioctl_cmd, &cmd);
	if (err >= 0) {
		if (!cfg.raw_binary) {
			printf("NVMe Status:%s Command Result:%08x\n",
				nvme_status_to_string(err), cmd.result);
			if (cmd.addr && cfg.read && !err)
				d((unsigned char *)cmd.addr, cmd.data_len, 16, 1);
		} else if (!err && cmd.addr && cfg.read)
			d_raw((unsigned char *)cmd.addr, cmd.data_len);
	} else
		perror("ioctl");
	return err;
}

static int io_passthru(int argc, char **argv)
{
	return nvme_passthru(argc, argv, NVME_IOCTL_IO_CMD);
}

static int admin_passthru(int argc, char **argv)
{
	return nvme_passthru(argc, argv, NVME_IOCTL_ADMIN_CMD);
}

static void usage(char *cmd)
{
	fprintf(stdout, "usage: %s <command> [<device>] [<args>]\n", cmd);
}

static void command_help(const char *cmd)
{
	unsigned i;
	struct command *c;

	for (i = 0; i < NUM_COMMANDS; i++) {
		c = &commands[i];
		if (strcmp(c->name, cmd))
			continue;
		exit(execlp("man", "man", c->man, (char *)NULL));
	}
	fprintf(stderr, "No entry for nvme sub-command %s\n", cmd);
}

static void general_help()
{
	unsigned i;

	usage("nvme");
	printf("\n");
	printf("'<device>' / '/dev/nvmeX' may be either an NVMe character "\
	       "device (ex: /dev/nvme0)\n or an nvme block device (ex: /d"\
	       "ev/nvme0n1)\n\n");
	printf("The following are all implemented sub-commands:\n");
	for (i = 0; i < NUM_COMMANDS; i++)
		printf("  %-*s %s\n", 15, commands[i].name, commands[i].help);
	printf("\n");
	printf("See 'nvme help <command>' for more information on a specific command.\n");
}

static int help(int argc, char **argv)
{
	if (argc == 1)
		general_help();
	else
		command_help(argv[1]);
	return 0;
}

static void handle_internal_command(int argc, char **argv)
{
	unsigned i;
	struct command *cmd;

	for (i = 0; i < NUM_COMMANDS; i++) {
		cmd = &commands[i];
		if (strcmp(argv[0], cmd->name))
			continue;
		exit(cmd->fn(argc, argv));
	}
	fprintf(stderr, "unknown command '%s'\n", argv[0]);
	help(1, NULL);
	exit(1);
}

int main(int argc, char **argv)
{
	if (argc < 2) {
		usage(argv[0]);
		return 0;
	}
	setlocale(LC_ALL, "");
	handle_internal_command(argc - 1, &argv[1]);
	return 0;
}
