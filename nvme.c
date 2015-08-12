/*
 * nvme.c -- NVM-Express command line utility.
 *
 * Copyright (c) 2014-2015, Intel Corporation.
 *
 * Written by Keith Busch <keith.busch@intel.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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
#include "src/suffix.h"

#define min(x, y) (x) > (y) ? (y) : (x)

#define	FORMAT_TIMEOUT	120000	// 120 seconds

static int fd;
static struct stat nvme_stat;
static const char *devicename;

#define COMMAND_LIST \
	ENTRY(LIST, "list", "List all NVMe devices and namespaces on machine", list) \
	ENTRY(ID_CTRL, "id-ctrl", "Send NVMe Identify Controller", id_ctrl) \
	ENTRY(ID_NS, "id-ns", "Send NVMe Identify Namespace, display structure", id_ns) \
	ENTRY(LIST_NS, "list-ns", "Send NVMe Identify List, display structure", list_ns) \
	ENTRY(CREATE_NS, "create-ns", "Creates a namespace with the provided parameters", create_ns) \
	ENTRY(DELETE_NS, "delete-ns", "Deletes a detached namespace from the controller", delete_ns) \
	ENTRY(ATTACH_NS, "attach-ns", "Attaches a created namespace to requested controller(s)", attach_ns) \
	ENTRY(DETACH_NS, "detach-ns", "Detaches a namespace from requested controller(s)", detach_ns) \
	ENTRY(LIST_CTRL, "list-ctrl", "Send NVMe Identify Controller List, show results", list_ctrl) \
	ENTRY(GET_NS_ID, "get-ns-id", "Retrieve the namespace ID of opened block device", get_ns_id) \
	ENTRY(GET_LOG, "get-log", "Returns entries from generic log in raw fmt", get_log) \
	ENTRY(GET_FW_LOG, "fw-log", "Retrieve FW Log in either hex or raw fmt", get_fw_log) \
	ENTRY(GET_SMART_LOG, "smart-log", "Retrieve SMART log, show in hex or raw fmt", get_smart_log) \
	ENTRY(GET_ADDITIONAL_SMART_LOG, "smart-log-add", "Retrieve additional SMART Log, show it", get_additional_smart_log) \
	ENTRY(GET_ERR_LOG, "error-log", "Retrieve entries from Error Log in hex or raw fmt", get_error_log) \
	ENTRY(GET_FEATURE, "get-feature", "Read and display controller's specified feature value", get_feature) \
	ENTRY(SET_FEATURE, "set-feature", "Set a feature and show the resulting value", set_feature) \
	ENTRY(FORMAT, "format", "Format namespace with new block format", format) \
	ENTRY(FW_ACTIVATE, "fw-activate", "Activate new firmware slot", fw_activate) \
	ENTRY(FW_DOWNLOAD, "fw-download", "Download new firmware", fw_download) \
	ENTRY(ADMIN_PASSTHRU, "admin-passthru", "Submit arbitrary admin command, return results", admin_passthru) \
	ENTRY(IO_PASSTHRU, "io-passthru", "Submit an arbitrary IO command, return results", io_passthru) \
	ENTRY(SECURITY_SEND, "security-send", "Submit a Security Send command, return results", sec_send) \
	ENTRY(SECURITY_RECV, "security-recv", "Obtain results of one or more previous same-protocol Security Sends", sec_recv) \
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

static void usage(char *cmd)
{
	fprintf(stdout, "usage: %s <command> [<device>] [<args>]\n", cmd);
}

static void command_help(struct option *opts, int num_opts, char *name)
{
	fprintf(stderr, "Usage: nvme %s /dev/nvmeX", name);
	for (int j = 0; j < num_opts; ++j) {
		if (opts[j].name != 0) {
			if (opts[j].has_arg == no_argument)
				fprintf(stderr, " [ --%s | -%s ]",
				opts[j].name, (char *)&opts[j].val);
			else
				fprintf(stderr, " [ --%s= | -%s ] ARG",
				opts[j].name, (char *)&opts[j].val);
		}

		if (j % 2 == 0)
			fprintf(stderr, "\n");
	}

	fprintf(stderr, "\nAlso try 'man nvme-%s'\n", name);
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
	printf("Try 'nvme help <command>' for more information on a specific command.\n");
}

static int help(int argc, char **argv)
{
	struct command *c;

	if (argc == 1)
		general_help();
	else {
		for (unsigned i = 0; i < NUM_COMMANDS; i++) {
			c = &commands[i];
			if (strcmp(c->name, argv[1])) continue;

			exit(execlp("man", "man", c->man, (char *) NULL));
		}

		fprintf(stderr, "no man entry for NVMe sub-command '%s'\n", argv[1]);
	}

	return 0;
}

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

	printf("Error Log Entries for device: %s entries: %d\n", devicename,
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

	printf("Firmware Log for device: %s\n", devicename);
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

	printf("Smart Log for NVME device: %s namespace-id: %x\n", devicename, nsid);
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
	printf("Additional Smart Log for NVME device: %s namespace-id: %x\n", devicename, nsid);
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
	case NVME_FEAT_LBA_RANGE:	return "LBA Range";
	case NVME_FEAT_TEMP_THRESH:	return "Temperature Threshold";
	case NVME_FEAT_ERR_RECOVERY:	return "Error Recovery";
	case NVME_FEAT_VOLATILE_WC:	return "Volatile Write Cache";
	case NVME_FEAT_NUM_QUEUES:	return "Number of Queues";
	case NVME_FEAT_IRQ_COALESCE:	return "IRQ Coalescing";
	case NVME_FEAT_IRQ_CONFIG: 	return "IRQ Configuration";
	case NVME_FEAT_WRITE_ATOMIC:	return "Write Atomicity";
	case NVME_FEAT_ASYNC_EVENT:	return "Async Event";
	case NVME_FEAT_SW_PROGRESS:	return "Software Progress";
	default:			return "Unknown";
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


static void show_lba_range(struct nvme_lba_range_type *lbrt, int nr_ranges)
{
	int i, j;

	for (i = 0; i < nr_ranges; i++) {
		printf("type       : %#x\n", lbrt[i].type);
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
	int c;
	int err;
	int i = 0;
	uint32_t namespace_id = 0;
	uint8_t raw_binary = 0;
	char *name = argv[0];

	/* needed for default behavior; NOT counting help option
	 * since it would generally be provided alone to nvme <name>
	 */
	int num_opts = 2;

	static struct option opts[] = {
		{"namespace-id", required_argument, 0, 'n'},
		{"raw-binary",   no_argument,       0, 'b'},
		/* --help should go last since we don't want to
		 * self-reference it in the help menu */
		{"help",	 no_argument,	    0, 'h'},
		{0,		 0,		    0,	0}
	};


	/* get device before parsing since it's a non-opt-arg */
	get_dev(1, argc, argv);

	while((c = getopt_long_only(argc, argv, "hbn:", opts, &i)) != -1) {
		switch (c) {
		case 'b':
			raw_binary = 1;
			break;
		case 'n':
			namespace_id = atoi(optarg);
			break;
		case 'h':
		default:
			command_help(opts, num_opts, name);
			return -1;
		}
	}

	err = nvme_get_log(&smart_log,
		sizeof(smart_log), 0x2 | (((sizeof(smart_log) / 4) - 1) << 16),
		namespace_id);
	if (!err) {
		if (!raw_binary)
			show_smart_log(&smart_log, namespace_id);
		else
			d_raw((unsigned char *)&smart_log, sizeof(smart_log));
	}
	else if (err > 0)
		fprintf(stderr, "NVMe Status: %s(%x)\n",
					nvme_status_to_string(err), err);
	return err;
}

static int get_additional_smart_log(int argc, char **argv)
{
	struct nvme_additional_smart_log smart_log;
	int err;
	int c;
	int option_index = 0;
	char *name = argv[0];
	uint32_t namespace_id = 0;
	uint8_t raw_binary = 0;

	int num_opts = 2;
	static struct option opts[] = {
		{"namespace-id", required_argument, 0, 'n'},
		{"raw-binary",   no_argument,       0, 'b'},
		{"help",	 no_argument,	    0, 'h'},
		{0,		 0,		    0,	0}
	};

	/* get device before parsing since it's a non-opt-arg */
	get_dev(1, argc, argv);

	while((c = getopt_long(argc, argv, "hbn:", opts, &option_index)) != -1) {
		switch (c) {
		case ':':
			fprintf(stderr, "nvme %s: '%s' was missing a required "\
			"parameter.\n", argv[0], argv[optind]);
			exit(1);
			break;
		case 'b':
			raw_binary = 1;
			break;
		case 'n':
			namespace_id = atoi(optarg);
			break;
		case 'h':
		default:
			command_help(opts, num_opts, name);
			return -1;
		}
	}

	err = nvme_get_log(&smart_log,
		sizeof(smart_log), 0xCA | (((sizeof(smart_log) / 4) - 1) << 16),
		namespace_id);
	if (!err) {
		if (!raw_binary)
			show_additional_smart_log(&smart_log, namespace_id);
		else
			d_raw((unsigned char *)&smart_log, sizeof(smart_log));
	}
	else if (err > 0)
		fprintf(stderr, "NVMe Status: %s(%x)\n",
					nvme_status_to_string(err), err);
	return err;
}

static int get_error_log(int argc, char **argv)
{
	int c;
	int err;
	int option_index = 0;

	uint32_t namespace_id = 0;
	uint32_t log_entries = 0;
	uint8_t raw_binary = 0;
	char *name = argv[0];
	int num_opts = 3;
	static struct option opts[] = {
		{"log-entries",  required_argument, 0, 'e'},
		{"namespace-id", required_argument, 0, 'n'},
		{"raw-binary",   no_argument,       0, 'b'},
		{"help",	 no_argument,	    0, 'h'},
		{0,		 0,		    0,	0}
	};

	/* get device before parsing since it's a non-opt-arg */
	get_dev(1, argc, argv);

	while((c = getopt_long_only(argc, argv,
			"hbn:e:", opts, &option_index)) != -1) {
		switch (c) {
		case 'b':
			raw_binary = 1;
			break;
		case 'e':
			log_entries = atoi(optarg);
			break;
		case 'n':
			namespace_id = atoi(optarg);
			break;
		case 'h':
		default:
			command_help(opts, num_opts, name);
			return -1;
		}
	}

	if (!log_entries) {
		fprintf(stderr, "nvme error-log requires a nonzero number of "\
				"log entries to fetch.\n");
		return EINVAL;
	}

	struct nvme_error_log_page err_log[log_entries];

	err = nvme_get_log(err_log,
			   sizeof(err_log), 0x1 | (((sizeof(err_log) / 4) - 1) << 16),
			   namespace_id);
	if (!err) {
		if (!raw_binary)
			show_error_log(err_log, log_entries);
		else
			d_raw((unsigned char *)err_log, sizeof(err_log));
	}
	else if (err > 0)
		fprintf(stderr, "NVMe Status: %s(%x)\n",
					nvme_status_to_string(err), err);
	return err;
}

static int get_fw_log(int argc, char **argv)
{
	struct nvme_firmware_log_page fw_log;
	int c;
	int err;
	int option_index = 0;
	char *name = argv[0];
	uint8_t raw_binary = 0;

	int num_opts = 1;
	static struct option opts[] = {
		{"raw-binary",   no_argument,       0, 'b'},
		{"help",	 no_argument,	    0, 'h'},
		{0,		 0,		    0,	0}
	};

	while((c = getopt_long(argc, argv, ":bh", opts, &option_index)) != -1) {
		switch (c) {
		case 'b':
			raw_binary = 1;
			break;
		case 'h':
		default:
			command_help(opts, num_opts, name);
			return -1;
		}
	}

	get_dev(1, argc, argv);

	err = nvme_get_log(&fw_log,
			sizeof(fw_log), 0x3 | (((sizeof(fw_log) / 4) - 1) << 16),
			0xffffffff);
	if (!err) {
		if (!raw_binary)
			show_fw_log(&fw_log);
		else
			d_raw((unsigned char *)&fw_log, sizeof(fw_log));
	}
	else if (err > 0)
		fprintf(stderr, "NVMe Status: %s(%x)\n",
				nvme_status_to_string(err), err);
	else
		perror("fw log");
	return err;
}

static int get_log(int argc, char **argv)
{
	int c;
	int err;
	int option_index = 0;

	uint32_t namespace_id = 0;
	uint32_t log_id = 0;
	uint32_t log_len = 0;
	uint8_t raw_binary = 0;
	char *name = argv[0];
	int num_opts = 4;
	static struct option opts[] = {
		{"namespace-id", required_argument, 0, 'n'},
		{"log-id",       required_argument, 0, 'i'},
		{"log-len",      required_argument, 0, 'l'},
		{"raw-binary",   no_argument,       0, 'b'},
		{"help",	 no_argument,	    0, 'h'},
		{0,		 0,		    0,	0}
	};

	/* get device before parsing since it's a non-opt-arg */
	get_dev(1, argc, argv);

	while((c = getopt_long(argc, argv, "hl:i:n:b", opts, &option_index)) != -1) {
		switch (c) {
		case 'l':
			log_len = atoi(optarg);
			break;
		case 'i':
			log_id = atoi(optarg);
			break;
		case 'b':
			raw_binary = 1;
			break;
		case 'h':
		default:
			command_help(opts, num_opts, name);
			return -1;
		}
	}

	if (!log_len) {
		fprintf(stderr, "nvme get-log requires a non-zero log length "\
				"to fetch.\n");
		return EINVAL;
	} else {
		unsigned char log[log_len];

		err = nvme_get_log(log, log_len, log_id | (((log_len / 4) - 1) << 16),
				   namespace_id);
		if (!err) {
			if (!raw_binary) {
				printf("Device: %s log-id: %d namespace-id: %#x",
				       devicename, log_id,
				       namespace_id);
				d(log, log_len, 16, 1);
			} else
				d_raw((unsigned char *)log, log_len);
		} else if (err > 0)
			fprintf(stderr, "NVMe Status: %s(%x)\n",
						nvme_status_to_string(err), err);
		return err;
	}
}

static int list_ctrl(int argc, char **argv)
{
	int c;
	int err;
	int i;
	int option_index = 0;
	char *name = argv[0];
	uint16_t controller_id = 0;
	uint32_t namespace_id = 0;

	struct nvme_controller_list *controller_list;
	int num_opts = 2;
	static struct option opts[] = {
		{"controller-id", required_argument, 0, 'c'},
		{"namespace-id",  required_argument, 0, 'n'},
		{"help",	  no_argument,	     0, 'h'},
		{0,		  0,		     0,	0}
	};

	/* get device before parsing since it's a non-opt-arg */
	get_dev(1, argc, argv);

	while((c = getopt_long(argc, argv, "hc:n:", opts, &option_index)) != -1) {
		switch (c) {
		case 'c':
			controller_id = atoi(optarg);
			break;
		case 'n':
			namespace_id = atoi(optarg);
			break;
		case 'h':
		default:
			command_help(opts, num_opts, name);
			return -1;
		}
	}

	if (posix_memalign((void *)&controller_list, getpagesize(), 0x1000))
		return ENOMEM;

	err = identify(namespace_id, controller_list,
			controller_id << 16 | namespace_id ? 0x12 : 0x13);
	if (!err) {
		for (i = 0; i < (min(controller_list->num, 2048)); i++)
			printf("[%4u]: %#x\n", i, controller_list->identifier[i]);
	}
	else if (err > 0)
		fprintf(stderr, "NVMe Status: %s(%x) controller-id: %d\n",
			nvme_status_to_string(err), err, controller_id);
	return err;
}

static int list_ns(int argc, char **argv)
{
	int c;
	int err;
	int i;
	__u32 ns_list[1024];
	int option_index = 0;
	char *name = argv[0];
	uint32_t namespace_id = 0;
	int num_opts = 1;
	static struct option opts[] = {
		{"namespace-id",   required_argument,    0, 'n'},
		{"help",	   no_argument,		 0, 'h'},
		{0,		   0,			 0, 0}
	};

	/* get device before parsing since it's a non-opt-arg */
	get_dev(1, argc, argv);

	while((c = getopt_long(argc, argv, "hn:", opts, &option_index)) != -1) {
		switch (c) {
		case 'n':
			namespace_id = atoi(optarg);
			break;
		case 'h':
		default:
			command_help(opts, num_opts, name);
			return -1;
		}
	}

	err = identify(namespace_id, ns_list, 2);
	if (!err) {
		for (i = 0; i < 1024; i++)
			if (ns_list[i])
				printf("[%4u]: %#x\n", i, ns_list[i]);
	}
	else if (err > 0)
		fprintf(stderr, "NVMe Status: %s(%x) NSID: %d\n",
			nvme_status_to_string(err), err, namespace_id);
	return err;
}

static int delete_ns(int argc, char **argv)
{
	struct nvme_admin_cmd cmd;
	int c;
	int err;
	int option_index = 0;
	char *name = argv[0];
	uint32_t namespace_id = 0;
	int num_opts = 1;
	static struct option opts[] = {
		{"namespace-id",   required_argument,    0, 'n'},
		{"help",	   no_argument,		 0, 'h'},
		{0,		   0,			 0, 0}
	};

	/* get device before parsing since it's a non-opt-arg */
	get_dev(1, argc, argv);

	while((c = getopt_long(argc, argv, "hn:", opts, &option_index)) != -1) {
		switch (c) {
		case 'n':
			namespace_id = atoi(optarg);
			break;
		case 'h':
		default:
			command_help(opts, num_opts, name);
			return -1;
		}
	}

	if (!namespace_id) {
		fprintf(stderr, "%s: namespace-id parameter required\n",
						commands[DELETE_NS].name);
		return EINVAL;
	}

	memset(&cmd, 0, sizeof(cmd));
	cmd.opcode = nvme_admin_ns_mgmt;
	cmd.nsid = namespace_id;
	cmd.cdw10 = 1;

	err = ioctl(fd, NVME_IOCTL_ADMIN_CMD, &cmd);
	if (!err)
		printf("%s: Success, deleted nsid: %d\n", commands[DELETE_NS].name,
								namespace_id);
	else if (err > 0)
		fprintf(stderr, "NVMe Status: %s(%x)\n",
					nvme_status_to_string(err), err);
	return err;
}

static int nvme_attach_ns(int argc, char **argv, int attach)
{
	struct nvme_admin_cmd cmd;
	char *name = commands[attach ? ATTACH_NS : DETACH_NS].name;

	struct nvme_controller_list *controller_list;
	char *controllers = NULL;
	char *ocpy = NULL;
	int iter = 0;
	int c;
	int err;
	int option_index = 0;
	char *n = argv[0];
	uint32_t namespace_id = 0;
	int num_opts = 2;
	static struct option opts[] = {
		{"namespace-id",   required_argument,    0, 'n'},
		{"controllers",    required_argument,	 0, 'c'},
		{"help",	   no_argument,		 0, 'h'},
		{0,		   0,			 0, 0}
	};

	/* get device before parsing since it's a non-opt-arg */
	get_dev(1, argc, argv);

	while((c = getopt_long(argc, argv, "hn:c:", opts, &option_index)) != -1) {
		switch (c) {
		case 'n':
			namespace_id = atoi(optarg);
			break;
		case 'c':
			ocpy = strdup(optarg);
			controllers = strtok(ocpy,",\n");

			/* pull out comma-separated list of controllers */
			if ((controllers != NULL) && (controllers != 0)) {
				if (posix_memalign((void *)&controller_list,
						   getpagesize(), 0x1000)) {
					free(ocpy);
					free(controller_list);
					return ENOMEM;
				}

				controller_list = memset(controller_list,
						  0, sizeof(*controller_list));
				controller_list->identifier[iter] =
					atoi(controllers);
				iter++;

				do {
					controllers = strtok(NULL, ",\n ");
					if (controllers == NULL) break;

					controller_list->identifier[iter] =
						atoi(controllers);
					iter++;

				} while (iter < strlen(optarg));

			}
			free(controller_list);
			free(ocpy);
			break;
		case 'h':
		default:
			command_help(opts, num_opts, n);
			free(controllers);
			return -1;
		}
	}

	if (!namespace_id) {
		fprintf(stderr, "nvme %s: namespace-id parameter required\n",
						name);
		return EINVAL;
	}

	memset(&cmd, 0, sizeof(cmd));
	cmd.opcode = nvme_admin_ns_attach;
	cmd.addr = (__u64)controller_list;
	cmd.data_len = 4096;
	cmd.nsid = namespace_id;
	cmd.cdw10 = attach ? 0 : 1;

	err = ioctl(fd, NVME_IOCTL_ADMIN_CMD, &cmd);
	if (!err)
		printf("%s: Success, nsid: %d\n", name, namespace_id);
	else if (err > 0)
		fprintf(stderr, "NVMe Status: %s(%x)\n",
					nvme_status_to_string(err), err);
	return err;
}

static int attach_ns(int argc, char **argv)
{
	return nvme_attach_ns(argc, argv, 1);
}

static int detach_ns(int argc, char **argv)
{
	return nvme_attach_ns(argc, argv, 0);
}

static int create_ns(int argc, char **argv)
{
	struct nvme_admin_cmd cmd;
	struct nvme_id_ns *ns;
	int c;
	int err = 0;
	int option_index = 0;
	char *name = argv[0];
	uint64_t nsze = 0;
	uint64_t ncap = 0;
	uint8_t flbas = 0;
	uint8_t dps = 0;
	uint8_t nmic = 0;
	int num_opts = 5;
	static struct option opts[] = {
		{"nsze",           required_argument,	 0, 's'},
		{"ncap",           required_argument,	 0, 'c'},
		{"flbas",          required_argument,	 0, 'f'},
		{"dps",            required_argument,	 0, 'd'},
		{"nmic",           required_argument,	 0, 'm'},
		{"help",	   no_argument,		 0, 'h'},
		{0,		   0,			 0, 0}
	};

	/* get device before parsing since it's a non-opt-arg */
	get_dev(1, argc, argv);

	while((c = getopt_long(argc, argv, "hs:c:f:d:m:", opts, &option_index)) != -1) {
		switch (c) {
		case 's':
			nsze = strtoull(optarg, NULL, 10);
			break;
		case 'c':
			ncap = strtoull(optarg, NULL, 10);
			break;
		case 'f':
			flbas = atoi(optarg);
			break;
		case 'd':
			dps = atoi(optarg);
			break;
		case 'm':
			nmic = atoi(optarg);
			break;
		case 'h':
		default:
			command_help(opts, num_opts, name);
			return -1;
		}
	}

	if (posix_memalign((void *)&ns, getpagesize(), 4096))
		return -ENOMEM;
	memset(ns, 0, sizeof(*ns));
	memset(&cmd, 0, sizeof(cmd));

	ns->nsze  = nsze;
	ns->ncap  = ncap;
	ns->flbas = flbas;
	ns->dps   = dps;
	ns->nmic  = nmic;

	cmd.opcode = nvme_admin_ns_mgmt;
	cmd.addr = (unsigned long)ns;
	cmd.data_len = 4096;

	err = ioctl(fd, NVME_IOCTL_ADMIN_CMD, &cmd);
	if (!err)
		printf("%s: Success, created nsid: %d\n", commands[CREATE_NS].name,
								cmd.result);
	else if (err > 0)
		fprintf(stderr, "NVMe Status: %s(%x)\n",
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

	fprintf(stdout, "%-8s\t%-.20s\t%-8s\t%-8d\t%-26s\t%-.16s\n", list_item.node,
		list_item.ctrl.mn, version, list_item.nsid, usage, format);
}

static void print_list_items(struct list_item *list_items, unsigned len)
{
	fprintf(stdout,"%-8s\t%-20s\t%-8s\t%-8s\t%-26s\t%-16s\n",
		"Node","Vendor","Version","Namepace", "Usage", "Format");
	fprintf(stdout,"%-8s\t%-20s\t%-8s\t%-8s\t%-26s\t%-16s\n",
		"----","------","-------","--------","------","-------");
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
	char *name = argv[0];
	int c;
	int err;
	int option_index = 0;
	struct nvme_id_ctrl ctrl;
	uint8_t vendor_specific = 0;
	uint8_t raw_binary = 0;
	uint8_t human_readable = 0;
	int num_opts = 3;
	static struct option opts[] = {
		{"vendor-specific",	no_argument,	0, 'v'},
		{"raw-binary",		no_argument,	0, 'b'},
		{"human-readable",	no_argument,	0, 'H'},
		{"help",		no_argument,	0, 'h'},
		{0,			0,		0, 0}
	};

	/* get device before parsing since it's a non-opt-arg */
	get_dev(1, argc, argv);

	while((c = getopt_long(argc, argv, "hvbH", opts, &option_index)) != -1) {
		switch (c) {
		case 'v':
			vendor_specific = 1;
			break;
		case 'b':
			raw_binary = 1;
			break;
		case 'H':
			human_readable = 1;
			break;
		case 'h':
		default:
			command_help(opts, num_opts, name);
			return -1;
		}
	}

	err = identify(0, &ctrl, 1);
	if (!err) {
		if (raw_binary)
			d_raw((unsigned char *)&ctrl, sizeof(ctrl));
		else
			show_nvme_id_ctrl(&ctrl, vendor_specific, human_readable);
	}
	else if (err > 0)
		fprintf(stderr, "NVMe Status: %s(%x)\n",
				nvme_status_to_string(err), err);

	return err;
}

static int id_ns(int argc, char **argv)
{
	char *name = argv[0];
	int c;
	int err;
	int option_index = 0;
	struct nvme_id_ns ns;
	uint8_t vendor_specific = 0;
	uint8_t raw_binary = 0;
	uint8_t human_readable = 0;
	uint32_t namespace_id = 0;
	int num_opts = 4;
	static struct option opts[] = {
		{"namespace-id",	required_argument, 0, 'n'},
		{"vendor-specific",	no_argument,	   0, 'v'},
		{"raw-binary",		no_argument,	   0, 'b'},
		{"human-readable",	no_argument,	   0, 'H'},
		{"help",		no_argument,	   0, 'h'},
		{0,			0,		   0, 0}
	};

	/* get device before parsing since it's a non-opt-arg */
	get_dev(1, argc, argv);

	while((c = getopt_long(argc, argv, "hvbHn:", opts, &option_index)) != -1) {
		switch (c) {
		case 'v':
			vendor_specific = 1;
			break;
		case 'b':
			raw_binary = 1;
			break;
		case 'H':
			human_readable = 1;
			break;
		case 'n':
			namespace_id = atoi(optarg);
			break;
		case 'h':
		default:
			command_help(opts, num_opts, name);
			return -1;
		}
	}

	if (!namespace_id) {
		if (!S_ISBLK(nvme_stat.st_mode)) {
			fprintf(stderr,
				"%s: non-block device requires namespace-id param\n",
				devicename);
			exit(ENOTBLK);
		}
		namespace_id = ioctl(fd, NVME_IOCTL_ID);
		if (namespace_id <= 0) {
			perror(devicename);
			exit(errno);
		}
	}
	err = identify(namespace_id, &ns, 0);
	if (!err) {
		if (raw_binary)
			d_raw((unsigned char *)&ns, sizeof(ns));
		else
			show_nvme_id_ns(&ns, namespace_id,
					vendor_specific, human_readable);
	}
	else if (err > 0)
		fprintf(stderr, "NVMe Status: %s(%x) NSID: %d\n",
			nvme_status_to_string(err), err, namespace_id);
	return err;
}

static int get_ns_id(int argc, char **argv)
{
	int nsid;

	open_dev(argv[1]);
	if (!S_ISBLK(nvme_stat.st_mode)) {
		fprintf(stderr, "nvme get-ns-id: %s is not"\
				" a block device; a namespace ID is needed\n",
								devicename);
		exit(ENOTBLK);
	}
	nsid = ioctl(fd, NVME_IOCTL_ID);
	if (nsid <= 0) {
		perror(devicename);
		exit(errno);
	}
	printf("%s: namespace-id: %d\n", devicename, nsid);
	return 0;
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
	int c;
	int err;
	unsigned int result, cdw10 = 0;
	void *buf = NULL;
	int option_index = 0;
	char *name = argv[0];
	uint8_t sel = 0;
	uint8_t raw_binary = 0;
	uint32_t namespace_id = 0;
	uint32_t feature_id = 0;
	uint32_t cdw11 = 0;
	uint32_t data_len = 0;
	int num_opts = 6;
	static struct option opts[] = {
		{"namespace-id",   required_argument,    0, 'n'},
		{"feature-id",	   required_argument,	 0, 'f'},
		{"sel",            required_argument,	 0, 's'},
		{"data-len",       required_argument,	 0, 'l'},
		{"cdw11",	   required_argument,    0, 'c'},
		{"raw-binary",	   no_argument,		 0, 'b'},
		{"help",	   no_argument,		 0, 'h'},
		{0,		   0,			 0, 0}
	};

	/* get device before parsing since it's a non-opt-arg */
	get_dev(1, argc, argv);

	while((c = getopt_long(argc, argv, "hbn:f:s:l:c:", opts, &option_index)) != -1) {
		switch (c) {
		case 'n':
			namespace_id = atoi(optarg);
			break;
		case 'f':
			feature_id = atoi(optarg);
			break;
		case 's':
			sel = atoi(optarg);
			break;
		case 'l':
			data_len = atoi(optarg);
			break;
		case 'c':
			cdw11 = atoi(optarg);
			break;
		case 'b':
			raw_binary = 1;
			break;
		case 'h':
		default:
			command_help(opts, num_opts, name);
			return -1;
		}
	}

	if (sel > 7) {
		fprintf(stderr, "invalid 'select' param: %d\n", sel);
		return EINVAL;
	}
	if (!feature_id) {
		fprintf(stderr, "nvme get-feature: cannot get feature without feature-id\n");
		return EINVAL;
	}
	if (feature_id == NVME_FEAT_LBA_RANGE)
		data_len = 4096;
	if (data_len)
		buf = malloc(data_len);

	cdw10 = sel << 8 | feature_id;
	err = nvme_feature(nvme_admin_get_features, buf, data_len, cdw10,
			   namespace_id, cdw11, &result);
	if (!err) {
		printf("get-feature: %d(%s), value: %#08x\n", feature_id,
			nvme_feature_to_string(feature_id), result);
		if (buf) {
			if (!raw_binary) {
				if (feature_id == NVME_FEAT_LBA_RANGE)
					show_lba_range((struct nvme_lba_range_type *)buf,
									result);
				else
					d(buf, data_len, 16, 1);
			}
			else
				d_raw(buf, data_len);
		}
	}
	else if (err > 0)
		fprintf(stderr, "NVMe Status: %s(%x)\n",
				nvme_status_to_string(err), err);
	if (buf)
		free(buf);
	return err;
}

static int fw_download(int argc, char **argv)
{
	int err;
	int fw_fd = -1;
	unsigned int fw_size;
	struct stat sb;
	struct nvme_admin_cmd cmd;
	void *fw_buf;
	int c;
	int option_index = 0;
	char *name = argv[0];
	char *fw = NULL;
	uint32_t xfer = 0;
	uint32_t offset = 0;
	int num_opts = 3;
	static struct option opts[] = {
		{"fw",		   required_argument,	0, 'f'},
		{"xfer",	   required_argument,   0, 'x'},
		{"offset",	   required_argument,   0, 'o'},
		{"help",	   no_argument,		0, 'h'},
		{0,		   0,			0, 0}
	};

	/* get device before parsing since it's a non-opt-arg */
	get_dev(1, argc, argv);

	while((c = getopt_long(argc, argv, "hf:x:o:", opts, &option_index)) != -1) {
		switch (c) {
		case 'f':
			fw = strdup(optarg);
			break;
		case 'x':
			xfer = atoi(optarg);
			break;
		case 'o':
			offset = atoi(optarg);
			break;
		case 'h':
		default:
			command_help(opts, num_opts, name);
			return -1;
		}
	}

	fw_fd = open(fw, O_RDONLY);
	offset <<= 2;
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
		fprintf(stderr, "Invalid size: %d for f/w image\n", fw_size);
		return EINVAL;
	}
	if (posix_memalign(&fw_buf, getpagesize(), fw_size)) {
		fprintf(stderr, "No memory for f/w size: %d\n", fw_size);
		return ENOMEM;
	}
	if (xfer == 0 || xfer % 4096)
		xfer = 4096;
	if (read(fw_fd, fw_buf, fw_size) != ((ssize_t)(fw_size)))
		return EIO;

	while (fw_size > 0) {
		xfer = min(xfer, fw_size);

		memset(&cmd, 0, sizeof(cmd));
		cmd.opcode   = nvme_admin_download_fw;
		cmd.addr     = (__u64)fw_buf;
		cmd.data_len = xfer;
		cmd.cdw10    = (xfer >> 2) - 1;
		cmd.cdw11    = offset >> 2;

		err = ioctl(fd, NVME_IOCTL_ADMIN_CMD, &cmd);
		if (err < 0) {
			perror("ioctl");
			exit(errno);
		} else if (err != 0) {
			fprintf(stderr, "NVME Admin command error: %s(%x)\n",
					nvme_status_to_string(err), err);
			break;
		}
		fw_buf     += xfer;
		fw_size    -= xfer;
		offset += xfer;
	}
	if (!err)
		printf("Firmware download success\n");
	return err;
}

static int fw_activate(int argc, char **argv)
{
	int c;
	int err;
	int option_index = 0;
	struct nvme_admin_cmd cmd;
	char *name = argv[0];
	uint8_t slot = 0;
	uint8_t action = 0;
	int num_opts = 2;
	static struct option opts[] = {
		{"slot",	required_argument,  0 ,'s'},
		{"action",	required_argument,  0, 'a'},
		{"help",	no_argument,	    0, 'h'},
		{0,		0,		    0,	0}
	};

	while((c = getopt_long(argc, argv, "hs:a:", opts, &option_index)) != -1) {
		switch (c) {
		case 's':
			slot = atoi(optarg);
			break;
		case 'a':
			action = atoi(optarg);
			break;
		case 'h':
		default:
			command_help(opts, num_opts, name);
			return -1;
		}
	}

	get_dev(1, argc, argv);

	if (slot > 7) {
		fprintf(stderr, "invalid slot: %d\n", slot);
		return EINVAL;
	}
	if (action > 3) {
		fprintf(stderr, "invalid action: %d\n", action);
		return EINVAL;
	}

	memset(&cmd, 0, sizeof(cmd));
	cmd.opcode = nvme_admin_activate_fw;
	cmd.cdw10  = (action << 3) | slot;

	err = ioctl(fd, NVME_IOCTL_ADMIN_CMD, &cmd);
	if (err < 0)
		perror("ioctl");
	else if (err != 0)
		if (err == NVME_SC_FIRMWARE_NEEDS_RESET)
			printf("Success activating firmware action:%d slot:%d,"\
				" but a conventional reset is required\n",
			       action, slot);
		else
			fprintf(stderr, "NVME Admin command error:%s(%x)\n",
						nvme_status_to_string(err), err);
	else
		printf("Success activating firmware; action: %d slot: %d\n",
		       action, slot);
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
	int c;
	int err;
	struct nvme_admin_cmd cmd;
	int option_index = 0;
	char *name = argv[0];
	uint8_t lbaf = 0;
	uint8_t ses = 0;
	uint8_t pi = 0;
	uint8_t pil = 0;
	uint8_t ms = 0;
	uint32_t namespace_id = 0;
	int num_opts = 6;
	static struct option opts[] = {
		{"namespace-id",   required_argument,    0, 'n'},
		{"lbaf",           required_argument,	 0, 'l'},
		{"ses",            required_argument,	 0, 's'},
		{"pi",		   required_argument,	 0, 'i'},
		{"pil",		   required_argument,	 0, 'p'},
		{"ms",		   required_argument,	 0, 'm'},
		{"help",	   no_argument,		 0, 'h'},
		{0,		   0,			 0, 0}
	};

	/* get device before parsing since it's a non-opt-arg */
	get_dev(1, argc, argv);

	while((c = getopt_long(argc, argv, "hn:l:s:i:p:m:", opts, &option_index)) != -1) {
		switch (c) {
		case 'n':
			namespace_id = atoi(optarg);
			break;
		case 'l':
			lbaf = atoi(optarg);
			break;
		case 's':
			ses = atoi(optarg);
			break;
		case 'i':
			pi = atoi(optarg);
			break;
		case 'p':
			pil = atoi(optarg);
			break;
		case 'm':
			ms = atoi(optarg);
			break;
		case 'h':
		default:
			command_help(opts, num_opts, name);
			return -1;
		}
	}

	if (ses > 7) {
		fprintf(stderr, "invalid secure erase settings: %d\n", ses);
		return EINVAL;
	}
	if (lbaf > 15) {
		fprintf(stderr, "invalid lbaf: %d\n", lbaf);
		return EINVAL;
	}
	if (pi > 7) {
		fprintf(stderr, "invalid pi: %d\n", pi);
		return EINVAL;
	}
	if (S_ISBLK(nvme_stat.st_mode)) {
		namespace_id = ioctl(fd, NVME_IOCTL_ID);
		if (namespace_id <= 0) {
			fprintf(stderr,
				"%s: failed to return namespace id\n",
				devicename);
			return errno;
		}
	}

	memset(&cmd, 0, sizeof(cmd));
	cmd.opcode = nvme_admin_format_nvm;
	cmd.nsid   = namespace_id;
	cmd.cdw10  = (lbaf << 0) | (ms << 4) | (pi << 5) | (pil << 8) | (ses << 9);
	cmd.timeout_ms = FORMAT_TIMEOUT;

	err = ioctl(fd, NVME_IOCTL_ADMIN_CMD, &cmd);
	if (err < 0)
		perror("ioctl");
	else if (err != 0)
		fprintf(stderr, "NVME Admin command error: %s(%x)\n",
					nvme_status_to_string(err), err);
	else {
		printf("Success formatting namespace: %x\n", namespace_id);
		ioctl(fd, BLKRRPART);
	}
	return err;
}

static int set_feature(int argc, char **argv)
{
	unsigned int result;
	void *buf = NULL;
	int fd = STDIN_FILENO;
	int c;
	int err;
	int option_index = 0;
	char *name = argv[0];
	char *file = NULL;
	uint32_t namespace_id = 0;
	uint32_t feature_id = 0;
	uint32_t value = 0;
	uint32_t data_len = 0;
	int num_opts = 5;
	static struct option opts[] = {
		{"namespace-id", required_argument, 0, 'n'},
		{"feature-id",   required_argument, 0, 'f'},
		{"value",        required_argument, 0, 'v'},
		{"data-len",     required_argument, 0, 'l'},
		{"data",         required_argument, 0, 'd'},
		{"help",	 no_argument,       0, 'h'},
		{0,		0,		    0, 0}
	};

	/* get device before parsing since it's a non-opt-arg */
	get_dev(1, argc, argv);

	while((c = getopt_long(argc, argv, "hn:f:v:l:d:", opts, &option_index)) != -1) {
		switch (c) {
		case 'n':
			namespace_id = atoi(optarg);
			break;
		case 'f':
			feature_id = atoi(optarg);
			break;
		case 'v':
			value = atoi(optarg);
			break;
		case 'l':
			data_len = atoi(optarg);
			break;
		case 'd':
			file = strdup(optarg);
			break;
		case 'h':
		default:
			command_help(opts, num_opts, name);
			return -1;
		}
	}

	if (value == -1) {
		fprintf(stderr, "nvme set-feature: a new feature value is required\n");
		return EINVAL;
	}
	if (!feature_id) {
		fprintf(stderr, "nvme set-feature: the feature id is required\n");
		return EINVAL;
	}
	if (feature_id == NVME_FEAT_LBA_RANGE)
		data_len = 4096;
	if (data_len)
		buf = malloc(data_len);
	if (buf) {
		if (strlen(file)) {
			fd = open(file, O_RDONLY);
			if (fd <= 0) {
				fprintf(stderr, "no firmware file provided\n");
				return -EINVAL;
			}
		}
		if (read(fd, (void *)buf, data_len) < 0) {
			fprintf(stderr, "failed to read data buffer from input file\n");
			return EINVAL;
		}
	}

	err = nvme_feature(nvme_admin_set_features, buf, data_len, feature_id,
			   namespace_id, value, &result);
	if (!err) {
		printf("set-feature: %d(%s), value: %#08x\n", feature_id,
			nvme_feature_to_string(feature_id), result);
		if (buf) {
			if (feature_id == NVME_FEAT_LBA_RANGE)
				show_lba_range((struct nvme_lba_range_type *)buf,
								result);
			else
				d(buf, data_len, 16, 1);
		}
	}
	else if (err > 0)
		fprintf(stderr, "NVMe Status: %s(%x)\n",
				nvme_status_to_string(err), err);
	if (buf)
		free(buf);
	return err;
}

static int sec_send(int argc, char **argv)
{
	struct stat sb;
	struct nvme_admin_cmd cmd;
	int c;
	int err;
	int sec_fd = -1;
	void *sec_buf;
	unsigned int sec_size;
	int option_index = 0;
	char *name = argv[0];
	char *file = NULL;
	uint8_t secp = 0;
	uint16_t spsp = 0;
	uint32_t tl = 0;
	int num_opts = 4;
	static struct option opts[] = {
		{"file",	   required_argument,	 0, 'f'},
		{"secp",	   required_argument,    0, 'p'},
		{"spsp",	   required_argument,    0, 's'},
		{"tl",		   required_argument,	 0, 't'},
		{"help",	   no_argument,		 0, 'h'},
		{0,		   0,			 0, 0}
	};

	/* get device before parsing since it's a non-opt-arg */
	get_dev(1, argc, argv);

	while((c = getopt_long(argc, argv, "hf:p:s:t:", opts, &option_index)) != -1) {
		switch (c) {
		case 'f':
			file = strdup(optarg);
			break;
		case 'p':
			secp = atoi(optarg);
			break;
		case 's':
			spsp = atoi(optarg);
			break;
		case 't':
			tl = atoi(optarg);
			break;
		case 'h':
		default:
			command_help(opts, num_opts, name);
			return -1;
		}
	}

	sec_fd = open(file, O_RDONLY);
	if (sec_fd < 0) {
		fprintf(stderr, "nvme security-send: a firmware file must be provided\n");
		return EINVAL;
	}
	err = fstat(sec_fd, &sb);
	if (err < 0) {
		perror("fstat");
		return errno;
	}
	sec_size = sb.st_size;
	if (posix_memalign(&sec_buf, getpagesize(), sec_size)) {
		fprintf(stderr, "No memory for security size: %d\n", sec_size);
		return ENOMEM;
	}

	memset(&cmd, 0, sizeof(cmd));
	cmd.opcode   = nvme_admin_security_send;
	cmd.cdw10    = secp << 24 | spsp << 8;
	cmd.cdw11    = tl;
	cmd.data_len = sec_size;
	cmd.addr     = (__u64)sec_buf;

	err = ioctl(fd, NVME_IOCTL_ADMIN_CMD, &cmd);
	if (err < 0)
		return errno;
	else if (err != 0)
		fprintf(stderr, "NVME Security Send Command Error: %d\n", err);
	else
		printf("NVME Security Send Command Success: %d\n", cmd.result);
	return err;
}

static int flush(int argc, char **argv)
{
	struct nvme_passthru_cmd cmd;
	int c;
	int err;
	int option_index = 0;
	char *name = argv[0];
	uint32_t namespace_id = 0;
	int num_opts = 1;
	static struct option opts[] = {
		{"namespace-id",   required_argument,    0, 'n'},
		{"help",	   no_argument,		 0, 'h'},
		{0,		   0,			 0, 0}
	};

	/* get device before parsing since it's a non-opt-arg */
	get_dev(1, argc, argv);

	while((c = getopt_long(argc, argv, "hn:", opts, &option_index)) != -1) {
		switch (c) {
		case 'n':
			namespace_id = atoi(optarg);
			break;
		case 'h':
		default:
			command_help(opts, num_opts, name);
			return -1;
		}
	}

	memset(&cmd, 0, sizeof(cmd));
	cmd.opcode = nvme_cmd_flush;
	cmd.nsid   = namespace_id;

	err = ioctl(fd, NVME_IOCTL_IO_CMD, &cmd);
	if (err < 0)
		return errno;
	else if (err != 0)
		fprintf(stderr, "NVME IO command error: %s(%x)\n",
				nvme_status_to_string(err), err);
	else
		printf("NVMe Flush: success\n");
	return 0;
}

static int resv_acquire(int argc, char **argv)
{
	struct nvme_passthru_cmd cmd;
	int c;
	int err;
	__u64 payload[2];
	int option_index = 0;
	char *name = argv[0];
	uint8_t rtype = 0;
	uint8_t racqa = 0;
	uint8_t iekey = 0;
	uint32_t namespace_id = 0;
	uint64_t crkey = 0;
	uint64_t prkey = 0;
	int num_opts = 6;
	static struct option opts[] = {
		{"namespace-id",   required_argument,    0, 'n'},
		{"crkey",          required_argument,	 0, 'c'},
		{"prkey",	   required_argument,	 0, 'p'},
		{"rtype",	   required_argument,    0, 't'},
		{"racqa",          required_argument,	 0, 'a'},
		{"iekey",	   no_argument,		 0, 'i'},
		{"help",	   no_argument,          0, 'h'},
		{0,		   0,			 0, 0}
	};

	/* get device before parsing since it's a non-opt-arg */
	get_dev(1, argc, argv);

	while((c = getopt_long(argc, argv, "hin:c:p:t:a:", opts, &option_index)) != -1) {
		switch (c) {
		case 'n':
			namespace_id = atoi(optarg);
			break;
		case 'c':
			crkey = strtoull(optarg, NULL, 10);
			break;
		case 'p':
			prkey = strtoull(optarg, NULL, 10);
			break;
		case 't':
			rtype = atoi(optarg);
			break;
		case 'a':
			racqa = atoi(optarg);
			break;
		case 'i':
			iekey = 1;
			break;
		case 'h':
		default:
			command_help(opts, num_opts, name);
			return -1;
		}
	}

	if (!namespace_id) {
		if (!S_ISBLK(nvme_stat.st_mode)) {
			fprintf(stderr,
				"nvme resv-acquire: %s is not a block "\
				"device; a namespace id is needed\n",
				devicename);
			exit(ENOTBLK);
		}
		namespace_id = ioctl(fd, NVME_IOCTL_ID);
		if (namespace_id <= 0) {
			fprintf(stderr,
				"%s: failed to return namespace id\n",
				devicename);
			return errno;
		}
	}
	if (racqa > 7) {
		fprintf(stderr, "invalid racqa: %d\n", racqa);
		return EINVAL;
	}

	payload[0] = crkey;
	payload[1] = prkey;

	memset(&cmd, 0, sizeof(cmd));
	cmd.opcode   = nvme_cmd_resv_acquire;
	cmd.nsid     = namespace_id;
	cmd.cdw10    = rtype << 8 | iekey << 3 | racqa;
	cmd.addr     = (__u64)payload;
	cmd.data_len = sizeof(payload);

	err = ioctl(fd, NVME_IOCTL_IO_CMD, &cmd);
	if (err < 0)
		return errno;
	else if (err != 0)
		fprintf(stderr, "NVME IO command error: %04x\n", err);
	else
		printf("NVME Reservation Acquire success\n");
	return 0;
}

static int resv_register(int argc, char **argv)
{
	struct nvme_passthru_cmd cmd;
	int c;
	int err;
	__u64 payload[2];
	int option_index = 0;
	char *name = argv[0];
	uint8_t rrega = 0;
	uint8_t cptpl = 0;
	uint8_t iekey = 0;
	uint32_t namespace_id = 0;
	uint64_t crkey = 0;
	uint64_t nrkey = 0;
	int num_opts = 6;
	static struct option opts[] = {
		{"namespace-id",   required_argument,    0, 'n'},
		{"crkey",          required_argument,	 0, 'c'},
		{"nrkey",          required_argument,	 0, 'k'},
		{"rrega",          required_argument,	 0, 'r'},
		{"cptpl",          required_argument,    0, 'p'},
		{"iekey",	   no_argument,		 0, 'i'},
		{"help",	   no_argument,		 0, 'h'},
		{0,		   0,			 0, 0}
	};

	/* get device before parsing since it's a non-opt-arg */
	get_dev(1, argc, argv);

	while((c = getopt_long(argc, argv,
			"hin:c:k:r:p:", opts, &option_index)) != -1) {
		switch (c) {
		case 'n':
			namespace_id = atoi(optarg);
			break;
		case 'c':
			crkey = strtoull(optarg, NULL, 10);
			break;
		case 'k':
			nrkey = strtoull(optarg, NULL, 10);
			break;
		case 'r':
			rrega = atoi(optarg);
			break;
		case 'p':
			cptpl = atoi(optarg);
			break;
		case 'i':
			iekey = 1;
			break;
		case 'h':
		default:
			command_help(opts, num_opts, name);
			return -1;
		}
	}

	if (!namespace_id) {
		if (!S_ISBLK(nvme_stat.st_mode)) {
			fprintf(stderr,
				"nvme resv-register: %s is not a block "\
				"device; a namespace id is needed\n",
				devicename);
			exit(ENOTBLK);
		}
		namespace_id = ioctl(fd, NVME_IOCTL_ID);
		if (namespace_id <= 0) {
			fprintf(stderr,
				"%s: failed to return namespace id\n",
				devicename);
			return errno;
		}
	}
	if (cptpl > 3) {
		fprintf(stderr, "invalid cptpl: %d\n", cptpl);
		return EINVAL;
	}

	payload[0] = crkey;
	payload[1] = nrkey;

	memset(&cmd, 0, sizeof(cmd));
	cmd.opcode   = nvme_cmd_resv_register;
	cmd.nsid     = namespace_id;
	cmd.cdw10    = cptpl << 30 | iekey << 3 | rrega;
	cmd.addr     = (__u64)payload;
	cmd.data_len = sizeof(payload);

	err = ioctl(fd, NVME_IOCTL_IO_CMD, &cmd);
	if (err < 0)
		return errno;
	else if (err != 0)
		fprintf(stderr, "NVME IO command error: %04x\n", err);
	else
		printf("NVME Reservation  success\n");
	return 0;
}

static int resv_release(int argc, char **argv)
{
	struct nvme_passthru_cmd cmd;
	int c;
	int err;
	int option_index = 0;
	char *name = argv[0];
	uint8_t rtype = 0;
	uint8_t rrela = 0;
	uint8_t iekey = 0;
	uint32_t namespace_id = 0;
	uint64_t crkey = 0;
	int num_opts = 5;
	static struct option opts[] = {
		{"namespace-id",   required_argument,    0, 'n'},
		{"rtype",          required_argument,    0, 't'},
		{"rrela",          required_argument,    0, 'a'},
		{"crkey",          required_argument,	 0, 'c'},
		{"iekey",	   no_argument,		 0, 'i'},
		{"help",	   no_argument,		 0, 'h'},
		{0,		   0,			 0, 0}
	};

	/* get device before parsing since it's a non-opt-arg */
	get_dev(1, argc, argv);

	while((c = getopt_long(argc, argv, "hin:t:a:c:",
				opts, &option_index)) != -1) {
		switch (c) {
		case 'n':
			namespace_id = atoi(optarg);
			break;
		case 't':
			rtype = atoi(optarg);
			break;
		case 'a':
			rrela = atoi(optarg);
			break;
		case 'c':
			crkey = strtoull(optarg, NULL, 10);
			break;
		case 'i':
			iekey = 1;
			break;
		case 'h':
		default:
			command_help(opts, num_opts, name);
			return -1;
		}
	}

	if (!namespace_id) {
		if (!S_ISBLK(nvme_stat.st_mode)) {
			fprintf(stderr,
				"nvme resv-release: %s is not a block"\
				"device; a namespace ID is needed\n",
				devicename);
			exit(ENOTBLK);
		}
		namespace_id = ioctl(fd, NVME_IOCTL_ID);
		if (namespace_id <= 0) {
			fprintf(stderr,
				"%s: failed to return namespace id\n",
				devicename);
			return errno;
		}
	}
	if (iekey > 1) {
		fprintf(stderr, "invalid iekey: %d\n", iekey);
		return EINVAL;
	}
	if (rrela > 7) {
		fprintf(stderr, "invalid rrela: %d\n", rrela);
		return EINVAL;
	}

	memset(&cmd, 0, sizeof(cmd));
	cmd.opcode   = nvme_cmd_resv_release;
	cmd.nsid     = namespace_id;
	cmd.cdw10    = rtype << 8 | iekey << 3 | rrela;
	cmd.addr     = (__u64)&crkey;
	cmd.data_len = sizeof(crkey);

	err = ioctl(fd, NVME_IOCTL_IO_CMD, &cmd);
	if (err < 0)
		return errno;
	else if (err != 0)
		fprintf(stderr, "NVME IO command error: %04x\n", err);
	else
		printf("NVME Reservation Register success\n");
	return 0;
}

static int resv_report(int argc, char **argv)
{
	struct nvme_passthru_cmd cmd;
	struct nvme_reservation_status *status;
	int c;
	int err;
	int option_index = 0;
	char *name = argv[0];
	uint8_t raw_binary = 0;
	uint32_t numd = 0;
	uint32_t namespace_id = 0;
	int num_opts = 3;
	static struct option opts[] = {
		{"namespace-id",   required_argument,    0, 'n'},
		{"numd",           required_argument,    0, 'd'},
		{"raw-binary",     no_argument,          0, 'b'},
		{"help",	   no_argument,		 0, 'h'},
		{0,		   0,			 0, 0}
	};

	/* get device before parsing since it's a non-opt-arg */
	get_dev(1, argc, argv);

	while((c = getopt_long(argc, argv, "hbn:d:", opts, &option_index)) != -1) {
		switch (c) {
		case 'n':
			namespace_id = atoi(optarg);
			break;
		case 'd':
			numd = atoi(optarg);
			break;
		case 'b':
			raw_binary = 1;
			break;
		case 'h':
		default:
			command_help(opts, num_opts, name);
			return -1;
		}
	}

	if (!namespace_id) {
		if (!S_ISBLK(nvme_stat.st_mode)) {
			fprintf(stderr,
				"nvme resv-report: %s is not a "\
				"block device; a namespace ID is needed\n",
				devicename);
			exit(ENOTBLK);
		}
		namespace_id = ioctl(fd, NVME_IOCTL_ID);
		if (namespace_id <= 0) {
			fprintf(stderr,
				"%s: failed to return namespace id\n",
				devicename);
			return errno;
		}
	}
	if (!numd || numd > (0x1000 >> 2))
		numd = 0x1000 >> 2;

	if (posix_memalign((void **)&status, getpagesize(), numd << 2)) {
		fprintf(stderr, "No memory for resv report: %d\n", numd << 2);
		return ENOMEM;
	}

	memset(&cmd, 0, sizeof(cmd));
	cmd.opcode   = nvme_cmd_resv_report;
	cmd.nsid     = namespace_id;
	cmd.cdw10    = numd;
	cmd.addr     = (__u64)status;
	cmd.data_len = numd << 2;

	err = ioctl(fd, NVME_IOCTL_IO_CMD, &cmd);
	if (err < 0)
		return errno;
	else if (err != 0)
		fprintf(stderr, "NVME IO command error: %04x\n", err);
	else {
		if (!raw_binary) {
			printf("NVME Reservation Report success\n");
			show_nvme_resv_report(status);
		} else
			d_raw((unsigned char *)status, numd << 2);
	}
	return 0;
}

static int submit_io(int opcode, char *command, int argc, char **argv)
{
	struct nvme_user_io io;
	struct timeval start_time, end_time;
	void *buffer, *mbuffer = NULL;
	int dfd = opcode & 1 ? STDIN_FILENO : STDOUT_FILENO;
	char *name = argv[0];
	int c;
	int err = 0;
	int option_index = 0;
	char  *data = NULL;
	uint8_t prinfo = 0;
	uint8_t app_tag_mask = 0;
	uint8_t limited_retry = 0;
	uint8_t force_unit_access = 0;
	uint8_t show = 0;
	uint8_t dry_run = 0;
	uint8_t latency = 0;
	uint16_t block_count = 0;
	uint32_t data_size = 0;
	uint32_t metadata_size = 0;
	uint32_t ref_tag = 0;
	uint32_t app_tag = 0;
	uint64_t start_block = 0;
	int num_opts = 14;
	static struct option opts[] = {
		{"start-block",		required_argument,	 0, 's'},
		{"block-count",		required_argument,	 0, 'c'},
		{"data-size",		required_argument,	 0, 'z'},
		{"metadata-size",	required_argument,	 0, 'y'},
		{"ref-tag",		required_argument,	 0, 'r'},
		{"data",		required_argument,	 0, 'd'},
		{"prinfo",		required_argument,	 0 ,'p'},
		{"app-tag-mask",	required_argument,	 0, 'm'},
		{"app-tag",		required_argument,	 0, 'a'},
		{"limited-retry",	no_argument,		 0, 'l'},
		{"force-unit-access",	no_argument,		 0, 'f'},
		{"show-command",	no_argument,		 0, 'v'},
		{"dry-run",		no_argument,		 0, 'w'},
		{"latency",		no_argument,		 0, 't'},
		{"help",		no_argument,		 0, 'h'},
		{0,		   0,			 0, 0}
	};

	/* get device before parsing since it's a non-opt-arg */
	get_dev(1, argc, argv);

	while((c = getopt_long(argc, argv, "hlfvwts:c:z:y:r:d:p:m:a:",
			       opts, &option_index)) != -1) {
		switch (c) {
		case 's':
			start_block = strtoull(optarg, NULL, 10);
			break;
		case 'c':
			block_count = atoi(optarg);
			break;
		case 'z':
			data_size = atoi(optarg);
			break;
		case 'y':
			metadata_size = atoi(optarg);
			break;
		case 'r':
			ref_tag = atoi(optarg);
			break;
		case 'd':
			data = strdup(optarg);
			break;
		case 'p':
			prinfo = atoi(optarg);
			break;
		case 'm':
			app_tag_mask = atoi(optarg);
			break;
		case 'a':
			app_tag = atoi(optarg);
			break;
		case 'l':
			limited_retry = 1;
			break;
		case 'f':
			force_unit_access = 1;
			break;
		case 'v':
			show = 1;
			break;
		case 'w':
			dry_run = 1;
			break;
		case 't':
			latency = 1;
			break;
		case 'h':
		default:
			command_help(opts, num_opts, name);
			return -1;
		}
	}

	memset(&io, 0, sizeof(io));

	io.slba    = start_block;
	io.nblocks = block_count;
	io.reftag  = ref_tag;
	io.appmask = app_tag_mask;
	io.apptag  = app_tag;
	if (prinfo > 0xf)
		return EINVAL;
	io.control |= (prinfo << 10);
	if (limited_retry)
		io.control |= NVME_RW_LR;
	if (force_unit_access)
		io.control |= NVME_RW_FUA;
	if ((data != NULL) && strlen(data)){
		if (opcode & 1)
			dfd = open(data, O_RDONLY);
		else
			dfd = open(data, O_WRONLY | O_CREAT,
				   S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP| S_IROTH);
		if (dfd < 0) {
			perror(data);
			return EINVAL;
		}
	}

	if (!data_size)	{
		fprintf(stderr, "nvme %s: data size to %s not provided but required\n", argv[0], argv[0]);
		return EINVAL;
	}
	buffer = malloc(data_size);
	if (metadata_size)
		mbuffer = malloc(metadata_size);
	if ((opcode & 1) && read(dfd, (void *)buffer, data_size) < 0) {
		fprintf(stderr, "failed to read data buffer from input file\n");
		return EINVAL;
	}
	if ((opcode & 1) && metadata_size && read(dfd, (void *)mbuffer, metadata_size) < 0) {
		fprintf(stderr, "failed to read meta-data buffer from input file\n");
		return EINVAL;
	}

	io.opcode = opcode;
	io.addr   = (__u64)buffer;
	if (metadata_size)
		io.metadata = (__u64)mbuffer;
	if (show) {
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
		if (dry_run)
			goto free_and_return;
	}

	gettimeofday(&start_time, NULL);
	err = ioctl(fd, NVME_IOCTL_SUBMIT_IO, &io);
	gettimeofday(&end_time, NULL);
	if (latency)
		fprintf(stdout, " latency: %s: %llu us\n",
			command, elapsed_utime(start_time, end_time));
	if (err < 0)
		perror("ioctl");
	else if (err)
		printf("%s: %s(%04x)\n", command, nvme_status_to_string(err), err);
	else {
		if (!(opcode & 1) && write(dfd, (void *)buffer, data_size) < 0) {
			fprintf(stderr, "failed to write buffer to output file\n");
			return EINVAL;
		} else
			printf("%s: success\n", command);
	}
 free_and_return:
	free(buffer);
	if (metadata_size)
		free(mbuffer);
    return err;
}

static int compare(int argc, char **argv)
{
	return submit_io(nvme_cmd_compare, "compare", argc, argv);
}

static int read_cmd(int argc, char **argv)
{
	return submit_io(nvme_cmd_read, "read", argc, argv);
}

static int write_cmd(int argc, char **argv)
{
	return submit_io(nvme_cmd_write, "write", argc, argv);
}

static int sec_recv(int argc, char **argv)
{
	struct nvme_admin_cmd cmd;
	void *sec_buf = NULL;
	int c;
	int err;
	int option_index = 0;
	char *name = argv[0];
	uint8_t raw_binary = 0;
	uint8_t secp = 0;
	uint16_t spsp = 0;
	uint32_t size = 0;
	uint32_t al = 0;
	int num_opts = 5;
	static struct option opts[] = {
		{"size",	   required_argument,	 0, 'x'},
		{"secp",	   required_argument,	 0, 'p'},
		{"spsp",	   required_argument,	 0, 's'},
		{"al",		   required_argument,	 0, 't'},
		{"raw-binary",     no_argument,          0, 'b'},
		{"help",	   no_argument,		 0, 'h'},
		{0,		   0,			 0, 0}
	};

	/* get device before parsing since it's a non-opt-arg */
	get_dev(1, argc, argv);

	while((c = getopt_long(argc, argv, "hbx:p:s:t:",
				opts, &option_index)) != -1) {
		switch (c) {
		case 'x':
			size = atoi(optarg);
			break;
		case 'p':
			secp = atoi(optarg);
			break;
		case 's':
			spsp = atoi(optarg);
			break;
		case 't':
			al = atoi(optarg);
			break;
		case 'b':
			raw_binary = 1;
			break;
		case 'h':
		default:
			command_help(opts, num_opts, name);
			return -1;
		}
	}

	if (size) {
		if (posix_memalign(&sec_buf, getpagesize(), size)) {
			fprintf(stderr, "No memory for security size: %d\n",
								size);
			return ENOMEM;
		}
	}
	memset(&cmd, 0, sizeof(cmd));
	cmd.opcode   = nvme_admin_security_recv;
	cmd.cdw10    = secp << 24 | spsp << 8;
	cmd.cdw11    = al;
	cmd.data_len = size;
	cmd.addr     = (__u64)sec_buf;

	err = ioctl(fd, NVME_IOCTL_ADMIN_CMD, &cmd);
	if (err < 0)
		return errno;
	else if (err != 0)
		fprintf(stderr, "NVME Security Receive Command Error: %d\n",
									err);
	else {
		if (!raw_binary) {
			printf("NVME Security Receive Command Success: %d\n",
							cmd.result);
			d(sec_buf, size, 16, 1);
		} else if (size)
			d_raw((unsigned char *)&sec_buf, size);
	}
	return err;
}

static int nvme_passthru(int argc, char **argv, int ioctl_cmd)
{
	int wfd = STDIN_FILENO;
	struct nvme_passthru_cmd cmd;
	int c;
	int err;
	int option_index = 0;
	char *name = argv[0];
	char  *input_file = NULL;
	uint8_t opcode = 0;
	uint8_t flags = 0;
	uint8_t raw_binary = 0;
	uint8_t show_command = 0;
	uint8_t dry_run = 0;
	uint8_t read_it = 0;
	uint8_t write_it = 0;
	uint16_t rsvd = 0;
	uint32_t namespace_id = 0;
	uint32_t data_len = 0;
	uint32_t metadata_len = 0;
	uint32_t timeout = 0;
	uint32_t cdw2 = 0;
	uint32_t cdw3 = 0;
	uint32_t cdw10 = 0;
	uint32_t cdw11 = 0;
	uint32_t cdw12 = 0;
	uint32_t cdw13 = 0;
	uint32_t cdw14 = 0;
	uint32_t cdw15 = 0;
	int num_opts = 21;
	struct option opts[] = {
		{"opcode",	   required_argument,	 0, 'o'},
		{"flags",	   required_argument,	 0, 'f'},
		{"rsvd",	   required_argument,    0, 'R'},
		{"namespace-id",   required_argument,	 0, 'n'},
		{"data-len",	   required_argument,	 0, 'l'},
		{"metadata-len",   required_argument,	 0, 'm'},
		{"timeout",        required_argument,    0, 't'},
		{"cdw2",           required_argument,	 0, '2'},
		{"cdw3",	   required_argument,	 0, '3'},
		{"cdw10",          required_argument,	 0, '4'},
		{"cdw11",          required_argument,    0, '5'},
		{"cdw12",          required_argument,    0, '6'},
		{"cdw13",          required_argument,    0, '7'},
		{"cdw14",          required_argument,	 0, '8'},
		{"cdw15",          required_argument,	 0, '9'},
		{"input-file",     required_argument,	 0, 'i'},
		{"raw-binary",     no_argument,		 0, 'b'},
		{"show-command",   no_argument,		 0, 's'},
		{"dry-run",        no_argument,		 0, 'd'},
		{"read",           no_argument,          0, 'r'},
		{"write",	   no_argument,		 0, 'w'},
		{"help",	   no_argument,		 0, 'h'},
		{0,		   0,			 0, 0}
	};

	/* get device before parsing since it's a non-opt-arg */
	get_dev(1, argc, argv);

	while((c = getopt_long(argc, argv,
			"hbsdrwo:f:R:n:l:m:t:2:3:4:5:6:7:8:9:i:", opts,
			&option_index)) != -1) {
		switch (c) {
		case 'o':
			opcode = atoi(optarg);
			break;
		case 'f':
			flags = atoi(optarg);
			break;
		case 'R':
			rsvd = atoi(optarg);
			break;
		case 'n':
			namespace_id = atoi(optarg);
			break;
		case 'l':
			data_len = atoi(optarg);
			break;
		case 'm':
			metadata_len = atoi(optarg);
			break;
		case 't':
			timeout = atoi(optarg);
			break;
		case '2':
			cdw2 = atoi(optarg);
			break;
		case '3':
			cdw3 = atoi(optarg);
			break;
		case '4':
			cdw10 = atoi(optarg);
			break;
		case '5':
			cdw11 = atoi(optarg);
			break;
		case '6':
			cdw12 = atoi(optarg);
			break;
		case '7':
			cdw13 = atoi(optarg);
			break;
		case '8':
			cdw14 = atoi(optarg);
			break;
		case '9':
			cdw15 = atoi(optarg);
			break;
		case 'i':
			input_file = strdup(optarg);
			break;
		case 'b':
			raw_binary = 1;
			break;
		case 's':
			show_command = 1;
			break;
		case 'd':
			dry_run = 1;
			break;
		case 'r':
			read_it = 1;
			break;
		case 'w':
			write_it = 1;
			break;
		case 'h':
		default:
			command_help(opts, num_opts, name);
			return -1;
		}
	}

	memset(&cmd, 0, sizeof(cmd));

	cmd.cdw2         = cdw2;
	cmd.cdw3         = cdw3;
	cmd.cdw10        = cdw10;
	cmd.cdw11        = cdw11;
	cmd.cdw12        = cdw12;
	cmd.cdw13        = cdw13;
	cmd.cdw14        = cdw14;
	cmd.cdw15        = cdw15;
	cmd.opcode       = opcode;
	cmd.flags        = flags;
	cmd.rsvd1        = rsvd;
	cmd.nsid         = namespace_id;
	cmd.data_len     = data_len;
	cmd.metadata_len = metadata_len;
	cmd.timeout_ms   = timeout;
	if (strlen(input_file)){
		wfd = open(input_file, O_RDONLY,
			   S_IRUSR | S_IRGRP | S_IROTH);
		if (wfd < 0) {
			perror(input_file);
			return EINVAL;
		}
	}

	if (cmd.metadata_len)
		cmd.metadata = (__u64)malloc(cmd.metadata_len);
	if (cmd.data_len) {
		cmd.addr = (__u64)malloc(cmd.data_len);
		if (!read_it && !write_it) {
			fprintf(stderr, "data direction not given\n");
			return EINVAL;
		}
		if (read_it && write_it) {
			fprintf(stderr, "command can't be both read and write\n");
			return EINVAL;
		}
		if (write_it) {
			if (read(wfd, (void *)cmd.addr, cmd.data_len) < 0) {
				fprintf(stderr, "failed to read write buffer\n");
				return EINVAL;
			}
		}
	}
	if (show_command) {
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
		if (dry_run)
			return 0;
	}
	err = ioctl(fd, ioctl_cmd, &cmd);
	if (err >= 0) {
		if (!raw_binary) {
			printf("NVMe Status: %s; Command Result: %08x\n",
				nvme_status_to_string(err), cmd.result);
			if (cmd.addr && read_it && !err)
				d((unsigned char *)cmd.addr, cmd.data_len, 16, 1);
		} else if (!err && cmd.addr && read_it)
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
	help(argc, argv);
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
