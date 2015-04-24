/*
 * nvme.c -- NVM-Express command line utility.
 *
 * Copyright (c) 2014, Intel Corporation.
 *
 * Written by Keith Busch <keith.busch@intel.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * This program uses NVMe IOCTLs to run native nvme commands to a device.
 */

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

static int fd;
static struct stat nvme_stat;
static const char *devicename;

#define COMMAND_LIST \
	ENTRY(LIST, "list", "List all NVMe devices and namespaces on machine", list) \
	ENTRY(ID_CTRL, "id-ctrl", "Send NVMe Identify Controller", id_ctrl) \
	ENTRY(ID_NS, "id-ns", "Send NVMe Identify Namespace, display structure", id_ns) \
	ENTRY(LIST_NS, "list-ns", "Send NVMe Identify List, display structure", list_ns) \
	ENTRY(GET_NS_ID, "get-ns-id", "Retrieve the namespace ID of opened block device", get_ns_id) \
	ENTRY(GET_LOG, "get-log", "Generic NVMe get log, returns log in raw format", get_log) \
	ENTRY(GET_FW_LOG, "fw-log", "Retrieve FW Log, show it", get_fw_log) \
	ENTRY(GET_SMART_LOG, "smart-log", "Retrieve SMART Log, show it", get_smart_log) \
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
		printf("error_count  : %lld\n", err_log[i].error_count);
		printf("sqid         : %d\n", err_log[i].sqid);
		printf("cmdid        : %#x\n", err_log[i].cmdid);
		printf("status_field : %#x\n", err_log[i].status_field);
		printf("parm_err_loc : %#x\n", err_log[i].parm_error_location);
		printf("lba          : %#llx\n", err_log[i].lba);
		printf("nsid         : %d\n", err_log[i].nsid);
		printf("vs           : %d\n", err_log[i].vs);
		printf(".................\n");
	}
}

static void show_nvme_resv_report(struct nvme_reservation_status *status)
{
	int i, regctl;

	regctl = status->regctl[0] | (status->regctl[1] << 8);

	printf("\nNVME Reservatation status:\n\n");
	printf("gen       : %d\n", le32toh(status->gen));
	printf("regctl    : %d\n", regctl);
	printf("rtype     : %d\n", status->rtype);
	printf("ptpls     : %d\n", status->ptpls);

	for (i = 0; i < regctl; i++) {
		printf("regctl[%d] :\n", i);
		printf("  cntlid  : %x\n", le16toh(status->regctl_ds[i].cntlid));
		printf("  rcsts   : %x\n", status->regctl_ds[i].rcsts);
		printf("  hostid  : %llx\n", le64toh(status->regctl_ds[i].hostid));
		printf("  rkey    : %llx\n", le64toh(status->regctl_ds[i].rkey));
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
			printf("frs%d : %#016llx (%s)\n", i + 1, fw_log->frs[i],
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

static int identify(int namespace, void *ptr, int cns)
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

static void show_nvme_id_ctrl(struct nvme_id_ctrl *ctrl, int vs)
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
	printf("mdts    : %d\n", ctrl->mdts);
	printf("cntlid  : %x\n", ctrl->cntlid);
	printf("ver     : %x\n", ctrl->ver);
	printf("rtd3r   : %x\n", ctrl->rtd3r);
	printf("rtd3e   : %x\n", ctrl->rtd3e);
	printf("oacs    : %#x\n", ctrl->oacs);
	printf("acl     : %d\n", ctrl->acl);
	printf("aerl    : %d\n", ctrl->aerl);
	printf("frmw    : %#x\n", ctrl->frmw);
	printf("lpa     : %#x\n", ctrl->lpa);
	printf("elpe    : %d\n", ctrl->elpe);
	printf("npss    : %d\n", ctrl->npss);
	printf("avscc   : %#x\n", ctrl->avscc);
	printf("apsta   : %#x\n", ctrl->apsta);
	printf("wctemp  : %d\n", ctrl->wctemp);
	printf("cctemp  : %d\n", ctrl->cctemp);
	printf("mtfa    : %d\n", ctrl->mtfa);
	printf("hmmin   : %d\n", ctrl->hmmin);
	printf("tnvmcap : %.0Lf\n", int128_to_double(ctrl->tnvmcap));
	printf("unvmcap : %.0Lf\n", int128_to_double(ctrl->unvmcap));
	printf("rpmbs   : %#x\n", ctrl->rpmbs);
	printf("sqes    : %#x\n", ctrl->sqes);
	printf("cqes    : %#x\n", ctrl->cqes);
	printf("nn      : %d\n", ctrl->nn);
	printf("oncs    : %#x\n", ctrl->oncs);
	printf("fuses   : %#x\n", ctrl->fuses);
	printf("fna     : %#x\n", ctrl->fna);
	printf("vwc     : %#x\n", ctrl->vwc);
	printf("awun    : %d\n", ctrl->awun);
	printf("awupf   : %d\n", ctrl->awupf);
	printf("nvscc   : %d\n", ctrl->nvscc);
	printf("acwu    : %d\n", ctrl->acwu);
	printf("sgls    : %d\n", ctrl->sgls);

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
		printf("slba       : %#llx", lbrt[i].slba);
		printf("nlb        : %#llx", lbrt[i].nlb);
		printf("guid       : ");
		for (j = 0; j < 16; j++)
			printf("%02x", lbrt[i].guid[j]);
		printf("\n");
	}
}

static void show_nvme_id_ns(struct nvme_id_ns *ns, int id, int vs)
{
	int i;

	printf("NVME Identify Namespace %d:\n", id);
	printf("nsze    : %#llx\n", ns->nsze);
	printf("ncap    : %#llx\n", ns->ncap);
	printf("nuse    : %#llx\n", ns->nuse);
	printf("nsfeat  : %#x\n", ns->nsfeat);
	printf("nlbaf   : %d\n", ns->nlbaf);
	printf("flbas   : %#x\n", ns->flbas);
	printf("mc      : %#x\n", ns->mc);
	printf("dpc     : %#x\n", ns->dpc);
	printf("dps     : %#x\n", ns->dps);
	printf("nmic    : %#x\n", ns->nmic);
	printf("rescap  : %#x\n", ns->rescap);
	printf("fpi     : %#x\n", ns->fpi);
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
		{"namespace-id", "NUM", CFG_POSITIVE, &defaults.namespace_id, required_argument, NULL},
		{"n",            "NUM", CFG_POSITIVE, &defaults.namespace_id, required_argument, NULL},
		{"raw-binary",   "",    CFG_NONE,     &defaults.raw_binary,   no_argument,       NULL},
		{"b",            "",    CFG_NONE,     &defaults.raw_binary,   no_argument,       NULL},
		{0}
	};
	argconfig_parse(argc, argv, "get_smart_log", command_line_options,
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
		fprintf(stderr, "NVMe Status: %s\n", nvme_status_to_string(err));
	return err;
}

static int get_error_log(int argc, char **argv)
{
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
		{"namespace-id", "NUM",  CFG_POSITIVE, &defaults.namespace_id, required_argument, NULL},
		{"n",            "NUM",  CFG_POSITIVE, &defaults.namespace_id, required_argument, NULL},
		{"log-entries",  "NUM",  CFG_POSITIVE, &defaults.log_entries,  required_argument, NULL},
		{"e",            "NUM",  CFG_POSITIVE, &defaults.log_entries,  required_argument, NULL},
		{"raw-binary",   "",     CFG_NONE,     &defaults.raw_binary,   no_argument,       NULL},
		{"b",            "",     CFG_NONE,     &defaults.raw_binary,   no_argument,       NULL},
		{0}
	};
	argconfig_parse(argc, argv, "get_error_log", command_line_options,
			&defaults, &cfg, sizeof(cfg));
	get_dev(1, argc, argv);

	if (!cfg.log_entries) {
		fprintf(stderr, "non-zero log-entires is required param\n");
		return EINVAL;
	}
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
		fprintf(stderr, "NVMe Status: %s\n", nvme_status_to_string(err));
	return err;
}

static int get_fw_log(int argc, char **argv)
{
	int err;
	struct nvme_firmware_log_page fw_log;

	struct config {
		__u8  raw_binary;
	};
	struct config cfg;

	const struct config defaults = {
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"raw-binary", "",   CFG_NONE, &defaults.raw_binary,   no_argument,       NULL},
		{"b",          "",   CFG_NONE, &defaults.raw_binary,   no_argument,       NULL},
		{0}
	};
	argconfig_parse(argc, argv, "get_fw_log", command_line_options,
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
		fprintf(stderr, "NVMe Status: %s\n", nvme_status_to_string(err));
	else
		perror("fw log");
	return err;
}

static int get_log(int argc, char **argv)
{
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
		{"namespace-id", "NUM",  CFG_POSITIVE, &defaults.namespace_id, required_argument, NULL},
		{"n",            "NUM",  CFG_POSITIVE, &defaults.namespace_id, required_argument, NULL},
		{"log-id",       "NUM",  CFG_POSITIVE, &defaults.log_id,       required_argument, NULL},
		{"i",            "NUM",  CFG_POSITIVE, &defaults.log_id,       required_argument, NULL},
		{"log-len",      "NUM",  CFG_POSITIVE, &defaults.log_len,      required_argument, NULL},
		{"l",            "NUM",  CFG_POSITIVE, &defaults.log_len,      required_argument, NULL},
		{"raw-binary",   "",     CFG_NONE,     &defaults.raw_binary,   no_argument,       NULL},
		{"b",            "",     CFG_NONE,     &defaults.raw_binary,   no_argument,       NULL},
		{0}
	};
	argconfig_parse(argc, argv, "get_log", command_line_options,
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
			fprintf(stderr, "NVMe Status: %s\n",
						nvme_status_to_string(err));
		return err;
	}
}

static int list_ns(int argc, char **argv)
{
	int err, i;
	__u32 ns_list[1024];

	struct config {
		__u32 namespace_id;
	};
	struct config cfg;

	const struct config defaults = {
		.namespace_id = 0,
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"namespace-id", "NUM",  CFG_POSITIVE, &defaults.namespace_id, required_argument, NULL},
		{"n",            "NUM",  CFG_POSITIVE, &defaults.namespace_id, required_argument, NULL},
		{0}
	};
	argconfig_parse(argc, argv, "list_ns", command_line_options,
			&defaults, &cfg, sizeof(cfg));
	get_dev(1, argc, argv);

	err = identify(cfg.namespace_id, ns_list, 2);
	if (!err) {
		for (i = 0; i < 1024; i++)
			if (ns_list[i])
				printf("[%4u]:%#x\n", i, ns_list[i]);
	}
	else if (err > 0)
		fprintf(stderr, "NVMe Status: %s NSID:%d\n",
				nvme_status_to_string(err), cfg.namespace_id);
	return err;
}

static char * nvme_char_from_block(char *block)
{
    char slen[16];
    unsigned len;
    if (strncmp("nvme", block, 4) )
    {
        fprintf(stderr,"Device %s is not a nvme device.", block);
        exit(-1);
    }
    sscanf(block,"nvme%d", &len);
    sprintf(slen,"%d", len);
    block[4+strlen(slen)] = 0;
    return block;
}

static void get_registers(struct nvme_bar *bar, unsigned char_only)
{
	int pci_fd;
	char *base, path[512];
	void *membase;

	if (char_only && !S_ISCHR(nvme_stat.st_mode)) {
		fprintf(stderr, "%s is not character device\n", devicename);
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
    memcpy(bar, membase, sizeof(struct nvme_bar));
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
  /* For pre NVMe 1.2 devices we must get the version from the BAR, not
   * the ctrl_id.*/
static void get_version( struct list_item* list_item)
{
    list_item->ver = list_item->ctrl.ver;
    if (list_item->ctrl.ver)
        return;
    struct nvme_bar bar;
    get_registers(&bar, 0);
    list_item->ver = bar.vs;

}

static void print_list_item(struct list_item list_item)
{

	double nsze       = list_item.ns.nsze;
	double nuse       = list_item.ns.nuse;
	long long int lba = list_item.ns.lbaf[list_item.ns.flbas].ds;

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
		list_item.ns.lbaf[list_item.ns.flbas].ms);
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
	int err;
	struct nvme_id_ctrl ctrl;

	struct config {
		__u8  vendor_specific;
		__u8  raw_binary;
	};
	struct config cfg;

	const struct config defaults = {
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"vendor-specific", "", CFG_NONE, &defaults.vendor_specific, no_argument,       NULL},
		{"v",               "", CFG_NONE, &defaults.vendor_specific, no_argument,       NULL},
		{"raw-binary",      "", CFG_NONE, &defaults.raw_binary,      no_argument,       NULL},
		{"b",               "", CFG_NONE, &defaults.raw_binary,      no_argument,       NULL},
		{0}
	};
	argconfig_parse(argc, argv, "id_ctrl", command_line_options,
			&defaults, &cfg, sizeof(cfg));
	get_dev(1, argc, argv);

	err = identify(0, &ctrl, 1);
	if (!err) {
		if (cfg.raw_binary)
			d_raw((unsigned char *)&ctrl, sizeof(ctrl));
		else
			show_nvme_id_ctrl(&ctrl, cfg.vendor_specific);
	}
	else if (err > 0)
		fprintf(stderr, "NVMe Status: %s\n", nvme_status_to_string(err));

	return err;
}

static int id_ns(int argc, char **argv)
{
	struct nvme_id_ns ns;
	int err;

	struct config {
		__u32 namespace_id;
		__u8  vendor_specific;
		__u8  raw_binary;
	};
	struct config cfg;

	const struct config defaults = {
		.namespace_id    = 0,
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"namespace-id",    "NUM",  CFG_POSITIVE, &defaults.namespace_id,    required_argument, NULL},
		{"n",               "NUM",  CFG_POSITIVE, &defaults.namespace_id,    required_argument, NULL},
		{"vendor-specific", "",     CFG_NONE,     &defaults.vendor_specific, no_argument,       NULL},
		{"v",               "",     CFG_NONE,     &defaults.vendor_specific, no_argument,       NULL},
		{"raw-binary",      "",     CFG_NONE,     &defaults.raw_binary,      no_argument,       NULL},
		{"b",               "",     CFG_NONE,     &defaults.raw_binary,      no_argument,       NULL},
		{0}
	};
	argconfig_parse(argc, argv, "id_ns", command_line_options,
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
			show_nvme_id_ns(&ns, cfg.namespace_id, cfg.vendor_specific);
	}
	else if (err > 0)
		fprintf(stderr, "NVMe Status: %s NSID:%d\n", nvme_status_to_string(err),
			cfg.namespace_id);
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
		{"namespace-id", "NUM",  CFG_POSITIVE, &defaults.namespace_id, required_argument, NULL},
		{"n",            "NUM",  CFG_POSITIVE, &defaults.namespace_id, required_argument, NULL},
		{"feature-id",   "NUM",  CFG_POSITIVE, &defaults.feature_id,   required_argument, NULL},
		{"f",            "NUM",  CFG_POSITIVE, &defaults.feature_id,   required_argument, NULL},
		{"sel",          "NUM",  CFG_POSITIVE, &defaults.sel,          required_argument, NULL},
		{"s",            "NUM",  CFG_POSITIVE, &defaults.sel,          required_argument, NULL},
		{"cdw11",        "NUM",  CFG_POSITIVE, &defaults.cdw11,        required_argument, NULL},
		{"data-len",     "NUM",  CFG_POSITIVE, &defaults.data_len,     required_argument, NULL},
		{"l",            "NUM",  CFG_POSITIVE, &defaults.data_len,     required_argument, NULL},
		{"raw-binary",   "",     CFG_NONE,     &defaults.raw_binary,   no_argument,       NULL},
		{"b",            "",     CFG_NONE,     &defaults.raw_binary,   no_argument,       NULL},
		{0}
	};
	argconfig_parse(argc, argv, "get_feature", command_line_options,
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
	if (cfg.feature_id == NVME_FEAT_LBA_RANGE)
		cfg.data_len = 4096;
	if (cfg.data_len)
		buf = malloc(cfg.data_len);

	cdw10 = cfg.sel << 8 | cfg.feature_id;
	err = nvme_feature(nvme_admin_get_features, buf, cfg.data_len, cdw10,
			   cfg.namespace_id, cfg.cdw11, &result);
	if (!err) {
		printf("get-feature:%d(%s), value:%#08x\n", cfg.feature_id,
			nvme_feature_to_string(cfg.feature_id), result);
		if (buf) {
			if (!cfg.raw_binary) {
				if (cfg.feature_id == NVME_FEAT_LBA_RANGE)
					show_lba_range((struct nvme_lba_range_type *)buf,
									result);
				else
					d(buf, cfg.data_len, 16, 1);
			}
			else
				d_raw(buf, cfg.data_len);
		}
	}
	else if (err > 0)
		fprintf(stderr, "NVMe Status: %s\n", nvme_status_to_string(err));
	if (buf)
		free(buf);
	return err;
}

#define min(x, y) x > y ? y : x;
static int fw_download(int argc, char **argv)
{
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
		.xfer   = 0,
		.offset = 0,
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"fw",     "FILE", CFG_STRING,   &defaults.fw,     required_argument, NULL},
		{"f",      "FILE", CFG_STRING,   &defaults.fw,     required_argument, NULL},
		{"xfer",   "NUM",  CFG_POSITIVE, &defaults.xfer,   required_argument, NULL},
		{"x",      "NUM",  CFG_POSITIVE, &defaults.xfer,   required_argument, NULL},
		{"offset", "NUM",  CFG_POSITIVE, &defaults.offset, required_argument, NULL},
		{"o",      "NUM",  CFG_POSITIVE, &defaults.offset, required_argument, NULL},
		{0}
	};
	argconfig_parse(argc, argv, "fw_download", command_line_options,
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
	if (cfg.xfer % 4096)
		cfg.xfer = 4096;

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
			fprintf(stderr, "NVME Admin command error:%d\n", err);
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
		{"slot",   "NUM", CFG_POSITIVE, &defaults.slot,   required_argument, NULL},
		{"s",      "NUM", CFG_POSITIVE, &defaults.slot,   required_argument, NULL},
		{"action", "NUM", CFG_POSITIVE, &defaults.action, required_argument, NULL},
		{"a",      "NUM", CFG_POSITIVE, &defaults.action, required_argument, NULL},
		{0}
	};
	argconfig_parse(argc, argv, "fw_activate", command_line_options,
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
		fprintf(stderr, "NVME Admin command error:%d\n", err);
	else
		printf("Success activating firmware action:%d slot:%d\n",
		       cfg.action, cfg.slot);
	return err;
}

static int show_registers(int argc, char **argv)
{
	int opt, long_index;
	struct nvme_bar bar;
	static struct option opts[] = {};

	while ((opt = getopt_long(argc, (char **)argv, "", opts,
					&long_index)) != -1);
	get_dev(optind, argc, argv);

	get_registers(&bar, 1);
	printf("cap     : %"PRIx64"\n", (uint64_t)bar.cap);
	printf("version : %x\n", bar.vs);
	printf("intms   : %x\n", bar.intms);
	printf("intmc   : %x\n", bar.intmc);
	printf("cc      : %x\n", bar.cc);
	printf("csts    : %x\n", bar.csts);
	printf("nssr    : %x\n", bar.nssr);
	printf("aqa     : %x\n", bar.aqa);
	printf("asq     : %"PRIx64"\n", (uint64_t)bar.asq);
	printf("acq     : %"PRIx64"\n", (uint64_t)bar.acq);
	printf("cmbloc  : %x\n", bar.cmbloc);
	printf("cmbsz   : %x\n", bar.cmbsz);

	return 0;
}

static int format(int argc, char **argv)
{
	int err;
	struct nvme_admin_cmd cmd;

	struct config {
		__u32 namespace_id;
		__u8  lbaf;
		__u8  ses;
		__u8  pi;
		__u8  pil;
		__u8  ms;
	};
	struct config cfg;

	const struct config defaults = {
		.namespace_id = 0xffffffff,
		.lbaf         = 0,
		.ses          = 0,
		.pi           = 0,
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"namespace-id", "NUM",  CFG_POSITIVE, &defaults.namespace_id, required_argument, NULL},
		{"n",            "NUM",  CFG_POSITIVE, &defaults.namespace_id, required_argument, NULL},
		{"lbaf",         "NUM",  CFG_POSITIVE, &defaults.lbaf,         required_argument, NULL},
		{"l",            "NUM",  CFG_POSITIVE, &defaults.lbaf,         required_argument, NULL},
		{"ses",          "NUM",  CFG_POSITIVE, &defaults.ses,          required_argument, NULL},
		{"s",            "NUM",  CFG_POSITIVE, &defaults.ses,          required_argument, NULL},
		{"pi",           "NUM",  CFG_POSITIVE, &defaults.pi,           required_argument, NULL},
		{"i",            "NUM",  CFG_POSITIVE, &defaults.pi,           required_argument, NULL},
		{"pil",          "NUM",  CFG_POSITIVE, &defaults.pil,          required_argument, NULL},
		{"p",            "NUM",  CFG_POSITIVE, &defaults.pil,          required_argument, NULL},
		{"ms",           "NUM",  CFG_POSITIVE, &defaults.ms,           required_argument, NULL},
		{"m",            "NUM",  CFG_POSITIVE, &defaults.ms,           required_argument, NULL},
		{0}
	};
	argconfig_parse(argc, argv, "format", command_line_options,
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

	err = ioctl(fd, NVME_IOCTL_ADMIN_CMD, &cmd);
	if (err < 0)
		perror("ioctl");
	else if (err != 0)
		fprintf(stderr, "NVME Admin command error:%s(%d)\n",
					nvme_status_to_string(err), err);
	else {
		printf("Success formatting namespace:%x\n", cfg.namespace_id);
		ioctl(fd, BLKRRPART);
	}
	return err;
}

static int set_feature(int argc, char **argv)
{
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
		{"namespace-id", "NUM",  CFG_POSITIVE, &defaults.namespace_id, required_argument, NULL},
		{"n",            "NUM",  CFG_POSITIVE, &defaults.namespace_id, required_argument, NULL},
		{"feature-id",   "NUM",  CFG_POSITIVE, &defaults.feature_id,   required_argument, NULL},
		{"f",            "NUM",  CFG_POSITIVE, &defaults.feature_id,   required_argument, NULL},
		{"value",        "NUM",  CFG_POSITIVE, &defaults.value,        required_argument, NULL},
		{"v",            "NUM",  CFG_POSITIVE, &defaults.value,        required_argument, NULL},
		{"data-len",     "NUM",  CFG_POSITIVE, &defaults.data_len,     required_argument, NULL},
		{"l",            "NUM",  CFG_POSITIVE, &defaults.data_len,     required_argument, NULL},
		{"data",         "FILE", CFG_STRING,   &defaults.file,         required_argument, NULL},
		{"d",            "FILE", CFG_STRING,   &defaults.file,         required_argument, NULL},
		{0}
	};
	argconfig_parse(argc, argv, "set_feature", command_line_options,
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
		fprintf(stderr, "NVMe Status: %s\n", nvme_status_to_string(err));
	if (buf)
		free(buf);
	return err;
}

static int sec_send(int argc, char **argv)
{
	struct stat sb;
	struct nvme_admin_cmd cmd;
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
		{"file",       "FILE",  CFG_STRING,   &defaults.file,       required_argument, NULL},
		{"f",          "FILE",  CFG_STRING,   &defaults.file,       required_argument, NULL},
		{"secp",       "NUM",   CFG_POSITIVE, &defaults.secp,       required_argument, NULL},
		{"p",          "NUM",   CFG_POSITIVE, &defaults.secp,       required_argument, NULL},
		{"spsp",       "NUM",   CFG_POSITIVE, &defaults.spsp,       required_argument, NULL},
		{"s",          "NUM",   CFG_POSITIVE, &defaults.spsp,       required_argument, NULL},
		{"tl",         "NUM",   CFG_POSITIVE, &defaults.tl,         required_argument, NULL},
		{"t",          "NUM",   CFG_POSITIVE, &defaults.tl,         required_argument, NULL},
		{0}
	};
	argconfig_parse(argc, argv, "sec_send", command_line_options,
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
        int err;

	struct config {
		__u32 namespace_id;
	};
	struct config cfg;

	const struct config defaults = {
		.namespace_id = 0xffffffff,
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"namespace-id", "NUM",  CFG_POSITIVE,    &defaults.namespace_id, required_argument, NULL},
		{"n",            "NUM",  CFG_POSITIVE,    &defaults.namespace_id, required_argument, NULL},
		{0}
	};
	argconfig_parse(argc, argv, "flush", command_line_options,
			&defaults, &cfg, sizeof(cfg));
	get_dev(1, argc, argv);

	memset(&cmd, 0, sizeof(cmd));
	cmd.opcode = nvme_cmd_flush;
	cmd.nsid   = cfg.namespace_id;

	err = ioctl(fd, NVME_IOCTL_IO_CMD, &cmd);
	if (err < 0)
		return errno;
	else if (err != 0)
		fprintf(stderr, "NVME IO command error:%s(%d)\n",
				nvme_status_to_string(err), err);
	else
		printf("NVMe Flush: success\n");
	return 0;
}

static int resv_acquire(int argc, char **argv)
{
	struct nvme_passthru_cmd cmd;
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
		{"namespace-id", "NUM",  CFG_POSITIVE,    &defaults.namespace_id, required_argument, NULL},
		{"n",            "NUM",  CFG_POSITIVE,    &defaults.namespace_id, required_argument, NULL},
		{"crkey",        "NUM",  CFG_LONG_SUFFIX, &defaults.crkey,        required_argument, NULL},
		{"c",            "NUM",  CFG_LONG_SUFFIX, &defaults.crkey,        required_argument, NULL},
		{"prkey",        "NUM",  CFG_LONG_SUFFIX, &defaults.prkey,        required_argument, NULL},
		{"p",            "NUM",  CFG_LONG_SUFFIX, &defaults.prkey,        required_argument, NULL},
		{"rtype",        "NUM",  CFG_POSITIVE,    &defaults.rtype,        required_argument, NULL},
		{"t",            "NUM",  CFG_POSITIVE,    &defaults.rtype,        required_argument, NULL},
		{"racqa",        "NUM",  CFG_POSITIVE,    &defaults.racqa,        required_argument, NULL},
		{"a",            "NUM",  CFG_POSITIVE,    &defaults.racqa,        required_argument, NULL},
		{"iekey",        "",     CFG_NONE,        &defaults.iekey,        no_argument,       NULL},
		{"i",            "",     CFG_NONE,        &defaults.iekey,        no_argument,       NULL},
		{0}
	};
	argconfig_parse(argc, argv, "resv_acquire", command_line_options,
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
		{"namespace-id", "NUM",  CFG_POSITIVE,    &defaults.namespace_id, required_argument, NULL},
		{"n",            "NUM",  CFG_POSITIVE,    &defaults.namespace_id, required_argument, NULL},
		{"crkey",        "NUM",  CFG_LONG_SUFFIX, &defaults.crkey,        required_argument, NULL},
		{"c",            "NUM",  CFG_LONG_SUFFIX, &defaults.crkey,        required_argument, NULL},
		{"nrkey",        "NUM",  CFG_LONG_SUFFIX, &defaults.nrkey,        required_argument, NULL},
		{"k",            "NUM",  CFG_LONG_SUFFIX, &defaults.nrkey,        required_argument, NULL},
		{"rrega",        "NUM",  CFG_POSITIVE,    &defaults.rrega,        required_argument, NULL},
		{"r",            "NUM",  CFG_POSITIVE,    &defaults.rrega,        required_argument, NULL},
		{"cptpl",        "NUM",  CFG_POSITIVE,    &defaults.cptpl,        required_argument, NULL},
		{"p",            "NUM",  CFG_POSITIVE,    &defaults.cptpl,        required_argument, NULL},
		{"iekey",        "",     CFG_NONE,        &defaults.iekey,        no_argument,       NULL},
		{"i",            "",     CFG_NONE,        &defaults.iekey,        no_argument,       NULL},
		{0}
	};
	argconfig_parse(argc, argv, "resv_register", command_line_options,
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
		{"namespace-id", "NUM",  CFG_POSITIVE,    &defaults.namespace_id, required_argument, NULL},
		{"n",            "NUM",  CFG_POSITIVE,    &defaults.namespace_id, required_argument, NULL},
		{"crkey",        "NUM",  CFG_LONG_SUFFIX, &defaults.crkey,        required_argument, NULL},
		{"c",            "NUM",  CFG_LONG_SUFFIX, &defaults.crkey,        required_argument, NULL},
		{"rtype",        "NUM",  CFG_POSITIVE,    &defaults.rtype,        required_argument, NULL},
		{"t",            "NUM",  CFG_POSITIVE,    &defaults.rtype,        required_argument, NULL},
		{"rrela",        "NUM",  CFG_POSITIVE,    &defaults.rrela,        required_argument, NULL},
		{"a",            "NUM",  CFG_POSITIVE,    &defaults.rrela,        required_argument, NULL},
		{"iekey",        "NUM",  CFG_POSITIVE,    &defaults.iekey,        required_argument, NULL},
		{"i",            "NUM",  CFG_POSITIVE,    &defaults.iekey,        required_argument, NULL},
		{0}
	};
	argconfig_parse(argc, argv, "resv_release", command_line_options,
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
		{"namespace-id", "NUM",  CFG_POSITIVE, &defaults.namespace_id, required_argument, NULL},
		{"n",            "NUM",  CFG_POSITIVE, &defaults.namespace_id, required_argument, NULL},
		{"numd",         "NUM",  CFG_POSITIVE, &defaults.numd,         required_argument, NULL},
		{"d",            "NUM",  CFG_POSITIVE, &defaults.numd,         required_argument, NULL},
		{"raw-binary",   "",     CFG_NONE,     &defaults.raw_binary,   no_argument,       NULL},
		{"b",            "",     CFG_NONE,     &defaults.raw_binary,   no_argument,       NULL},
		{0}
	};
	argconfig_parse(argc, argv, "resv_report", command_line_options,
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

static int submit_io(int opcode, char *command, int argc, char **argv)
{
	struct nvme_user_io io;
	struct timeval start_time, end_time;
	void *buffer, *mbuffer = NULL;
        int err, dfd = opcode & 1 ? STDIN_FILENO : STDOUT_FILENO;

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
		{"s",                 "NUM",  CFG_LONG_SUFFIX, &defaults.start_block,       required_argument, NULL},
		{"start-block",       "NUM",  CFG_LONG_SUFFIX, &defaults.start_block,       required_argument, NULL},
		{"c",                 "NUM",  CFG_LONG_SUFFIX, &defaults.block_count,       required_argument, NULL},
		{"block-count",       "NUM",  CFG_LONG_SUFFIX, &defaults.block_count,       required_argument, NULL},
		{"z",                 "NUM",  CFG_LONG_SUFFIX, &defaults.data_size,         required_argument, NULL},
		{"data-size",         "NUM",  CFG_LONG_SUFFIX, &defaults.data_size,         required_argument, NULL},
		{"y",                 "NUM",  CFG_POSITIVE,    &defaults.metadata_size,     required_argument, NULL},
		{"metadata-size",     "NUM",  CFG_POSITIVE,    &defaults.metadata_size,     required_argument, NULL},
		{"r",                 "NUM",  CFG_POSITIVE,    &defaults.ref_tag,           required_argument, NULL},
		{"ref-tag",           "NUM",  CFG_POSITIVE,    &defaults.ref_tag,           required_argument, NULL},
		{"d",                 "FILE", CFG_STRING,      &defaults.data,              required_argument, NULL},
		{"data",              "FILE", CFG_STRING,      &defaults.data,              required_argument, NULL},
		{"p",                 "NUM",  CFG_POSITIVE,    &defaults.prinfo,            required_argument, NULL},
		{"prinfo",            "NUM",  CFG_POSITIVE,    &defaults.prinfo,            required_argument, NULL},
		{"t",                 "NUM",  CFG_POSITIVE,    &defaults.prinfo,            required_argument, NULL},
		{"app-tag",           "NUM",  CFG_POSITIVE,    &defaults.prinfo,            required_argument, NULL},
		{"m",                 "NUM",  CFG_POSITIVE,    &defaults.app_tag_mask,      required_argument, NULL},
		{"app-tag-mask",      "NUM",  CFG_POSITIVE,    &defaults.app_tag_mask,      required_argument, NULL},
		{"a",                 "NUM",  CFG_POSITIVE,    &defaults.app_tag,           required_argument, NULL},
		{"app-tag",           "NUM",  CFG_POSITIVE,    &defaults.app_tag,           required_argument, NULL},
		{"l",                 "",     CFG_NONE,        &defaults.limited_retry,     no_argument,       NULL},
		{"limited-retry",     "",     CFG_NONE,        &defaults.limited_retry,     no_argument,       NULL},
		{"f",                 "",     CFG_NONE,        &defaults.force_unit_access, no_argument,       NULL},
		{"force-unit-access", "",     CFG_NONE,        &defaults.force_unit_access, no_argument,       NULL},
		{"v",                 "",     CFG_NONE,        &defaults.show,              no_argument,       NULL},
		{"show-command",      "",     CFG_NONE,        &defaults.show,              no_argument,       NULL},
		{"w",                 "",     CFG_NONE,        &defaults.dry_run,           no_argument,       NULL},
		{"dry-run",           "",     CFG_NONE,        &defaults.dry_run,           no_argument,       NULL},
		{"t",                 "",     CFG_NONE,        &defaults.latency,           no_argument,       NULL},
		{"latency",           "",     CFG_NONE,        &defaults.latency,           no_argument,       NULL},
		{0}
	};

	argconfig_parse(argc, argv, command, command_line_options,
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
	return 0;
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
        int err;
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
		{"size",       "NUM",  CFG_POSITIVE, &defaults.size,       required_argument, NULL},
		{"x",          "NUM",  CFG_POSITIVE, &defaults.size,       required_argument, NULL},
		{"secp",       "NUM",  CFG_POSITIVE, &defaults.secp,       required_argument, NULL},
		{"p",          "NUM",  CFG_POSITIVE, &defaults.secp,       required_argument, NULL},
		{"spsp",       "NUM",  CFG_POSITIVE, &defaults.spsp,       required_argument, NULL},
		{"s",          "NUM",  CFG_POSITIVE, &defaults.spsp,       required_argument, NULL},
		{"al",         "NUM",  CFG_POSITIVE, &defaults.al,         required_argument, NULL},
		{"t",          "NUM",  CFG_POSITIVE, &defaults.al,         required_argument, NULL},
		{"raw-binary", "",     CFG_NONE,     &defaults.raw_binary, no_argument,       NULL},
		{"b",          "",     CFG_NONE,     &defaults.raw_binary, no_argument,       NULL},
		{0}
	};
	argconfig_parse(argc, argv, "sec_recv", command_line_options,
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
                fprintf(stderr, "NVME Security Receivce Command Error:%d\n",
									err);
	else {
		if (!cfg.raw_binary) {
                	printf("NVME Security Receivce Command Success:%d\n",
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

	const struct argconfig_commandline_options command_line_options[] = {
		{"opcode",       "NUM",  CFG_POSITIVE, &defaults.opcode,       required_argument, NULL},
		{"o",            "NUM",  CFG_POSITIVE, &defaults.opcode,       required_argument, NULL},
		{"flags",        "NUM",  CFG_POSITIVE, &defaults.flags,        required_argument, NULL},
		{"f",            "NUM",  CFG_POSITIVE, &defaults.flags,        required_argument, NULL},
		{"rsvd",         "NUM",  CFG_POSITIVE, &defaults.rsvd,         required_argument, NULL},
		{"R",            "NUM",  CFG_POSITIVE, &defaults.rsvd,         required_argument, NULL},
		{"namespace-id", "NUM",  CFG_POSITIVE, &defaults.namespace_id, required_argument, NULL},
		{"n",            "NUM",  CFG_POSITIVE, &defaults.namespace_id, required_argument, NULL},
		{"data-len",     "NUM",  CFG_POSITIVE, &defaults.data_len,     required_argument, NULL},
		{"l",            "NUM",  CFG_POSITIVE, &defaults.data_len,     required_argument, NULL},
		{"metadata-len", "NUM",  CFG_POSITIVE, &defaults.metadata_len, required_argument, NULL},
		{"m",            "NUM",  CFG_POSITIVE, &defaults.metadata_len, required_argument, NULL},
		{"timeout",      "NUM",  CFG_POSITIVE, &defaults.timeout,      required_argument, NULL},
		{"t",            "NUM",  CFG_POSITIVE, &defaults.timeout,      required_argument, NULL},
		{"cdw2",         "NUM",  CFG_POSITIVE, &defaults.cdw2,         required_argument, NULL},
		{"2",            "NUM",  CFG_POSITIVE, &defaults.cdw2,         required_argument, NULL},
		{"cdw3",         "NUM",  CFG_POSITIVE, &defaults.cdw3,         required_argument, NULL},
		{"3",            "NUM",  CFG_POSITIVE, &defaults.cdw3,         required_argument, NULL},
		{"cdw10",        "NUM",  CFG_POSITIVE, &defaults.cdw10,        required_argument, NULL},
		{"4",            "NUM",  CFG_POSITIVE, &defaults.cdw10,        required_argument, NULL},
		{"cdw11",        "NUM",  CFG_POSITIVE, &defaults.cdw11,        required_argument, NULL},
		{"5",            "NUM",  CFG_POSITIVE, &defaults.cdw11,        required_argument, NULL},
		{"cdw12",        "NUM",  CFG_POSITIVE, &defaults.cdw12,        required_argument, NULL},
		{"6",            "NUM",  CFG_POSITIVE, &defaults.cdw12,        required_argument, NULL},
		{"cdw13",        "NUM",  CFG_POSITIVE, &defaults.cdw13,        required_argument, NULL},
		{"7",            "NUM",  CFG_POSITIVE, &defaults.cdw13,        required_argument, NULL},
		{"cdw14",        "NUM",  CFG_POSITIVE, &defaults.cdw14,        required_argument, NULL},
		{"8",            "NUM",  CFG_POSITIVE, &defaults.cdw14,        required_argument, NULL},
		{"cdw15",        "NUM",  CFG_POSITIVE, &defaults.cdw15,        required_argument, NULL},
		{"9",            "NUM",  CFG_POSITIVE, &defaults.cdw15,        required_argument, NULL},
		{"input-file",   "FILE", CFG_STRING,   &defaults.input_file,   required_argument, NULL},
		{"i",            "FILE", CFG_STRING,   &defaults.input_file,   required_argument, NULL},
		{"raw-binary",   "",     CFG_NONE,     &defaults.raw_binary,   no_argument,       NULL},
		{"b",            "",     CFG_NONE,     &defaults.raw_binary,   no_argument,       NULL},
		{"show-command", "",     CFG_NONE,     &defaults.show_command, no_argument,       NULL},
		{"s",            "",     CFG_NONE,     &defaults.show_command, no_argument,       NULL},
		{"dry-run",      "",     CFG_NONE,     &defaults.dry_run,      no_argument,       NULL},
		{"d",            "",     CFG_NONE,     &defaults.dry_run,      no_argument,       NULL},
		{"read",         "",     CFG_NONE,     &defaults.read,         no_argument,       NULL},
		{"r",            "",     CFG_NONE,     &defaults.read,         no_argument,       NULL},
		{"write",        "",     CFG_NONE,     &defaults.write,        no_argument,       NULL},
		{"w",            "",     CFG_NONE,     &defaults.write,        no_argument,       NULL},
		{0}
	};

	memset(&cmd, 0, sizeof(cmd));
	argconfig_parse(argc, argv, "nvme_passthrou", command_line_options,
			&defaults, &cfg, sizeof(cfg));

	cmd.cdw2         = cfg.cdw13;
	cmd.cdw3         = cfg.cdw13;
	cmd.cdw10        = cfg.cdw13;
	cmd.cdw11        = cfg.cdw13;
	cmd.cdw12        = cfg.cdw13;
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
	printf("The '<device>' may be either an NVMe character device (ex: /dev/nvme0)\n"
	       "or an nvme block device (ex: /dev/nvme0n1)\n\n");
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
