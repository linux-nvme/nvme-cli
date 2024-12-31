// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2023 Solidigm.
 *
 * Authors: leonardo.da.cunha@solidigm.com
 * shankaralingegowda.singonahalli@solidigm.com
 * haro.panosyan@solidigm.com
 */

#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <inttypes.h>
#include <time.h>

#include "common.h"
#include "nvme.h"
#include "libnvme.h"
#include "plugin.h"
#include "nvme-print.h"
#include "solidigm-util.h"

#define DWORD_SIZE 4
#define LOG_FILE_PERMISSION 0644

enum log_type {
	NLOG = 0,
	EVENTLOG = 1,
	ASSERTLOG = 2,
	HIT,
	CIT,
	ALL
};

#pragma pack(push, internal_logs, 1)
struct version {
	__u16    major;
	__u16    minor;
};

struct event_dump_instance {
	__u32 numeventdumps;
	__u32 coresize;
	__u32 coreoffset;
	__u32 eventidoffset[16];
	__u8  eventIdValidity[16];
};

struct commom_header {
	struct version ver;
	__u32    header_size;
	__u32    log_size;
	__u32    numcores;
};

struct event_dump_header {
	struct commom_header header;
	__u32 eventidsize;
	struct event_dump_instance edumps[0];
};

struct assert_dump_core {
	__u32 coreoffset;
	__u32 assertsize;
	__u8  assertdumptype;
	__u8  assertvalid;
	__u8  reserved[2];
};

struct assert_dump_header {
	struct commom_header header;
	struct assert_dump_core core[];
};

struct nlog_dump_header_common {
	struct version ver;
	__u32 logselect;
	__u32 totalnlogs;
	__u32 nlognum;
	char nlogname[4];
	__u32 nlogbytesize;
	__u32 nlogprimarybuffsize;
	__u32 tickspersecond;
	__u32 corecount;
};

struct nlog_dump_header3_0 {
	struct nlog_dump_header_common common;
	__u32 nlogpausestatus;
	__u32 selectoffsetref;
	__u32 selectnlogpause;
	__u32 selectaddedoffset;
	__u32 nlogbufnum;
	__u32 nlogbufnummax;
};

struct nlog_dump_header4_0 {
	struct nlog_dump_header_common common;
	__u64 nlogpausestatus;
	__u32 selectoffsetref;
	__u32 selectnlogpause;
	__u32 selectaddedoffset;
	__u32 nlogbufnum;
	__u32 nlogbufnummax;
	__u32 coreselected;
	__u32 reserved[2];
};

struct nlog_dump_header4_1 {
	struct nlog_dump_header_common common;
	__u64 nlogpausestatus;
	__u32 selectoffsetref;
	__u32 selectnlogpause;
	__u32 selectaddedoffset;
	__u32 nlogbufnum;
	__u32 nlogbufnummax;
	__u32 coreselected;
	__u32 lpaPointer1High;
	__u32 lpaPointer1Low;
	__u32 lpaPointer2High;
	__u32 lpaPointer2Low;
};

#pragma pack(pop, internal_logs)

struct config {
	char *out_dir;
	char *type;
	bool verbose;
};

struct ilog {
	struct nvme_dev *dev;
	struct config *cfg;
	int count;
	struct nvme_id_ctrl id_ctrl;
	enum nvme_telemetry_da max_da;
};

static void print_nlog_header(__u8 *buffer)
{
	struct nlog_dump_header_common *nlog_header = (struct nlog_dump_header_common *) buffer;

	if (nlog_header->ver.major >= 3) {
		printf("Version Major %u\n", nlog_header->ver.major);
		printf("Version Minor %u\n", nlog_header->ver.minor);
		printf("Log_select %u\n", nlog_header->logselect);
		printf("totalnlogs %u\n", nlog_header->totalnlogs);
		printf("nlognum %u\n", nlog_header->nlognum);
		printf("nlogname %c%c%c%c\n", nlog_header->nlogname[3], nlog_header->nlogname[2],
		       nlog_header->nlogname[1], nlog_header->nlogname[0]);
		printf("nlogbytesize %u\n", nlog_header->nlogbytesize);
		printf("nlogprimarybuffsize %u\n", nlog_header->nlogprimarybuffsize);
		printf("tickspersecond %u\n", nlog_header->tickspersecond);
		printf("corecount %u\n", nlog_header->corecount);
	}
	if (nlog_header->ver.major >= 4) {
		struct nlog_dump_header4_0 *nlog_header = (struct nlog_dump_header4_0 *) buffer;

		printf("nlogpausestatus %"PRIu64"\n", (uint64_t)nlog_header->nlogpausestatus);
		printf("selectoffsetref %u\n", nlog_header->selectoffsetref);
		printf("selectnlogpause %u\n", nlog_header->selectnlogpause);
		printf("selectaddedoffset %u\n", nlog_header->selectaddedoffset);
		printf("nlogbufnum %u\n", nlog_header->nlogbufnum);
		printf("nlogbufnummax %u\n", nlog_header->nlogbufnummax);
		printf("coreselected %u\n\n", nlog_header->coreselected);
	}
}

#define INTERNAL_LOG_MAX_BYTE_TRANSFER 4096
#define INTERNAL_LOG_MAX_DWORD_TRANSFER (INTERNAL_LOG_MAX_BYTE_TRANSFER / 4)

static int cmd_dump_repeat(struct nvme_passthru_cmd *cmd, __u32 total_dw_size,
			   int out_fd, int ioctl_fd, bool force_max_transfer)
{
	int err = 0;

	while (total_dw_size > 0) {
		size_t dword_tfer = min(INTERNAL_LOG_MAX_DWORD_TRANSFER, total_dw_size);

		cmd->cdw10 = force_max_transfer ? INTERNAL_LOG_MAX_DWORD_TRANSFER : dword_tfer;
		cmd->data_len = dword_tfer * 4;
		err = nvme_submit_admin_passthru(ioctl_fd, cmd, NULL);
		if (err)
			return err;

		if (out_fd > 0) {
			err = write(out_fd, (const void *)(uintptr_t)cmd->addr, cmd->data_len);
			if (err < 0) {
				perror("write failure");
				return err;
			}
			err = 0;
		}
		total_dw_size -= dword_tfer;
		cmd->cdw13 += dword_tfer;
	}
	return err;
}

static int write_header(__u8 *buf, int fd, size_t amnt)
{
	if (write(fd, buf, amnt) < 0)
		return 1;
	return 0;
}

static int read_header(struct nvme_passthru_cmd *cmd, int ioctl_fd)
{
	memset((void *)(uintptr_t)cmd->addr, 0, INTERNAL_LOG_MAX_BYTE_TRANSFER);
	return cmd_dump_repeat(cmd, INTERNAL_LOG_MAX_DWORD_TRANSFER, -1, ioctl_fd, false);
}

static int get_serial_number(char *str, int fd)
{
	struct nvme_id_ctrl ctrl = {0};
	int err;

	err = nvme_identify_ctrl(fd, &ctrl);
	if (err)
		return err;

	/* Remove trailing spaces  */
	for (int i = sizeof(ctrl.sn) - 1; i && ctrl.sn[i] == ' '; i--)
		ctrl.sn[i] = '\0';
	sprintf(str, "%-.*s", (int)sizeof(ctrl.sn), ctrl.sn);
	return err;
}

static int ilog_dump_assert_logs(struct ilog *ilog)
{
	__u8 buf[INTERNAL_LOG_MAX_BYTE_TRANSFER];
	__u8 head_buf[INTERNAL_LOG_MAX_BYTE_TRANSFER];
	_cleanup_free_ char *file_path = NULL;
	char file_name[] = "AssertLog.bin";
	struct assert_dump_header *ad = (struct assert_dump_header *) head_buf;
	struct nvme_passthru_cmd cmd = {
		.opcode = 0xd2,
		.nsid = NVME_NSID_ALL,
		.addr = (unsigned long)(void *)head_buf,
		.cdw12 = ASSERTLOG,
		.cdw13 = 0,
	};
	int output, err;

	err = read_header(&cmd, dev_fd(ilog->dev));
	if (err)
		return err;

	if (asprintf(&file_path, "%.*s/%s",
		 (int) (sizeof(file_path) - sizeof(file_name) - 1),
		 ilog->cfg->out_dir, file_name) < 0)
		return -errno;
	output = open(file_path, O_WRONLY | O_CREAT | O_TRUNC, LOG_FILE_PERMISSION);
	if (output < 0)
		return -errno;
	err = write_header((__u8 *)ad, output, ad->header.header_size * DWORD_SIZE);
	if (err) {
		perror("write failure");
		close(output);
		return err;
	}
	cmd.addr = (unsigned long)(void *)buf;

	if (ilog->cfg->verbose) {
		printf("Assert Log, cores: %d log size: %d header size: %d\n", ad->header.numcores,
		       ad->header.log_size * DWORD_SIZE, ad->header.header_size * DWORD_SIZE);
		for (__u32 i = 0; i < ad->header.numcores; i++)
			printf("core %d assert size: %d\n", i, ad->core[i].assertsize * DWORD_SIZE);
	}

	for (__u32 i = 0; i < ad->header.numcores; i++) {
		if (!ad->core[i].assertvalid)
			continue;
		cmd.cdw13 = ad->core[i].coreoffset;
		err = cmd_dump_repeat(&cmd, ad->core[i].assertsize, output,
				      dev_fd(ilog->dev), false);
		if (err) {
			close(output);
			return err;
		}
	}
	close(output);
	printf("Successfully wrote Assert to %s\n", file_path);
	return err;
}

static int ilog_dump_event_logs(struct ilog *ilog)
{
	__u8 buf[INTERNAL_LOG_MAX_BYTE_TRANSFER];
	__u8 head_buf[INTERNAL_LOG_MAX_BYTE_TRANSFER];
	_cleanup_free_ char *file_path = NULL;
	struct event_dump_header *ehdr = (struct event_dump_header *) head_buf;
	struct nvme_passthru_cmd cmd = {
		.opcode = 0xd2,
		.nsid = NVME_NSID_ALL,
		.addr = (unsigned long)(void *)head_buf,
		.cdw12 = EVENTLOG,
		.cdw13 = 0,
	};
	int output;
	int core_num, err;

	err = read_header(&cmd, dev_fd(ilog->dev));
	if (err)
		return err;
	if (asprintf(&file_path, "%s/EventLog.bin", ilog->cfg->out_dir))
		return -errno;
	output = open(file_path, O_WRONLY | O_CREAT | O_TRUNC, LOG_FILE_PERMISSION);
	if (output < 0)
		return -errno;
	err = write_header(head_buf, output, INTERNAL_LOG_MAX_BYTE_TRANSFER);

	core_num = ehdr->header.numcores;

	if (err) {
		close(output);
		return err;
	}
	cmd.addr = (unsigned long)(void *)buf;

	if (ilog->cfg->verbose)
		printf("Event Log, cores: %d log size: %d\n", core_num, ehdr->header.log_size * 4);

	for (__u32 j = 0; j < core_num; j++) {
		if (ilog->cfg->verbose) {
			for (int k = 0 ; k < 16; k++) {
				printf("core: %d event: %d ", j, k);
				printf("validity: %d ", ehdr->edumps[j].eventIdValidity[k]);
				printf("offset: %d\n", ehdr->edumps[j].eventidoffset[k]);
			}
		}
		cmd.cdw13 = ehdr->edumps[j].coreoffset;
		err = cmd_dump_repeat(&cmd, ehdr->edumps[j].coresize,
				output, dev_fd(ilog->dev), false);
		if (err) {
			close(output);
			return err;
		}
	}
	close(output);
	printf("Successfully wrote Events to %s\n", file_path);
	return err;
}

static size_t get_nlog_header_size(struct nlog_dump_header_common *nlog_header)
{
	switch (nlog_header->ver.major) {
	case 3:
		return sizeof(struct nlog_dump_header3_0);
	case 4:
		if (nlog_header->ver.minor == 0)
			return sizeof(struct nlog_dump_header4_0);
		return sizeof(struct nlog_dump_header4_1);
	default:
		return INTERNAL_LOG_MAX_BYTE_TRANSFER;
	}

}

/* dumps nlogs from specified core or all cores when core = -1 */
static int ilog_dump_nlogs(struct ilog *ilog, int core)
{
	int err = 0;
	__u32 count, core_num;
	__u8 buf[INTERNAL_LOG_MAX_BYTE_TRANSFER];
	_cleanup_free_ char *file_path = NULL;
	struct nlog_dump_header_common *nlog_header = (struct nlog_dump_header_common *)buf;
	struct nvme_passthru_cmd cmd = {
		.opcode = 0xd2,
		.nsid = NVME_NSID_ALL,
		.addr = (unsigned long)(void *)buf
	};

	struct dump_select {
		union {
			struct {
				__u32 selectLog  : 3;
				__u32 selectCore : 2;
				__u32 selectNlog : 8;
			};
			__u32 raw;
		};
	} log_select;
	int output;
	bool is_open = false;
	size_t header_size = 0;

	log_select.selectCore = core < 0 ? 0 : core;
	do {
		log_select.selectNlog = 0;
		do {
			cmd.cdw13 = 0;
			cmd.cdw12 = log_select.raw;
			err = read_header(&cmd, dev_fd(ilog->dev));
			if (err) {
				if (is_open)
					close(output);
				return err;
			}
			count = nlog_header->totalnlogs;
			core_num = core < 0 ? nlog_header->corecount : 0;
			if (!header_size) {
				if (asprintf(&file_path, "%s/NLog.bin", ilog->cfg->out_dir) >= 0) {
					output = open(file_path, O_WRONLY | O_CREAT | O_TRUNC,
							LOG_FILE_PERMISSION);
					if (output < 0)
						return -errno;
				} else
					return -errno;
				header_size = get_nlog_header_size(nlog_header);
				is_open = true;
			}
			err = write_header(buf, output, header_size);
			if (err)
				break;
			if (ilog->cfg->verbose)
				print_nlog_header(buf);
			cmd.cdw13 = 0x400;
			err = cmd_dump_repeat(&cmd, nlog_header->nlogbytesize / 4,
				output, dev_fd(ilog->dev), true);
			if (err)
				break;
		} while (++log_select.selectNlog < count);
		if (err)
			break;
	} while (++log_select.selectCore < core_num);
	if (is_open) {
		close(output);
		printf("Successfully wrote Nlog to %s\n", file_path);
	}
	return err;
}

int ensure_dir(const char *parent_dir_name, const char *name)
{
	_cleanup_free_ char *file_path = NULL;
	struct stat sb;

	if (asprintf(&file_path, "%s/%s", parent_dir_name, name) < 0)
		return -errno;

	if (!(stat(file_path, &sb) == 0 && S_ISDIR(sb.st_mode))) {
		if (mkdir(file_path, 777) != 0) {
			perror(file_path);
			return -errno;
		}
	}

	return 0;
}

struct log {
	__u8 id;
	const char *desc;
	size_t buffer_size;
	__u8 *buffer;
};

static int log_save(struct log *log, const char *parent_dir_name, const char *subdir_name,
		    const char *file_name, __u8 *buffer, size_t buf_size)
{
	_cleanup_fd_ int output = -1;
	_cleanup_free_ char *file_path = NULL;
	size_t bytes_remaining = 0;

	ensure_dir(parent_dir_name, subdir_name);

	if (asprintf(&file_path, "%s/%s/%s", parent_dir_name, subdir_name, file_name) < 0)
		return -errno;

	output = open(file_path, O_WRONLY | O_CREAT | O_TRUNC, LOG_FILE_PERMISSION);
	if (output < 0)
		return -errno;

	bytes_remaining = buf_size;

	while (bytes_remaining) {
		ssize_t bytes_written = write(output, buffer, bytes_remaining);

		if (bytes_written < 0)
			return -errno;

		bytes_remaining -= bytes_written;
		buffer += bytes_written;
	}
	printf("Successfully wrote %s to %s\n", log->desc, file_path);
	return 0;
}

static int ilog_dump_identify_page(struct ilog *ilog, struct log *cns, __u32 nsid)
{
	__u8 data[NVME_IDENTIFY_DATA_SIZE];
	__u8 *buff = cns->buffer ? cns->buffer : data;
	_cleanup_free_ char *filename = NULL;
	int err = nvme_identify_cns_nsid(dev_fd(ilog->dev), cns->id, nsid, buff);

	if (err)
		return err;

	if (asprintf(&filename, "cntid_0_cns_%d_nsid_%d_nvmsetid_0_csi_0.bin", cns->id, nsid) < 0)
		return -errno;

	return log_save(cns, ilog->cfg->out_dir, "identify", filename, buff, sizeof(data));
}

static int ilog_ensure_dump_id_ctrl(struct ilog *ilog)
{
	static bool first = true;
	static int err;
	struct log idctrl = {NVME_IDENTIFY_CNS_CTRL, "Id Controller Data", sizeof(ilog->id_ctrl),
		(__u8 *) &ilog->id_ctrl};

	if (!first)
		return err;

	first = false;
	err = ilog_dump_identify_page(ilog, &idctrl, 0);

	if (err)
		return err;

	ilog->count++;

	if (ilog->id_ctrl.lpa & 0x8)
		ilog->max_da = NVME_TELEMETRY_DA_3;
	if (ilog->id_ctrl.lpa & 0x40)
		ilog->max_da = NVME_TELEMETRY_DA_4;

	return err;
}

static int ilog_dump_telemetry(struct ilog *ilog, enum log_type ttype)
{
	int err = 0;
	enum nvme_telemetry_da da;
	size_t mdts;
	const char *file_name;
	struct nvme_feat_host_behavior prev = {0};
	bool host_behavior_changed = false;
	struct log log = {0};

	err = ilog_ensure_dump_id_ctrl(ilog);
	if (err)
		return err;

	da = ilog->max_da;
	mdts = ilog->id_ctrl.mdts;

	if (da == 4) {
		__u32 result;
		int err = nvme_get_features_host_behavior(dev_fd(ilog->dev), 0, &prev, &result);

		if (!err && !prev.etdas) {
			struct nvme_feat_host_behavior da4_enable = prev;

			da4_enable.etdas = 1;
			nvme_set_features_host_behavior(dev_fd(ilog->dev), 0, &da4_enable);
			host_behavior_changed = true;
		}
	}

	switch (ttype) {
	case HIT:
		file_name = "lid_0x07_lsp_0x01_lsi_0x0000.bin";
		log.desc = "Host Initiated Telemetry";
		err = sldgm_dynamic_telemetry(dev_fd(ilog->dev), true, false, false, mdts,
					      da, (struct nvme_telemetry_log **) &log.buffer,
					      &log.buffer_size);
		break;
	case CIT:
		file_name = "lid_0x08_lsp_0x00_lsi_0x0000.bin";
		log.desc = "Controller Initiated Telemetry";
		err = sldgm_dynamic_telemetry(dev_fd(ilog->dev), false, true, true, mdts,
					      da, (struct nvme_telemetry_log **) &log.buffer,
					      &log.buffer_size);
		break;
	default:
		return -EINVAL;
	}

	if (host_behavior_changed)
		nvme_set_features_host_behavior(dev_fd(ilog->dev), 0, &prev);

	if (err)
		return err;

	err = log_save(&log, ilog->cfg->out_dir, "log_pages", file_name, log.buffer,
		       log.buffer_size);
	return err;
}

static int ilog_dump_identify_pages(struct ilog *ilog)
{
	struct nvme_ns_list ns_attached_list;
	struct nvme_ns_list ns_allocated_list;
	__u32 j = 0;

	struct log identify_base_list[] = {
		{NVME_IDENTIFY_CNS_NS_ACTIVE_LIST, "Id Active Namespace ID list",
		 sizeof(ns_attached_list), (__u8 *) &ns_attached_list},
		{NVME_IDENTIFY_CNS_NVMSET_LIST, "Id NVM Set List"},
		{NVME_IDENTIFY_CNS_CSI_CTRL, "Id I/O Command Set specific"},
		{NVME_IDENTIFY_CNS_ALLOCATED_NS_LIST, "Id Allocated Namespace ID list",
		sizeof(ns_allocated_list), (__u8 *) &ns_allocated_list},
		{NVME_IDENTIFY_CNS_CTRL_LIST, "Id Controller List"}
	};
	struct log identify_ns_required_list[] = {
		{NVME_IDENTIFY_CNS_NS, "Id Namespace data"},
		{NVME_IDENTIFY_CNS_NS_DESC_LIST, "Id Namespace Id Descriptor list"},
		{NVME_IDENTIFY_CNS_CSI_NS, "Id Namespace ID I/O Command Set specific"},
		{NVME_IDENTIFY_CNS_CSI_INDEPENDENT_ID_NS,
		 "I/O Command Set Independent Identify Namespace Data"},
		{NVME_IDENTIFY_CNS_NS_CTRL_LIST, "Id Namespace Id Controller List"},
	};

	struct log allocated = {NVME_IDENTIFY_CNS_ALLOCATED_NS, "Allocated Namespace Data",
				NVME_IDENTIFY_DATA_SIZE, NULL};

	ilog_ensure_dump_id_ctrl(ilog);

	for (int i = 0; i < ARRAY_SIZE(identify_base_list); i++) {
		int err = ilog_dump_identify_page(ilog, &identify_base_list[i], 0);

		if (err == 0)
			ilog->count++;
	}

	while (ns_attached_list.ns[j]) {
		for (int i = 0; i < ARRAY_SIZE(identify_ns_required_list); i++) {
			int err = ilog_dump_identify_page(ilog, &identify_ns_required_list[i],
							  ns_attached_list.ns[j]);

			if (err == 0)
				ilog->count++;
		}
		j++;
	}

	j = 0;
	while (ns_allocated_list.ns[j]) {
		int err = ilog_dump_identify_page(ilog, &allocated, ns_allocated_list.ns[j]);

		if (err == 0)
			ilog->count++;
		j++;
	}

	return 0;
}

static int ilog_dump_log_page(struct ilog *ilog, struct log *lp, __u32 nsid)
{
	__u8 *buff = lp->buffer;
	_cleanup_free_ char *filename = NULL;

	int err;
	if (!lp->buffer_size)
		return -EINVAL;
	if (!buff) {
		buff = nvme_alloc(lp->buffer_size);
		if (!buff)
			return -ENOMEM;
	}
	err = nvme_get_nsid_log(dev_fd(ilog->dev), 0, lp->id, 0, lp->buffer_size, buff);
	if (err)
		return err;

	if (asprintf(&filename, "lid_0x%02x_lsp_0x00_lsi_0x0000.bin", lp->id) < 0)
		return -errno;

	return log_save(lp, ilog->cfg->out_dir, "log_pages", filename, buff, lp->buffer_size);
}

static int ilog_dump_no_lsp_log_pages(struct ilog *ilog)
{
	struct lba_status_info {
		__u32 lslplen;
		__u32 nlslne;
		__u32 estulb;
		__u16 rsvd;
		__u16 lsgc;
	} lba_status = {};
	__u64 num_entries = 0;
	struct log log_page_dependent_list[] = {
		{NVME_LOG_LID_LBA_STATUS},
		{NVME_LOG_LID_ENDURANCE_GRP_EVT},
	};
	struct log log_page_base_list[] = {
		{NVME_LOG_LID_SUPPORTED_LOG_PAGES, NULL, sizeof(struct nvme_supported_log_pages)},
		{NVME_LOG_LID_ERROR, NULL,
		 (ilog->id_ctrl.elpe + 1) * sizeof(struct nvme_error_log_page)},
		{NVME_LOG_LID_SMART, NULL, sizeof(struct nvme_smart_log)},
		{NVME_LOG_LID_FW_SLOT, NULL, sizeof(struct nvme_firmware_slot)},
		{NVME_LOG_LID_CHANGED_NS, NULL, sizeof(struct nvme_ns_list)},
		{NVME_LOG_LID_CMD_EFFECTS, NULL, sizeof(struct nvme_cmd_effects_log)},
		{NVME_LOG_LID_DEVICE_SELF_TEST, NULL, sizeof(struct nvme_self_test_log)},
		{NVME_LOG_LID_LBA_STATUS, NULL, sizeof(lba_status), (__u8 *) &lba_status},
		{NVME_LOG_LID_ENDURANCE_GRP_EVT, NULL, sizeof(num_entries), (__u8 *) &num_entries},
		{NVME_LOG_LID_FID_SUPPORTED_EFFECTS, NULL,
		 sizeof(struct nvme_fid_supported_effects_log)},
		{NVME_LOG_LID_MI_CMD_SUPPORTED_EFFECTS, NULL,
		 sizeof(struct nvme_mi_cmd_supported_effects_log)},
		{NVME_LOG_LID_CMD_AND_FEAT_LOCKDOWN, NULL, 512},
		{NVME_LOG_LID_PHY_RX_EOM, NULL, 512},
		{NVME_LOG_LID_SANITIZE, NULL, sizeof(struct nvme_sanitize_log_page)},
		{0xC0, "OCP or VU SMART / Health Information Extended",  512},
		{0xC1, "OCP Error Recovery or VU Latency Reads",  512},
		{0xC2, "OCP Firmware Activation History or VU Latency Writes",  4096},
		{0xC3, "OCP Latency Monitor",  512},
		{0xC4, "OCP Device Capabilities or VU Endurance Manager Statistics",  4096},
		{0xC5, "OCP Unsupported Requirements or VU Tempeture Statistics",  4096},
		{0xC7, "OCP TCG Configuration", 512},
		{0xCA, "SMART Attributes", 512},
		{0xd5, "Tempeture Statistics", 512},
		{0xfe, "Latency Outlier",  8192},
	};

	for (int i = 0; i < ARRAY_SIZE(log_page_base_list); i++) {
		log_page_base_list[i].desc = log_page_base_list[i].desc ?
			log_page_base_list[i].desc :
			nvme_log_to_string(log_page_base_list[i].id);
		if (!ilog_dump_log_page(ilog, &log_page_base_list[i], 0))
			ilog->count++;
	}

	/* if needed, patch logs based on retrieved log size */
	if (lba_status.lslplen > sizeof(lba_status))
		log_page_dependent_list[0].buffer_size = lba_status.lslplen;
	if (num_entries)
		log_page_dependent_list[1].buffer_size = sizeof(num_entries) +
			(num_entries * sizeof(__u16));

	for (int i = 0; i < ARRAY_SIZE(log_page_dependent_list); i++) {
		log_page_dependent_list[i].desc = log_page_dependent_list[i].desc ?
			log_page_dependent_list[i].desc :
			nvme_log_to_string(log_page_dependent_list[i].id);
		ilog_dump_log_page(ilog, &log_page_dependent_list[i], 0);
	}

	return 0;
}

static int ilog_dump_pel(struct ilog *ilog)
{
	struct log lp = {
		NVME_LOG_LID_PERSISTENT_EVENT,
		nvme_log_to_string(NVME_LOG_LID_PERSISTENT_EVENT)
	};
	void *pevent_log_full;
	int err;
	struct nvme_get_log_args args;
	size_t max_data_tx;

	_cleanup_free_ struct nvme_persistent_event_log *pevent = NULL;

	_cleanup_huge_ struct nvme_mem_huge mh = {0};

	err = nvme_get_log_persistent_event(dev_fd(ilog->dev), NVME_PEVENT_LOG_RELEASE_CTX,
					    sizeof(*pevent), pevent);
	if (err)
		return err;


	pevent = nvme_alloc(sizeof(*pevent));
	if (!pevent)
		return -ENOMEM;

	err = nvme_get_log_persistent_event(dev_fd(ilog->dev), NVME_PEVENT_LOG_EST_CTX_AND_READ,
					    sizeof(*pevent), pevent);
	if (err)
		return err;

	lp.buffer_size = le64_to_cpu(pevent->tll);

	pevent_log_full = nvme_alloc_huge(lp.buffer_size, &mh);
	if (!pevent_log_full)
		return -ENOMEM;

	err = nvme_get_log_persistent_event(dev_fd(ilog->dev), NVME_PEVENT_LOG_READ,
						lp.buffer_size, pevent_log_full);
	args = (struct nvme_get_log_args) {
		.lpo = 0,
		.result = NULL,
		.log = pevent_log_full,
		.args_size = sizeof(args),
		.fd = dev_fd(ilog->dev),
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.lid = NVME_LOG_LID_PERSISTENT_EVENT,
		.len = lp.buffer_size,
		.nsid = NVME_NSID_ALL,
		.csi = NVME_CSI_NVM,
		.lsi = NVME_LOG_LSI_NONE,
		.lsp = NVME_PEVENT_LOG_READ,
		.uuidx = NVME_UUID_NONE,
		.rae = false,
		.ot = false,
	};

	max_data_tx = (1 << ilog->id_ctrl.mdts) * NVME_LOG_PAGE_PDU_SIZE;
	do {
		err = nvme_get_log_page(dev_fd(ilog->dev), max_data_tx, &args);
		max_data_tx /= 2;
	} while (err == -EPERM && max_data_tx >= NVME_LOG_PAGE_PDU_SIZE);

	if (err)
		return err;

	err = log_save(&lp, ilog->cfg->out_dir, "log_pages", "lid_0x0d_lsp_0x00_lsi_0x0000.bin",
		       pevent_log_full, lp.buffer_size);

	nvme_get_log_persistent_event(dev_fd(ilog->dev), NVME_PEVENT_LOG_RELEASE_CTX,
				      sizeof(*pevent), pevent);

	return err;
}

int solidigm_get_internal_log(int argc, char **argv, struct command *command,
				struct plugin *plugin)
{
	char sn_prefix[sizeof(((struct nvme_id_ctrl *)0)->sn)+1];
	char date_str[sizeof("-YYYYMMDDHHMMSS")];
	_cleanup_free_ char *full_folder = NULL;
	_cleanup_free_ char *unique_folder = NULL;
	_cleanup_free_ char *zip_name = NULL;

	char *initial_folder;
	char *output_path;
	struct ilog ilog = {0};
	int err;
	_cleanup_nvme_dev_ struct nvme_dev *dev = NULL;
	enum log_type log_type = ALL;
	char type_ALL[] = "ALL";
	time_t current_time;
	DIR *dir;

	const char *desc = "Get Debug Firmware Logs and save them.";
	const char *type = "Log type; Defaults to ALL.";
	const char *out_dir = "Output directory; defaults to current working directory.";
	const char *verbose = "To print out verbose info.";

	struct config cfg = {
		.out_dir = ".",
		.type = type_ALL,
	};

	OPT_ARGS(opts) = {
		OPT_STRING("type",     't', "ALL|CIT|HIT|NLOG|ASSERT|EVENT", &cfg.type, type),
		OPT_STRING("dir-name", 'd', "DIRECTORY", &cfg.out_dir, out_dir),
		OPT_FLAG("verbose",    'v', &cfg.verbose,      verbose),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;
	ilog.dev = dev;
	ilog.cfg = &cfg;

	for (char *p = cfg.type; *p; ++p)
		*p = toupper(*p);

	if (!strcmp(cfg.type, "ALL"))
		log_type = ALL;
	else if (!strcmp(cfg.type, "HIT"))
		log_type = HIT;
	else if (!strcmp(cfg.type, "CIT"))
		log_type = CIT;
	else if (!strcmp(cfg.type, "NLOG"))
		log_type = NLOG;
	else if (!strcmp(cfg.type, "ASSERT"))
		log_type = ASSERTLOG;
	else if (!strcmp(cfg.type, "EVENT"))
		log_type = EVENTLOG;
	else {
		fprintf(stderr, "Invalid log type: %s\n", cfg.type);
		return -EINVAL;
	}

	dir = opendir(cfg.out_dir);
	if (dir)
		closedir(dir);
	else  {
		perror(cfg.out_dir);
		return -errno;
	}

	initial_folder = cfg.out_dir;

	err = get_serial_number(sn_prefix, dev_fd(dev));
	if (err)
		return err;

	current_time = time(NULL);
	strftime(date_str, sizeof(date_str), "-%Y%m%d%H%M%S", localtime(&current_time));
	if (asprintf(&unique_folder, "%s%s", sn_prefix, date_str) < 0)
		return -errno;
	if (asprintf(&full_folder, "%s/%s", cfg.out_dir, unique_folder) < 0)
		return -errno;

	if (mkdir(full_folder, 0755) !=  0) {
		perror("mkdir");
		return -errno;
	}

	cfg.out_dir = full_folder;
	output_path = full_folder;

	/* Retrieve first logs that records actions to retrieve other logs */
	if (log_type == ALL || log_type == HIT) {
		err = ilog_dump_telemetry(&ilog, HIT);
		if (err == 0)
			ilog.count++;
		else if (err < 0)
			perror("Error retrieving Host Initiated Telemetry");
	}
	if (log_type == ALL || log_type == NLOG) {
		err = ilog_dump_nlogs(&ilog, -1);
		if (err == 0)
			ilog.count++;
		else if (err < 0)
			perror("Error retrieving Nlog");
	}
	if (log_type == ALL || log_type == CIT) {
		err = ilog_dump_telemetry(&ilog, CIT);
		if (err == 0)
			ilog.count++;
		else if (err < 0)
			perror("Error retrieving Controller Initiated Telemetry");
	}
	if (log_type == ALL || log_type == ASSERTLOG) {
		err = ilog_dump_assert_logs(&ilog);
		if (err == 0)
			ilog.count++;
		else if (err < 0)
			perror("Error retrieving Assert log");
	}
	if (log_type == ALL || log_type == EVENTLOG) {
		err = ilog_dump_event_logs(&ilog);
		if (err == 0)
			ilog.count++;
		else if (err < 0)
			perror("Error retrieving Event log");
	}
	if (log_type == ALL) {
		err = ilog_dump_identify_pages(&ilog);
		if (err < 0)
			perror("Error retrieving Identify pages");

		err = ilog_dump_pel(&ilog);
		if (err < 0)
			perror("Error retrieving Persistent Event Log page");

		err = ilog_dump_no_lsp_log_pages(&ilog);
		if (err < 0)
			perror("Error retrieving no LSP Log pages");
	}

	if (ilog.count > 0) {
		int ret_cmd;
		_cleanup_free_ char *cmd = NULL;
		char *quiet = cfg.verbose ? "" : " -q";

		if (asprintf(&zip_name, "%s.zip", unique_folder) < 0)
			return -errno;

		if (asprintf(&cmd, "cd \"%s\" && zip -MM -r \"../%s\" ./* %s", cfg.out_dir,
			     zip_name, quiet) < 0) {
			err = errno;
			perror("Can't allocate string for zip command");
			goto out;
		}
		printf("Compressing logs to %s\n", zip_name);
		ret_cmd = system(cmd);
		if (ret_cmd)
			perror(cmd);
		else {
			output_path = zip_name;
			if (asprintf(&cmd, "rm -rf %s", cfg.out_dir) < 0) {
				err = errno;
				perror("Can't allocate string for cleanup");
				goto out;
			}
			if (system(cmd) != 0)
				perror("Failed removing logs folder");
		}
	}

out:
	if (ilog.count == 0) {
		if (err > 0)
			nvme_show_status(err);

	} else if ((ilog.count > 1) || cfg.verbose)
		printf("Total: %d log files in %s/%s\n", ilog.count, initial_folder, output_path);

	return err;
}
