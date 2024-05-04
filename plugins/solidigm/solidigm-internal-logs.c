// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2023 Solidigm.
 *
 * Authors: leonardo.da.cunha@solidigm.com
 * shankaralingegowda.singonahalli@solidigm.com
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

static int dump_assert_logs(struct nvme_dev *dev, struct config cfg)
{
	__u8 buf[INTERNAL_LOG_MAX_BYTE_TRANSFER];
	__u8 head_buf[INTERNAL_LOG_MAX_BYTE_TRANSFER];
	char file_path[PATH_MAX];
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

	err = read_header(&cmd, dev_fd(dev));
	if (err)
		return err;

	snprintf(file_path, sizeof(file_path), "%.*s/%s",
		 (int) (sizeof(file_path) - sizeof(file_name) - 1), cfg.out_dir, file_name);
	output = open(file_path, O_WRONLY | O_CREAT | O_TRUNC, 0666);
	if (output < 0)
		return -errno;
	err = write_header((__u8 *)ad, output, ad->header.header_size * DWORD_SIZE);
	if (err) {
		perror("write failure");
		close(output);
		return err;
	}
	cmd.addr = (unsigned long)(void *)buf;

	if (cfg.verbose) {
		printf("Assert Log, cores: %d log size: %d header size: %d\n", ad->header.numcores,
		       ad->header.log_size * DWORD_SIZE, ad->header.header_size * DWORD_SIZE);
		for (__u32 i = 0; i < ad->header.numcores; i++)
			printf("core %d assert size: %d\n", i, ad->core[i].assertsize * DWORD_SIZE);
	}

	for (__u32 i = 0; i < ad->header.numcores; i++) {
		if (!ad->core[i].assertvalid)
			continue;
		cmd.cdw13 = ad->core[i].coreoffset;
		err = cmd_dump_repeat(&cmd, ad->core[i].assertsize,
				output,
				dev_fd(dev), false);
		if (err) {
			close(output);
			return err;
		}
	}
	close(output);
	printf("Successfully wrote log to %s\n", file_path);
	return err;
}

static int dump_event_logs(struct nvme_dev *dev, struct config cfg)
{
	__u8 buf[INTERNAL_LOG_MAX_BYTE_TRANSFER];
	__u8 head_buf[INTERNAL_LOG_MAX_BYTE_TRANSFER];
	char file_path[PATH_MAX];
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

	err = read_header(&cmd, dev_fd(dev));
	if (err)
		return err;
	snprintf(file_path, sizeof(file_path), "%s/EventLog.bin", cfg.out_dir);
	output = open(file_path, O_WRONLY | O_CREAT | O_TRUNC, 0666);
	if (output < 0)
		return -errno;
	err = write_header(head_buf, output, INTERNAL_LOG_MAX_BYTE_TRANSFER);

	core_num = ehdr->header.numcores;

	if (err) {
		close(output);
		return err;
	}
	cmd.addr = (unsigned long)(void *)buf;

	if (cfg.verbose)
		printf("Event Log, cores: %d log size: %d\n", core_num, ehdr->header.log_size * 4);

	for (__u32 j = 0; j < core_num; j++) {
		if (cfg.verbose) {
			for (int k = 0 ; k < 16; k++) {
				printf("core: %d event: %d ", j, k);
				printf("validity: %d ", ehdr->edumps[j].eventIdValidity[k]);
				printf("offset: %d\n", ehdr->edumps[j].eventidoffset[k]);
			}
		}
		cmd.cdw13 = ehdr->edumps[j].coreoffset;
		err = cmd_dump_repeat(&cmd, ehdr->edumps[j].coresize,
				output, dev_fd(dev), false);
		if (err) {
			close(output);
			return err;
		}
	}
	close(output);
	printf("Successfully wrote log to %s\n", file_path);
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
static int dump_nlogs(struct nvme_dev *dev, struct config cfg, int core)
{
	int err = 0;
	__u32 count, core_num;
	__u8 buf[INTERNAL_LOG_MAX_BYTE_TRANSFER];
	char file_path[PATH_MAX];
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
			err = read_header(&cmd, dev_fd(dev));
			if (err) {
				if (is_open)
					close(output);
				return err;
			}
			count = nlog_header->totalnlogs;
			core_num = core < 0 ? nlog_header->corecount : 0;
			if (!header_size) {
				snprintf(file_path, sizeof(file_path), "%s/NLog.bin",
					 cfg.out_dir);
				output = open(file_path, O_WRONLY | O_CREAT | O_TRUNC, 0666);
				if (output < 0)
					return -errno;
				header_size = get_nlog_header_size(nlog_header);
				is_open = true;
			}
			err = write_header(buf, output, header_size);
			if (err)
				break;
			if (cfg.verbose)
				print_nlog_header(buf);
			cmd.cdw13 = 0x400;
			err = cmd_dump_repeat(&cmd, nlog_header->nlogbytesize / 4,
					output, dev_fd(dev), true);
			if (err)
				break;
		} while (++log_select.selectNlog < count);
		if (err)
			break;
	} while (++log_select.selectCore < core_num);
	if (is_open) {
		close(output);
		printf("Successfully wrote log to %s\n", file_path);
	}
	return err;
}

static int dump_telemetry(struct nvme_dev *dev, struct config cfg, enum log_type ttype)
{
	_cleanup_free_ struct nvme_telemetry_log *log = NULL;
	size_t log_size = 0;
	int err = 0;
	__u8 *buffer = NULL;
	size_t bytes_remaining = 0;
	enum nvme_telemetry_da da;
	size_t max_data_tx;
	char file_path[PATH_MAX];
	char *file_name;
	char *log_descr;
	struct stat sb;
	struct nvme_feat_host_behavior prev = {0};
	bool host_behavior_changed = false;
	_cleanup_file_ int output = -1;

	err = nvme_get_telemetry_max(dev_fd(dev), &da, &max_data_tx);
	if (err)
		return err;

	if (max_data_tx > DRIVER_MAX_TX_256K)
		max_data_tx = DRIVER_MAX_TX_256K;

	if (da == 4) {
		__u32 result;
		int err = nvme_get_features_host_behavior(dev_fd(dev), 0, &prev, &result);

		if (!err && !prev.etdas) {
			struct nvme_feat_host_behavior da4_enable = prev;

			da4_enable.etdas = 1;
			nvme_set_features_host_behavior(dev_fd(dev), 0, &da4_enable);
			host_behavior_changed = true;
		}
	}

	switch (ttype) {
	case HIT:
		file_name = "lid_0x07_lsp_0x01_lsi_0x0000.bin";
		log_descr = "Host Initiated";
		err = nvme_get_telemetry_log(dev_fd(dev), true, false, false, max_data_tx, da,
					     &log, &log_size);
		break;
	case CIT:
		file_name = "lid_0x08_lsp_0x00_lsi_0x0000.bin";
		log_descr = "Controller Initiated";
		err = nvme_get_telemetry_log(dev_fd(dev), false, true, true, max_data_tx, da, &log,
					     &log_size);
		break;
	default:
		return -EINVAL;
	}

	if (host_behavior_changed)
		nvme_set_features_host_behavior(dev_fd(dev), 0, &prev);

	if (err)
		return err;

	snprintf(file_path, sizeof(file_path), "%s/log_pages", cfg.out_dir);
	if (!(stat(file_path, &sb) == 0 && S_ISDIR(sb.st_mode))) {
		if (mkdir(file_path, 777) != 0) {
			perror(file_path);
			return -errno;
		}
	}

	snprintf(file_path, sizeof(file_path), "%s/log_pages/%s", cfg.out_dir, file_name);
	output = open(file_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (output < 0)
		return -errno;

	bytes_remaining = log_size;
	buffer = (__u8 *)log;

	while (bytes_remaining) {
		ssize_t bytes_written = write(output, buffer, bytes_remaining);

		if (bytes_written < 0) {
			err = -errno;
			goto tele_close_output;
		}

		bytes_remaining -= bytes_written;
		buffer += bytes_written;
	}
	printf("Successfully wrote %s Telemetry log to %s\n", log_descr, file_path);

tele_close_output:
	close(output);
	return err;
}

int solidigm_get_internal_log(int argc, char **argv, struct command *command,
				struct plugin *plugin)
{
	char sn_prefix[sizeof(((struct nvme_id_ctrl *)0)->sn)+1];
	char date_str[sizeof("-YYYYMMDDHHMMSS")];
	char full_folder[PATH_MAX];
	char unique_folder[sizeof(sn_prefix)+sizeof(date_str)-1];
	char *initial_folder;
	char zip_name[PATH_MAX];
	char *output_path;
	int log_count = 0;
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
	snprintf(unique_folder, sizeof(unique_folder), "%s%s", sn_prefix, date_str);
	snprintf(full_folder, sizeof(full_folder), "%s/%s", cfg.out_dir, unique_folder);
	if (mkdir(full_folder, 0777) != 0) {
		perror("mkdir");
		return -errno;
	}
	cfg.out_dir = full_folder;
	output_path = full_folder;

	/* Retrieve first logs that records actions to retrieve other logs */
	if (log_type == ALL || log_type == HIT) {
		err = dump_telemetry(dev, cfg, HIT);
		if (err == 0)
			log_count++;
		else if (err < 0)
			perror("Error retrieving Host Initiated Telemetry");
	}
	if (log_type == ALL || log_type == NLOG) {
		err = dump_nlogs(dev, cfg, -1);
		if (err == 0)
			log_count++;
		else if (err < 0)
			perror("Error retrieving Nlog");
	}
	if (log_type == ALL || log_type == CIT) {
		err = dump_telemetry(dev, cfg, CIT);
		if (err == 0)
			log_count++;
		else if (err < 0)
			perror("Error retrieving Controller Initiated Telemetry");
	}
	if (log_type == ALL || log_type == ASSERTLOG) {
		err = dump_assert_logs(dev, cfg);
		if (err == 0)
			log_count++;
		else if (err < 0)
			perror("Error retrieving Assert log");
	}
	if (log_type == ALL || log_type == EVENTLOG) {
		err = dump_event_logs(dev, cfg);
		if (err == 0)
			log_count++;
		else if (err < 0)
			perror("Error retrieving Event log");
	}

	if (log_count > 0) {
		int ret_cmd;
		char *cmd;
		char *quiet = cfg.verbose ? "" : " -q";

		snprintf(zip_name, sizeof(zip_name), "%s.zip", unique_folder);
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
			free(cmd);
			if (asprintf(&cmd, "rm -rf %s", cfg.out_dir) < 0) {
				err = errno;
				perror("Can't allocate string for cleanup");
				goto out;
			}
			if (system(cmd) != 0)
				perror("Failed removing logs folder");
		}
		free(cmd);
	}

out:
	if (log_count == 0) {
		if (err > 0)
			nvme_show_status(err);

	} else if ((log_count > 1) || cfg.verbose)
		printf("Total: %d log files in %s/%s\n", log_count, initial_folder, output_path);

	return err;
}
