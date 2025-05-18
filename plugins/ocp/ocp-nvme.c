// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2023 Meta Platforms, Inc.
 *
 * Authors: Arthur Shau <arthurshau@meta.com>,
 *          Wei Zhang <wzhang@meta.com>,
 *          Venkat Ramesh <venkatraghavan@meta.com>
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>
#include <errno.h>
#include <limits.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>

#include "common.h"
#include "nvme.h"
#include "libnvme.h"
#include "plugin.h"
#include "linux/types.h"
#include "util/types.h"
#include "logging.h"
#include "nvme-print.h"
#include "nvme-wrap.h"

#include "ocp-smart-extended-log.h"
#include "ocp-clear-features.h"
#include "ocp-fw-activation-history.h"
#include "ocp-telemetry-decode.h"
#include "ocp-hardware-component-log.h"
#include "ocp-print.h"
#include "ocp-types.h"

#define CREATE_CMD
#include "ocp-nvme.h"
#include "ocp-utils.h"

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
/// Latency Monitor Log

#define C3_LATENCY_MON_LOG_BUF_LEN		0x200

static __u8 lat_mon_guid[GUID_LEN] = {
	0x92, 0x7a, 0xc0, 0x8c,
	0xd0, 0x84, 0x6c, 0x9c,
	0x70, 0x43, 0xe6, 0xd4,
	0x58, 0x5e, 0xd4, 0x85
};

#define RESERVED	0

struct __packed feature_latency_monitor {
	__le16 active_bucket_timer_threshold;
	__u8 active_threshold_a;
	__u8 active_threshold_b;
	__u8 active_threshold_c;
	__u8 active_threshold_d;
	__le16 active_latency_config;
	__u8 active_latency_minimum_window;
	__le16 debug_log_trigger_enable;
	__u8 discard_debug_log;
	__u8 latency_monitor_feature_enable;
	__u8 reserved[4083];
};

struct erri_entry {
	union {
		__u8 flags;
		struct {
			__u8 enable:1;
			__u8 single:1;
			__u8 rsvd2:6;
		};
	};
	__u8 rsvd1;
	__le16 type;
	union {
		__u8 specific[28];
		struct {
			__le16 nrtdp;
			__u8 rsvd4[26];
		};
	};
};

#define ERRI_ENTRIES_MAX 127

enum erri_type {
	ERRI_TYPE_CPU_CTRL_HANG = 1,
	ERRI_TYPE_NAND_HANG,
	ERRI_TYPE_PLP_DEFECT,
	ERRI_TYPE_LOGICAL_FIRMWARE_ERROR,
	ERRI_TYPE_DRAM_CORRUPT_CRIT,
	ERRI_TYPE_DRAM_CORRUPT_NON_CRIT,
	ERRI_TYPE_NAND_CORRUPT,
	ERRI_TYPE_SRAM_CORRUPT,
	ERRI_TYPE_HW_MALFUNCTION,
	ERRI_TYPE_NO_MORE_NAND_SPARES,
	ERRI_TYPE_INCOMPLETE_SHUTDOWN,
	ERRI_TYPE_METADATA_CORRUPTION,
	ERRI_TYPE_CRITICAL_GC,
	ERRI_TYPE_LATENCY_SPIKE,
	ERRI_TYPE_IO_CMD_FAILURE,
	ERRI_TYPE_IO_CMD_TIMEOUT,
	ERRI_TYPE_ADMIN_CMD_FAILURE,
	ERRI_TYPE_ADMIN_CMD_TIMEOUT,
	ERRI_TYPE_THERMAL_THROTTLE_ENGAGED,
	ERRI_TYPE_THERMAL_THROTTLE_DISENGAGED,
	ERRI_TYPE_CRITICAL_TEMPERATURE_EVENT,
	ERRI_TYPE_DIE_OFFLINE,
};

const char *erri_type_to_string(__le16 type)
{
	switch (type) {
	case ERRI_TYPE_CPU_CTRL_HANG:
		return "CPU/controller hang";
	case ERRI_TYPE_NAND_HANG:
		return "NAND hang";
	case ERRI_TYPE_PLP_DEFECT:
		return "PLP defect";
	case ERRI_TYPE_LOGICAL_FIRMWARE_ERROR:
		return "logical firmware error";
	case ERRI_TYPE_DRAM_CORRUPT_CRIT:
		return "DRAM corruption critical path";
	case ERRI_TYPE_DRAM_CORRUPT_NON_CRIT:
		return "DRAM corruption non-critical path";
	case ERRI_TYPE_NAND_CORRUPT:
		return "NAND corruption";
	case ERRI_TYPE_SRAM_CORRUPT:
		return "SRAM corruption";
	case ERRI_TYPE_HW_MALFUNCTION:
		return "HW malfunction";
	case ERRI_TYPE_NO_MORE_NAND_SPARES:
		return "no more NAND spares available";
	case ERRI_TYPE_INCOMPLETE_SHUTDOWN:
		return "incomplete shutdown";
	case ERRI_TYPE_METADATA_CORRUPTION:
		return "Metadata Corruption";
	case ERRI_TYPE_CRITICAL_GC:
		return "Critical Garbage Collection";
	case ERRI_TYPE_LATENCY_SPIKE:
		return "Latency Spike";
	case ERRI_TYPE_IO_CMD_FAILURE:
		return "I/O command failure";
	case ERRI_TYPE_IO_CMD_TIMEOUT:
		return "I/O command timeout";
	case ERRI_TYPE_ADMIN_CMD_FAILURE:
		return "Admin command failure";
	case ERRI_TYPE_ADMIN_CMD_TIMEOUT:
		return "Admin command timeout";
	case ERRI_TYPE_THERMAL_THROTTLE_ENGAGED:
		return "Thermal Throttle Engaged";
	case ERRI_TYPE_THERMAL_THROTTLE_DISENGAGED:
		return "Thermal Throttle Disengaged";
	case ERRI_TYPE_CRITICAL_TEMPERATURE_EVENT:
		return "Critical Temperature Event";
	case ERRI_TYPE_DIE_OFFLINE:
		return "Die Offline";
	default:
		break;
	}

	return "unknown";
}

struct erri_get_cq_entry {
	__u32 nume:7;
	__u32 rsvd7:25;
};

struct erri_config {
	char *file;
	__u8 number;
	__u16 type;
	__u16 nrtdp;
};

struct ieee1667_get_cq_entry {
	__u32 enabled:3;
	__u32 rsvd3:29;
};

static const char *sel = "[0-3]: current/default/saved/supported";
static const char *no_uuid = "Skip UUID index search (UUID index not required for OCP 1.0)";
const char *data = "Error injection data structure entries";
const char *number = "Number of valid error injection data entries";
static const char *type = "Error injection type";
static const char *nrtdp = "Number of reads to trigger device panic";
static const char *save = "Specifies that the controller shall save the attribute";
static const char *enable_ieee1667_silo = "enable IEEE1667 silo";

static int get_c3_log_page(struct nvme_dev *dev, char *format)
{
	struct ssd_latency_monitor_log *log_data;
	nvme_print_flags_t fmt;
	int ret;
	__u8 *data;
	int i;

	ret = validate_output_format(format, &fmt);
	if (ret < 0) {
		fprintf(stderr, "ERROR : OCP : invalid output format\n");
		return ret;
	}

	data = malloc(sizeof(__u8) * C3_LATENCY_MON_LOG_BUF_LEN);
	if (!data) {
		fprintf(stderr, "ERROR : OCP : malloc : %s\n", strerror(errno));
		return -1;
	}
	memset(data, 0, sizeof(__u8) * C3_LATENCY_MON_LOG_BUF_LEN);

	ret = ocp_get_log_simple(dev, OCP_LID_LMLOG, C3_LATENCY_MON_LOG_BUF_LEN, data);

	if (strcmp(format, "json"))
		fprintf(stderr, "NVMe Status:%s(%x)\n", nvme_status_to_string(ret, false), ret);

	if (!ret) {
		log_data = (struct ssd_latency_monitor_log *)data;

		/*
		 * check log page guid
		 * Verify GUID matches
		 */
		for (i = 0; i < 16; i++) {
			if (lat_mon_guid[i] != log_data->log_page_guid[i]) {
				int j;

				fprintf(stderr, "ERROR : OCP : Unknown GUID in C3 Log Page data\n");
				fprintf(stderr, "ERROR : OCP : Expected GUID: 0x");
				for (j = 0; j < 16; j++)
					fprintf(stderr, "%02x", lat_mon_guid[j]);

				fprintf(stderr, "\nERROR : OCP : Actual GUID: 0x");
				for (j = 0; j < 16; j++)
					fprintf(stderr, "%02x", log_data->log_page_guid[j]);
				fprintf(stderr, "\n");

				ret = -1;
				goto out;
			}
		}
		ocp_c3_log(dev, log_data, fmt);
	} else {
		fprintf(stderr, "ERROR : OCP : Unable to read C3 data from buffer\n");
	}

out:
	free(data);
	return ret;
}

static int ocp_latency_monitor_log(int argc, char **argv,
				   struct command *command,
				   struct plugin *plugin)
{
	const char *desc = "Retrieve latency monitor log data.";
	struct nvme_dev *dev;
	int ret = 0;

	struct config {
		char *output_format;
	};

	struct config cfg = {
		.output_format = "normal",
	};

	OPT_ARGS(opts) = {
		OPT_FMT("output-format", 'o', &cfg.output_format,
			"output Format: normal|json"),
		OPT_END()
	};

	ret = parse_and_open(&dev, argc, argv, desc, opts);
	if (ret)
		return ret;

	ret = get_c3_log_page(dev, cfg.output_format);
	if (ret)
		fprintf(stderr,
			"ERROR : OCP : Failure reading the C3 Log Page, ret = %d\n",
			ret);

	dev_close(dev);
	return ret;
}

int ocp_set_latency_monitor_feature(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	int err = -1;
	struct nvme_dev *dev;
	__u32 result;
	struct feature_latency_monitor buf = { 0 };
	__u32  nsid = NVME_NSID_ALL;
	struct stat nvme_stat;
	struct nvme_id_ctrl ctrl;

	const char *desc = "Set Latency Monitor feature.";
	const char *active_bucket_timer_threshold = "This is the value that loads the Active Bucket Timer Threshold.";
	const char *active_threshold_a = "This is the value that loads into the Active Threshold A.";
	const char *active_threshold_b = "This is the value that loads into the Active Threshold B.";
	const char *active_threshold_c = "This is the value that loads into the Active Threshold C.";
	const char *active_threshold_d = "This is the value that loads into the Active Threshold D.";
	const char *active_latency_config = "This is the value that loads into the Active Latency Configuration.";
	const char *active_latency_minimum_window = "This is the value that loads into the Active Latency Minimum Window.";
	const char *debug_log_trigger_enable = "This is the value that loads into the Debug Log Trigger Enable.";
	const char *discard_debug_log = "Discard Debug Log.";
	const char *latency_monitor_feature_enable = "Latency Monitor Feature Enable.";

	struct config {
		__u16 active_bucket_timer_threshold;
		__u8 active_threshold_a;
		__u8 active_threshold_b;
		__u8 active_threshold_c;
		__u8 active_threshold_d;
		__u16 active_latency_config;
		__u8 active_latency_minimum_window;
		__u16 debug_log_trigger_enable;
		__u8 discard_debug_log;
		__u8 latency_monitor_feature_enable;
	};

	struct config cfg = {
		.active_bucket_timer_threshold = 0x7E0,
		.active_threshold_a = 0x5,
		.active_threshold_b = 0x13,
		.active_threshold_c = 0x1E,
		.active_threshold_d = 0x2E,
		.active_latency_config = 0xFFF,
		.active_latency_minimum_window = 0xA,
		.debug_log_trigger_enable = 0,
		.discard_debug_log = 0,
		.latency_monitor_feature_enable = 0x1,
	};

	OPT_ARGS(opts) = {
		OPT_UINT("active_bucket_timer_threshold", 't', &cfg.active_bucket_timer_threshold, active_bucket_timer_threshold),
		OPT_UINT("active_threshold_a", 'a', &cfg.active_threshold_a, active_threshold_a),
		OPT_UINT("active_threshold_b", 'b', &cfg.active_threshold_b, active_threshold_b),
		OPT_UINT("active_threshold_c", 'c', &cfg.active_threshold_c, active_threshold_c),
		OPT_UINT("active_threshold_d", 'd', &cfg.active_threshold_d, active_threshold_d),
		OPT_UINT("active_latency_config", 'f', &cfg.active_latency_config, active_latency_config),
		OPT_UINT("active_latency_minimum_window", 'w', &cfg.active_latency_minimum_window, active_latency_minimum_window),
		OPT_UINT("debug_log_trigger_enable", 'r', &cfg.debug_log_trigger_enable, debug_log_trigger_enable),
		OPT_UINT("discard_debug_log", 'l', &cfg.discard_debug_log, discard_debug_log),
		OPT_UINT("latency_monitor_feature_enable", 'e', &cfg.latency_monitor_feature_enable, latency_monitor_feature_enable),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	err = fstat(dev_fd(dev), &nvme_stat);
	if (err < 0)
		return err;

	if (S_ISBLK(nvme_stat.st_mode)) {
		err = nvme_get_nsid(dev_fd(dev), &nsid);
		if (err < 0) {
			perror("invalid-namespace-id");
			return err;
		}
	}

	err = nvme_identify_ctrl(dev_fd(dev), &ctrl);
	if (err)
		return err;

	buf.active_bucket_timer_threshold = cpu_to_le16(cfg.active_bucket_timer_threshold);
	buf.active_threshold_a = cfg.active_threshold_a;
	buf.active_threshold_b = cfg.active_threshold_b;
	buf.active_threshold_c = cfg.active_threshold_c;
	buf.active_threshold_d = cfg.active_threshold_d;
	buf.active_latency_config = cpu_to_le16(cfg.active_latency_config);
	buf.active_latency_minimum_window = cfg.active_latency_minimum_window;
	buf.debug_log_trigger_enable = cpu_to_le16(cfg.debug_log_trigger_enable);
	buf.discard_debug_log = cfg.discard_debug_log;
	buf.latency_monitor_feature_enable = cfg.latency_monitor_feature_enable;

	struct nvme_set_features_args args = {
		.args_size = sizeof(args),
		.fd = dev_fd(dev),
		.fid = OCP_FID_LM,
		.nsid = 0,
		.cdw12 = 0,
		.save = 1,
		.data_len = sizeof(struct feature_latency_monitor),
		.data = (void *)&buf,
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.result = &result,
	};

	err = nvme_set_features(&args);
	if (err < 0) {
		perror("set-feature");
	} else if (!err) {
		printf("NVME_FEAT_OCP_LATENCY_MONITOR: 0x%02x\n", OCP_FID_LM);
		printf("active bucket timer threshold: 0x%x\n",
		       le16_to_cpu(buf.active_bucket_timer_threshold));
		printf("active threshold a: 0x%x\n", buf.active_threshold_a);
		printf("active threshold b: 0x%x\n", buf.active_threshold_b);
		printf("active threshold c: 0x%x\n", buf.active_threshold_c);
		printf("active threshold d: 0x%x\n", buf.active_threshold_d);
		printf("active latency config: 0x%x\n", le16_to_cpu(buf.active_latency_config));
		printf("active latency minimum window: 0x%x\n", buf.active_latency_minimum_window);
		printf("debug log trigger enable: 0x%x\n",
		       le16_to_cpu(buf.debug_log_trigger_enable));
		printf("discard debug log: 0x%x\n", buf.discard_debug_log);
		printf("latency monitor feature enable: 0x%x\n", buf.latency_monitor_feature_enable);
	} else if (err > 0) {
		fprintf(stderr, "NVMe Status:%s(%x)\n", nvme_status_to_string(err, false), err);
	}

	return err;
}

static int ocp_get_latency_monitor_feature(int argc, char **argv, struct command *cmd,
					   struct plugin *plugin)
{
	const char *desc = "Define Issue Get Feature command (FID: 0xC5) Latency Monitor";
	const char *sel = "[0-3]: current/default/saved/supported/";
	const char *nsid = "Byte[04-07]: Namespace Identifier Valid/Invalid/Inactive";

	_cleanup_nvme_dev_ struct nvme_dev *dev = NULL;

	__u32 result;
	int err;
	bool uuid;
	__u8 uuid_index = 0;

	struct config {
		__u8 sel;
		__u32 nsid;
	};

	struct config cfg = {
		.sel = 0,
		.nsid = 0,
	};

	OPT_ARGS(opts) = {
		OPT_BYTE("sel", 's', &cfg.sel, sel),
		OPT_UINT("namespace-id", 'n', &cfg.nsid, nsid),
		OPT_FLAG("no-uuid", 'u', NULL, no_uuid),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	uuid = !argconfig_parse_seen(opts, "no-uuid");

	if (uuid) {
		/* OCP 2.0 requires UUID index support */
		err = ocp_get_uuid_index(dev, &uuid_index);
		if (err || !uuid_index) {
			nvme_show_error("ERROR: No OCP UUID index found");
			return err;
		}
	}

	struct nvme_get_features_args args = {
		.args_size  = sizeof(args),
		.fd         = dev_fd(dev),
		.fid        = OCP_FID_LM,
		.nsid       = cfg.nsid,
		.sel        = cfg.sel,
		.cdw11      = 0,
		.uuidx      = uuid_index,
		.data_len   = 0,
		.data       = NULL,
		.timeout    = NVME_DEFAULT_IOCTL_TIMEOUT,
		.result     = &result,
	};

	err = nvme_get_features(&args);
	if (!err) {
		printf("get-feature:0xC5 %s value: %#08x\n",
		nvme_select_to_string(cfg.sel), result);

		if (cfg.sel == NVME_GET_FEATURES_SEL_SUPPORTED)
			nvme_show_select_result(0xC5, result);
	} else {
		nvme_show_error("Could not get feature: 0xC5");
	}

	return err;
}

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
/// EOL/PLP Failure Mode

static const char *eol_plp_failure_mode_to_string(__u8 mode)
{
	switch (mode) {
	case 1:
		return "Read only mode (ROM)";
	case 2:
		return "Write through mode (WTM)";
	case 3:
		return "Normal mode";
	default:
		break;
	}

	return "Reserved";
}

static int eol_plp_failure_mode_get(struct nvme_dev *dev, const __u32 nsid, const __u8 fid,
				    __u8 sel, bool uuid)
{
	__u32 result;
	int err;

	struct nvme_get_features_args args = {
		.args_size	= sizeof(args),
		.fd		= dev_fd(dev),
		.fid		= fid,
		.nsid		= nsid,
		.sel		= sel,
		.cdw11		= 0,
		.uuidx		= 0,
		.data_len	= 0,
		.data		= NULL,
		.timeout	= NVME_DEFAULT_IOCTL_TIMEOUT,
		.result		= &result,
	};

	if (uuid) {
		/* OCP 2.0 requires UUID index support */
		err = ocp_get_uuid_index(dev, &args.uuidx);
		if (err || !args.uuidx) {
			nvme_show_error("ERROR: No OCP UUID index found");
			return err;
		}
	}

	err = nvme_get_features(&args);
	if (!err) {
		nvme_show_result("End of Life Behavior (feature: %#0*x): %#0*x (%s: %s)",
				 fid ? 4 : 2, fid, result ? 10 : 8, result,
				 nvme_select_to_string(sel),
				 eol_plp_failure_mode_to_string(result));
		if (sel == NVME_GET_FEATURES_SEL_SUPPORTED)
			nvme_show_select_result(fid, result);
	} else {
		nvme_show_error("Could not get feature: %#0*x.", fid ? 4 : 2, fid);
	}

	return err;
}

static int eol_plp_failure_mode_set(struct nvme_dev *dev, const __u32 nsid,
				    const __u8 fid, __u8 mode, bool save,
				    bool uuid)
{
	__u32 result;
	int err;
	__u8 uuid_index = 0;

	if (uuid) {
		/* OCP 2.0 requires UUID index support */
		err = ocp_get_uuid_index(dev, &uuid_index);
		if (err || !uuid_index) {
			nvme_show_error("ERROR: No OCP UUID index found");
			return err;
		}
	}

	struct nvme_set_features_args args = {
		.args_size = sizeof(args),
		.fd = dev_fd(dev),
		.fid = fid,
		.nsid = nsid,
		.cdw11 = mode << 30,
		.cdw12 = 0,
		.save = save,
		.uuidx = uuid_index,
		.cdw15 = 0,
		.data_len = 0,
		.data = NULL,
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.result = &result,
	};

	err = nvme_set_features(&args);
	if (err > 0) {
		nvme_show_status(err);
	} else if (err < 0) {
		nvme_show_perror("Define EOL/PLP failure mode");
		fprintf(stderr, "Command failed while parsing.\n");
	} else {
		nvme_show_result("Successfully set mode (feature: %#0*x): %#0*x (%s: %s).",
				 fid ? 4 : 2, fid, mode ? 10 : 8, mode,
				 save ? "Save" : "Not save",
				 eol_plp_failure_mode_to_string(mode));
	}

	return err;
}

static int eol_plp_failure_mode(int argc, char **argv, struct command *cmd,
				struct plugin *plugin)
{
	const char *desc = "Define EOL or PLP circuitry failure mode.\n"
			   "No argument prints current mode.";
	const char *mode = "[0-3]: default/rom/wtm/normal";
	const __u32 nsid = 0;
	const __u8 fid = OCP_FID_ROWTM;
	struct nvme_dev *dev;
	int err;

	struct config {
		__u8 mode;
		bool save;
		__u8 sel;
	};

	struct config cfg = {
		.mode = 0,
		.save = false,
		.sel = 0,
	};

	NVME_ARGS(opts,
		  OPT_BYTE("mode", 'm', &cfg.mode, mode),
		  OPT_FLAG("save", 's', &cfg.save, save),
		  OPT_BYTE("sel", 'S', &cfg.sel, sel),
		  OPT_FLAG("no-uuid", 'n', NULL, no_uuid));

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	if (argconfig_parse_seen(opts, "mode"))
		err = eol_plp_failure_mode_set(dev, nsid, fid, cfg.mode,
					       cfg.save,
					       !argconfig_parse_seen(opts, "no-uuid"));
	else
		err = eol_plp_failure_mode_get(dev, nsid, fid, cfg.sel,
					       !argconfig_parse_seen(opts, "no-uuid"));

	dev_close(dev);

	return err;
}

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
/// Telemetry Log
//global buffers
static __le64 total_log_page_sz;
static __u8 *header_data;
static struct telemetry_str_log_format *log_data;

__u8 *ptelemetry_buffer;
__u8 *pstring_buffer;
__u8 *pC9_string_buffer;

static void get_serial_number(struct nvme_id_ctrl *ctrl, char *sn)
{
	int i;

	/* Remove trailing spaces from the name */
	for (i = 0; i < sizeof(ctrl->sn); i++) {
		if (ctrl->sn[i] == ' ')
			break;
		sn[i] = ctrl->sn[i];
	}
}

static void print_telemetry_header(struct telemetry_initiated_log *logheader, int tele_type)
{
	if (logheader) {
		unsigned int i = 0, j = 0;
		__u8 dataGenNum;

		if (tele_type == TELEMETRY_TYPE_HOST) {
			printf("============ Telemetry Host Header ============\n");
			dataGenNum = logheader->DataHostGenerationNumber;
		} else {
			printf("========= Telemetry Controller Header =========\n");
			dataGenNum = logheader->DataCtlrGenerationNumber;
		}

		printf("Log Identifier         : 0x%02X\n", logheader->LogIdentifier);
		printf("IEEE                   : 0x%02X%02X%02X\n",
			logheader->IEEE[0], logheader->IEEE[1], logheader->IEEE[2]);
		printf("Data Area 1 Last Block : 0x%04X\n",
			le16_to_cpu(logheader->DataArea1LastBlock));
		printf("Data Area 2 Last Block : 0x%04X\n",
			le16_to_cpu(logheader->DataArea2LastBlock));
		printf("Data Area 3 Last Block : 0x%04X\n",
			le16_to_cpu(logheader->DataArea3LastBlock));
		printf("Data Available         : 0x%02X\n",
			logheader->CtlrDataAvailable);
		printf("Data Generation Number : 0x%02X\n",
			dataGenNum);
		printf("Reason Identifier      :\n");

		for (i = 0; i < 8; i++) {
			for (j = 0; j < 16; j++)
				printf("%02X ",	logheader->ReasonIdentifier[127 - ((i * 16) + j)]);
			printf("\n");
		}
		printf("===============================================\n\n");
	}
}

static int get_telemetry_data(struct nvme_dev *dev, __u32 ns, __u8 tele_type,
							  __u32 data_len, void *data, __u8 nLSP, __u8 nRAE,
							  __u64 offset)
{
	struct nvme_passthru_cmd cmd = {
		.opcode = nvme_admin_get_log_page,
		.nsid = ns,
		.addr = (__u64)(uintptr_t) data,
		.data_len = data_len,
	};
	__u32 numd = (data_len >> 2) - 1;
	__u16 numdu = numd >> 16;
	__u16 numdl = numd & 0xffff;

	cmd.cdw10 = tele_type | (nLSP & 0x0F) << 8 | (nRAE & 0x01) << 15 | (numdl & 0xFFFF) << 16;
	cmd.cdw11 = numdu;
	cmd.cdw12 = (__u32)(0x00000000FFFFFFFF & offset);
	cmd.cdw13 = (__u32)((0xFFFFFFFF00000000 & offset) >> 8);
	cmd.cdw14 = 0;
	return nvme_submit_admin_passthru(dev_fd(dev), &cmd, NULL);
}

static void print_telemetry_data_area_1(struct telemetry_data_area_1 *da1,
										int tele_type)
{
	if (da1) {
		int i = 0;

		if (tele_type == TELEMETRY_TYPE_HOST)
			printf("============ Telemetry Host Data area 1 ============\n");
		else
			printf("========= Telemetry Controller Data area 1 =========\n");
		printf("Major Version     : 0x%x\n", le16_to_cpu(da1->major_version));
		printf("Minor Version     : 0x%x\n", le16_to_cpu(da1->minor_version));
		printf("Timestamp         : %"PRIu64"\n", le64_to_cpu(da1->timestamp));
		printf("Log Page GUID     : 0x");
		for (int j = 15; j >= 0; j--)
			printf("%02x", da1->log_page_guid[j]);
		printf("\n");
		printf("Number Telemetry Profiles Supported   : 0x%x\n",
				da1->no_of_tps_supp);
		printf("Telemetry Profile Selected (TPS)      : 0x%x\n",
				da1->tps);
		printf("Telemetry String Log Size (SLS)       : 0x%"PRIx64"\n",
		       le64_to_cpu(da1->sls));
		printf("Firmware Revision                     : ");
		for (i = 0; i < 8; i++)
			printf("%c", (char)da1->fw_revision[i]);
		printf("\n");
		printf("Data Area 1 Statistic Start           : 0x%"PRIx64"\n",
				le64_to_cpu(da1->da1_stat_start));
		printf("Data Area 1 Statistic Size            : 0x%"PRIx64"\n",
				le64_to_cpu(da1->da1_stat_size));
		printf("Data Area 2 Statistic Start           : 0x%"PRIx64"\n",
				le64_to_cpu(da1->da2_stat_start));
		printf("Data Area 2 Statistic Size            : 0x%"PRIx64"\n",
				le64_to_cpu(da1->da2_stat_size));
		for (i = 0; i < 16; i++) {
			printf("Event FIFO %d Data Area                : 0x%x\n",
					i, da1->event_fifo_da[i]);
			printf("Event FIFO %d Start                    : 0x%"PRIx64"\n",
					i, le64_to_cpu(da1->event_fifos[i].start));
			printf("Event FIFO %d Size                     : 0x%"PRIx64"\n",
					i, le64_to_cpu(da1->event_fifos[i].size));
		}
		printf("SMART / Health Information     :\n");
		printf("0x");
		for (i = 0; i < 512; i++)
			printf("%02x", da1->smart_health_info[i]);
		printf("\n");

		printf("SMART / Health Information Extended     :\n");
		printf("0x");
		for (i = 0; i < 512; i++)
			printf("%02x", da1->smart_health_info_extended[i]);
		printf("\n");

		printf("===============================================\n\n");
	}
}

static void print_telemetry_da_stat(struct telemetry_stats_desc *da_stat, int tele_type,
				    __u16 buf_size, __u8 data_area)
{
	if (da_stat) {
		unsigned int i = 0;
		struct telemetry_stats_desc *next_da_stat = da_stat;

		if (tele_type == TELEMETRY_TYPE_HOST)
			printf("============ Telemetry Host Data Area %d Statistics ============\n",
			       data_area);
		else
			printf("========= Telemetry Controller Data Area %d Statistics =========\n",
			       data_area);
		while ((i + 8) < buf_size) {
			print_stats_desc(next_da_stat);
			i += 8 + ((next_da_stat->size) * 4);
			next_da_stat = (struct telemetry_stats_desc *)((void *)da_stat + i);

			if ((next_da_stat->id == 0) && (next_da_stat->size == 0))
				break;
		}
		printf("===============================================\n\n");
	}
}
static void print_telemetry_da_fifo(struct telemetry_event_desc *da_fifo,
		__u64 buf_size,
		int tele_type,
		int da,
		int index)
{
	if (da_fifo) {
		__u64 i = 0;
		struct telemetry_event_desc *next_da_fifo = da_fifo;

		if (tele_type == TELEMETRY_TYPE_HOST)
			printf("========= Telemetry Host Data area %d Event FIFO %d =========\n",
				da, index);
		else
			printf("====== Telemetry Controller Data area %d Event FIFO %d ======\n",
				da, index);

		while ((i + 4) < buf_size) {
			/* break if last entry  */
			if (next_da_fifo->class == 0)
				break;

			/* Print Event Data */
			print_telemetry_fifo_event(next_da_fifo->class, /* Event class type */
				next_da_fifo->id,                           /* Event ID         */
				next_da_fifo->size,                         /* Event data size  */
				(__u8 *)&next_da_fifo->data);               /* Event data       */

			i += (4 + (next_da_fifo->size * 4));
			next_da_fifo = (struct telemetry_event_desc *)((void *)da_fifo + i);
		}
		printf("===============================================\n\n");
	}
}
static int extract_dump_get_log(struct nvme_dev *dev, char *featurename, char *filename, char *sn,
				int dumpsize, int transfersize, __u32 nsid, __u8 log_id,
				__u8 lsp, __u64 offset, bool rae)
{
	int i = 0, err = 0;

	char *data = calloc(transfersize, sizeof(char));
	char filepath[FILE_NAME_SIZE] = {0,};
	int output = 0;
	int total_loop_cnt = dumpsize / transfersize;
	int last_xfer_size = dumpsize % transfersize;

	if (last_xfer_size)
		total_loop_cnt++;
	else
		last_xfer_size = transfersize;

	if (filename == 0)
		snprintf(filepath, FILE_NAME_SIZE, "%s_%s.bin", featurename, sn);
	else
		snprintf(filepath, FILE_NAME_SIZE, "%s%s_%s.bin", filename, featurename, sn);

	for (i = 0; i < total_loop_cnt; i++) {
		memset(data, 0, transfersize);

		struct nvme_get_log_args args = {
			.lpo = offset,
			.result = NULL,
			.log = (void *)data,
			.args_size = sizeof(args),
			.fd = dev_fd(dev),
			.lid = log_id,
			.len = transfersize,
			.nsid = nsid,
			.lsp = lsp,
			.uuidx = 0,
			.rae = rae,
			.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
			.csi = NVME_CSI_NVM,
			.ot = false,
		};

		err = nvme_get_log(&args);
		if (err) {
			if (i > 0)
				goto close_output;
			else
				goto end;
		}

		if (i != total_loop_cnt - 1) {
			if (!i) {
				output = open(filepath, O_WRONLY | O_CREAT | O_TRUNC, 0666);
				if (output < 0) {
					err = -13;
					goto end;
				}
			}
			if (write(output, data, transfersize) < 0) {
				err = -10;
				goto close_output;
			}
		} else {
			if (write(output, data, last_xfer_size) < 0) {
				err = -10;
				goto close_output;
			}
		}
		offset += transfersize;
		printf("%d%%\r", (i + 1) * 100 / total_loop_cnt);
	}
	printf("100%%\nThe log file was saved at \"%s\"\n", filepath);

close_output:
	close(output);

end:
	free(data);
	return err;
}

static int get_telemetry_dump(struct nvme_dev *dev, char *filename, char *sn,
			      enum TELEMETRY_TYPE tele_type, int data_area, bool header_print)
{
	__u32 err = 0, nsid = 0;
	__u64 da1_sz = 512, m_512_sz = 0, da1_off = 0, m_512_off = 0, diff = 0, temp_sz = 0,
		temp_ofst = 0;
	__u8 lsp = 0, rae = 0, flag = 0;
	__u8 data[TELEMETRY_HEADER_SIZE] = { 0 };
	unsigned int i = 0;
	char data1[TELEMETRY_DATA_SIZE] = { 0 };
	char *featurename = 0;
	struct telemetry_initiated_log *logheader = (struct telemetry_initiated_log *)data;
	struct telemetry_data_area_1 *da1 = (struct telemetry_data_area_1 *)data1;
	__u64 offset = 0, size = 0;
	char dumpname[FILE_NAME_SIZE] = { 0 };

	if (tele_type == TELEMETRY_TYPE_HOST_0) {
		featurename = "Host(0)";
		lsp = 0;
		rae = 0;
		tele_type = TELEMETRY_TYPE_HOST;
	} else if (tele_type == TELEMETRY_TYPE_HOST_1) {
		featurename = "Host(1)";
		lsp = 1;
		rae = 0;
		tele_type = TELEMETRY_TYPE_HOST;
	} else {
		featurename = "Controller";
		lsp = 0;
		rae = 1;
	}

	/* Get the telemetry header */
	err = get_telemetry_data(dev, nsid, tele_type, TELEMETRY_HEADER_SIZE, (void *)data, lsp,
				 rae, 0);
	if (err) {
		printf("get_telemetry_header failed, err: %d.\n", err);
		return err;
	}

	if (header_print)
		print_telemetry_header(logheader, tele_type);

	/* Get the telemetry data */
	err = get_telemetry_data(dev, nsid, tele_type, TELEMETRY_DATA_SIZE, (void *)data1, lsp,
				 rae, 512);
	if (err) {
		printf("get_telemetry_data failed for type: 0x%x, err: %d.\n", tele_type, err);
		return err;
	}

	print_telemetry_data_area_1(da1, tele_type);

	/* Print the Data Area 1 Stats */
	if (da1->da1_stat_size != 0) {
		diff = 0;
		da1_sz = le64_to_cpu(da1->da1_stat_size) * 4;
		m_512_sz = le64_to_cpu(da1->da1_stat_size) * 4;
		da1_off = le64_to_cpu(da1->da1_stat_start) * 4;
		m_512_off = le64_to_cpu(da1->da1_stat_start) * 4;
		temp_sz = le64_to_cpu(da1->da1_stat_size) * 4;
		temp_ofst = le64_to_cpu(da1->da1_stat_start) * 4;
		flag = 0;

		if ((da1_off % 512) > 0) {
			m_512_off = (da1_off / 512);
			da1_off = m_512_off * 512;
			diff = temp_ofst - da1_off;
			flag = 1;
		}

		if (da1_sz < 512) {
			da1_sz = 512;
		} else if ((da1_sz % 512) > 0) {
			if (flag == 0) {
				m_512_sz = (da1_sz / 512) + 1;
				da1_sz = m_512_sz * 512;
			} else {
				if (diff < 512)
					diff = 1;
				else
					diff = (diff / 512) * 512;

				m_512_sz = (da1_sz / 512) + 1 + diff + 1;
				da1_sz = m_512_sz * 512;
			}
		}

		char *da1_stat = calloc(da1_sz, sizeof(char));

		err = get_telemetry_data(dev, nsid, tele_type, da1_sz, (void *)da1_stat, lsp, rae,
					 da1_off);
		if (err) {
			printf("get_telemetry_data da1 stats failed, err: %d.\n", err);
			return err;
		}

		print_telemetry_da_stat((void *)(da1_stat + (temp_ofst - da1_off)), tele_type,
					le64_to_cpu(da1->da1_stat_size) * 4, 1);
	}

	/* Print the Data Area 1 Event FIFO's */
	for (i = 0; i < 16 ; i++) {
		if ((da1->event_fifo_da[i] == 1) && (da1->event_fifos[i].size != 0)) {
			diff = 0;
			da1_sz = le64_to_cpu(da1->event_fifos[i].size) * 4;
			m_512_sz = le64_to_cpu(da1->event_fifos[i].size) * 4;
			da1_off = le64_to_cpu(da1->event_fifos[i].start) * 4;
			m_512_off = le64_to_cpu(da1->event_fifos[i].start) * 4;
			temp_sz = le64_to_cpu(da1->event_fifos[i].size) * 4;
			temp_ofst = le64_to_cpu(da1->event_fifos[i].start) * 4;
			flag = 0;

			if ((da1_off % 512) > 0) {
				m_512_off = ((da1_off / 512));
				da1_off = m_512_off * 512;
				diff = temp_ofst - da1_off;
				flag = 1;
			}

			if (da1_sz < 512) {
				da1_sz = 512;
			} else if ((da1_sz % 512) > 0) {
				if (flag == 0) {
					m_512_sz = (da1_sz / 512) + 1;
					da1_sz = m_512_sz * 512;
				} else {
					if (diff < 512)
						diff = 1;
					else
						diff = (diff / 512) * 512;

					m_512_sz = (da1_sz / 512) + 1 + diff + 1;
					da1_sz = m_512_sz * 512;
				}
			}

			char *da1_fifo = calloc(da1_sz, sizeof(char));

			printf("Get DA 1 FIFO addr: %p, offset 0x%"PRIx64"\n", da1_fifo,
			       (uint64_t)da1_off);
			err = get_telemetry_data(dev, nsid, tele_type,
						 le64_to_cpu(da1->event_fifos[i].size) * 4,
						 (void *)da1_fifo, lsp, rae, da1_off);
			if (err) {
				printf("get_telemetry_data da1 event fifos failed, err: %d.\n",
				       err);
				return err;
			}
			print_telemetry_da_fifo((void *)(da1_fifo + (temp_ofst - da1_off)), temp_sz,
						tele_type, le64_to_cpu(da1->event_fifo_da[i]), i);
		}
	}

	/* Print the Data Area 2 Stats */
	if (da1->da2_stat_size != 0) {
		da1_off = le64_to_cpu(da1->da2_stat_start) * 4;
		temp_ofst = le64_to_cpu(da1->da2_stat_start) * 4;
		da1_sz = le64_to_cpu(da1->da2_stat_size) * 4;
		diff = 0;
		flag = 0;

		if (da1->da2_stat_start == 0) {
			da1_off = 512 + (le16_to_cpu(logheader->DataArea1LastBlock) * 512);
			temp_ofst = 512 + (le16_to_cpu(logheader->DataArea1LastBlock) * 512);
			if ((da1_off % 512) == 0) {
				m_512_off = ((da1_off) / 512);
				da1_off = m_512_off * 512;
				diff = temp_ofst - da1_off;
				flag = 1;
			}
		} else {
			if (((da1_off * 4) % 512) > 0) {
				m_512_off =  ((le64_to_cpu(da1->da2_stat_start) * 4) / 512);
				da1_off = m_512_off * 512;
				diff = (le64_to_cpu(da1->da2_stat_start) * 4) - da1_off;
				flag = 1;
			}
		}

		if (da1_sz < 512) {
			da1_sz = 512;
		} else if ((da1_sz % 512) > 0) {
			if (flag == 0) {
				m_512_sz = (le64_to_cpu(da1->da2_stat_size) / 512) + 1;
				da1_sz = m_512_sz * 512;
			} else {
				if (diff < 512)
					diff = 1;
				else
					diff = (diff / 512) * 512;
				m_512_sz =  (le64_to_cpu(da1->da2_stat_size) / 512) + 1 + diff + 1;
				da1_sz = m_512_sz * 512;
			}
		}

		char *da2_stat = calloc(da1_sz, sizeof(char));

		err = get_telemetry_data(dev, nsid, tele_type, da1_sz, (void *)da2_stat, lsp, rae,
					 da1_off);
		if (err) {
			printf("get_telemetry_data da2 stats failed, err: %d.\n", err);
			return err;
		}

		print_telemetry_da_stat((void *)(da2_stat + (temp_ofst - da1_off)), tele_type,
					le64_to_cpu(da1->da2_stat_size) * 4, 2);
	}

	/* Print the Data Area 2 Event FIFO's */
	for (i = 0; i < 16 ; i++) {
		if ((da1->event_fifo_da[i] == 2) && (da1->event_fifos[i].size != 0)) {
			diff = 0;
			da1_sz = le64_to_cpu(da1->event_fifos[i].size) * 4;
			m_512_sz = le64_to_cpu(da1->event_fifos[i].size) * 4;
			da1_off = le64_to_cpu(da1->event_fifos[i].start) * 4;
			m_512_off = le64_to_cpu(da1->event_fifos[i].start) * 4;
			temp_sz = le64_to_cpu(da1->event_fifos[i].size) * 4;
			temp_ofst = le64_to_cpu(da1->event_fifos[i].start) * 4;
			flag = 0;

			if ((da1_off % 512) > 0) {
				m_512_off = ((da1_off / 512));
				da1_off = m_512_off * 512;
				diff = temp_ofst - da1_off;
				flag = 1;
			}

			if (da1_sz < 512) {
				da1_sz = 512;
			} else if ((da1_sz % 512) > 0) {
				if (flag == 0) {
					m_512_sz = (da1_sz / 512) + 1;
					da1_sz = m_512_sz * 512;
				} else {
					if (diff < 512)
						diff = 1;
					else
						diff = (diff / 512) * 512;

					m_512_sz = (da1_sz / 512) + 1 + diff + 1;
					da1_sz = m_512_sz * 512;
				}
			}

			char *da1_fifo = calloc(da1_sz, sizeof(char));

			err = get_telemetry_data(dev, nsid, tele_type,
						 le64_to_cpu(da1->event_fifos[i].size) * 4,
						 (void *)da1_fifo, lsp, rae, da1_off);
			if (err) {
				printf("get_telemetry_data da2 event fifos failed, err: %d.\n",
				       err);
				return err;
			}
			print_telemetry_da_fifo((void *)(da1_fifo + (temp_ofst - da1_off)), temp_sz,
						tele_type, le64_to_cpu(da1->event_fifo_da[i]), i);
		}
	}

	printf("------------------------------FIFO End---------------------------\n");

	switch (data_area) {
	case 1:
		offset = TELEMETRY_HEADER_SIZE;
		size = le16_to_cpu(logheader->DataArea1LastBlock);
		break;
	case 2:
		offset = TELEMETRY_HEADER_SIZE +
			 (le16_to_cpu(logheader->DataArea1LastBlock) * TELEMETRY_BYTE_PER_BLOCK);
		size = le16_to_cpu(logheader->DataArea2LastBlock) -
		       le16_to_cpu(logheader->DataArea1LastBlock);
		break;
	case 3:
		offset = TELEMETRY_HEADER_SIZE +
			 (le16_to_cpu(logheader->DataArea2LastBlock) * TELEMETRY_BYTE_PER_BLOCK);
		size = le16_to_cpu(logheader->DataArea3LastBlock) -
		       le16_to_cpu(logheader->DataArea2LastBlock);
		break;
	default:
		break;
	}

	if (!size) {
		printf("Telemetry %s Area %d is empty.\n", featurename, data_area);
		return err;
	}

	snprintf(dumpname, FILE_NAME_SIZE, "Telemetry_%s_Area_%d", featurename, data_area);
	err = extract_dump_get_log(dev, dumpname, filename, sn, size * TELEMETRY_BYTE_PER_BLOCK,
				   TELEMETRY_TRANSFER_SIZE, nsid, tele_type, 0, offset, rae);

	return err;
}

static int get_telemetry_log_page_data(struct nvme_dev *dev, int tele_type)
{
	char file_path[PATH_MAX];
	void *telemetry_log;
	const size_t bs = 512;
	struct nvme_telemetry_log *hdr;
	size_t full_size, offset = bs;
	int err, fd;

	if ((tele_type == TELEMETRY_TYPE_HOST_0) || (tele_type == TELEMETRY_TYPE_HOST_1))
		tele_type = TELEMETRY_TYPE_HOST;

	int log_id = (tele_type == TELEMETRY_TYPE_HOST ? NVME_LOG_LID_TELEMETRY_HOST :
			NVME_LOG_LID_TELEMETRY_CTRL);

	hdr = malloc(bs);
	telemetry_log = malloc(bs);
	if (!hdr || !telemetry_log) {
		fprintf(stderr, "Failed to allocate %zu bytes for log: %s\n",
			bs, strerror(errno));
		err = -ENOMEM;
		goto exit_status;
	}
	memset(hdr, 0, bs);

	sprintf(file_path, DEFAULT_TELEMETRY_BIN);
	fd = open(file_path, O_WRONLY | O_CREAT | O_TRUNC, 0666);
	if (fd < 0) {
		fprintf(stderr, "Failed to open output file %s: %s!\n",
			file_path, strerror(errno));
		err = fd;
		goto exit_status;
	}

	struct nvme_get_log_args args = {
		.lpo = 0,
		.result = NULL,
		.log = hdr,
		.args_size = sizeof(args),
		.fd = dev_fd(dev),
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.lid = log_id,
		.len = bs,
		.nsid = NVME_NSID_ALL,
		.csi = NVME_CSI_NVM,
		.lsi = NVME_LOG_LSI_NONE,
		.lsp = NVME_LOG_TELEM_HOST_LSP_CREATE,
		.uuidx = NVME_UUID_NONE,
		.rae = true,
		.ot = false,
	};

	err = nvme_get_log(&args);
	if (err < 0)
		nvme_show_error("Failed to fetch the log from drive.\n");
	else if (err > 0) {
		nvme_show_status(err);
		nvme_show_error("Failed to fetch telemetry-header. Error:%d.\n", err);
		goto close_fd;
	}

	err = write(fd, (void *)hdr, bs);
	if (err != bs) {
		nvme_show_error("Failed to write data to file.\n");
		goto close_fd;
	}

	full_size = (le16_to_cpu(hdr->dalb3) * bs) + offset;

	while (offset != full_size) {
		args.log = telemetry_log;
		args.lpo = offset;
		args.lsp = NVME_LOG_LSP_NONE;
		err = nvme_get_log(&args);
		if (err < 0) {
			nvme_show_error("Failed to fetch the log from drive.\n");
			break;
		} else if (err > 0) {
			nvme_show_error("Failed to fetch telemetry-log.\n");
			nvme_show_status(err);
			break;
		}

		err = write(fd, (void *)telemetry_log, bs);
		if (err != bs) {
			nvme_show_error("Failed to write data to file.\n");
			break;
		}
		err = 0;
		offset += bs;
	}

close_fd:
	close(fd);
exit_status:
	free(hdr);
	free(telemetry_log);

	return err;
}

static int get_c9_log_page_data(struct nvme_dev *dev, int print_data, int save_bin)
{
	int ret = 0;
	__le64 stat_id_str_table_ofst = 0;
	__le64 event_str_table_ofst = 0;
	__le64 vu_event_str_table_ofst = 0;
	__le64 ascii_table_ofst = 0;
	char file_path[PATH_MAX];

	_cleanup_fd_ int fd = STDIN_FILENO;

	header_data = (__u8 *)malloc(sizeof(__u8) * C9_TELEMETRY_STR_LOG_LEN);
	if (!header_data) {
		fprintf(stderr, "ERROR : OCP : malloc : %s\n", strerror(errno));
		return -1;
	}
	memset(header_data, 0, sizeof(__u8) * C9_TELEMETRY_STR_LOG_LEN);

	ret = ocp_get_log_simple(dev, OCP_LID_TELSLG, C9_TELEMETRY_STR_LOG_LEN, header_data);

	if (!ret) {
		log_data = (struct telemetry_str_log_format *)header_data;
		if (print_data) {
			printf("Statistics Identifier String Table Size = %"PRIu64"\n",
			       le64_to_cpu(log_data->sitsz));
			printf("Event String Table Size = %"PRIu64"\n",
			       le64_to_cpu(log_data->estsz));
			printf("VU Event String Table Size = %"PRIu64"\n",
			       le64_to_cpu(log_data->vu_eve_st_sz));
			printf("ASCII Table Size = %"PRIu64"\n", le64_to_cpu(log_data->asctsz));
		}

		/* Calculating the offset for dynamic fields. */

		stat_id_str_table_ofst = log_data->sits * 4;
		event_str_table_ofst = log_data->ests * 4;
		vu_event_str_table_ofst = log_data->vu_eve_sts * 4;
		ascii_table_ofst = log_data->ascts * 4;
		total_log_page_sz = C9_TELEMETRY_STR_LOG_LEN +
		    (log_data->sitsz * 4) + (log_data->estsz * 4) +
		    (log_data->vu_eve_st_sz * 4) + (log_data->asctsz * 4);

		if (print_data) {
			printf("stat_id_str_table_ofst = %"PRIu64"\n",
			       le64_to_cpu(stat_id_str_table_ofst));
			printf("event_str_table_ofst = %"PRIu64"\n",
			       le64_to_cpu(event_str_table_ofst));
			printf("vu_event_str_table_ofst = %"PRIu64"\n",
			       le64_to_cpu(vu_event_str_table_ofst));
			printf("ascii_table_ofst = %"PRIu64"\n", le64_to_cpu(ascii_table_ofst));
			printf("total_log_page_sz = %"PRIu64"\n", le64_to_cpu(total_log_page_sz));
		}

		pC9_string_buffer = (__u8 *)malloc(sizeof(__u8) * total_log_page_sz);
		if (!pC9_string_buffer) {
			fprintf(stderr, "ERROR : OCP : malloc : %s\n", strerror(errno));
			return -1;
		}
		memset(pC9_string_buffer, 0, sizeof(__u8) * total_log_page_sz);

		ret = ocp_get_log_simple(dev, OCP_LID_TELSLG, total_log_page_sz, pC9_string_buffer);
	} else {
		fprintf(stderr, "ERROR : OCP : Unable to read C9 data.\n");
	}

	if (save_bin) {
		sprintf(file_path, DEFAULT_STRING_BIN);
		fd = open(file_path, O_WRONLY | O_CREAT | O_TRUNC, 0666);
		if (fd < 0) {
			fprintf(stderr, "Failed to open output file %s: %s!\n", file_path,
				strerror(errno));
			return fd;
		}

		ret = write(fd, (void *)pC9_string_buffer, total_log_page_sz);
		if (ret != total_log_page_sz)
			fprintf(stderr, "Failed to flush all data to file!\n");
	}

	return 0;
}

int parse_ocp_telemetry_log(struct ocp_telemetry_parse_options *options)
{
	int status = 0;
	long telemetry_buffer_size = 0;
	long string_buffer_size = 0;
	enum nvme_print_flags fmt;
	unsigned char log_id;

	if (options->telemetry_log) {
		if (strstr((const char *)options->telemetry_log, "bin")) {
			// Read the data from the telemetry binary file
			ptelemetry_buffer =
				read_binary_file(NULL, (const char *)options->telemetry_log,
						 &telemetry_buffer_size, 1);
			if (ptelemetry_buffer == NULL) {
				nvme_show_error("Failed to read telemetry-log.\n");
				return -1;
			}
		}
	} else {
		nvme_show_error("telemetry-log is empty.\n");
		return -1;
	}

	log_id = ptelemetry_buffer[0];
	if ((log_id != NVME_LOG_LID_TELEMETRY_HOST) && (log_id != NVME_LOG_LID_TELEMETRY_CTRL)) {
		nvme_show_error("Invalid LogPageId [0x%02X]\n", log_id);
		return -1;
	}

	if (options->string_log) {
		// Read the data from the string binary file
		if (strstr((const char *)options->string_log, "bin")) {
			pstring_buffer = read_binary_file(NULL, (const char *)options->string_log,
							  &string_buffer_size, 1);
			if (pstring_buffer == NULL) {
				nvme_show_error("Failed to read string-log.\n");
				return -1;
			}
		}
	} else {
		nvme_show_error("string-log is empty.\n");
		return -1;
	}

	status = validate_output_format(options->output_format, &fmt);
	if (status < 0) {
		nvme_show_error("Invalid output format\n");
		return status;
	}

	ocp_show_telemetry_log(options, fmt);

	return 0;
}

static int ocp_telemetry_log(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Retrieve and parse OCP Telemetry log.";
	const char *telemetry_log = "Telemetry log binary;\n 'host.bin' or 'controller.bin'";
	const char *string_log = "String log binary; 'C9.bin'";
	const char *output_file = "Output file name with path;\n"
			"e.g. '-o ./path/name'\n'-o ./path1/path2/';\n"
			"If requested path does not exist, the directory will be newly created.";
	const char *output_format = "output format normal|json";
	const char *data_area = "Telemetry Data Area; 1 or 2;\n"
			"e.g. '-a 1 for Data Area 1.'\n'-a 2 for Data Areas 1 and 2.';\n";
	const char *telemetry_type = "Telemetry Type; 'host', 'host0', 'host1' or 'controller'";

	struct nvme_dev *dev;
	int err = 0;
	__u32  nsid = NVME_NSID_ALL;
	struct stat nvme_stat;
	char sn[21] = {0,};
	struct nvme_id_ctrl ctrl;
	bool is_support_telemetry_controller;
	struct ocp_telemetry_parse_options opt;
	int tele_type = 0;
	int tele_area = 0;

	OPT_ARGS(opts) = {
		OPT_STR("telemetry-log", 'l', &opt.telemetry_log, telemetry_log),
		OPT_STR("string-log", 's', &opt.string_log, string_log),
		OPT_FILE("output-file", 'o', &opt.output_file, output_file),
		OPT_FMT("output-format", 'f', &opt.output_format, output_format),
		OPT_INT("data-area", 'a', &opt.data_area, data_area),
		OPT_STR("telemetry-type", 't', &opt.telemetry_type, telemetry_type),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	if (opt.telemetry_type == 0)
		opt.telemetry_type = "host";

	err = fstat(dev_fd(dev), &nvme_stat);
	if (err < 0)
		return err;

	if (S_ISBLK(nvme_stat.st_mode)) {
		err = nvme_get_nsid(dev_fd(dev), &nsid);
		if (err < 0)
			return err;
	}

	err = nvme_identify_ctrl(dev_fd(dev), &ctrl);
	if (err)
		return err;

	get_serial_number(&ctrl, sn);

	is_support_telemetry_controller = ((ctrl.lpa & 0x8) >> 3);

	if (!opt.data_area) {
		nvme_show_result("Missing data-area. Using default data area 1.\n");
		opt.data_area = DATA_AREA_1;//Default data area 1
	} else if (opt.data_area != 1 && opt.data_area != 2) {
		nvme_show_result("Invalid data-area specified. Please specify 1 or 2.\n");
		goto out;
	}

	tele_area = opt.data_area;

	if (opt.telemetry_type) {
		if (!strcmp(opt.telemetry_type, "host0"))
			tele_type = TELEMETRY_TYPE_HOST_0;
		else if (!strcmp(opt.telemetry_type, "host1"))
			tele_type = TELEMETRY_TYPE_HOST_1;
		else if (!strcmp(opt.telemetry_type, "host"))
			tele_type = TELEMETRY_TYPE_HOST;
		else if (!strcmp(opt.telemetry_type, "controller"))
			tele_type = TELEMETRY_TYPE_CONTROLLER;
		else {
			nvme_show_error(
			    "telemetry-type should be host, host0, host1 or controller.\n");
			goto out;
		}
	} else {
		tele_type = TELEMETRY_TYPE_HOST; //Default Type - Host
		opt.telemetry_type = "host";
		nvme_show_result("Missing telemetry-type. Using default - host.\n");
	}

	if (!opt.telemetry_log) {
		nvme_show_result("\nMissing telemetry-log. Fetching from drive...\n");
		err = get_telemetry_log_page_data(dev, tele_type);//Pull Telemetry log
		if (err) {
			nvme_show_error("Failed to fetch telemetry-log from the drive.\n");
			goto out;
		}
		nvme_show_result("telemetry.bin generated. Proceeding with next steps.\n");
		opt.telemetry_log = DEFAULT_TELEMETRY_BIN;
	}

	if (!opt.string_log) {
		nvme_show_result("Missing string-log. Fetching from drive...\n");
		err = get_c9_log_page_data(dev, 0, 1); //Pull String log
		if (err) {
			nvme_show_error("Failed to fetch string-log from the drive.\n");
			goto out;
		}
		nvme_show_result("string.bin generated. Proceeding with next steps.\n");
		opt.string_log = DEFAULT_STRING_BIN;
	}

	if (!opt.output_format) {
		nvme_show_result("Missing format. Using default format - JSON.\n");
		opt.output_format = DEFAULT_OUTPUT_FORMAT_JSON;
	}

	switch (tele_type) {
	case TELEMETRY_TYPE_HOST:
		printf("Extracting Telemetry Host Dump (Data Area %d)...\n", tele_area);
		err = parse_ocp_telemetry_log(&opt);
		if (err)
			nvme_show_result("Status:(%x)\n", err);
		break;
	case TELEMETRY_TYPE_CONTROLLER:
		printf("Extracting Telemetry Controller Dump (Data Area %d)...\n", tele_area);
		if (is_support_telemetry_controller == true) {
			err = parse_ocp_telemetry_log(&opt);
			if (err)
				nvme_show_result("Status:(%x)\n", err);
		}
		break;
	case TELEMETRY_TYPE_HOST_0:
	case TELEMETRY_TYPE_HOST_1:
	default:
		printf("Extracting Telemetry Host(%d) Dump (Data Area %d)...\n",
				(tele_type == TELEMETRY_TYPE_HOST_0) ? 0 : 1, tele_area);

		err = get_telemetry_dump(dev, opt.output_file, sn, tele_type, tele_area, true);
		if (err)
			fprintf(stderr, "NVMe Status: %s(%x)\n", nvme_status_to_string(err, false),
				err);
		break;
	}

	printf("ocp internal-log command completed.\n");
out:
	dev_close(dev);
	return err;
}

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
/// Unsupported Requirement Log Page (LID : C5h)

/* C5 Unsupported Requirement Log Page */
#define C5_UNSUPPORTED_REQS_LEN            4096

static __u8 unsupported_req_guid[GUID_LEN] = {
	0x2F, 0x72, 0x9C, 0x0E,
	0x99, 0x23, 0x2C, 0xBB,
	0x63, 0x48, 0x32, 0xD0,
	0xB7, 0x98, 0xBB, 0xC7
};

/* Function declaration for unsupported requirement log page (LID:C5h) */
static int ocp_unsupported_requirements_log(int argc, char **argv, struct command *cmd,
					    struct plugin *plugin);

static int get_c5_log_page(struct nvme_dev *dev, char *format)
{
	nvme_print_flags_t fmt;
	int ret;
	__u8 *data;
	int i;
	struct unsupported_requirement_log *log_data;
	int j;

	ret = validate_output_format(format, &fmt);
	if (ret < 0) {
		fprintf(stderr, "ERROR : OCP : invalid output format\n");
		return ret;
	}

	data = (__u8 *)malloc(sizeof(__u8) * C5_UNSUPPORTED_REQS_LEN);
	if (!data) {
		fprintf(stderr, "ERROR : OCP : malloc : %s\n", strerror(errno));
		return -1;
	}
	memset(data, 0, sizeof(__u8) * C5_UNSUPPORTED_REQS_LEN);

	ret = ocp_get_log_simple(dev, OCP_LID_URLP, C5_UNSUPPORTED_REQS_LEN, data);
	if (!ret) {
		log_data = (struct unsupported_requirement_log *)data;

		/*
		 * check log page guid
		 * Verify GUID matches
		 */
		for (i = 0; i < 16; i++) {
			if (unsupported_req_guid[i] != log_data->log_page_guid[i]) {
				fprintf(stderr, "ERROR : OCP : Unknown GUID in C5 Log Page data\n");
				fprintf(stderr, "ERROR : OCP : Expected GUID: 0x");
				for (j = 0; j < 16; j++)
					fprintf(stderr, "%02x", unsupported_req_guid[j]);
				fprintf(stderr, "\nERROR : OCP : Actual GUID: 0x");
				for (j = 0; j < 16; j++)
					fprintf(stderr, "%02x", log_data->log_page_guid[j]);
				fprintf(stderr, "\n");

				ret = -1;
				goto out;
			}
		}
		ocp_c5_log(dev, log_data, fmt);
	} else {
		fprintf(stderr, "ERROR : OCP : Unable to read C3 data from buffer\n");
	}

out:
	free(data);
	return ret;
}

static int ocp_unsupported_requirements_log(int argc, char **argv, struct command *cmd,
					    struct plugin *plugin)
{
	const char *desc = "Retrieve unsupported requirements log data.";
	struct nvme_dev *dev;
	int ret = 0;

	struct config {
		char *output_format;
	};

	struct config cfg = {
		.output_format = "normal",
	};

	OPT_ARGS(opts) = {
		OPT_FMT("output-format", 'o', &cfg.output_format, "output Format: normal|json"),
		OPT_END()
	};

	ret = parse_and_open(&dev, argc, argv, desc, opts);
	if (ret)
		return ret;

	ret = get_c5_log_page(dev, cfg.output_format);
	if (ret)
		fprintf(stderr, "ERROR : OCP : Failure reading the C5 Log Page, ret = %d\n", ret);

	dev_close(dev);
	return ret;
}

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
/// Error Recovery Log Page(0xC1)

#define C1_ERROR_RECOVERY_LOG_BUF_LEN       0x200

static __u8 error_recovery_guid[GUID_LEN] = {
	0x44, 0xd9, 0x31, 0x21,
	0xfe, 0x30, 0x34, 0xae,
	0xab, 0x4d, 0xfd, 0x3d,
	0xba, 0x83, 0x19, 0x5a
};

static int get_c1_log_page(struct nvme_dev *dev, char *format);
static int ocp_error_recovery_log(int argc, char **argv, struct command *cmd, struct plugin *plugin);

static int get_c1_log_page(struct nvme_dev *dev, char *format)
{
	struct ocp_error_recovery_log_page *log_data;
	nvme_print_flags_t fmt;
	int ret;
	__u8 *data;
	int i, j;

	ret = validate_output_format(format, &fmt);
	if (ret < 0) {
		fprintf(stderr, "ERROR : OCP : invalid output format\n");
		return ret;
	}

	data = (__u8 *)malloc(sizeof(__u8) * C1_ERROR_RECOVERY_LOG_BUF_LEN);
	if (!data) {
		fprintf(stderr, "ERROR : OCP : malloc : %s\n", strerror(errno));
		return -1;
	}
	memset(data, 0, sizeof(__u8) * C1_ERROR_RECOVERY_LOG_BUF_LEN);

	ret = ocp_get_log_simple(dev, OCP_LID_EREC, C1_ERROR_RECOVERY_LOG_BUF_LEN, data);

	if (!ret) {
		log_data = (struct ocp_error_recovery_log_page *)data;

		/*
		 * check log page guid
		 * Verify GUID matches
		 */
		for (i = 0; i < 16; i++) {
			if (error_recovery_guid[i] != log_data->log_page_guid[i]) {
				fprintf(stderr, "ERROR : OCP : Unknown GUID in C1 Log Page data\n");
				fprintf(stderr, "ERROR : OCP : Expected GUID: 0x");
				for (j = 0; j < 16; j++)
					fprintf(stderr, "%02x", error_recovery_guid[j]);
				fprintf(stderr, "\nERROR : OCP : Actual GUID: 0x");
				for (j = 0; j < 16; j++)
					fprintf(stderr, "%02x", log_data->log_page_guid[j]);
				fprintf(stderr, "\n");

				ret = -1;
				goto out;
			}
		}
		ocp_c1_log(log_data, fmt);
	} else {
		fprintf(stderr, "ERROR : OCP : Unable to read C1 data from buffer\n");
	}

out:
	free(data);
	return ret;
}

static int ocp_error_recovery_log(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Retrieve C1h Error Recovery Log data.";
	struct nvme_dev *dev;
	int ret = 0;

	struct config {
		char *output_format;
	};

	struct config cfg = {
		.output_format = "normal",
	};

	OPT_ARGS(opts) = {
		OPT_FMT("output-format", 'o', &cfg.output_format, "output Format: normal|json|binary"),
		OPT_END()
	};

	ret = parse_and_open(&dev, argc, argv, desc, opts);
	if (ret)
		return ret;

	ret = get_c1_log_page(dev, cfg.output_format);
	if (ret)
		fprintf(stderr, "ERROR : OCP : Failure reading the C1h Log Page, ret = %d\n", ret);
	dev_close(dev);
	return ret;
}

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
/// Device Capabilities (Log Identifier C4h) Requirements

#define C4_DEV_CAP_REQ_LEN			0x1000
static __u8 dev_cap_req_guid[GUID_LEN] = {
	0x97, 0x42, 0x05, 0x0d,
	0xd1, 0xe1, 0xc9, 0x98,
	0x5d, 0x49, 0x58, 0x4b,
	0x91, 0x3c, 0x05, 0xb7
};

static int get_c4_log_page(struct nvme_dev *dev, char *format);
static int ocp_device_capabilities_log(int argc, char **argv, struct command *cmd, struct plugin *plugin);

static int get_c4_log_page(struct nvme_dev *dev, char *format)
{
	struct ocp_device_capabilities_log_page *log_data;
	nvme_print_flags_t fmt;
	int ret;
	__u8 *data;
	int i, j;

	ret = validate_output_format(format, &fmt);
	if (ret < 0) {
		fprintf(stderr, "ERROR : OCP : invalid output format\n");
		return ret;
	}

	data = (__u8 *)malloc(sizeof(__u8) * C4_DEV_CAP_REQ_LEN);
	if (!data) {
		fprintf(stderr, "ERROR : OCP : malloc : %s\n", strerror(errno));
		return -1;
	}
	memset(data, 0, sizeof(__u8) * C4_DEV_CAP_REQ_LEN);

	ret = ocp_get_log_simple(dev, OCP_LID_DCLP, C4_DEV_CAP_REQ_LEN, data);

	if (!ret) {
		log_data = (struct ocp_device_capabilities_log_page *)data;

		/*
		 * check log page guid
		 * Verify GUID matches
		 */
		for (i = 0; i < 16; i++) {
			if (dev_cap_req_guid[i] != log_data->log_page_guid[i]) {
				fprintf(stderr, "ERROR : OCP : Unknown GUID in C4 Log Page data\n");
				fprintf(stderr, "ERROR : OCP : Expected GUID: 0x");
				for (j = 0; j < 16; j++)
					fprintf(stderr, "%02x", dev_cap_req_guid[j]);
				fprintf(stderr, "\nERROR : OCP : Actual GUID: 0x");
				for (j = 0; j < 16; j++)
					fprintf(stderr, "%02x", log_data->log_page_guid[j]);
				fprintf(stderr, "\n");

				ret = -1;
				goto out;
			}
		}
		ocp_c4_log(log_data, fmt);
	} else {
		fprintf(stderr, "ERROR : OCP : Unable to read C4 data from buffer\n");
	}

out:
	free(data);
	return ret;
}

static int ocp_device_capabilities_log(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Retrieve C4h Device Capabilities Log data.";
	struct nvme_dev *dev;
	int ret = 0;

	struct config {
		char *output_format;
	};

	struct config cfg = {
		.output_format = "normal",
	};

	OPT_ARGS(opts) = {
		OPT_FMT("output-format", 'o', &cfg.output_format, "output Format: normal|json|binary"),
		OPT_END()
	};

	ret = parse_and_open(&dev, argc, argv, desc, opts);
	if (ret)
		return ret;

	ret = get_c4_log_page(dev, cfg.output_format);
	if (ret)
		fprintf(stderr, "ERROR : OCP : Failure reading the C4h Log Page, ret = %d\n", ret);
	dev_close(dev);
	return ret;
}

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
/// Set Telemetry Profile (Feature Identifier C8h) Set Feature

static int ocp_set_telemetry_profile(struct nvme_dev *dev, __u8 tps)
{
	__u32 result;
	int err;
	__u8 uuid_index = 0;

	/* OCP 2.0 requires UUID index support */
	err = ocp_get_uuid_index(dev, &uuid_index);
	if (err || !uuid_index) {
		nvme_show_error("ERROR: No OCP UUID index found");
		return err;
	}

	struct nvme_set_features_args args = {
		.args_size = sizeof(args),
		.fd = dev_fd(dev),
		.fid = OCP_FID_TEL_CFG,
		.nsid = 0xFFFFFFFF,
		.cdw11 = tps,
		.cdw12 = 0,
		.save = true,
		.uuidx = uuid_index,
		.cdw15 = 0,
		.data_len = 0,
		.data = NULL,
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.result = &result,
	};

	err = nvme_set_features(&args);
	if (err > 0) {
		nvme_show_status(err);
	} else if (err < 0) {
		nvme_show_perror("Set Telemetry Profile");
		fprintf(stderr, "Command failed while parsing.\n");
	} else {
		printf("Successfully Set Telemetry Profile (feature: 0xC8) to below values\n");
		printf("Telemetry Profile Select: 0x%x\n", tps);
	}

	return err;
}

static int ocp_set_telemetry_profile_feature(int argc, char **argv, struct command *cmd,
					     struct plugin *plugin)
{
	const char *desc = "Set Telemetry Profile (Feature Identifier C8h) Set Feature.";
	const char *tps = "Telemetry Profile Select for device debug data collection";
	struct nvme_dev *dev;
	int err;

	struct config {
		__u8 tps;
	};

	struct config cfg = {
		.tps = 0,
	};

	OPT_ARGS(opts) = {
		OPT_BYTE("telemetry-profile-select", 't', &cfg.tps, tps),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	if (argconfig_parse_seen(opts, "telemetry-profile-select"))
		err = ocp_set_telemetry_profile(dev, cfg.tps);
	else
		nvme_show_error("Telemetry Profile Select is a required argument");

	dev_close(dev);

	return err;
}

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
/// DSSD Power State (Feature Identifier C8h) Get Feature
static int ocp_get_telemetry_profile_feature(int argc, char **argv, struct command *cmd,
					      struct plugin *plugin)
{
	const char *desc = "Define Issue Get Feature command (FID: 0xC8) Latency Monitor";
	const char *sel = "[0-3]: current/default/saved/supported/";
	const char *nsid = "Byte[04-07]: Namespace Identifier Valid/Invalid/Inactive";

	_cleanup_nvme_dev_ struct nvme_dev *dev = NULL;

	__u32 result;
	int err;
	bool uuid;
	__u8 uuid_index = 0;

	struct config {
		__u8 sel;
		__u32 nsid;
	};

	struct config cfg = {
		.sel = 0,
		.nsid = 0,
	};

	OPT_ARGS(opts) = {
		OPT_BYTE("sel", 's', &cfg.sel, sel),
		OPT_UINT("namespace-id", 'n', &cfg.nsid, nsid),
		OPT_FLAG("no-uuid", 'u', NULL, no_uuid),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	uuid = !argconfig_parse_seen(opts, "no-uuid");

	if (uuid) {
		/* OCP 2.0 requires UUID index support */
		err = ocp_get_uuid_index(dev, &uuid_index);
		if (err || !uuid_index) {
			nvme_show_error("ERROR: No OCP UUID index found");
			return err;
		}
	}

	struct nvme_get_features_args args = {
		.args_size  = sizeof(args),
		.fd         = dev_fd(dev),
		.fid        = OCP_FID_TEL_CFG,
		.nsid       = cfg.nsid,
		.sel        = cfg.sel,
		.cdw11      = 0,
		.uuidx      = uuid_index,
		.data_len   = 0,
		.data       = NULL,
		.timeout    = NVME_DEFAULT_IOCTL_TIMEOUT,
		.result     = &result,
	};

	err = nvme_get_features(&args);
	if (!err) {
		printf("get-feature:0xC8 %s value: %#08x\n",
		nvme_select_to_string(cfg.sel), result);

		if (cfg.sel == NVME_GET_FEATURES_SEL_SUPPORTED)
			nvme_show_select_result(0xC8, result);
	} else {
		nvme_show_error("Could not get feature: 0xC8");
	}

	return err;
}

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
/// DSSD Power State (Feature Identifier C7h) Set Feature

static int set_dssd_power_state(struct nvme_dev *dev, const __u32 nsid,
				const __u8 fid, __u8 power_state, bool save,
				bool uuid)
{
	__u32 result;
	int err;
	__u8 uuid_index = 0;

	if (uuid) {
		/* OCP 2.0 requires UUID index support */
		err = ocp_get_uuid_index(dev, &uuid_index);
		if (err || !uuid_index) {
			nvme_show_error("ERROR: No OCP UUID index found");
			return err;
		}
	}

	struct nvme_set_features_args args = {
		.args_size = sizeof(args),
		.fd = dev_fd(dev),
		.fid = fid,
		.nsid = nsid,
		.cdw11 = power_state,
		.cdw12 = 0,
		.save = save,
		.uuidx = uuid_index,
		.cdw15 = 0,
		.data_len = 0,
		.data = NULL,
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.result = &result,
	};

	err = nvme_set_features(&args);
	if (err > 0) {
		nvme_show_status(err);
	} else if (err < 0) {
		nvme_show_perror("Define DSSD Power State");
		fprintf(stderr, "Command failed while parsing.\n");
	} else {
		printf("Successfully set DSSD Power State (feature: 0xC7) to below values\n");
		printf("DSSD Power State: 0x%x\n", power_state);
		printf("Save bit Value: 0x%x\n", save);
	}

	return err;
}

static int set_dssd_power_state_feature(int argc, char **argv, struct command *cmd,
										struct plugin *plugin)
{
	const char *desc = "Define DSSD Power State (Feature Identifier C7h) Set Feature.";
	const char *power_state = "DSSD Power State to set in watts";
	const char *save = "Specifies that the controller shall save the attribute";
	const __u32 nsid = 0;
	struct nvme_dev *dev;
	int err;

	struct config {
		__u8 power_state;
		bool save;
	};

	struct config cfg = {
		.power_state = 0,
		.save = false,
	};

	OPT_ARGS(opts) = {
		OPT_BYTE("power-state", 'p', &cfg.power_state, power_state),
		OPT_FLAG("save", 's', &cfg.save, save),
		OPT_FLAG("no-uuid", 'n', NULL, no_uuid),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	if (argconfig_parse_seen(opts, "power-state"))
		err = set_dssd_power_state(dev, nsid, OCP_FID_DSSDPS, cfg.power_state, cfg.save,
					   !argconfig_parse_seen(opts, "no-uuid"));

	dev_close(dev);

	return err;
}

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
/// DSSD Power State (Feature Identifier C7h) Get Feature

static int get_dssd_power_state(struct nvme_dev *dev, const __u32 nsid,
				const __u8 fid, __u8 sel, bool uuid)
{
	__u32 result;
	int err;
	__u8 uuid_index = 0;

	if (uuid) {
		/* OCP 2.0 requires UUID index support */
		err = ocp_get_uuid_index(dev, &uuid_index);
		if (err || !uuid_index) {
			nvme_show_error("ERROR: No OCP UUID index found");
			return err;
		}
	}

	struct nvme_get_features_args args = {
		.args_size	= sizeof(args),
		.fd		= dev_fd(dev),
		.fid		= fid,
		.nsid		= nsid,
		.sel		= sel,
		.cdw11		= 0,
		.uuidx		= uuid_index,
		.data_len	= 0,
		.data		= NULL,
		.timeout	= NVME_DEFAULT_IOCTL_TIMEOUT,
		.result		= &result,
	};

	err = nvme_get_features(&args);
	if (!err) {
		printf("get-feature:0xC7 %s value: %#08x\n", nvme_select_to_string(sel), result);

		if (sel == NVME_GET_FEATURES_SEL_SUPPORTED)
			nvme_show_select_result(fid, result);
	} else {
		nvme_show_error("Could not get feature: 0xC7 with sel: %d\n", sel);
	}

	return err;
}

static int get_dssd_power_state_feature(int argc, char **argv, struct command *cmd,
										struct plugin *plugin)
{
	const char *desc = "Define DSSD Power State (Feature Identifier C7h) Get Feature.";
	const char *all = "Print out all 3 values at once - Current, Default, and Saved";
	const char *sel = "[0-3]: current/default/saved/supported/";
	const __u32 nsid = 0;
	const __u8 fid = OCP_FID_DSSDPS;
	struct nvme_dev *dev;
	int i, err;

	struct config {
		__u8 sel;
		bool all;
	};

	struct config cfg = {
		.sel = 0,
		.all = false,
	};

	OPT_ARGS(opts) = {
		OPT_BYTE("sel", 'S', &cfg.sel, sel),
		OPT_FLAG("all", 'a', NULL, all),
		OPT_FLAG("no-uuid", 'n', NULL, no_uuid),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	if (argconfig_parse_seen(opts, "all")) {
		for (i = 0; i < 3; i++) {
			err = get_dssd_power_state(dev, nsid, fid, i,
							!argconfig_parse_seen(opts, "no-uuid"));
			if (err)
				break;
		}
	} else if (argconfig_parse_seen(opts, "sel"))
		err = get_dssd_power_state(dev, nsid, fid, cfg.sel,
					       !argconfig_parse_seen(opts, "no-uuid"));
	else
		nvme_show_error("Required to have --sel as an argument, or pass the --all flag.");

	dev_close(dev);

	return err;
}

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
/// plp_health_check_interval

static int set_plp_health_check_interval(int argc, char **argv, struct command *cmd,
					 struct plugin *plugin)
{

	const char *desc = "Define Issue Set Feature command (FID : 0xC6) PLP Health Check Interval";
	const char *plp_health_interval = "[31:16]:PLP Health Check Interval";
	const char *save = "Specifies that the controller shall save the attribute";
	const __u32 nsid = 0;
	struct nvme_dev *dev;
	int err;
	__u32 result;
	__u8 uuid_index = 0;

	struct config {
		__le16 plp_health_interval;
		bool save;
	};

	struct config cfg = {
		.plp_health_interval = 0,
		.save = false,
	};

	OPT_ARGS(opts) = {
		OPT_BYTE("plp_health_interval", 'p', &cfg.plp_health_interval, plp_health_interval),
		OPT_FLAG("save", 's', &cfg.save, save),
		OPT_FLAG("no-uuid", 'n', NULL, no_uuid),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;


	if (!argconfig_parse_seen(opts, "no-uuid")) {
		/* OCP 2.0 requires UUID index support */
		err = ocp_get_uuid_index(dev, &uuid_index);
		if (err || !uuid_index) {
			printf("ERROR: No OCP UUID index found");
			return err;
		}
	}


	struct nvme_set_features_args args = {
		.args_size = sizeof(args),
		.fd = dev_fd(dev),
		.fid = OCP_FID_PLPI,
		.nsid = nsid,
		.cdw11 = cfg.plp_health_interval << 16,
		.cdw12 = 0,
		.save = cfg.save,
		.uuidx = uuid_index,
		.cdw15 = 0,
		.data_len = 0,
		.data = NULL,
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.result = &result,
	};

	err = nvme_set_features(&args);
	if (err > 0) {
		nvme_show_status(err);
	} else if (err < 0) {
		nvme_show_perror("Define PLP Health Check Interval");
		fprintf(stderr, "Command failed while parsing.\n");
	} else {
		printf("Successfully set the PLP Health Check Interval");
		printf("PLP Health Check Interval: 0x%x\n", cfg.plp_health_interval);
		printf("Save bit Value: 0x%x\n", cfg.save);
	}
	return err;
}

static int get_plp_health_check_interval(int argc, char **argv, struct command *cmd,
					 struct plugin *plugin)
{

	const char *desc = "Define Issue Get Feature command (FID : 0xC6) PLP Health Check Interval";
	const __u32 nsid = 0;
	const __u8 fid = 0xc6;
	struct nvme_dev *dev;
	__u32 result;
	int err;

	struct config {
		__u8 sel;
	};

	struct config cfg = {
		.sel = 0,
	};

	OPT_ARGS(opts) = {
		OPT_BYTE("sel", 'S', &cfg.sel, sel),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;


	struct nvme_get_features_args args = {
		.args_size  = sizeof(args),
		.fd         = dev_fd(dev),
		.fid        = OCP_FID_PLPI,
		.nsid       = nsid,
		.sel        = cfg.sel,
		.cdw11      = 0,
		.uuidx      = 0,
		.data_len   = 0,
		.data       = NULL,
		.timeout    = NVME_DEFAULT_IOCTL_TIMEOUT,
		.result     = &result,
	};

	err = nvme_get_features(&args);
	if (!err) {
		printf("get-feature:0xC6 %s value: %#08x\n", nvme_select_to_string(cfg.sel), result);

		if (cfg.sel == NVME_GET_FEATURES_SEL_SUPPORTED)
			nvme_show_select_result(fid, result);
	} else {
		nvme_show_error("Could not get feature: 0xC6");
	}

	return err;
}

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
/// dssd_async_event_config

static int set_dssd_async_event_config(int argc, char **argv, struct command *cmd,
				       struct plugin *plugin)
{

	const char *desc = "Issue Set Feature command (FID : 0xC9) DSSD Async Event Config";
	const char *epn = "[0]:Enable Panic Notices";
	const char *save = "Specifies that the controller shall save the attribute";
	const __u32 nsid = 0;
	struct nvme_dev *dev;
	int err;
	__u32 result;
	__u8 uuid_index = 0;

	struct config {
		bool epn;
		bool save;
	};

	struct config cfg = {
		.epn = false,
		.save = false,
	};

	OPT_ARGS(opts) = {
		OPT_FLAG("enable-panic-notices", 'e', &cfg.epn, epn),
		OPT_FLAG("save", 's', &cfg.save, save),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	/* OCP 2.0 requires UUID index support */
	err = ocp_get_uuid_index(dev, &uuid_index);
	if (err || !uuid_index) {
		printf("ERROR: No OCP UUID index found\n");
		return err;
	}

	struct nvme_set_features_args args = {
		.args_size = sizeof(args),
		.fd = dev_fd(dev),
		.fid = OCP_FID_DAEC,
		.nsid = nsid,
		.cdw11 = cfg.epn ? 1 : 0,
		.cdw12 = 0,
		.save = cfg.save,
		.uuidx = uuid_index,
		.cdw15 = 0,
		.data_len = 0,
		.data = NULL,
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.result = &result,
	};

	err = nvme_set_features(&args);
	if (err > 0) {
		nvme_show_status(err);
	} else if (err < 0) {
		nvme_show_perror("Set DSSD Asynchronous Event Configuration\n");
		fprintf(stderr, "Command failed while parsing.\n");
	} else {
		printf("Successfully set the DSSD Asynchronous Event Configuration\n");
		printf("Enable Panic Notices bit Value: 0x%x\n", cfg.epn);
		printf("Save bit Value: 0x%x\n", cfg.save);
	}
	return err;
}

static int get_dssd_async_event_config(int argc, char **argv, struct command *cmd,
				       struct plugin *plugin)
{

	const char *desc = "Issue Get Feature command (FID : 0xC9) DSSD Async Event Config";
	const char *sel = "[0-3]: current/default/saved/supported";
	const __u32 nsid = 0;
	const __u8 fid = OCP_FID_DAEC;
	struct nvme_dev *dev;
	__u32 result;
	int err;

	struct config {
		__u8 sel;
	};

	struct config cfg = {
		.sel = 0,
	};

	OPT_ARGS(opts) = {
		OPT_BYTE("sel", 'S', &cfg.sel, sel),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;


	struct nvme_get_features_args args = {
		.args_size  = sizeof(args),
		.fd         = dev_fd(dev),
		.fid        = fid,
		.nsid       = nsid,
		.sel        = cfg.sel,
		.cdw11      = 0,
		.uuidx      = 0,
		.data_len   = 0,
		.data       = NULL,
		.timeout    = NVME_DEFAULT_IOCTL_TIMEOUT,
		.result     = &result,
	};

	err = nvme_get_features(&args);
	if (!err) {
		printf("get-feature:0xC9 %s value: %#08x\n", nvme_select_to_string(cfg.sel), result);

		if (cfg.sel == NVME_GET_FEATURES_SEL_SUPPORTED)
			nvme_show_select_result(fid, result);
	} else {
		nvme_show_error("Could not get feature: 0xC9\n");
	}

	return err;
}

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
/// Telemetry String Log Format Log Page (LID : C9h)

/* Function declaration for Telemetry String Log Format (LID:C9h) */
static int ocp_telemetry_str_log_format(int argc, char **argv, struct command *cmd,
					struct plugin *plugin);

static int get_c9_log_page(struct nvme_dev *dev, char *format)
{
	int ret = 0;
	nvme_print_flags_t fmt;

	ret = validate_output_format(format, &fmt);
	if (ret < 0) {
		fprintf(stderr, "ERROR : OCP : invalid output format\n");
		return ret;
	}

	if (fmt == BINARY)
		ret = get_c9_log_page_data(dev, 0, 1);
	else
		ret = get_c9_log_page_data(dev, 0, 0);

	if (!ret) {
		ocp_c9_log(log_data, pC9_string_buffer, total_log_page_sz, fmt);
	} else {
		fprintf(stderr, "ERROR : OCP : Unable to read C9 data from buffer\n");
	}

	free(header_data);
	return ret;
}

static int ocp_telemetry_str_log_format(int argc, char **argv, struct command *cmd,
					struct plugin *plugin)
{
	struct nvme_dev *dev;
	int ret = 0;
	const char *desc = "Retrieve telemetry string log format";

	struct config {
		char *output_format;
	};

	struct config cfg = {
		.output_format = "normal",
	};

	OPT_ARGS(opts) = {
		OPT_FMT("output-format", 'o', &cfg.output_format,
				"output Format:normal|json|binary"),
		OPT_END()
	};

	ret = parse_and_open(&dev, argc, argv, desc, opts);
	if (ret)
		return ret;

	ret = get_c9_log_page(dev, cfg.output_format);
	if (ret)
		fprintf(stderr, "ERROR : OCP : Failure reading the C9 Log Page, ret = %d\n", ret);

	dev_close(dev);

	return ret;
}

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
/// TCG Configuration Log Page (LID : C7h)

/* C7 TCG Configuration Log Page */
#define C7_TCG_CONFIGURATION_LEN           512

static __u8 tcg_configuration_guid[GUID_LEN] = {
	0x06, 0x40, 0x24, 0xBD,
	0x7E, 0xE0, 0xE6, 0x83,
	0xC0, 0x47, 0x54, 0xFA,
	0x9D, 0x2A, 0xE0, 0x54
};

/* Function declaration for TCG Configuration log page (LID:C7h) */
static int ocp_tcg_configuration_log(int argc, char **argv, struct command *cmd,
					    struct plugin *plugin);

static int get_c7_log_page(struct nvme_dev *dev, char *format)
{
	nvme_print_flags_t fmt;
	int ret;
	__u8 *data;
	int i;
	struct tcg_configuration_log *log_data;
	int j;

	ret = validate_output_format(format, &fmt);
	if (ret < 0) {
		fprintf(stderr, "ERROR : OCP : invalid output format\n");
		return ret;
	}

	data = (__u8 *)malloc(sizeof(__u8) * C7_TCG_CONFIGURATION_LEN);
	if (!data) {
		fprintf(stderr, "ERROR : OCP : malloc : %s\n", strerror(errno));
		return -1;
	}
	memset(data, 0, sizeof(__u8) * C7_TCG_CONFIGURATION_LEN);

	ret = ocp_get_log_simple(dev, OCP_LID_TCGL, C7_TCG_CONFIGURATION_LEN, data);
	if (!ret) {
		log_data = (struct tcg_configuration_log *)data;

		/*
		 * check log page guid
		 * Verify GUID matches
		 */
		for (i = 0; i < 16; i++) {
			if (tcg_configuration_guid[i] != log_data->log_page_guid[i]) {
				fprintf(stderr, "ERROR : OCP : Unknown GUID in C7 Log Page data\n");
				fprintf(stderr, "ERROR : OCP : Expected GUID: 0x");
				for (j = 0; j < 16; j++)
					fprintf(stderr, "%02x", tcg_configuration_guid[j]);
				fprintf(stderr, "\nERROR : OCP : Actual GUID: 0x");
				for (j = 0; j < 16; j++)
					fprintf(stderr, "%02x", log_data->log_page_guid[j]);
				fprintf(stderr, "\n");

				ret = -1;
				goto out;
			}
		}
		ocp_c7_log(dev, log_data, fmt);
	} else {
		fprintf(stderr, "ERROR : OCP : Unable to read C7 data from buffer\n");
	}

out:
	free(data);
	return ret;
}

static int ocp_tcg_configuration_log(int argc, char **argv, struct command *cmd,
					    struct plugin *plugin)
{
	const char *desc = "Retrieve TCG Configuration Log Page Data";
	struct nvme_dev *dev;
	int ret = 0;

	struct config {
		char *output_format;
	};

	struct config cfg = {
		.output_format = "normal",
	};

	OPT_ARGS(opts) = {
		OPT_FMT("output-format", 'o', &cfg.output_format, "output Format: normal|json"),
		OPT_END()
	};

	ret = parse_and_open(&dev, argc, argv, desc, opts);
	if (ret)
		return ret;

	ret = get_c7_log_page(dev, cfg.output_format);
	if (ret)
		fprintf(stderr, "ERROR : OCP : Failure reading the C7 Log Page, ret = %d\n", ret);

	dev_close(dev);
	return ret;
}

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
/// Misc

static int clear_fw_update_history(int argc, char **argv,
				   struct command *cmd, struct plugin *plugin)
{
	return ocp_clear_fw_update_history(argc, argv, cmd, plugin);
}

static int smart_add_log(int argc, char **argv, struct command *cmd,
			 struct plugin *plugin)
{
	return ocp_smart_add_log(argc, argv, cmd, plugin);
}

static int clear_pcie_correctable_error_counters(int argc, char **argv, struct command *cmd,
						struct plugin *plugin)
{
	return ocp_clear_pcie_correctable_errors(argc, argv, cmd, plugin);
}

static int get_clear_pcie_correctable_error_counters(int argc, char **argv, struct command *cmd,
						      struct plugin *plugin)
{
	return get_ocp_error_counters(argc, argv, cmd, plugin);
}

static int fw_activation_history_log(int argc, char **argv, struct command *cmd,
				     struct plugin *plugin)
{
	return ocp_fw_activation_history_log(argc, argv, cmd, plugin);
}

static int error_injection_get(struct nvme_dev *dev, const __u8 sel, bool uuid)
{
	struct erri_get_cq_entry cq_entry;
	int err;
	int i;
	const __u8 fid = OCP_FID_ERRI;

	_cleanup_free_ struct erri_entry *entry = NULL;

	struct nvme_get_features_args args = {
		.result = (__u32 *)&cq_entry,
		.data = entry,
		.args_size = sizeof(args),
		.fd = dev_fd(dev),
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.sel = sel,
		.data_len = sizeof(*entry) * ERRI_ENTRIES_MAX,
		.fid = fid,
	};

	if (uuid) {
		/* OCP 2.0 requires UUID index support */
		err = ocp_get_uuid_index(dev, &args.uuidx);
		if (err || !args.uuidx) {
			nvme_show_error("ERROR: No OCP UUID index found");
			return err;
		}
	}

	entry = nvme_alloc(args.data_len);
	if (!entry) {
		nvme_show_error("malloc: %s", strerror(errno));
		return -errno;
	}

	err = nvme_cli_get_features(dev, &args);
	if (!err) {
		nvme_show_result("Number of Error Injecttions (feature: %#0*x): %#0*x (%s: %d)",
				 fid ? 4 : 2, fid, cq_entry.nume ? 10 : 8, cq_entry.nume,
				 nvme_select_to_string(sel), cq_entry.nume);
		if (sel == NVME_GET_FEATURES_SEL_SUPPORTED)
			nvme_show_select_result(fid, *args.result);
		for (i = 0; i < cq_entry.nume; i++) {
			printf("Entry: %d, Flags: %x (%s%s), Type: %x (%s), NRTDP: %d\n", i,
			       entry->flags, entry->enable ? "Enabled" : "Disabled",
			       entry->single ? ", Single instance" : "", entry->type,
			       erri_type_to_string(entry->type), entry->nrtdp);
		}
	} else {
		nvme_show_error("Could not get feature: %#0*x.", fid ? 4 : 2, fid);
	}

	return err;
}

static int get_error_injection(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Return set of error injection";
	int err;
	struct config {
		__u8 sel;
	};
	struct config cfg = { 0 };

	_cleanup_nvme_dev_ struct nvme_dev *dev = NULL;

	OPT_ARGS(opts) = {
		OPT_BYTE("sel", 's', &cfg.sel, sel),
		OPT_FLAG("no-uuid", 'n', NULL, no_uuid),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	return error_injection_get(dev, cfg.sel, !argconfig_parse_seen(opts, "no-uuid"));
}

static int error_injection_set(struct nvme_dev *dev, struct erri_config *cfg, bool uuid)
{
	int err;
	__u32 result;
	struct nvme_set_features_args args = {
		.args_size = sizeof(args),
		.fd = dev_fd(dev),
		.fid = OCP_FID_ERRI,
		.cdw11 = cfg->number,
		.data_len = cfg->number * sizeof(struct erri_entry),
		.timeout = nvme_cfg.timeout,
		.result = &result,
	};

	_cleanup_fd_ int ffd = -1;

	_cleanup_free_ struct erri_entry *entry = NULL;

	if (uuid) {
		/* OCP 2.0 requires UUID index support */
		err = ocp_get_uuid_index(dev, &args.uuidx);
		if (err || !args.uuidx) {
			nvme_show_error("ERROR: No OCP UUID index found");
			return err;
		}
	}

	entry = nvme_alloc(args.data_len);
	if (!entry) {
		nvme_show_error("malloc: %s", strerror(errno));
		return -errno;
	}

	if (cfg->file && strlen(cfg->file)) {
		ffd = open(cfg->file, O_RDONLY);
		if (ffd < 0) {
			nvme_show_error("Failed to open file %s: %s", cfg->file, strerror(errno));
			return -EINVAL;
		}
		err = read(ffd, entry, args.data_len);
		if (err < 0) {
			nvme_show_error("failed to read data buffer from input file: %s",
					strerror(errno));
			return -errno;
		}
	} else {
		entry->enable = 1;
		entry->single = 1;
		entry->type = cfg->type;
		entry->nrtdp = cfg->nrtdp;
	}

	args.data = entry;

	err = nvme_set_features(&args);
	if (err) {
		if (err < 0)
			nvme_show_error("set-error-injection: %s", nvme_strerror(errno));
		else if (err > 0)
			nvme_show_status(err);
		return err;
	}

	printf("set-error-injection, data: %s, number: %d, uuid: %d, type: %d, nrtdp: %d\n",
	       cfg->file, cfg->number, args.uuidx, cfg->type, cfg->nrtdp);
	if (args.data)
		d(args.data, args.data_len, 16, 1);

	return 0;
}

static int set_error_injection(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Inject error conditions";
	int err;
	struct erri_config cfg = {
		.number = 1,
	};

	_cleanup_nvme_dev_ struct nvme_dev *dev = NULL;

	NVME_ARGS(opts,
		  OPT_FILE("data", 'd', &cfg.file, data),
		  OPT_BYTE("number", 'n', &cfg.number, number),
		  OPT_FLAG("no-uuid", 'N', NULL, no_uuid),
		  OPT_SHRT("type", 't', &cfg.type, type),
		  OPT_SHRT("nrtdp", 'r', &cfg.nrtdp, nrtdp));

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	return error_injection_set(dev, &cfg, !argconfig_parse_seen(opts, "no-uuid"));
}

static int enable_ieee1667_silo_get(struct nvme_dev *dev, const __u8 sel, bool uuid)
{
	struct ieee1667_get_cq_entry cq_entry;
	int err;
	const __u8 fid = OCP_FID_1667;

	struct nvme_get_features_args args = {
		.result = (__u32 *)&cq_entry,
		.args_size = sizeof(args),
		.fd = dev_fd(dev),
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.sel = sel,
		.fid = fid,
	};

	if (uuid) {
		/* OCP 2.0 requires UUID index support */
		err = ocp_get_uuid_index(dev, &args.uuidx);
		if (err || !args.uuidx) {
			nvme_show_error("ERROR: No OCP UUID index found");
			return err;
		}
	}

	err = nvme_cli_get_features(dev, &args);
	if (!err) {
		if (sel == NVME_GET_FEATURES_SEL_SUPPORTED)
			nvme_show_select_result(fid, *args.result);
		else
			nvme_show_result("IEEE1667 Sifo Enabled (feature: 0x%02x): 0x%0x (%s: %s)",
					 fid, cq_entry.enabled, nvme_select_to_string(sel),
					 cq_entry.enabled ? "enabled" : "disabled");
	} else {
		nvme_show_error("Could not get feature: 0x%02x.", fid);
	}

	return err;
}

static int get_enable_ieee1667_silo(int argc, char **argv, struct command *cmd,
				    struct plugin *plugin)
{
	const char *desc = "return set of enable IEEE1667 silo";
	int err;
	struct config {
		__u8 sel;
	};
	struct config cfg = { 0 };

	_cleanup_nvme_dev_ struct nvme_dev *dev = NULL;

	OPT_ARGS(opts) = {
		OPT_BYTE("sel", 's', &cfg.sel, sel),
		OPT_FLAG("no-uuid", 'n', NULL, no_uuid),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	return enable_ieee1667_silo_get(dev, cfg.sel, !argconfig_parse_seen(opts, "no-uuid"));
}

static int enable_ieee1667_silo_set(struct nvme_dev *dev,
				    struct argconfig_commandline_options *opts)
{
	struct ieee1667_get_cq_entry cq_entry;
	int err;
	const __u8 fid = OCP_FID_1667;
	bool enable = argconfig_parse_seen(opts, "enable");

	struct nvme_set_features_args args = {
		.result = (__u32 *)&cq_entry,
		.args_size = sizeof(args),
		.fd = dev_fd(dev),
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.cdw11 = OCP_SET(enable, ENABLE_IEEE1667_SILO),
		.save = argconfig_parse_seen(opts, "save"),
		.fid = fid,
	};

	if (!argconfig_parse_seen(opts, "no-uuid")) {
		/* OCP 2.0 requires UUID index support */
		err = ocp_get_uuid_index(dev, &args.uuidx);
		if (err || !args.uuidx) {
			nvme_show_error("ERROR: No OCP UUID index found");
			return err;
		}
	}

	err = nvme_cli_set_features(dev, &args);
	if (err > 0) {
		nvme_show_status(err);
	} else if (err < 0) {
		nvme_show_perror(enable_ieee1667_silo);
		fprintf(stderr, "Command failed while parsing.\n");
	} else {
		enable = OCP_GET(args.cdw11, ENABLE_IEEE1667_SILO);
		nvme_show_result("Successfully set enable (feature: 0x%02x): %d (%s: %s).", fid,
				 enable, args.save ? "Save" : "Not save",
				 enable ? "Enabled" : "Disabled");
	}

	return err;
}

static int set_enable_ieee1667_silo(int argc, char **argv, struct command *cmd,
				    struct plugin *plugin)
{
	int err;

	_cleanup_nvme_dev_ struct nvme_dev *dev = NULL;

	OPT_ARGS(opts) = {
		OPT_FLAG("enable", 'e', NULL, no_uuid),
		OPT_FLAG("save", 's', NULL, save),
		OPT_FLAG("no-uuid", 'n', NULL, no_uuid),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, enable_ieee1667_silo, opts);
	if (err)
		return err;

	return enable_ieee1667_silo_set(dev, opts);
}

static int hwcomp_log(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	return ocp_hwcomp_log(argc, argv, cmd, plugin);
}
