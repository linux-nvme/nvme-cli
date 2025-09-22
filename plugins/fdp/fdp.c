// SPDX-License-Identifier: GPL-2.0-or-later

#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <inttypes.h>
#include <linux/fs.h>
#include <sys/stat.h>

#include "common.h"
#include "nvme.h"
#include "libnvme.h"
#include "nvme-print.h"

#define CREATE_CMD
#include "fdp.h"

static int fdp_configs(int argc, char **argv, struct command *acmd,
		       struct plugin *plugin)
{
	const char *desc = "Get Flexible Data Placement Configurations";
	const char *egid = "Endurance group identifier";
	const char *human_readable = "show log in readable format";
	const char *raw = "use binary output";

	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	_cleanup_free_ void *log = NULL;
	struct nvme_fdp_config_log hdr;
	nvme_print_flags_t flags;
	int err;

	struct config {
		__u16	egid;
		char	*output_format;
		bool	human_readable;
		bool	raw_binary;
	};

	struct config cfg = {
		.egid		= 0,
		.output_format	= "normal",
		.raw_binary	= false,
	};

	OPT_ARGS(opts) = {
		OPT_UINT("endgrp-id",      'e', &cfg.egid,           egid),
		OPT_FMT("output-format",   'o', &cfg.output_format,  output_format),
		OPT_FLAG("raw-binary",     'b', &cfg.raw_binary,     raw),
		OPT_FLAG("human-readable", 'H', &cfg.human_readable, human_readable),
		OPT_END()
	};

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(cfg.output_format, &flags);
	if (err < 0)
		return err;

	if (cfg.raw_binary)
		flags = BINARY;

	if (cfg.human_readable)
		flags |= VERBOSE;

	if (!cfg.egid) {
		fprintf(stderr, "endurance group identifier required\n");
		return -EINVAL;
	}

	err = nvme_get_log_fdp_configurations(hdl, cfg.egid, 0,
					      &hdr, sizeof(hdr));
	if (err) {
		nvme_show_status(errno);
		return err;
	}

	log = malloc(hdr.size);
	if (!log)
		return -ENOMEM;

	err = nvme_get_log_fdp_configurations(hdl, cfg.egid, 0, log, hdr.size);
	if (err) {
		nvme_show_status(errno);
		return err;
	}

	nvme_show_fdp_configs(log, hdr.size, flags);

	return 0;
}

static int fdp_usage(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Get Flexible Data Placement Reclaim Unit Handle Usage";
	const char *egid = "Endurance group identifier";
	const char *raw = "use binary output";

	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	_cleanup_free_ void *log = NULL;
	struct nvme_fdp_ruhu_log hdr;
	nvme_print_flags_t flags;
	size_t len;
	int err;

	struct config {
		__u16	egid;
		char	*output_format;
		bool	raw_binary;
	};

	struct config cfg = {
		.egid		= 0,
		.output_format	= "normal",
		.raw_binary	= false,
	};

	OPT_ARGS(opts) = {
		OPT_UINT("endgrp-id",    'e', &cfg.egid,          egid),
		OPT_FMT("output-format", 'o', &cfg.output_format, output_format),
		OPT_FLAG("raw-binary",   'b', &cfg.raw_binary,    raw),
		OPT_END()
	};

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(cfg.output_format, &flags);
	if (err < 0)
		return err;

	if (cfg.raw_binary)
		flags = BINARY;

	err = nvme_get_log_reclaim_unit_handle_usage(hdl, cfg.egid,
						     0, &hdr, sizeof(hdr));
	if (err) {
		nvme_show_status(err);
		return err;
	}

	len = sizeof(hdr) + le16_to_cpu(hdr.nruh) * sizeof(struct nvme_fdp_ruhu_desc);
	log = malloc(len);
	if (!log)
		return -ENOMEM;

	err = nvme_get_log_reclaim_unit_handle_usage(hdl, cfg.egid,
						     0, log, len);
	if (err) {
		nvme_show_status(err);
		return err;
	}

	nvme_show_fdp_usage(log, len, flags);

	return 0;
}

static int fdp_stats(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Get Flexible Data Placement Statistics";
	const char *egid = "Endurance group identifier";
	const char *raw = "use binary output";

	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	struct nvme_fdp_stats_log stats;
	nvme_print_flags_t flags;
	int err;

	struct config {
		__u16	egid;
		char	*output_format;
		bool	raw_binary;
	};

	struct config cfg = {
		.egid		= 0,
		.output_format	= "normal",
		.raw_binary	= false,
	};

	OPT_ARGS(opts) = {
		OPT_UINT("endgrp-id",    'e', &cfg.egid,          egid),
		OPT_FMT("output-format", 'o', &cfg.output_format, output_format),
		OPT_FLAG("raw-binary",   'b', &cfg.raw_binary,    raw),
		OPT_END()
	};

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(cfg.output_format, &flags);
	if (err < 0)
		return err;

	if (cfg.raw_binary)
		flags = BINARY;

	if (!cfg.egid) {
		fprintf(stderr, "endurance group identifier required\n");
		return -EINVAL;
	}

	memset(&stats, 0x0, sizeof(stats));

	err = nvme_get_log_fdp_stats(hdl, cfg.egid, 0, &stats, sizeof(stats));
	if (err) {
		nvme_show_status(err);
		return err;
	}

	nvme_show_fdp_stats(&stats, flags);

	return 0;
}

static int fdp_events(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Get Flexible Data Placement Events";
	const char *egid = "Endurance group identifier";
	const char *host_events = "Get host events";
	const char *raw = "use binary output";

	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	struct nvme_fdp_events_log events;
	nvme_print_flags_t flags;
	int err;

	struct config {
		__u16	egid;
		bool	host_events;
		char	*output_format;
		bool	raw_binary;
	};

	struct config cfg = {
		.egid		= 0,
		.host_events =	false,
		.output_format	= "normal",
		.raw_binary	= false,
	};

	OPT_ARGS(opts) = {
		OPT_UINT("endgrp-id",    'e', &cfg.egid,          egid),
		OPT_FLAG("host-events",  'E', &cfg.host_events,   host_events),
		OPT_FMT("output-format", 'o', &cfg.output_format, output_format),
		OPT_FLAG("raw-binary",   'b', &cfg.raw_binary,    raw),
		OPT_END()
	};

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(cfg.output_format, &flags);
	if (err < 0)
		return err;

	if (cfg.raw_binary)
		flags = BINARY;

	if (!cfg.egid) {
		fprintf(stderr, "endurance group identifier required\n");
		return -EINVAL;
	}

	memset(&events, 0x0, sizeof(events));

	err = nvme_get_log_fdp_events(hdl, cfg.egid,
			cfg.host_events, 0, &events, sizeof(events));
	if (err) {
		nvme_show_status(err);
		return err;
	}

	nvme_show_fdp_events(&events, flags);

	return 0;
}

static int fdp_status(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Reclaim Unit Handle Status";
	const char *namespace_id = "Namespace identifier";
	const char *raw = "use binary output";

	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	_cleanup_free_ void *buf = NULL;
	struct nvme_fdp_ruh_status hdr;
	nvme_print_flags_t flags;
	int err = -1;
	size_t len;

	struct config {
		__u32	namespace_id;
		char	*output_format;
		bool	raw_binary;
	};

	struct config cfg = {
		.output_format	= "normal",
		.raw_binary	= false,
	};

	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id", 'n', &cfg.namespace_id,  namespace_id),
		OPT_FMT("output-format", 'o', &cfg.output_format, output_format),
		OPT_FLAG("raw-binary",   'b', &cfg.raw_binary,    raw),
		OPT_END()
	};

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(cfg.output_format, &flags);
	if (err < 0)
		return err;

	if (cfg.raw_binary)
		flags = BINARY;

	if (!cfg.namespace_id) {
		err = nvme_get_nsid(hdl, &cfg.namespace_id);
		if (err < 0) {
			perror("get-namespace-id");
			return err;
		}
	}

	err = nvme_fdp_reclaim_unit_handle_status(hdl,
			cfg.namespace_id, sizeof(hdr), &hdr);
	if (err) {
		nvme_show_status(err);
		return err;
	}

	len = sizeof(struct nvme_fdp_ruh_status) +
		le16_to_cpu(hdr.nruhsd) * sizeof(struct nvme_fdp_ruh_status_desc);
	buf = malloc(len);
	if (!buf)
		return -ENOMEM;

	err = nvme_fdp_reclaim_unit_handle_status(hdl,
			cfg.namespace_id, len, buf);
	if (err) {
		nvme_show_status(err);
		return err;
	}

	nvme_show_fdp_ruh_status(buf, len, flags);

	return 0;
}

static int fdp_update(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Reclaim Unit Handle Update";
	const char *namespace_id = "Namespace identifier";
	const char *_pids = "Comma-separated list of placement identifiers to update";

	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	unsigned short pids[256];
	__u16 buf[256];
	int npids;
	int err = -1;

	struct config {
		__u32 namespace_id;
		char *pids;
	};

	struct config cfg = {
		.pids = "",
	};

	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id",  'n', &cfg.namespace_id,   namespace_id),
		OPT_LIST("pids",          'p', &cfg.pids,           _pids),
		OPT_END()
	};

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	npids = argconfig_parse_comma_sep_array_short(cfg.pids, pids, ARRAY_SIZE(pids));
	if (npids < 0) {
		perror("could not parse pids");
		return -EINVAL;
	} else if (npids == 0) {
		fprintf(stderr, "no placement identifiers set\n");
		return -EINVAL;
	}

	if (!cfg.namespace_id) {
		err = nvme_get_nsid(hdl, &cfg.namespace_id);
		if (err < 0) {
			perror("get-namespace-id");
			return err;
		}
	}

	for (unsigned int i = 0; i < npids; i++)
		buf[i] = cpu_to_le16(pids[i]);

	err = nvme_fdp_reclaim_unit_handle_update(hdl, cfg.namespace_id, npids, buf);
	if (err) {
		nvme_show_status(err);
		return err;
	}

	printf("update: Success\n");

	return 0;
}

static int fdp_set_events(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Enable or disable FDP events";
	const char *nsid = "Namespace identifier";
	const char *enable = "Enable/disable event";
	const char *event_types = "Comma-separated list of event types";
	const char *ph = "Placement Handle";
	const char *sv = "specifies that the controller shall save the attribute";

	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	unsigned short evts[255];
	__u8 buf[255];
	int err = -1;
	int nev;

	struct config {
		__u32	nsid;
		__u16	ph;
		char	*event_types;
		bool	enable;
		bool	sv;
	};

	struct config cfg = {
		.enable	= false,
		.sv	= false,
	};

	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id",     'n', &cfg.nsid,         nsid),
		OPT_SHRT("placement-handle", 'p', &cfg.ph,           ph),
		OPT_FLAG("enable",           'e', &cfg.enable,       enable),
		OPT_FLAG("save",             's', &cfg.sv,		     sv),
		OPT_LIST("event-types",      't', &cfg.event_types,  event_types),
		OPT_END()
	};

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	nev = argconfig_parse_comma_sep_array_short(cfg.event_types, evts, ARRAY_SIZE(evts));
	if (nev < 0) {
		perror("could not parse event types");
		return -EINVAL;
	} else if (nev == 0) {
		fprintf(stderr, "no event types set\n");
		return -EINVAL;
	} else if (nev > 255) {
		fprintf(stderr, "too many event types (max 255)\n");
		return -EINVAL;
	}

	if (!cfg.nsid) {
		err = nvme_get_nsid(hdl, &cfg.nsid);
		if (err < 0) {
			if (errno != ENOTTY) {
				fprintf(stderr, "get-namespace-id: %s\n", nvme_strerror(errno));
				return err;
			}

			cfg.nsid = NVME_NSID_ALL;
		}
	}

	for (unsigned int i = 0; i < nev; i++)
		buf[i] = (__u8)evts[i];

	err = nvme_set_features(hdl, cfg.nsid, NVME_FEAT_FID_FDP_EVENTS, cfg.sv,
			(nev << 16) | cfg.ph, cfg.enable ? 0x1 : 0x0,
			0, 0, 0, buf, sizeof(buf), NULL);
	if (err) {
		nvme_show_status(err);
		return err;;
	}

	printf("set-events: Success\n");

	return 0;
}

static int fdp_feature(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Show, enable or disable FDP configuration";
	const char *enable_conf_idx = "FDP configuration index to enable";
	const char *endurance_group = "Endurance group ID";
	const char *disable = "Disable current FDP configuration";

	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	bool enabling_conf_idx = false;
	__u32 result;
	int err = -1;

	struct config {
		bool disable;
		__u8 fdpcidx;
		__u16 endgid;
	};

	struct config cfg = {
		.disable = false,
		.fdpcidx = 0,
		.endgid = 0,
	};

	OPT_ARGS(opts) = {
		OPT_SHRT("endgrp-id", 'e', &cfg.endgid, endurance_group),
		OPT_BYTE("enable-conf-idx", 'c', &cfg.fdpcidx, enable_conf_idx),
		OPT_FLAG("disable", 'd', &cfg.disable, disable),
		OPT_INCR("verbose",      'v', &nvme_cfg.verbose, verbose),
		OPT_END()
	};

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	enabling_conf_idx = argconfig_parse_seen(opts, "enable-conf-idx");
	if (enabling_conf_idx && cfg.disable) {
		nvme_show_error("Cannot enable and disable at the same time");
		return -EINVAL;
	}

	if (!enabling_conf_idx && !cfg.disable) {
		nvme_show_result("Endurance Group                               : %d", cfg.endgid);

		err = nvme_get_features(hdl, NVME_NSID_ALL, NVME_FEAT_FID_FDP,
				NVME_GET_FEATURES_SEL_CURRENT, cfg.endgid, 0,
				NULL, 0, &result);
		if (err) {
			nvme_show_status(err);
			return err;
		}

		nvme_show_result("Flexible Direct Placement Enable (FDPE)       : %s",
				(result & 0x1) ? "Yes" : "No");
		nvme_show_result("Flexible Direct Placement Configuration Index : %u",
				(result >> 8) & 0xf);
		return err;
	}

	err = nvme_set_features(hdl, NVME_NSID_ALL, NVME_FEAT_FID_FDP, 1, cfg.endgid,
			cfg.fdpcidx << 8 | (!cfg.disable),
			0, 0, 0, NULL, 0, NULL);
	if (err) {
		nvme_show_status(err);
		return err;
	}
	nvme_show_result("Success %s Endurance Group: %d, FDP configuration index: %d",
	       (cfg.disable) ? "disabling" : "enabling", cfg.endgid, cfg.fdpcidx);
	return err;
}
