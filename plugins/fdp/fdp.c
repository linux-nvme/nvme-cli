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

static int fdp_configs(int argc, char **argv, struct command *cmd,
		struct plugin *plugin)
{
	const char *desc = "Get Flexible Data Placement Configurations";
	const char *egid = "Endurance group identifier";
	const char *human_readable = "show log in readable format";
	const char *raw = "use binary output";

	enum nvme_print_flags flags;
	struct nvme_dev *dev;
	struct nvme_fdp_config_log hdr;
	void *log = NULL;
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

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0)
		goto out;

	if (cfg.raw_binary)
		flags = BINARY;

	if (cfg.human_readable)
		flags |= VERBOSE;

	if (!cfg.egid) {
		fprintf(stderr, "endurance group identifier required\n");
		err = -EINVAL;
		goto out;
	}

	err = nvme_get_log_fdp_configurations(dev_fd(dev), cfg.egid, 0,
			sizeof(hdr), &hdr);
	if (err) {
		nvme_show_status(errno);
		goto out;
	}

	log = malloc(hdr.size);
	if (!log) {
		err = -ENOMEM;
		goto out;
	}

	err = nvme_get_log_fdp_configurations(dev_fd(dev), cfg.egid, 0,
			hdr.size, log);
	if (err) {
		nvme_show_status(errno);
		goto out;
	}

	nvme_show_fdp_configs(log, hdr.size, flags);

out:
	dev_close(dev);
	free(log);

	return err;
}

static int fdp_usage(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Get Flexible Data Placement Reclaim Unit Handle Usage";
	const char *egid = "Endurance group identifier";
	const char *raw = "use binary output";

	enum nvme_print_flags flags;
	struct nvme_dev *dev;
	struct nvme_fdp_ruhu_log hdr;
	size_t len;
	void *log = NULL;
	int err;

	struct config {
		__u16	egid;
		char	*output_format;
		bool	raw_binary;
	};

	struct config cfg = {
		.egid      = 0,
		.output_format	= "normal",
		.raw_binary	= false,
	};

	OPT_ARGS(opts) = {
		OPT_UINT("endgrp-id",    'e', &cfg.egid,          egid),
		OPT_FMT("output-format", 'o', &cfg.output_format, output_format),
		OPT_FLAG("raw-binary",   'b', &cfg.raw_binary,    raw),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0)
		goto out;

	if (cfg.raw_binary)
		flags = BINARY;

	err = nvme_get_log_reclaim_unit_handle_usage(dev_fd(dev), cfg.egid,
			0, sizeof(hdr), &hdr);
	if (err) {
		nvme_show_status(err);
		goto out;
	}

	len = sizeof(hdr) + le16_to_cpu(hdr.nruh) * sizeof(struct nvme_fdp_ruhu_desc);
	log = malloc(len);
	if (!log) {
		err = -ENOMEM;
		goto out;
	}

	err = nvme_get_log_reclaim_unit_handle_usage(dev_fd(dev), cfg.egid,
			0, len, log);
	if (err) {
		nvme_show_status(err);
		goto out;
	}

	nvme_show_fdp_usage(log, len, flags);

out:
	dev_close(dev);
	free(log);

	return err;
}

static int fdp_stats(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Get Flexible Data Placement Statistics";
	const char *egid = "Endurance group identifier";
	const char *raw = "use binary output";

	enum nvme_print_flags flags;
	struct nvme_dev *dev;
	struct nvme_fdp_stats_log stats;
	int err;

	struct config {
		__u16	egid;
		char	*output_format;
		bool	raw_binary;
	};

	struct config cfg = {
		.egid      = 0,
		.output_format	= "normal",
		.raw_binary	= false,
	};

	OPT_ARGS(opts) = {
		OPT_UINT("endgrp-id",    'e', &cfg.egid,          egid),
		OPT_FMT("output-format", 'o', &cfg.output_format, output_format),
		OPT_FLAG("raw-binary",   'b', &cfg.raw_binary,    raw),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0)
		goto out;

	if (cfg.raw_binary)
		flags = BINARY;

	memset(&stats, 0x0, sizeof(stats));

	err = nvme_get_log_fdp_stats(dev_fd(dev), cfg.egid, 0, sizeof(stats), &stats);
	if (err) {
		nvme_show_status(err);
		goto out;
	}

	nvme_show_fdp_stats(&stats, flags);

out:
	dev_close(dev);

	return err;
}

static int fdp_events(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Get Flexible Data Placement Events";
	const char *egid = "Endurance group identifier";
	const char *host_events = "Get host events";
	const char *raw = "use binary output";

	enum nvme_print_flags flags;
	struct nvme_dev *dev;
	struct nvme_fdp_events_log events;
	int err;

	struct config {
		__u16	egid;
		bool	host_events;
		char	*output_format;
		bool	raw_binary;
	};

	struct config cfg = {
		.egid      = 0,
		.host_events = false,
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

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0)
		goto out;

	if (cfg.raw_binary)
		flags = BINARY;

	memset(&events, 0x0, sizeof(events));

	err = nvme_get_log_fdp_events(dev_fd(dev), cfg.egid,
			cfg.host_events, 0, sizeof(events), &events);
	if (err) {
		nvme_show_status(err);
		goto out;
	}

	nvme_show_fdp_events(&events, flags);

out:
	dev_close(dev);

	return err;
}

static int fdp_status(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Reclaim Unit Handle Status";
	const char *namespace_id = "Namespace identifier";
	const char *raw = "use binary output";

	enum nvme_print_flags flags;
	struct nvme_dev *dev;
	struct nvme_fdp_ruh_status hdr;
	size_t len;
	void *buf = NULL;
	int err = -1;

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

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0)
		goto out;

	if (cfg.raw_binary)
		flags = BINARY;

	if (!cfg.namespace_id) {
		err = nvme_get_nsid(dev_fd(dev), &cfg.namespace_id);
		if (err < 0) {
			perror("get-namespace-id");
			goto out;
		}
	}

	err = nvme_fdp_reclaim_unit_handle_status(dev_fd(dev),
			cfg.namespace_id, sizeof(hdr), &hdr);
	if (err) {
		nvme_show_status(err);
		goto out;
	}

	len = sizeof(struct nvme_fdp_ruh_status) +
		le16_to_cpu(hdr.nruhsd) * sizeof(struct nvme_fdp_ruh_status_desc);
	buf = malloc(len);
	if (!buf) {
		err = -ENOMEM;
		goto out;
	}

	err = nvme_fdp_reclaim_unit_handle_status(dev_fd(dev),
			cfg.namespace_id, len, buf);
	if (err) {
		nvme_show_status(err);
		goto out;
	}

	nvme_show_fdp_ruh_status(buf, len, flags);

out:
	free(buf);
	dev_close(dev);

	return err;
}

static int fdp_update(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Reclaim Unit Handle Update";
	const char *namespace_id = "Namespace identifier";
	const char *_pids = "Comma-separated list of placement identifiers to update";

	struct nvme_dev *dev;
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

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	npids = argconfig_parse_comma_sep_array_short(cfg.pids, pids, ARRAY_SIZE(pids));
	if (npids < 0) {
		perror("could not parse pids");
		err = -EINVAL;
		goto out;
	} else if (npids == 0) {
		fprintf(stderr, "no placement identifiers set\n");
		err = -EINVAL;
		goto out;
	}

	if (!cfg.namespace_id) {
		err = nvme_get_nsid(dev_fd(dev), &cfg.namespace_id);
		if (err < 0) {
			perror("get-namespace-id");
			goto out;
		}
	}

	for (unsigned int i = 0; i < npids; i++) {
		buf[i] = cpu_to_le16(pids[i]);
	}

	err = nvme_fdp_reclaim_unit_handle_update(dev_fd(dev), cfg.namespace_id, npids, buf);
	if (err) {
		nvme_show_status(err);
		goto out;
	}

	printf("update: Success\n");

out:
	dev_close(dev);

	return err;
}

static int fdp_set_events(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Enable or disable FDP events";
	const char *namespace_id = "Namespace identifier";
	const char *enable = "Enable/disable event";
	const char *event_types = "Comma-separated list of event types";
	const char *ph = "Placement Handle";

	struct nvme_dev *dev;
	int err = -1;
	unsigned short evts[255];
	int nev;
	__u8 buf[255];

	struct config {
		__u32	namespace_id;
		__u16   ph;
		char    *event_types;
		bool    enable;
	};

	struct config cfg = {
		.enable = false,
	};

	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id",     'n', &cfg.namespace_id, namespace_id),
		OPT_SHRT("placement-handle", 'p', &cfg.ph,           ph),
		OPT_FLAG("enable",           'e', &cfg.enable,       enable),
		OPT_LIST("event-types",      't', &cfg.event_types,  event_types),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	nev = argconfig_parse_comma_sep_array_short(cfg.event_types, evts, ARRAY_SIZE(evts));
	if (nev < 0) {
		perror("could not parse event types");
		err = -EINVAL;
		goto out;
	} else if (nev == 0) {
		fprintf(stderr, "no event types set\n");
		err = -EINVAL;
		goto out;
	} else if (nev > 255) {
		fprintf(stderr, "too many event types (max 255)\n");
		err = -EINVAL;
		goto out;
	}

	if (!cfg.namespace_id) {
		err = nvme_get_nsid(dev_fd(dev), &cfg.namespace_id);
		if (err < 0) {
			if (errno != ENOTTY) {
				fprintf(stderr, "get-namespace-id: %s\n", nvme_strerror(errno));
				goto out;
			}

			cfg.namespace_id = NVME_NSID_ALL;
		}
	}

	for (unsigned int i = 0; i < nev; i++) {
		buf[i] = (__u8)evts[i];
	}

	struct nvme_set_features_args args = {
		.hnd            = dev_fd(dev),
		.args_size	= sizeof(args),
		.fid		= NVME_FEAT_FID_FDP_EVENTS,
		.nsid		= cfg.namespace_id,
		.cdw11		= (nev << 16) | cfg.ph,
		.cdw12		= cfg.enable ? 0x1 : 0x0,
		.data_len	= sizeof(buf),
		.data		= buf,
		.timeout	= NVME_DEFAULT_IOCTL_TIMEOUT,
		.result		= NULL,
	};

	err = nvme_set_features(&args);
	if (err) {
		nvme_show_status(err);
		goto out;
	}

	printf("set-events: Success\n");

out:
	dev_close(dev);

	return err;
}
