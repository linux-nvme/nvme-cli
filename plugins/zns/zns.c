// SPDX-License-Identifier: GPL-2.0-or-later
#include <asm-generic/errno-base.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/fs.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#include <libnvme.h>

#include <ccan/array_size/array_size.h>
#include <ccan/endian/endian.h>
#include <shared/compiler-attributes-util.h>
#include <shared/time-util.h>

#include "global-ctx.h"
#include "nvme-print.h"
#include "plugin.h"
#include "src/cleanup.h"

static const char *namespace_id = "Namespace identifier to use";

static int detect_zns(libnvme_ns_t ns, int *out_supported)
{
	int err = 0;
	char *zoned;

	*out_supported = 0;

	zoned = libnvme_get_attr(libnvme_ns_get_sysfs_dir(ns), "queue/zoned");
	if (!zoned) {
		*out_supported = 0;
		return err;
	}

	*out_supported = strcmp("host-managed", zoned) == 0;
	free(zoned);

	return err;
}

static int print_zns_list_ns(libnvme_ns_t ns, struct shr_table *t)
{
	int supported;
	int err = 0;

	err = detect_zns(ns, &supported);
	if (err) {
		nvme_show_perror("Failed to enumerate namespace");
		return err;
	}

	if (supported)
		nvme_show_list_item(ns, t);

	return err;
}

static int print_zns_list(struct libnvme_global_ctx *ctx, struct shr_table *t)
{
	int err = 0;
	libnvme_host_t h;
	libnvme_subsystem_t s;
	libnvme_ctrl_t c;
	libnvme_ns_t n;

	libnvme_for_each_host(ctx, h) {
		libnvme_for_each_subsystem(h, s) {
			libnvme_subsystem_for_each_ns(s, n) {
				err = print_zns_list_ns(n, t);
				if (err)
					return err;
			}

			libnvme_subsystem_for_each_ctrl(s, c) {
				libnvme_ctrl_for_each_ns(c, n) {
					err = print_zns_list_ns(n, t);
					if (err)
						return err;
				}
			}
		}
	}

	return err;
}

static int list(int argc, char **argv, struct command *acmd,
		struct plugin *plugin)
{
	const char *desc = "Retrieve basic information for all ZNS namespaces.";
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	int err;
	struct shr_table_column columns[] = {
		{ "Node", LEFT, 21 },
		{ "Generic", LEFT, 21 },
		{ "SN", LEFT, 20 },
		{ "Model", LEFT, 40 },
		{ "Namespace", LEFT, 10 },
		{ "Usage", LEFT, 26 },
		{ "Format", LEFT, 16 },
		{ "FW Rev", LEFT, 8 },
	};
	struct shr_table *t;

	NVME_ARGS_OUTPUT_FORMATS(opts, NORMAL, "Output format: normal");

	err = parse_args(argc, argv, desc, opts);
	if (err)
		return err;

	err = nvme_create_global_ctx(&ctx);
	if (err)
		return err;

	err = libnvme_scan_topology(ctx, NULL, NULL);
	if (err) {
		nvme_show_error("Failed to scan nvme subsystems");
		return err;
	}

	t = shr_table_init_with_columns(columns, ARRAY_SIZE(columns));
	if (!t) {
		nvme_show_error("Failed to allocate table");
		return -ENOMEM;
	}

	err = print_zns_list(ctx, t);

	shr_table_print(t);

	shr_table_free(t);

	return err;
}

static int id_ctrl(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Send a ZNS specific Identify Controller command to\n"
			   "the given device and report information about the specified\n"
			   "controller in various formats.";

	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	struct libnvme_passthru_cmd cmd;
	struct nvme_zns_id_ctrl ctrl;
	nvme_print_flags_t flags;
	int err = -1;

	NVME_ARGS(opts);

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return errno;

	err = validate_output_format(nvme_args.output_format, &flags);
	if (err < 0)
		return err;

	nvme_init_zns_identify_ctrl(&cmd, &ctrl);
	err = libnvme_exec_admin_passthru(hdl, &cmd);
	if (!err)
		nvme_show_zns_id_ctrl(&ctrl, flags);
	else
		nvme_show_err(err, "zns identify controller");

	return err;
}

static int id_ns(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Send a ZNS specific Identify Namespace command to\n"
			   "the given device and report information about the specified\n"
			   "namespace in varios formats.";
	const char *vendor_specific = "dump binary vendor fields";
	const char *human_readable = "show identify in readable format";

	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	nvme_print_flags_t flags;
	struct nvme_zns_id_ns ns;
	struct nvme_id_ns id_ns;
	struct libnvme_passthru_cmd cmd;
	int err = -1;

	struct config {
		__u32 namespace_id;
		bool human_readable;
		bool vendor_specific;
	};

	struct config cfg = { };

	NVME_ARGS(opts,
		OPT_UINT("namespace-id", 'n', &cfg.namespace_id,  namespace_id),
		OPT_FLAG("vendor-specific", 'V', &cfg.vendor_specific, vendor_specific),
		OPT_FLAG("human-readable", 'H', &cfg.human_readable, human_readable));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return errno;

	err = validate_output_format(nvme_args.output_format, &flags);
	if (err < 0)
		return err;
	if (cfg.vendor_specific)
		flags |= VS;
	if (cfg.human_readable)
		flags |= VERBOSE;

	if (!cfg.namespace_id) {
		err = libnvme_get_nsid(hdl, &cfg.namespace_id);
		if (err < 0) {
			nvme_show_err(err, "get-namespace-id");
			return err;
		}
	}

	nvme_init_identify_ns(&cmd, cfg.namespace_id, &id_ns);
	err = libnvme_exec_admin_passthru(hdl, &cmd);
	if (err) {
		nvme_show_status(err);
		return err;
	}

	nvme_init_zns_identify_ns(&cmd, cfg.namespace_id, &ns);
	err = libnvme_exec_admin_passthru(hdl, &cmd);
	if (!err)
		nvme_show_zns_id_ns(&ns, &id_ns, flags);
	else
		nvme_show_err(err, "zns identify namespace");

	return err;
}

static int zns_mgmt_send(int argc, char **argv, struct command *acmd, struct plugin *plugin,
	const char *desc, enum nvme_zns_send_action zsa)
{
	const char *zslba = "starting LBA of the zone for this command";
	const char *select_all = "send command to all zones";
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	struct libnvme_passthru_cmd cmd;
	int err, zcapc = 0;
	char *cmdstr;

	struct config {
		__u64	zslba;
		__u32	namespace_id;
		bool	select_all;
	};

	struct config cfg = {};

	NVME_ARGS(opts,
		OPT_UINT("namespace-id", 'n', &cfg.namespace_id,  namespace_id),
		OPT_SUFFIX("start-lba",  's', &cfg.zslba,         zslba),
		OPT_FLAG("select-all",   'a', &cfg.select_all,    select_all));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = asprintf(&cmdstr, "%s-%s", plugin->name, acmd->name);
	if (err < 0)
		return err;

	if (!cfg.namespace_id) {
		err = libnvme_get_nsid(hdl, &cfg.namespace_id);
		if (err < 0) {
			nvme_show_err(err, "get-namespace-id");
			goto free;
		}
	}

	nvme_init_zns_mgmt_send(&cmd, cfg.namespace_id, cfg.zslba, zsa,
				cfg.select_all, 0, 0, NULL, 0);
	err = libnvme_exec_admin_passthru(hdl, &cmd);
	if (!err) {
		if (zsa == NVME_ZNS_ZSA_RESET)
			zcapc = cmd.result & 0x1;

		nvme_show_verbose_result("%s: Success, action:%d zone:%"PRIx64" all:%d zcapc:%u nsid:%d",
			cmdstr, zsa, (uint64_t)cfg.zslba, (int)cfg.select_all,
			zcapc, cfg.namespace_id);
	} else {
		nvme_show_err(err, "%s", desc);
	}
free:
	free(cmdstr);
	return err;
}

static int get_zdes_bytes(struct libnvme_transport_handle *hdl, __u32 nsid)
{
	struct nvme_zns_id_ns ns;
	struct nvme_id_ns id_ns;
	struct libnvme_passthru_cmd cmd;
	__u8 lbaf;
	int err;

	nvme_init_identify_ns(&cmd, nsid, &id_ns);
	err = libnvme_exec_admin_passthru(hdl, &cmd);
	if (err) {
		nvme_show_err(err, "identify namespace");
		return -1;
	}

	nvme_init_zns_identify_ns(&cmd, nsid, &ns);
	err = libnvme_exec_admin_passthru(hdl, &cmd);
	if (err) {
		nvme_show_err(err, "zns identify namespace");
		return -1;
	}

	nvme_id_ns_flbas_to_lbaf_inuse(id_ns.flbas, &lbaf);
	return ns.lbafe[lbaf].zdes << 6;
}

static int zone_mgmt_send(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Zone Management Send";
	const char *zslba =
	    "starting LBA of the zone for this command(for flush action, last lba to flush)";
	const char *zsaso = "Zone Send Action Specific Option";
	const char *select_all = "send command to all zones";
	const char *zsa = "zone send action";
	const char *data_len = "buffer length if data required";
	const char *data = "optional file for data (default stdin)";

	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	int ffd = STDIN_FILENO, err = -1;
	struct libnvme_passthru_cmd cmd;
	__cleanup_libnvme_free void *buf = NULL;

	struct config {
		__u64	zslba;
		__u32	namespace_id;
		bool	zsaso;
		bool	select_all;
		__u8	zsa;
		int	data_len;
		char	*file;
	};

	struct config cfg = {};

	NVME_ARGS(opts,
		OPT_UINT("namespace-id", 'n', &cfg.namespace_id,  namespace_id),
		OPT_SUFFIX("start-lba",  's', &cfg.zslba,         zslba),
		OPT_FLAG("zsaso",        'O', &cfg.zsaso,         zsaso),
		OPT_FLAG("select-all",   'a', &cfg.select_all,    select_all),
		OPT_BYTE("zsa",          'z', &cfg.zsa,           zsa),
		OPT_UINT("data-len",     'l', &cfg.data_len,      data_len),
		OPT_FILE("data",         'd', &cfg.file,          data));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return errno;

	if (!cfg.namespace_id) {
		err = libnvme_get_nsid(hdl, &cfg.namespace_id);
		if (err < 0) {
			nvme_show_err(err, "get-namespace-id");
			return err;
		}
	}

	if (!cfg.zsa) {
		nvme_show_error("zone send action must be specified");
		return -EINVAL;
	}

	if (cfg.zsa == NVME_ZNS_ZSA_SET_DESC_EXT) {
		if (!cfg.data_len) {
			int data_len = get_zdes_bytes(hdl,
						      cfg.namespace_id);

			if (data_len == 0) {
				nvme_show_error("Zone Descriptor Extensions are not supported");
				return -EINVAL;
			} else if (data_len < 0) {
				return data_len;
			}
			cfg.data_len = data_len;
		}
		buf = libnvme_alloc(cfg.data_len);
		if (!buf) {
			nvme_show_error("can not allocate feature payload");
			return -ENOMEM;
		}

		if (cfg.file) {
			ffd = open(cfg.file, O_RDONLY);
			if (ffd < 0) {
				nvme_show_perror("%s", cfg.file);
				return -errno;
			}
		}

		err = read(ffd, (void *)buf, cfg.data_len);
		if (err < 0) {
			nvme_show_perror("read");
			goto close_ffd;
		}
	} else {
		if (cfg.file || cfg.data_len) {
			nvme_show_error("data, data_len only valid with set extended descriptor");
			return -EINVAL;
		}
	}

	nvme_init_zns_mgmt_send(&cmd, cfg.namespace_id, cfg.zslba, cfg.zsa,
				cfg.select_all, cfg.zsaso, 0, buf,
				cfg.data_len);
	err = libnvme_exec_admin_passthru(hdl, &cmd);
	if (!err)
		nvme_show_verbose_result("zone-mgmt-send: Success, action:%d zone:%"PRIx64" all:%d nsid:%d",
		       cfg.zsa, (uint64_t)cfg.zslba, (int)cfg.select_all, cfg.namespace_id);
	else
		nvme_show_err(err, "zns zone-mgmt-send");

close_ffd:
	if (cfg.file)
		close(ffd);
	return err;
}

static int close_zone(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Close zones\n";

	return zns_mgmt_send(argc, argv, acmd, plugin, desc, NVME_ZNS_ZSA_CLOSE);
}

static int finish_zone(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Finish zones\n";

	return zns_mgmt_send(argc, argv, acmd, plugin, desc, NVME_ZNS_ZSA_FINISH);
}

static int open_zone(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Open zones\n";
	const char *zslba = "starting LBA of the zone for this command";
	const char *zrwaa = "Allocate Zone Random Write Area to zone";
	const char *select_all = "send command to all zones";
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	struct libnvme_passthru_cmd cmd;
	int err;

	struct config {
		__u64	zslba;
		__u32	namespace_id;
		bool	zrwaa;
		bool	select_all;
	};

	struct config cfg = {
	};

	NVME_ARGS(opts,
		OPT_UINT("namespace-id", 'n', &cfg.namespace_id,  namespace_id),
		OPT_SUFFIX("start-lba",  's', &cfg.zslba,         zslba),
		OPT_FLAG("zrwaa",         'r', &cfg.zrwaa,          zrwaa),
		OPT_FLAG("select-all",   'a', &cfg.select_all,    select_all));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return errno;

	if (!cfg.namespace_id) {
		err = libnvme_get_nsid(hdl, &cfg.namespace_id);
		if (err < 0) {
			nvme_show_err(err, "get-namespace-id");
			return err;
		}
	}

	nvme_init_zns_mgmt_send(&cmd, cfg.namespace_id, cfg.zslba,
				NVME_ZNS_ZSA_OPEN, cfg.select_all, cfg.zrwaa, 0,
				NULL, 0);
	err = libnvme_exec_admin_passthru(hdl, &cmd);
	if (!err)
		nvme_show_verbose_result("zns-open-zone: Success zone slba:%"PRIx64" nsid:%d",
		       (uint64_t)cfg.zslba, cfg.namespace_id);
	else
		nvme_show_err(err, "zns open-zone");

	return err;
}

static int reset_zone(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Reset zones\n";

	return zns_mgmt_send(argc, argv, acmd, plugin, desc, NVME_ZNS_ZSA_RESET);
}

static int offline_zone(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Offline zones\n";

	return zns_mgmt_send(argc, argv, acmd, plugin, desc, NVME_ZNS_ZSA_OFFLINE);
}

static int set_zone_desc(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Set Zone Descriptor Extension\n";
	const char *zslba = "starting LBA of the zone for this command";
	const char *zrwaa = "Allocate Zone Random Write Area to zone";
	const char *data = "optional file for zone extension data (default stdin)";

	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	struct libnvme_passthru_cmd cmd;
	int ffd = STDIN_FILENO, err;
	void *buf = NULL;
	int data_len;

	struct config {
		__u64	zslba;
		bool	zrwaa;
		__u32	namespace_id;
		char   *file;
	};

	struct config cfg = {};

	NVME_ARGS(opts,
		OPT_UINT("namespace-id", 'n', &cfg.namespace_id,  namespace_id),
		OPT_SUFFIX("start-lba",  's', &cfg.zslba,         zslba),
		OPT_FLAG("zrwaa",        'r', &cfg.zrwaa,         zrwaa),
		OPT_FILE("data",         'd', &cfg.file,          data));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return errno;

	if (!cfg.namespace_id) {
		err = libnvme_get_nsid(hdl, &cfg.namespace_id);
		if (err < 0) {
			nvme_show_err(err, "get-namespace-id");
			return err;
		}
	}

	data_len = get_zdes_bytes(hdl, cfg.namespace_id);

	if (!data_len || data_len < 0) {
		nvme_show_error(
			"zone format does not provide descriptor extension");
		return -EINVAL;
	}

	buf = calloc(1, data_len);
	if (!buf) {
		nvme_show_perror("could not alloc memory for zone desc");
		return -ENOMEM;
	}

	if (cfg.file) {
		ffd = open(cfg.file, O_RDONLY);
		if (ffd < 0) {
			nvme_show_perror("%s", cfg.file);
			err = -1;
			goto free;
		}
	}

	err = read(ffd, (void *)buf, data_len);
	if (err < 0) {
		nvme_show_perror("read");
		goto close_ffd;
	}

	nvme_init_zns_mgmt_send(&cmd, cfg.namespace_id, cfg.zslba,
				NVME_ZNS_ZSA_SET_DESC_EXT, 0, cfg.zrwaa, 0, buf,
				data_len);
	err = libnvme_exec_admin_passthru(hdl, &cmd);
	if (!err)
		nvme_show_verbose_result("set-zone-desc: Success, zone:%"PRIx64" nsid:%d",
		       (uint64_t)cfg.zslba, cfg.namespace_id);
	else
		nvme_show_err(err, "zns set-zone-desc");
close_ffd:
	if (cfg.file)
		close(ffd);
free:
	free(buf);

	return err;
}


static int zrwa_flush_zone(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Flush Explicit ZRWA Range";
	const char *slba = "LBA to flush up to";
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	struct libnvme_passthru_cmd cmd;
	int err;

	struct config {
		__u64	lba;
		__u32	namespace_id;
	};

	struct config cfg = {};

	NVME_ARGS(opts,
		OPT_UINT("namespace-id", 'n', &cfg.namespace_id,  namespace_id),
		OPT_SUFFIX("lba",        'l', &cfg.lba,           slba));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return errno;

	if (!cfg.namespace_id) {
		err = libnvme_get_nsid(hdl, &cfg.namespace_id);
		if (err < 0) {
			nvme_show_err(err, "get-namespace-id");
			return err;
		}
	}

	nvme_init_zns_mgmt_send(&cmd, cfg.namespace_id, cfg.lba,
				NVME_ZNS_ZSA_ZRWA_FLUSH, 0, 0, 0, NULL, 0);
	err = libnvme_exec_admin_passthru(hdl, &cmd);
	if (!err)
		nvme_show_verbose_result("zrwa-flush-zone: Success, lba:%"PRIx64" nsid:%d",
		       (uint64_t)cfg.lba, cfg.namespace_id);
	else
		nvme_show_err(err, "zns zrwa-flush-zone");

	return err;
}

static int zone_mgmt_recv(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Zone Management Receive";
	const char *zslba = "starting LBA of the zone";
	const char *zra = "Zone Receive Action";
	const char *zrasf = "Zone Receive Action Specific Field(Reporting Options)";
	const char *partial = "Zone Receive Action Specific Features(Partial Report)";
	const char *data_len = "length of data in bytes";

	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	struct libnvme_passthru_cmd cmd;
	nvme_print_flags_t flags;
	void *data = NULL;
	int err = -1;

	struct config {
		__u64  zslba;
		__u32  namespace_id;
		__u8   zra;
		__u8   zrasf;
		bool   partial;
		__u32  data_len;
	};

	struct config cfg = { };

	NVME_ARGS(opts,
		OPT_UINT("namespace-id",  'n', &cfg.namespace_id,   namespace_id),
		OPT_SUFFIX("start-lba",   's', &cfg.zslba,          zslba),
		OPT_BYTE("zra",           'z', &cfg.zra,            zra),
		OPT_BYTE("zrasf",         'S', &cfg.zrasf,          zrasf),
		OPT_FLAG("partial",       'p', &cfg.partial,        partial),
		OPT_UINT("data-len",      'l', &cfg.data_len,       data_len));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return errno;

	err = validate_output_format(nvme_args.output_format, &flags);
	if (err < 0)
		return err;

	if (!cfg.namespace_id) {
		err = libnvme_get_nsid(hdl, &cfg.namespace_id);
		if (err < 0) {
			nvme_show_err(err, "get-namespace-id");
			return err;
		}
	}

	if (cfg.zra == NVME_ZNS_ZRA_REPORT_ZONES && !cfg.data_len) {
		nvme_show_error("error: data len is needed for NVME_ZRA_ZONE_REPORT");
		return -EINVAL;
	}
	if (cfg.data_len) {
		data = calloc(1, cfg.data_len);
		if (!data) {
			nvme_show_perror("could not alloc memory for zone mgmt receive data");
			return -ENOMEM;
		}
	}

	nvme_init_zns_mgmt_recv(&cmd, cfg.namespace_id, cfg.zslba, cfg.zra,
				cfg.zrasf, cfg.partial, data, cfg.data_len);
	err = libnvme_exec_admin_passthru(hdl, &cmd);
	if (!err)
		nvme_show_verbose_result("zone-mgmt-recv: Success, action:%d zone:%"PRIx64" nsid:%d",
		       cfg.zra, (uint64_t)cfg.zslba, cfg.namespace_id);
	else
		nvme_show_err(err, "zns zone-mgmt-recv");

	free(data);

	return err;
}

static int report_zones(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Retrieve the Report Zones data structure";
	const char *zslba = "starting LBA of the zone";
	const char *num_descs = "number of descriptors to retrieve (default: all of them)";
	const char *state = "state of zones to list";
	const char *ext = "set to use the extended report zones";
	const char *part = "set to use the partial report";
	const char *verbose = "show report zones verbosity";

	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_huge struct libnvme_mem_huge mh = { 0, };
	struct nvme_zone_report *report, *buff;
	struct libnvme_passthru_cmd cmd;
	nvme_print_flags_t flags;
	int zdes = 0, err = -1;
	__u32 report_size;

	unsigned int nr_zones_chunks = 1024,   /* 1024 entries * 64 bytes per entry = 64k byte transfer */
			nr_zones_retrieved = 0,
			nr_zones,
			log_len;
	__u64 offset;
	int total_nr_zones = 0;
	struct nvme_zns_id_ns id_zns;
	struct nvme_id_ns id_ns;
	uint8_t lbaf;
	__le64	zsze;
	struct json_object *zone_list = NULL;

	struct config {
		__u64 zslba;
		__u32 namespace_id;
		int   num_descs;
		int   state;
		bool  verbose;
		bool  extended;
		bool  partial;
	};

	struct config cfg = {
		.num_descs = -1,
	};

	NVME_ARGS(opts,
		OPT_UINT("namespace-id",  'n', &cfg.namespace_id,   namespace_id),
		OPT_SUFFIX("start-lba",   's', &cfg.zslba,          zslba),
		OPT_UINT("descs",         'd', &cfg.num_descs,      num_descs),
		OPT_UINT("state",         'S', &cfg.state,          state),
		OPT_FLAG("verbose",       'V', &cfg.verbose,        verbose),
		OPT_FLAG("extended",      'e', &cfg.extended,       ext),
		OPT_FLAG("partial",       'p', &cfg.partial,        part));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return errno;

	err = validate_output_format(nvme_args.output_format, &flags);
	if (err < 0)
		return err;
	if (cfg.verbose)
		flags |= VERBOSE;

	if (!cfg.namespace_id) {
		err = libnvme_get_nsid(hdl, &cfg.namespace_id);
		if (err < 0) {
			nvme_show_err(err, "get-namespace-id");
			return err;
		}
	}

	if (cfg.extended) {
		zdes = get_zdes_bytes(hdl, cfg.namespace_id);
		if (zdes < 0)
			return zdes;
	}

	nvme_init_identify_ns(&cmd, cfg.namespace_id, &id_ns);
	err = libnvme_exec_admin_passthru(hdl, &cmd);
	if (err) {
		nvme_show_status(err);
		return err;
	}

	nvme_init_zns_identify_ns(&cmd, cfg.namespace_id, &id_zns);
	err = libnvme_exec_admin_passthru(hdl, &cmd);
	if (!err) {
		/* get zsze field from zns id ns data - needed for offset calculation */
		nvme_id_ns_flbas_to_lbaf_inuse(id_ns.flbas, &lbaf);
		zsze = le64_to_cpu(id_zns.lbafe[lbaf].zsze);
	} else {
		nvme_show_status(err);
		return err;
	}

	log_len = sizeof(struct nvme_zone_report);
	buff = calloc(1, log_len);
	if (!buff) {
		return -ENOMEM;
	}

	nvme_init_zns_report_zones(&cmd, cfg.namespace_id, 0, cfg.state, false,
				   false, buff, log_len);
	err = libnvme_exec_io_passthru(hdl, &cmd);
	if (err) {
		nvme_show_err(err, "zns report-zones");
		goto free_buff;
	}

	total_nr_zones = le64_to_cpu(buff->nr_zones);

	if (cfg.num_descs == -1)
		cfg.num_descs = total_nr_zones;

	nr_zones = cfg.num_descs;
	if (nr_zones < nr_zones_chunks)
		nr_zones_chunks = nr_zones;

	log_len = sizeof(struct nvme_zone_report) + ((sizeof(struct nvme_zns_desc) * nr_zones_chunks) + (nr_zones_chunks * zdes));
	report_size = log_len;

	report = libnvme_alloc_huge(report_size, &mh);
	if (!report) {
		nvme_show_perror("alloc");
		return -ENOMEM;
	}

	offset = cfg.zslba;

	nvme_zns_start_zone_list(total_nr_zones, &zone_list, flags);

	while (nr_zones_retrieved < nr_zones) {
		if (nr_zones_retrieved >= nr_zones)
			break;

		if (nr_zones_retrieved + nr_zones_chunks > nr_zones) {
			nr_zones_chunks = nr_zones - nr_zones_retrieved;
			log_len = sizeof(struct nvme_zone_report) + ((sizeof(struct nvme_zns_desc) * nr_zones_chunks) + (nr_zones_chunks * zdes));
		}

		nvme_init_zns_report_zones(&cmd, cfg.namespace_id, offset,
					   cfg.state, cfg.extended, cfg.partial,
					   report, log_len);
		err = libnvme_exec_io_passthru(hdl, &cmd);
		if (err) {
			nvme_show_err(err, "zns report-zones");
			break;
		}

		if (!err)
			nvme_show_zns_report_zones(report, nr_zones_chunks,
						   zdes, log_len, zone_list, flags);

		nr_zones_retrieved += nr_zones_chunks;
		offset = le64_to_cpu(report->entries[nr_zones_chunks-1].zslba) + zsze;
	}

	nvme_zns_finish_zone_list(total_nr_zones, zone_list, flags);

free_buff:
	free(buff);

	return err;
}

static int zone_append(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "The zone append command is used to write to a zone\n"
			   "using the slba of the zone, and the write will be appended from the\n"
			   "write pointer of the zone";
	const char *zslba = "starting LBA of the zone";
	const char *data = "file containing data to write";
	const char *metadata = "file with metadata to be written";
	const char *limited_retry = "limit media access attempts";
	const char *fua = "force unit access";
	const char *prinfo = "protection information action and checks field";
	const char *piremap = "protection information remap (for type 1 PI)";
	const char *metadata_size = "size of metadata in bytes";
	const char *data_size = "size of data in bytes";
	const char *latency = "output latency statistics";

	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	int err = -1, dfd = STDIN_FILENO, mfd = STDIN_FILENO;
	struct timeval start_time, end_time;
	unsigned int lba_size, meta_size;
	__cleanup_libnvme_free void *buf = NULL;
	__cleanup_libnvme_free void *mbuf = NULL;
	struct libnvme_passthru_cmd cmd;
	__u16 nblocks, control = 0;
	__u16 cev = 0, dspec = 0;
	__u8 lba_index;

	struct nvme_id_ns ns;

	struct config {
		char  *data;
		char  *metadata;
		__u64  zslba;
		__u64  data_size;
		__u64  metadata_size;
		bool   limited_retry;
		bool   fua;
		__u32  namespace_id;
		__u8   prinfo;
		bool   piremap;
		bool   latency;
	};

	struct config cfg = {};

	NVME_ARGS(opts,
		OPT_UINT("namespace-id", 'n', &cfg.namespace_id,  namespace_id),
		OPT_SUFFIX("zslba",           's', &cfg.zslba,         zslba),
		OPT_SUFFIX("data-size",       'z', &cfg.data_size,     data_size),
		OPT_SUFFIX("metadata-size",   'y', &cfg.metadata_size, metadata_size),
		OPT_FILE("data",              'd', &cfg.data,          data),
		OPT_FILE("metadata",          'M', &cfg.metadata,      metadata),
		OPT_FLAG("limited-retry",     'l', &cfg.limited_retry, limited_retry),
		OPT_FLAG("force-unit-access", 'f', &cfg.fua,           fua),
		OPT_BYTE("prinfo",            'p', &cfg.prinfo,        prinfo),
		OPT_FLAG("piremap",           'P', &cfg.piremap,       piremap),
		OPT_FLAG("latency",           't', &cfg.latency,       latency));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return errno;

	if (!cfg.data_size) {
		nvme_show_error("Append size not provided");
		return -EINVAL;
	}

	if (!cfg.namespace_id) {
		err = libnvme_get_nsid(hdl, &cfg.namespace_id);
		if (err < 0) {
			nvme_show_err(err, "get-namespace-id");
			return err;;
		}
	}

	nvme_init_identify_ns(&cmd, cfg.namespace_id, &ns);
	err = libnvme_exec_admin_passthru(hdl, &cmd);
	if (err) {
		nvme_show_status(err);
		return err;
	}

	nvme_id_ns_flbas_to_lbaf_inuse(ns.flbas, &lba_index);
	lba_size = 1 << ns.lbaf[lba_index].ds;
	if (cfg.data_size & (lba_size - 1)) {
		nvme_show_error(
			"Data size:%#"PRIx64" not aligned to lba size:%#x",
			(uint64_t)cfg.data_size, lba_size);
		return -EINVAL;
	}

	meta_size = ns.lbaf[lba_index].ms;
	if (meta_size && !(meta_size == 8 && (cfg.prinfo & 0x8)) &&
	    (!cfg.metadata_size || cfg.metadata_size % meta_size)) {
		nvme_show_error(
			"Metadata size:%#"PRIx64" not aligned to metadata size:%#x",
			(uint64_t)cfg.metadata_size, meta_size);
		return -EINVAL;
	}

	if (cfg.prinfo > 0xf) {
		nvme_show_error("Invalid value for prinfo:%#x", cfg.prinfo);
		return -EINVAL;
	}

	if (cfg.data) {
		dfd = open(cfg.data, O_RDONLY);
		if (dfd < 0) {
			nvme_show_perror("%s", cfg.data);
			return -errno;
		}
	}

	buf = libnvme_alloc(cfg.data_size);
	if (!buf) {
		nvme_show_error("No memory for data size:%"PRIx64"",
			(uint64_t)cfg.data_size);
		goto close_dfd;
	}

	err = read(dfd, buf, cfg.data_size);
	if (err < 0) {
		nvme_show_perror("read-data");
		goto close_dfd;
	}

	if (cfg.metadata) {
		mfd = open(cfg.metadata, O_RDONLY);
		if (mfd < 0) {
			nvme_show_perror("%s", cfg.metadata);
			goto close_dfd;
		}
	}

	if (cfg.metadata_size) {
		mbuf = libnvme_alloc(meta_size);
		if (!mbuf) {
			nvme_show_error("No memory for metadata size:%d",
				meta_size);
			err = -1;
			goto close_mfd;
		}

		err = read(mfd, mbuf, cfg.metadata_size);
		if (err < 0) {
			nvme_show_perror("read-metadata");
			goto close_mfd;
		}
	}

	nblocks = (cfg.data_size / lba_size) - 1;
	control |= (cfg.prinfo << 10);
	if (cfg.limited_retry)
		control |= NVME_IO_LR;
	if (cfg.fua)
		control |= NVME_IO_FUA;
	if (cfg.piremap)
		control |= NVME_IO_ZNS_APPEND_PIREMAP;

	gettimeofday(&start_time, NULL);
	nvme_init_zns_append(&cmd, cfg.namespace_id, cfg.zslba, nblocks,
			     control, cev, dspec, buf, cfg.data_size, mbuf,
			     cfg.metadata_size);
	err = libnvme_exec_admin_passthru(hdl, &cmd);
	gettimeofday(&end_time, NULL);
	if (cfg.latency)
		nvme_show_result(" latency: zone append: %llu us",
		       shr_elapsed_utime(start_time, end_time));

	if (!err)
		nvme_show_verbose_result("Success appended data to LBA %"PRIx64,
		       (uint64_t)cmd.result);
	else
		nvme_show_err(err, "zns zone-append");

close_mfd:
	if (cfg.metadata)
		close(mfd);
close_dfd:
	if (cfg.data)
		close(dfd);

	return err;
}

static int changed_zone_list(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Retrieve Changed Zone log for the given device";
	const char *rae = "retain an asynchronous event";

	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	struct nvme_zns_changed_zone_log log;
	struct libnvme_passthru_cmd cmd;
	nvme_print_flags_t flags;
	int err = -1;

	struct config {
		__u32 namespace_id;
		bool  rae;
	};

	struct config cfg = { };

	NVME_ARGS(opts,
		OPT_UINT("namespace-id", 'n', &cfg.namespace_id,  namespace_id),
		OPT_FLAG("rae",          'r', &cfg.rae,           rae));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return errno;

	err = validate_output_format(nvme_args.output_format, &flags);
	if (err < 0)
		return err;

	if (!cfg.namespace_id) {
		err = libnvme_get_nsid(hdl, &cfg.namespace_id);
		if (err < 0) {
			nvme_show_err(err, "get-namespace-id");
			return err;
		}
	}

	nvme_init_get_log_zns_changed_zones(&cmd, cfg.namespace_id, &log);

	err = libnvme_get_log(hdl, &cmd, cfg.rae, sizeof(log));
	if (!err)
		nvme_show_zns_changed(&log, flags);
	else
		nvme_show_err(err, "zns changed-zone-list");

	return err;
}

static struct command list_cmd = {
	.name = "list",
	.help = "List all NVMe devices with Zoned Namespace Command Set support",
	.fn = list,
	.no_device = true,
};

static struct command id_ctrl_cmd = {
	.name = "id-ctrl",
	.help = "Send NVMe Identify Zoned Namespace Controller, display structure",
	.fn = id_ctrl,
};

static struct command id_ns_cmd = {
	.name = "id-ns",
	.help = "Send NVMe Identify Zoned Namespace Namespace, display structure",
	.fn = id_ns,
};

static struct command report_zones_cmd = {
	.name = "report-zones",
	.help = "Report zones associated to a Zoned Namespace",
	.fn = report_zones,
};

static struct command reset_zone_cmd = {
	.name = "reset-zone",
	.help = "Reset one or more zones",
	.fn = reset_zone,
};

static struct command close_zone_cmd = {
	.name = "close-zone",
	.help = "Close one or more zones",
	.fn = close_zone,
};

static struct command finish_zone_cmd = {
	.name = "finish-zone",
	.help = "Finish one or more zones",
	.fn = finish_zone,
};

static struct command open_zone_cmd = {
	.name = "open-zone",
	.help = "Open one or more zones",
	.fn = open_zone,
};

static struct command offline_zone_cmd = {
	.name = "offline-zone",
	.help = "Offline one or more zones",
	.fn = offline_zone,
};

static struct command set_zone_desc_cmd = {
	.name = "set-zone-desc",
	.help = "Attach zone descriptor extension data to a zone",
	.fn = set_zone_desc,
};

static struct command zrwa_flush_zone_cmd = {
	.name = "zrwa-flush-zone",
	.help = "Flush LBAs associated with a ZRWA to a zone.",
	.fn = zrwa_flush_zone,
};

static struct command changed_zone_list_cmd = {
	.name = "changed-zone-list",
	.help = "Retrieve the changed zone list log",
	.fn = changed_zone_list,
};

static struct command zone_mgmt_recv_cmd = {
	.name = "zone-mgmt-recv",
	.help = "Send the zone management receive command",
	.fn = zone_mgmt_recv,
};

static struct command zone_mgmt_send_cmd = {
	.name = "zone-mgmt-send",
	.help = "Send the zone management send command",
	.fn = zone_mgmt_send,
};

static struct command zone_append_cmd = {
	.name = "zone-append",
	.help = "Append data and metadata (if applicable) to a zone",
	.fn = zone_append,
};

static struct command *commands[] = {
	&list_cmd,
	&id_ctrl_cmd,
	&id_ns_cmd,
	&report_zones_cmd,
	&reset_zone_cmd,
	&close_zone_cmd,
	&finish_zone_cmd,
	&open_zone_cmd,
	&offline_zone_cmd,
	&set_zone_desc_cmd,
	&zrwa_flush_zone_cmd,
	&changed_zone_list_cmd,
	&zone_mgmt_recv_cmd,
	&zone_mgmt_send_cmd,
	&zone_append_cmd,
	NULL,
};

static struct plugin plugin = {
	.name = "zns",
	.desc = "Zoned Namespace Command Set",
	.version = NVME_VERSION,
	.core = true,
};

static void __shr_constructor register_plugin(void)
{
	plugin_add_group(&plugin, NULL, commands);
	register_extension(&plugin);
}
