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
#include "util/cleanup.h"

#define CREATE_CMD
#include "zns.h"

static const char *namespace_id = "Namespace identifier to use";
static const char dash[100] = { [0 ... 99] = '-' };

static int detect_zns(nvme_ns_t ns, int *out_supported)
{
	int err = 0;
	char *zoned;

	*out_supported = 0;

	zoned = nvme_get_attr(nvme_ns_get_sysfs_dir(ns), "queue/zoned");
	if (!zoned) {
		*out_supported = 0;
		return err;
	}

	*out_supported = strcmp("host-managed", zoned) == 0;
	free(zoned);

	return err;
}

static int print_zns_list_ns(nvme_ns_t ns)
{
	int supported;
	int err = 0;

	err = detect_zns(ns, &supported);
	if (err) {
		perror("Failed to enumerate namespace");
		return err;
	}

	if (supported)
		nvme_show_list_item(ns);

	return err;
}

static int print_zns_list(nvme_root_t nvme_root)
{
	int err = 0;
	nvme_host_t h;
	nvme_subsystem_t s;
	nvme_ctrl_t c;
	nvme_ns_t n;

	nvme_for_each_host(nvme_root, h) {
		nvme_for_each_subsystem(h, s) {
			nvme_subsystem_for_each_ns(s, n) {
				err = print_zns_list_ns(n);
				if (err)
					return err;
			}

			nvme_subsystem_for_each_ctrl(s, c) {
				nvme_ctrl_for_each_ns(c, n) {
					err = print_zns_list_ns(n);
					if (err)
						return err;
				}
			}
		}
	}

	return err;
}

static int list(int argc, char **argv, struct command *cmd,
		struct plugin *plugin)
{
	int err = 0;
	nvme_root_t nvme_root;

	printf("%-21s %-20s %-40s %-9s %-26s %-16s %-8s\n", "Node", "SN",
	       "Model", "Namespace", "Usage", "Format", "FW Rev");
	printf("%-.21s %-.20s %-.40s %-.9s %-.26s %-.16s %-.8s\n", dash, dash,
	       dash, dash, dash, dash, dash);

	nvme_root = nvme_scan(NULL);
	if (nvme_root) {
		err = print_zns_list(nvme_root);
		nvme_free_tree(nvme_root);
	} else {
		fprintf(stderr, "Failed to scan nvme subsystems\n");
		err = -errno;
	}

	return err;
}

static int id_ctrl(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Send a ZNS specific Identify Controller command to\n"
			   "the given device and report information about the specified\n"
			   "controller in various formats.";

	nvme_print_flags_t flags;
	struct nvme_zns_id_ctrl ctrl;
	struct nvme_dev *dev;
	int err = -1;

	struct config {
		char *output_format;
	};

	struct config cfg = {
		.output_format = "normal",
	};

	OPT_ARGS(opts) = {
		OPT_FMT("output-format", 'o', &cfg.output_format, output_format),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return errno;

	err = validate_output_format(cfg.output_format, &flags);
	if (err < 0)
		goto close_dev;

	err = nvme_zns_identify_ctrl(dev_fd(dev), &ctrl);
	if (!err)
		nvme_show_zns_id_ctrl(&ctrl, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		perror("zns identify controller");
close_dev:
	dev_close(dev);
	return err;
}

static int id_ns(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Send a ZNS specific Identify Namespace command to\n"
			   "the given device and report information about the specified\n"
			   "namespace in varios formats.";
	const char *vendor_specific = "dump binary vendor fields";
	const char *human_readable = "show identify in readable format";

	nvme_print_flags_t flags;
	struct nvme_zns_id_ns ns;
	struct nvme_id_ns id_ns;
	struct nvme_dev *dev;
	int err = -1;

	struct config {
		char *output_format;
		__u32 namespace_id;
		bool human_readable;
		bool vendor_specific;
	};

	struct config cfg = {
		.output_format = "normal",
	};

	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id", 'n', &cfg.namespace_id,  namespace_id),
		OPT_FLAG("vendor-specific", 'v', &cfg.vendor_specific, vendor_specific),
		OPT_FMT("output-format", 'o', &cfg.output_format, output_format),
		OPT_FLAG("human-readable", 'H', &cfg.human_readable, human_readable),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return errno;

	err = validate_output_format(cfg.output_format, &flags);
	if (err < 0)
		goto close_dev;
	if (cfg.vendor_specific)
		flags |= VS;
	if (cfg.human_readable)
		flags |= VERBOSE;

	if (!cfg.namespace_id) {
		err = nvme_get_nsid(dev_fd(dev), &cfg.namespace_id);
		if (err < 0) {
			perror("get-namespace-id");
			goto close_dev;
		}
	}

	err = nvme_identify_ns(dev_fd(dev), cfg.namespace_id, &id_ns);
	if (err) {
		nvme_show_status(err);
		goto close_dev;
	}

	err = nvme_zns_identify_ns(dev_fd(dev), cfg.namespace_id, &ns);
	if (!err)
		nvme_show_zns_id_ns(&ns, &id_ns, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		perror("zns identify namespace");
close_dev:
	dev_close(dev);
	return err;
}

static int zns_mgmt_send(int argc, char **argv, struct command *cmd, struct plugin *plugin,
	const char *desc, enum nvme_zns_send_action zsa)
{
	const char *zslba = "starting LBA of the zone for this command";
	const char *select_all = "send command to all zones";
	const char *timeout = "timeout value, in milliseconds";
	struct nvme_dev *dev;
	int err, zcapc = 0;
	char *command;
	__u32 result;

	struct config {
		__u64	zslba;
		__u32	namespace_id;
		bool	select_all;
		__u32	timeout;
	};

	struct config cfg = {};

	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id", 'n', &cfg.namespace_id,  namespace_id),
		OPT_SUFFIX("start-lba",  's', &cfg.zslba,         zslba),
		OPT_FLAG("select-all",   'a', &cfg.select_all,    select_all),
		OPT_UINT("timeout",      't', &cfg.timeout,       timeout),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		goto ret;

	err = asprintf(&command, "%s-%s", plugin->name, cmd->name);
	if (err < 0)
		goto close_dev;

	if (!cfg.namespace_id) {
		err = nvme_get_nsid(dev_fd(dev), &cfg.namespace_id);
		if (err < 0) {
			perror("get-namespace-id");
			goto free;
		}
	}

	struct nvme_zns_mgmt_send_args args = {
		.args_size	= sizeof(args),
		.fd		= dev_fd(dev),
		.nsid		= cfg.namespace_id,
		.slba		= cfg.zslba,
		.zsa		= zsa,
		.select_all	= cfg.select_all,
		.zsaso		= 0,
		.data_len	= 0,
		.data		= NULL,
		.timeout	= cfg.timeout,
		.result		= &result,
	};
	err = nvme_zns_mgmt_send(&args);
	if (!err) {
		if (zsa == NVME_ZNS_ZSA_RESET)
			zcapc = result & 0x1;

		printf("%s: Success, action:%d zone:%"PRIx64" all:%d zcapc:%u nsid:%d\n",
			command, zsa, (uint64_t)cfg.zslba, (int)cfg.select_all,
			zcapc, cfg.namespace_id);
	} else if (err > 0) {
		nvme_show_status(err);
	} else {
		perror(desc);
	}
free:
	free(command);
close_dev:
	dev_close(dev);
ret:
	return err;
}

static int get_zdes_bytes(int fd, __u32 nsid)
{
	struct nvme_zns_id_ns ns;
	struct nvme_id_ns id_ns;
	__u8 lbaf;
	int err;

	err = nvme_identify_ns(fd, nsid, &id_ns);
	if (err > 0) {
		nvme_show_status(err);
		return -1;
	} else if (err < 0) {
		perror("identify namespace");
		return -1;
	}

	err = nvme_zns_identify_ns(fd, nsid,  &ns);
	if (err > 0) {
		nvme_show_status(err);
		return -1;
	} else if (err < 0) {
		perror("zns identify namespace");
		return -1;
	}

	nvme_id_ns_flbas_to_lbaf_inuse(id_ns.flbas, &lbaf);
	return ns.lbafe[lbaf].zdes << 6;
}

static int zone_mgmt_send(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Zone Management Send";
	const char *zslba =
	    "starting LBA of the zone for this command(for flush action, last lba to flush)";
	const char *zsaso = "Zone Send Action Specific Option";
	const char *select_all = "send command to all zones";
	const char *zsa = "zone send action";
	const char *data_len = "buffer length if data required";
	const char *data = "optional file for data (default stdin)";
	const char *timeout = "timeout value, in milliseconds";

	int ffd = STDIN_FILENO, err = -1;
	struct nvme_dev *dev;
	void *buf = NULL;

	struct config {
		__u64	zslba;
		__u32	namespace_id;
		bool	zsaso;
		bool	select_all;
		__u8	zsa;
		int	data_len;
		char	*file;
		__u32	timeout;
	};

	struct config cfg = {};

	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id", 'n', &cfg.namespace_id,  namespace_id),
		OPT_SUFFIX("start-lba",  's', &cfg.zslba,         zslba),
		OPT_FLAG("zsaso",        'o', &cfg.zsaso,         zsaso),
		OPT_FLAG("select-all",   'a', &cfg.select_all,    select_all),
		OPT_BYTE("zsa",          'z', &cfg.zsa,           zsa),
		OPT_UINT("data-len",     'l', &cfg.data_len,      data_len),
		OPT_FILE("data",         'd', &cfg.file,          data),
		OPT_UINT("timeout",      't', &cfg.timeout,       timeout),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return errno;

	if (!cfg.namespace_id) {
		err = nvme_get_nsid(dev_fd(dev), &cfg.namespace_id);
		if (err < 0) {
			perror("get-namespace-id");
			goto close_dev;
		}
	}

	if (!cfg.zsa) {
		fprintf(stderr, "zone send action must be specified\n");
		err = -EINVAL;
		goto close_dev;
	}

	if (cfg.zsa == NVME_ZNS_ZSA_SET_DESC_EXT) {
		if (!cfg.data_len) {
			int data_len = get_zdes_bytes(dev_fd(dev),
						      cfg.namespace_id);

			if (data_len == 0) {
				fprintf(stderr, "Zone Descriptor Extensions are not supported\n");
				goto close_dev;
			} else if (data_len < 0) {
				err = data_len;
				goto close_dev;
			}
			cfg.data_len = data_len;
		}
		if (posix_memalign(&buf, getpagesize(), cfg.data_len)) {
			fprintf(stderr, "can not allocate feature payload\n");
			goto close_dev;
		}
		memset(buf, 0, cfg.data_len);

		if (cfg.file) {
			ffd = open(cfg.file, O_RDONLY);
			if (ffd < 0) {
				perror(cfg.file);
				goto free;
			}
		}

		err = read(ffd, (void *)buf, cfg.data_len);
		if (err < 0) {
			perror("read");
			goto close_ffd;
		}
	} else {
		if (cfg.file || cfg.data_len) {
			fprintf(stderr, "data, data_len only valid with set extended descriptor\n");
			err = -EINVAL;
			goto close_dev;
		}
	}

	struct nvme_zns_mgmt_send_args args = {
		.args_size	= sizeof(args),
		.fd		= dev_fd(dev),
		.nsid		= cfg.namespace_id,
		.slba		= cfg.zslba,
		.zsa		= cfg.zsa,
		.select_all	= cfg.select_all,
		.zsaso		= cfg.zsaso,
		.data_len	= cfg.data_len,
		.data		= buf,
		.timeout	= cfg.timeout,
		.result		= NULL,
	};
	err = nvme_zns_mgmt_send(&args);
	if (!err)
		printf("zone-mgmt-send: Success, action:%d zone:%"PRIx64" all:%d nsid:%d\n",
		       cfg.zsa, (uint64_t)cfg.zslba, (int)cfg.select_all, cfg.namespace_id);
	else if (err > 0)
		nvme_show_status(err);
	else
		perror("zns zone-mgmt-send");

close_ffd:
	if (cfg.file)
		close(ffd);
free:
	free(buf);
close_dev:
	dev_close(dev);
	return err;
}

static int close_zone(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Close zones\n";

	return zns_mgmt_send(argc, argv, cmd, plugin, desc, NVME_ZNS_ZSA_CLOSE);
}

static int finish_zone(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Finish zones\n";

	return zns_mgmt_send(argc, argv, cmd, plugin, desc, NVME_ZNS_ZSA_FINISH);
}

static int open_zone(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Open zones\n";
	const char *zslba = "starting LBA of the zone for this command";
	const char *zrwaa = "Allocate Zone Random Write Area to zone";
	const char *select_all = "send command to all zones";
	const char *timeout = "timeout value, in milliseconds";
	struct nvme_dev *dev;
	int err;

	struct config {
		__u64	zslba;
		__u32	namespace_id;
		bool	zrwaa;
		bool	select_all;
		__u32	timeout;
	};

	struct config cfg = {
	};

	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id", 'n', &cfg.namespace_id,  namespace_id),
		OPT_SUFFIX("start-lba",  's', &cfg.zslba,         zslba),
		OPT_FLAG("zrwaa",         'r', &cfg.zrwaa,          zrwaa),
		OPT_FLAG("select-all",   'a', &cfg.select_all,    select_all),
		OPT_UINT("timeout",      't', &cfg.timeout,       timeout),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return errno;

	if (!cfg.namespace_id) {
		err = nvme_get_nsid(dev_fd(dev), &cfg.namespace_id);
		if (err < 0) {
			perror("get-namespace-id");
			goto close_dev;
		}
	}

	struct nvme_zns_mgmt_send_args args = {
		.args_size	= sizeof(args),
		.fd		= dev_fd(dev),
		.nsid		= cfg.namespace_id,
		.slba		= cfg.zslba,
		.zsa		= NVME_ZNS_ZSA_OPEN,
		.select_all	= cfg.select_all,
		.zsaso		= cfg.zrwaa,
		.data_len	= 0,
		.data		= NULL,
		.timeout	= cfg.timeout,
		.result		= NULL,
	};
	err = nvme_zns_mgmt_send(&args);
	if (!err)
		printf("zns-open-zone: Success zone slba:%"PRIx64" nsid:%d\n",
		       (uint64_t)cfg.zslba, cfg.namespace_id);
	else
		nvme_show_status(err);
close_dev:
	dev_close(dev);
	return err;
}

static int reset_zone(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Reset zones\n";

	return zns_mgmt_send(argc, argv, cmd, plugin, desc, NVME_ZNS_ZSA_RESET);
}

static int offline_zone(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Offline zones\n";

	return zns_mgmt_send(argc, argv, cmd, plugin, desc, NVME_ZNS_ZSA_OFFLINE);
}

static int set_zone_desc(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Set Zone Descriptor Extension\n";
	const char *zslba = "starting LBA of the zone for this command";
	const char *zrwaa = "Allocate Zone Random Write Area to zone";
	const char *data = "optional file for zone extension data (default stdin)";
	const char *timeout = "timeout value, in milliseconds";

	int ffd = STDIN_FILENO, err;
	struct nvme_dev *dev;
	void *buf = NULL;
	int data_len;

	struct config {
		__u64	zslba;
		bool	zrwaa;
		__u32	namespace_id;
		char   *file;
		__u32	timeout;
	};

	struct config cfg = {};

	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id", 'n', &cfg.namespace_id,  namespace_id),
		OPT_SUFFIX("start-lba",  's', &cfg.zslba,         zslba),
		OPT_FLAG("zrwaa",        'r', &cfg.zrwaa,         zrwaa),
		OPT_FILE("data",         'd', &cfg.file,          data),
		OPT_UINT("timeout",      't', &cfg.timeout,       timeout),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return errno;

	if (!cfg.namespace_id) {
		err = nvme_get_nsid(dev_fd(dev), &cfg.namespace_id);
		if (err < 0) {
			perror("get-namespace-id");
			goto close_dev;
		}
	}

	data_len = get_zdes_bytes(dev_fd(dev), cfg.namespace_id);

	if (!data_len || data_len < 0) {
		fprintf(stderr,
			"zone format does not provide descriptor extension\n");
		errno = EINVAL;
		err = -1;
		goto close_dev;
	}

	buf = calloc(1, data_len);
	if (!buf) {
		perror("could not alloc memory for zone desc");
		err = -ENOMEM;
		goto close_dev;
	}

	if (cfg.file) {
		ffd = open(cfg.file, O_RDONLY);
		if (ffd < 0) {
			perror(cfg.file);
			err = -1;
			goto free;
		}
	}

	err = read(ffd, (void *)buf, data_len);
	if (err < 0) {
		perror("read");
		goto close_ffd;
	}

	struct nvme_zns_mgmt_send_args args = {
		.args_size	= sizeof(args),
		.fd		= dev_fd(dev),
		.nsid		= cfg.namespace_id,
		.slba		= cfg.zslba,
		.zsa		= NVME_ZNS_ZSA_SET_DESC_EXT,
		.select_all	= 0,
		.zsaso		= cfg.zrwaa,
		.data_len	= data_len,
		.data		= buf,
		.timeout	= cfg.timeout,
		.result		= NULL,
	};
	err = nvme_zns_mgmt_send(&args);
	if (!err)
		printf("set-zone-desc: Success, zone:%"PRIx64" nsid:%d\n",
		       (uint64_t)cfg.zslba, cfg.namespace_id);
	else if (err > 0)
		nvme_show_status(err);
	else
		perror("zns set-zone-desc");
close_ffd:
	if (cfg.file)
		close(ffd);
free:
	free(buf);
close_dev:
	dev_close(dev);
	return err;
}


static int zrwa_flush_zone(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Flush Explicit ZRWA Range";
	const char *slba = "LBA to flush up to";
	const char *timeout = "timeout value, in milliseconds";
	struct nvme_dev *dev;
	int err;

	struct config {
		__u64	lba;
		__u32	namespace_id;
		__u32	timeout;
	};

	struct config cfg = {};

	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id", 'n', &cfg.namespace_id,  namespace_id),
		OPT_SUFFIX("lba",        'l', &cfg.lba,           slba),
		OPT_UINT("timeout",      't', &cfg.timeout,       timeout),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return errno;

	if (!cfg.namespace_id) {
		err = nvme_get_nsid(dev_fd(dev), &cfg.namespace_id);
		if (err < 0) {
			perror("get-namespace-id");
			goto close_dev;
		}
	}

	struct nvme_zns_mgmt_send_args args = {
		.args_size	= sizeof(args),
		.fd		= dev_fd(dev),
		.nsid		= cfg.namespace_id,
		.slba		= cfg.lba,
		.zsa		= NVME_ZNS_ZSA_ZRWA_FLUSH,
		.select_all	= 0,
		.zsaso		= 0,
		.data_len	= 0,
		.data		= NULL,
		.timeout	= cfg.timeout,
		.result		= NULL,
	};
	err = nvme_zns_mgmt_send(&args);
	if (!err)
		printf("zrwa-flush-zone: Success, lba:%"PRIx64" nsid:%d\n",
		       (uint64_t)cfg.lba, cfg.namespace_id);
	else
		nvme_show_status(err);
close_dev:
	dev_close(dev);
	return err;
}

static int zone_mgmt_recv(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Zone Management Receive";
	const char *zslba = "starting LBA of the zone";
	const char *zra = "Zone Receive Action";
	const char *zrasf = "Zone Receive Action Specific Field(Reporting Options)";
	const char *partial = "Zone Receive Action Specific Features(Partial Report)";
	const char *data_len = "length of data in bytes";

	nvme_print_flags_t flags;
	struct nvme_dev *dev;
	void *data = NULL;
	int err = -1;

	struct config {
		char *output_format;
		__u64  zslba;
		__u32  namespace_id;
		__u8   zra;
		__u8   zrasf;
		bool   partial;
		__u32  data_len;
	};

	struct config cfg = {
		.output_format = "normal",
	};

	OPT_ARGS(opts) = {
		OPT_FMT("output-format",  'o', &cfg.output_format,  output_format),
		OPT_UINT("namespace-id",  'n', &cfg.namespace_id,   namespace_id),
		OPT_SUFFIX("start-lba",   's', &cfg.zslba,          zslba),
		OPT_BYTE("zra",           'z', &cfg.zra,            zra),
		OPT_BYTE("zrasf",         'S', &cfg.zrasf,          zrasf),
		OPT_FLAG("partial",       'p', &cfg.partial,        partial),
		OPT_UINT("data-len",      'l', &cfg.data_len,       data_len),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return errno;

	err = validate_output_format(cfg.output_format, &flags);
	if (err < 0)
		goto close_dev;

	if (!cfg.namespace_id) {
		err = nvme_get_nsid(dev_fd(dev), &cfg.namespace_id);
		if (err < 0) {
			perror("get-namespace-id");
			goto close_dev;
		}
	}

	if (cfg.zra == NVME_ZNS_ZRA_REPORT_ZONES && !cfg.data_len) {
		fprintf(stderr, "error: data len is needed for NVME_ZRA_ZONE_REPORT\n");
		err = -EINVAL;
		goto close_dev;
	}
	if (cfg.data_len) {
		data = calloc(1, cfg.data_len);
		if (!data) {
			perror("could not alloc memory for zone mgmt receive data");
			err = -ENOMEM;
			goto close_dev;
		}
	}

	struct nvme_zns_mgmt_recv_args args = {
		.args_size	= sizeof(args),
		.fd		= dev_fd(dev),
		.nsid		= cfg.namespace_id,
		.slba		= cfg.zslba,
		.zra		= cfg.zra,
		.zrasf		= cfg.zrasf,
		.zras_feat	= cfg.partial,
		.data_len	= cfg.data_len,
		.data		= data,
		.timeout	= NVME_DEFAULT_IOCTL_TIMEOUT,
		.result		= NULL,
	};
	err = nvme_zns_mgmt_recv(&args);
	if (!err)
		printf("zone-mgmt-recv: Success, action:%d zone:%"PRIx64" nsid:%d\n",
		       cfg.zra, (uint64_t)cfg.zslba, cfg.namespace_id);
	else if (err > 0)
		nvme_show_status(err);
	else
		perror("zns zone-mgmt-recv");

	free(data);
close_dev:
	dev_close(dev);
	return err;
}

static int report_zones(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Retrieve the Report Zones data structure";
	const char *zslba = "starting LBA of the zone";
	const char *num_descs = "number of descriptors to retrieve (default: all of them)";
	const char *state = "state of zones to list";
	const char *ext = "set to use the extended report zones";
	const char *part = "set to use the partial report";
	const char *verbose = "show report zones verbosity";

	nvme_print_flags_t flags;
	int zdes = 0, err = -1;
	struct nvme_dev *dev;
	__u32 report_size;
	struct nvme_zone_report *report, *buff;
	_cleanup_huge_ struct nvme_mem_huge mh = { 0, };

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
		char *output_format;
		__u64 zslba;
		__u32 namespace_id;
		int   num_descs;
		int   state;
		bool  verbose;
		bool  extended;
		bool  partial;
	};

	struct config cfg = {
		.output_format = "normal",
		.num_descs = -1,
	};

	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id",  'n', &cfg.namespace_id,   namespace_id),
		OPT_SUFFIX("start-lba",   's', &cfg.zslba,          zslba),
		OPT_UINT("descs",         'd', &cfg.num_descs,      num_descs),
		OPT_UINT("state",         'S', &cfg.state,          state),
		OPT_FMT("output-format",  'o', &cfg.output_format,  output_format),
		OPT_FLAG("verbose",       'v', &cfg.verbose,        verbose),
		OPT_FLAG("extended",      'e', &cfg.extended,       ext),
		OPT_FLAG("partial",       'p', &cfg.partial,        part),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return errno;

	err = validate_output_format(cfg.output_format, &flags);
	if (err < 0)
		goto close_dev;
	if (cfg.verbose)
		flags |= VERBOSE;

	if (!cfg.namespace_id) {
		err = nvme_get_nsid(dev_fd(dev), &cfg.namespace_id);
		if (err < 0) {
			perror("get-namespace-id");
			goto close_dev;
		}
	}

	if (cfg.extended) {
		zdes = get_zdes_bytes(dev_fd(dev), cfg.namespace_id);
		if (zdes < 0) {
			err = zdes;
			goto close_dev;
		}
	}

	err = nvme_identify_ns(dev_fd(dev), cfg.namespace_id, &id_ns);
	if (err) {
		nvme_show_status(err);
		goto close_dev;
	}

	err = nvme_zns_identify_ns(dev_fd(dev), cfg.namespace_id, &id_zns);
	if (!err) {
		/* get zsze field from zns id ns data - needed for offset calculation */
		nvme_id_ns_flbas_to_lbaf_inuse(id_ns.flbas, &lbaf);
		zsze = le64_to_cpu(id_zns.lbafe[lbaf].zsze);
	} else {
		nvme_show_status(err);
		goto close_dev;
	}

	log_len = sizeof(struct nvme_zone_report);
	buff = calloc(1, log_len);
	if (!buff) {
		err = -ENOMEM;
		goto close_dev;
	}

	err = nvme_zns_report_zones(dev_fd(dev), cfg.namespace_id, 0,
				    cfg.state, false, false,
				    log_len, buff,
				    NVME_DEFAULT_IOCTL_TIMEOUT, NULL);
	if (err > 0) {
		nvme_show_status(err);
		goto free_buff;
	} else if (err < 0) {
		perror("zns report-zones");
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

	report = nvme_alloc_huge(report_size, &mh);
	if (!report) {
		perror("alloc");
		err = -ENOMEM;
		goto close_dev;
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

		err = nvme_zns_report_zones(dev_fd(dev), cfg.namespace_id,
					    offset,
					    cfg.state, cfg.extended,
					    cfg.partial, log_len, report,
					    NVME_DEFAULT_IOCTL_TIMEOUT, NULL);
		if (err > 0) {
			nvme_show_status(err);
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
close_dev:
	dev_close(dev);
	return err;
}

static int zone_append(int argc, char **argv, struct command *cmd, struct plugin *plugin)
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
	const char *ref_tag = "reference tag for end-to-end PI";
	const char *lbat = "logical block application tag for end-to-end PI";
	const char *lbatm = "logical block application tag mask for end-to-end PI";
	const char *metadata_size = "size of metadata in bytes";
	const char *data_size = "size of data in bytes";
	const char *latency = "output latency statistics";

	int err = -1, dfd = STDIN_FILENO, mfd = STDIN_FILENO;
	unsigned int lba_size, meta_size;
	void *buf = NULL, *mbuf = NULL;
	__u16 nblocks, control = 0;
	struct nvme_dev *dev;
	__u64 result;
	__u8 lba_index;
	struct timeval start_time, end_time;

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
		__u64  ref_tag;
		__u16  lbat;
		__u16  lbatm;
		__u8   prinfo;
		bool   piremap;
		bool   latency;
	};

	struct config cfg = {};

	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id", 'n', &cfg.namespace_id,  namespace_id),
		OPT_SUFFIX("zslba",           's', &cfg.zslba,         zslba),
		OPT_SUFFIX("data-size",       'z', &cfg.data_size,     data_size),
		OPT_SUFFIX("metadata-size",   'y', &cfg.metadata_size, metadata_size),
		OPT_FILE("data",              'd', &cfg.data,          data),
		OPT_FILE("metadata",          'M', &cfg.metadata,      metadata),
		OPT_FLAG("limited-retry",     'l', &cfg.limited_retry, limited_retry),
		OPT_FLAG("force-unit-access", 'f', &cfg.fua,           fua),
		OPT_SUFFIX("ref-tag",         'r', &cfg.ref_tag,       ref_tag),
		OPT_SHRT("app-tag-mask",      'm', &cfg.lbatm,         lbatm),
		OPT_SHRT("app-tag",           'a', &cfg.lbat,          lbat),
		OPT_BYTE("prinfo",            'p', &cfg.prinfo,        prinfo),
		OPT_FLAG("piremap",           'P', &cfg.piremap,       piremap),
		OPT_FLAG("latency",           't', &cfg.latency,       latency),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return errno;

	if (!cfg.data_size) {
		fprintf(stderr, "Append size not provided\n");
		errno = EINVAL;
		goto close_dev;
	}

	if (!cfg.namespace_id) {
		err = nvme_get_nsid(dev_fd(dev), &cfg.namespace_id);
		if (err < 0) {
			perror("get-namespace-id");
			goto close_dev;
		}
	}

	err = nvme_identify_ns(dev_fd(dev), cfg.namespace_id, &ns);
	if (err) {
		nvme_show_status(err);
		goto close_dev;
	}

	nvme_id_ns_flbas_to_lbaf_inuse(ns.flbas, &lba_index);
	lba_size = 1 << ns.lbaf[lba_index].ds;
	if (cfg.data_size & (lba_size - 1)) {
		fprintf(stderr,
			"Data size:%#"PRIx64" not aligned to lba size:%#x\n",
			(uint64_t)cfg.data_size, lba_size);
		errno = EINVAL;
		goto close_dev;
	}

	meta_size = ns.lbaf[lba_index].ms;
	if (meta_size && !(meta_size == 8 && (cfg.prinfo & 0x8)) &&
	    (!cfg.metadata_size || cfg.metadata_size % meta_size)) {
		fprintf(stderr,
			"Metadata size:%#"PRIx64" not aligned to metadata size:%#x\n",
			(uint64_t)cfg.metadata_size, meta_size);
		errno = EINVAL;
		goto close_dev;
	}

	if (cfg.prinfo > 0xf) {
		fprintf(stderr, "Invalid value for prinfo:%#x\n", cfg.prinfo);
		errno = EINVAL;
		goto close_dev;
	}

	if (cfg.data) {
		dfd = open(cfg.data, O_RDONLY);
		if (dfd < 0) {
			perror(cfg.data);
			goto close_dev;
		}
	}

	if (posix_memalign(&buf, getpagesize(), cfg.data_size)) {
		fprintf(stderr, "No memory for data size:%"PRIx64"\n",
			(uint64_t)cfg.data_size);
		goto close_dfd;
	}

	memset(buf, 0, cfg.data_size);
	err = read(dfd, buf, cfg.data_size);
	if (err < 0) {
		perror("read-data");
		goto free_data;
	}

	if (cfg.metadata) {
		mfd = open(cfg.metadata, O_RDONLY);
		if (mfd < 0) {
			perror(cfg.metadata);
			err = -1;
			goto free_data;
		}
	}

	if (cfg.metadata_size) {
		if (posix_memalign(&mbuf, getpagesize(), meta_size)) {
			fprintf(stderr, "No memory for metadata size:%d\n",
				meta_size);
			err = -1;
			goto close_mfd;
		}

		memset(mbuf, 0, cfg.metadata_size);
		err = read(mfd, mbuf, cfg.metadata_size);
		if (err < 0) {
			perror("read-metadata");
			goto free_meta;
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

	struct nvme_zns_append_args args = {
		.args_size	= sizeof(args),
		.fd		= dev_fd(dev),
		.nsid		= cfg.namespace_id,
		.zslba		= cfg.zslba,
		.nlb		= nblocks,
		.control	= control,
		.ilbrt_u64	= cfg.ref_tag,
		.lbat		= cfg.lbat,
		.lbatm		= cfg.lbatm,
		.data_len	= cfg.data_size,
		.data		= buf,
		.metadata_len	= cfg.metadata_size,
		.metadata	= mbuf,
		.timeout	= NVME_DEFAULT_IOCTL_TIMEOUT,
		.result		= &result,
	};

	gettimeofday(&start_time, NULL);
	err = nvme_zns_append(&args);
	gettimeofday(&end_time, NULL);
	if (cfg.latency)
		printf(" latency: zone append: %llu us\n",
		       elapsed_utime(start_time, end_time));

	if (!err)
		printf("Success appended data to LBA %"PRIx64"\n", (uint64_t)result);
	else if (err > 0)
		nvme_show_status(err);
	else
		perror("zns zone-append");

free_meta:
	free(mbuf);
close_mfd:
	if (cfg.metadata)
		close(mfd);
free_data:
	free(buf);
close_dfd:
	if (cfg.data)
		close(dfd);
close_dev:
	dev_close(dev);
	return err;
}

static int changed_zone_list(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Retrieve Changed Zone log for the given device";
	const char *rae = "retain an asynchronous event";

	struct nvme_zns_changed_zone_log log;
	nvme_print_flags_t flags;
	struct nvme_dev *dev;
	int err = -1;

	struct config {
		char *output_format;
		__u32 namespace_id;
		bool  rae;
	};

	struct config cfg = {
		.output_format = "normal",
	};

	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id", 'n', &cfg.namespace_id,  namespace_id),
		OPT_FMT("output-format", 'o', &cfg.output_format, output_format),
		OPT_FLAG("rae",          'r', &cfg.rae,           rae),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return errno;

	err = validate_output_format(cfg.output_format, &flags);
	if (err < 0)
		goto close_dev;

	if (!cfg.namespace_id) {
		err = nvme_get_nsid(dev_fd(dev), &cfg.namespace_id);
		if (err < 0) {
			perror("get-namespace-id");
			goto close_dev;
		}
	}

	err = nvme_get_log_zns_changed_zones(dev_fd(dev), cfg.namespace_id,
					     cfg.rae, &log);
	if (!err)
		nvme_show_zns_changed(&log, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		perror("zns changed-zone-list");

close_dev:
	dev_close(dev);
	return err;
}
