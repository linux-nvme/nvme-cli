#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <inttypes.h>
#include <linux/fs.h>
#include <sys/stat.h>

#include "nvme.h"
#include "nvme-ioctl.h"
#include "nvme-print.h"

#define CREATE_CMD
#include "zns.h"

static const char *namespace_id = "Namespace identifier to use";

static int id_ctrl(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Send an ZNS specific Identify Controller command to "\
		"the given device and report information about the specified "\
		"controller in various formats.";

	enum nvme_print_flags flags;
	struct nvme_zns_id_ctrl ctrl;
	int fd, err = -1;

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

	fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		return errno;

	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0)
		goto close_fd;

	err = nvme_zns_identify_ctrl(fd, &ctrl);
	if (!err)
		nvme_show_zns_id_ctrl(&ctrl, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		perror("zns identify controller");
close_fd:
	close(fd);
	return err;
}

static int id_ns(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Send an ZNS specific Identify Namespace command to "\
		"the given device and report information about the specified "\
		"namespace in varios formats.";
	const char *vendor_specific = "dump binary vendor fields";
	const char *human_readable = "show identify in readable format";

	enum nvme_print_flags flags;
	struct nvme_zns_id_ns ns;
	struct nvme_id_ns id_ns;
	int fd, err = -1;

	struct config {
		char *output_format;
		__u32 namespace_id;
		int human_readable;
		int vendor_specific;
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

	fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		return errno;

	flags = validate_output_format(cfg.output_format);
	if (flags < 0)
		goto close_fd;
	if (cfg.vendor_specific)
		flags |= VS;
	if (cfg.human_readable)
		flags |= VERBOSE;

	if (!cfg.namespace_id) {
		err = cfg.namespace_id = nvme_get_nsid(fd);
		if (err < 0) {
			perror("get-namespace-id");
			goto close_fd;
		}
	}

	err = nvme_identify_ns(fd, cfg.namespace_id, false, &id_ns);
	if (err) {
		nvme_show_status(err);
		goto close_fd;
	}

	err = nvme_zns_identify_ns(fd, cfg.namespace_id, &ns);
	if (!err)
		nvme_show_zns_id_ns(&ns, &id_ns, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		perror("zns identify namespace");
close_fd:
	close(fd);
	return err;
}

static int __zns_mgmt_send(int fd, __u32 namespace_id, __u64 zslba,
	bool select_all, enum nvme_zns_send_action zsa, __u32 data_len, void *buf)
{
	int err;

	err = nvme_zns_mgmt_send(fd, namespace_id, zslba, select_all, zsa,
			data_len, buf);
	close(fd);
	return err;
}

static int zns_mgmt_send(int argc, char **argv, struct command *cmd, struct plugin *plugin,
	const char *desc, enum nvme_zns_send_action zsa)
{
	const char *zslba = "starting LBA of the zone for this command";
	const char *select_all = "send command to all zones";

	int err, fd;
	char *command;

	struct config {
		__u64	zslba;
		int	namespace_id;
		bool	select_all;
	};

	struct config cfg = {
	};

	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id", 'n', &cfg.namespace_id,  namespace_id),
		OPT_SUFFIX("start-lba",  's', &cfg.zslba,         zslba),
		OPT_FLAG("select-all",   'a', &cfg.select_all,    select_all),
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		return errno;

	err = asprintf(&command, "%s-%s", plugin->name, cmd->name);
	if (err < 0)
		goto close_fd;

	if (!cfg.namespace_id) {
		err = cfg.namespace_id = nvme_get_nsid(fd);
		if (err < 0) {
			perror("get-namespace-id");
			goto free;
		}
	}

	err = __zns_mgmt_send(fd, cfg.namespace_id, cfg.zslba,
		cfg.select_all, zsa, 0, NULL);
	if (!err)
		printf("%s: Success, action:%d zone:%"PRIx64" nsid:%d\n", command,
			zsa, (uint64_t)cfg.zslba, cfg.namespace_id);
	else if (err > 0)
		nvme_show_status(err);
	else
		perror(desc);
free:
	free(command);
close_fd:
	close(fd);
	return err;
}

static int get_zdes_bytes(int fd, __u32 nsid)
{
	struct nvme_zns_id_ns ns;
	struct nvme_id_ns id_ns;
	__u8 lbaf;
	int err;

	err = nvme_identify_ns(fd, nsid,  false, &id_ns);
	if (err > 0){
		nvme_show_status(err);
		return err;
	}
	else if (err < 0){
		perror("identify namespace");
		return err;
	}

	err = nvme_zns_identify_ns(fd, nsid,  &ns);
	if (err > 0){
		nvme_show_status(err);
		return err;
	}
	else if (err < 0){
		perror("zns identify namespace");
		return err;
	}

	lbaf = id_ns.flbas & NVME_NS_FLBAS_LBA_MASK;
	return ns.lbafe[lbaf].zdes << 6;
}

static int zone_mgmt_send(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Zone Management Send";
	const char *zslba = "starting LBA of the zone for this command";
	const char *select_all = "send command to all zones";
	const char *zsa = "zone send action";
	const char *data_len = "buffer length if data required";
	const char *data = "optional file for data (default stdin)";

	int fd, ffd = STDIN_FILENO, err = -1;
	void *buf = NULL;

	struct config {
		__u64	zslba;
		int	namespace_id;
		bool	select_all;
		__u8	zsa;
		int   data_len;
		char   *file;
	};

	struct config cfg = {
	};

	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id", 'n', &cfg.namespace_id,  namespace_id),
		OPT_SUFFIX("start-lba",  's', &cfg.zslba,         zslba),
		OPT_FLAG("select-all",   'a', &cfg.select_all,    select_all),
		OPT_BYTE("zsa",          'z', &cfg.zsa,           zsa),
		OPT_UINT("data-len",     'l', &cfg.data_len,     data_len),
		OPT_FILE("data",         'd', &cfg.file,         data),
		OPT_END()
	};

	fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		return errno;

	if (!cfg.namespace_id) {
		err = cfg.namespace_id = nvme_get_nsid(fd);
		if (err < 0) {
			perror("get-namespace-id");
			goto close_fd;
		}
	}

	if (!cfg.zsa) {
		fprintf(stderr, "zone send action must be specified\n");
		err = -EINVAL;
		goto close_fd;
	}

	if (cfg.zsa == NVME_ZNS_ZSA_SET_DESC_EXT) {
		if(!cfg.data_len) {
			cfg.data_len = get_zdes_bytes(fd, cfg.namespace_id);
			if (cfg.data_len == 0) {
				fprintf(stderr, 
				"Zone Descriptor Extensions are not supported\n");
				goto close_fd;
			} else if (cfg.data_len < 0) {
				err = cfg.data_len;
				goto close_fd;
			}
		}
		if (posix_memalign(&buf, getpagesize(), cfg.data_len)) {
			fprintf(stderr, "can not allocate feature payload\n");
			goto close_fd;
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
			fprintf(stderr, 
			"data, data_len only valid with set extended descriptor\n");
			err = -EINVAL;
			goto close_fd;
		}
	}

	err = __zns_mgmt_send(fd, cfg.namespace_id, cfg.zslba, cfg.select_all,
			cfg.zsa, cfg.data_len, buf);
	if (!err)
		printf("zone-mgmt-send: Success, action:%d zone:%"PRIx64" nsid:%d\n",
			cfg.zsa, (uint64_t)cfg.zslba, cfg.namespace_id);
	else if (err > 0)
		nvme_show_status(err);
	else
		perror("zns zone-mgmt-send");

close_ffd:
	if (cfg.file)
		close(ffd);
free:
	if (buf)
		free(buf);
close_fd:
	close(fd);
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

	return zns_mgmt_send(argc, argv, cmd, plugin, desc, NVME_ZNS_ZSA_OPEN);
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
	const char *data = "optional file for zone extention data (default stdin)";

	int fd, ffd = STDIN_FILENO, err;
	void *buf = NULL;
	__u32 data_len;

	struct config {
		__u64	zslba;
		int	namespace_id;
		char   *file;
	};

	struct config cfg = {
	};

	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id", 'n', &cfg.namespace_id,  namespace_id),
		OPT_SUFFIX("start-lba",  's', &cfg.zslba,         zslba),
		OPT_FILE("data",         'd', &cfg.file,         data),
		OPT_END()
	};

	fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		return errno;

	if (!cfg.namespace_id) {
		err = cfg.namespace_id = nvme_get_nsid(fd);
		if (err < 0) {
			perror("get-namespace-id");
			goto close_fd;
		}
	}

	data_len = get_zdes_bytes(fd, cfg.namespace_id);

	if (!data_len) {
		fprintf(stderr,
			"zone format does not provide descriptor extention\n");
		errno = EINVAL;
		err = -1;
		goto close_fd;
	}

	buf = calloc(1, data_len);
	if (!buf) {
		err = -1;
		goto close_fd;
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

	err = __zns_mgmt_send(fd, cfg.namespace_id, cfg.zslba, 0,
		NVME_ZNS_ZSA_SET_DESC_EXT, data_len, buf);
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
close_fd:
	close(fd);
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

	enum nvme_print_flags flags;
	int fd, err = -1;
	void *data = NULL;

	struct config {
		char *output_format;
		__u64  zslba;
		__u32  namespace_id;
		__u16  zra;
		__u16  zrasf;
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
		OPT_SHRT("zra",           'z', &cfg.zra,            zra),
		OPT_SHRT("zrasf",         'S', &cfg.zrasf,          zrasf),
		OPT_FLAG("partial",       'p', &cfg.partial,        partial),
		OPT_UINT("data-len",      'l', &cfg.data_len,       data_len),
		OPT_END()
	};

	fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		return errno;

	flags = validate_output_format(cfg.output_format);
	if (flags < 0)
		goto close_fd;

	if (!cfg.namespace_id) {
		err = cfg.namespace_id = nvme_get_nsid(fd);
		if (err < 0) {
			perror("get-namespace-id");
			goto close_fd;
		}
	}

	if (cfg.data_len) {
		data = calloc(1, cfg.data_len);
		if (!data) {
			err = -1;
			goto close_fd;
		}
	}

	err = nvme_zns_mgmt_recv(fd, cfg.namespace_id, cfg.zslba, cfg.zra,
		cfg.zrasf, cfg.partial, cfg.data_len, data);
	if (!err)
		printf("zone-mgmt-recv: Success, action:%d zone:%"PRIx64" nsid:%d\n",
			cfg.zra, (uint64_t)cfg.zslba, cfg.namespace_id);
	else if (err > 0)
		nvme_show_status(err);
	else
		perror("zns zone-mgmt-recv");

	if (data)
		free(data);
close_fd:
	close(fd);
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
	const char *human_readable = "show report zones in readable format";

	enum nvme_print_flags flags;
	int fd, zdes = 0, err = -1;
	__u32 report_size;
	void *report;
	bool huge = false;

	struct config {
		char *output_format;
		__u64 zslba;
		__u32 namespace_id;
		int   num_descs;
		int   state;
		int   human_readable;
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
		OPT_FLAG("human-readable",'H', &cfg.human_readable, human_readable),
		OPT_FLAG("extended",      'e', &cfg.extended,       ext),
		OPT_FLAG("partial",       'p', &cfg.partial,        part),
		OPT_END()
	};

	fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		return errno;

	flags = validate_output_format(cfg.output_format);
	if (flags < 0)
		goto close_fd;
	if (cfg.human_readable)
		flags |= VERBOSE;

	if (!cfg.namespace_id) {
		err = cfg.namespace_id = nvme_get_nsid(fd);
		if (err < 0) {
			perror("get-namespace-id");
			goto close_fd;
		}
	}

	if (cfg.extended) {
		zdes = get_zdes_bytes(fd, cfg.namespace_id);
		if (zdes < 0) {
			err = zdes;
			goto close_fd;
		}
	}

	if (cfg.num_descs == -1) {
		struct nvme_zone_report r;

		err = nvme_zns_report_zones(fd, cfg.namespace_id, 0,
			0, cfg.state, 0, sizeof(r), &r);
		if (err > 0) {
			nvme_show_status(err);
			goto close_fd;
		} else if (err < 0) {
			perror("zns report-zones");
			goto close_fd;
		}
		cfg.num_descs = le64_to_cpu(r.nr_zones);
	}

	report_size = sizeof(struct nvme_zone_report) + cfg.num_descs *
		(sizeof(struct nvme_zns_desc) + cfg.num_descs * zdes);

	report = nvme_alloc(report_size, &huge);
	if (!report) {
		perror("alloc");
		err = -1;
		goto close_fd;
	}

	err = nvme_zns_report_zones(fd, cfg.namespace_id, cfg.zslba,
		cfg.extended, cfg.state, cfg.partial, report_size, report);
	if (!err)
		nvme_show_zns_report_zones(report, cfg.num_descs, zdes,
			report_size, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		perror("zns report-zones");

	nvme_free(report, huge);
close_fd:
	close(fd);
	return err;
}

static int zone_append(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "The zone append command is used to write to a zone "\
		  "using the slba of the zone, and the write will be appended from the "\
		  "write pointer of the zone";
	const char *zslba = "starting LBA of the zone";
	const char *data = "file containing data to write";
	const char *metadata = "file with metadata to be written";
	const char *limited_retry = "limit media access attempts";
	const char *fua = "force unit access";
	const char *prinfo = "protection information action and checks field";
	const char *ref_tag = "reference tag (for end to end PI)";
	const char *lbat = "logical block application tag (for end to end PI)";
	const char *lbatm = "logical block application tag mask (for end to end PI)";
	const char *metadata_size = "size of metadata in bytes";
	const char *data_size = "size of data in bytes";
	const char *latency = "output latency statistics";

	int err = -1, fd, dfd = STDIN_FILENO, mfd = STDIN_FILENO;
	unsigned int lba_size, meta_size;
	void *buf = NULL, *mbuf = NULL;
	__u16 nblocks, control = 0;
	__u64 result;
	struct timeval start_time, end_time;

	struct nvme_id_ns ns;

	struct config {
		char  *data;
		char  *metadata;
		__u64  zslba;
		__u64  data_size;
		__u64  metadata_size;
		int    limited_retry;
		int    fua;
		int    namespace_id;
		__u32  ref_tag;
		__u16  lbat;
		__u16  lbatm;
		__u8   prinfo;
		int   latency;
	};

	struct config cfg = {
	};

	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id", 'n', &cfg.namespace_id,  namespace_id),
		OPT_SUFFIX("zslba",           's', &cfg.zslba,         zslba),
		OPT_SUFFIX("data-size",       'z', &cfg.data_size,     data_size),
		OPT_SUFFIX("metadata-size",   'y', &cfg.metadata_size, metadata_size),
		OPT_FILE("data",              'd', &cfg.data,          data),
		OPT_FILE("metadata",          'M', &cfg.metadata,      metadata),
		OPT_FLAG("limited-retry",     'l', &cfg.limited_retry, limited_retry),
		OPT_FLAG("force-unit-access", 'f', &cfg.fua,           fua),
		OPT_UINT("ref-tag",           'r', &cfg.ref_tag,       ref_tag),
		OPT_SHRT("app-tag-mask",      'm', &cfg.lbatm,         lbatm),
		OPT_SHRT("app-tag",           'a', &cfg.lbat,          lbat),
		OPT_BYTE("prinfo",            'p', &cfg.prinfo,        prinfo),
		OPT_FLAG("latency",           't', &cfg.latency,       latency),
		OPT_END()
	};

	fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		return errno;

	if (!cfg.data_size) {
		fprintf(stderr, "Append size not provided\n");
		errno = EINVAL;
		goto close_fd;
	}

	if (!cfg.namespace_id) {
		err = cfg.namespace_id = nvme_get_nsid(fd);
		if (err < 0) {
			perror("get-namespace-id");
			goto close_fd;
		}
	}

	err = nvme_identify_ns(fd, cfg.namespace_id, false, &ns);
	if (err) {
		nvme_show_status(err);
		goto close_fd;
	}

	lba_size = 1 << ns.lbaf[(ns.flbas & 0x0f)].ds;
	if (cfg.data_size & (lba_size - 1)) {
		fprintf(stderr,
			"Data size:%#"PRIx64" not aligned to lba size:%#x\n",
			(uint64_t)cfg.data_size, lba_size);
		errno = EINVAL;
		goto close_ns;
	}

	meta_size = ns.lbaf[(ns.flbas & 0x0f)].ms;
	if (meta_size && (!cfg.metadata_size || cfg.metadata_size % meta_size)) {
		fprintf(stderr,
			"Metadata size:%#"PRIx64" not aligned to metadata size:%#x\n",
			(uint64_t)cfg.metadata_size, meta_size);
		errno = EINVAL;
		goto close_ns;
	}

	if (cfg.prinfo > 0xf) {
	        fprintf(stderr, "Invalid value for prinfo:%#x\n", cfg.prinfo);
		errno = EINVAL;
		goto close_ns;
	}

	if (cfg.data) {
		dfd = open(cfg.data, O_RDONLY);
		if (dfd < 0) {
			perror(cfg.data);
			goto close_ns;
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
			goto close_dfd;
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
		control |= NVME_RW_LR;
	if (cfg.fua)
		control |= NVME_RW_FUA;

	gettimeofday(&start_time, NULL);
	err = nvme_zns_append(fd, cfg.namespace_id, cfg.zslba, nblocks,
			      control, cfg.ref_tag, cfg.lbat, cfg.lbatm,
			      cfg.data_size, buf, cfg.metadata_size, mbuf,
			      &result);
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
close_ns:
close_fd:
	close(fd);
	return err;
}

static int changed_zone_list(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Retrieve Changed Zone log for the given device";
	const char *rae = "retain an asynchronous event";

	struct nvme_zns_changed_zone_log log;
	enum nvme_print_flags flags;
	int fd, err = -1;

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

	fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		return errno;

	flags = validate_output_format(cfg.output_format);
	if (flags < 0)
		goto close_fd;

	if (!cfg.namespace_id) {
		err = cfg.namespace_id = nvme_get_nsid(fd);
		if (err < 0) {
			perror("get-namespace-id");
			goto close_fd;
		}
	}

	err = nvme_get_log(fd, cfg.namespace_id, NVME_LOG_ZONE_CHANGED_LIST, 
						cfg.rae, NVME_NO_LOG_LSP, sizeof(log), &log);
	if (!err)
		nvme_show_zns_changed(&log, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		perror("zns changed-zone-list");

close_fd:
	close(fd);
	return err;
}
