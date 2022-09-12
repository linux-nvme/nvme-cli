// SPDX-License-Identifier: GPL-2.0-or-later

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>
#include <errno.h>
#include <limits.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>

#include <sys/stat.h>
#include <sys/ioctl.h>

#include "common.h"
#include "nvme.h"
#include "libnvme.h"
#include "nvme-print.h"
#include "plugin.h"
#include "nvme/tree.h"
#include "nvme/private.h"

#include "util/logging.h"
#include "util/suffix.h"

#define CREATE_CMD
#include "spdk-nvme.h"

static struct stat nvme_stat;
static char *spdk_dev = "/dev/spdk";

static char *output_format_val = "normal";

#define NVME_ARGS(n, c, ...)                                                      \
	struct argconfig_commandline_options n[] = {                              \
		OPT_FLAG("verbose",      'v', NULL,               verbose),       \
		OPT_FMT("output-format", 'o', &output_format_val, output_format), \
		##__VA_ARGS__,                                                    \
		OPT_END()                                                         \
	}

static bool is_chardev(void)
{
	return S_ISCHR(nvme_stat.st_mode);
}

static bool is_blkdev(void)
{
	return S_ISBLK(nvme_stat.st_mode);
}

static bool nvme_match_device_filter(nvme_subsystem_t s,
		nvme_ctrl_t c, nvme_ns_t ns, void *f_args)
{
	int ret, instance, nsid, s_num;
	char *devname = f_args;

	if (!devname || !strlen(devname))
		return true;

	ret = sscanf(devname, "nvme%dn%d", &instance, &nsid);
	// Check number of input items successfully matched
	if (ret != 2)
		return true;

	if (s) {
		ret = sscanf(nvme_subsystem_get_name(s), "nvme%d",
			     &s_num);
		if (ret == 1 && s_num == instance)
			return true;
	}

	if (c) {
		s = nvme_ctrl_get_subsystem(c);

		ret = sscanf(nvme_subsystem_get_name(s), "nvme%d",
			     &s_num);
		if (ret == 1 && s_num == instance)
			return true;
	}

	if (ns) {
		if (!strcmp(devname, nvme_ns_get_name(ns)))
			return true;
	}

	return false;
}

static int spdk_open_dev(char *dev, int flags)
{
	int err, fd;

	err = open(dev, flags);
	if (err < 0)
		goto perror;

	fd = err;

	err = fstat(fd, &nvme_stat);
	if (err < 0) {
		close(fd);
		goto perror;
	}

	if (!is_chardev() && !is_blkdev()) {
		fprintf(stderr, "%s is not a block or character device\n", dev);
		close(fd);
		return -ENODEV;
	}

	return fd;
perror:
	perror(dev);
	return err;
}

static inline void spdk_nvme_id_ns_flbas_to_lbaf_inuse(__u8 flbas, __u8 *lbaf_inuse)
{
	*lbaf_inuse = (((flbas & NVME_NS_FLBAS_HIGHER_MASK) >> 1) |
			(flbas & NVME_NS_FLBAS_LOWER_MASK));
}

static void _nvme_ns_set_names(struct nvme_ns *n, const char *name)
{
	char nname[PATH_MAX];

	sprintf(nname, "%s/%s", spdk_dev, name);
	n->generic_name = strdup(nname);
	n->name = strdup(nname);
}

static int spdk_nvme_ns_init(struct nvme_ns *n)
{
	struct nvme_id_ns ns = { };
	uint8_t flbas;
	int ret;

	ret = nvme_ns_identify(n, &ns);
	if (ret)
		return ret;

	spdk_nvme_id_ns_flbas_to_lbaf_inuse(ns.flbas, &flbas);
	n->lba_shift = ns.lbaf[flbas].ds;
	n->lba_size = 1 << n->lba_shift;
	n->lba_count = le64_to_cpu(ns.nsze);
	n->lba_util = le64_to_cpu(ns.nuse);
	n->meta_size = le16_to_cpu(ns.lbaf[flbas].ms);

	return 0;
}

static nvme_ns_t nvme_ns_open(const char *name, char *path)
{
	struct nvme_ns *n;

	n = calloc(1, sizeof(*n));
	if (!n)
		return NULL;

	_nvme_ns_set_names(n, name);
	n->fd = spdk_open_dev(path, O_RDONLY);
	if (n->fd < 0)
		goto free_ns;

	if (nvme_get_nsid(n->fd, &n->nsid) < 0)
		goto close_fd;

	if (spdk_nvme_ns_init(n) != 0)
		goto close_fd;

	list_head_init(&n->paths);
	list_node_init(&n->entry);

	return n;

close_fd:
	close(n->fd);
free_ns:
	free(n->name);
	free(n);

	return NULL;
}

/* Since some data are not null terminated, trim trailing spaces */
static void trim(char **p)
{
	if (!p)
		return;

	char *tmp = *p;

	if (!tmp)
		return;

	for (int i = strlen(tmp) - 1; i >= 0; --i) {
		if (tmp[i] != ' ') {
			tmp[i + 1] = '\0';
			break;
		}
	}
}

#define SPDK_NVMF_TRSTRING_MAX_LEN 32
#define SPDK_NVMF_TRADDR_MAX_LEN 256

struct spdk_transport {
	char trstring[SPDK_NVMF_TRSTRING_MAX_LEN + 1];
	char traddr[SPDK_NVMF_TRADDR_MAX_LEN + 1];
};

#define SPDK_GET_TRANSPORT _IOWR('n', 0x1, struct spdk_transport)

static void spdk_identify(nvme_root_t r)
{
	int64_t nr_ctrlr = 0;
	int fd = 0, err = 0;
	char *path = NULL;
	char *host_traddr = NULL, *host_iface = NULL;
	char *trsvcid = NULL;

	nvme_host_t  h = NULL;
	nvme_ctrl_t  c = NULL, p = NULL;
	struct dirent **ctrlrs, **namespaces;
	struct spdk_transport tr;
	struct nvme_subsystem *s = NULL;
	struct nvme_id_ctrl ctrl;

	h = nvme_default_host(r);

	nr_ctrlr = scandir(spdk_dev, &ctrlrs, nvme_ctrls_filter, alphasort);
	for (int i = 0; i < nr_ctrlr; i++) {
		if (asprintf(&path, "%s/%s", spdk_dev, ctrlrs[i]->d_name) < 0)
			goto close_fd;

		fd = spdk_open_dev(path, O_RDONLY);
		if (!fd)
			return;

		err = nvme_identify_ctrl(fd, &ctrl);
		if (err < 0)
			goto close_fd;

		/* get traddr and trstring using spdk-cuse ioctl */
		err = ioctl(fd, SPDK_GET_TRANSPORT, &tr);
		if (err < 0)
			goto close_fd;

		s = nvme_lookup_subsystem(h, ctrlrs[i]->d_name, ctrl.subnqn);
		c = nvme_lookup_ctrl(s, tr.trstring, tr.traddr, host_traddr,
				     host_iface, trsvcid, p);

		if (!c)
			goto close_fd;

		c->fd = fd;
		/* c->traddr is not the same as c->address, so copy it here too */
		c->address  = strdup(tr.traddr);
		c->name  = strdup(path);
		trim(&c->name);
		c->model = strndup(ctrl.mn, sizeof(ctrl.mn));
		trim(&c->model);
		c->firmware = strndup(ctrl.fr, sizeof(ctrl.fr));
		trim(&c->firmware);
		c->serial = strndup(ctrl.sn, sizeof(ctrl.sn));
		trim(&c->serial);
		free(path);

		int ns_nr = scandir(spdk_dev, &namespaces, nvme_namespace_filter, alphasort);

		for (int j = 0; j < ns_nr; j++) {
			if (!s->name || strncmp(s->name, namespaces[j]->d_name, strlen(s->name))) {
				free(namespaces[j]);
				continue;
			}

			if (asprintf(&path, "%s/%s", spdk_dev, namespaces[j]->d_name) < 0)
				goto close_fd;

			nvme_ns_t ns = nvme_ns_open(namespaces[j]->d_name, path);

			ns->s = s;
			ns->c = c;
			list_add(&c->namespaces, &ns->entry);

			free(path);
			free(namespaces[j]);
		}

		free(namespaces);
		free(ctrlrs[i]);

		if (fd) {
			close(fd);
			fd = 0;
		}
	}

	free(ctrlrs);
close_fd:
	if (fd)
		close(fd);
}

static int spdk_list(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Retrieve basic information for all NVMe namespaces";
	const char *verbose = "Increase output verbosity";
	enum nvme_print_flags flags;
	nvme_root_t r;
	int err = 0;

	NVME_ARGS(opts, cfg);

	err = argconfig_parse(argc, argv, desc, opts);
	if (err < 0)
		return err;

	err = validate_output_format(output_format_val, &flags);
	if (err < 0 || (flags != JSON && flags != NORMAL)) {
		nvme_show_error("Invalid output format");
		return -EINVAL;
	}

	if (argconfig_parse_seen(opts, "verbose"))
		flags |= VERBOSE;

	r = nvme_create_root(stderr, map_log_level(!!(flags & VERBOSE), false));
	if (!r) {
		nvme_show_error("Failed to create topology root: %s", nvme_strerror(errno));
		return -errno;
	}
	err = nvme_scan_topology(r, NULL, NULL);
	if (err < 0) {
		nvme_show_error("Failed to scan topology: %s", nvme_strerror(errno));
		nvme_free_tree(r);
		return err;
	}

	spdk_identify(r);

	nvme_show_list_items(r, flags);
	nvme_free_tree(r);

	return err;
}

static int spdk_list_subsys(int argc, char **argv, struct command *cmd,
		struct plugin *plugin)
{
	nvme_root_t r = NULL;
	enum nvme_print_flags flags;
	const char *desc = "Retrieve information for subsystems";
	const char *verbose = "Increase output verbosity";
	nvme_scan_filter_t filter = NULL;
	char *devname;
	int err;
	int nsid = NVME_NSID_ALL;

	NVME_ARGS(opts, cfg);

	err = argconfig_parse(argc, argv, desc, opts);
	if (err < 0)
		goto ret;

	devname = NULL;
	if (optind < argc)
		devname = basename(argv[optind++]);

	err = validate_output_format(output_format_val, &flags);
	if (err < 0 || (flags != JSON && flags != NORMAL)) {
		nvme_show_error("Invalid output format");
		return -EINVAL;
	}

	if (argconfig_parse_seen(opts, "verbose"))
		flags |= VERBOSE;

	r = nvme_create_root(stderr, map_log_level(!!(flags & VERBOSE), false));
	if (!r) {
		if (devname)
			nvme_show_error("Failed to scan nvme subsystem for %s", devname);
		else
			nvme_show_error("Failed to scan nvme subsystem");
		err = -errno;
		goto ret;
	}

	if (devname) {
		int subsys_num;

		if (sscanf(devname, "nvme%dn%d", &subsys_num, &nsid) != 2) {
			nvme_show_error("Invalid device name %s", devname);
			err = -EINVAL;
			goto ret;
		}
		filter = nvme_match_device_filter;
	}

	err = nvme_scan_topology(r, filter, (void *)devname);
	if (err) {
		nvme_show_error("Failed to scan topology: %s", nvme_strerror(errno));
		goto ret;
	}

	spdk_identify(r);

	nvme_show_subsystem_list(r, nsid != NVME_NSID_ALL, flags);

ret:
	if (r)
		nvme_free_tree(r);
	return err;
}
