// SPDX-License-Identifier: GPL-2.0-or-later

#include <stdio.h>
#include <sys/stat.h>

#include <libnvme.h>

#include <shared/string-util.h>

#include "cmds-list-print.h"
#include "nvme-print.h"

/*
 * Run the printers in process: they read sysfs while printing. Like
 * nvme_print(), silently skip printers that an output format does not
 * implement.
 */
#define cmds_list_print(name, flags, ...)				\
	do {								\
		struct cmds_list_print_ops *__lops =			\
			cmds_list_print_ops(flags);			\
									\
		if (__lops && __lops->name)				\
			nvme_print_decoder(__lops, name, false, flags,	\
					   ##__VA_ARGS__);		\
	} while (false)

static struct cmds_list_print_ops *cmds_list_print_ops(nvme_print_flags_t flags)
{
	struct cmds_list_print_ops *ops = NULL;

	if (flags & JSON || nvme_is_output_format_json())
		ops = cmds_list_get_json_print_ops(flags);
	else if (!(flags & BINARY))
		ops = cmds_list_get_stdout_print_ops(flags);

	return ops;
}

void nvme_dev_full_path(struct libnvme_ns *n, char *path, size_t len)
{
	struct stat st;

	snprintf(path, len, "%s", libnvme_ns_get_name(n));
	if (shr_startswith(path, "/dev/spdk/") && stat(path, &st) == 0)
		return;

	snprintf(path, len, "/dev/%s", libnvme_ns_get_name(n));
	if (stat(path, &st) == 0)
		return;
	/*
	 * We could start trying to search for it but let's make
	 * it simple and just don't show the path at all.
	 */
	snprintf(path, len, "%s", libnvme_ns_get_name(n));
}

void nvme_generic_full_path(struct libnvme_ns *n, char *path, size_t len)
{
	int head_instance;
	int instance;
	struct stat st;

	/*
	 * There is no block devices for SPDK, point generic path to existing
	 * chardevice.
	 */
	snprintf(path, len, "%s", libnvme_ns_get_name(n));
	if (shr_startswith(path, "/dev/spdk/") && stat(path, &st) == 0)
		return;

	if (sscanf(libnvme_ns_get_name(n), "nvme%dn%d", &instance,
		   &head_instance) != 2)
		return;

	snprintf(path, len, "/dev/ng%dn%d", instance, head_instance);

	if (stat(path, &st) == 0)
		return;
	/*
	 * We could start trying to search for it but let's make
	 * it simple and just don't show the path at all.
	 */
	snprintf(path, len, "%s", libnvme_ns_get_generic_name(n));
}

void nvme_show_list_item(struct libnvme_ns *n, struct shr_table *t)
{
	cmds_list_print(list_item, NORMAL, n, t);
}

void nvme_show_list_items(struct libnvme_global_ctx *ctx,
			  nvme_print_flags_t flags)
{
	cmds_list_print(list_items, flags, ctx);
}

void nvme_show_subsystem_list(struct libnvme_global_ctx *ctx, bool show_ana,
			      nvme_print_flags_t flags)
{
	cmds_list_print(print_nvme_subsystem_list, flags, ctx, show_ana);
}

void nvme_show_top(nvme_print_flags_t flags, int refresh_interval)
{
	cmds_list_print(top, flags, refresh_interval);
}

void nvme_show_topology(struct libnvme_global_ctx *ctx,
			enum nvme_cli_topo_ranking ranking,
			nvme_print_flags_t flags)
{
	if (ranking == NVME_CLI_TOPO_NAMESPACE)
		cmds_list_print(topology_namespace, flags, ctx);
	else if (ranking == NVME_CLI_TOPO_CTRL)
		cmds_list_print(topology_ctrl, flags, ctx);
	else
		cmds_list_print(topology_multipath, flags, ctx);
}

void nvme_show_topology_tabular(struct libnvme_global_ctx *ctx,
				nvme_print_flags_t flags)
{
	cmds_list_print(topology_tabular, flags, ctx);
}
