// SPDX-License-Identifier: GPL-2.0-or-later

#include <stdio.h>

#include <libnvme.h>

#include "cmds-admin-print.h"
#include "nvme-print.h"
#include "nvme-resources.h"

static struct admin_print_ops admin_stdout_print_ops;

static void stdout_relatives(struct libnvme_global_ctx *ctx, const char *name)
{
	struct nvme_resources res;
	struct htable_ns_iter it;
	bool block = true;
	bool first = true;
	struct libnvme_ctrl *c;
	struct libnvme_path *p;
	struct libnvme_ns *n;
	int nsid;
	int ret;
	int id;

	ret = sscanf(name, "nvme%dn%d", &id, &nsid);

	switch (ret) {
	case 1:
		block = false;
		break;
	case 2:
		break;
	default:
		return;
	}

	nvme_resources_init(ctx, &res);

	if (block) {
		fprintf(stderr,
			"Namespace %s has parent controller(s):", name);
		for (n = htable_ns_getfirst(&res.ht_n, name, &it); n;
		     n = htable_ns_getnext(&res.ht_n, name, &it)) {
			if (libnvme_ns_get_ctrl(n)) {
				c = libnvme_ns_get_ctrl(n);
				fprintf(stderr, "%s", libnvme_ctrl_get_name(c));
				break;
			}
			libnvme_namespace_for_each_path(n, p) {
				c = libnvme_path_get_ctrl(p);
				fprintf(stderr, "%s%s", first ? "" : ", ",
					libnvme_ctrl_get_name(c));
				if (first)
					first = false;
			}
		}
		fprintf(stderr, "\n\n");
	} else {
		c = htable_ctrl_get(&res.ht_c, name);
		if (c) {
			fprintf(stderr,
				"Controller %s has child namespace(s):", name);
			libnvme_ctrl_for_each_ns(c, n) {
				fprintf(stderr, "%s%s", first ? "" : ", ",
					libnvme_ns_get_name(n));
				if (first)
					first = false;
			}
			fprintf(stderr, "\n\n");
		}
	}

	nvme_resources_free(&res);
}

static struct admin_print_ops admin_stdout_print_ops = {
	.relatives	= stdout_relatives,
};

struct admin_print_ops *admin_get_stdout_print_ops(nvme_print_flags_t flags)
{
	admin_stdout_print_ops.flags = flags;
	return &admin_stdout_print_ops;
}
