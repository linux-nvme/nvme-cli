// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2020 Western Digital Corporation or its affiliates.
 *
 * Authors: Keith Busch <keith.busch@wdc.com>
 */

/*
 * display-tree: Scans the nvme topology, prints as an ascii tree with some
 * selected attributes for each component.
 */
#include <stdio.h>
#include <inttypes.h>
#include <libnvme.h>

int main()
{
	struct libnvme_global_ctx *ctx;
	libnvme_host_t h;
	libnvme_subsystem_t s, _s;
	libnvme_ctrl_t c, _c;
	libnvme_path_t p, _p;
	libnvme_ns_t n, _n;
	int err;

	ctx = libnvme_create_global_ctx(stdout, LIBNVME_DEFAULT_LOGLEVEL);
	if (!ctx)
		return 1;

	err = libnvme_scan_topology(ctx, NULL, NULL);
	if (err) {
		libnvme_free_global_ctx(ctx);
		return 1;
	}

	printf(".\n");
	libnvme_for_each_host(ctx, h) {
		libnvme_for_each_subsystem_safe(h, s, _s) {
			printf("%c-- %s - NQN=%s\n", _s ? '|' : '`',
			       libnvme_subsystem_get_name(s),
			       libnvme_subsystem_get_subsysnqn(s));

			libnvme_subsystem_for_each_ns_safe(s, n, _n) {
				printf("%c   |-- %s lba size:%d lba max:%" PRIu64 "\n",
				       _s ? '|' : ' ',
				       libnvme_ns_get_name(n),
				       libnvme_ns_get_lba_size(n),
				       libnvme_ns_get_lba_count(n));
			}

			libnvme_subsystem_for_each_ctrl_safe(s, c, _c) {
				printf("%c   %c-- %s %s %s %s\n",
				       _s ? '|' : ' ', _c ? '|' : '`',
				       libnvme_ctrl_get_name(c),
				       libnvme_ctrl_get_transport(c),
				       libnvme_ctrl_get_traddr(c),
				       libnvme_ctrl_get_state(c));

				libnvme_ctrl_for_each_ns_safe(c, n, _n)
					printf("%c   %c   %c-- %s lba size:%d lba max:%" PRIu64 "\n",
					       _s ? '|' : ' ', _c ? '|' : ' ',
					       _n ? '|' : '`',
					       libnvme_ns_get_name(n),
					       libnvme_ns_get_lba_size(n),
					       libnvme_ns_get_lba_count(n));

				libnvme_ctrl_for_each_path_safe(c, p, _p)
					printf("%c   %c   %c-- %s %s\n",
					       _s ? '|' : ' ', _c ? '|' : ' ',
					       _p ? '|' : '`',
					       libnvme_path_get_name(p),
					       libnvme_path_get_ana_state(p));
			}
		}
	}
	libnvme_free_global_ctx(ctx);
	return 0;
}
