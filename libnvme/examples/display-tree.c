// SPDX-License-Identifier: LGPL-2.1-or-later
/**
 * This file is part of libnvme.
 * Copyright (c) 2020 Western Digital Corporation or its affiliates.
 *
 * Authors: Keith Busch <keith.busch@wdc.com>
 */

/**
 * display-tree: Scans the nvme topology, prints as an ascii tree with some
 * selected attributes for each component.
 */
#include <stdio.h>
#include <inttypes.h>
#include <libnvme.h>

int main()
{
	nvme_root_t r;
	nvme_host_t h;
	nvme_subsystem_t s, _s;
	nvme_ctrl_t c, _c;
	nvme_path_t p, _p;
	nvme_ns_t n, _n;

	r = nvme_scan(NULL);
	if (!r)
		return -1;

	printf(".\n");
	nvme_for_each_host(r, h) {
		nvme_for_each_subsystem_safe(h, s, _s) {
			printf("%c-- %s - NQN=%s\n", _s ? '|' : '`',
			       nvme_subsystem_get_name(s),
			       nvme_subsystem_get_nqn(s));

			nvme_subsystem_for_each_ns_safe(s, n, _n) {
				printf("%c   |-- %s lba size:%d lba max:%" PRIu64 "\n",
				       _s ? '|' : ' ',
				       nvme_ns_get_name(n),
				       nvme_ns_get_lba_size(n),
				       nvme_ns_get_lba_count(n));
			}

			nvme_subsystem_for_each_ctrl_safe(s, c, _c) {
				printf("%c   %c-- %s %s %s %s\n",
				       _s ? '|' : ' ', _c ? '|' : '`',
				       nvme_ctrl_get_name(c),
				       nvme_ctrl_get_transport(c),
				       nvme_ctrl_get_address(c),
				       nvme_ctrl_get_state(c));

				nvme_ctrl_for_each_ns_safe(c, n, _n)
					printf("%c   %c   %c-- %s lba size:%d lba max:%" PRIu64 "\n",
					       _s ? '|' : ' ', _c ? '|' : ' ',
					       _n ? '|' : '`',
					       nvme_ns_get_name(n),
					       nvme_ns_get_lba_size(n),
					       nvme_ns_get_lba_count(n));

				nvme_ctrl_for_each_path_safe(c, p, _p)
					printf("%c   %c   %c-- %s %s\n",
					       _s ? '|' : ' ', _c ? '|' : ' ',
					       _p ? '|' : '`',
					       nvme_path_get_name(p),
					       nvme_path_get_ana_state(p));
			}
		}
	}
	nvme_free_tree(r);
	return 0;
}
