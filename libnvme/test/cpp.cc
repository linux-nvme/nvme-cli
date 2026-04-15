// SPDX-License-Identifier: LGPL-2.1-or-later
/**
 * This file is part of libnvme.
 * Copyright (c) 2020 Western Digital Corporation or its affiliates.
 *
 * Authors: Keith Busch <keith.busch@wdc.com>
 */

#include <iostream>

#include <libnvme.h>

int main()
{
	struct libnvme_global_ctx *ctx;
	libnvme_host_t h;
	libnvme_subsystem_t s;
	libnvme_ctrl_t c;
	libnvme_path_t p;
	libnvme_ns_t n;
	int err;

	ctx = libnvme_create_global_ctx(stdout, LIBNVME_DEFAULT_LOGLEVEL);
	if (!ctx)
		return 1;

	err = libnvme_scan_topology(ctx, NULL, NULL);
	if (err && !(err == -ENOENT || err == -EACCES)) {
		fprintf(stderr, "libnvme_scan_topology failed %d\n", err);
		libnvme_free_global_ctx(ctx);
		return 1;
	}

	libnvme_for_each_host(ctx, h) {
		libnvme_for_each_subsystem(h, s) {
			std::cout <<  libnvme_subsystem_get_name(s)
				  << " - NQN=" << libnvme_subsystem_get_subsysnqn(s)
				  << "\n";
			libnvme_subsystem_for_each_ctrl(s, c) {
				std::cout << " `- " << libnvme_ctrl_get_name(c)
					  << " " << libnvme_ctrl_get_transport(c)
					  << " " << libnvme_ctrl_get_traddr(c)
					  << " " << libnvme_ctrl_get_state(c)
					  << "\n";
				libnvme_ctrl_for_each_ns(c, n) {
					std::cout << "   `- "
						  << libnvme_ns_get_name(n)
						  << "lba size:"
						  << libnvme_ns_get_lba_size(n)
						  << " lba max:"
						  << libnvme_ns_get_lba_count(n)
						  << "\n";
				}
				libnvme_ctrl_for_each_path(c, p) {
					std::cout << "   `- "
						  << libnvme_path_get_name(p)
						  << " "
						  << libnvme_path_get_ana_state(p)
						  << "\n";
				}
			}
			libnvme_subsystem_for_each_ns(s, n) {
				std::cout << "   `- " << libnvme_ns_get_name(n)
					  << "lba size:"
					  << libnvme_ns_get_lba_size(n)
					  << " lba max:"
					  << libnvme_ns_get_lba_count(n) << "\n";
			}
		}
	}
	std::cout << "\n";

	libnvme_free_global_ctx(ctx);

	return 0;
}
