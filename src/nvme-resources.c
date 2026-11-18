// SPDX-License-Identifier: GPL-2.0-or-later

#include <libnvme.h>

#include "nvme-resources.h"

static void htable_ctrl_add_unique(struct htable_ctrl *ht,
				   struct libnvme_ctrl *c)
{
	if (htable_ctrl_get(ht, libnvme_ctrl_get_name(c)))
		return;

	htable_ctrl_add(ht, c);
}

static void htable_ns_add_unique(struct htable_ns *ht, struct libnvme_ns *n)
{
	struct htable_ns_iter it;
	struct libnvme_ns *_n;

	/*
	 * Test if namespace pointer is already in the hash, and thus avoid
	 * inserting severaltimes the same pointer.
	 */
	for (_n = htable_ns_getfirst(ht, libnvme_ns_get_name(n), &it);
	     _n;
	     _n = htable_ns_getnext(ht, libnvme_ns_get_name(n), &it)) {
		if (_n == n)
			return;
	}
	htable_ns_add(ht, n);
}

int nvme_resources_init(struct libnvme_global_ctx *ctx,
			struct nvme_resources *res)
{
	struct libnvme_host *h;
	struct libnvme_subsystem *s;
	struct libnvme_ctrl *c;
	struct libnvme_ns *n;
	struct libnvme_path *p;

	res->ctx = ctx;
	htable_subsys_init(&res->ht_s);
	htable_ctrl_init(&res->ht_c);
	htable_ns_init(&res->ht_n);
	strset_init(&res->subsystems);
	strset_init(&res->ctrls);
	strset_init(&res->namespaces);

	libnvme_for_each_host(ctx, h) {
		libnvme_for_each_subsystem(h, s) {
			htable_subsys_add(&res->ht_s, s);
			strset_add(&res->subsystems,
				   libnvme_subsystem_get_name(s));

			libnvme_subsystem_for_each_ctrl(s, c) {
				htable_ctrl_add_unique(&res->ht_c, c);
				strset_add(&res->ctrls,
					   libnvme_ctrl_get_name(c));

				libnvme_ctrl_for_each_ns(c, n) {
					htable_ns_add_unique(&res->ht_n, n);
					strset_add(&res->namespaces,
						   libnvme_ns_get_name(n));
				}

				libnvme_ctrl_for_each_path(c, p) {
					n = libnvme_path_get_ns(p);
					if (!n)
						continue;
					htable_ns_add_unique(&res->ht_n, n);
					strset_add(&res->namespaces,
						   libnvme_ns_get_name(n));
				}
			}

			libnvme_subsystem_for_each_ns(s, n) {
				htable_ns_add_unique(&res->ht_n, n);
				strset_add(&res->namespaces,
					   libnvme_ns_get_name(n));
			}
		}
	}

	return 0;
}

void nvme_resources_free(struct nvme_resources *res)
{
	strset_clear(&res->namespaces);
	strset_clear(&res->ctrls);
	strset_clear(&res->subsystems);
	htable_ns_clear(&res->ht_n);
	htable_ctrl_clear(&res->ht_c);
	htable_subsys_clear(&res->ht_s);
}
