/* SPDX-License-Identifier: GPL-2.0-or-later */
#pragma once

#include <libnvme.h>

#include <ccan/hash/hash.h>
#include <ccan/htable/htable.h>
#include <ccan/htable/htable_type.h>
#include <ccan/str/str.h>
#include <ccan/strset/strset.h>

/*
 * The subsystems, controllers and namespaces of a libnvme tree, by name.
 * A namespace may be found more than once under the same name.
 */
static inline const char *subsys_key(const struct libnvme_subsystem *s)
{
	return libnvme_subsystem_get_name((struct libnvme_subsystem *)s);
}

static inline const char *ctrl_key(const struct libnvme_ctrl *c)
{
	return libnvme_ctrl_get_name((struct libnvme_ctrl *)c);
}

static inline const char *ns_key(const struct libnvme_ns *n)
{
	return libnvme_ns_get_name((struct libnvme_ns *)n);
}

static inline bool subsys_cmp(const struct libnvme_subsystem *s,
			      const char *name)
{
	return streq(libnvme_subsystem_get_name((struct libnvme_subsystem *)s),
		     name);
}

static inline bool ctrl_cmp(const struct libnvme_ctrl *c, const char *name)
{
	return streq(libnvme_ctrl_get_name((struct libnvme_ctrl *)c), name);
}

static inline bool ns_cmp(const struct libnvme_ns *n, const char *name)
{
	return streq(libnvme_ns_get_name((struct libnvme_ns *)n), name);
}

HTABLE_DEFINE_TYPE(struct libnvme_subsystem, subsys_key, hash_string,
		   subsys_cmp, htable_subsys);
HTABLE_DEFINE_TYPE(struct libnvme_ctrl, ctrl_key, hash_string,
		   ctrl_cmp, htable_ctrl);
HTABLE_DEFINE_TYPE(struct libnvme_ns, ns_key, hash_string,
		   ns_cmp, htable_ns);

struct nvme_resources {
	struct libnvme_global_ctx *ctx;

	struct htable_subsys ht_s;
	struct htable_ctrl ht_c;
	struct htable_ns ht_n;
	struct strset subsystems;
	struct strset ctrls;
	struct strset namespaces;
};

int nvme_resources_init(struct libnvme_global_ctx *ctx,
			struct nvme_resources *res);
void nvme_resources_free(struct nvme_resources *res);
