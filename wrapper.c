// SPDX-License-Identifier: GPL-2.0-only
/*
 * This file is part of nvme-cli
 *
 * Copyright (c) 2022 Daniel Wagner, SUSE
 */

#include <dlfcn.h>

#include <libnvme.h>

const char * __attribute__((weak)) nvme_get_version(enum nvme_version type)
{
	const char *(*libnvme_get_version)(enum nvme_version type);

	libnvme_get_version = dlsym(RTLD_NEXT, "nvme_get_version");

	if (libnvme_get_version)
		return libnvme_get_version(type);

	return "n/a";
}

void __attribute__((weak))
nvme_init_copy_range_f1(struct nvme_copy_range_f1 *copy, __u16 *nlbs,
		        __u64 *slbas, __u64 *eilbrts, __u32 *elbatms,
			__u32 *elbats, __u16 nr)
{
}
