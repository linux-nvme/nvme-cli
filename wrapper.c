// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This file is part of nvme-cli
 *
 * Copyright (c) 2022 Daniel Wagner, SUSE
 */

#include <dlfcn.h>

#include <libnvme.h>

#define PROTO(args...) args
#define ARGS(args...) args

#define VOID_FN(name, proto, args)				\
void __attribute__((weak)) name(proto)				\
{								\
	void (*fn)(proto);					\
	fn = dlsym(RTLD_NEXT, #name);				\
	if (fn)							\
		fn(args);					\
}

#define FN(name, rtype, proto, args, fallback)			\
rtype __attribute__((weak)) name(proto)				\
{								\
	rtype (*fn)(proto);					\
	fn = dlsym(RTLD_NEXT, #name);				\
	if (fn)							\
		return fn(args);				\
	return fallback;					\
}

FN(nvme_get_version,
	const char *, PROTO(enum nvme_version type),
	ARGS(type), "n/a")

VOID_FN(nvme_init_copy_range_f1,
	PROTO(struct nvme_copy_range_f1 *copy, __u16 *nlbs,
	      __u64 *slbas, __u64 *eilbrts, __u32 *elbatms,
	      __u32 *elbats, __u16 nr),
	ARGS(copy, nlbs, slbas, eilbrts, elbatms, elbats, nr))
