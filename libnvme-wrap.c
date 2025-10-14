// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This file is part of nvme-cli
 *
 * Copyright (c) 2022 Daniel Wagner, SUSE
 */

#include <dlfcn.h>
#include <errno.h>
#include <stdlib.h>

#include <libnvme.h>
#include "nvme-print.h"

#define PROTO(args...) args
#define ARGS(args...) args

#define VOID_FN(name, proto, args)					\
void __attribute__((weak)) name(proto)					\
{									\
	void (*fn)(proto);						\
	fn = dlsym(RTLD_NEXT, #name);					\
	if (!fn) {							\
		nvme_show_error("libnvme function " #name " not found");\
		exit(EXIT_FAILURE);					\
	}								\
	fn(args);						 	\
}

#define FN(name, rtype, proto, args, defret)			\
rtype __attribute__((weak)) name(proto)				\
{								\
	rtype (*fn)(proto);					\
	fn = dlsym(RTLD_NEXT, #name);				\
	if (fn)							\
		return fn(args);				\
	return defret;						\
}

FN(nvme_get_version,
	const char *, PROTO(enum nvme_version type),
	ARGS(type), "n/a")

VOID_FN(nvme_init_copy_range_f1,
	PROTO(struct nvme_copy_range_f1 *copy, __u16 *nlbs,
	      __u64 *slbas, __u64 *eilbrts, __u32 *elbatms,
	      __u32 *elbats, __u16 nr),
	ARGS(copy, nlbs, slbas, eilbrts, elbatms, elbats, nr))

VOID_FN(nvme_init_copy_range_f2,
	PROTO(struct nvme_copy_range_f2 *copy, __u32 *snsids,
	      __u16 *nlbs, __u64 *slbas, __u16 *sopts, __u32 *eilbrts,
	      __u32 *elbatms, __u32 *elbats, __u16 nr),
	ARGS(copy, snsids, nlbs, slbas, sopts, eilbrts, elbatms, elbats, nr))

VOID_FN(nvme_init_copy_range_f3,
	PROTO(struct nvme_copy_range_f3 *copy, __u32 *snsids,
	      __u16 *nlbs, __u64 *slbas, __u16 *sopts, __u64 *eilbrts,
	      __u32 *elbatms, __u32 *elbats, __u16 nr),
	ARGS(copy, snsids, nlbs, slbas, sopts, eilbrts, elbatms, elbats, nr))

FN(nvme_get_feature_length2,
	int,
	PROTO(int fid, __u32 cdw11, enum nvme_data_tfr dir,
	      __u32 *len),
	ARGS(fid, cdw11, dir, len),
	-EEXIST)

FN(nvme_ctrl_is_persistent,
	bool,
	PROTO(nvme_ctrl_t c),
	ARGS(c),
	false)
