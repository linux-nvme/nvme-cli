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
