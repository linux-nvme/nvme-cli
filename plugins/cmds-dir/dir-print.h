/* SPDX-License-Identifier: GPL-2.0-or-later */
#pragma once

#include <libnvme.h>

#include <ccan/endian/endian.h>

#include "args.h"

/*
 * The bytes of the Identify Directive Return Parameters the printers
 * decode: the directives supported, enabled and persistent across
 * controller level resets.
 */
#define NVME_DIRECTIVE_IDENTIFY_PARAM_LEN	96

/*
 * The Stream Identifiers of a Streams Directive Get Status data structure
 * of @len bytes, which holds at least its Open Stream Count: the count
 * the device reports, but at most as many as fit.
 */
static inline int nvme_streams_status_nr_sid(
	struct nvme_streams_directive_status *status, __u32 len)
{
	int max = (len - sizeof(*status)) / sizeof(status->sid[0]);
	int n = le16_to_cpu(status->osc);

	return n < max ? n : max;
}

struct dir_print_ops {
	void (*directive)(__u8 type, __u8 oper, __u16 spec, __u32 nsid,
			  __u64 result, void *buf, __u32 len);
	nvme_print_flags_t flags;
};

struct dir_print_ops *dir_get_stdout_print_ops(nvme_print_flags_t flags);
struct dir_print_ops *dir_get_binary_print_ops(nvme_print_flags_t flags);

#ifdef CONFIG_JSONC
struct dir_print_ops *dir_get_json_print_ops(nvme_print_flags_t flags);
#else
static inline struct dir_print_ops *
dir_get_json_print_ops(nvme_print_flags_t flags)
{
	return NULL;
}
#endif

void nvme_directive_show(__u8 type, __u8 oper, __u16 spec, __u32 nsid,
			 __u64 result, void *buf, __u32 len,
			 nvme_print_flags_t flags);
