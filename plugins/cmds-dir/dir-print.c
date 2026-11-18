// SPDX-License-Identifier: GPL-2.0-or-later

#include <libnvme.h>

#include "dir-print.h"
#include "nvme-print.h"

/*
 * Run the printers in the sandbox. Like nvme_print(), silently skip
 * printers that an output format does not implement.
 */
#define dir_print(name, flags, ...)					\
	do {								\
		struct dir_print_ops *ops = dir_print_ops(flags);	\
									\
		if (ops && ops->name)					\
			nvme_print_decoder(ops, name, true, flags,	\
					   ##__VA_ARGS__);		\
	} while (false)

static struct dir_print_ops *dir_print_ops(nvme_print_flags_t flags)
{
	struct dir_print_ops *ops = NULL;

	if (flags & JSON || nvme_is_output_format_json())
		ops = dir_get_json_print_ops(flags);
	else if (flags & BINARY)
		ops = dir_get_binary_print_ops(flags);
	else
		ops = dir_get_stdout_print_ops(flags);

	return ops;
}

void nvme_directive_show(__u8 type, __u8 oper, __u16 spec, __u32 nsid,
			 __u64 result, void *buf, __u32 len,
			 nvme_print_flags_t flags)
{
	dir_print(directive, flags, type, oper, spec, nsid, result, buf, len);
}
