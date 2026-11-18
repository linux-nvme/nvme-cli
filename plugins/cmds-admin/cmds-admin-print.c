// SPDX-License-Identifier: GPL-2.0-or-later

#include <libnvme.h>

#include "cmds-admin-print.h"
#include "nvme-print.h"

/*
 * The relatives printer reads sysfs, so it runs in process. Like
 * nvme_print(), silently skip printers that an output format does not
 * implement.
 */
#define admin_print(name, flags, ...)					\
	do {								\
		struct admin_print_ops *ops = admin_print_ops(flags);	\
									\
		if (ops && ops->name)					\
			nvme_print_decoder(ops, name, false, flags,	\
					   ##__VA_ARGS__);		\
	} while (false)

/* Only the normal output format has printers */
static struct admin_print_ops *admin_print_ops(nvme_print_flags_t flags)
{
	if (flags & JSON || nvme_is_output_format_json())
		return NULL;
	if (flags & BINARY)
		return NULL;

	return admin_get_stdout_print_ops(flags);
}

void nvme_show_relatives(struct libnvme_global_ctx *ctx, const char *name,
			 nvme_print_flags_t flags)
{
	admin_print(relatives, flags, ctx, name);
}
