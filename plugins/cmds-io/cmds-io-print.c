// SPDX-License-Identifier: GPL-2.0-or-later

#include <libnvme.h>

#include "cmds-io-print.h"
#include "nvme-print.h"

/*
 * Run the printers in the sandbox. Like nvme_print(), silently skip
 * printers that an output format does not implement.
 */
#define cmds_io_print(name, flags, ...)					\
	do {								\
		struct cmds_io_print_ops *ops =				\
			cmds_io_print_ops(flags);			\
									\
		if (ops && ops->name)					\
			nvme_print_decoder(ops, name, true, flags,	\
					   ##__VA_ARGS__);		\
	} while (false)

static struct cmds_io_print_ops *cmds_io_print_ops(nvme_print_flags_t flags)
{
	struct cmds_io_print_ops *ops = NULL;

	if (flags & JSON || nvme_is_output_format_json())
		ops = cmds_io_get_json_print_ops(flags);
	else if (flags & BINARY)
		ops = cmds_io_get_binary_print_ops(flags);
	else
		ops = cmds_io_get_stdout_print_ops(flags);

	return ops;
}

void nvme_show_lba_status(struct nvme_lba_status *list, unsigned long len,
			  nvme_print_flags_t flags)
{
	cmds_io_print(lba_status, flags, list, len);
}
