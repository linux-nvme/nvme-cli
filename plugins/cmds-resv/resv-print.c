// SPDX-License-Identifier: GPL-2.0-or-later

#include <libnvme.h>

#include "nvme-print.h"
#include "resv-print.h"

/*
 * Run the printers in the sandbox. Like nvme_print(), silently skip
 * printers that an output format does not implement.
 */
#define resv_print(name, flags, ...)					\
	do {								\
		struct resv_print_ops *ops = resv_print_ops(flags);	\
									\
		if (ops && ops->name)					\
			nvme_print_decoder(ops, name, true, flags,	\
					   ##__VA_ARGS__);		\
	} while (false)

static struct resv_print_ops *resv_print_ops(nvme_print_flags_t flags)
{
	struct resv_print_ops *ops = NULL;

	if (flags & JSON || nvme_is_output_format_json())
		ops = resv_get_json_print_ops(flags);
	else if (flags & BINARY)
		ops = resv_get_binary_print_ops(flags);
	else
		ops = resv_get_stdout_print_ops(flags);

	return ops;
}

void nvme_show_resv_report(struct nvme_resv_status *status, int bytes,
			   bool eds, nvme_print_flags_t flags)
{
	resv_print(resv_report, flags, status, bytes, eds);
}
