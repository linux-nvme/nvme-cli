/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <libnvme.h>

#include <ccan/endian/endian.h>

#include "nvme-print.h"

static struct print_ops binary_print_ops;

static struct print_ops binary_print_ops = {
	/* libnvme types.h print functions */
	.d				= NULL,
	.show_init			= NULL,
	.show_finish			= NULL,

	/* status and error messages */
	.show_message			= NULL,
	.show_perror			= NULL,
	.show_status			= NULL,
	.show_opcode_status		= NULL,
	.show_error_status		= NULL,
	.show_key_value			= NULL,
};

struct print_ops *nvme_get_binary_print_ops(nvme_print_flags_t flags)
{
	binary_print_ops.flags = flags;
	return &binary_print_ops;
}
