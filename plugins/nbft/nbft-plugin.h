/* SPDX-License-Identifier: GPL-2.0-or-later */
#undef CMD_INC_FILE
#define CMD_INC_FILE plugins/nbft/nbft-plugin

#if !defined(NBFT) || defined(CMD_HEADER_MULTI_READ)
#define NBFT

#include "cmd.h"

PLUGIN(NAME("nbft", "ACPI NBFT table extensions", NVME_VERSION),
	COMMAND_LIST(
		ENTRY("show", "Show contents of ACPI NBFT tables", show_nbft)
		ENTRY("gen-udev-link-files", "Generate udev network link files",
		      gen_udev_link_files)
	)
);

#endif

#include "define_cmd.h"
