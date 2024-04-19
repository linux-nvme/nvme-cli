/* SPDX-License-Identifier: GPL-2.0-or-later */
#undef CMD_INC_FILE
#define CMD_INC_FILE plugins/sed/sed

#include "cmd.h"
#include <linux/sed-opal.h>

PLUGIN(NAME("sed", "SED Opal Command Set", NVME_VERSION),
	COMMAND_LIST(
		ENTRY("discover", "Discover SED Opal Locking Features", sed_opal_discover, "1")
		ENTRY("initialize", "Initialize a SED Opal Device for locking", sed_opal_initialize)
		ENTRY("revert", "Revert a SED Opal Device from locking", sed_opal_revert)
		ENTRY("lock", "Lock a SED Opal Device", sed_opal_lock)
		ENTRY("unlock", "Unlock a SED Opal Device", sed_opal_unlock)
		ENTRY("password", "Change the SED Opal Device password", sed_opal_password)
	)
);

#include "define_cmd.h"
