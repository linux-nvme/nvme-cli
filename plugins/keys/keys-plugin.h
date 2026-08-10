/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 SUSE Software Solutions
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */

#undef CMD_INC_FILE
#define CMD_INC_FILE plugins/keys/keys-plugin

#if !defined(KEYS_PLUGIN) || defined(CMD_HEADER_MULTI_READ)
#define KEYS_PLUGIN

#include "cmd.h"

PLUGIN(NAME_CORE("keys", "Manage NVMeoF KX-HMAC-CHAP and TLS keys", NVME_VERSION),
	COMMAND_LIST(
		ENTRY("gen-kxchap", "Generate NVMeoF KX-HMAC-CHAP host secret", gen_kxchap)
		ENTRY("check-kxchap", "Validate NVMeoF KX-HMAC-CHAP host secret format or check if loaded", check_kxchap)
		ENTRY("gen-tls", "Generate NVMeoF TLS PSK", gen_tls)
		ENTRY("check-tls", "Validate NVMeoF TLS PSK format or check if loaded", check_tls)
		ENTRY("insert-tls", "Insert NVMeoF TLS PSK into a keyring", insert_tls)
		ENTRY("import", "Import NVMeoF TLS PSKs and KX-HMAC-CHAP secrets into a keyring", key_import)
		ENTRY("export", "Export NVMeoF TLS PSKs from a keyring", key_export)
		ENTRY("revoke", "Revoke an NVMeoF TLS PSK from a keyring", key_revoke)
	)
);

#endif

#include "define_cmd.h"
