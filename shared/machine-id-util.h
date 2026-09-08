/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */
#pragma once

#include "uuid-util.h"

/*
 * Derive an application-specific UUID from the local machine ID.
 *
 * Linux only. The machine ID is a systemd concept, and the sole caller is
 * fabrics code, which is not built for other platforms.
 *
 * @path:   File holding the machine ID, normally "/etc/machine-id". Passed in
 *          so tests can redirect it.
 * @app_id: Fixed 16-byte constant identifying the application. Must not be
 *          all zeros.
 * @out:    Where to store the derived UUID.
 *
 * The machine ID must not be published, so it is never returned directly.
 * The result is HMAC-SHA256(key=machine ID, data=@app_id), truncated to 16
 * bytes and shaped into a version 4 UUID. Two applications using different
 * @app_id values derive unrelated UUIDs from the same machine.
 *
 * This is the derivation systemd's sd_id128_get_machine_app_specific(3)
 * performs, reimplemented so it needs no libsystemd and no OpenSSL.
 *
 * Return: 0 on success, negative errno otherwise. -EINVAL covers every
 * unusable machine ID: absent, empty, not yet initialized, malformed, or all
 * zeros.
 */
int shr_machine_id_app_specific(const char *path,
		const unsigned char app_id[SHR_UUID_LEN],
		unsigned char out[SHR_UUID_LEN]);
