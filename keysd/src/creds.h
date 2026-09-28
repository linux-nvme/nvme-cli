/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */
#pragma once

#include <stddef.h>

/*
 * Decrypt the credential file @dir/@name through systemd-creds, and store
 * the plaintext in @buf as a string, without trailing white space. The
 * name embedded in the credential must be @name. The caller clears @buf.
 *
 * On a Varlink error, *@error is set to its allocated error id, for
 * example "io.systemd.Credentials.NameMismatch". The caller frees it.
 *
 * Return: 0 on success, -errno otherwise.
 */
int creds_decrypt(const char *dir, const char *name, char *buf, size_t size,
		  char **error);
