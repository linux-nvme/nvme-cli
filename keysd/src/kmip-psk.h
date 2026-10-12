/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */
#pragma once

#include <stddef.h>
#include <stdint.h>

struct keysd_kmip;
struct libnvme_global_ctx;

/*
 * Large enough for a PSK in the interchange format: a 48-byte key plus
 * its CRC is 72 characters in base64, plus the 17-character framing.
 */
#define KMIP_PSK_MAX 128

/*
 * Convert a key object of type @obj_type (a KMIP_OBJ_* value) to a PSK in
 * the interchange format. Secret Data holds the interchange string. A
 * Symmetric Key holds the PSK: 32 bytes for SHA-256, 48 bytes for
 * SHA-384. Returns 0, -EMEDIUMTYPE if the object is not a valid PSK, or
 * -ENOMEM.
 */
int kmip_psk_from_object(struct libnvme_global_ctx *ctx, uint32_t obj_type,
		const uint8_t *data, size_t len, char psk[KMIP_PSK_MAX]);

struct dmn_resolver;
struct kmip_get;

/*
 * Called from the event loop with 0 and the PSK in @psk, or a negative
 * errno. @server is the index of the server that answered. @psk is
 * cleared after the call.
 */
typedef void (*kmip_psk_callback)(int ret, const char *psk, size_t server,
				  void *user_data);

/*
 * Get the Active key named @name from @kms, as a PSK in the interchange
 * format. The servers of @kms are tried in order, starting with the one
 * at index @first, until one answers. The timeout of @kms applies to each
 * server: it covers the name lookup through @resolver, the connection and
 * the exchange. @key_path is the client private key, or NULL.
 * @done gets -ENOENT if no Active key has this name, -ENOTUNIQ if several
 * have, -EMEDIUMTYPE if the key is not a valid PSK, another errno if no
 * server can be reached or each reports an error.
 * Return: 0 if @done will be called, a negative errno otherwise. *@ret,
 * if @ret is not NULL, is valid until @done is called.
 */
int kmip_get_psk(struct dmn_resolver *resolver,
		struct libnvme_global_ctx *ctx, const struct keysd_kmip *kms,
		size_t first, const char *key_path, const char *name,
		kmip_psk_callback done, void *user_data, struct kmip_get **ret);

/* Stop @g. Its callback is not called. */
void kmip_get_cancel(struct kmip_get *g);
