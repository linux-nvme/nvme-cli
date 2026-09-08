/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 *
 * SHA-256 (FIPS 180-2) and HMAC-SHA256 (FIPS 198), with no external
 * dependency. Taken from systemd (src/fundamental/sha256.h,
 * src/fundamental/sha256.c, src/basic/hmac.c), which took SHA-256 from
 * glibc. Reindented to nvme-cli style and reduced to the entry points used
 * here.
 *
 * OpenSSL is faster and is the right choice where it is already linked. Use
 * this where linking OpenSSL is not acceptable, such as code that must work
 * in a build configured with -Dopenssl=disabled.
 */
#pragma once

#include <stddef.h>
#include <stdint.h>

#define SHR_SHA256_DIGEST_SIZE	32

struct shr_sha256_ctx {
	uint32_t H[8];

	union {
		uint64_t total64;
		uint32_t total[2];
	};

	uint32_t buflen;

	union {
		uint8_t buffer[128];	// always aligned for uint32_t
		uint32_t buffer32[32];
		uint64_t buffer64[16];
	};
};

void shr_sha256_init(struct shr_sha256_ctx *ctx);
void shr_sha256_update(struct shr_sha256_ctx *ctx, const void *data,
		size_t len);
uint8_t *shr_sha256_final(struct shr_sha256_ctx *ctx,
		uint8_t out[SHR_SHA256_DIGEST_SIZE]);

/*
 * Compute SHA-256 over data in one call. Returns out.
 */
uint8_t *shr_sha256(const void *data, size_t len,
		uint8_t out[SHR_SHA256_DIGEST_SIZE]);

/*
 * Compute HMAC-SHA256 into a caller-provided buffer. Unlike
 * shr_hmac_sha256() in crypto-util.h, this allocates nothing and needs no
 * OpenSSL.
 */
void shr_hmac_sha256_raw(const void *key, size_t key_len, const void *data,
		size_t data_len, uint8_t out[SHR_SHA256_DIGEST_SIZE]);
