// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 *
 * SHA-256 (FIPS 180-2) and HMAC-SHA256 (FIPS 198). Taken from systemd
 * (src/fundamental/sha256.c and src/basic/hmac.c), which took SHA-256 from
 * the GNU C Library. Both are LGPL-2.1-or-later, matching this file.
 */

#include <string.h>

#include "assert-util.h"
#include "sha256-util.h"

/*
 * total64 is read through the total[2] overlay, so the halves swap with the
 * byte order.
 */
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define SWAP(n)		__builtin_bswap32(n)
#define TOTAL64_LOW	0
#define TOTAL64_HIGH	1
#else
#define SWAP(n)		(n)
#define TOTAL64_LOW	1
#define TOTAL64_HIGH	0
#endif

#define IS_ALIGNED32(p)	(((uintptr_t)(p) % sizeof(uint32_t)) == 0)

/* Bytes used to pad the buffer to the next 64-byte boundary (FIPS 180-2:5.1.1) */
static const uint8_t fillbuf[64] = { 0x80, 0 /* , 0, 0, ... */ };

/* Constants for SHA-256 from FIPS 180-2:4.2.2 */
static const uint32_t K[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
	0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
	0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
	0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
	0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
	0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

/*
 * Zero memory in a way the compiler may not remove. The plain memset() of a
 * buffer that is never read again is dead code and may be optimized away,
 * which would leave key material on the stack.
 */
static void erase(void *p, size_t len)
{
	volatile unsigned char *v = p;

	while (len--)
		*v++ = 0;
}

/* Process len bytes of buffer into ctx. len must be a multiple of 64. */
static void sha256_process_block(const void *buffer, size_t len,
		struct shr_sha256_ctx *ctx)
{
	const uint32_t *words = buffer;
	size_t nwords = len / sizeof(uint32_t);
	uint32_t a, b, c, d, e, f, g, h;

	shr_assert(buffer);
	shr_assert(ctx);

	a = ctx->H[0];
	b = ctx->H[1];
	c = ctx->H[2];
	d = ctx->H[3];
	e = ctx->H[4];
	f = ctx->H[5];
	g = ctx->H[6];
	h = ctx->H[7];

	/*
	 * FIPS 180-2 allows a length up to 2^64 bits. Only the number of
	 * bytes is counted here.
	 */
	ctx->total64 += len;

	while (nwords > 0) {
		uint32_t W[64];
		uint32_t a_save = a;
		uint32_t b_save = b;
		uint32_t c_save = c;
		uint32_t d_save = d;
		uint32_t e_save = e;
		uint32_t f_save = f;
		uint32_t g_save = g;
		uint32_t h_save = h;
		size_t t;

		/* Operators defined in FIPS 180-2:4.1.2 */
#define CYCLIC(w, s) ((w >> s) | (w << (32 - s)))
#define Ch(x, y, z) ((x & y) ^ (~x & z))
#define Maj(x, y, z) ((x & y) ^ (x & z) ^ (y & z))
#define S0(x) (CYCLIC(x, 2) ^ CYCLIC(x, 13) ^ CYCLIC(x, 22))
#define S1(x) (CYCLIC(x, 6) ^ CYCLIC(x, 11) ^ CYCLIC(x, 25))
#define R0(x) (CYCLIC(x, 7) ^ CYCLIC(x, 18) ^ (x >> 3))
#define R1(x) (CYCLIC(x, 17) ^ CYCLIC(x, 19) ^ (x >> 10))

		/* Message schedule, FIPS 180-2:6.2.2 step 2 */
		for (t = 0; t < 16; ++t) {
			W[t] = SWAP(*words);
			++words;
		}
		for (t = 16; t < 64; ++t)
			W[t] = R1(W[t - 2]) + W[t - 7] + R0(W[t - 15]) +
			       W[t - 16];

		/* FIPS 180-2:6.2.2 step 3 */
		for (t = 0; t < 64; ++t) {
			uint32_t T1 = h + S1(e) + Ch(e, f, g) + K[t] + W[t];
			uint32_t T2 = S0(a) + Maj(a, b, c);

			h = g;
			g = f;
			f = e;
			e = d + T1;
			d = c;
			c = b;
			b = a;
			a = T1 + T2;
		}

#undef CYCLIC
#undef Ch
#undef Maj
#undef S0
#undef S1
#undef R0
#undef R1

		/* FIPS 180-2:6.2.2 step 4 */
		a += a_save;
		b += b_save;
		c += c_save;
		d += d_save;
		e += e_save;
		f += f_save;
		g += g_save;
		h += h_save;

		nwords -= 16;
	}

	ctx->H[0] = a;
	ctx->H[1] = b;
	ctx->H[2] = c;
	ctx->H[3] = d;
	ctx->H[4] = e;
	ctx->H[5] = f;
	ctx->H[6] = g;
	ctx->H[7] = h;
}

/* FIPS 180-2:5.3.2 */
void shr_sha256_init(struct shr_sha256_ctx *ctx)
{
	shr_assert(ctx);

	ctx->H[0] = 0x6a09e667;
	ctx->H[1] = 0xbb67ae85;
	ctx->H[2] = 0x3c6ef372;
	ctx->H[3] = 0xa54ff53a;
	ctx->H[4] = 0x510e527f;
	ctx->H[5] = 0x9b05688c;
	ctx->H[6] = 0x1f83d9ab;
	ctx->H[7] = 0x5be0cd19;

	ctx->total64 = 0;
	ctx->buflen = 0;
}

void shr_sha256_update(struct shr_sha256_ctx *ctx, const void *data,
		size_t len)
{
	shr_assert(ctx);
	shr_assert(data);

	/* Concatenate with whatever is already buffered. */
	if (ctx->buflen != 0) {
		size_t left_over = ctx->buflen;
		size_t add = 128 - left_over > len ? len : 128 - left_over;

		memcpy(&ctx->buffer[left_over], data, add);
		ctx->buflen += add;

		if (ctx->buflen > 64) {
			sha256_process_block(ctx->buffer, ctx->buflen & ~63,
					     ctx);
			ctx->buflen &= 63;
			/* The copied regions cannot overlap. */
			memcpy(ctx->buffer,
			       &ctx->buffer[(left_over + add) & ~63],
			       ctx->buflen);
		}

		data = (const char *)data + add;
		len -= add;
	}

	/* Process available complete blocks. */
	if (len >= 64) {
		if (IS_ALIGNED32(data)) {
			sha256_process_block(data, len & ~63, ctx);
			data = (const char *)data + (len & ~63);
			len &= 63;
		} else {
			while (len > 64) {
				memcpy(ctx->buffer, data, 64);
				sha256_process_block(ctx->buffer, 64, ctx);
				data = (const char *)data + 64;
				len -= 64;
			}
		}
	}

	/* Move the remaining bytes into the internal buffer. */
	if (len > 0) {
		size_t left_over = ctx->buflen;

		memcpy(&ctx->buffer[left_over], data, len);
		left_over += len;
		if (left_over >= 64) {
			sha256_process_block(ctx->buffer, 64, ctx);
			left_over -= 64;
			memcpy(ctx->buffer, &ctx->buffer[64], left_over);
		}
		ctx->buflen = left_over;
	}
}

uint8_t *shr_sha256_final(struct shr_sha256_ctx *ctx,
		uint8_t out[SHR_SHA256_DIGEST_SIZE])
{
	uint32_t bytes;
	size_t pad, i;

	shr_assert(ctx);
	shr_assert(out);

	bytes = ctx->buflen;
	ctx->total64 += bytes;

	pad = bytes >= 56 ? 64 + 56 - bytes : 56 - bytes;
	memcpy(&ctx->buffer[bytes], fillbuf, pad);

	/* Append the length in *bits* as a 64-bit big-endian value. */
	ctx->buffer32[(bytes + pad + 4) / 4] =
		SWAP(ctx->total[TOTAL64_LOW] << 3);
	ctx->buffer32[(bytes + pad) / 4] =
		SWAP((ctx->total[TOTAL64_HIGH] << 3) |
		     (ctx->total[TOTAL64_LOW] >> 29));

	sha256_process_block(ctx->buffer, bytes + pad + 8, ctx);

	for (i = 0; i < 8; ++i) {
		uint32_t w = SWAP(ctx->H[i]);

		memcpy(out + i * sizeof(uint32_t), &w, sizeof(w));
	}

	return out;
}

uint8_t *shr_sha256(const void *data, size_t len,
		uint8_t out[SHR_SHA256_DIGEST_SIZE])
{
	struct shr_sha256_ctx ctx;

	shr_sha256_init(&ctx);
	shr_sha256_update(&ctx, data, len);

	return shr_sha256_final(&ctx, out);
}

#define HMAC_BLOCK_SIZE		64
#define INNER_PADDING_BYTE	0x36
#define OUTER_PADDING_BYTE	0x5c

void shr_hmac_sha256_raw(const void *key, size_t key_len, const void *data,
		size_t data_len, uint8_t out[SHR_SHA256_DIGEST_SIZE])
{
	uint8_t inner_padding[HMAC_BLOCK_SIZE] = {};
	uint8_t outer_padding[HMAC_BLOCK_SIZE] = {};
	uint8_t replacement_key[SHR_SHA256_DIGEST_SIZE];
	struct shr_sha256_ctx hash;
	size_t i;

	shr_assert(key);
	shr_assert(key_len > 0);
	shr_assert(out);

	/* The key must be at most one block long; hash it if it is longer. */
	if (key_len > HMAC_BLOCK_SIZE) {
		shr_sha256(key, key_len, replacement_key);
		key = replacement_key;
		key_len = SHR_SHA256_DIGEST_SIZE;
	}

	/*
	 * Copy the key into both padding arrays. A key shorter than the block
	 * size leaves the rest zero, as FIPS 198 requires.
	 */
	memcpy(inner_padding, key, key_len);
	memcpy(outer_padding, key, key_len);

	for (i = 0; i < HMAC_BLOCK_SIZE; i++) {
		inner_padding[i] ^= INNER_PADDING_BYTE;
		outer_padding[i] ^= OUTER_PADDING_BYTE;
	}

	shr_sha256_init(&hash);
	shr_sha256_update(&hash, inner_padding, HMAC_BLOCK_SIZE);
	shr_sha256_update(&hash, data, data_len);
	shr_sha256_final(&hash, out);

	shr_sha256_init(&hash);
	shr_sha256_update(&hash, outer_padding, HMAC_BLOCK_SIZE);
	shr_sha256_update(&hash, out, SHR_SHA256_DIGEST_SIZE);
	shr_sha256_final(&hash, out);

	/* All of these are trivially reversible to the key. */
	erase(inner_padding, sizeof(inner_padding));
	erase(outer_padding, sizeof(outer_padding));
	erase(replacement_key, sizeof(replacement_key));
	erase(&hash, sizeof(hash));
}
