/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * KMIP TTLV encoding. Each item is a 3-byte tag, a 1-byte type, a 4-byte
 * length and a value padded to a multiple of 8 bytes. All numbers are
 * big-endian. The encoding is the same in all KMIP versions (KMIP 1.4,
 * section 9.1).
 */

enum ttlv_type {
	TTLV_STRUCTURE	= 0x01,
	TTLV_INTEGER	= 0x02,
	TTLV_LONG	= 0x03,
	TTLV_BIG_INT	= 0x04,
	TTLV_ENUM	= 0x05,
	TTLV_BOOL	= 0x06,
	TTLV_TEXT	= 0x07,
	TTLV_BYTES	= 0x08,
	TTLV_DATE_TIME	= 0x09,
	TTLV_INTERVAL	= 0x0a,
};

#define TTLV_HDR_LEN	8
#define TTLV_MAX_DEPTH	16

/*
 * Encoder. Writes into a buffer that grows as needed. The first error is
 * kept in @err and makes all later calls do nothing, so a caller checks
 * it once at the end. The buffer may hold secrets: it is cleared when it
 * grows and when it is freed.
 */
struct ttlv_buf {
	uint8_t *data;
	size_t len;
	size_t cap;
	int err;		// 0 or a negative errno
	int depth;
	size_t open[TTLV_MAX_DEPTH];	// offsets of the open structures
};

void ttlv_buf_init(struct ttlv_buf *b);
void ttlv_buf_free(struct ttlv_buf *b);

void ttlv_begin(struct ttlv_buf *b, uint32_t tag);
void ttlv_end(struct ttlv_buf *b);

void ttlv_add_int(struct ttlv_buf *b, uint32_t tag, int32_t v);
void ttlv_add_long(struct ttlv_buf *b, uint32_t tag, int64_t v);
void ttlv_add_enum(struct ttlv_buf *b, uint32_t tag, uint32_t v);
void ttlv_add_bool(struct ttlv_buf *b, uint32_t tag, bool v);
void ttlv_add_text(struct ttlv_buf *b, uint32_t tag, const char *s);
void ttlv_add_bytes(struct ttlv_buf *b, uint32_t tag, const void *p,
		size_t len);
void ttlv_add_date_time(struct ttlv_buf *b, uint32_t tag, int64_t v);
void ttlv_add_interval(struct ttlv_buf *b, uint32_t tag, uint32_t v);

/*
 * Decoder. Reads items from a buffer without copying. An item's value
 * points into the buffer, so the caller clears the buffer if it holds a
 * secret.
 */
struct ttlv_item {
	uint32_t tag;
	uint8_t type;
	uint32_t len;		// value length without padding
	const uint8_t *val;
};

struct ttlv_reader {
	const uint8_t *p;
	const uint8_t *end;
};

void ttlv_reader_init(struct ttlv_reader *r, const void *buf, size_t len);

/*
 * Read the next item. Returns 1 and fills @it, 0 at the end of the
 * buffer, or -EBADMSG if the item is malformed or does not fit.
 */
int ttlv_next(struct ttlv_reader *r, struct ttlv_item *it);

/* Find the next item with @tag. Returns as ttlv_next(), 0 if not found. */
int ttlv_find(struct ttlv_reader *r, uint32_t tag, struct ttlv_item *it);

/* Read the items of structure @it. Returns -EBADMSG if not a structure. */
int ttlv_open(const struct ttlv_item *it, struct ttlv_reader *r);

/* Return -EBADMSG if @it does not have the expected type. */
int ttlv_get_int(const struct ttlv_item *it, int32_t *v);
int ttlv_get_long(const struct ttlv_item *it, int64_t *v);
int ttlv_get_enum(const struct ttlv_item *it, uint32_t *v);
int ttlv_get_bool(const struct ttlv_item *it, bool *v);
