// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "ttlv.h"

static size_t pad8(size_t len)
{
	return (len + 7) & ~(size_t)7;
}

static void put_be32(uint8_t *p, uint32_t v)
{
	p[0] = v >> 24;
	p[1] = v >> 16;
	p[2] = v >> 8;
	p[3] = v;
}

static void put_be64(uint8_t *p, uint64_t v)
{
	put_be32(p, v >> 32);
	put_be32(p + 4, v);
}

static uint32_t get_be32(const uint8_t *p)
{
	return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 |
	       (uint32_t)p[2] << 8 | p[3];
}

static uint64_t get_be64(const uint8_t *p)
{
	return (uint64_t)get_be32(p) << 32 | get_be32(p + 4);
}

void ttlv_buf_init(struct ttlv_buf *b)
{
	memset(b, 0, sizeof(*b));
}

void ttlv_buf_free(struct ttlv_buf *b)
{
	if (b->data) {
		explicit_bzero(b->data, b->cap);
		free(b->data);
	}
	ttlv_buf_init(b);
}

/* Reserve @len zeroed bytes at the end. Returns NULL on error. */
static uint8_t *reserve(struct ttlv_buf *b, size_t len)
{
	uint8_t *p;

	if (b->err)
		return NULL;

	if (len > b->cap - b->len) {
		size_t cap = b->cap ? b->cap : 256;

		while (len > cap - b->len) {
			if (cap > SIZE_MAX / 2) {
				b->err = -ENOMEM;
				return NULL;
			}
			cap *= 2;
		}
		// Not realloc(): it frees the old copy without clearing it.
		p = malloc(cap);
		if (!p) {
			b->err = -ENOMEM;
			return NULL;
		}
		if (b->data) {
			memcpy(p, b->data, b->len);
			explicit_bzero(b->data, b->cap);
			free(b->data);
		}
		b->data = p;
		b->cap = cap;
	}

	p = b->data + b->len;
	memset(p, 0, len);
	b->len += len;

	return p;
}

/* Add an item with a value of @len bytes. Returns the value or NULL. */
static uint8_t *add_item(struct ttlv_buf *b, uint32_t tag, uint8_t type,
		size_t len)
{
	uint8_t *p;

	if (len > UINT32_MAX) {
		if (!b->err)
			b->err = -EOVERFLOW;
		return NULL;
	}

	p = reserve(b, TTLV_HDR_LEN + pad8(len));
	if (!p)
		return NULL;

	put_be32(p, tag << 8 | type);
	put_be32(p + 4, len);

	return p + TTLV_HDR_LEN;
}

void ttlv_begin(struct ttlv_buf *b, uint32_t tag)
{
	if (b->err)
		return;
	if (b->depth == TTLV_MAX_DEPTH) {
		b->err = -E2BIG;
		return;
	}

	b->open[b->depth] = b->len;
	if (add_item(b, tag, TTLV_STRUCTURE, 0))
		b->depth++;
}

void ttlv_end(struct ttlv_buf *b)
{
	size_t start, len;

	if (b->err)
		return;
	if (!b->depth) {
		b->err = -EINVAL;
		return;
	}

	start = b->open[--b->depth];
	len = b->len - start - TTLV_HDR_LEN;
	if (len > UINT32_MAX) {
		b->err = -EOVERFLOW;
		return;
	}
	put_be32(b->data + start + 4, len);
}

void ttlv_add_int(struct ttlv_buf *b, uint32_t tag, int32_t v)
{
	uint8_t *p = add_item(b, tag, TTLV_INTEGER, 4);

	if (p)
		put_be32(p, v);
}

void ttlv_add_long(struct ttlv_buf *b, uint32_t tag, int64_t v)
{
	uint8_t *p = add_item(b, tag, TTLV_LONG, 8);

	if (p)
		put_be64(p, v);
}

void ttlv_add_enum(struct ttlv_buf *b, uint32_t tag, uint32_t v)
{
	uint8_t *p = add_item(b, tag, TTLV_ENUM, 4);

	if (p)
		put_be32(p, v);
}

void ttlv_add_bool(struct ttlv_buf *b, uint32_t tag, bool v)
{
	uint8_t *p = add_item(b, tag, TTLV_BOOL, 8);

	if (p)
		put_be64(p, v);
}

static void add_string(struct ttlv_buf *b, uint32_t tag, uint8_t type,
		const void *v, size_t len)
{
	uint8_t *p = add_item(b, tag, type, len);

	if (p && len)
		memcpy(p, v, len);
}

void ttlv_add_text(struct ttlv_buf *b, uint32_t tag, const char *s)
{
	add_string(b, tag, TTLV_TEXT, s, strlen(s));
}

void ttlv_add_bytes(struct ttlv_buf *b, uint32_t tag, const void *v,
		size_t len)
{
	add_string(b, tag, TTLV_BYTES, v, len);
}

void ttlv_add_date_time(struct ttlv_buf *b, uint32_t tag, int64_t v)
{
	uint8_t *p = add_item(b, tag, TTLV_DATE_TIME, 8);

	if (p)
		put_be64(p, v);
}

void ttlv_add_interval(struct ttlv_buf *b, uint32_t tag, uint32_t v)
{
	uint8_t *p = add_item(b, tag, TTLV_INTERVAL, 4);

	if (p)
		put_be32(p, v);
}

void ttlv_reader_init(struct ttlv_reader *r, const void *buf, size_t len)
{
	static const uint8_t empty;

	// Pointer arithmetic on NULL is undefined, even with an offset of 0.
	r->p = len ? buf : &empty;
	r->end = r->p + len;
}

/* The fixed value length of @type, 0 for a variable length. */
static uint32_t fixed_len(uint8_t type)
{
	switch (type) {
	case TTLV_INTEGER:
	case TTLV_ENUM:
	case TTLV_INTERVAL:
		return 4;
	case TTLV_LONG:
	case TTLV_BOOL:
	case TTLV_DATE_TIME:
		return 8;
	default:
		return 0;
	}
}

int ttlv_next(struct ttlv_reader *r, struct ttlv_item *it)
{
	size_t avail = r->end - r->p;
	uint32_t hdr, fixed;
	size_t padded;

	if (!avail)
		return 0;
	if (avail < TTLV_HDR_LEN)
		return -EBADMSG;

	hdr = get_be32(r->p);
	it->tag = hdr >> 8;
	it->type = hdr & 0xff;
	it->len = get_be32(r->p + 4);

	if (it->type < TTLV_STRUCTURE || it->type > TTLV_INTERVAL)
		return -EBADMSG;

	fixed = fixed_len(it->type);
	if (fixed && it->len != fixed)
		return -EBADMSG;
	if ((it->type == TTLV_STRUCTURE || it->type == TTLV_BIG_INT) &&
	    it->len % 8)
		return -EBADMSG;

	padded = pad8(it->len);
	if (padded > avail - TTLV_HDR_LEN)
		return -EBADMSG;

	it->val = r->p + TTLV_HDR_LEN;
	r->p = it->val + padded;

	return 1;
}

int ttlv_find(struct ttlv_reader *r, uint32_t tag, struct ttlv_item *it)
{
	int ret;

	while ((ret = ttlv_next(r, it)) > 0) {
		if (it->tag == tag)
			return 1;
	}

	return ret;
}

int ttlv_open(const struct ttlv_item *it, struct ttlv_reader *r)
{
	if (it->type != TTLV_STRUCTURE)
		return -EBADMSG;

	ttlv_reader_init(r, it->val, it->len);

	return 0;
}

int ttlv_get_int(const struct ttlv_item *it, int32_t *v)
{
	if (it->type != TTLV_INTEGER)
		return -EBADMSG;

	*v = (int32_t)get_be32(it->val);

	return 0;
}

int ttlv_get_long(const struct ttlv_item *it, int64_t *v)
{
	if (it->type != TTLV_LONG)
		return -EBADMSG;

	*v = (int64_t)get_be64(it->val);

	return 0;
}

int ttlv_get_enum(const struct ttlv_item *it, uint32_t *v)
{
	if (it->type != TTLV_ENUM)
		return -EBADMSG;

	*v = get_be32(it->val);

	return 0;
}

int ttlv_get_bool(const struct ttlv_item *it, bool *v)
{
	uint64_t raw;

	if (it->type != TTLV_BOOL)
		return -EBADMSG;

	raw = get_be64(it->val);
	if (raw > 1)
		return -EBADMSG;

	*v = raw;

	return 0;
}
