// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ttlv.h"

#define TAG	0x420020

static bool check(bool cond, const char *what)
{
	printf(" - %s [%s]\n", what, cond ? "PASS" : "FAIL");
	return cond;
}

static bool check_bytes(const struct ttlv_buf *b, const uint8_t *exp,
		size_t len, const char *what)
{
	return check(!b->err && b->len == len && !memcmp(b->data, exp, len),
		     what);
}

/* The examples of KMIP 1.4, section 9.1.2. */
static bool test_encode_spec_examples(void)
{
	static const uint8_t integer[] = {
		0x42, 0x00, 0x20, 0x02, 0x00, 0x00, 0x00, 0x04,
		0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00,
	};
	static const uint8_t long_int[] = {
		0x42, 0x00, 0x20, 0x03, 0x00, 0x00, 0x00, 0x08,
		0x01, 0xb6, 0x9b, 0x4b, 0xa5, 0x74, 0x92, 0x00,
	};
	static const uint8_t enumeration[] = {
		0x42, 0x00, 0x20, 0x05, 0x00, 0x00, 0x00, 0x04,
		0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00, 0x00,
	};
	static const uint8_t boolean[] = {
		0x42, 0x00, 0x20, 0x06, 0x00, 0x00, 0x00, 0x08,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
	};
	static const uint8_t text[] = {
		0x42, 0x00, 0x20, 0x07, 0x00, 0x00, 0x00, 0x0b,
		0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f,
		0x72, 0x6c, 0x64, 0x00, 0x00, 0x00, 0x00, 0x00,
	};
	static const uint8_t bytes[] = {
		0x42, 0x00, 0x20, 0x08, 0x00, 0x00, 0x00, 0x03,
		0x01, 0x02, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00,
	};
	static const uint8_t date_time[] = {
		0x42, 0x00, 0x20, 0x09, 0x00, 0x00, 0x00, 0x08,
		0x00, 0x00, 0x00, 0x00, 0x47, 0xda, 0x67, 0xf8,
	};
	static const uint8_t interval[] = {
		0x42, 0x00, 0x20, 0x0a, 0x00, 0x00, 0x00, 0x04,
		0x00, 0x0d, 0x2f, 0x00, 0x00, 0x00, 0x00, 0x00,
	};
	static const uint8_t structure[] = {
		0x42, 0x00, 0x20, 0x01, 0x00, 0x00, 0x00, 0x20,
		0x42, 0x00, 0x04, 0x05, 0x00, 0x00, 0x00, 0x04,
		0x00, 0x00, 0x00, 0xfe, 0x00, 0x00, 0x00, 0x00,
		0x42, 0x00, 0x05, 0x02, 0x00, 0x00, 0x00, 0x04,
		0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00, 0x00,
	};
	static const uint8_t raw[] = { 0x01, 0x02, 0x03 };
	struct ttlv_buf b;
	bool pass = true;

	printf("test_encode_spec_examples:\n");

#define ENCODE(call, exp, what)					\
	do {							\
		ttlv_buf_init(&b);				\
		call;						\
		pass &= check_bytes(&b, exp, sizeof(exp), what);	\
		ttlv_buf_free(&b);				\
	} while (0)

	ENCODE(ttlv_add_int(&b, TAG, 8), integer, "Integer");
	ENCODE(ttlv_add_long(&b, TAG, 123456789000000000LL), long_int,
	       "Long Integer");
	ENCODE(ttlv_add_enum(&b, TAG, 255), enumeration, "Enumeration");
	ENCODE(ttlv_add_bool(&b, TAG, true), boolean, "Boolean");
	ENCODE(ttlv_add_text(&b, TAG, "Hello World"), text, "Text String");
	ENCODE(ttlv_add_bytes(&b, TAG, raw, sizeof(raw)), bytes,
	       "Byte String");
	ENCODE(ttlv_add_date_time(&b, TAG, 0x47da67f8), date_time,
	       "Date-Time");
	ENCODE(ttlv_add_interval(&b, TAG, 10 * 86400), interval, "Interval");
	ENCODE(ttlv_begin(&b, TAG);
	       ttlv_add_enum(&b, 0x420004, 254);
	       ttlv_add_int(&b, 0x420005, 255);
	       ttlv_end(&b), structure, "Structure");

#undef ENCODE

	return pass;
}

static bool test_encode_errors(void)
{
	struct ttlv_buf b;
	bool pass = true;
	int i;

	printf("test_encode_errors:\n");

	ttlv_buf_init(&b);
	ttlv_end(&b);
	pass &= check(b.err == -EINVAL, "end without begin");
	ttlv_add_int(&b, TAG, 1);
	pass &= check(b.len == 0, "no output after an error");
	ttlv_buf_free(&b);

	ttlv_buf_init(&b);
	for (i = 0; i <= TTLV_MAX_DEPTH; i++)
		ttlv_begin(&b, TAG);
	pass &= check(b.err == -E2BIG, "nesting deeper than the maximum");
	ttlv_buf_free(&b);

	return pass;
}

static bool test_decode_round_trip(void)
{
	struct ttlv_reader r, sub;
	struct ttlv_item it;
	struct ttlv_buf b;
	bool pass = true;
	uint32_t e;
	int32_t i;
	int64_t l;
	bool v;

	printf("test_decode_round_trip:\n");

	ttlv_buf_init(&b);
	ttlv_begin(&b, 0x420078);
	ttlv_add_int(&b, 0x42006a, -2);
	ttlv_add_text(&b, 0x420055, "abc");
	ttlv_begin(&b, 0x42007c);
	ttlv_add_enum(&b, 0x42005c, 10);
	ttlv_end(&b);
	ttlv_add_long(&b, 0x420092, -1);
	ttlv_add_bool(&b, 0x420007, false);
	ttlv_end(&b);
	pass &= check(!b.err, "encode");

	ttlv_reader_init(&r, b.data, b.len);
	pass &= check(ttlv_next(&r, &it) == 1 && it.tag == 0x420078 &&
		      ttlv_open(&it, &sub) == 0, "outer structure");
	pass &= check(ttlv_next(&r, &it) == 0, "nothing after it");

	pass &= check(ttlv_next(&sub, &it) == 1 &&
		      ttlv_get_int(&it, &i) == 0 && i == -2, "Integer -2");
	pass &= check(ttlv_next(&sub, &it) == 1 && it.type == TTLV_TEXT &&
		      it.len == 3 && !memcmp(it.val, "abc", 3), "Text String");
	pass &= check(ttlv_find(&sub, 0x420092, &it) == 1 &&
		      ttlv_get_long(&it, &l) == 0 && l == -1,
		      "find skips the nested structure");
	pass &= check(ttlv_next(&sub, &it) == 1 &&
		      ttlv_get_bool(&it, &v) == 0 && !v, "Boolean false");
	pass &= check(ttlv_next(&sub, &it) == 0, "end of structure");

	ttlv_reader_init(&r, b.data, b.len);
	ttlv_next(&r, &it);
	ttlv_open(&it, &sub);
	pass &= check(ttlv_find(&sub, 0x42007c, &it) == 1 &&
		      ttlv_open(&it, &r) == 0 && ttlv_next(&r, &it) == 1 &&
		      ttlv_get_enum(&it, &e) == 0 && e == 10,
		      "nested Enumeration");
	pass &= check(ttlv_get_int(&it, &i) == -EBADMSG,
		      "get with the wrong type");

	ttlv_buf_free(&b);

	return pass;
}

static int decode_one(const uint8_t *buf, size_t len)
{
	struct ttlv_reader r;
	struct ttlv_item it;

	ttlv_reader_init(&r, buf, len);

	return ttlv_next(&r, &it);
}

static bool test_decode_malformed(void)
{
	static const uint8_t short_hdr[] = { 0x42, 0x00, 0x20, 0x02 };
	static const uint8_t bad_type[] = {
		0x42, 0x00, 0x20, 0x0b, 0x00, 0x00, 0x00, 0x00,
	};
	static const uint8_t bad_int_len[] = {
		0x42, 0x00, 0x20, 0x02, 0x00, 0x00, 0x00, 0x08,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	};
	static const uint8_t bad_struct_len[] = {
		0x42, 0x00, 0x20, 0x01, 0x00, 0x00, 0x00, 0x04,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	};
	static const uint8_t truncated_value[] = {
		0x42, 0x00, 0x20, 0x07, 0x00, 0x00, 0x00, 0x09,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
	};
	static const uint8_t huge_len[] = {
		0x42, 0x00, 0x20, 0x08, 0xff, 0xff, 0xff, 0xff,
	};
	static const uint8_t bad_bool[] = {
		0x42, 0x00, 0x20, 0x06, 0x00, 0x00, 0x00, 0x08,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
	};
	struct ttlv_reader r;
	struct ttlv_item it;
	bool pass = true;
	bool v;

	printf("test_decode_malformed:\n");

	pass &= check(decode_one(NULL, 0) == 0, "empty buffer");
	pass &= check(decode_one(short_hdr, sizeof(short_hdr)) == -EBADMSG,
		      "header shorter than 8 bytes");
	pass &= check(decode_one(bad_type, sizeof(bad_type)) == -EBADMSG,
		      "unknown type");
	pass &= check(decode_one(bad_int_len, sizeof(bad_int_len)) ==
		      -EBADMSG, "Integer with length 8");
	pass &= check(decode_one(bad_struct_len, sizeof(bad_struct_len)) ==
		      -EBADMSG, "Structure length not a multiple of 8");
	pass &= check(decode_one(truncated_value, sizeof(truncated_value)) ==
		      -EBADMSG, "padded value past the end");
	pass &= check(decode_one(huge_len, sizeof(huge_len)) == -EBADMSG,
		      "length 0xffffffff");

	ttlv_reader_init(&r, bad_bool, sizeof(bad_bool));
	pass &= check(ttlv_next(&r, &it) == 1 &&
		      ttlv_get_bool(&it, &v) == -EBADMSG,
		      "Boolean value other than 0 or 1");

	return pass;
}

int main(void)
{
	bool pass = true;

	pass &= test_encode_spec_examples();
	pass &= test_encode_errors();
	pass &= test_decode_round_trip();
	pass &= test_decode_malformed();

	fflush(stdout);
	exit(pass ? EXIT_SUCCESS : EXIT_FAILURE);
}
