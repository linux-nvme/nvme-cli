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

#include "kmip.h"
#include "kmip-responses.h"

static bool check(bool cond, const char *what)
{
	printf(" - %s [%s]\n", what, cond ? "PASS" : "FAIL");
	return cond;
}

/* Open the structure with @tag in @r. */
static bool enter(struct ttlv_reader *r, enum kmip_tag tag,
		struct ttlv_reader *sub)
{
	struct ttlv_item it;

	return ttlv_find(r, tag, &it) == 1 && ttlv_open(&it, sub) == 0;
}

static bool next_int(struct ttlv_reader *r, enum kmip_tag tag, int32_t exp)
{
	struct ttlv_item it;
	int32_t v;

	return ttlv_next(r, &it) == 1 && it.tag == tag &&
	       ttlv_get_int(&it, &v) == 0 && v == exp;
}

static bool next_enum(struct ttlv_reader *r, enum kmip_tag tag, uint32_t exp)
{
	struct ttlv_item it;
	uint32_t v;

	return ttlv_next(r, &it) == 1 && it.tag == tag &&
	       ttlv_get_enum(&it, &v) == 0 && v == exp;
}

static bool next_text(struct ttlv_reader *r, enum kmip_tag tag,
		const char *exp)
{
	struct ttlv_item it;

	return ttlv_next(r, &it) == 1 && it.tag == tag &&
	       it.type == TTLV_TEXT && it.len == strlen(exp) &&
	       !memcmp(it.val, exp, it.len);
}

/* Check the request header and batch item, and open the payload. */
static bool check_request(const struct ttlv_buf *b, enum kmip_op op,
		struct ttlv_reader *payload)
{
	struct ttlv_reader r, msg, hdr, ver, item;
	bool pass = true;

	ttlv_reader_init(&r, b->data, b->len);
	pass &= check(enter(&r, KMIP_TAG_REQUEST_MESSAGE, &msg),
		      "Request Message");

	pass &= check(enter(&msg, KMIP_TAG_REQUEST_HEADER, &hdr) &&
		      enter(&hdr, KMIP_TAG_PROTOCOL_VERSION, &ver) &&
		      next_int(&ver, KMIP_TAG_PROTOCOL_VERSION_MAJOR, 1) &&
		      next_int(&ver, KMIP_TAG_PROTOCOL_VERSION_MINOR, 4),
		      "Protocol Version 1.4");
	pass &= check(next_int(&hdr, KMIP_TAG_BATCH_COUNT, 1), "Batch Count 1");

	pass &= check(enter(&msg, KMIP_TAG_BATCH_ITEM, &item) &&
		      next_enum(&item, KMIP_TAG_OPERATION, op), "Operation");
	pass &= check(enter(&item, KMIP_TAG_REQUEST_PAYLOAD, payload),
		      "Request Payload");

	return pass;
}

/* Check a Locate request up to its Name attribute. */
static bool check_locate(const struct ttlv_buf *b, struct ttlv_reader *payload)
{
	struct ttlv_reader attr, value;
	bool pass = true;

	pass &= check_request(b, KMIP_OP_LOCATE, payload);
	pass &= check(next_int(payload, KMIP_TAG_MAXIMUM_ITEMS, 2),
		      "Maximum Items 2");
	pass &= check(enter(payload, KMIP_TAG_ATTRIBUTE, &attr) &&
		      next_text(&attr, KMIP_TAG_ATTRIBUTE_NAME, "Name"),
		      "Attribute Name");
	pass &= check(enter(&attr, KMIP_TAG_ATTRIBUTE_VALUE, &value) &&
		      next_text(&value, KMIP_TAG_NAME_VALUE, "nvme-psk-1") &&
		      next_enum(&value, KMIP_TAG_NAME_TYPE,
				KMIP_NAME_UNINTERPRETED_TEXT),
		      "Name Value and Name Type");

	return pass;
}

static bool test_build_locate(void)
{
	static const struct kmip_version v2_0 = { .major = 2, .minor = 0 };
	struct ttlv_reader payload, attr;
	struct ttlv_item it;
	struct ttlv_buf b;
	bool pass = true;

	printf("test_build_locate:\n");

	ttlv_buf_init(&b);
	pass &= check(kmip_build_locate(&b, &kmip_v1_4, "nvme-psk-1",
					KMIP_STATE_ANY) == 0,
		      "build without State");
	pass &= check_locate(&b, &payload);
	pass &= check(ttlv_next(&payload, &it) == 0, "nothing else");
	ttlv_buf_free(&b);

	ttlv_buf_init(&b);
	pass &= check(kmip_build_locate(&b, &kmip_v1_4, "nvme-psk-1",
					KMIP_STATE_ACTIVE) == 0,
		      "build with State Active");
	pass &= check_locate(&b, &payload);
	pass &= check(enter(&payload, KMIP_TAG_ATTRIBUTE, &attr) &&
		      next_text(&attr, KMIP_TAG_ATTRIBUTE_NAME, "State") &&
		      next_enum(&attr, KMIP_TAG_ATTRIBUTE_VALUE,
				KMIP_STATE_ACTIVE),
		      "State Active");
	pass &= check(ttlv_next(&payload, &it) == 0, "nothing else");
	ttlv_buf_free(&b);

	ttlv_buf_init(&b);
	pass &= check(kmip_build_locate(&b, &v2_0, "nvme-psk-1",
					KMIP_STATE_ANY) ==
		      -EOPNOTSUPP, "Protocol Version 2.0 not supported");
	ttlv_buf_free(&b);

	return pass;
}

static bool test_build_get(void)
{
	struct ttlv_reader payload;
	struct ttlv_item it;
	struct ttlv_buf b;
	bool pass = true;

	printf("test_build_get:\n");

	ttlv_buf_init(&b);
	pass &= check(kmip_build_get(&b, &kmip_v1_4, "uid-1") == 0, "build");
	pass &= check_request(&b, KMIP_OP_GET, &payload);
	pass &= check(next_text(&payload, KMIP_TAG_UNIQUE_IDENTIFIER,
				"uid-1"), "Unique Identifier");
	pass &= check(ttlv_next(&payload, &it) == 0, "nothing else");

	ttlv_buf_free(&b);

	return pass;
}

static int parse_locate(struct ttlv_buf *b, char *uid, size_t size,
		struct kmip_result *res)
{
	int ret = kmip_parse_locate(b->data, b->len, &kmip_v1_4, uid, size,
				    res);

	ttlv_buf_free(b);

	return ret;
}

static bool test_parse_locate(void)
{
	struct kmip_result res;
	struct ttlv_buf b;
	bool pass = true;
	char uid[64];

	printf("test_parse_locate:\n");

	locate_response(&b, 1);
	pass &= check(parse_locate(&b, uid, sizeof(uid), &res) == 0 &&
		      !strcmp(uid, "uid-1"), "one match");

	locate_response(&b, 0);
	pass &= check(parse_locate(&b, uid, sizeof(uid), &res) == -ENOENT,
		      "no match");

	locate_response(&b, 2);
	pass &= check(parse_locate(&b, uid, sizeof(uid), &res) == -ENOTUNIQ,
		      "two matches");

	locate_response(&b, 1);
	pass &= check(parse_locate(&b, uid, 5, &res) == -EMSGSIZE,
		      "buffer too small for the identifier");

	begin_response(&b, 1, KMIP_OP_LOCATE, 1);
	ttlv_add_enum(&b, KMIP_TAG_RESULT_REASON, 1);
	ttlv_add_text(&b, KMIP_TAG_RESULT_MESSAGE, "no such object");
	end_response(&b);
	pass &= check(parse_locate(&b, uid, sizeof(uid), &res) ==
		      -EREMOTEIO && res.status == 1 && res.reason == 1 &&
		      !strcmp(res.message, "no such object"),
		      "failed operation with reason and message");

	begin_response(&b, 1, KMIP_OP_LOCATE, 1);
	end_response(&b);
	pass &= check(parse_locate(&b, uid, sizeof(uid), &res) ==
		      -EREMOTEIO && res.reason == 0 && !res.message[0],
		      "failed operation without reason or message");

	begin_response(&b, 1, KMIP_OP_GET, KMIP_STATUS_SUCCESS);
	end_response(&b);
	pass &= check(parse_locate(&b, uid, sizeof(uid), &res) == -EBADMSG,
		      "response to another operation");

	begin_response(&b, 2, KMIP_OP_LOCATE, KMIP_STATUS_SUCCESS);
	end_response(&b);
	pass &= check(parse_locate(&b, uid, sizeof(uid), &res) == -EBADMSG,
		      "Batch Count 2");

	begin_response(&b, 1, KMIP_OP_LOCATE, KMIP_STATUS_SUCCESS);
	end_response(&b);
	pass &= check(parse_locate(&b, uid, sizeof(uid), &res) == -EBADMSG,
		      "no Response Payload");

	/* A server that cannot parse the request names no Operation. */
	begin_response(&b, 1, 0, 1);
	ttlv_add_enum(&b, KMIP_TAG_RESULT_REASON, 4);	// Invalid Message
	end_response(&b);
	pass &= check(parse_locate(&b, uid, sizeof(uid), &res) ==
		      -EREMOTEIO && res.reason == 4,
		      "failed operation without Operation");

	begin_response_version(&b, 1, 2, 1, KMIP_OP_LOCATE,
			       KMIP_STATUS_SUCCESS);
	ttlv_begin(&b, KMIP_TAG_RESPONSE_PAYLOAD);
	ttlv_add_text(&b, KMIP_TAG_UNIQUE_IDENTIFIER, "uid-1");
	ttlv_end(&b);
	end_response(&b);
	pass &= check(parse_locate(&b, uid, sizeof(uid), &res) == 0 &&
		      !strcmp(uid, "uid-1"), "Protocol Version 1.2");

	begin_response_version(&b, 2, 0, 1, KMIP_OP_LOCATE,
			       KMIP_STATUS_SUCCESS);
	end_response(&b);
	pass &= check(parse_locate(&b, uid, sizeof(uid), &res) == -EPROTO,
		      "Protocol Version 2.0");

	locate_response(&b, 1);
	pass &= check(kmip_parse_locate(b.data, b.len - 8, &kmip_v1_4, uid,
					sizeof(uid), &res) == -EBADMSG,
		      "truncated response");
	ttlv_buf_free(&b);

	return pass;
}

static int parse_get(struct ttlv_buf *b, uint32_t *type, uint8_t *key,
		size_t size, size_t *len)
{
	struct kmip_result res;
	int ret;

	ret = kmip_parse_get(b->data, b->len, &kmip_v1_4, type, key, size,
			     len, &res);
	ttlv_buf_free(b);

	return ret;
}

/* A PSK interchange string, as stored in Secret Data. */
static const char psk[] =
	"NVMeTLSkey-1:01:VRLbtnN9AQb2WXW3c9+wEf/DRLz0QuLdbYvEhwtdWwNf9LrZ:";

static bool test_parse_get(void)
{
	uint8_t raw[32], key[128];
	struct ttlv_buf b;
	bool pass = true;
	uint32_t type;
	size_t len;

	printf("test_parse_get:\n");

	memset(raw, 0xa5, sizeof(raw));

	get_response(&b, KMIP_OBJ_SECRET_DATA, KMIP_TAG_SECRET_DATA,
		     KMIP_KEY_FORMAT_OPAQUE, psk, strlen(psk));
	pass &= check(parse_get(&b, &type, key, sizeof(key), &len) == 0 &&
		      type == KMIP_OBJ_SECRET_DATA && len == strlen(psk) &&
		      !memcmp(key, psk, len),
		      "Secret Data, Opaque: interchange string");

	get_response(&b, KMIP_OBJ_SYMMETRIC_KEY, KMIP_TAG_SYMMETRIC_KEY,
		     KMIP_KEY_FORMAT_RAW, raw, sizeof(raw));
	pass &= check(parse_get(&b, &type, key, sizeof(key), &len) == 0 &&
		      type == KMIP_OBJ_SYMMETRIC_KEY && len == sizeof(raw) &&
		      !memcmp(key, raw, len), "Symmetric Key, Raw");

	get_response(&b, KMIP_OBJ_SYMMETRIC_KEY, KMIP_TAG_SYMMETRIC_KEY,
		     0x07, raw, sizeof(raw));
	pass &= check(parse_get(&b, &type, key, sizeof(key), &len) ==
		      -EOPNOTSUPP, "Transparent Symmetric Key format");

	get_response(&b, 0x01, 0x420013, KMIP_KEY_FORMAT_RAW, raw,
		     sizeof(raw));	// Certificate
	pass &= check(parse_get(&b, &type, key, sizeof(key), &len) ==
		      -EOPNOTSUPP, "Certificate object");

	get_response(&b, KMIP_OBJ_SYMMETRIC_KEY, KMIP_TAG_SYMMETRIC_KEY,
		     KMIP_KEY_FORMAT_RAW, raw, sizeof(raw));
	pass &= check(parse_get(&b, &type, key, 16, &len) == -EMSGSIZE,
		      "buffer too small for the key");

	get_response(&b, KMIP_OBJ_SYMMETRIC_KEY, KMIP_TAG_SECRET_DATA,
		     KMIP_KEY_FORMAT_RAW, raw, sizeof(raw));
	pass &= check(parse_get(&b, &type, key, sizeof(key), &len) ==
		      -EBADMSG, "object does not match the Object Type");

	get_response(&b, KMIP_OBJ_SYMMETRIC_KEY, KMIP_TAG_SYMMETRIC_KEY,
		     KMIP_KEY_FORMAT_RAW, raw, 0);
	pass &= check(parse_get(&b, &type, key, sizeof(key), &len) ==
		      -EBADMSG, "empty Key Material");

	return pass;
}

/* Every prefix of a valid response is rejected, and read within bounds. */
static bool test_truncated(void)
{
	struct kmip_result res;
	uint8_t key[64];
	struct ttlv_buf b;
	bool pass = true;
	uint32_t type;
	char uid[64];
	size_t len;

	printf("test_truncated:\n");

	locate_response(&b, 1);
	for (size_t n = 0; n < b.len; n++) {
		uint8_t *copy = malloc(n ?: 1);

		memcpy(copy, b.data, n);
		pass &= kmip_parse_locate(copy, n, &kmip_v1_4, uid,
					  sizeof(uid), &res) < 0;
		free(copy);
	}
	ttlv_buf_free(&b);
	pass &= check(pass, "Locate response prefixes");

	get_response(&b, KMIP_OBJ_SYMMETRIC_KEY, KMIP_TAG_SYMMETRIC_KEY,
		     KMIP_KEY_FORMAT_RAW, "0123456789abcdef", 16);
	for (size_t n = 0; n < b.len; n++) {
		uint8_t *copy = malloc(n ?: 1);

		memcpy(copy, b.data, n);
		pass &= kmip_parse_get(copy, n, &kmip_v1_4, &type, key,
				       sizeof(key), &len, &res) < 0;
		free(copy);
	}
	ttlv_buf_free(&b);
	pass &= check(pass, "Get response prefixes");

	return pass;
}

int main(void)
{
	bool pass = true;

	pass &= test_build_locate();
	pass &= test_build_get();
	pass &= test_parse_locate();
	pass &= test_parse_get();
	pass &= test_truncated();

	fflush(stdout);
	exit(pass ? EXIT_SUCCESS : EXIT_FAILURE);
}
