// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */

#include <errno.h>
#include <string.h>

#include "kmip.h"

/* Ask for two matches, to find out if a name is ambiguous. */
#define LOCATE_MAX_ITEMS	2

const struct kmip_version kmip_v1_4 = { .major = 1, .minor = 4 };

static void begin_request(struct ttlv_buf *b, const struct kmip_version *v,
		enum kmip_op op)
{
	ttlv_begin(b, KMIP_TAG_REQUEST_MESSAGE);

	ttlv_begin(b, KMIP_TAG_REQUEST_HEADER);
	ttlv_begin(b, KMIP_TAG_PROTOCOL_VERSION);
	ttlv_add_int(b, KMIP_TAG_PROTOCOL_VERSION_MAJOR, v->major);
	ttlv_add_int(b, KMIP_TAG_PROTOCOL_VERSION_MINOR, v->minor);
	ttlv_end(b);
	ttlv_add_int(b, KMIP_TAG_BATCH_COUNT, 1);
	ttlv_end(b);

	ttlv_begin(b, KMIP_TAG_BATCH_ITEM);
	ttlv_add_enum(b, KMIP_TAG_OPERATION, op);
	ttlv_begin(b, KMIP_TAG_REQUEST_PAYLOAD);
}

static int end_request(struct ttlv_buf *b)
{
	ttlv_end(b);	// Request Payload
	ttlv_end(b);	// Batch Item
	ttlv_end(b);	// Request Message

	return b->err;
}

/* Add a KMIP 1.x Name attribute with @name as Uninterpreted Text. */
static void add_name_attr_v1(struct ttlv_buf *b, const char *name)
{
	ttlv_begin(b, KMIP_TAG_ATTRIBUTE);
	ttlv_add_text(b, KMIP_TAG_ATTRIBUTE_NAME, "Name");
	ttlv_begin(b, KMIP_TAG_ATTRIBUTE_VALUE);
	ttlv_add_text(b, KMIP_TAG_NAME_VALUE, name);
	ttlv_add_enum(b, KMIP_TAG_NAME_TYPE, KMIP_NAME_UNINTERPRETED_TEXT);
	ttlv_end(b);	// Attribute Value
	ttlv_end(b);	// Attribute
}

/* Add a KMIP 1.x State attribute. */
static void add_state_attr_v1(struct ttlv_buf *b, enum kmip_state state)
{
	ttlv_begin(b, KMIP_TAG_ATTRIBUTE);
	ttlv_add_text(b, KMIP_TAG_ATTRIBUTE_NAME, "State");
	ttlv_add_enum(b, KMIP_TAG_ATTRIBUTE_VALUE, state);
	ttlv_end(b);	// Attribute
}

int kmip_build_locate(struct ttlv_buf *b, const struct kmip_version *v,
		const char *name, enum kmip_state state)
{
	if (v->major != 1)
		return -EOPNOTSUPP;

	begin_request(b, v, KMIP_OP_LOCATE);
	ttlv_add_int(b, KMIP_TAG_MAXIMUM_ITEMS, LOCATE_MAX_ITEMS);
	add_name_attr_v1(b, name);
	if (state != KMIP_STATE_ANY)
		add_state_attr_v1(b, state);

	return end_request(b);
}

int kmip_build_get(struct ttlv_buf *b, const struct kmip_version *v,
		const char *uid)
{
	begin_request(b, v, KMIP_OP_GET);
	ttlv_add_text(b, KMIP_TAG_UNIQUE_IDENTIFIER, uid);

	return end_request(b);
}

/* Find the structure with @tag in @r and open it in @sub. */
static int open_struct(struct ttlv_reader *r, enum kmip_tag tag,
		struct ttlv_reader *sub)
{
	struct ttlv_item it;
	int ret;

	ret = ttlv_find(r, tag, &it);
	if (ret <= 0)
		return -EBADMSG;

	return ttlv_open(&it, sub);
}

static int find_enum(struct ttlv_reader *r, enum kmip_tag tag, uint32_t *v)
{
	struct ttlv_item it;

	if (ttlv_find(r, tag, &it) <= 0)
		return -EBADMSG;

	return ttlv_get_enum(&it, v);
}

static void copy_text(char *dst, size_t size, const struct ttlv_item *it)
{
	size_t len = it->len < size - 1 ? it->len : size - 1;

	memcpy(dst, it->val, len);
	dst[len] = '\0';
}

/* Read the reason and message of a failed batch item. Both are optional. */
static void read_failure(const struct ttlv_reader *item,
		struct kmip_result *res)
{
	struct ttlv_reader r = *item;
	struct ttlv_item it;

	if (ttlv_find(&r, KMIP_TAG_RESULT_REASON, &it) > 0)
		ttlv_get_enum(&it, &res->reason);

	r = *item;
	if (ttlv_find(&r, KMIP_TAG_RESULT_MESSAGE, &it) > 0 &&
	    it.type == TTLV_TEXT)
		copy_text(res->message, sizeof(res->message), &it);
}

/*
 * A server answers with any minor version of the major version of the
 * request (KMIP 1.4, section 6.1).
 */
static int check_version(struct ttlv_reader *hdr, const struct kmip_version *v)
{
	struct ttlv_reader ver;
	struct ttlv_item it;
	int32_t major;

	if (open_struct(hdr, KMIP_TAG_PROTOCOL_VERSION, &ver) ||
	    ttlv_find(&ver, KMIP_TAG_PROTOCOL_VERSION_MAJOR, &it) <= 0 ||
	    ttlv_get_int(&it, &major))
		return -EBADMSG;

	return major == v->major ? 0 : -EPROTO;
}

/*
 * Check the response to a request for operation @op and protocol version
 * @v, and open its payload in @payload.
 */
static int open_response(const void *buf, size_t len,
		const struct kmip_version *v, enum kmip_op op,
		struct ttlv_reader *payload, struct kmip_result *res)
{
	struct ttlv_reader r, msg, hdr, item;
	struct ttlv_item it;
	uint32_t resp_op;
	int32_t count;
	int ret;

	memset(res, 0, sizeof(*res));

	ttlv_reader_init(&r, buf, len);
	ret = open_struct(&r, KMIP_TAG_RESPONSE_MESSAGE, &msg);
	if (ret)
		return ret;

	r = msg;
	ret = open_struct(&r, KMIP_TAG_RESPONSE_HEADER, &hdr);
	if (ret)
		return ret;
	r = hdr;
	ret = check_version(&r, v);
	if (ret)
		return ret;
	if (ttlv_find(&hdr, KMIP_TAG_BATCH_COUNT, &it) <= 0 ||
	    ttlv_get_int(&it, &count) || count != 1)
		return -EBADMSG;

	ret = open_struct(&msg, KMIP_TAG_BATCH_ITEM, &item);
	if (ret)
		return ret;

	/*
	 * A message the server cannot parse fails without an Operation
	 * (KMIP 1.4, section 11.1), so read the Result Status first.
	 */
	r = item;
	if (find_enum(&r, KMIP_TAG_RESULT_STATUS, &res->status))
		return -EBADMSG;
	if (res->status != KMIP_STATUS_SUCCESS) {
		read_failure(&item, res);
		return -EREMOTEIO;
	}

	r = item;
	if (find_enum(&r, KMIP_TAG_OPERATION, &resp_op) || resp_op != op)
		return -EBADMSG;

	r = item;

	return open_struct(&r, KMIP_TAG_RESPONSE_PAYLOAD, payload);
}

int kmip_parse_locate(const void *buf, size_t len,
		const struct kmip_version *v, char *uid, size_t uid_size,
		struct kmip_result *res)
{
	struct ttlv_reader payload;
	struct ttlv_item it, next;
	int ret;

	ret = open_response(buf, len, v, KMIP_OP_LOCATE, &payload, res);
	if (ret)
		return ret;

	ret = ttlv_find(&payload, KMIP_TAG_UNIQUE_IDENTIFIER, &it);
	if (ret < 0)
		return ret;
	if (!ret)
		return -ENOENT;
	if (it.type != TTLV_TEXT || !it.len || memchr(it.val, '\0', it.len))
		return -EBADMSG;

	ret = ttlv_find(&payload, KMIP_TAG_UNIQUE_IDENTIFIER, &next);
	if (ret < 0)
		return ret;
	if (ret)
		return -ENOTUNIQ;

	if (it.len >= uid_size)
		return -EMSGSIZE;
	copy_text(uid, uid_size, &it);

	return 0;
}

/* Copy the key material of the Key Block @kb to @key. */
static int read_key_block(struct ttlv_reader *kb, uint8_t *key,
		size_t key_size, size_t *key_len)
{
	struct ttlv_reader r = *kb, kv;
	struct ttlv_item it;
	uint32_t format;

	if (find_enum(&r, KMIP_TAG_KEY_FORMAT_TYPE, &format))
		return -EBADMSG;
	if (format != KMIP_KEY_FORMAT_RAW && format != KMIP_KEY_FORMAT_OPAQUE)
		return -EOPNOTSUPP;

	r = *kb;
	if (open_struct(&r, KMIP_TAG_KEY_VALUE, &kv))
		return -EBADMSG;
	if (ttlv_find(&kv, KMIP_TAG_KEY_MATERIAL, &it) <= 0 ||
	    it.type != TTLV_BYTES || !it.len)
		return -EBADMSG;

	if (it.len > key_size)
		return -EMSGSIZE;
	memcpy(key, it.val, it.len);
	*key_len = it.len;

	return 0;
}

int kmip_parse_get(const void *buf, size_t len,
		const struct kmip_version *v, uint32_t *obj_type, uint8_t *key,
		size_t key_size, size_t *key_len, struct kmip_result *res)
{
	struct ttlv_reader payload, r, obj, kb;
	enum kmip_tag tag;
	int ret;

	ret = open_response(buf, len, v, KMIP_OP_GET, &payload, res);
	if (ret)
		return ret;

	r = payload;
	if (find_enum(&r, KMIP_TAG_OBJECT_TYPE, obj_type))
		return -EBADMSG;

	switch (*obj_type) {
	case KMIP_OBJ_SYMMETRIC_KEY:
		tag = KMIP_TAG_SYMMETRIC_KEY;
		break;
	case KMIP_OBJ_SECRET_DATA:
		tag = KMIP_TAG_SECRET_DATA;
		break;
	default:
		return -EOPNOTSUPP;
	}

	r = payload;
	if (open_struct(&r, tag, &obj) || open_struct(&obj, KMIP_TAG_KEY_BLOCK,
						      &kb))
		return -EBADMSG;

	return read_key_block(&kb, key, key_size, key_len);
}
