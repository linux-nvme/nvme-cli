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

#include "ttlv.h"

/*
 * KMIP 1.4 requests and responses: Locate a key by name, and Get it.
 * Requests carry one batch item.
 */

/* Protocol Version (KMIP 1.4, section 6.1) */
struct kmip_version {
	int32_t major;
	int32_t minor;
};

extern const struct kmip_version kmip_v1_4;

/* Tags (KMIP 1.4, section 9.1.3.1) */
enum kmip_tag {
	KMIP_TAG_ATTRIBUTE		= 0x420008,
	KMIP_TAG_ATTRIBUTE_NAME		= 0x42000a,
	KMIP_TAG_ATTRIBUTE_VALUE	= 0x42000b,
	KMIP_TAG_BATCH_COUNT		= 0x42000d,
	KMIP_TAG_BATCH_ITEM		= 0x42000f,
	KMIP_TAG_KEY_BLOCK		= 0x420040,
	KMIP_TAG_KEY_FORMAT_TYPE	= 0x420042,
	KMIP_TAG_KEY_MATERIAL		= 0x420043,
	KMIP_TAG_KEY_VALUE		= 0x420045,
	KMIP_TAG_MAXIMUM_ITEMS		= 0x42004f,
	KMIP_TAG_NAME_TYPE		= 0x420054,
	KMIP_TAG_NAME_VALUE		= 0x420055,
	KMIP_TAG_OBJECT_TYPE		= 0x420057,
	KMIP_TAG_OPERATION		= 0x42005c,
	KMIP_TAG_PROTOCOL_VERSION	= 0x420069,
	KMIP_TAG_PROTOCOL_VERSION_MAJOR	= 0x42006a,
	KMIP_TAG_PROTOCOL_VERSION_MINOR	= 0x42006b,
	KMIP_TAG_REQUEST_HEADER		= 0x420077,
	KMIP_TAG_REQUEST_MESSAGE	= 0x420078,
	KMIP_TAG_REQUEST_PAYLOAD	= 0x420079,
	KMIP_TAG_RESPONSE_HEADER	= 0x42007a,
	KMIP_TAG_RESPONSE_MESSAGE	= 0x42007b,
	KMIP_TAG_RESPONSE_PAYLOAD	= 0x42007c,
	KMIP_TAG_RESULT_MESSAGE		= 0x42007d,
	KMIP_TAG_RESULT_REASON		= 0x42007e,
	KMIP_TAG_RESULT_STATUS		= 0x42007f,
	KMIP_TAG_SECRET_DATA		= 0x420085,
	KMIP_TAG_STATE			= 0x42008d,
	KMIP_TAG_SYMMETRIC_KEY		= 0x42008f,
	KMIP_TAG_TIME_STAMP		= 0x420092,
	KMIP_TAG_UNIQUE_IDENTIFIER	= 0x420094,
};

/* Operation (KMIP 1.4, section 9.1.3.2.27) */
enum kmip_op {
	KMIP_OP_LOCATE	= 0x08,
	KMIP_OP_GET	= 0x0a,
};

/* Object Type (KMIP 1.4, section 9.1.3.2.12) */
enum kmip_obj_type {
	KMIP_OBJ_SYMMETRIC_KEY	= 0x02,
	KMIP_OBJ_SECRET_DATA	= 0x07,
};

/* Result Status (KMIP 1.4, section 9.1.3.2.28) */
enum kmip_result_status {
	KMIP_STATUS_SUCCESS	= 0x00,
};

/* State (KMIP 1.4, section 9.1.3.2.18) */
enum kmip_state {
	KMIP_STATE_ANY		= 0x00,	// not a KMIP value: no State filter
	KMIP_STATE_ACTIVE	= 0x02,
};

/* Name Type (KMIP 1.4, section 9.1.3.2.11) */
enum kmip_name_type {
	KMIP_NAME_UNINTERPRETED_TEXT	= 0x01,
};

/* Key Format Type (KMIP 1.4, section 9.1.3.2.3) */
enum kmip_key_format {
	KMIP_KEY_FORMAT_RAW	= 0x01,
	KMIP_KEY_FORMAT_OPAQUE	= 0x02,
};

/* The result of a failed operation, for the log. */
struct kmip_result {
	uint32_t status;
	uint32_t reason;	// 0 if the response has none
	char message[128];	// empty if the response has none
};

/*
 * Build a request for protocol version @v. Returns 0 or a negative errno:
 * -EOPNOTSUPP if Locate does not support the major version of @v.
 *
 * Locate matches objects named @name and, unless @state is
 * KMIP_STATE_ANY, in @state.
 */
int kmip_build_locate(struct ttlv_buf *b, const struct kmip_version *v,
		const char *name, enum kmip_state state);
int kmip_build_get(struct ttlv_buf *b, const struct kmip_version *v,
		const char *uid);

/*
 * Parse a Locate response to a request for protocol version @v, and copy
 * the Unique Identifier of the only match to @uid. Returns 0, or:
 *   -EREMOTEIO	the operation failed, see @res
 *   -EPROTO	the response has another major protocol version
 *   -ENOENT	no object has this name
 *   -ENOTUNIQ	more than one object has this name
 *   -EMSGSIZE	@uid is too small
 *   -EBADMSG	malformed response
 */
int kmip_parse_locate(const void *buf, size_t len,
		const struct kmip_version *v, char *uid, size_t uid_size,
		struct kmip_result *res);

/*
 * Parse a Get response, set @obj_type (a KMIP_OBJ_* value) and copy the
 * key material to @key. The caller clears @key after use. Returns 0, or
 * -EREMOTEIO, -EPROTO, -EMSGSIZE, -EBADMSG as kmip_parse_locate(), or:
 *   -EOPNOTSUPP	not a Symmetric Key or Secret Data, or a key
 *			format other than Raw or Opaque
 */
int kmip_parse_get(const void *buf, size_t len,
		const struct kmip_version *v, uint32_t *obj_type, uint8_t *key,
		size_t key_size, size_t *key_len, struct kmip_result *res);
