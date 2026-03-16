// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2020 Western Digital Corporation or its affiliates.
 *
 * Authors: Keith Busch <keith.busch@wdc.com>
 *	    Chaitanya Kulkarni <chaitanya.kulkarni@wdc.com>
 */
#pragma once

#include <nvme/types.h>

/**
 * DOC: util.h
 *
 * libnvme utility functions
 */

/**
 * enum nvme_connect_err - nvme connect error codes
 * @ENVME_CONNECT_RESOLVE:	failed to resolve host
 * @ENVME_CONNECT_ADDRFAM:	unrecognized address family
 * @ENVME_CONNECT_TRADDR:	failed to get traddr
 * @ENVME_CONNECT_TARG:		need a transport (-t) argument
 * @ENVME_CONNECT_AARG:		need a address (-a) argument
 * @ENVME_CONNECT_OPEN:		failed to open nvme-fabrics device
 * @ENVME_CONNECT_WRITE:	failed to write to nvme-fabrics device
 * @ENVME_CONNECT_READ:		failed to read from nvme-fabrics device
 * @ENVME_CONNECT_PARSE:	failed to parse ctrl info
 * @ENVME_CONNECT_INVAL_TR:	invalid transport type
 * @ENVME_CONNECT_LOOKUP_SUBSYS_NAME:	failed to lookup subsystem name
 * @ENVME_CONNECT_LOOKUP_SUBSYS: failed to lookup subsystem
 * @ENVME_CONNECT_ALREADY:	the connect attempt failed, already connected
 * @ENVME_CONNECT_INVAL:	invalid arguments/configuration
 * @ENVME_CONNECT_ADDRINUSE:	hostnqn already in use
 * @ENVME_CONNECT_NODEV:	invalid interface
 * @ENVME_CONNECT_OPNOTSUPP:	not supported
 * @ENVME_CONNECT_CONNREFUSED:	connection refused
 * @ENVME_CONNECT_ADDRNOTAVAIL:	cannot assign requested address
 * @ENVME_CONNECT_IGNORED:	connect attempt is ignored due to configuration
 * @ENVME_CONNECT_NOKEY:	the TLS key is missing
 */
enum nvme_connect_err {
	ENVME_CONNECT_RESOLVE	= 1000,
	ENVME_CONNECT_ADDRFAM,
	ENVME_CONNECT_TRADDR,
	ENVME_CONNECT_TARG,
	ENVME_CONNECT_AARG,
	ENVME_CONNECT_OPEN,
	ENVME_CONNECT_WRITE,
	ENVME_CONNECT_READ,
	ENVME_CONNECT_PARSE,
	ENVME_CONNECT_INVAL_TR,
	ENVME_CONNECT_LOOKUP_SUBSYS_NAME,
	ENVME_CONNECT_LOOKUP_SUBSYS,
	ENVME_CONNECT_ALREADY,
	ENVME_CONNECT_INVAL,
	ENVME_CONNECT_ADDRINUSE,
	ENVME_CONNECT_NODEV,
	ENVME_CONNECT_OPNOTSUPP,
	ENVME_CONNECT_CONNREFUSED,
	ENVME_CONNECT_ADDRNOTAVAIL,
	ENVME_CONNECT_IGNORED,
	ENVME_CONNECT_NOKEY,
};

/**
 * nvme_status_to_errno() - Converts nvme return status to errno
 * @status:  Return status from an nvme passthrough command
 * @fabrics: Set to true if &status is to a fabrics target.
 *
 * Return: An errno representing the nvme status if it is an nvme status field,
 * or unchanged status is < 0 since errno is already set.
 */
__u8 nvme_status_to_errno(int status, bool fabrics);

/**
 * nvme_status_to_string() - Returns string describing nvme return status.
 * @status:  Return status from an nvme passthrough command
 * @fabrics: Set to true if &status is to a fabrics target.
 *
 * Return: String representation of the nvme status if it is an nvme status field,
 * or a standard errno string if status is < 0.
 */
const char *nvme_status_to_string(int status, bool fabrics);

/**
 * nvme_sanitize_ns_status_to_string() - Returns sanitize ns status string.
 * @sc: Return status code from an sanitize ns command
 *
 * Return: The sanitize ns status string if it is a specific status code.
 */
static inline const char *
nvme_sanitize_ns_status_to_string(__u16 sc)
{
	switch (sc) {
	case NVME_SC_EXCEEDS_MAX_NS_SANITIZE:
		return "Req Exceeds Max NS Sanitize Operations In Progress";
	default:
		break;
	}

	return NULL;
};

/**
 * nvme_opcode_status_to_string() - Returns nvme opcode status string.
 * @status: Return status from an nvme passthrough command
 * @admin:  Set to true if an admin command
 * @opcode: Opcode from an nvme passthrough command
 *
 * Return: The nvme opcode status string if it is an nvme status field,
 * or a standard errno string if status is < 0.
 */
static inline const char *
nvme_opcode_status_to_string(int status, bool admin, __u8 opcode)
{
	__u16 sct = nvme_status_code_type(status);
	__u16 sc = nvme_status_code(status);
	const char *s = NULL;

	if (status >= 0 && sct == NVME_SCT_CMD_SPECIFIC) {
		if (admin && opcode == nvme_admin_sanitize_ns)
			s = nvme_sanitize_ns_status_to_string(sc);
	}

	if (s)
		return s;

	return nvme_status_to_string(status, false);
}

/**
 * nvme_errno_to_string() - Returns string describing nvme connect failures
 * @err: Returned error code from nvme_add_ctrl()
 *
 * Return: String representation of the nvme connect error codes
 */
const char *nvme_errno_to_string(int err);

/**
 * nvme_strerror() - Returns string describing nvme errors and errno
 * @err: Returned error codes from all libnvme functions
 *
 * Return: String representation of either the nvme connect error codes
 * (positive values) or errno string (negative values)
 */
const char *nvme_strerror(int err);

/**
 * nvmf_exat_ptr_next - Increment @p to the next element in the array.
 * @p: Pointer to an element of an array of "struct nvmf_ext_attr".
 *
 * Extended attributes are saved to an array of "struct nvmf_ext_attr"
 * where each element of the array is of variable size. In order to
 * move to the next element in the array one must increment the
 * pointer to the current element (@p) by the size of the current
 * element.
 *
 * Return: Pointer to the next element in the array.
 */
struct nvmf_ext_attr *nvmf_exat_ptr_next(struct nvmf_ext_attr *p);

/**
 * enum nvme_version - Selector for version to be returned by @nvme_get_version
 *
 * @NVME_VERSION_PROJECT:	Project release version
 * @NVME_VERSION_GIT:		Git reference
 */
enum nvme_version {
	NVME_VERSION_PROJECT	= 0,
	NVME_VERSION_GIT	= 1,
};

/**
 * nvme_get_version - Return version libnvme string
 * @type:	Selects which version type (see @struct nvme_version)
 *
 * Return: Returns version string for known types or else "n/a"
 */
const char *nvme_get_version(enum nvme_version type);

/**
 * nvme_uuid_to_string - Return string represenation of encoded UUID
 * @uuid:	Binary encoded input UUID
 * @str:	Output string represenation of UUID
 *
 * Return: Returns error code if type conversion fails.
 */
int nvme_uuid_to_string(unsigned char uuid[NVME_UUID_LEN], char *str);

/**
 * nvme_uuid_from_string - Return encoded UUID represenation of string UUID
 * @uuid:	Binary encoded input UUID
 * @str:	Output string represenation of UUID
 *
 * Return: Returns error code if type conversion fails.
 */
int nvme_uuid_from_string(const char *str, unsigned char uuid[NVME_UUID_LEN]);

/**
 * nvme_random_uuid - Generate random UUID
 * @uuid:       Generated random UUID
 *
 * Generate random number according
 * https://www.rfc-editor.org/rfc/rfc4122#section-4.4
 *
 * Return: Returns error code if generating of random number fails.
 */
int nvme_random_uuid(unsigned char uuid[NVME_UUID_LEN]);

/**
 * nvme_find_uuid - Find UUID position on UUID list
 * @uuid_list:	UUID list returned by identify UUID
 * @uuid:	Binary encoded input UUID
 *
 * Return: The array position where given UUID is present, or -1 on failure
 *  with errno set.
 */
int nvme_find_uuid(struct nvme_id_uuid_list *uuid_list,
		const unsigned char uuid[NVME_UUID_LEN]);

/**
 * nvme_basename - Return the final path component (the one after the last '/')
 * @path: A string containing a filesystem path
 *
 * Return: A pointer into the original null-terminated path string.
 */
char *nvme_basename(const char *path);
