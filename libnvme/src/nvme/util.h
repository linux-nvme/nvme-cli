// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2020 Western Digital Corporation or its affiliates.
 *
 * Authors: Keith Busch <keith.busch@wdc.com>
 *	    Chaitanya Kulkarni <chaitanya.kulkarni@wdc.com>
 */
#pragma once

#include <ifaddrs.h>

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

struct nvme_root;

int hostname2traddr(struct nvme_global_ctx *ctx, const char *traddr, char **hostname);

/**
 * get_entity_name - Get Entity Name (ENAME).
 * @buffer: The buffer where the ENAME will be saved as an ASCII string.
 * @bufsz:  The size of @buffer.
 *
 * Per TP8010, ENAME is defined as the name associated with the host (i.e.
 * hostname).
 *
 * Return: Number of characters copied to @buffer.
 */
size_t get_entity_name(char *buffer, size_t bufsz);

/**
 * get_entity_version - Get Entity Version (EVER).
 * @buffer: The buffer where the EVER will be saved as an ASCII string.
 * @bufsz:  The size of @buffer.
 *
 * EVER is defined as the operating system name and version as an ASCII
 * string. This function reads different files from the file system and
 * builds a string as follows: [os type] [os release] [distro release]
 *
 *     E.g. "Linux 5.17.0-rc1 SLES 15.4"
 *
 * Return: Number of characters copied to @buffer.
 */
size_t get_entity_version(char *buffer, size_t bufsz);

/**
 * kv_strip - Strip blanks from key value string
 * @kv: The key-value string to strip
 *
 * Strip leading/trailing blanks as well as trailing comments from the
 * Key=Value string pointed to by @kv.
 *
 * Return: A pointer to the stripped string. Note that the original string,
 * @kv, gets modified.
 */
char *kv_strip(char *kv);

/**
 * kv_keymatch - Look for key in key value string
 * @kv:  The key=value string to search for the presence of @key
 * @key: The key to look for
 *
 * Look for @key in the Key=Value pair pointed to by @k and return a
 * pointer to the Value if @key is found.
 *
 * Check if @kv starts with @key. If it does then make sure that we
 * have a whole-word match on the @key, and if we do, return a pointer
 * to the first character of value (i.e. skip leading spaces, tabs,
 * and equal sign)
 *
 * Return: A pointer to the first character of "value" if a match is found.
 * NULL otherwise.
 */
char *kv_keymatch(const char *kv, const char *key);

/**
 * startswith - Checks that a string starts with a given prefix.
 * @s:      The string to check
 * @prefix: A string that @s could be starting with
 *
 * Return: If @s starts with @prefix, then return a pointer within @s at
 * the first character after the matched @prefix. NULL otherwise.
 */
char *startswith(const char *s, const char *prefix);

#define __round_mask(val, mult) ((__typeof__(val))((mult)-1))

/**
 * round_up - Round a value @val to the next multiple specified by @mult.
 * @val:  Value to round
 * @mult: Multiple to round to.
 *
 * usage: int x = round_up(13, sizeof(__u32)); // 13 -> 16
 */
#define round_up(val, mult)     ((((val)-1) | __round_mask((val), (mult)))+1)

/**
 * nvmf_exat_len() - Return length rounded up by 4
 * @val_len: Value length
 *
 * Return the size in bytes, rounded to a multiple of 4 (e.g., size of
 * __u32), of the buffer needed to hold the exat value of size
 * @val_len.
 *
 * Return: Length rounded up by 4
 */
static inline __u16 nvmf_exat_len(size_t val_len)
{
	return (__u16)round_up(val_len, sizeof(__u32));
}

/**
 * nvmf_exat_size - Return min aligned size to hold value
 * @val_len: This is the length of the data to be copied to the "exatval"
 *           field of a "struct nvmf_ext_attr".
 *
 * Return the size of the "struct nvmf_ext_attr" needed to hold
 * a value of size @val_len.
 *
 * Return: The size in bytes, rounded to a multiple of 4 (i.e. size of
 * __u32), of the "struct nvmf_ext_attr" required to hold a string of
 * length @val_len.
 */
static inline __u16 nvmf_exat_size(size_t val_len)
{
	return (__u16)(sizeof(struct nvmf_ext_attr) + nvmf_exat_len(val_len));
}

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
 * nvme_uuid_random - Generate random UUID
 * @uuid:       Generated random UUID
 *
 * Generate random number according
 * https://www.rfc-editor.org/rfc/rfc4122#section-4.4
 *
 * Return: Returns error code if generating of random number fails.
 */
int nvme_uuid_random(unsigned char uuid[NVME_UUID_LEN]);

/**
 * nvme_uuid_find - Find UUID position on UUID list
 * @uuid_list:	UUID list returned by identify UUID
 * @uuid:	Binary encoded input UUID
 *
 * Return: The array position where given UUID is present, or -1 on failure with errno set.
 */
int nvme_uuid_find(struct nvme_id_uuid_list *uuid_list, const unsigned char uuid[NVME_UUID_LEN]);

/**
 * nvme_ipaddrs_eq - Check if 2 IP addresses are equal.
 * @addr1: IP address (can be IPv4 or IPv6)
 * @addr2: IP address (can be IPv4 or IPv6)
 *
 * Return: true if addr1 == addr2. false otherwise.
 */
bool nvme_ipaddrs_eq(const char *addr1, const char *addr2);

/**
 * nvme_iface_matching_addr - Get interface matching @addr
 * @iface_list: Interface list returned by getifaddrs()
 * @addr: Address to match
 *
 * Parse the interface list pointed to by @iface_list looking
 * for the interface that has @addr as one of its assigned
 * addresses.
 *
 * Return: The name of the interface that owns @addr or NULL.
 */
const char *nvme_iface_matching_addr(const struct ifaddrs *iface_list, const char *addr);

/**
 * nvme_iface_primary_addr_matches - Check that interface's primary address matches
 * @iface_list: Interface list returned by getifaddrs()
 * @iface: Interface to match
 * @addr: Address to match
 *
 * Parse the interface list pointed to by @iface_list and looking for
 * interface @iface. The get its primary address and check if it matches
 * @addr.
 *
 * Return: true if a match is found, false otherwise.
 */
bool nvme_iface_primary_addr_matches(const struct ifaddrs *iface_list, const char *iface, const char *addr);
