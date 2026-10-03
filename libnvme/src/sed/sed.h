/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * This file is part of libnvme.
 * Copyright (c) 2026 SUSE Software Solutions
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>

#include <nvme/lib.h>
#include <nvme/types.h>
#include <sed/tcg-types.h>

/**
 * DOC: sed.h - TCG Storage (Self-Encrypting Drive) support
 */

/**
 * LIBNVME_SED_KEY_MAX - Maximum size of a SED key
 */
#define LIBNVME_SED_KEY_MAX	256

/**
 * enum libnvme_sed_key_type - Source of a SED key
 * @LIBNVME_SED_KEY_INCLUDED:	The key is stored in &struct libnvme_sed_key
 * @LIBNVME_SED_KEY_KEYRING:	The kernel looks up the key in its keyring
 */
enum libnvme_sed_key_type {
	LIBNVME_SED_KEY_INCLUDED	= 0,
	LIBNVME_SED_KEY_KEYRING		= 1,
};

/**
 * struct libnvme_sed_key - SED key (password or PSID)
 * @type:	Key source, see &enum libnvme_sed_key_type
 * @len:	Length of @key in bytes, ignored for
 *		%LIBNVME_SED_KEY_KEYRING
 * @key:	Key data
 */
struct libnvme_sed_key {
	__u8	type;
	__u8	len;
	__u8	key[LIBNVME_SED_KEY_MAX];
};

/**
 * enum libnvme_sed_lock_state - Locking range lock state
 * @LIBNVME_SED_LOCK_RO:	Read-only, writes are locked
 * @LIBNVME_SED_LOCK_RW:	Read-write, the range is unlocked
 * @LIBNVME_SED_LOCK_LK:	Reads and writes are locked
 */
enum libnvme_sed_lock_state {
	LIBNVME_SED_LOCK_RO		= 1 << 0,
	LIBNVME_SED_LOCK_RW		= 1 << 1,
	LIBNVME_SED_LOCK_LK		= 1 << 2,
};

/**
 * libnvme_sed_discover() - Retrieve the TCG Level 0 Discovery data
 * @hdl:	Transport handle
 * @buf:	Buffer for the Level 0 Discovery data
 * @len:	Size of @buf in bytes
 *
 * Issues a Security Receive for the Level 0 Discovery ComID. The data
 * is returned unparsed; use libnvme_sed_l0_for_each() or
 * libnvme_sed_l0_find() to walk the feature descriptors.
 *
 * Return: 0 on success, the NVMe command status if a response was
 * received (see &enum nvme_status_field) or a negative error code
 * otherwise.
 */
int libnvme_sed_discover(struct libnvme_transport_handle *hdl,
		void *buf, __u32 len);

/**
 * libnvme_sed_l0_next() - Return the next Level 0 Discovery descriptor
 * @buf:	Level 0 Discovery data
 * @len:	Size of @buf in bytes
 * @desc:	Current descriptor, or NULL to get the first descriptor
 *
 * The walk ends at the length reported in the header or at the end of
 * @buf, whichever comes first. A descriptor which does not fit
 * completely ends the walk.
 *
 * Return: Pointer to the next descriptor, or NULL if there is none.
 */
struct tcg_l0_desc *libnvme_sed_l0_next(void *buf, size_t len,
		struct tcg_l0_desc *desc);

/**
 * libnvme_sed_l0_find() - Find a Level 0 Discovery descriptor
 * @buf:	Level 0 Discovery data
 * @len:	Size of @buf in bytes
 * @code:	Feature code, see &enum tcg_l0_code
 *
 * Return: Pointer to the first descriptor with feature code @code, or
 * NULL if there is none.
 */
struct tcg_l0_desc *libnvme_sed_l0_find(void *buf, size_t len, __u16 code);

/**
 * libnvme_sed_l0_for_each() - Iterate over Level 0 Discovery descriptors
 * @desc:	&struct tcg_l0_desc pointer used as the loop cursor
 * @buf:	Level 0 Discovery data
 * @len:	Size of @buf in bytes
 */
#define libnvme_sed_l0_for_each(desc, buf, len)				\
	for (desc = libnvme_sed_l0_next(buf, len, NULL); desc;		\
	     desc = libnvme_sed_l0_next(buf, len, desc))

/**
 * libnvme_sed_l0_data() - Return the feature data of a descriptor
 * @desc:	Level 0 Discovery feature descriptor
 *
 * Return: Pointer to the feature data following the descriptor header.
 */
static inline void *libnvme_sed_l0_data(struct tcg_l0_desc *desc)
{
	return desc + 1;
}

/*
 * The functions below operate on the Admin1 authority and the global
 * locking range of the Locking SP. They must be issued on a namespace
 * handle.
 *
 * Unless stated otherwise they return 0 on success, the TCG method
 * status (see &enum tcg_method_status) if the TPer rejected the
 * operation or a negative error code otherwise.
 */

/**
 * libnvme_sed_take_ownership() - Take ownership of the TPer
 * @hdl:	Transport handle
 * @key:	New SID password
 *
 * Return: See the return value convention above.
 */
int libnvme_sed_take_ownership(struct libnvme_transport_handle *hdl,
		const struct libnvme_sed_key *key);

/**
 * libnvme_sed_activate_lsp() - Activate the Locking SP
 * @hdl:	Transport handle
 * @key:	SID password
 *
 * Return: See the return value convention above.
 */
int libnvme_sed_activate_lsp(struct libnvme_transport_handle *hdl,
		const struct libnvme_sed_key *key);

/**
 * libnvme_sed_setup_range() - Configure the global locking range
 * @hdl:	Transport handle
 * @key:	Admin1 password
 * @read_lock:	Enable read locking
 * @write_lock:	Enable write locking
 *
 * Return: See the return value convention above.
 */
int libnvme_sed_setup_range(struct libnvme_transport_handle *hdl,
		const struct libnvme_sed_key *key, bool read_lock,
		bool write_lock);

/**
 * libnvme_sed_lock_unlock() - Change the lock state of the global range
 * @hdl:	Transport handle
 * @key:	Admin1 password
 * @state:	New lock state, see &enum libnvme_sed_lock_state
 *
 * Return: See the return value convention above.
 */
int libnvme_sed_lock_unlock(struct libnvme_transport_handle *hdl,
		const struct libnvme_sed_key *key,
		enum libnvme_sed_lock_state state);

/**
 * libnvme_sed_set_password() - Change the Admin1 password
 * @hdl:	Transport handle
 * @key:	Current Admin1 password
 * @new_key:	New Admin1 password
 *
 * Return: See the return value convention above.
 */
int libnvme_sed_set_password(struct libnvme_transport_handle *hdl,
		const struct libnvme_sed_key *key,
		const struct libnvme_sed_key *new_key);

/**
 * libnvme_sed_set_sid_password() - Change the SID password
 * @hdl:	Transport handle
 * @key:	Current SID password
 * @new_key:	New SID password
 *
 * Return: See the return value convention above.
 */
int libnvme_sed_set_sid_password(struct libnvme_transport_handle *hdl,
		const struct libnvme_sed_key *key,
		const struct libnvme_sed_key *new_key);

/**
 * libnvme_sed_revert_tper() - Revert the TPer to its factory state
 * @hdl:	Transport handle
 * @key:	SID password
 *
 * This erases all user data.
 *
 * Return: See the return value convention above.
 */
int libnvme_sed_revert_tper(struct libnvme_transport_handle *hdl,
		const struct libnvme_sed_key *key);

/**
 * libnvme_sed_revert_psid() - Revert the TPer using the PSID
 * @hdl:	Transport handle
 * @psid:	Physical Security ID printed on the drive label
 *
 * This erases all user data.
 *
 * Return: See the return value convention above.
 */
int libnvme_sed_revert_psid(struct libnvme_transport_handle *hdl,
		const struct libnvme_sed_key *psid);

/**
 * libnvme_sed_revert_lsp() - Revert the Locking SP
 * @hdl:	Transport handle
 * @key:	Admin1 password
 * @keep_data:	Preserve the user data
 *
 * Return: See the return value convention above.
 */
int libnvme_sed_revert_lsp(struct libnvme_transport_handle *hdl,
		const struct libnvme_sed_key *key, bool keep_data);
