// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2020 Western Digital Corporation or its affiliates.
 *
 * Authors: Keith Busch <keith.busch@wdc.com>
 *	    Chaitanya Kulkarni <chaitanya.kulkarni@wdc.com>
 *	    Daniel Wagner <dwagner@suse.de>
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>

#include <nvme/lib-types.h>

/**
 * DOC: crypto.h
 *
 * crypto utility functions
 */
/**
 * enum libnvmf_hmac_alg - HMAC algorithm
 * @LIBNVMF_HMAC_ALG_NONE:	No HMAC algorithm
 * @LIBNVMF_HMAC_ALG_SHA2_256:	SHA2-256
 * @LIBNVMF_HMAC_ALG_SHA2_384:	SHA2-384
 * @LIBNVMF_HMAC_ALG_SHA2_512:	SHA2-512
 */
enum libnvmf_hmac_alg {
	LIBNVMF_HMAC_ALG_NONE		= 0,
	LIBNVMF_HMAC_ALG_SHA2_256	= 1,
	LIBNVMF_HMAC_ALG_SHA2_384	= 2,
	LIBNVMF_HMAC_ALG_SHA2_512	= 3,
};

/**
 * libnvmf_gen_kxchap_key() - KX-HMAC-CHAP key generation
 * @ctx:	struct libnvme_global_ctx object
 * @hostnqn:	Host NVMe Qualified Name
 * @hmac:	HMAC algorithm
 * @key_len:	Output key length
 * @secret:	Secret to used for digest
 * @key:	Generated KX-HMAC-CHAP key
 *
 * Return: If key generation was successful the function returns 0 or
 * a negative error code otherwise.
 */
int libnvmf_gen_kxchap_key(struct libnvme_global_ctx *ctx,
		char *hostnqn, enum libnvmf_hmac_alg hmac,
		unsigned int key_len, unsigned char *secret,
		unsigned char *key);

/**
 * libnvmf_lookup_keyring() - Lookup keyring serial number
 * @ctx:	struct libnvme_global_ctx object
 * @keyring:    Keyring name
 * @key:	Key serial number to return
 *
 * Looks up the serial number of the keyring @keyring.
 *
 * Return: 0 on success, negative error code otherwise.
 */
int libnvmf_lookup_keyring(struct libnvme_global_ctx *ctx,
		const char *keyring, long *key);

/**
 * libnvmf_describe_key_serial() - Return key description
 * @ctx:	struct libnvme_global_ctx object
 * @key_id:    Key serial number
 *
 * Fetches the description of the key or keyring identified
 * by the serial number @key_id.
 *
 * Return: The description of @key_id or NULL on failure.
 * The returned string needs to be freed by the caller.
 */
char *libnvmf_describe_key_serial(struct libnvme_global_ctx *ctx,
		long key_id);

/**
 * libnvmf_lookup_key() - Lookup key serial number
 * @ctx:	struct libnvme_global_ctx object
 * @type:	Key type
 * @identity:	Key description
 * @key:	Key serial number to return
 *
 * Looks up the serial number of the key @identity
 * with type @type in the current session keyring.
 *
 * Return: 0 on success, negative error code otherwise.
 */
int libnvmf_lookup_key(struct libnvme_global_ctx *ctx, const char *type,
		const char *identity, long *key);

/**
 * libnvmf_set_keyring() - Link keyring for lookup
 * @ctx:           struct libnvme_global_ctx object
 * @keyring_id:    Keyring id
 *
 * Links @keyring_id into the session keyring such that
 * its keys are available for further key lookups.
 *
 * Return: 0 on success, negative error code otherwise.
 */
int libnvmf_set_keyring(struct libnvme_global_ctx *ctx, long keyring_id);

/**
 * libnvmf_create_raw_secret() - Generate a raw secret buffer from input data
 * @ctx:		struct libnvme_global_ctx object
 * @secret:		Input secret data
 * @key_len:		The length of the raw_secret in bytes
 * @raw_secret:		Return buffer with the generated raw secret
 *
 * Transforms the provided @secret into a raw secret buffer suitable for
 * use with NVMe key management operations.
 *
 * The generated raw secret can subsequently be passed to
 * libnvmf_insert_tls_key_versioned() or libnvmf_update_key().
 *
 * Return: 0 on success, negative error code otherwise.
 */
int libnvmf_create_raw_secret(struct libnvme_global_ctx *ctx,
		const char *secret, size_t key_len, unsigned char **raw_secret);

/**
 * libnvmf_read_key() - Read key raw data
 * @ctx:		struct libnvme_global_ctx object
 * @keyring_id:		Id of the keyring holding @key_id
 * @key_id:		Key id
 * @len:		Length of @key to return
 * @key:		Raw key data to return
 *
 * Links the keyring specified by @keyring_id into the session
 * keyring and reads the payload of the key specified by @key_id.
 * @len holds the size of the returned buffer.
 * If @keyring_id is 0 the default keyring '.nvme' is used.
 *
 * Return: 0 on success, negative error code otherwise.
 */
int libnvmf_read_key(struct libnvme_global_ctx *ctx, long keyring_id,
		long key_id, int *len, unsigned char **key);

/**
 * libnvmf_update_key() - Update key raw data
 * @ctx:	struct libnvme_global_ctx object
 * @keyring_id:	Id of the keyring holding @key_id
 * @key_type:	Type of the key to insert
 * @identity:	Key identity string
 * @key_data:	Raw data of the key
 * @key_len:	Length of @key_data
 * @key:	Key serial to return
 *
 * Links the keyring specified by @keyring_id into the session
 * keyring and updates the key reference by @identity with @key_data.
 * The old key with identity @identity will be revoked to make it
 * inaccessible.
 *
 * Return: 0 on success, negative error code otherwise.
 */
int libnvmf_update_key(struct libnvme_global_ctx *ctx, long keyring_id,
		const char *key_type, const char *identity,
		unsigned char *key_data, int key_len, long *key);

/**
 * typedef libnvmf_scan_tls_keys_cb_t - Callback for iterating TLS PSKs
 * @ctx:	struct libnvme_global_ctx object
 * @keyring:	Keyring which has been iterated
 * @key:	Key for which the callback has been invoked
 * @desc:	Description of the key
 * @desc_len:	Length of @desc
 * @data:	Pointer for caller data
 *
 * Called for each TLS PSK in the keyring.
 */
typedef void (*libnvmf_scan_tls_keys_cb_t)(struct libnvme_global_ctx *ctx,
		long keyring, long key, char *desc, int desc_len, void *data);

/**
 * libnvmf_scan_tls_keys() - Iterate over TLS PSKs in a keyring
 * @ctx:	struct libnvme_global_ctx object
 * @keyring:	Keyring holding TLS PSKs
 * @cb:		Callback function
 * @data:	Pointer for data to be passed to @cb
 *
 * Iterates @keyring and call @cb for each TLS PSK. When @keyring is NULL
 * the default '.nvme' keyring is used.
 * A key holding a TLS PSK must be of type 'psk' and its description must
 * be of the form 'NVMe<0|1><R|G><01|02> <identity>', otherwise it will be
 * skipped during iteration.
 *
 * Return: Number of keys for which @cb was called, or negative error code
 */
int libnvmf_scan_tls_keys(struct libnvme_global_ctx *ctx, const char *keyring,
		libnvmf_scan_tls_keys_cb_t cb, void *data);

/**
 * libnvmf_insert_tls_key() - Derive and insert a TLS PSK
 * @ctx:	struct libnvme_global_ctx object
 * @keyring:	Keyring to use
 * @key_type:	Type of the resulting key
 * @hostnqn:	Host NVMe Qualified Name
 * @subsysnqn:	Subsystem NVMe Qualified Name
 * @hmac:	HMAC algorithm
 * @configured_key:	Configured PSK to derive the retained PSK from
 * @key_len:	Length of @configured_key
 * @key:	Key serial to return
 *
 * Derives a retained PSK from @configured_key and, from that, the TLS PSK
 * and its identity, using identity version 0, as specified in the NVMe
 * TCP Transport Specification 1.0, section 3.6.1.3. Stores the TLS PSK
 * as type @key_type under that identity in the keyring specified by
 * @keyring.
 *
 * The NVMe TCP Transport Specification 1.3 marks identity version 0
 * obsolete. Use libnvmf_insert_tls_key_versioned() to select the
 * identity version.
 *
 * Return: 0 on success, negative error code otherwise.
 */
int libnvmf_insert_tls_key(struct libnvme_global_ctx *ctx, const char *keyring,
		const char *key_type, const char *hostnqn,
		const char *subsysnqn, enum libnvmf_hmac_alg hmac,
		unsigned char *configured_key, int key_len, long *key);

/**
 * libnvmf_insert_tls_key_versioned() - Derive and insert a TLS PSK
 * @ctx:	struct libnvme_global_ctx object
 * @keyring:    Keyring to use
 * @key_type:	Type of the resulting key
 * @hostnqn:	Host NVMe Qualified Name
 * @subsysnqn:	Subsystem NVMe Qualified Name
 * @version:	TLS PSK identity version to use
 * @hmac:	HMAC algorithm
 * @configured_key:	Configured PSK to derive the retained PSK from
 * @key_len:	Length of @configured_key
 * @key:	Key serial to return
 *
 * Derives a retained PSK from @configured_key and, from that, the TLS PSK
 * and its identity as specified in the NVMe TCP Transport Specification
 * 1.3, section 3.6.1.3. Stores the TLS PSK as type @key_type under that
 * identity in the keyring specified by @keyring.
 *
 * @version selects the identity version: 0 is obsolete and defined in
 * the NVMe TCP Transport Specification 1.0, 1 is TLS 1.3 with the PSK
 * digest in the identity.
 *
 * Return: 0 on success, negative error code otherwise.
 */
int libnvmf_insert_tls_key_versioned(struct libnvme_global_ctx *ctx,
		const char *keyring, const char *key_type,
		const char *hostnqn, const char *subsysnqn,
		int version, enum libnvmf_hmac_alg hmac,
		unsigned char *configured_key, int key_len,
		long *key);

/**
 * libnvmf_insert_tls_key_compat() - Derive and insert a TLS PSK
 * @ctx:	struct libnvme_global_ctx object
 * @keyring:    Keyring to use
 * @key_type:	Type of the resulting key
 * @hostnqn:	Host NVMe Qualified Name
 * @subsysnqn:	Subsystem NVMe Qualified Name
 * @version:	TLS PSK identity version to use
 * @hmac:	HMAC algorithm
 * @configured_key:	Configured PSK to derive the retained PSK from
 * @key_len:	Length of @configured_key
 * @key:	Key serial to return
 *
 * Derives a retained PSK from @configured_key and, from that, the TLS PSK
 * and its identity as specified in the NVMe TCP Transport Specification
 * 1.3, section 3.6.1.3. Stores the TLS PSK as type @key_type under that
 * identity in the keyring specified by @keyring.
 * This function differs from libnvmf_insert_tls_key_versioned() in that
 * it uses the original implementation for HKDF Expand-Label which does
 * not prefix the 'info' and 'label' strings with the length.
 *
 * @version selects the identity version: 0 is obsolete and defined in
 * the NVMe TCP Transport Specification 1.0, 1 is TLS 1.3 with the PSK
 * digest in the identity.
 *
 * Return: 0 on success, negative error code otherwise.
 */
int libnvmf_insert_tls_key_compat(struct libnvme_global_ctx *ctx,
		const char *keyring, const char *key_type,
		const char *hostnqn, const char *subsysnqn,
		int version, enum libnvmf_hmac_alg hmac,
		unsigned char *configured_key, int key_len,
		long *key);

/**
 * libnvmf_generate_tls_key_identity() - Generate the TLS PSK identity
 * @ctx:	struct libnvme_global_ctx object
 * @hostnqn:	Host NVMe Qualified Name
 * @subsysnqn:	Subsystem NVMe Qualified Name
 * @version:	TLS PSK identity version to use
 * @hmac:	HMAC algorithm
 * @configured_key:	Configured PSK to derive the retained PSK from
 * @key_len:	Length of @configured_key
 * @identity:	TLS PSK identity to return
 *
 * Derives a retained PSK as specified in the NVMe TCP Transport
 * Specification 1.3, section 3.6.1.3, and generates the corresponding
 * TLS PSK identity.
 *
 * It is the responsibility of the caller to free the returned string.
 *
 * Return: 0 on success, negative error code otherwise.
 */
int libnvmf_generate_tls_key_identity(struct libnvme_global_ctx *ctx,
		const char *hostnqn, const char *subsysnqn,
		int version, enum libnvmf_hmac_alg hmac,
		unsigned char *configured_key, int key_len,
		char **identity);

/**
 * libnvmf_generate_tls_key_identity_compat() - Generate the TLS PSK identity
 * @ctx:	struct libnvme_global_ctx object
 * @hostnqn:	Host NVMe Qualified Name
 * @subsysnqn:	Subsystem NVMe Qualified Name
 * @version:	TLS PSK identity version to use
 * @hmac:	HMAC algorithm
 * @configured_key:	Configured PSK to derive the retained PSK from
 * @key_len:	Length of @configured_key
 * @identity:	TLS PSK identity to return
 *
 * Derives a retained PSK as specified in the NVMe TCP Transport
 * Specification 1.3, section 3.6.1.3, and generates the corresponding
 * TLS PSK identity. This function differs from
 * libnvmf_generate_tls_key_identity() in that it uses the original
 * implementation for HKDF-Expand-Label which does not prefix the 'info'
 * and 'label' strings with the length.
 *
 * It is the responsibility of the caller to free the returned string.
 *
 * Return: 0 on success, negative error code otherwise.
 */
int libnvmf_generate_tls_key_identity_compat(struct libnvme_global_ctx *ctx,
		const char *hostnqn, const char *subsysnqn,
		int version, enum libnvmf_hmac_alg hmac,
		unsigned char *configured_key,
		int key_len, char **identity);

/**
 * libnvmf_revoke_tls_key() - Revoke a TLS PSK from a keyring
 * @ctx:	struct libnvme_global_ctx object
 * @keyring:    Keyring to use
 * @key_type:    Type of the key to revoke
 * @identity:    Key identity string
 *
 * Return: 0 on success, negative error code otherwise.
 */
int libnvmf_revoke_tls_key(struct libnvme_global_ctx *ctx, const char *keyring,
		const char *key_type, const char *identity);

/**
 * libnvmf_export_tls_key() - Encode a PSK in the PSK interchange format
 * @ctx:	struct libnvme_global_ctx object
 * @key_data:	Raw PSK data
 * @key_len:	Length of @key_data
 * @encoded_keyp:	Encoded PSK to return
 *
 * Returns @key_data in the PSK Interchange format as defined in section
 * 3.6.1.5 of the NVMe TCP Transport Specification 1.3.
 *
 * It is the responsibility of the caller to free the returned
 * string.
 *
 * Return: 0 on success, negative error code otherwise.
 */
int libnvmf_export_tls_key(struct libnvme_global_ctx *ctx,
		const unsigned char *key_data, int key_len, char **encoded_keyp);

/**
 * libnvmf_export_tls_key_versioned() - Encode a PSK in the PSK
 * interchange format
 * @ctx:	struct libnvme_global_ctx object
 * @version:	Version of the PSK interchange format to write. The
 *		specification defines 1, which appears in the encoded
 *		string as the digit after "NVMeTLSkey-".
 * @hmac:	Hash function recorded in the encoded PSK, used to derive
 *		a retained PSK from a configured PSK
 * @key_data:	Raw PSK data
 * @key_len:	Length of @key_data
 * @encoded_keyp:	Encoded PSK to return
 *
 * Returns @key_data in the PSK Interchange format as defined in section
 * 3.6.1.5 of the NVMe TCP Transport Specification 1.3.
 *
 * It is the responsibility of the caller to free the returned
 * string.
 *
 * Return: 0 on success, negative error code otherwise.
 */
int libnvmf_export_tls_key_versioned(struct libnvme_global_ctx *ctx,
		unsigned char version, enum libnvmf_hmac_alg hmac,
		const unsigned char *key_data,
		size_t key_len, char **encoded_keyp);

/**
 * libnvmf_import_tls_key() - Decode a PSK from the PSK interchange format
 * @ctx:		struct libnvme_global_ctx object
 * @encoded_key:	PSK in PSK interchange format
 * @key_len:		Length of the decoded PSK to return
 * @hmac:		Hash function recorded in @encoded_key to return
 * @key:		Decoded PSK to return
 *
 * Decodes @encoded_key from the PSK Interchange format as defined in
 * section 3.6.1.5 of the NVMe TCP Transport Specification 1.3.
 *
 * It is the responsibility of the caller to free the returned buffer.
 *
 * Return: 0 on success, negative error code otherwise.
 */
int libnvmf_import_tls_key(struct libnvme_global_ctx *ctx,
		const char *encoded_key, int *key_len,
		enum libnvmf_hmac_alg *hmac, unsigned char **key);

/**
 * libnvmf_import_tls_key_versioned() - Decode a PSK from the PSK
 * interchange format
 * @ctx:		struct libnvme_global_ctx object
 * @encoded_key:	PSK in PSK interchange format
 * @version:		Version of the PSK interchange format read from
 *			@encoded_key to return. Always 1; any other value
 *			is rejected with -EINVAL.
 * @hmac:		Hash function recorded in @encoded_key to return; it
 *			derives a retained PSK from a configured PSK
 * @key_len:		Length of the decoded PSK to return
 * @key:		Decoded PSK to return
 *
 * Decodes @encoded_key from the PSK Interchange format as defined in
 * section 3.6.1.5 of the NVMe TCP Transport Specification 1.3.
 *
 * It is the responsibility of the caller to free the returned buffer.
 *
 * Return: 0 on success, negative error code otherwise.
 */
int libnvmf_import_tls_key_versioned(struct libnvme_global_ctx *ctx,
		const char *encoded_key, unsigned char *version,
		enum libnvmf_hmac_alg *hmac, size_t *key_len,
		unsigned char **key);
