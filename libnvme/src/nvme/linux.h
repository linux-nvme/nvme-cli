// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2020 Western Digital Corporation or its affiliates.
 *
 * Authors: Keith Busch <keith.busch@wdc.com>
 *	    Chaitanya Kulkarni <chaitanya.kulkarni@wdc.com>
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>

#include <nvme/lib-types.h>

/**
 * DOC: linux.h
 *
 * linux-specific utility functions
 */
/**
 * enum nvme_hmac_alg - HMAC algorithm
 * @NVME_HMAC_ALG_NONE:		No HMAC algorithm
 * @NVME_HMAC_ALG_SHA2_256:	SHA2-256
 * @NVME_HMAC_ALG_SHA2_384:	SHA2-384
 * @NVME_HMAC_ALG_SHA2_512:	SHA2-512
 */
enum nvme_hmac_alg {
	NVME_HMAC_ALG_NONE	= 0,
	NVME_HMAC_ALG_SHA2_256	= 1,
	NVME_HMAC_ALG_SHA2_384	= 2,
	NVME_HMAC_ALG_SHA2_512	= 3,
};

/**
 * nvme_gen_dhchap_key() - DH-HMAC-CHAP key generation
 * @ctx:	struct nvme_global_ctx object
 * @hostnqn:	Host NVMe Qualified Name
 * @hmac:	HMAC algorithm
 * @key_len:	Output key length
 * @secret:	Secret to used for digest
 * @key:	Generated DH-HMAC-CHAP key
 *
 * Return: If key generation was successful the function returns 0 or
 * a negative error code otherwise.
 */
int nvme_gen_dhchap_key(struct nvme_global_ctx *ctx,
		char *hostnqn, enum nvme_hmac_alg hmac,
		unsigned int key_len, unsigned char *secret,
		unsigned char *key);

/**
 * nvme_lookup_keyring() - Lookup keyring serial number
 * @ctx:	struct nvme_global_ctx object
 * @keyring:    Keyring name
 * @key:	Key serial number to return
 *
 * Looks up the serial number of the keyring @keyring.
 *
 * Return: 0 on success or negative error code otherwise
 */
int nvme_lookup_keyring(struct nvme_global_ctx *ctx,
		const char *keyring, long *key);

/**
 * nvme_describe_key_serial() - Return key description
 * @ctx:	struct nvme_global_ctx object
 * @key_id:    Key serial number
 *
 * Fetches the description of the key or keyring identified
 * by the serial number @key_id.
 *
 * Return: The description of @key_id or NULL on failure.
 * The returned string needs to be freed by the caller.
 */
char *nvme_describe_key_serial(struct nvme_global_ctx *ctx,
		long key_id);

/**
 * nvme_lookup_key() - Lookup key serial number
 * @ctx:	struct nvme_global_ctx object
 * @type:	Key type
 * @identity:	Key description
 * @key:	Key serial number to return
 *
 * Looks up the serial number of the key @identity
 * with type %type in the current session keyring.
 *
 * Return: 0 on success or negative error code otherwise
 */
int nvme_lookup_key(struct nvme_global_ctx *ctx, const char *type,
		const char *identity, long *key);

/**
 * nvme_set_keyring() - Link keyring for lookup
 * @ctx:           struct nvme_global_ctx object
 * @keyring_id:    Keyring id
 *
 * Links @keyring_id into the session keyring such that
 * its keys are available for further key lookups.
 *
 * Return: 0 on success or negative error code otherwise
 */
int nvme_set_keyring(struct nvme_global_ctx *ctx, long keyring_id);

/**
 * nvme_read_key() - Read key raw data
 * @ctx:		struct nvme_global_ctx object
 * @keyring_id:		Id of the keyring holding %key_id
 * @key_id:		Key id
 * @len:		Length of the returned data
 * @key:		Key serial to return
 *
 * Links the keyring specified by @keyring_id into the session
 * keyring and reads the payload of the key specified by @key_id.
 * @len holds the size of the returned buffer.
 * If @keyring is 0 the default keyring '.nvme' is used.
 *
 * Return: 0 on success or negative error code otherwise
 */
int nvme_read_key(struct nvme_global_ctx *ctx, long keyring_id,
		long key_id, int *len, unsigned char **key);

/**
 * nvme_update_key() - Update key raw data
 * @ctx:	struct nvme_global_ctx object
 * @keyring_id:	Id of the keyring holding %key_id
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
 * Return: 0 on success or negative error code otherwise
 */
int nvme_update_key(struct nvme_global_ctx *ctx, long keyring_id,
		const char *key_type, const char *identity,
		unsigned char *key_data, int key_len, long *key);

/**
 * typedef nvme_scan_tls_keys_cb_t - Callback for iterating TLS keys
 * @ctx:	struct nvme_global_ctx object
 * @keyring:	Keyring which has been iterated
 * @key:	Key for which the callback has been invoked
 * @desc:	Description of the key
 * @desc_len:	Length of @desc
 * @data:	Pointer for caller data
 *
 * Called for each TLS PSK in the keyring.
 */
typedef void (*nvme_scan_tls_keys_cb_t)(struct nvme_global_ctx *ctx,
		long keyring, long key, char *desc, int desc_len, void *data);

/**
 * nvme_scan_tls_keys() - Iterate over TLS keys in a keyring
 * @ctx:	struct nvme_global_ctx object
 * @keyring:	Keyring holding TLS keys
 * @cb:		Callback function
 * @data:	Pointer for data to be passed to @cb
 *
 * Iterates @keyring and call @cb for each TLS key. When @keyring is NULL
 * the default '.nvme' keyring is used.
 * A TLS key must be of type 'psk' and the description must be of the
 * form 'NVMe<0|1><R|G>0<1|2> <identity>', otherwise it will be skipped
 * during iteration.
 *
 * Return: Number of keys for which @cb was called, or negative error code
 */
int nvme_scan_tls_keys(struct nvme_global_ctx *ctx, const char *keyring,
		nvme_scan_tls_keys_cb_t cb, void *data);

/**
 * nvme_insert_tls_key() - Derive and insert TLS key
 * @ctx:	struct nvme_global_ctx object
 * @keyring:	Keyring to use
 * @key_type:	Type of the resulting key
 * @hostnqn:	Host NVMe Qualified Name
 * @subsysnqn:	Subsystem NVMe Qualified Name
 * @hmac:	HMAC algorithm
 * @configured_key:	Configured key data to derive the key from
 * @key_len:	Length of @configured_key
 * @key:	Key serial to return
 *
 * Derives a 'retained' TLS key as specified in NVMe TCP 1.0a and
 * stores it as type @key_type in the keyring specified by @keyring.
 *
 * Return: 0 on success or negative error code otherwise
 */
int nvme_insert_tls_key(struct nvme_global_ctx *ctx, const char *keyring,
		const char *key_type, const char *hostnqn,
		const char *subsysnqn, int hmac, unsigned char *configured_key,
		int key_len, long *key);

/**
 * nvme_insert_tls_key_versioned() - Derive and insert TLS key
 * @ctx:	struct nvme_global_ctx object
 * @keyring:    Keyring to use
 * @key_type:	Type of the resulting key
 * @hostnqn:	Host NVMe Qualified Name
 * @subsysnqn:	Subsystem NVMe Qualified Name
 * @version:	Key version to use
 * @hmac:	HMAC algorithm
 * @configured_key:	Configured key data to derive the key from
 * @key_len:	Length of @configured_key
 * @key:	Key serial to return
 *
 * Derives a 'retained' TLS key as specified in NVMe TCP 1.0a (if
 * @version s set to '0') or NVMe TP8028 (if @version is set to '1) and
 * stores it as type @key_type in the keyring specified by @keyring.
 *
 * Return: 0 on success or negative error code otherwise
 */
int nvme_insert_tls_key_versioned(struct nvme_global_ctx *ctx,
		const char *keyring, const char *key_type,
		const char *hostnqn, const char *subsysnqn,
		int version, int hmac,
		unsigned char *configured_key, int key_len,
		long *key);

/**
 * nvme_insert_tls_key_compat() - Derive and insert TLS key
 * @ctx:	struct nvme_global_ctx object
 * @keyring:    Keyring to use
 * @key_type:	Type of the resulting key
 * @hostnqn:	Host NVMe Qualified Name
 * @subsysnqn:	Subsystem NVMe Qualified Name
 * @version:	Key version to use
 * @hmac:	HMAC algorithm
 * @configured_key:	Configured key data to derive the key from
 * @key_len:	Length of @configured_key
 * @key:	Key serial to return
 *
 * Derives a 'retained' TLS key as specified in NVMe TCP 1.0a (if
 * @version s set to '0') or NVMe TP8028 (if @version is set to '1) and
 * stores it as type @key_type in the keyring specified by @keyring.
 * This version differs from @nvme_insert_tls_key_versioned() in that it
 * uses the original implementation for HKDF Expand-Label which does not
 * prefix the 'info' and 'label' strings with the length.
 *
 * Return: The key serial number if the key could be inserted into
 * the keyring or 0 with errno otherwise.
 */
int nvme_insert_tls_key_compat(struct nvme_global_ctx *ctx,
		const char *keyring, const char *key_type,
		const char *hostnqn, const char *subsysnqn,
		int version, int hmac,
		unsigned char *configured_key, int key_len,
		long *key);

/**
 * nvme_generate_tls_key_identity() - Generate the TLS key identity
 * @ctx:	struct nvme_global_ctx object
 * @hostnqn:	Host NVMe Qualified Name
 * @subsysnqn:	Subsystem NVMe Qualified Name
 * @version:	Key version to use
 * @hmac:	HMAC algorithm
 * @configured_key:	Configured key data to derive the key from
 * @key_len:	Length of @configured_key
 * @identity:	TLS identity to return
 *
 * Derives a 'retained' TLS key as specified in NVMe TCP and
 * generate the corresponding TLs identity.
 *
 * It is the responsibility of the caller to free the returned string.
 *
 * Return: 0 on success or negative error code otherwise
 */
int nvme_generate_tls_key_identity(struct nvme_global_ctx *ctx,
		const char *hostnqn, const char *subsysnqn,
		int version, int hmac,
		unsigned char *configured_key, int key_len,
		char **identity);

/**
 * nvme_generate_tls_key_identity_compat() - Generate the TLS key identity
 * @ctx:	struct nvme_global_ctx object
 * @hostnqn:	Host NVMe Qualified Name
 * @subsysnqn:	Subsystem NVMe Qualified Name
 * @version:	Key version to use
 * @hmac:	HMAC algorithm
 * @configured_key:	Configured key data to derive the key from
 * @key_len:	Length of @configured_key
 * @identity:	TLS identity to return
 *
 * Derives a 'retained' TLS key as specified in NVMe TCP and
 * generate the corresponding TLs identity. This version differs
 * from @nvme_generate_tls_key_identity() in that it uses the original
 * implementation for HKDF-Expand-Label which does not prefix the 'info'
 * and 'label' string with the length.
 *
 * It is the responsibility of the caller to free the returned string.
 *
 * Return: 0 on success or negative error code otherwise
 */
int nvme_generate_tls_key_identity_compat(struct nvme_global_ctx *ctx,
		const char *hostnqn, const char *subsysnqn,
		int version, int hmac, unsigned char *configured_key,
		int key_len, char **identity);

/**
 * nvme_revoke_tls_key() - Revoke TLS key from keyring
 * @ctx:	struct nvme_global_ctx object
 * @keyring:    Keyring to use
 * @key_type:    Type of the key to revoke
 * @identity:    Key identity string
 *
 * Return: 0 on success or negative error code otherwise
 */
int nvme_revoke_tls_key(struct nvme_global_ctx *ctx, const char *keyring,
		const char *key_type, const char *identity);

/**
 * nvme_export_tls_key() - Export a TLS key
 * @ctx:	struct nvme_global_ctx object
 * @key_data:	Raw data of the key
 * @key_len:	Length of @key_data
 * @identity:	TLS identity
 *
 * Returns @key_data in the PSK Interchange format as defined in section
 * 3.6.1.5 of the NVMe TCP Transport specification.
 *
 * It is the responsibility of the caller to free the returned
 * string.
 *
 * Return: 0 on success or negative error code otherwise
 */
int nvme_export_tls_key(struct nvme_global_ctx *ctx,
		const unsigned char *key_data, int key_len, char **identity);

/**
 * nvme_export_tls_key_versioned() - Export a TLS pre-shared key
 * @ctx:	struct nvme_global_ctx object
 * @version:	Indicated the representation of the TLS PSK
 * @hmac:	HMAC algorithm used to transfor the configured PSK
 *		in a retained PSK
 * @key_data:	Raw data of the key
 * @key_len:	Length of @key_data
 * @identity:	TLS identity to return
 *
 * Returns @key_data in the PSK Interchange format as defined in section
 * 3.6.1.5 of the NVMe TCP Transport specification.
 *
 * It is the responsibility of the caller to free the returned
 * string.
 *
 * Return: 0 on success or negative error code otherwise
 */
int nvme_export_tls_key_versioned(struct nvme_global_ctx *ctx,
		unsigned char version, unsigned char hmac,
		const unsigned char *key_data,
		size_t key_len, char **identity);

/**
 * nvme_import_tls_key() - Import a TLS key
 * @ctx:		struct nvme_global_ctx object
 * @encoded_key:	TLS key in PSK interchange format
 * @key_len:		Length of the resulting key data
 * @hmac:		HMAC algorithm
 * @key:		Key serial to return
 *
 * Imports @key_data in the PSK Interchange format as defined in section
 * 3.6.1.5 of the NVMe TCP Transport specification.
 *
 * It is the responsibility of the caller to free the returned string.
 *
 * Return: 0 on success or negative error code otherwise
 */
int nvme_import_tls_key(struct nvme_global_ctx *ctx, const char *encoded_key,
		 int *key_len, unsigned int *hmac, unsigned char **key);

/**
 * nvme_import_tls_key_versioned() - Import a TLS key
 * @ctx:		struct nvme_global_ctx object
 * @encoded_key:	TLS key in PSK interchange format
 * @version:		Indicated the representation of the TLS PSK
 * @hmac:		HMAC algorithm used to transfor the configured
 *			PSK in a retained PSK
 * @key_len:		Length of the resulting key data
 * @key:		Key serial to return
 *
 * Imports @key_data in the PSK Interchange format as defined in section
 * 3.6.1.5 of the NVMe TCP Transport specification.
 *
 * It is the responsibility of the caller to free the returned string.
 *
 * Return: 0 on success or negative error code otherwise
 */
int nvme_import_tls_key_versioned(struct nvme_global_ctx *ctx,
		const char *encoded_key, unsigned char *version,
		unsigned char *hmac, size_t *key_len, unsigned char **key);

/**
 * nvme_hostnqn_generate() - Generate a machine specific host nqn
 * Returns: An nvm namespace qualified name string based on the machine
 * identifier, or NULL if not successful.
 */
char *nvme_hostnqn_generate();

/**
 * nvme_hostnqn_generate_from_hostid() - Generate a host nqn from
 * host identifier
 * @hostid:		Host identifier
 *
 * If @hostid is NULL, the function generates it based on the machine
 * identifier.
 *
 * Return: On success, an NVMe Qualified Name for host identification. This
 * name is based on the given host identifier. On failure, NULL.
 */
char *nvme_hostnqn_generate_from_hostid(char *hostid);

/**
 * nvme_hostid_generate() - Generate a machine specific host identifier
 *
 * Return: On success, an identifier string based on the machine identifier to
 * be used as NVMe Host Identifier, or NULL on failure.
 */
char *nvme_hostid_generate();

/**
 * nvme_hostnqn_from_file() - Reads the host nvm qualified name from the config
 *			      default location
 *
 * Retrieve the qualified name from the config file located in $SYSCONFDIR/nvme.
 * $SYSCONFDIR is usually /etc.
 *
 * Return: The host nqn, or NULL if unsuccessful. If found, the caller
 * is responsible to free the string.
 */
char *nvme_hostnqn_from_file();

/**
 * nvme_hostid_from_file() - Reads the host identifier from the config default
 *			     location
 *
 * Retrieve the host idenditifer from the config file located in
 * $SYSCONFDIR/nvme/. $SYSCONFDIR is usually /etc.
 *
 * Return: The host identifier, or NULL if unsuccessful. If found, the caller
 *	   is responsible to free the string.
 */
char *nvme_hostid_from_file();
