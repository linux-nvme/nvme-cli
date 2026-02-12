// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2020 Western Digital Corporation or its affiliates.
 *
 * Authors: Keith Busch <keith.busch@wdc.com>
 *	    Chaitanya Kulkarni <chaitanya.kulkarni@wdc.com>
 */
#ifndef _LIBNVME_LINUX_H
#define _LIBNVME_LINUX_H

#include <stddef.h>
#include <stdio.h>

#include <nvme/ioctl.h>
#include <nvme/types.h>

/**
 * DOC: linux.h
 *
 * linux-specific utility functions
 */

/**
 * nvme_fw_download_seq() - Firmware download sequence
 * @hdl:	Transport handle
 * @ish:	Ignore Shutdown (for NVMe-MI command)
 * @size:	Total size of the firmware image to transfer
 * @xfer:	Maximum size to send with each partial transfer
 * @offset:	Starting offset to send with this firmware download
 * @buf:	Address of buffer containing all or part of the firmware image.
 *
 * Return: 0 on success, the nvme command status if a response was
 * received (see &enum nvme_status_field) or a negative error otherwise.
 */
int nvme_fw_download_seq(struct nvme_transport_handle *hdl, bool ish,
			__u32 size, __u32 xfer, __u32 offset, void *buf);

/**
 * nvme_set_etdas() - Set the Extended Telemetry Data Area 4 Supported bit
 * @hdl:	Transport handle
 * @changed:	boolean to indicate whether or not the host
 *		behavior support feature had been changed
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_set_etdas(struct nvme_transport_handle *hdl, bool *changed);

/**
 * nvme_clear_etdas() - Clear the Extended Telemetry Data Area 4 Supported bit
 * @hdl:	Transport handle
 * @changed:	boolean to indicate whether or not the host
 *		behavior support feature had been changed
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_clear_etdas(struct nvme_transport_handle *hdl, bool *changed);

/**
 * nvme_get_uuid_list - Returns the uuid list (if supported)
 * @hdl:	Transport handle
 * @uuid_list:	UUID list returned by identify UUID
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_get_uuid_list(struct nvme_transport_handle *hdl,
		struct nvme_id_uuid_list *uuid_list);

/**
 * nvme_get_telemetry_max() - Get telemetry limits
 * @hdl:	Transport handle
 * @da:		On success return max supported data area
 * @max_data_tx: On success set to max transfer chunk supported by the controller
 *
 * Return: 0 on success, the nvme command status if a response was
 * received (see &enum nvme_status_field) or a negative error otherwise.
 */
int nvme_get_telemetry_max(struct nvme_transport_handle *hdl, enum nvme_telemetry_da *da, size_t *max_data_tx);

/**
 * nvme_get_telemetry_log() - Get specified telemetry log
 * @hdl:	Transport handle
 * @create:	Generate new host initated telemetry capture
 * @ctrl:	Get controller Initiated log
 * @rae:	Retain asynchronous events
 * @max_data_tx: Set the max data transfer size to be used retrieving telemetry.
 * @da:		Log page data area, valid values: &enum nvme_telemetry_da.
 * @log:	On success, set to the value of the allocated and retrieved log.
 * @size:	Ptr to the telemetry log size, so it can be returned
 *
 * The total size allocated can be calculated as:
 *   (nvme_telemetry_log da size  + 1) * NVME_LOG_TELEM_BLOCK_SIZE.
 *
 * Return: 0 on success, the nvme command status if a response was
 * received (see &enum nvme_status_field) or a negative error otherwise.
 */
int nvme_get_telemetry_log(struct nvme_transport_handle *hdl, bool create, bool ctrl, bool rae, size_t max_data_tx,
			   enum nvme_telemetry_da da, struct nvme_telemetry_log **log,
			   size_t *size);
/**
 * nvme_get_ctrl_telemetry() - Get controller telemetry log
 * @hdl:	Transport handle
 * @rae:	Retain asynchronous events
 * @log:	On success, set to the value of the allocated and retrieved log.
 * @da:		Log page data area, valid values: &enum nvme_telemetry_da
 * @size:	Ptr to the telemetry log size, so it can be returned
 *
 * The total size allocated can be calculated as:
 *   (nvme_telemetry_log da size  + 1) * NVME_LOG_TELEM_BLOCK_SIZE.
 *
 * Return: 0 on success, the nvme command status if a response was
 * received (see &enum nvme_status_field) or a negative error otherwise.
 */
int nvme_get_ctrl_telemetry(struct nvme_transport_handle *hdl, bool rae, struct nvme_telemetry_log **log,
		enum nvme_telemetry_da da, size_t *size);

/**
 * nvme_get_host_telemetry() - Get host telemetry log
 * @hdl:	Transport handle
 * @log:	On success, set to the value of the allocated and retrieved log.
 * @da:		Log page data area, valid values: &enum nvme_telemetry_da
 * @size:	Ptr to the telemetry log size, so it can be returned
 *
 * The total size allocated can be calculated as:
 *   (nvme_telemetry_log da size  + 1) * NVME_LOG_TELEM_BLOCK_SIZE.
 *
 * Return: 0 on success, the nvme command status if a response was
 * received (see &enum nvme_status_field) or a negative error otherwise.
 */
int nvme_get_host_telemetry(struct nvme_transport_handle *hdl,  struct nvme_telemetry_log **log,
		enum nvme_telemetry_da da, size_t *size);

/**
 * nvme_get_new_host_telemetry() - Get new host telemetry log
 * @hdl:	Transport handle
 * @log:	On success, set to the value of the allocated and retrieved log.
 * @da:		Log page data area, valid values: &enum nvme_telemetry_da
 * @size:	Ptr to the telemetry log size, so it can be returned
 *
 * The total size allocated can be calculated as:
 *   (nvme_telemetry_log da size  + 1) * NVME_LOG_TELEM_BLOCK_SIZE.
 *
 * Return: 0 on success, the nvme command status if a response was
 * received (see &enum nvme_status_field) or a negative error otherwise.
 */
int nvme_get_new_host_telemetry(struct nvme_transport_handle *hdl,  struct nvme_telemetry_log **log,
		enum nvme_telemetry_da da, size_t *size);

/**
 * nvme_get_ana_log_len_from_id_ctrl() - Retrieve maximum possible ANA log size
 * @id_ctrl:	Controller identify data
 * @rgo:	If true, return maximum log page size without NSIDs
 *
 * Return: A byte limit on the size of the controller's ANA log page
 */
size_t nvme_get_ana_log_len_from_id_ctrl(const struct nvme_id_ctrl *id_ctrl,
					 bool rgo);

/**
 * nvme_get_ana_log_len() - Retrieve size of the current ANA log
 * @hdl:	Transport handle
 * @analen:	Pointer to where the length will be set on success
 *
 * Return: 0 on success, the nvme command status if a response was
 * received (see &enum nvme_status_field) or a negative error otherwise.
 */
int nvme_get_ana_log_len(struct nvme_transport_handle *hdl, size_t *analen);

/**
 * nvme_get_logical_block_size() - Retrieve block size
 * @hdl:	Transport handle
 * @nsid:	Namespace id
 * @blksize:	Pointer to where the block size will be set on success
 *
 * Return: 0 on success, the nvme command status if a response was
 * received (see &enum nvme_status_field) or a negative error otherwise.
 */
int nvme_get_logical_block_size(struct nvme_transport_handle *hdl, __u32 nsid, int *blksize);

/**
 * nvme_get_lba_status_log() - Retrieve the LBA Status log page
 * @hdl:	Transport handle
 * @rae:	Retain asynchronous events
 * @log:	On success, set to the value of the allocated and retrieved log.
 *
 * Return: 0 on success, the nvme command status if a response was
 * received (see &enum nvme_status_field) or a negative error otherwise.
 */
int nvme_get_lba_status_log(struct nvme_transport_handle *hdl, bool rae, struct nvme_lba_status_log **log);

/**
 * nvme_namespace_attach_ctrls() - Attach namespace to controller(s)
 * @hdl:	Transport handle
 * @ish:	Ignore Shutdown (for NVMe-MI command)
 * @nsid:	Namespace ID to attach
 * @num_ctrls:	Number of controllers in ctrlist
 * @ctrlist:	List of controller IDs to perform the attach action
 *
 * Return: 0 on success, the nvme command status if a response was
 * received (see &enum nvme_status_field) or a negative error otherwise.
 */
int nvme_namespace_attach_ctrls(struct nvme_transport_handle *hdl, bool ish,
				__u32 nsid, __u16 num_ctrls, __u16 *ctrlist);

/**
 * nvme_namespace_detach_ctrls() - Detach namespace from controller(s)
 * @hdl:	Transport handle
 * @ish:	Ignore Shutdown (for NVMe-MI command)
 * @nsid:	Namespace ID to detach
 * @num_ctrls:	Number of controllers in ctrlist
 * @ctrlist:	List of controller IDs to perform the detach action
 *
 * Return: 0 on success, the nvme command status if a response was
 * received (see &enum nvme_status_field) or a negative error otherwise.
 */
int nvme_namespace_detach_ctrls(struct nvme_transport_handle *hdl, bool ish,
			__u32 nsid, __u16 num_ctrls, __u16 *ctrlist);

/**
 * nvme_open() - Open an nvme controller or namespace device
 * @ctx:	struct nvme_global_ctx object
 * @name:	The basename of the device to open
 * @hdl:	Transport handle to return
 *
 * This will look for the handle in /dev/ and validate the name and filetype
 * match linux conventions.
 *
 * Return: 0 on success or negative error code otherwise
 */
int nvme_open(struct nvme_global_ctx *ctx, const char *name,
	      struct nvme_transport_handle **hdl);

/**
 * nvme_close() - Close transport handle
 * @hdl:	Transport handle
 */
void nvme_close(struct nvme_transport_handle *hdl);

/**
 * nvme_transport_handle_get_fd - Return file descriptor from transport handle
 * @hdl:	Transport handle
 *
 * If the device handle is for a ioctl based device,
 * nvme_transport_handle_get_fd will return a valid file descriptor.
 *
 * Return: File descriptor for an IOCTL based transport handle, otherwise -1.
 */
nvme_fd_t nvme_transport_handle_get_fd(struct nvme_transport_handle *hdl);

/**
 * nvme_transport_handle_get_name - Return name of the device transport handle
 * @hdl:	Transport handle
 *
 * Return: Device file name, otherwise -1.
 */
const char *nvme_transport_handle_get_name(struct nvme_transport_handle *hdl);

/**
 * nvme_transport_handle_is_blkdev - Check if transport handle is a block device
 * @hdl:	Transport handle
 *
 * Return: Return true if transport handle is a block device, otherwise false.
 */
bool nvme_transport_handle_is_blkdev(struct nvme_transport_handle *hdl);

/**
 * nvme_transport_handle_is_chardev - Check if transport handle is a char device
 * @hdl:	Transport handle
 *
 * Return: Return true if transport handle is a char device, otherwise false.
 */
bool nvme_transport_handle_is_chardev(struct nvme_transport_handle *hdl);

/**
 * nvme_transport_handle_is_direct - Check if transport handle is using IOCTL interface
 * @hdl:	Transport handle
 *
 * Return: Return true if transport handle is using IOCTL itnerface,
 * otherwise false.
 */
bool nvme_transport_handle_is_direct(struct nvme_transport_handle *hdl);

/**
 * nvme_transport_handle_is_mi - Check if transport handle is a using MI interface
 * @hdl:	Transport handle
 *
 * Return: Return true if transport handle is using MI interface,
 * otherwise false.
 */
bool nvme_transport_handle_is_mi(struct nvme_transport_handle *hdl);

/**
 * nvme_transport_handle_set_submit_entry() - Install a submit-entry callback
 * @hdl:	Transport handle to configure
 * @submit_entry: Callback invoked immediately before a passthrough command is
 *		submitted. The function receives the command about to be issued
 *		and may return an opaque pointer representing per-command
 *		context. This pointer is later passed unmodified to the
 *		submit-exit callback. Implementations typically use this hook
 *		for logging, tracing, or allocating per-command state.
 *
 * Installs a user-defined callback that is invoked at the moment a passthrough
 * command enters the NVMe submission path. Passing NULL removes any previously
 * installed callback.
 *
 * Return: None.
 */
void nvme_transport_handle_set_submit_entry(struct nvme_transport_handle *hdl,
		void *(*submit_entry)(struct nvme_transport_handle *hdl,
				struct nvme_passthru_cmd *cmd));

/**
 * nvme_transport_handle_set_submit_exit() - Install a submit-exit callback
 * @hdl:	Transport handle to configure
 * @submit_exit: Callback invoked after a passthrough command completes. The
 *		function receives the command, the completion status @err
 *		(0 for success, a negative errno, or an NVMe status value), and
 *		the @user_data pointer returned earlier by the submit-entry
 *		callback. Implementations typically use this hook for logging,
 *		tracing, or freeing per-command state.
 *
 * Installs a callback that is invoked when a passthrough command leaves the
 * NVMe submission path. Passing NULL removes any previously installed callback.
 *
 * Return: None.
 */
void nvme_transport_handle_set_submit_exit(struct nvme_transport_handle *hdl,
		void (*submit_exit)(struct nvme_transport_handle *hdl,
				struct nvme_passthru_cmd *cmd,
				int err, void *user_data));

/**
 * nvme_transport_handle_set_decide_retry() - Install a retry-decision callback
 * @hdl:	Transport handle to configure
 * @decide_retry: Callback used to determine whether a passthrough command
 *		should be retried after an error. The function is called with
 *		the command that failed and the error code returned by the
 *		kernel or device. The callback should return true if the
 *		submission path should retry the command, or false if the
 *		error is final.
 *
 * Installs a user-provided callback to control retry behavior for
 * passthrough commands issued through @hdl. This allows transports or
 * higher-level logic to implement custom retry policies, such as retrying on
 * transient conditions like -EAGAIN or device-specific status codes.
 *
 * Passing NULL clears any previously installed callback and reverts to the
 * default behavior (no retries).
 *
 * Return: None.
 */
void nvme_transport_handle_set_decide_retry(struct nvme_transport_handle *hdl,
		bool (*decide_retry)(struct nvme_transport_handle *hdl,
				struct nvme_passthru_cmd *cmd, int err));

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
 * nvme_set_dry_run() - Set global dry run state
 * @ctx:	struct nvme_global_ctx object
 * @enable:	Enable/disable dry run state
 *
 * When dry_run is enabled, any IOCTL commands send via the passthru
 * interface wont be executed.
 */
void nvme_set_dry_run(struct nvme_global_ctx *ctx, bool enable);

#endif /* _LIBNVME_LINUX_H */
