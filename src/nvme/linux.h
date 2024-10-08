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

#include "ioctl.h"
#include "types.h"

/**
 * DOC: linux.h
 *
 * linux-specific utility functions
 */

/**
 * nvme_fw_download_seq() - Firmware download sequence
 * @fd:		File descriptor of nvme device
 * @size:	Total size of the firmware image to transfer
 * @xfer:	Maximum size to send with each partial transfer
 * @offset:	Starting offset to send with this firmware download
 * @buf:	Address of buffer containing all or part of the firmware image.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_fw_download_seq(int fd, __u32 size, __u32 xfer, __u32 offset,
			 void *buf);

/**
 * enum nvme_telemetry_da - Telemetry Log Data Area
 * @NVME_TELEMETRY_DA_1:	Data Area 1
 * @NVME_TELEMETRY_DA_2:	Data Area 2
 * @NVME_TELEMETRY_DA_3:	Data Area 3
 * @NVME_TELEMETRY_DA_4:	Data Area 4
 */
enum nvme_telemetry_da {
	NVME_TELEMETRY_DA_1	= 1,
	NVME_TELEMETRY_DA_2	= 2,
	NVME_TELEMETRY_DA_3	= 3,
	NVME_TELEMETRY_DA_4	= 4,
};

/**
 * nvme_get_telemetry_max() - Get telemetry limits
 * @fd:		File descriptor of nvme device
 * @da:		On success return max supported data area
 * @max_data_tx: On success set to max transfer chunk supported by the controller
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_get_telemetry_max(int fd, enum nvme_telemetry_da *da, size_t *max_data_tx);

/**
 * nvme_get_telemetry_log() - Get specified telemetry log
 * @fd:		File descriptor of nvme device
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
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_get_telemetry_log(int fd, bool create, bool ctrl, bool rae, size_t max_data_tx,
			   enum nvme_telemetry_da da, struct nvme_telemetry_log **log,
			   size_t *size);
/**
 * nvme_get_ctrl_telemetry() - Get controller telemetry log
 * @fd:		File descriptor of nvme device
 * @rae:	Retain asynchronous events
 * @log:	On success, set to the value of the allocated and retrieved log.
 * @da:		Log page data area, valid values: &enum nvme_telemetry_da
 * @size:	Ptr to the telemetry log size, so it can be returned
 *
 * The total size allocated can be calculated as:
 *   (nvme_telemetry_log da size  + 1) * NVME_LOG_TELEM_BLOCK_SIZE.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_get_ctrl_telemetry(int fd, bool rae, struct nvme_telemetry_log **log,
		enum nvme_telemetry_da da, size_t *size);

/**
 * nvme_get_host_telemetry() - Get host telemetry log
 * @fd:		File descriptor of nvme device
 * @log:	On success, set to the value of the allocated and retrieved log.
 * @da:		Log page data area, valid values: &enum nvme_telemetry_da
 * @size:	Ptr to the telemetry log size, so it can be returned
 *
 * The total size allocated can be calculated as:
 *   (nvme_telemetry_log da size  + 1) * NVME_LOG_TELEM_BLOCK_SIZE.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_get_host_telemetry(int fd,  struct nvme_telemetry_log **log,
		enum nvme_telemetry_da da, size_t *size);

/**
 * nvme_get_new_host_telemetry() - Get new host telemetry log
 * @fd:		File descriptor of nvme device
 * @log:	On success, set to the value of the allocated and retrieved log.
 * @da:		Log page data area, valid values: &enum nvme_telemetry_da
 * @size:	Ptr to the telemetry log size, so it can be returned
 *
 * The total size allocated can be calculated as:
 *   (nvme_telemetry_log da size  + 1) * NVME_LOG_TELEM_BLOCK_SIZE.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_get_new_host_telemetry(int fd,  struct nvme_telemetry_log **log,
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
 * @fd:		File descriptor of nvme device
 * @analen:	Pointer to where the length will be set on success
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_get_ana_log_len(int fd, size_t *analen);

/**
 * nvme_get_logical_block_size() - Retrieve block size
 * @fd:		File descriptor of nvme device
 * @nsid:	Namespace id
 * @blksize:	Pointer to where the block size will be set on success
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_get_logical_block_size(int fd, __u32 nsid, int *blksize);

/**
 * nvme_get_lba_status_log() - Retrieve the LBA Status log page
 * @fd:		File descriptor of the nvme device
 * @rae:	Retain asynchronous events
 * @log:	On success, set to the value of the allocated and retrieved log.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_get_lba_status_log(int fd, bool rae, struct nvme_lba_status_log **log);

/**
 * nvme_namespace_attach_ctrls() - Attach namespace to controller(s)
 * @fd:		File descriptor of nvme device
 * @nsid:	Namespace ID to attach
 * @num_ctrls:	Number of controllers in ctrlist
 * @ctrlist:	List of controller IDs to perform the attach action
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_namespace_attach_ctrls(int fd, __u32 nsid, __u16 num_ctrls, __u16 *ctrlist);

/**
 * nvme_namespace_detach_ctrls() - Detach namespace from controller(s)
 * @fd:		File descriptor of nvme device
 * @nsid:	Namespace ID to detach
 * @num_ctrls:	Number of controllers in ctrlist
 * @ctrlist:	List of controller IDs to perform the detach action
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_namespace_detach_ctrls(int fd, __u32 nsid, __u16 num_ctrls, __u16 *ctrlist);

/**
 * nvme_open() - Open an nvme controller or namespace device
 * @name:	The basename of the device to open
 *
 * This will look for the handle in /dev/ and validate the name and filetype
 * match linux conventions.
 *
 * Return: A file descriptor for the device on a successful open, or -1 with
 * errno set otherwise.
 */
int nvme_open(const char *name);

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
 * @hostnqn:	Host NVMe Qualified Name
 * @hmac:	HMAC algorithm
 * @key_len:	Output key length
 * @secret:	Secret to used for digest
 * @key:	Generated DH-HMAC-CHAP key
 *
 * Return: If key generation was successful the function returns 0 or
 * -1 with errno set otherwise.
 */
int nvme_gen_dhchap_key(char *hostnqn, enum nvme_hmac_alg hmac,
			unsigned int key_len, unsigned char *secret,
			unsigned char *key);

/**
 * nvme_lookup_keyring() - Lookup keyring serial number
 * @keyring:    Keyring name
 *
 * Looks up the serial number of the keyring @keyring.
 *
 * Return: The key serial number of the keyring
 * or 0 with errno set otherwise.
 */
long nvme_lookup_keyring(const char *keyring);

/**
 * nvme_describe_key_serial() - Return key description
 * @key_id:    Key serial number
 *
 * Fetches the description of the key or keyring identified
 * by the serial number @key_id.
 *
 * Return: The description of @key_id or NULL on failure.
 * The returned string needs to be freed by the caller.
 */
char *nvme_describe_key_serial(long key_id);

/**
 * nvme_lookup_key() - Lookup key serial number
 * @type:        Key type
 * @identity:    Key description
 *
 * Looks up the serial number of the key @identity
 * with type %type in the current session keyring.
 *
 * Return: The key serial number of the key
 * or 0 with errno set otherwise.
 */
long nvme_lookup_key(const char *type, const char *identity);

/**
 * nvme_set_keyring() - Link keyring for lookup
 * @keyring_id:    Keyring id
 *
 * Links @keyring_id into the session keyring such that
 * its keys are available for further key lookups.
 *
 * Return: 0 on success, a negative number on error
 * with errno set.
 */
int nvme_set_keyring(long keyring_id);

/**
 * nvme_read_key() - Read key raw data
 * @keyring_id:     Id of the keyring holding %key_id
 * @key_id:      Key id
 * @len:         Length of the returned data
 *
 * Links the keyring specified by @keyring_id into the session
 * keyring and reads the payload of the key specified by @key_id.
 * @len holds the size of the returned buffer.
 * If @keyring is 0 the default keyring '.nvme' is used.
 *
 * Return: Pointer to the payload on success,
 * or NULL with errno set otherwise.
 */
unsigned char *nvme_read_key(long keyring_id, long key_id, int *len);

/**
 * nvme_update_key() - Update key raw data
 * @keyring_id:  Id of the keyring holding %key_id
 * @key_type:    Type of the key to insert
 * @identity:    Key identity string
 * @key_data:    Raw data of the key
 * @key_len:     Length of @key_data
 *
 * Links the keyring specified by @keyring_id into the session
 * keyring and updates the key reference by @identity with @key_data.
 * The old key with identity @identity will be revoked to make it
 * inaccessible.
 *
 * Return: Key id of the new key or 0 with errno set otherwise.
 */
long nvme_update_key(long keyring_id, const char *key_type,
		     const char *identity, unsigned char *key_data,
		     int key_len);

/**
 * typedef nvme_scan_tls_keys_cb_t - Callback for iterating TLS keys
 * @keyring:	Keyring which has been iterated
 * @key:	Key for which the callback has been invoked
 * @desc:	Description of the key
 * @desc_len:	Length of @desc
 * @data:	Pointer for caller data
 *
 * Called for each TLS PSK in the keyring.
 */
typedef void (*nvme_scan_tls_keys_cb_t)(long keyring, long key,
					char *desc, int desc_len, void *data);

/**
 * nvme_scan_tls_keys() - Iterate over TLS keys in a keyring
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
 * Return: Number of keys for which @cb was called, or -1 with errno set
 * on error.
 */
int nvme_scan_tls_keys(const char *keyring, nvme_scan_tls_keys_cb_t cb,
		       void *data);

/**
 * nvme_insert_tls_key() - Derive and insert TLS key
 * @keyring:    Keyring to use
 * @key_type:	Type of the resulting key
 * @hostnqn:	Host NVMe Qualified Name
 * @subsysnqn:	Subsystem NVMe Qualified Name
 * @hmac:	HMAC algorithm
 * @configured_key:	Configured key data to derive the key from
 * @key_len:	Length of @configured_key
 *
 * Derives a 'retained' TLS key as specified in NVMe TCP 1.0a and
 * stores it as type @key_type in the keyring specified by @keyring.
 *
 * Return: The key serial number if the key could be inserted into
 * the keyring or 0 with errno otherwise.
 */
long nvme_insert_tls_key(const char *keyring, const char *key_type,
			 const char *hostnqn, const char *subsysnqn, int hmac,
			 unsigned char *configured_key, int key_len);

/**
 * nvme_insert_tls_key_versioned() - Derive and insert TLS key
 * @keyring:    Keyring to use
 * @key_type:	Type of the resulting key
 * @hostnqn:	Host NVMe Qualified Name
 * @subsysnqn:	Subsystem NVMe Qualified Name
 * @version:	Key version to use
 * @hmac:	HMAC algorithm
 * @configured_key:	Configured key data to derive the key from
 * @key_len:	Length of @configured_key
 *
 * Derives a 'retained' TLS key as specified in NVMe TCP 1.0a (if
 * @version s set to '0') or NVMe TP8028 (if @version is set to '1) and
 * stores it as type @key_type in the keyring specified by @keyring.
 *
 * Return: The key serial number if the key could be inserted into
 * the keyring or 0 with errno otherwise.
 */
long nvme_insert_tls_key_versioned(const char *keyring, const char *key_type,
				   const char *hostnqn, const char *subsysnqn,
				   int version, int hmac,
				   unsigned char *configured_key, int key_len);

/**
 * nvme_generate_tls_key_identity() - Generate the TLS key identity
 * @hostnqn:	Host NVMe Qualified Name
 * @subsysnqn:	Subsystem NVMe Qualified Name
 * @version:	Key version to use
 * @hmac:	HMAC algorithm
 * @configured_key:	Configured key data to derive the key from
 * @key_len:	Length of @configured_key
 *
 * Derives a 'retained' TLS key as specified in NVMe TCP and
 * generate the corresponding TLs identity.
 *
 * Return: The string containing the TLS identity. It is the responsibility
 * of the caller to free the returned string.
 */
char *nvme_generate_tls_key_identity(const char *hostnqn, const char *subsysnqn,
				     int version, int hmac,
				     unsigned char *configured_key, int key_len);

/**
 * nvme_revoke_tls_key() - Revoke TLS key from keyring
 * @keyring:    Keyring to use
 * @key_type:    Type of the key to revoke
 * @identity:    Key identity string
 *
 * Return: 0 on success or on failure -1 with errno set.
 */
long nvme_revoke_tls_key(const char *keyring, const char *key_type,
			 const char *identity);

/**
 * nvme_export_tls_key() - Export a TLS key
 * @key_data:	Raw data of the key
 * @key_len:	Length of @key_data
 *
 * Returns @key_data in the PSK Interchange format as defined in section
 * 3.6.1.5 of the NVMe TCP Transport specification.
 *
 * Return: The string containing the TLS identity or NULL with errno set
 * on error. It is the responsibility of the caller to free the returned
 * string.
 */
char *nvme_export_tls_key(const unsigned char *key_data, int key_len);

/**
 * nvme_export_tls_key_versioned() - Export a TLS pre-shared key
 * @version:	Indicated the representation of the TLS PSK
 * @hmac:	HMAC algorithm used to transfor the configured PSK
 *		in a retained PSK
 * @key_data:	Raw data of the key
 * @key_len:	Length of @key_data
 *
 * Returns @key_data in the PSK Interchange format as defined in section
 * 3.6.1.5 of the NVMe TCP Transport specification.
 *
 * Return: The string containing the TLS identity or NULL with errno set
 * on error. It is the responsibility of the caller to free the returned
 * string.
 */
char *nvme_export_tls_key_versioned(unsigned char version, unsigned char hmac,
				    const unsigned char *key_data,
				    size_t key_len);

/**
 * nvme_import_tls_key() - Import a TLS key
 * @encoded_key:	TLS key in PSK interchange format
 * @key_len:		Length of the resulting key data
 * @hmac:		HMAC algorithm
 *
 * Imports @key_data in the PSK Interchange format as defined in section
 * 3.6.1.5 of the NVMe TCP Transport specification.
 *
 * Return: The raw data of the PSK or NULL with errno set on error. It is
 * the responsibility of the caller to free the returned string.
 */
unsigned char *nvme_import_tls_key(const char *encoded_key, int *key_len,
				   unsigned int *hmac);

/**
 * nvme_import_tls_key_versioned() - Import a TLS key
 * @encoded_key:	TLS key in PSK interchange format
 * @version:		Indicated the representation of the TLS PSK
 * @hmac:		HMAC algorithm used to transfor the configured
 *			PSK in a retained PSK
 * @key_len:		Length of the resulting key data
 *
 * Imports @key_data in the PSK Interchange format as defined in section
 * 3.6.1.5 of the NVMe TCP Transport specification.
 *
 * Return: The raw data of the PSK or NULL with errno set on error. It is
 * the responsibility of the caller to free the returned string.
 */
unsigned char *nvme_import_tls_key_versioned(const char *encoded_key,
					     unsigned char *version,
					     unsigned char *hmac,
					     size_t *key_len);
/**
 * nvme_submit_passthru - Low level ioctl wrapper for passthru commands
 * @fd:		File descriptor of the nvme device
 * @ioctl_cmd:	IOCTL command id
 * @cmd:	Passhtru command
 * @result:	Optional field to return the result
 *
 * This is a low level library function which should not be used directly. It is
 * exposed as weak symbol so that the user application is able to provide their own
 * implementation of this function with additional debugging or logging code.
 *
 * Return: The value from the ioctl system call (see ioctl documentation)
 */
__attribute__((weak))
int nvme_submit_passthru(int fd, unsigned long ioctl_cmd,
			 struct nvme_passthru_cmd *cmd, __u32 *result);

/**
 * nvme_submit_passthru64 - Low level ioctl wrapper for passthru commands
 * @fd:		File descriptor of the nvme device
 * @ioctl_cmd:	IOCTL command id
 * @cmd:	Passhtru command
 * @result:	Optional field to return the result
 *
 * This is a low level library function which should not be used directly. It is
 * exposed as weak symbol so that the user application is able to provide their own
 * implementation of this function with additional debugging or logging code.
 *
 * Return: The value from the ioctl system call (see ioctl documentation)
 */
__attribute__((weak))
int nvme_submit_passthru64(int fd, unsigned long ioctl_cmd,
			   struct nvme_passthru_cmd64 *cmd,
			   __u64 *result);

#endif /* _LIBNVME_LINUX_H */
