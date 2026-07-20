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
#include <stdint.h>

#include <nvme/tree.h>

/**
 * DOC: fabrics.h
 *
 * Fabrics-specific definitions.
 */

/* default to 600 seconds of reconnect attempts before giving up */
#define NVMF_DEF_CTRL_LOSS_TMO		600

/*
 * struct libnvmf_context - Opaque context for fabrics operations
 *
 * Used to manage state and configuration for fabrics discovery and connect
 * operations.
 */
struct libnvmf_context;
struct libnvmf_tid;

/**
 * libnvmf_generate_hostnqn() - Generate a machine specific host nqn
 * Return: An nvm namespace qualified name string based on the machine
 * identifier, or NULL if not successful.
 */
char *libnvmf_generate_hostnqn(void);

/**
 * libnvmf_generate_hostnqn_from_hostid() - Generate a host nqn from
 * host identifier
 * @hostid:		Host identifier
 *
 * If @hostid is NULL, the function generates it based on the machine
 * identifier.
 *
 * Return: On success, an NVMe Qualified Name for host identification. This
 * name is based on the given host identifier. On failure, NULL.
 */
char *libnvmf_generate_hostnqn_from_hostid(char *hostid);

/**
 * libnvmf_generate_hostid() - Generate a machine specific host identifier
 *
 * Return: On success, an identifier string based on the machine identifier to
 * be used as NVMe Host Identifier, or NULL on failure.
 */
char *libnvmf_generate_hostid(void);

/**
 * libnvmf_read_hostnqn() - Reads the host nvm qualified name from the config
 *			      default location
 * @ctx:		struct libnvme_global_ctx object
 *
 * Retrieve the qualified name from the config file located in $SYSCONFDIR/nvme.
 * $SYSCONFDIR is usually /etc.
 *
 * Return: The host nqn, or NULL if unsuccessful. If found, the caller
 * is responsible to free the string.
 */
char *libnvmf_read_hostnqn(struct libnvme_global_ctx *ctx);

/**
 * libnvmf_read_hostid() - Reads the host identifier from the config default
 *			     location
 * @ctx:		struct libnvme_global_ctx object
 *
 * Retrieve the host idenditifer from the config file located in
 * $SYSCONFDIR/nvme/. $SYSCONFDIR is usually /etc.
 *
 * Return: The host identifier, or NULL if unsuccessful. If found, the caller
 *	   is responsible to free the string.
 */
char *libnvmf_read_hostid(struct libnvme_global_ctx *ctx);

/**
 * libnvmf_host_get_ids() - Retrieve host ids from various sources
 * @ctx:		struct libnvme_global_ctx object
 * @hostnqn_arg:	Input hostnqn (command line) argument
 * @hostid_arg:		Input hostid (command line) argument
 * @hostnqn:		Output hostnqn; may be NULL if the caller does not need it
 * @hostid:		Output hostid; may be NULL if the caller does not need it
 *
 * libnvmf_host_get_ids figures out which hostnqn/hostid is to be used.
 * There are several sources where this information can be retrieved.
 *
 * The order is:
 *
 *  - Start with information from DMI or device-tree
 *  - Override hostnqn and hostid from /etc/nvme files
 *  - Override hostnqn or hostid with values from JSON
 *    configuration file. The first host entry in the file is
 *    considered the default host.
 *  - Override hostnqn or hostid with values from the command line
 *    (@hostnqn_arg, @hostid_arg).
 *
 *  If the IDs are still NULL after the lookup algorithm, the function
 *  will generate random IDs.
 *
 *  The function also verifies that hostnqn and hostid matches. The Linux
 *  NVMe implementation expects a 1:1 matching between the IDs.
 *
 *  Return: 0 on success (@hostnqn and @hostid contain valid strings
 *  which the caller needs to free), or negative error code otherwise.
 */
int libnvmf_host_get_ids(struct libnvme_global_ctx *ctx,
		      const char *hostnqn_arg, const char *hostid_arg,
		      char **hostnqn, char **hostid);

/**
 * libnvmf_trtype_str() - Decode TRTYPE field
 * @trtype: value to be decoded
 *
 * Decode the transport type field in the discovery
 * log page entry.
 *
 * Return: decoded string
 */
const char *libnvmf_trtype_str(__u8 trtype);

/**
 * libnvmf_adrfam_str() - Decode ADRFAM field
 * @adrfam: value to be decoded
 *
 * Decode the address family field in the discovery
 * log page entry.
 *
 * Return: decoded string
 */
const char *libnvmf_adrfam_str(__u8 adrfam);

/**
 * libnvmf_subtype_str() - Decode SUBTYPE field
 * @subtype: value to be decoded
 *
 * Decode the subsystem type field in the discovery
 * log page entry.
 *
 * Return: decoded string
 */
const char *libnvmf_subtype_str(__u8 subtype);

/**
 * libnvmf_treq_str() - Decode TREQ field
 * @treq: value to be decoded
 *
 * Decode the transport requirements field in the
 * discovery log page entry.
 *
 * Return: decoded string
 */
const char *libnvmf_treq_str(__u8 treq);

/**
 * libnvmf_eflags_str() - Decode EFLAGS field
 * @eflags: value to be decoded
 *
 * Decode the EFLAGS field in the discovery log page
 * entry.
 *
 * Return: decoded string
 */
const char *libnvmf_eflags_str(__u16 eflags);

/**
 * libnvmf_sectype_str() - Decode SECTYPE field
 * @sectype: value to be decoded
 *
 * Decode the SECTYPE field in the discovery log page
 * entry.
 *
 * Return: decoded string
 */
const char *libnvmf_sectype_str(__u8 sectype);

/**
 * libnvmf_prtype_str() - Decode RDMA Provider type field
 * @prtype: value to be decoded
 *
 * Decode the RDMA Provider type field in the discovery
 * log page entry.
 *
 * Return: decoded string
 */
const char *libnvmf_prtype_str(__u8 prtype);

/**
 * libnvmf_qptype_str() - Decode RDMA QP Service type field
 * @qptype: value to be decoded
 *
 * Decode the RDMA QP Service type field in the discovery log page
 * entry.
 *
 * Return: decoded string
 */
const char *libnvmf_qptype_str(__u8 qptype);

/**
 * libnvmf_cms_str() - Decode RDMA connection management service field
 * @cms: value to be decoded
 *
 * Decode the RDMA connection management service field in the discovery
 * log page entry.
 *
 * Return: decoded string
 */
const char *libnvmf_cms_str(__u8 cms);

/**
 * libnvmf_add_ctrl() - Connect a controller and update topology
 * @h:		Host to which the controller should be attached
 * @c:		Controller to be connected
 *
 * Issues a 'connect' command to the NVMe-oF controller and inserts @c
 * into the topology using @h as parent.
 * @c must be initialized and not connected to the topology.
 *
 * Return: 0 on success, negative error code otherwise.
 */
int libnvmf_add_ctrl(libnvme_host_t h, libnvme_ctrl_t c);

/**
 * libnvmf_connect_ctrl() - Connect a controller
 * @c:		Controller to be connected
 *
 * Issues a 'connect' command to the NVMe-oF controller.
 * @c must be initialized and not connected to the topology.
 *
 * Return: 0 on success, negative error code otherwise.
 */
int libnvmf_connect_ctrl(libnvme_ctrl_t c);

/*
 * struct libnvmf_discovery_args - Opaque arguments for libnvmf_get_discovery_log()
 *
 * Allocate with libnvmf_discovery_args_new() and release with
 * libnvmf_discovery_args_free(). Use the setter/getter accessors to configure
 * fields; do not access members directly.
 */
struct libnvmf_discovery_args;

/*
 * struct libnvmf_uri - Opaque data struct for URI
 */
struct libnvmf_uri;

/**
 * libnvmf_get_discovery_log() - Fetch the NVMe-oF discovery log page
 * @ctrl:	Discovery controller
 * @args:	Optional arguments (pass NULL for defaults)
 * @logp:	On success, set to the allocated log page (caller must free())
 *
 * Issues the three-phase Get Log Page protocol against @ctrl, validates
 * generation-counter atomicity, and normalises each log entry.
 *
 * Return: 0 on success, negative error code otherwise.
 */
int libnvmf_get_discovery_log(libnvme_ctrl_t ctrl,
			   const struct libnvmf_discovery_args *args,
			   struct nvmf_discovery_log **logp);


/**
 * libnvmf_is_registration_supported - check whether registration can be performed.
 * @c:	Controller instance
 *
 * Only discovery controllers (DC) that comply with TP8010 support
 * explicit registration with the DIM PDU. These can be identified by
 * looking at the value of a dctype in the Identify command
 * response. A value of 1 (DDC) or 2 (CDC) indicates that the DC
 * supports explicit registration.
 *
 * Return: true if controller supports explicit registration. false
 * otherwise.
 */
bool libnvmf_is_registration_supported(libnvme_ctrl_t c);

/**
 * libnvmf_register_ctrl() - Perform registration task with a DC
 * @c:		Controller instance
 * @tas:	Task field of the Command Dword 10 (cdw10). Indicates whether to
 *		perform a Registration, Deregistration, or Registration-update.
 * @result:	The command-specific result returned by the DC upon command
 *		completion.
 *
 * Perform registration task with a Discovery Controller (DC). Three
 * tasks are supported: register, deregister, and registration update.
 *
 * Return: 0 on success, negative error code otherwise.
 */
int libnvmf_register_ctrl(libnvme_ctrl_t c, enum nvmf_dim_tas tas, __u32 *result);

/**
 * libnvmf_uri_parse() - Parse the URI string
 * @str:	URI string
 * @uri:	URI object to return
 *
 * Parse the URI string as defined in the NVM Express Boot Specification.
 * Supported URI elements looks as follows:
 *
 *   nvme+tcp://user@host:port/subsys_nqn/nid?query=val#fragment
 *
 * Return: 0 on success, negative error code otherwise.
 */
int libnvmf_uri_parse(const char *str, struct libnvmf_uri **uri);

/**
 * libnvmf_uri_free() - Free the URI structure
 * @uri:	&libnvme_fabrics_uri structure
 *
 * Free an &libnvmf_uri structure.
 */
void libnvmf_uri_free(struct libnvmf_uri *uri);

/**
 * libnvmf_get_default_trsvcid() - Get default transport service ID
 * @transport: Transport type string (e.g., "tcp", "rdma")
 * @discovery_ctrl: True if for discovery controller, false otherwise
 *
 * Returns the default trsvcid (port) for the given transport and controller
 * type.
 *
 * Return: Allocated string with default trsvcid, or NULL on failure.
 */
const char *libnvmf_get_default_trsvcid(const char *transport,
		bool discovery_ctrl);

/**
 * libnvmf_context_create() - Create a new fabrics context for discovery/connect
 * @ctx: Global context
 * @decide_retry: Hook to decide if a retry should be attempted
 * @connected: Hook invoked when a connection is established
 * @already_connected: Hook invoked if already connected
 * @user_data: User data passed to hooks
 * @fctxp: Pointer to store the created context
 *
 * Allocates and initializes a new fabrics context for discovery/connect
 * operations.
 *
 * Return: 0 on success, negative error code otherwise.
 */
int libnvmf_context_create(struct libnvme_global_ctx *ctx,
		bool (*decide_retry)(struct libnvmf_context *fctx, int err,
			void *user_data),
		void (*connected)(struct libnvmf_context *fctx,
			struct libnvme_ctrl *c, void *user_data),
		void (*already_connected)(struct libnvmf_context *fctx,
			struct libnvme_host *host, const char *subsysnqn,
			const char *transport, const char *traddr,
			const char *trsvcid, void *user_data),
		void *user_data, struct libnvmf_context **fctxp);

/**
 * libnvmf_context_free() - Free a fabrics context
 * @fctx: Fabrics context to free
 *
 * Releases all resources associated with @fctx. The context must have
 * been previously created with libnvmf_context_create().
 *
 * After this call, @fctx must not be used.
 */
void libnvmf_context_free(struct libnvmf_context *fctx);

/**
 * libnvmf_context_set_discovery_hooks() - Set discovery hooks for context
 * @fctx: Fabrics context
 * @discovery_log: Hook for discovery log events
 *
 * Sets the hooks used during discovery operations for the given context.
 *
 * Return: 0 on success, negative error code otherwise.
 */
int libnvmf_context_set_discovery_hooks(struct libnvmf_context *fctx,
		void (*discovery_log)(struct libnvmf_context *fctx,
			bool connect, struct nvmf_discovery_log *log,
			uint64_t numrec, void *user_data));

/**
 * libnvmf_context_set_connection() - Set connection parameters for context
 * @fctx: Fabrics context
 * @subsysnqn: Subsystem NQN
 * @transport: Transport type
 * @traddr: Transport address
 * @trsvcid: Transport service ID
 * @host_traddr: Host transport address
 * @host_iface: Host interface
 *
 * Sets the connection parameters for the context.
 *
 * Return: 0 on success, negative error code otherwise.
 */
int libnvmf_context_set_connection(struct libnvmf_context *fctx,
		const char *subsysnqn, const char *transport,
		const char *traddr, const char *trsvcid,
		const char *host_traddr, const char *host_iface);

/**
 * libnvmf_context_set_hostnqn() - Set host NQN and host ID for context
 * @fctx: Fabrics context
 * @hostnqn: Host NQN
 * @hostid: Host identifier
 *
 * Sets the host NQN and host ID for the context.
 *
 * Return: 0 on success, negative error code otherwise.
 */
int libnvmf_context_set_hostnqn(struct libnvmf_context *fctx,
		const char *hostnqn, const char *hostid);

/**
 * libnvmf_context_set_connection_from_tid() - Set connection and identity
 * from a TID
 * @fctx: Fabrics context
 * @tid:  Transport ID to copy from
 *
 * Equivalent to libnvmf_context_set_connection() followed by
 * libnvmf_context_set_hostnqn(), reading every field from @tid.
 *
 * Return: 0 on success, -EINVAL if @fctx or @tid is NULL.
 */
int libnvmf_context_set_connection_from_tid(struct libnvmf_context *fctx,
		const struct libnvmf_tid *tid);

/**
 * libnvmf_context_set_crypto() - Set cryptographic parameters for context
 * @fctx: Fabrics context
 * @hostkey: Host key
 * @ctrlkey: Controller key
 * @keyring: Keyring identifier
 * @tls_key: TLS key
 * @tls_key_identity: TLS key identity
 *
 * Sets cryptographic and TLS parameters for the context.
 *
 * Return: 0 on success, negative error code otherwise.
 */
int libnvmf_context_set_crypto(struct libnvmf_context *fctx,
		const char *hostkey, const char *ctrlkey,
		const char *keyring, const char *tls_key,
		const char *tls_key_identity);

/**
 * libnvmf_context_set_device() - Set device for context
 * @fctx: Fabrics context
 * @device: Device path or identifier
 *
 * Sets the device to be used by the context.
 *
 * Return: 0 on success, negative error code otherwise.
 */
int libnvmf_context_set_device(struct libnvmf_context *fctx, const char *device);

/**
 * libnvmf_context_set_devid_file() - Set devid file for context
 * @fctx: Fabrics context
 * @devid_file: Path to the output file
 *
 * Configure a file that libnvmf_connect() uses to record the
 * kernel-assigned device name (for example, "nvme0").
 *
 * If the controller is already connected, the existing device name is
 * written. Otherwise, the device name is written after the controller is
 * connected.
 *
 * The output file is created before attempting the connection. If the
 * file cannot be created, for example because the parent directory does
 * not exist, libnvmf_connect() fails without attempting the connection.
 *
 * This is intended for applications that need to identify the device
 * associated with a connection, for example to disconnect it later.
 *
 * Return: 0 on success, negative error code otherwise.
 */
int libnvmf_context_set_devid_file(struct libnvmf_context *fctx,
		const char *devid_file);

/**
 * libnvmf_context_set_io_queues() - Set I/O queue topology for context
 * @fctx: Fabrics context
 * @nr_io_queues: Number of I/O queues
 * @nr_write_queues: Number of write-only queues
 * @nr_poll_queues: Number of polling queues
 * @queue_size: Number of entries per I/O queue (SQSIZE in Connect command)
 * @disable_sqflow: Disable SQ flow control negotiation
 *
 * Convenience setter for the five parameters that together define the I/O
 * queue structure used when establishing a controller connection. All five
 * feed directly into the Connect command at queue creation time.
 * @nr_write_queues and @nr_poll_queues are additive: total I/O queues is
 * @nr_io_queues + @nr_write_queues + @nr_poll_queues.
 *
 * Individual libnvmf_context_set_nr_io_queues(), _set_nr_write_queues(),
 * _set_nr_poll_queues(), _set_queue_size(), and _set_disable_sqflow()
 * accessors are also available when only a subset needs to change.
 *
 * Return: 0 on success, negative error code otherwise.
 */
int libnvmf_context_set_io_queues(struct libnvmf_context *fctx,
		int nr_io_queues, int nr_write_queues, int nr_poll_queues,
		int queue_size, bool disable_sqflow);

/**
 * libnvmf_context_set_reconnect_policy() - Set reconnect policy for context
 * @fctx: Fabrics context
 * @ctrl_loss_tmo: Controller loss timeout in seconds; negative means retry
 *                 indefinitely
 * @reconnect_delay: Delay between reconnect attempts in seconds
 * @fast_io_fail_tmo: Fast I/O fail timeout in seconds; negative disables it;
 *                    must not exceed @ctrl_loss_tmo
 *
 * Convenience setter for the three coupled reconnect policy parameters.
 * @ctrl_loss_tmo and @reconnect_delay are coupled: the kernel derives the
 * maximum reconnect attempt count from their ratio. @fast_io_fail_tmo
 * controls how quickly outstanding I/O is failed while reconnection is in
 * progress.
 *
 * Individual libnvmf_context_set_ctrl_loss_tmo(), _set_reconnect_delay(),
 * and _set_fast_io_fail_tmo() accessors are also available when only a
 * subset needs to change.
 *
 * Return: 0 on success, negative error code otherwise.
 */
int libnvmf_context_set_reconnect_policy(struct libnvmf_context *fctx,
		int ctrl_loss_tmo, int reconnect_delay, int fast_io_fail_tmo);

/**
 * libnvmf_discovery() - Perform fabrics discovery
 * @ctx: Global context
 * @fctx: Fabrics context
 * @connect: Whether to connect discovered subsystems
 * @force: Force discovery even if already connected
 *
 * Performs discovery for fabrics subsystems and optionally connects.
 *
 * Return: 0 on success, negative error code otherwise.
 */
int libnvmf_discovery(struct libnvme_global_ctx *ctx,
		struct libnvmf_context *fctx, bool connect, bool force);

/**
 * libnvmf_discovery_nbft() - Perform discovery using NBFT
 * @ctx: Global context
 * @fctx: Fabrics context
 * @connect: Whether to connect discovered subsystems
 * @nbft_path: Path to NBFT file
 *
 * Performs discovery using the specified NBFT file.
 *
 * Return: 0 on success, negative error code otherwise.
 */
int libnvmf_discovery_nbft(struct libnvme_global_ctx *ctx,
		struct libnvmf_context *fctx, bool connect, char *nbft_path);

/**
 * libnvmf_create_ctrl() - Allocate an unconnected NVMe controller
 * @ctx:		struct libnvme_global_ctx object
 * @fctx:		Fabrics context
 * @c:			@libnvme_ctrl_t object to return
 *
 * Creates an unconnected controller to be used for libnvme_add_ctrl().
 *
 * Return: 0 on success, negative error code otherwise.
 */
int libnvmf_create_ctrl(struct libnvme_global_ctx *ctx,
		struct libnvmf_context *fctx, libnvme_ctrl_t *c);

/**
 * libnvmf_connect() - Connect to fabrics subsystem
 * @ctx: Global context
 * @fctx: Fabrics context
 *
 * Connects to the fabrics subsystem using the provided context.
 *
 * Return: 0 on success, negative error code otherwise.
 */
int libnvmf_connect(struct libnvme_global_ctx *ctx,
		struct libnvmf_context *fctx);

/**
 * libnvmf_disconnect_ctrl() - Disconnect a controller
 * @c:	Controller instance
 *
 * Issues a 'disconnect' fabrics command to @c
 *
 * Return: 0 on success, -1 on failure.
 */
int libnvmf_disconnect_ctrl(libnvme_ctrl_t c);

/**
 * libnvmf_config_modify() - Modify and update the configurtion
 * @ctx: Global context
 * @fctx: Fabrics context
 *
 * Update the current configuration by adding the crypto
 * information.
 *
 * Return: 0 on success, negative error code otherwise.
 */
int libnvmf_config_modify(struct libnvme_global_ctx *ctx,
		struct libnvmf_context *fctx);

struct nbft_file_entry;

/**
 * libnvmf_nbft_read_files() - Read NBFT files from path
 * @ctx: struct libnvme_global_ctx object
 * @path: Path to NBFT files
 * @head: Pointer to store linked list of NBFT file entries
 *
 * Reads NBFT files from the specified path and populates a linked list.
 *
 * Return: 0 on success, negative error code otherwise.
 */
int libnvmf_nbft_read_files(struct libnvme_global_ctx *ctx, char *path,
		struct nbft_file_entry **head);

/**
 * libnvmf_nbft_free() - Free NBFT file entry list
 * @ctx: struct libnvme_global_ctx object
 * @head: Head of the NBFT file entry list
 *
 * Frees all memory associated with the NBFT file entry list.
 */
void libnvmf_nbft_free(struct libnvme_global_ctx *ctx,
		struct nbft_file_entry *head);
