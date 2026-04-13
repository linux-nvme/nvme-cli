// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2020 Western Digital Corporation or its affiliates.
 *
 * Authors: Keith Busch <keith.busch@wdc.com>
 *	    Chaitanya Kulkarni <chaitanya.kulkarni@wdc.com>
 */
#ifndef _LIBNVME_FABRICS_H
#define _LIBNVME_FABRICS_H

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

/**
 * struct libnvme_fabrics_config - Defines all linux nvme fabrics initiator options
 * @queue_size:		Number of IO queue entries
 * @nr_io_queues:	Number of controller IO queues to establish
 * @reconnect_delay:	Time between two consecutive reconnect attempts.
 * @ctrl_loss_tmo:	Override the default controller reconnect attempt timeout in seconds
 * @fast_io_fail_tmo:	Set the fast I/O fail timeout in seconds.
 * @keep_alive_tmo:	Override the default keep-alive-timeout to this value in seconds
 * @nr_write_queues:	Number of queues to use for exclusively for writing
 * @nr_poll_queues:	Number of queues to reserve for polling completions
 * @tos:		Type of service
 * @keyring:		Keyring to store and lookup keys
 * @tls_key:		TLS PSK for the connection
 * @tls_configured_key: TLS PSK for connect command for the connection
 * @duplicate_connect:	Allow multiple connections to the same target
 * @disable_sqflow:	Disable controller sq flow control
 * @hdr_digest:		Generate/verify header digest (TCP)
 * @data_digest:	Generate/verify data digest (TCP)
 * @tls:		Start TLS on the connection (TCP)
 * @concat:		Enable secure concatenation (TCP)
 */
struct libnvme_fabrics_config {
	int queue_size;
	int nr_io_queues;
	int reconnect_delay;
	int ctrl_loss_tmo;
	int fast_io_fail_tmo;
	int keep_alive_tmo;
	int nr_write_queues;
	int nr_poll_queues;
	int tos;
	long keyring;
	long tls_key;
	long tls_configured_key;

	bool duplicate_connect;
	bool disable_sqflow;
	bool hdr_digest;
	bool data_digest;
	bool tls;
	bool concat;
};

/**
 * struct libnvme_fabrics_uri - Parsed URI structure
 * @scheme:		Scheme name (typically 'nvme')
 * @protocol:		Optional protocol/transport (e.g. 'tcp')
 * @userinfo:		Optional user information component of the URI authority
 * @host:		Host transport address
 * @port:		The port subcomponent or 0 if not specified
 * @path_segments:	NULL-terminated array of path segments
 * @query:		Optional query string component (separated by '?')
 * @fragment:		Optional fragment identifier component (separated by '#')
 */
struct libnvme_fabrics_uri {
	char *scheme;
	char *protocol;
	char *userinfo;
	char *host;
	int port;
	char **path_segments;
	char *query;
	char *fragment;
};

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
 * libnvmf_default_config() - Default values for fabrics configuration
 * @cfg: config values to set
 *
 * Initializes @cfg with default values.
 */
void libnvmf_default_config(struct libnvme_fabrics_config *cfg);

/**
 * libnvmf_update_config() - Update fabrics configuration values
 * @c:          Controller to be modified
 * @cfg:        Updated configuration values
 *
 * Updates the values from @c with the configuration values from @cfg;
 * all non-default values from @cfg will overwrite the values in @c.
 */
void libnvmf_update_config(libnvme_ctrl_t c,
		const struct libnvme_fabrics_config *cfg);

/**
 * libnvmf_add_ctrl() - Connect a controller and update topology
 * @h:		Host to which the controller should be attached
 * @c:		Controller to be connected
 * @fctx:	Fabrics context
 *
 * Issues a 'connect' command to the NVMe-oF controller and inserts @c
 * into the topology using @h as parent.
 * @c must be initialized and not connected to the topology.
 *
 * Return: 0 on success, or an error code on failure.
 */
int libnvmf_add_ctrl(libnvme_host_t h, libnvme_ctrl_t c,
		  const struct libnvmf_context *fctx);

/**
 * libnvmf_connect_ctrl() - Connect a controller
 * @c:		Controller to be connected
 *
 * Issues a 'connect' command to the NVMe-oF controller.
 * @c must be initialized and not connected to the topology.
 *
 * Return: 0 on success, or an error code on failure.
 */
int libnvmf_connect_ctrl(libnvme_ctrl_t c);

/*
 * struct libnvmf_discovery_args - Opaque arguments for libnvmf_get_discovery_log()
 *
 * Allocate with libnvmf_discovery_args_create() and release with
 * libnvmf_discovery_args_free(). Use the setter/getter accessors to configure
 * fields; do not access members directly.
 */
struct libnvmf_discovery_args;

/**
 * libnvmf_discovery_args_create() - Allocate a discovery args object
 * @argsp:	On success, set to the newly allocated object
 *
 * Allocates and initialises a &struct libnvmf_discovery_args with sensible
 * defaults. The caller must release it with libnvmf_discovery_args_free().
 *
 * Return: 0 on success, or a negative error code on failure.
 */
int libnvmf_discovery_args_create(struct libnvmf_discovery_args **argsp);

/**
 * libnvmf_discovery_args_free() - Release a discovery args object
 * @args:	Object previously returned by libnvmf_discovery_args_create()
 */
void libnvmf_discovery_args_free(struct libnvmf_discovery_args *args);

/**
 * libnvmf_get_discovery_log() - Fetch the NVMe-oF discovery log page
 * @ctrl:	Discovery controller
 * @args:	Optional arguments (pass NULL for defaults)
 * @logp:	On success, set to the allocated log page (caller must free())
 *
 * Issues the three-phase Get Log Page protocol against @ctrl, validates
 * generation-counter atomicity, and normalises each log entry.
 *
 * Return: 0 on success, or a negative error code on failure.
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
 * Return: 0 on success, or an error code on failure.
 */
int libnvmf_register_ctrl(libnvme_ctrl_t c, enum nvmf_dim_tas tas, __u32 *result);

/**
 * libnvme_parse_uri() - Parse the URI string
 * @str:	URI string
 * @uri:	URI object to return
 *
 * Parse the URI string as defined in the NVM Express Boot Specification.
 * Supported URI elements looks as follows:
 *
 *   nvme+tcp://user@host:port/subsys_nqn/nid?query=val#fragment
 *
 * Return: &libnvme_fabrics_uri structure on success; NULL on failure with errno
 * set.
 */
int libnvme_parse_uri(const char *str, struct libnvme_fabrics_uri **uri);

/**
 * libnvmf_free_uri() - Free the URI structure
 * @uri:	&libnvme_fabrics_uri structure
 *
 * Free an &libnvme_fabrics_uri structure.
 */
void libnvmf_free_uri(struct libnvme_fabrics_uri *uri);

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
 * @decide_retry: Callback to decide if a retry should be attempted
 * @connected: Callback invoked when a connection is established
 * @already_connected: Callback invoked if already connected
 * @user_data: User data passed to callbacks
 * @fctxp: Pointer to store the created context
 *
 * Allocates and initializes a new fabrics context for discovery/connect
 * operations.
 *
 * Return: 0 on success, or a negative error code on failure.
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
 * libnvmf_context_set_discovery_cbs() - Set discovery callbacks for context
 * @fctx: Fabrics context
 * @discovery_log: Callback for discovery log events
 * @parser_init: Callback to initialize parser
 * @parser_cleanup: Callback to cleanup parser
 * @parser_next_line: Callback to parse next line
 *
 * Sets the callbacks used during discovery operations for the given context.
 *
 * Return: 0 on success, or a negative error code on failure.
 */
int libnvmf_context_set_discovery_cbs(struct libnvmf_context *fctx,
		void (*discovery_log)(struct libnvmf_context *fctx,
			bool connect, struct nvmf_discovery_log *log,
			uint64_t numrec, void *user_data),
		int (*parser_init)(struct libnvmf_context *fctx,
			void *user_data),
		void (*parser_cleanup)(struct libnvmf_context *fctx,
			void *user_data),
		int (*parser_next_line)(struct libnvmf_context *fctx,
			void *user_data));

/**
 * libnvmf_context_set_discovery_defaults() - Set default discovery parameters
 * @fctx: Fabrics context
 * @max_discovery_retries: Maximum number of discovery retries
 * @keep_alive_timeout: Keep-alive timeout in seconds
 *
 * Sets default values for discovery retries and keep-alive timeout.
 *
 * Return: 0 on success, or a negative error code on failure.
 */
int libnvmf_context_set_discovery_defaults(struct libnvmf_context *fctx,
		int max_discovery_retries, int keep_alive_timeout);

/**
 * libnvmf_context_set_fabrics_config() - Set fabrics configuration for context
 * @fctx: Fabrics context
 * @cfg: Fabrics configuration to apply
 *
 * Applies the given fabrics configuration to the context.
 *
 * Return: 0 on success, or a negative error code on failure.
 */
int libnvmf_context_set_fabrics_config(struct libnvmf_context *fctx,
		struct libnvme_fabrics_config *cfg);

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
 * Return: 0 on success, or a negative error code on failure.
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
 * Return: 0 on success, or a negative error code on failure.
 */
int libnvmf_context_set_hostnqn(struct libnvmf_context *fctx,
		const char *hostnqn, const char *hostid);

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
 * Return: 0 on success, or a negative error code on failure.
 */
int libnvmf_context_set_crypto(struct libnvmf_context *fctx,
		const char *hostkey, const char *ctrlkey,
		const char *keyring, const char *tls_key,
		const char *tls_key_identity);

/**
 * libnvmf_context_set_persistent() - Set persistence for context
 * @fctx: Fabrics context
 * @persistent: Whether to enable persistent connections
 *
 * Sets whether the context should use persistent connections.
 *
 * Return: 0 on success, or a negative error code on failure.
 */

int libnvmf_context_set_persistent(struct libnvmf_context *fctx, bool persistent);

/**
 * libnvmf_context_set_device() - Set device for context
 * @fctx: Fabrics context
 * @device: Device path or identifier
 *
 * Sets the device to be used by the context.
 *
 * Return: 0 on success, or a negative error code on failure.
 */
int libnvmf_context_set_device(struct libnvmf_context *fctx, const char *device);

/**
 * libnvmf_discovery() - Perform fabrics discovery
 * @ctx: Global context
 * @fctx: Fabrics context
 * @connect: Whether to connect discovered subsystems
 * @force: Force discovery even if already connected
 *
 * Performs discovery for fabrics subsystems and optionally connects.
 *
 * Return: 0 on success, or a negative error code on failure.
 */
int libnvmf_discovery(struct libnvme_global_ctx *ctx,
		struct libnvmf_context *fctx, bool connect, bool force);

/**
 * libnvmf_discovery_config_json() - Perform discovery using JSON config
 * @ctx: Global context
 * @fctx: Fabrics context
 * @connect: Whether to connect discovered subsystems
 * @force: Force discovery even if already connected
 *
 * Performs discovery using a JSON configuration.
 *
 * Return: 0 on success, or a negative error code on failure.
 */
int libnvmf_discovery_config_json(struct libnvme_global_ctx *ctx,
		struct libnvmf_context *fctx, bool connect, bool force);

/**
 * libnvmf_discovery_config_file() - Perform discovery using config file
 * @ctx: Global context
 * @fctx: Fabrics context
 * @connect: Whether to connect discovered subsystems
 * @force: Force discovery even if already connected
 *
 * Performs discovery using a configuration file.
 *
 * Return: 0 on success, or a negative error code on failure.
 */
int libnvmf_discovery_config_file(struct libnvme_global_ctx *ctx,
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
 * Return: 0 on success, or a negative error code on failure.
 */
int libnvmf_discovery_nbft(struct libnvme_global_ctx *ctx,
		struct libnvmf_context *fctx, bool connect, char *nbft_path);

/**
 * libnvmf_connect() - Connect to fabrics subsystem
 * @ctx: Global context
 * @fctx: Fabrics context
 *
 * Connects to the fabrics subsystem using the provided context.
 *
 * Return: 0 on success, or a negative error code on failure.
 */
int libnvmf_connect(struct libnvme_global_ctx *ctx, struct libnvmf_context *fctx);

/**
 * libnvmf_connect_config_json() - Connect using JSON config
 * @ctx: Global context
 * @fctx: Fabrics context
 *
 * Connects to the fabrics subsystem using a JSON configuration.
 *
 * Return: 0 on success, or a negative error code on failure.
 */
int libnvmf_connect_config_json(struct libnvme_global_ctx *ctx,
		struct libnvmf_context *fctx);

/**
 * libnvmf_config_modify() - Modify and update the configurtion
 * @ctx: Global context
 * @fctx: Fabrics context
 *
 * Update the current configuration by adding the crypto
 * information.
 *
 * Return: 0 on success, or a negative error code on failure.
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
 * Return: 0 on success, or a negative error code on failure.
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

#endif /* _LIBNVME_FABRICS_H */
