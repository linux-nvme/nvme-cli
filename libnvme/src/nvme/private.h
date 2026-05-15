// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2021 SUSE Software Solutions
 *
 * Authors: Hannes Reinecke <hare@suse.de>
 */
#pragma once

#include <sys/stat.h>
#include <sys/types.h>
#include <string.h>

#if defined(HAVE_NETDB) || defined(CONFIG_FABRICS)
#include <ifaddrs.h>
#endif

#include <ccan/list/list.h>

#include "nvme/nvme-types.h"
#include "nvme/lib-types.h"

#include <nvme/tree.h>

const char *libnvme_subsys_sysfs_dir(void);
const char *libnvme_ctrl_sysfs_dir(void);
const char *libnvme_ns_sysfs_dir(void);
const char *libnvme_slots_sysfs_dir(void);
const char *libnvme_uuid_ibm_filename(void);
const char *libnvme_dmi_entries_dir(void);

struct linux_passthru_cmd32 {
	__u8    opcode;
	__u8    flags;
	__u16   rsvd1;
	__u32   nsid;
	__u32   cdw2;
	__u32   cdw3;
	__u64   metadata;
	__u64   addr;
	__u32   metadata_len;
	__u32   data_len;
	__u32   cdw10;
	__u32   cdw11;
	__u32   cdw12;
	__u32   cdw13;
	__u32   cdw14;
	__u32   cdw15;
	__u32   timeout_ms;
	__u32   result;
};

struct linux_passthru_cmd64 {
	__u8    opcode;
	__u8    flags;
	__u16   rsvd1;
	__u32   nsid;
	__u32   cdw2;
	__u32   cdw3;
	__u64   metadata;
	__u64   addr;
	__u32   metadata_len;
	__u32   data_len;
	__u32   cdw10;
	__u32   cdw11;
	__u32   cdw12;
	__u32   cdw13;
	__u32   cdw14;
	__u32   cdw15;
	__u32   timeout_ms;
	__u32   rsvd2;
	__u64   result;
};

#define LIBNVME_IOCTL_ID		_IO('N', 0x40)
#define LIBNVME_IOCTL_RESET		_IO('N', 0x44)
#define LIBNVME_IOCTL_SUBSYS_RESET	_IO('N', 0x45)
#define LIBNVME_IOCTL_RESCAN		_IO('N', 0x46)

#define LIBNVME_IOCTL_ADMIN_CMD		_IOWR('N', 0x41, struct linux_passthru_cmd32)
#define LIBNVME_IOCTL_IO_CMD		_IOWR('N', 0x43, struct linux_passthru_cmd32)
#define LIBNVME_IOCTL_ADMIN64_CMD	_IOWR('N', 0x47, struct linux_passthru_cmd64)
#define LIBNVME_IOCTL_IO64_CMD		_IOWR('N', 0x48, struct linux_passthru_cmd64)

/* io_uring async commands: */
#define LIBNVME_URING_CMD_IO		_IOWR('N', 0x80, struct libnvme_uring_cmd)
#define LIBNVME_URING_CMD_IO_VEC	_IOWR('N', 0x81, struct libnvme_uring_cmd)
#define LIBNVME_URING_CMD_ADMIN		_IOWR('N', 0x82, struct libnvme_uring_cmd)
#define LIBNVME_URING_CMD_ADMIN_VEC	_IOWR('N', 0x83, struct libnvme_uring_cmd)

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
 * @keyring_id:		Keyring to store and lookup keys
 * @tls_key_id:		TLS PSK for the connection
 * @tls_configured_key_id: TLS PSK for connect command for the connection
 * @duplicate_connect:	Allow multiple connections to the same target
 * @disable_sqflow:	Disable controller sq flow control
 * @hdr_digest:		Generate/verify header digest (TCP)
 * @data_digest:	Generate/verify data digest (TCP)
 * @tls:		Start TLS on the connection (TCP)
 * @concat:		Enable secure concatenation (TCP)
 */
struct libnvme_fabrics_config { // !generate-accessors !generate-dict-table
	int queue_size;
	int nr_io_queues;
	int reconnect_delay;
	int ctrl_loss_tmo;
	int fast_io_fail_tmo;
	int keep_alive_tmo;
	int nr_write_queues;
	int nr_poll_queues;
	int tos;
	long keyring_id;
	long tls_key_id;
	long tls_configured_key_id;

	bool duplicate_connect;
	bool disable_sqflow;
	bool hdr_digest;
	bool data_digest;
	bool tls;
	bool concat;
};

struct libnvme_log {
	int fd;
	int level;
	bool pid;
	bool timestamp;
};

enum libnvme_transport_handle_type {
	LIBNVME_TRANSPORT_HANDLE_TYPE_UNKNOWN = 0,
	LIBNVME_TRANSPORT_HANDLE_TYPE_DIRECT,
	LIBNVME_TRANSPORT_HANDLE_TYPE_MI,
};

enum ioctl_state {
	IOCTL_STATE_UNKNOWN = 0,
	IOCTL_STATE_IOCTL32 = 1,
	IOCTL_STATE_IOCTL64 = 2,
};

struct libnvme_transport_handle {
	struct libnvme_global_ctx *ctx;
	enum libnvme_transport_handle_type type;
	char *name;

	void *(*submit_entry)(struct libnvme_transport_handle *hdl,
			struct libnvme_passthru_cmd *cmd);
	void (*submit_exit)(struct libnvme_transport_handle *hdl,
			struct libnvme_passthru_cmd *cmd,
			int err, void *user_data);
	bool (*decide_retry)(struct libnvme_transport_handle *hdl,
			struct libnvme_passthru_cmd *cmd, int err);

	/* global command timeout */
	__u32 timeout;

	/* direct */
	libnvme_fd_t fd;
	struct stat stat;
	enum ioctl_state ioctl_admin_state;
	enum ioctl_state ioctl_io_state;
	bool uring_enabled;

#ifdef CONFIG_MI
	/* mi */
	struct libnvme_mi_ep *ep;
	__u16 id;
	struct list_node ep_entry;
#endif

	struct libnvme_log *log;
};

enum libnvme_stat_group {
	READ = 0,
	WRITE,
	DISCARD,
	FLUSH,

	NR_STAT_GROUPS
};

struct libnvme_stat {
	struct {
		unsigned long ios;
		unsigned long merges;
		unsigned long long sectors;
		unsigned int ticks;	/* in milliseconds */
	} group[NR_STAT_GROUPS];

	unsigned int inflights;
	unsigned int io_ticks;		/* in milliseconds */
	unsigned int tot_ticks;		/* in milliseconds */

	double ts_ms;			/* timestamp when the stat is updated */
};

struct libnvme_path {		// !generate-accessors:read=generated,write=none
	struct list_node entry;
	struct list_node nentry;

	/* Double-buffered gendisk I/O stats: stat[curr_idx] is the latest
	 * snapshot, stat[!curr_idx] the previous one. curr_idx toggles on
	 * each update_stat() call; diffstat selects raw vs. delta for getters.
	 * Managed exclusively by the stat subsystem — do not access directly.
	 */
	struct libnvme_stat stat[2];
	unsigned int curr_idx;	       // !access:read=none
	bool diffstat;		       // !access:read=none

	struct libnvme_ctrl *c;
	struct libnvme_ns *n;

	char *name;		       // !access:write=generated
	char *sysfs_dir;	       // !access:write=generated
	char *ana_state;	       // !access:read=custom
	char *numa_nodes;	       // !access:read=custom
	int grpid;		       // !access:write=generated
	int queue_depth;	       // !access:read=custom
	long multipath_failover_count; // !access:read=custom
	long command_retry_count;      // !access:read=custom
	long command_error_count;      // !access:read=custom
};

struct libnvme_ns_head {
	struct list_head paths;
	struct libnvme_ns *n;

	char *sysfs_dir;
};

struct libnvme_ns {  // !generate-accessors:read=generated,write=none !generate-python:alias=Namespace
	struct list_node entry;

	struct libnvme_subsystem *s;
	struct libnvme_ctrl *c;
	struct libnvme_ns_head *head;

	struct libnvme_global_ctx *ctx;

	/* Double-buffered gendisk I/O stats: stat[curr_idx] is the latest
	 * snapshot, stat[!curr_idx] the previous one. curr_idx toggles on
	 * each update_stat() call; diffstat selects raw vs. delta for getters.
	 * Managed exclusively by the stat subsystem — do not access directly.
	 */
	struct libnvme_stat stat[2];
	unsigned int curr_idx;		     // !access:read=none
	bool diffstat;			     // !access:read=none

	struct libnvme_transport_handle *hdl;
	__u32 nsid;			     // !access:write=generated
	char *name;
	char *generic_name;
	char *sysfs_dir;		     // !access:write=generated

	int lba_shift;			     // !access:write=generated
	int lba_size;			     // !access:write=generated
	int meta_size;			     // !access:write=generated
	uint64_t lba_count;		     // !access:write=generated
	uint64_t lba_util;		     // !access:write=generated

	uint8_t eui64[8];
	uint8_t nguid[16];
	unsigned char uuid[NVME_UUID_LEN];   // !access:read=none
	enum nvme_csi csi;

	long command_retry_count;	     // !access:read=custom
	long command_error_count;	     // !access:read=custom
	long requeue_no_usable_path_count;   // !access:read=custom
	long fail_no_available_path_count;   // !access:read=custom
};

struct libnvme_ctrl {  // !generate-accessors:read=generated,write=none !generate-python:alias=Ctrl
	struct list_node entry;
	struct list_head paths;
	struct list_head namespaces;
	struct libnvme_subsystem *s;

	struct libnvme_global_ctx *ctx;
	struct libnvme_transport_handle *hdl;
	char *name;
	char *sysfs_dir;
	char *address;
	char *firmware;
	char *model;
	char *state;			// !access:read=custom
	char *numa_node;
	char *queue_count;
	char *serial;
	char *sqsize;
	char *transport;
	char *subsysnqn;
	char *traddr;
	char *trsvcid;
	char *dhchap_host_key;		// !access:write=generated
	char *dhchap_ctrl_key;		// !access:write=generated
	char *keyring;			// !access:write=generated
	char *tls_key_identity;		// !access:write=generated
	char *tls_key;			// !access:write=generated
	char *cntrltype;
	char *cntlid;
	char *dctype;
	char *phy_slot;
	char *host_traddr;
	char *host_iface;
	bool discovery_ctrl;		// !access:write=generated
	bool unique_discovery_ctrl;	// !access:write=generated
	bool discovered;		// !access:write=generated
	bool persistent;		// !access:write=generated
	long command_error_count;	// !access:read=custom
	long reset_count;		// !access:read=custom
	long reconnect_count;		// !access:read=custom
	struct libnvme_fabrics_config cfg;
};

struct libnvme_subsystem {  // !generate-accessors:read=generated,write=none !generate-python:alias=Subsystem
	struct list_node entry;
	struct list_head ctrls;
	struct list_head namespaces;
	struct libnvme_host *h;

	char *name;
	char *sysfs_dir;
	char *subsysnqn;
	char *model;
	char *serial;
	char *firmware;
	char *subsystype;
	char *application;		// !access:write=generated
	char *iopolicy;			// !access:read=custom
};

struct libnvme_host {  // !generate-accessors:read=generated,write=none !generate-python:alias=Host
	struct list_node entry;
	struct list_head subsystems;
	struct libnvme_global_ctx *ctx;

	char *hostnqn;
	char *hostid;
	char *dhchap_host_key;		// !access:write=generated
	char *hostsymname;		// !access:write=generated

	/* pdc_enabled and pdc_enabled_valid work together. pdc_enabled_valid,
	 * when true, indicates that pdc_enabled has been explicitly defined.
	 * pdc_enabled_valid is internal meta-data for pdc_enabled.
	 */
	bool pdc_enabled;		// !access:read=none,write=custom
	bool pdc_enabled_valid;		// !access:read=none
};

struct libnvme_fabric_options { // !generate-accessors
	bool cntlid;
	bool concat;
	bool ctrl_loss_tmo;
	bool data_digest;
	bool dhchap_ctrl_secret;
	bool dhchap_secret;
	bool disable_sqflow;
	bool discovery;
	bool duplicate_connect;
	bool fast_io_fail_tmo;
	bool hdr_digest;
	bool host_iface;
	bool host_traddr;
	bool hostid;
	bool hostnqn;
	bool instance;
	bool keep_alive_tmo;
	bool keyring;
	bool nqn;
	bool nr_io_queues;
	bool nr_poll_queues;
	bool nr_write_queues;
	bool queue_size;
	bool reconnect_delay;
	bool tls;
	bool tls_key;
	bool tos;
	bool traddr;
	bool transport;
	bool trsvcid;
};

enum libnvme_io_uring_state {
	LIBNVME_IO_URING_STATE_UNKNOWN = 0,
	LIBNVME_IO_URING_STATE_NOT_AVAILABLE,
	LIBNVME_IO_URING_STATE_AVAILABLE,
};

struct libnvme_global_ctx { // !generate-python:alias=GlobalCtx
	char *config_file;
	char *application;
	struct list_head endpoints; /* MI endpoints */
	struct list_head hosts;
	struct libnvme_log log;
	bool mi_probe_enabled;
	bool ioctl_probing;
	bool create_only;
	bool dry_run;
#ifdef CONFIG_FABRICS
	struct libnvme_fabric_options *options;
	struct ifaddrs *ifaddrs_cache; /* init with libnvmf_getifaddrs() */
#endif

	enum libnvme_io_uring_state uring_state;
#ifdef CONFIG_LIBURING
	int ring_cmds;
	struct io_uring *ring;
#endif
};
int libnvme_set_attr(const char *dir, const char *attr, const char *value);

int json_read_config(struct libnvme_global_ctx *ctx, const char *config_file);

int json_update_config(struct libnvme_global_ctx *ctx, int fd);

int json_dump_tree(struct libnvme_global_ctx *ctx);

void *__libnvme_submit_entry(struct libnvme_transport_handle *hdl,
		struct libnvme_passthru_cmd *cmd);
void __libnvme_submit_exit(struct libnvme_transport_handle *hdl,
		struct libnvme_passthru_cmd *cmd, int err, void *user_data);
bool __libnvme_decide_retry(struct libnvme_transport_handle *hdl,
		struct libnvme_passthru_cmd *cmd, int err);

struct libnvme_transport_handle *__libnvme_open(struct libnvme_global_ctx *ctx,
		const char *name);
struct libnvme_transport_handle *__libnvme_create_transport_handle(
		struct libnvme_global_ctx *ctx);

struct libnvmf_context;

int _libnvme_create_ctrl(struct libnvme_global_ctx *ctx,
		struct libnvmf_context *fctx,
		struct libnvme_ctrl **cp);
bool _libnvme_ctrl_match_config(struct libnvme_ctrl *c,
		struct libnvmf_context *fctx);

void nvme_deconfigure_ctrl(struct libnvme_ctrl *c);

struct libnvme_host *libnvme_lookup_host(struct libnvme_global_ctx *ctx,
		const char *hostnqn, const char *hostid);
struct libnvme_subsystem *libnvme_lookup_subsystem(struct libnvme_host *h,
		const char *name, const char *subsysnqn);
struct libnvme_ctrl * libnvme_lookup_ctrl(struct libnvme_subsystem * s,
		struct libnvmf_context *fctx, struct libnvme_ctrl *p);
struct libnvme_ctrl * libnvme_ctrl_find(struct libnvme_subsystem *s,
		struct libnvmf_context *fctx);

void __libnvme_free_host(struct libnvme_host * h);

#if (LOG_FUNCNAME == 1)
#define __libnvme_log_func __func__
#else
#define __libnvme_log_func NULL
#endif

void __attribute__((format(printf, 4, 5)))
__libnvme_msg(struct libnvme_global_ctx *ctx, int level,
		const char *func, const char *format, ...);

#define libnvme_msg(ctx, level, format, ...)	\
	__libnvme_msg(ctx, level, __libnvme_log_func, format, ##__VA_ARGS__)

#define SECTOR_SIZE	512
#define SECTOR_SHIFT	9

int __libnvme_import_keys_from_config(struct libnvme_host *h,
		struct libnvme_ctrl *c, long *keyring_id, long *key_id);

static inline char *xstrdup(const char *s)
{
	if (!s)
		return NULL;
	return strdup(s);
}

static inline bool streq0(const char *s1, const char *s2)
{
	if (s1 == s2)
		return true;
	if (!s1 || !s2)
		return false;
	return !strcmp(s1, s2);
}

static inline bool streqcase0(const char *s1, const char *s2)
{
	if (s1 == s2)
		return true;
	if (!s1 || !s2)
		return false;
	return !strcasecmp(s1, s2);
}

/**
 * libnvme_ipaddrs_eq - Check if 2 IP addresses are equal.
 * @addr1: IP address (can be IPv4 or IPv6)
 * @addr2: IP address (can be IPv4 or IPv6)
 *
 * Return: true if addr1 == addr2. false otherwise.
 */
bool libnvme_ipaddrs_eq(const char *addr1, const char *addr2);

#if defined(HAVE_NETDB) || defined(CONFIG_FABRICS)
/**
 * libnvme_iface_matching_addr - Get interface matching @addr
 * @iface_list: Interface list returned by getifaddrs()
 * @addr: Address to match
 *
 * Parse the interface list pointed to by @iface_list looking
 * for the interface that has @addr as one of its assigned
 * addresses.
 *
 * Return: The name of the interface that owns @addr or NULL.
 */
const char *libnvme_iface_matching_addr(const struct ifaddrs *iface_list,
		const char *addr);

/**
 * libnvme_iface_primary_addr_matches - Check that interface's primary
 * address matches
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
bool libnvme_iface_primary_addr_matches(const struct ifaddrs *iface_list,
		const char *iface, const char *addr);
#endif /* HAVE_NETDB || CONFIG_FABRICS */

int hostname2traddr(struct libnvme_global_ctx *ctx, const char *traddr,
		char **hostname);

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
 * startswith - Checks that a string starts with a given prefix.
 * @s:      The string to check
 * @prefix: A string that @s could be starting with
 *
 * Return: If @s starts with @prefix, then return a pointer within @s at
 * the first character after the matched @prefix. NULL otherwise.
 */
char *startswith(const char *s, const char *prefix);

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
 * libnvme_ns_get_transport_handle() - Get associated transport handle
 * @n:	Namespace instance
 * @hdl: Transport handle
 *
 * libnvme will open() the file (if not already opened) and keep
 * an internal copy of the link handle. Following calls to
 * this API retrieve the internal cached copy of the link
 * handle. The file will remain opened and the device handle will
 * remain cached until the ns object is deleted or
 * libnvme_ns_release_transport_handle() is called.
 *
 * Return: On success 0, else error code.
 */
int libnvme_ns_get_transport_handle(struct libnvme_ns *n,
		struct libnvme_transport_handle **hdl);

/**
 * libnvme_ns_release_transport_handle() - Free transport handle from ns object
 * @n:	Namespace instance
 *
 */
void libnvme_ns_release_transport_handle(struct libnvme_ns *n);

/**
 * libnvme_mi_admin_admin_passthru() - Submit an nvme admin passthrough command
 * @hdl:	Transport handle to send command to
 * @cmd:	The nvme admin command to send
 *
 * Send a customized NVMe Admin command request message and get the
 * corresponding response message.
 *
 * This interface supports no data, host to controller and controller to
 * host but it doesn't support bidirectional data transfer.
 * Also this interface only supports data transfer size range [0, 4096] (bytes)
 * so the & data_len parameter must be less than 4097.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int libnvme_mi_admin_admin_passthru(struct libnvme_transport_handle *hdl,
		struct libnvme_passthru_cmd *cmd);

int libnvme_open_uring(struct libnvme_global_ctx *ctx);
void libnvme_close_uring(struct libnvme_global_ctx *ctx);
int __libnvme_transport_handle_open_uring(struct libnvme_transport_handle *hdl);
int libnvme_submit_admin_passthru_async(struct libnvme_transport_handle *hdl,
		struct libnvme_passthru_cmd *cmd);

