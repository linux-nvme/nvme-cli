// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2021 SUSE Software Solutions
 *
 * Authors: Hannes Reinecke <hare@suse.de>
 */
#pragma once

#include <platform/includes.h>

#include <ccan/list/list.h>

#include <nvme/fabrics.h>
#include <nvme/mi.h>

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

	/* direct */
	nvme_fd_t fd;
	struct stat stat;
	bool ioctl_admin64;
	bool ioctl_io64;
	bool uring_enabled;

	/* mi */
	struct libnvme_mi_ep *ep;
	__u16 id;
	struct list_node ep_entry;

	struct libnvme_log *log;
};

struct libnvme_path { /*!generate-accessors*/
	struct list_node entry;
	struct list_node nentry;

	struct libnvme_ctrl *c;
	struct libnvme_ns *n;

	char *name;
	char *sysfs_dir;
	char *ana_state;
	char *numa_nodes;
	int grpid;
	int queue_depth; //!accessors:none
};

struct libnvme_ns_head {
	struct list_head paths;
	struct libnvme_ns *n;

	char *sysfs_dir;
};

struct libnvme_ns { /*!generate-accessors*/
	struct list_node entry;

	struct libnvme_subsystem *s;
	struct libnvme_ctrl *c;
	struct libnvme_ns_head *head;

	struct libnvme_global_ctx *ctx;
	struct libnvme_transport_handle *hdl;
	__u32 nsid;
	char *name;
	char *generic_name; //!accessors:none
	char *sysfs_dir;

	int lba_shift;
	int lba_size;
	int meta_size;
	uint64_t lba_count;
	uint64_t lba_util;

	uint8_t eui64[8];
	uint8_t nguid[16];
	unsigned char uuid[NVME_UUID_LEN];
	enum nvme_csi csi;
};

struct libnvme_ctrl { /*!generate-accessors*/
	struct list_node entry;
	struct list_head paths;
	struct list_head namespaces;
	struct libnvme_subsystem *s;

	struct libnvme_global_ctx *ctx;
	struct libnvme_transport_handle *hdl;
	char *name; //!accessors:readonly
	char *sysfs_dir; //!accessors:readonly
	char *address; //!accessors:none
	char *firmware; //!accessors:readonly
	char *model; //!accessors:readonly
	char *state; //!accessors:none
	char *numa_node; //!accessors:readonly
	char *queue_count; //!accessors:readonly
	char *serial; //!accessors:readonly
	char *sqsize; //!accessors:readonly
	char *transport; //!accessors:readonly
	char *subsysnqn; //!accessors:readonly
	char *traddr; //!accessors:readonly
	char *trsvcid; //!accessors:readonly
	char *dhchap_host_key;
	char *dhchap_ctrl_key;
	char *keyring;
	char *tls_key_identity;
	char *tls_key;
	char *cntrltype; //!accessors:readonly
	char *cntlid; //!accessors:readonly
	char *dctype; //!accessors:readonly
	char *phy_slot; //!accessors:readonly
	char *host_traddr; //!accessors:readonly
	char *host_iface; //!accessors:readonly
	bool discovery_ctrl;
	bool unique_discovery_ctrl;
	bool discovered;
	bool persistent;
	struct libnvme_fabrics_config cfg;
};

struct libnvme_subsystem { /*!generate-accessors*/
	struct list_node entry;
	struct list_head ctrls;
	struct list_head namespaces;
	struct libnvme_host *h;

	char *name; /*!accessors:readonly*/
	char *sysfs_dir; /*!accessors:readonly*/
	char *subsysnqn; /*!accessors:readonly*/
	char *model; /*!accessors:readonly*/
	char *serial; /*!accessors:readonly*/
	char *firmware; /*!accessors:readonly*/
	char *subsystype; /*!accessors:readonly*/
	char *application;
	char *iopolicy;
};

struct libnvme_host { /*!generate-accessors*/
	struct list_node entry;
	struct list_head subsystems;
	struct libnvme_global_ctx *ctx;

	char *hostnqn; /*!accessors:readonly*/
	char *hostid; /*!accessors:readonly*/
	char *dhchap_host_key;
	char *hostsymname;
	bool pdc_enabled; //!accessors:none
	bool pdc_enabled_valid; /* set if pdc_enabled doesn't have an undefined
				 * value */
};

struct libnvme_fabric_options { /*!generate-accessors*/
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

struct libnvme_global_ctx {
	char *config_file;
	char *application;
	struct list_head endpoints; /* MI endpoints */
	struct list_head hosts;
	struct libnvme_log log;
	bool mi_probe_enabled;
	bool ioctl_probing;
	bool create_only;
	bool dry_run;
	struct libnvme_fabric_options *options;
	struct ifaddrs *ifaddrs_cache; /* init with libnvme_getifaddrs() */

	enum libnvme_io_uring_state uring_state;
#ifdef CONFIG_LIBURING
	int ring_cmds;
	struct io_uring *ring;
#endif
};

struct nvmf_context {
	struct libnvme_global_ctx *ctx;

	/* common callbacks */
	bool (*decide_retry)(struct nvmf_context *fctx, int err,
			void *user_data);
	void (*connected)(struct nvmf_context *fctx, struct libnvme_ctrl *c,
			void *user_data);
	void (*already_connected)(struct nvmf_context *fctx,
			struct libnvme_host *host, const char *subsysnqn,
			const char *transport, const char *traddr,
			const char *trsvcid, void *user_data);

	/* discovery callbacks */
	void (*discovery_log)(struct nvmf_context *fctx,
			bool connect,
			struct nvmf_discovery_log *log,
			uint64_t numrec, void *user_data);
	int (*parser_init)(struct nvmf_context *fctx,
			void *user_data);
	void (*parser_cleanup)(struct nvmf_context *fctx,
			void *user_data);
	int (*parser_next_line)(struct nvmf_context *fctx,
			void *user_data);

	/* discovery defaults */
	int default_max_discovery_retries;
	int default_keep_alive_timeout;

	/* common fabrics configuraiton */
	const char *device;
	bool persistent;
	struct libnvme_fabrics_config *cfg;

	/* connection configuration */
	const char *subsysnqn;
	const char *transport;
	const char *traddr;
	const char *trsvcid;
	const char *host_traddr;
	const char *host_iface;

	/* host configuration */
	const char *hostnqn;
	const char *hostid;

	/* authentication and transport encryption configuration */
	const char *hostkey;
	const char *ctrlkey;
	const char *keyring;
	char *tls_key;
	const char *tls_key_identity;

	void *user_data;
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
int __libnvme_transport_handle_open_mi(struct libnvme_transport_handle *hdl,
		const char *devname);
int __libnvme_transport_handle_init_mi(struct libnvme_transport_handle *hdl);
void __libnvme_transport_handle_close_mi(struct libnvme_transport_handle *hdl);

int _libnvme_create_ctrl(struct libnvme_global_ctx *ctx,
		struct nvmf_context *fctx,
		libnvme_ctrl_t *cp);
bool _libnvme_ctrl_match_config(struct libnvme_ctrl *c,
		struct nvmf_context *fctx);

void *__libnvme_alloc(size_t len);

void *__libnvme_realloc(void *p, size_t len);

void __nvme_free(void *p);

libnvme_host_t libnvme_lookup_host(struct libnvme_global_ctx *ctx,
		const char *hostnqn, const char *hostid);
libnvme_subsystem_t libnvme_lookup_subsystem(struct libnvme_host *h,
		const char *name, const char *subsysnqn);
libnvme_ctrl_t libnvme_lookup_ctrl(libnvme_subsystem_t s,
		struct nvmf_context *fctx, libnvme_ctrl_t p);
libnvme_ctrl_t libnvme_ctrl_find(libnvme_subsystem_t s,
		struct nvmf_context *fctx);

void __libnvme_free_host(libnvme_host_t h);

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

/* mi internal headers */

/* internal transport API */
struct libnvme_mi_req {
	struct nvme_mi_msg_hdr *hdr;
	size_t hdr_len;
	void *data;
	size_t data_len;
	__u32 mic;
};

struct libnvme_mi_resp {
	struct nvme_mi_msg_hdr *hdr;
	size_t hdr_len;
	void *data;
	size_t data_len;
	__u32 mic;
};

struct libnvme_mi_ep;
struct libnvme_mi_transport {
	const char *name;
	bool mic_enabled;
	int (*submit)(struct libnvme_mi_ep *ep,
		      struct libnvme_mi_req *req,
		      struct libnvme_mi_resp *resp);
	void (*close)(struct libnvme_mi_ep *ep);
	int (*desc_ep)(struct libnvme_mi_ep *ep, char *buf, size_t len);
	int (*check_timeout)(struct libnvme_mi_ep *ep, unsigned int timeout);
	int (*aem_fd)(struct libnvme_mi_ep *ep);
	int (*aem_read)(struct libnvme_mi_ep *ep,
			  struct libnvme_mi_resp *resp);
	int (*aem_purge)(struct libnvme_mi_ep *ep);
};

struct libnvme_mi_aem_ctx {
	struct nvme_mi_aem_occ_list_hdr *occ_header;
	struct nvme_mi_aem_occ_data *list_start;
	struct nvme_mi_aem_occ_data *list_current;
	int list_current_index;
	struct libnvme_mi_aem_config callbacks;
	int last_generation_num;
	struct libnvme_mi_event event;
};

/* quirks */

/* Set a minimum time between receiving a response from one command and
 * sending the next request. Some devices may ignore new commands sent too soon
 * after the previous request, so manually insert a delay
 */
#define LIBNVME_QUIRK_MIN_INTER_COMMAND_TIME		(1 << 0)

/* Some devices may not support using CSI 1.  Attempting to set an
 * endpoint to use this with these devices should return an error
 */
#define LIBNVME_QUIRK_CSI_1_NOT_SUPPORTED		(1 << 1)

struct libnvme_mi_ep {
	struct libnvme_global_ctx *ctx;
	const struct libnvme_mi_transport *transport;
	void *transport_data;
	struct list_node root_entry;
	struct list_head controllers;
	bool quirks_probed;
	bool controllers_scanned;
	unsigned int timeout;
	unsigned int mprt_max;
	unsigned long quirks;

	__u8 csi;

	/* inter-command delay, for LIBNVME_QUIRK_MIN_INTER_COMMAND_TIME */
	unsigned int inter_command_us;
	struct timespec last_resp_time;
	bool last_resp_time_valid;

	struct libnvme_mi_aem_ctx *aem_ctx;
};

struct libnvme_mi_ep *libnvme_mi_init_ep(struct libnvme_global_ctx *ctx);
void libnvme_mi_ep_probe(struct libnvme_mi_ep *ep);

/* for tests, we need to calculate the correct MICs */
__u32 libnvme_mi_crc32_update(__u32 crc, void *data, size_t len);

/* we have a facility to mock MCTP socket operations in the mi-mctp transport,
 * using this ops type. This should only be used for test, and isn't exposed
 * in the shared lib */;
struct mctp_ioc_tag_ctl;
struct __mi_mctp_socket_ops {
	int (*msg_socket)(void);
	int (*aem_socket)(__u8 eid, unsigned int network);
	ssize_t (*sendmsg)(int, const struct msghdr *, int);
	ssize_t (*recvmsg)(int, struct msghdr *, int);
	int (*poll)(struct pollfd *, nfds_t, int);
	int (*ioctl_tag)(int, unsigned long, struct mctp_ioc_tag_ctl *);
};
void __libnvme_mi_mctp_set_ops(const struct __mi_mctp_socket_ops *newops);

#define SECTOR_SIZE	512
#define SECTOR_SHIFT	9

int __libnvme_import_keys_from_config(libnvme_host_t h, libnvme_ctrl_t c,
		long *keyring_id, long *key_id);

static inline char *xstrdup(const char *s)
{
	if (!s)
		return NULL;
	return strdup(s);
}

/**
 * libnvme_getifaddrs - Cached wrapper around getifaddrs()
 * @ctx: pointer to the global context
 *
 * On the first call, this function invokes the POSIX getifaddrs()
 * and caches the result in the global context. Subsequent calls
 * return the cached data. The caller must NOT call freeifaddrs()
 * on the returned data. The cache will be freed when the global
 * context is freed.
 *
 * Return: Pointer to I/F data, NULL on error (with errno set).
 */
const struct ifaddrs *libnvme_getifaddrs(struct libnvme_global_ctx *ctx);

/**
 * libnvme_ipaddrs_eq - Check if 2 IP addresses are equal.
 * @addr1: IP address (can be IPv4 or IPv6)
 * @addr2: IP address (can be IPv4 or IPv6)
 *
 * Return: true if addr1 == addr2. false otherwise.
 */
bool libnvme_ipaddrs_eq(const char *addr1, const char *addr2);

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
int libnvme_ns_get_transport_handle(libnvme_ns_t n,
		struct libnvme_transport_handle **hdl);

/**
 * libnvme_ns_release_transport_handle() - Free transport handle from ns object
 * @n:	Namespace instance
 *
 */
void libnvme_ns_release_transport_handle(libnvme_ns_t n);

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

#ifdef CONFIG_LIBURING
int libnvme_open_uring(struct libnvme_global_ctx *ctx);
void libnvme_close_uring(struct libnvme_global_ctx *ctx);
int __libnvme_transport_handle_open_uring(struct libnvme_transport_handle *hdl);
int libnvme_submit_admin_passthru_async(struct libnvme_transport_handle *hdl,
		struct libnvme_passthru_cmd *cmd);
int libnvme_wait_complete_passthru(struct libnvme_transport_handle *hdl);
#else
static inline int
libnvme_open_uring(struct libnvme_global_ctx *ctx)
{
	return -ENOTSUP;
}
static inline void
libnvme_close_uring(struct libnvme_global_ctx *ctx)
{
}
static inline int
__libnvme_transport_handle_open_uring(struct libnvme_transport_handle *hdl)
{
	hdl->ctx->uring_state = LIBNVME_IO_URING_STATE_NOT_AVAILABLE;
	return -ENOTSUP;
}
static inline int
libnvme_submit_admin_passthru_async(struct libnvme_transport_handle *hdl,
		struct libnvme_passthru_cmd *cmd)
{
	return -ENOTSUP;
}
static inline int
libnvme_wait_complete_passthru(struct libnvme_transport_handle *hdl)
{
	return -ENOTSUP;
}
#endif

