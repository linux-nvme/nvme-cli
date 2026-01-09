// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2021 SUSE Software Solutions
 *
 * Authors: Hannes Reinecke <hare@suse.de>
 */

#ifndef _LIBNVME_PRIVATE_H
#define _LIBNVME_PRIVATE_H

#include <ccan/list/list.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <nvme/fabrics.h>
#include <nvme/mi.h>

const char *nvme_subsys_sysfs_dir(void);
const char *nvme_ctrl_sysfs_dir(void);
const char *nvme_ns_sysfs_dir(void);
const char *nvme_slots_sysfs_dir(void);
const char *nvme_uuid_ibm_filename(void);
const char *nvme_dmi_entries_dir(void);

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

#define NVME_IOCTL_ADMIN_CMD	_IOWR('N', 0x41, struct linux_passthru_cmd32)
#define NVME_IOCTL_IO_CMD	_IOWR('N', 0x43, struct linux_passthru_cmd32)
#define NVME_IOCTL_ADMIN64_CMD  _IOWR('N', 0x47, struct linux_passthru_cmd64)
#define NVME_IOCTL_IO64_CMD     _IOWR('N', 0x48, struct linux_passthru_cmd64)

struct nvme_log {
	int fd;
	int level;
	bool pid;
	bool timestamp;
};

enum nvme_transport_handle_type {
	NVME_TRANSPORT_HANDLE_TYPE_UNKNOWN = 0,
	NVME_TRANSPORT_HANDLE_TYPE_DIRECT,
	NVME_TRANSPORT_HANDLE_TYPE_MI,
};

struct nvme_transport_handle {
	struct nvme_global_ctx *ctx;
	enum nvme_transport_handle_type type;
	char *name;

	void *(*submit_entry)(struct nvme_transport_handle *hdl,
			struct nvme_passthru_cmd *cmd);
	void (*submit_exit)(struct nvme_transport_handle *hdl,
			struct nvme_passthru_cmd *cmd,
			int err, void *user_data);
	bool (*decide_retry)(struct nvme_transport_handle *hdl,
			struct nvme_passthru_cmd *cmd, int err);

	/* direct */
	int fd;
	struct stat stat;
	bool ioctl64;

	/* mi */
	struct nvme_mi_ep *ep;
	__u16 id;
	struct list_node ep_entry;

	struct nvme_log *log;
};

struct nvme_path {
	struct list_node entry;
	struct list_node nentry;

	struct nvme_ctrl *c;
	struct nvme_ns *n;

	char *name;
	char *sysfs_dir;
	char *ana_state;
	char *numa_nodes;
	int grpid;
	int queue_depth;
};

struct nvme_ns_head {
	struct list_head paths;
	struct nvme_ns *n;

	char *sysfs_dir;
};

struct nvme_ns {
	struct list_node entry;

	struct nvme_subsystem *s;
	struct nvme_ctrl *c;
	struct nvme_ns_head *head;

	struct nvme_transport_handle *hdl;
	__u32 nsid;
	char *name;
	char *generic_name;
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

struct nvme_ctrl {
	struct list_node entry;
	struct list_head paths;
	struct list_head namespaces;
	struct nvme_subsystem *s;

	struct nvme_transport_handle *hdl;
	char *name;
	char *sysfs_dir;
	char *address;
	char *firmware;
	char *model;
	char *state;
	char *numa_node;
	char *queue_count;
	char *serial;
	char *sqsize;
	char *transport;
	char *subsysnqn;
	char *traddr;
	char *trsvcid;
	char *dhchap_key;
	char *dhchap_ctrl_key;
	char *keyring;
	char *tls_key_identity;
	char *tls_key;
	char *cntrltype;
	char *cntlid;
	char *dctype;
	char *phy_slot;
	char *host_traddr;
	char *host_iface;
	bool discovery_ctrl;
	bool unique_discovery_ctrl;
	bool discovered;
	bool persistent;
	struct nvme_fabrics_config cfg;
};

struct nvme_subsystem {
	struct list_node entry;
	struct list_head ctrls;
	struct list_head namespaces;
	struct nvme_host *h;

	char *name;
	char *sysfs_dir;
	char *subsysnqn;
	char *model;
	char *serial;
	char *firmware;
	char *subsystype;
	char *application;
	char *iopolicy;
};

struct nvme_host {
	struct list_node entry;
	struct list_head subsystems;
	struct nvme_global_ctx *ctx;

	char *hostnqn;
	char *hostid;
	char *dhchap_key;
	char *hostsymname;
	bool pdc_enabled;
	bool pdc_enabled_valid; /* set if pdc_enabled doesn't have an undefined
				 * value */
};

struct nvme_fabric_options {
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

struct nvme_global_ctx {
	char *config_file;
	char *application;
	struct list_head endpoints; /* MI endpoints */
	struct list_head hosts;
	struct nvme_log log;
	bool mi_probe_enabled;
	bool create_only;
	bool dry_run;
	struct nvme_fabric_options *options;
};

struct nvmf_discovery_ctx {
	/* defaults */
	int default_max_discovery_retries;
	int default_keep_alive_timeout;

	void (*discovery_log)(struct nvmf_discovery_ctx *dctx,
			bool connect,
			struct nvmf_discovery_log *log,
			uint64_t numrec, void *user_data);
	void (*already_connected)(struct nvme_host *host,
			struct nvmf_disc_log_entry *entry,
			void *user_data);
	bool (*decide_retry)(struct nvmf_discovery_ctx *dctx, int err,
			void *user_data);
	void (*connected)(struct nvmf_discovery_ctx *dctx, struct nvme_ctrl *c,
			void *user_data);
	int (*parser_init)(struct nvmf_discovery_ctx *dctx,
			void *user_data);
	void (*parser_cleanup)(struct nvmf_discovery_ctx *dctx,
			void *user_data);
	int (*parser_next_line)(struct nvmf_discovery_ctx *dctx,
			void *user_data);

	/* connfiguration */
	bool persistent;
	const char *device;
	const char *subsysnqn;
	const char *transport;
	const char *traddr;
	const char *host_traddr;
	const char *host_iface;
	const char *trsvcid;
	const char *hostnqn;
	const char *hostid;
	const char *hostkey;
	const char *ctrlkey;
	const char *keyring;
	const char *tls_key;
	const char *tls_key_identity;
	struct nvme_fabrics_config *cfg;
	struct nvme_fabrics_config *defcfg;

	void *user_data;
};

struct nvmf_context {
	/* common callbacks */
	bool (*decide_retry)(struct nvmf_context *fctx, int err,
			void *user_data);
	void (*connected)(struct nvmf_context *fctx, struct nvme_ctrl *c,
			void *user_data);
	void (*already_connected)(struct nvmf_context *fctx,
			struct nvme_host *host, const char *subsysnqn,
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
	struct nvme_fabrics_config *cfg;

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
	const char *tls_key;
	const char *tls_key_identity;

	void *user_data;
};

struct fabric_args {
	const char *subsysnqn;
	const char *transport;
	const char *traddr;
	const char *trsvcid;
	const char *host_traddr;
	const char *host_iface;
};

int nvme_set_attr(const char *dir, const char *attr, const char *value);

int json_read_config(struct nvme_global_ctx *ctx, const char *config_file);

int json_update_config(struct nvme_global_ctx *ctx, const char *config_file);

int json_dump_tree(struct nvme_global_ctx *ctx);

void *__nvme_submit_entry(struct nvme_transport_handle *hdl,
		struct nvme_passthru_cmd *cmd);
void __nvme_submit_exit(struct nvme_transport_handle *hdl,
		struct nvme_passthru_cmd *cmd, int err, void *user_data);
bool __nvme_decide_retry(struct nvme_transport_handle *hdl,
		struct nvme_passthru_cmd *cmd, int err);

struct nvme_transport_handle *__nvme_open(struct nvme_global_ctx *ctx, const char *name);
struct nvme_transport_handle *__nvme_create_transport_handle(struct nvme_global_ctx *ctx);
int __nvme_transport_handle_open_mi(struct nvme_transport_handle *hdl, const char *devname);
int __nvme_transport_handle_init_mi(struct nvme_transport_handle *hdl);
void __nvme_transport_handle_close_mi(struct nvme_transport_handle *hdl);

nvme_ctrl_t __nvme_lookup_ctrl(nvme_subsystem_t s, const char *transport,
			       const char *traddr, const char *host_traddr,
			       const char *host_iface, const char *trsvcid,
			       const char *subsysnqn, nvme_ctrl_t p);

void *__nvme_alloc(size_t len);

void *__nvme_realloc(void *p, size_t len);

nvme_host_t nvme_lookup_host(struct nvme_global_ctx *ctx, const char *hostnqn,
			     const char *hostid);
nvme_subsystem_t nvme_lookup_subsystem(struct nvme_host *h,
				       const char *name,
				       const char *subsysnqn);


#if (LOG_FUNCNAME == 1)
#define __nvme_log_func __func__
#else
#define __nvme_log_func NULL
#endif

void __attribute__((format(printf, 4, 5)))
__nvme_msg(struct nvme_global_ctx *ctx, int level, const char *func, const char *format, ...);

#define nvme_msg(ctx, level, format, ...)					\
	__nvme_msg(ctx, level, __nvme_log_func, format, ##__VA_ARGS__)

#define ctx_from_ctrl(c) ((c)->s && (c)->s->h ? (c)->s->h->ctx : NULL)
#define ctx_from_ns(n) ((n)->s && (n)->s->h ? (n)->s->h->ctx : \
			 (n)->c && (n)->c->s && (n)->c->s->h ? (n)->c->s->h->ctx : \
			 NULL)

/* mi internal headers */

/* internal transport API */
struct nvme_mi_req {
	struct nvme_mi_msg_hdr *hdr;
	size_t hdr_len;
	void *data;
	size_t data_len;
	__u32 mic;
};

struct nvme_mi_resp {
	struct nvme_mi_msg_hdr *hdr;
	size_t hdr_len;
	void *data;
	size_t data_len;
	__u32 mic;
};

struct nvme_mi_ep;
struct nvme_mi_transport {
	const char *name;
	bool mic_enabled;
	int (*submit)(struct nvme_mi_ep *ep,
		      struct nvme_mi_req *req,
		      struct nvme_mi_resp *resp);
	void (*close)(struct nvme_mi_ep *ep);
	int (*desc_ep)(struct nvme_mi_ep *ep, char *buf, size_t len);
	int (*check_timeout)(struct nvme_mi_ep *ep, unsigned int timeout);
	int (*aem_fd)(struct nvme_mi_ep *ep);
	int (*aem_read)(struct nvme_mi_ep *ep,
			  struct nvme_mi_resp *resp);
	int (*aem_purge)(struct nvme_mi_ep *ep);
};

struct nvme_mi_aem_ctx {
	struct nvme_mi_aem_occ_list_hdr *occ_header;
	struct nvme_mi_aem_occ_data *list_start;
	struct nvme_mi_aem_occ_data *list_current;
	int list_current_index;
	struct nvme_mi_aem_config callbacks;
	int last_generation_num;
	struct nvme_mi_event event;
};

/* quirks */

/* Set a minimum time between receiving a response from one command and
 * sending the next request. Some devices may ignore new commands sent too soon
 * after the previous request, so manually insert a delay
 */
#define NVME_QUIRK_MIN_INTER_COMMAND_TIME	(1 << 0)

/* Some devices may not support using CSI 1.  Attempting to set an
 * endpoint to use this with these devices should return an error
 */
#define NVME_QUIRK_CSI_1_NOT_SUPPORTED          (1 << 1)

struct nvme_mi_ep {
	struct nvme_global_ctx *ctx;
	const struct nvme_mi_transport *transport;
	void *transport_data;
	struct list_node root_entry;
	struct list_head controllers;
	bool quirks_probed;
	bool controllers_scanned;
	unsigned int timeout;
	unsigned int mprt_max;
	unsigned long quirks;

	__u8 csi;

	/* inter-command delay, for NVME_QUIRK_MIN_INTER_COMMAND_TIME */
	unsigned int inter_command_us;
	struct timespec last_resp_time;
	bool last_resp_time_valid;

	struct nvme_mi_aem_ctx *aem_ctx;
};

struct nvme_mi_ep *nvme_mi_init_ep(struct nvme_global_ctx *ctx);
void nvme_mi_ep_probe(struct nvme_mi_ep *ep);

/* for tests, we need to calculate the correct MICs */
__u32 nvme_mi_crc32_update(__u32 crc, void *data, size_t len);

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
void __nvme_mi_mctp_set_ops(const struct __mi_mctp_socket_ops *newops);

#define SECTOR_SIZE	512
#define SECTOR_SHIFT	9

int __nvme_import_keys_from_config(nvme_host_t h, nvme_ctrl_t c,
				   long *keyring_id, long *key_id);

static inline char *xstrdup(const char *s)
{
	if (!s)
		return NULL;
	return strdup(s);
}

#endif /* _LIBNVME_PRIVATE_H */
