/* SPDX-License-Identifier: GPL-2.0-or-later */
#pragma once

#include <inttypes.h>
#include <stddef.h>
#include <string.h>

#include <ccan/array_size/array_size.h>
#include <ccan/endian/endian.h>
#include <ccan/list/list.h>
#include <ccan/str/str.h>

#include "args.h"
#include "nvme-json.h"
#include <shared/int-util.h>
#include <shared/mem-util.h>
#include <shared/table-util.h>
#include <shared/uint128-util.h>
#include <shared/unaligned-util.h>
#include <shared/uuid-util.h>

#define STR_LEN 100

typedef struct nvme_effects_log_node {
	struct nvme_cmd_effects_log effects; /* needs to be first member because of alignment requirement. */
	enum nvme_csi csi;
	struct list_node node;
} nvme_effects_log_node_t;

#define nvme_show_error(msg, ...) nvme_show_message(true, msg, ##__VA_ARGS__)
#define nvme_show_result(msg, ...) nvme_show_message(false, msg, ##__VA_ARGS__)
#define nvme_show_verbose_result(msg, ...) nvme_show_verbose_message(msg, ##__VA_ARGS__)
#define nvme_show_verbose_info(msg, ...) nvme_show_verbose_message(msg, ##__VA_ARGS__)

#define POWER_OF_TWO(exponent) (1 << (exponent))

#define BYTE_TO_BIT(byte) ((byte) * 8)
#define MS_TO_SEC(time) ((time) / 1000)
#define MS500_TO_MS(time) ((time) * 500)
#define MS500_TO_SEC(time) (MS_TO_SEC(MS500_TO_MS(time)))

void d(unsigned char *buf, int len, int width, int group);
void d_raw(unsigned char *buf, unsigned len);

enum nvme_cli_topo_ranking {
	NVME_CLI_TOPO_NAMESPACE,
	NVME_CLI_TOPO_CTRL,
	NVME_CLI_TOPO_MULTIPATH,
};

/*
 * NPSS is a 0's based value. A device can report more power states than
 * the power state descriptor table holds.
 */
static inline int nvme_id_ctrl_nr_psd(struct nvme_id_ctrl *ctrl)
{
	int max = ARRAY_SIZE(ctrl->psd);

	return ctrl->npss < max ? ctrl->npss + 1 : max;
}

/*
 * NLBAF and NULBAF are 0's based values. A device can report more LBA
 * formats than the LBA format table holds.
 */
static inline int nvme_id_ns_nr_lbaf(struct nvme_id_ns *ns)
{
	int max = ARRAY_SIZE(ns->lbaf);
	int n = ns->nlbaf + ns->nulbaf + 1;

	return n < max ? n : max;
}

/*
 * A log page counts its entries, but the count comes from the device and
 * the page may be shorter: a later read can report more entries than the
 * buffer was sized for. Return: @nr, but at most the number of @size byte
 * entries @len bytes hold after a @hdr byte header.
 */
static inline size_t nvme_log_nr_entries(size_t nr, size_t len, size_t hdr,
					 size_t size)
{
	size_t max = len > hdr ? (len - hdr) / size : 0;

	return nr < max ? nr : max;
}

/*
 * The namespace identification descriptor at offset @pos of the list, or
 * NULL where the list ends: at a descriptor of length 0, or at one which
 * does not fit into the list. A descriptor takes its header and NIDL bytes.
 */
static inline struct nvme_ns_id_desc *nvme_ns_id_desc(void *data, size_t pos)
{
	struct nvme_ns_id_desc *cur = data + pos;

	if (pos > NVME_IDENTIFY_DATA_SIZE - sizeof(*cur))
		return NULL;
	if (!cur->nidl ||
	    cur->nidl > NVME_IDENTIFY_DATA_SIZE - pos - sizeof(*cur))
		return NULL;

	return cur;
}

/*
 * Return: the type of the namespace identification descriptor @cur, or 0,
 * a reserved type, if its length is not the one its type has.
 */
static inline __u8 nvme_ns_id_desc_type(const struct nvme_ns_id_desc *cur)
{
	__u8 len;

	switch (cur->nidt) {
	case NVME_NIDT_EUI64:
		len = NVME_NIDT_EUI64_LEN;
		break;
	case NVME_NIDT_NGUID:
		len = NVME_NIDT_NGUID_LEN;
		break;
	case NVME_NIDT_UUID:
		len = NVME_NIDT_UUID_LEN;
		break;
	case NVME_NIDT_CSI:
		len = NVME_NIDT_CSI_LEN;
		break;
	default:
		return cur->nidt;
	}

	return cur->nidl == len ? cur->nidt : 0;
}

/* Return: the LBA data size in bytes, or 0 if it is not representable. */
static inline unsigned int nvme_lbaf_data_size(__u8 ds)
{
	return ds < 32 ? 1U << ds : 0;
}

static inline bool nvme_is_multipath(struct libnvme_subsystem *s)
{
	struct libnvme_ns *n;
	struct libnvme_path *p;

	libnvme_subsystem_for_each_ns(s, n)
		libnvme_namespace_for_each_path(n, p)
			return true;

	return false;
}

static inline bool subsystem_iopolicy_filter(const char *name, void *arg)
{
	struct libnvme_subsystem *s = arg;
	const char *iopolicy;

	libnvme_subsystem_get_iopolicy(s, &iopolicy, "");

	if (streq(iopolicy, "queue-depth")) {
		/* exclude "Nodes" for iopolicy queue-depth */
		if (streq(name, "Nodes"))
			return false;
	} else if (streq(iopolicy, "numa")) {
		/* exclude "Qdepth" for iopolicy numa */
		if (streq(name, "Qdepth"))
			return false;
	} else { /* round-robin */
		/* exclude "Nodes" and "Qdepth" for iopolicy round-robin */
		if (streq(name, "Nodes") || streq(name, "Qdepth"))
			return false;
	}

	return true;
}


/* config.h is fabrics-only; forward-declare so this header stays valid in a
 * -Dfabrics=disabled build.
 */
struct libnvmf_config;

struct print_ops {
	/* libnvme types.h print functions */
	void (*discovery_log)(const struct nvmf_discovery_log *log, int numrec);
	void (*relatives)(struct libnvme_global_ctx *ctx, const char *name);
	void (*select_result)(enum nvme_features_id fid, __u64 result);
	void (*show_feature)(enum nvme_features_id fid, int sel,
			     unsigned int result, void *buf, __u32 data_len);
	void (*show_feature_fields)(enum nvme_features_id fid, unsigned int result, unsigned char *buf);
	void (*lba_range)(struct nvme_lba_range_type *lbrt, int nr_ranges);
	void (*lba_status_info)(__u64 result);
	void (*d)(unsigned char *buf, int len, int width, int group);
	void (*show_init)(void);
	void (*show_finish)(void);

	/* libnvme tree print functions */
	void (*list_item)(struct libnvme_ns *n, struct shr_table *t);
	void (*list_items)(struct libnvme_global_ctx *ctx);
	void (*print_nvme_subsystem_list)(struct libnvme_global_ctx *ctx, bool show_ana);
	void (*topology_ctrl)(struct libnvme_global_ctx *ctx);
	void (*topology_namespace)(struct libnvme_global_ctx *ctx);
	void (*topology_multipath)(struct libnvme_global_ctx *ctx);
	void (*topology_tabular)(struct libnvme_global_ctx *ctx);

	/* config show */
	void (*config_conn_list)(struct libnvmf_config *config);

	/* nvme top */
	void (*top)(int refresh_interval);

	/* status and error messages */
	void (*connect_msg)(struct libnvme_ctrl *c);
	void (*show_message)(bool error, const char *msg, va_list ap);
	void (*show_perror)(const char *msg, va_list ap);
	void (*show_status)(int status);
	void (*show_opcode_status)(int status, bool admin, __u8 opcode);
	void (*show_error_status)(int status, const char *msg, va_list ap);
	void (*show_key_value)(const char *key, const char *val, va_list ap);

	/*
	 * A sandboxed printer, see nvme_print_begin(): output which does not
	 * go to stdout is captured in the child, between capture_begin() and
	 * capture_end(), and handed to capture_add() in the caller. Optional.
	 */
	int (*capture_begin)(void);
	int (*capture_end)(void **buf, size_t *len);
	int (*capture_add)(const void *buf, size_t len);

	nvme_print_flags_t flags;
};

#ifdef CONFIG_JSONC

struct print_ops *nvme_get_json_print_ops(nvme_print_flags_t flags);

#else /* !CONFIG_JSONC */

static inline struct print_ops *nvme_get_json_print_ops(nvme_print_flags_t flags) { return NULL; }

#endif /* !CONFIG_JSONC */

/* A printer failed in the sandbox */
bool nvme_show_failed(void);

/*
 * Run a printer from a plugin's printer table the same way nvme_print()
 * runs the core printers: skip it for dry runs, and run it in the decoder
 * sandbox if that is enabled and @sandbox is set. Pass false for printers
 * that open files, issue commands or pass data back to the caller. See
 * Documentation/PRIVSEP.md.
 */
bool nvme_print_decoder_begin(nvme_print_flags_t flags, bool sandbox);
void nvme_print_decoder_end(nvme_print_flags_t flags);

#define nvme_print_decoder(ops, name, sandbox, flags, ...)		\
	do {								\
		typeof(ops) __ops = (ops);				\
									\
		if (!__ops || !__ops->name)				\
			nvme_show_error("unhandled output format");	\
		else if (nvme_print_decoder_begin(flags, sandbox)) {	\
			__ops->name(__VA_ARGS__);			\
			nvme_print_decoder_end(flags);			\
		}							\
	} while (false)

/*
 * Log page decoder registered by a plugin for get-log -v. ->show returns
 * true if it decoded the log page.
 */
struct nvme_log_decoder {
	bool (*show)(const char *devname, enum nvme_cmd_get_log_lid lid,
		     __u32 nsid, __u16 lsi, __u8 lsp, void *log, __u32 len,
		     nvme_print_flags_t flags);
	struct nvme_log_decoder *next;
};

void nvme_register_log_decoder(struct nvme_log_decoder *dec);

/* Run the registered decoders, true if one of them decoded the log page */
bool nvme_show_log_decoded(const char *devname, enum nvme_cmd_get_log_lid lid,
			   __u32 nsid, __u16 lsi, __u8 lsp, void *log,
			   __u32 len, nvme_print_flags_t flags);

struct print_ops *nvme_get_stdout_print_ops(nvme_print_flags_t flags);
struct print_ops *nvme_get_binary_print_ops(nvme_print_flags_t flags);

void stdout_top(int refresh_interval);

void nvme_show_status(int status);
void nvme_show_err(int err, const char *fmt, ...);
void nvme_show_io_cmd_err(const char *msg, __u8 opcode, int err);
void nvme_show_admin_cmd_err(const char *msg, __u8 opcode, int err);
void nvme_show_opcode_status(int status, bool admin, __u8 opcode);
void nvme_show_lba_status_info(__u64 result);
void nvme_show_relatives(struct libnvme_global_ctx *ctx, const char *name, nvme_print_flags_t flags);

void nvme_show_lba_range(struct nvme_lba_range_type *lbrt, int nr_ranges,
	nvme_print_flags_t flags);

/*
 * The Metadata Element Descriptor at offset *@off of a Host Metadata data
 * structure. A descriptor is 4 bytes and its value, so it may start at
 * any offset: its fixed part is copied to @desc. Returns its value, which
 * *@len long ends with the structure at the latest, and advances *@off
 * to the next descriptor. NULL if the fixed part does not fit anymore.
 */
static inline const __u8 *
nvme_host_metadata_element(const struct nvme_host_metadata *data,
		size_t *off, struct nvme_metadata_element_desc *desc,
		__u16 *len)
{
	size_t size = sizeof(data->descs_buf);
	const __u8 *val;

	if (*off > size || size - *off < sizeof(*desc))
		return NULL;

	memcpy(desc, data->descs_buf + *off, sizeof(*desc));
	*off += sizeof(*desc);
	val = data->descs_buf + *off;
	*len = le16_to_cpu(desc->len);
	if (*len > size - *off)
		*len = size - *off;
	*off += *len;

	return val;
}

void nvme_show_list_items(struct libnvme_global_ctx *ctx, nvme_print_flags_t flags);
void nvme_show_subsystem_list(struct libnvme_global_ctx *ctx, bool show_ana,
			      nvme_print_flags_t flags);
void nvme_show_topology(struct libnvme_global_ctx *ctx,
			enum nvme_cli_topo_ranking ranking,
			nvme_print_flags_t flags);
void nvme_show_topology_tabular(struct libnvme_global_ctx *ctx, nvme_print_flags_t flags);
void nvme_show_feature(enum nvme_features_id fid, int sel, unsigned int result,
		       void *buf, __u32 data_len, nvme_print_flags_t flags);
void nvme_show_top(nvme_print_flags_t flags, int refresh_interval);
void nvme_feature_show_fields(enum nvme_features_id fid, unsigned int result, unsigned char *buf);
void nvme_show_select_result(enum nvme_features_id fid, __u64 result);

void nvme_show_list_item(struct libnvme_ns *n, struct shr_table *t);

void nvme_show_discovery_log(const struct nvmf_discovery_log *log,
			     uint64_t numrec, nvme_print_flags_t flags);
void nvme_show_connect_msg(struct libnvme_ctrl *c, nvme_print_flags_t flags);
void nvme_show_config_conn_list(struct libnvmf_config *config,
				 nvme_print_flags_t flags);

const char *nvme_cmd_to_string(int admin, __u8 opcode);
const char *nvme_fdp_event_to_string(enum nvme_fdp_event_type event);
const char *nvme_feature_lba_type_to_string(__u8 type);
const char *nvme_feature_temp_sel_to_string(__u8 sel);
const char *nvme_feature_temp_type_to_string(__u8 type);
const char *nvme_feature_to_string(enum nvme_features_id feature);
const char *nvme_feature_wl_hints_to_string(__u8 wh);
const char *nvme_feature_perfc_attri_to_string(__u8 attri);
const char *nvme_feature_perfc_r4karl_to_string(__u8 r4karl);
const char *nvme_feature_perfc_attrtyp_to_string(__u8 attrtyp);
const char *nvme_host_metadata_type_to_string(enum nvme_features_id fid, __u8 type);
const char *nvme_select_to_string(int sel);
const char *nvme_plm_window_to_string(__u32 plm);
const char *nvme_ns_wp_cfg_to_string(enum nvme_ns_write_protect_cfg state);
const char *nvme_time_scale_to_string(__u8 ts);
const char *nvme_pls_mode_to_string(__u8 mode);
const char *nvme_bpwps_to_string(__u8 bpwps);
const char *nvme_feature_power_limit_scale_to_string(__u8 pls);
const char *nvme_power_measurement_type_to_string(__u8 pmt);
const char *nvme_power_measurement_action_to_string(__u8 act);
const char *nvme_ipmsr_srs_to_string(__u8 srs);

void nvme_dev_full_path(struct libnvme_ns *n, char *path, size_t len);
void nvme_generic_full_path(struct libnvme_ns *n, char *path, size_t len);
void nvme_show_message(bool error, const char *msg, ...);
void nvme_show_verbose_message(const char *msg, ...);
void nvme_show_perror(const char *msg, ...);
void nvme_show_error_status(int status, const char *msg, ...);
void nvme_show_init(void);
void nvme_show_finish(void);
void nvme_show_key_value(const char *key, const char *value, ...);
void nvme_show_verbose_key_value(const char *key, const char *value, ...);
const char *nvme_degrees_string(long t);
const char *nvme_degrees_fahrenheit_string(long t);
const char *nvme_format_timestamp(__u8 *timestamp_bytes);
const char *nvme_format_timestamp_origin(__u8 attr);
const char *nvme_format_timestamp_sync(__u8 attr);
void print_array(char *name, __u8 *data, int size);
void json_print(struct json_object *r);
struct json_object *obj_create_array_obj(struct json_object *o, const char *k);
const char *nvme_support_str(bool support);
const char *nvme_yes_str(bool yes);

extern const char *alloc_error;
extern const char *feat_ae_dlpcn;
extern const char *feat_ae_hdlpcn;
extern const char *feat_ae_adlpcn;
extern const char *feat_ae_pmdrlpcn;
extern const char *feat_ae_zdcn;
extern const char *feat_ae_rlccn;
extern const char *feat_ae_lhcn;
extern const char *feat_ae_ccrcn;
extern const char *feat_ae_ansan;
extern const char *feat_ae_rgrp0;
extern const char *feat_ae_rassn;
extern const char *feat_ae_tthry;
extern const char *feat_ae_nnsshdn;
extern const char *feat_ae_ega;
extern const char *feat_ae_lbas;
extern const char *feat_ae_pla;
extern const char *feat_ae_ana;
extern const char *feat_ae_telem;
extern const char *feat_ae_fw;
extern const char *feat_ae_nan;
extern const char *feat_ae_smart;
