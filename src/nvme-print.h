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


/* config.h is fabrics-only; forward-declare so this header stays valid in a
 * -Dfabrics=disabled build.
 */
struct libnvmf_config;

struct print_ops {
	/* libnvme types.h print functions */
	void (*discovery_log)(const struct nvmf_discovery_log *log, int numrec);
	void (*relatives)(struct libnvme_global_ctx *ctx, const char *name);
	void (*d)(unsigned char *buf, int len, int width, int group);
	void (*show_init)(void);
	void (*show_finish)(void);

	/* config show */
	void (*config_conn_list)(struct libnvmf_config *config);

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
bool nvme_print_decoder_begin_always(nvme_print_flags_t flags, bool sandbox);
void nvme_print_decoder_end(nvme_print_flags_t flags);

#define __nvme_print_decoder(begin, ops, name, sandbox, flags, ...)	\
	do {								\
		typeof(ops) __ops = (ops);				\
									\
		if (!__ops || !__ops->name)				\
			nvme_show_error("unhandled output format");	\
		else if (begin(flags, sandbox)) {			\
			__ops->name(__VA_ARGS__);			\
			nvme_print_decoder_end(flags);			\
		}							\
	} while (false)

#define nvme_print_decoder(ops, name, sandbox, flags, ...)		\
	__nvme_print_decoder(nvme_print_decoder_begin, ops, name,	\
			     sandbox, flags, ##__VA_ARGS__)

/*
 * Like nvme_print_decoder(), but run the printer for dry runs as well.
 * A command uses it to show the fields of the value it sets.
 */
#define nvme_print_decoder_always(ops, name, sandbox, flags, ...)	\
	__nvme_print_decoder(nvme_print_decoder_begin_always, ops, name, \
			     sandbox, flags, ##__VA_ARGS__)

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


void nvme_show_status(int status);
void nvme_show_err(int err, const char *fmt, ...);
void nvme_show_io_cmd_err(const char *msg, __u8 opcode, int err);
void nvme_show_admin_cmd_err(const char *msg, __u8 opcode, int err);
void nvme_show_opcode_status(int status, bool admin, __u8 opcode);
void nvme_show_relatives(struct libnvme_global_ctx *ctx, const char *name, nvme_print_flags_t flags);

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


void nvme_show_discovery_log(const struct nvmf_discovery_log *log,
			     uint64_t numrec, nvme_print_flags_t flags);
void nvme_show_connect_msg(struct libnvme_ctrl *c, nvme_print_flags_t flags);
void nvme_show_config_conn_list(struct libnvmf_config *config,
				 nvme_print_flags_t flags);

const char *nvme_cmd_to_string(int admin, __u8 opcode);
const char *nvme_fdp_event_to_string(enum nvme_fdp_event_type event);
const char *nvme_time_scale_to_string(__u8 ts);
const char *nvme_feature_power_limit_scale_to_string(__u8 pls);
const char *nvme_power_measurement_type_to_string(__u8 pmt);
const char *nvme_ipmsr_srs_to_string(__u8 srs);

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
