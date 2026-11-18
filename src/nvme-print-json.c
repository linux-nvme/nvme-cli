// SPDX-License-Identifier: GPL-2.0-or-later

#include <assert.h>
#include <errno.h>
#include <sys/types.h>
#include <time.h>

#ifdef CONFIG_FABRICS
#include <arpa/inet.h>
#include <sys/socket.h>
#endif

#include <libnvme-mi.h>
#include <libnvme.h>

#include <ccan/array_size/array_size.h>
#include <ccan/compiler/compiler.h>
#include <ccan/endian/endian.h>
#include <ccan/minmax/minmax.h>
#include <shared/compiler-attributes-util.h>
#include <shared/hex-util.h>
#include <shared/mmio-util.h>
#include <shared/string-util.h>
#include <shared/unaligned-util.h>

#include "cleanup.h"
#include "nvme-json.h"
#include "nvme-print.h"
#include "nvme-print-json.h"

#define ERROR_MSG_LEN 100
#define BUF_LEN 320

static struct print_ops json_print_ops;
static struct json_object *json_r;
static bool json_init;

static void d_json(unsigned char *buf, int len, int width, int group, struct json_object *array)
{
	int i;
	char ascii[32 + 1] = { 0 };

	assert(width < sizeof(ascii));

	for (i = 0; i < len; i++) {
		ascii[i % width] = (buf[i] >= '!' && buf[i] <= '~') ? buf[i] : '.';
		if (!((i + 1) % width)) {
			array_add_str(array, ascii);
			memset(ascii, 0, sizeof(ascii));
		}
	}

	if (strlen(ascii)) {
		ascii[i % width + 1] = '\0';
		array_add_str(array, ascii);
	}
}

void obj_d(struct json_object *o, const char *k, unsigned char *buf, int len,
	   int width, int group)
{
	struct json_object *data = json_create_array();

	d_json(buf, len, width, group, data);
	obj_add_array(o, k, data);
}


void obj_add_uint_nx(struct json_object *o, const char *k, __u32 v)
{
	char str[STR_LEN];

	sprintf(str, "%#x", v);
	obj_add_str(o, k, str);
}


void obj_add_result(struct json_object *o, const char *v, ...)
{
	va_list ap;

	__cleanup_free char *value = NULL;

	va_start(ap, v);

	if (vasprintf(&value, v, ap) < 0)
		value = NULL;

	obj_add_str(o, "Result", value ? value : alloc_error);

	va_end(ap);
}

void obj_add_key(struct json_object *o, const char *k, const char *v, ...)
{
	va_list ap;

	__cleanup_free char *value = NULL;

	va_start(ap, v);

	if (vasprintf(&value, v, ap) < 0)
		value = NULL;

	obj_add_str(o, k, value ? value : alloc_error);

	va_end(ap);
}

struct json_object *obj_create_array_obj(struct json_object *o, const char *k)
{
	struct json_object *array = json_create_array();
	struct json_object *obj = json_create_object();

	obj_add_array(o, k, array);
	array_add_obj(array, obj);

	return obj;
}

struct json_object *obj_create(const char *k)
{
	struct json_object *array;
	struct json_object *obj = json_create_object();

	if (json_r) {
		array = json_create_array();
		obj_add_array(json_r, k, array);
		array_add_obj(array, obj);
	}

	return obj;
}

void json_print(struct json_object *r)
{
	json_print_object(r, NULL);
	printf("\n");
	json_free_object(r);
}

void obj_print(struct json_object *o)
{
	if (!json_r)
		json_print(o);
}

static bool verbose_mode(void)
{
	return json_print_ops.flags & VERBOSE;
}

bool json_verbose_mode(void)
{
	return verbose_mode();
}

struct json_object *json_root(void)
{
	return json_r;
}

void json_timestamp(struct json_object *r, struct nvme_timestamp *ts)
{
	obj_add_uint64(r, "timestamp", int48_to_long(ts->timestamp));
	obj_add_str(r, "timestamp string", nvme_format_timestamp(ts->timestamp));
	obj_add_str(r, "timestamp origin", nvme_format_timestamp_origin(ts->attr));
	obj_add_str(r, "synch", nvme_format_timestamp_sync(ts->attr));
}

void json_d(unsigned char *buf, int len, int width, int group)
{
	struct json_object *r = json_r;
	char json_str[STR_LEN];

	sprintf(json_str, "data: buf=%p len=%d width=%d group=%d", buf, len, width, group);
	obj_d(r, json_str, buf, len, width, group);
}

#ifdef CONFIG_FABRICS
static void json_discovery_log(const struct nvmf_discovery_log *log, int numrec)
{
	struct json_object *r = json_r;
	struct json_object *entries = json_create_array();
	int i;

	obj_add_uint64(r, "genctr", le64_to_cpu(log->genctr));
	obj_add_array(r, "records", entries);

	for (i = 0; i < numrec; i++) {
		const struct nvmf_disc_log_entry *e = &log->entries[i];
		struct json_object *entry = json_create_object();
		/*
		 * e->trsvcid/subnqn/traddr are fixed-width fields off the wire,
		 * not guaranteed NUL-terminated. json_object_new_string()
		 * needs a NUL-terminated C string, so make NUL-terminated
		 * copies and trim trailing spaces (if any). Members of e
		 * cannot be modified directly (we do not own that data).
		 */
		__cleanup_free char *trsvcid = NULL;
		__cleanup_free char *traddr = NULL;
		__cleanup_free char *subnqn = NULL;

		trsvcid = shr_buf2str(e->trsvcid, sizeof(e->trsvcid));
		traddr = shr_buf2str(e->traddr, sizeof(e->traddr));
		subnqn = shr_buf2str(e->subnqn, sizeof(e->subnqn));

		obj_add_str(entry, "trtype", libnvmf_trtype_str(e->trtype));
		obj_add_str(entry, "adrfam", libnvmf_adrfam_str(e->adrfam));
		obj_add_str(entry, "subtype", libnvmf_subtype_str(e->subtype));
		obj_add_str(entry, "treq", libnvmf_treq_str(e->treq));
		obj_add_uint(entry, "portid", le16_to_cpu(e->portid));
		obj_add_str(entry, "trsvcid", trsvcid);
		obj_add_str(entry, "subnqn", subnqn);
		obj_add_str(entry, "traddr", traddr);
		obj_add_str(entry, "eflags", libnvmf_eflags_str(le16_to_cpu(e->eflags)));

		switch (e->trtype) {
		case NVMF_TRTYPE_RDMA:
			obj_add_str(entry, "rdma_prtype", libnvmf_prtype_str(e->tsas.rdma.prtype));
			obj_add_str(entry, "rdma_qptype", libnvmf_qptype_str(e->tsas.rdma.qptype));
			obj_add_str(entry, "rdma_cms", libnvmf_cms_str(e->tsas.rdma.cms));
			obj_add_uint(entry, "rdma_pkey", le16_to_cpu(e->tsas.rdma.pkey));
			break;
		case NVMF_TRTYPE_TCP:
			obj_add_str(entry, "sectype", libnvmf_sectype_str(e->tsas.tcp.sectype));
			break;
		default:
			break;
		}
		array_add_obj(entries, entry);
	}
}
#else
static void json_discovery_log(const struct nvmf_discovery_log *log,
				int numrec)
{
}
#endif

#ifdef CONFIG_FABRICS
static void json_add_param(const char *key, const char *value, void *user_data)
{
	obj_add_str(user_data, key, value);
}

/*
 * libnvmf_config_conn_for_each() callback for "nvme config show -o json".
 * Reports fields as configured, not canonicalized through a TID (which has
 * no per-field accessors). hostnqn/hostid are null when a persona falls
 * back to the system default, not the value it would resolve to.
 */
static void json_add_conn(const struct libnvmf_config_conn *c, void *user_data)
{
	struct json_object *entries = user_data;
	struct json_object *entry = json_create_object();
	struct json_object *params_obj = json_create_object();
	const struct libnvmf_params *params = libnvmf_config_conn_get_params(c);

	obj_add_str(entry, "source", libnvmf_config_conn_get_source(c));
	obj_add_bool(entry, "is_dc", libnvmf_config_conn_is_dc(c));
	obj_add_str(entry, "transport", libnvmf_config_conn_get_transport(c));
	obj_add_str(entry, "traddr", libnvmf_config_conn_get_traddr(c));
	obj_add_str(entry, "trsvcid", libnvmf_config_conn_get_trsvcid(c));
	obj_add_str(entry, "nqn", libnvmf_config_conn_get_subsysnqn(c));
	obj_add_str(entry, "host-traddr",
		    libnvmf_config_conn_get_host_traddr(c));
	obj_add_str(entry, "host-iface", libnvmf_config_conn_get_host_iface(c));
	obj_add_str(entry, "hostnqn", libnvmf_config_conn_get_hostnqn(c));
	obj_add_str(entry, "hostid", libnvmf_config_conn_get_hostid(c));

	libnvmf_params_for_each(params, json_add_param, params_obj);
	obj_add_obj(entry, "params", params_obj);

	array_add_obj(entries, entry);
}

static void json_config_conn_list(struct libnvmf_config *config)
{
	struct json_object *r = json_r;
	struct json_object *entries = json_create_array();

	obj_add_array(r, "connections", entries);
	libnvmf_config_conn_for_each(config, json_add_conn, entries);
}
#else
static void json_config_conn_list(struct libnvmf_config *config) {}
#endif

static void json_connect_msg(struct libnvme_ctrl *c)
{
	struct json_object *r = json_r;

	obj_add_str(r, "device", libnvme_ctrl_get_name(c));
}

static void json_output_object(struct json_object *r)
{
	json_print(r);
}

static void json_output_status(int status)
{
	struct json_object *r;
	char json_str[STR_LEN];
	int val;
	int type;

	sprintf(json_str, "status: %d", status);
	r = obj_create(json_str);

	if (status < 0) {
		obj_add_str(r, "error", libnvme_strerror(-status));
		obj_print(r);
		return;
	}

	val = nvme_status_get_value(status);
	type = nvme_status_get_type(status);

	switch (type) {
	case NVME_STATUS_TYPE_NVME:
		obj_add_str(r, "error", libnvme_status_to_string(val, false));
		obj_add_str(r, "type", "nvme");
		break;
#ifdef CONFIG_MI
	case NVME_STATUS_TYPE_MI:
		obj_add_str(r, "error", libnvme_mi_status_to_string(val));
		obj_add_str(r, "type", "nvme-mi");
		break;
#endif
	default:
		obj_add_str(r, "type", "Unknown");
		break;
	}

	obj_print(r);
}

static void json_output_opcode_status(int status, bool admin, __u8 opcode)
{
	struct json_object *r;
	char json_str[STR_LEN];
	int val = nvme_status_get_value(status);
	int type = nvme_status_get_type(status);

	if (status >= 0 && type == NVME_STATUS_TYPE_NVME) {
		sprintf(json_str, "status: %d", status);
		r = obj_create(json_str);
		obj_add_str(r, "error",
			    libnvme_opcode_status_to_string(val, admin, opcode));
		obj_add_str(r, "type", "nvme");
		obj_print(r);
		return;
	}

	json_output_status(status);
}

static void json_output_error_status(int status, const char *msg, va_list ap)
{
	struct json_object *r;
	char json_str[STR_LEN];
	int val;
	int type;

	__cleanup_free char *value = NULL;

	if (vasprintf(&value, msg, ap) < 0)
		value = NULL;

	sprintf(json_str, "Error: %s", value ? value : alloc_error);
	r = obj_create(json_str);

	if (status < 0) {
		obj_add_str(r, "error", libnvme_strerror(-status));
		obj_print(r);
		return;
	}

	val = nvme_status_get_value(status);
	type = nvme_status_get_type(status);

	switch (type) {
	case NVME_STATUS_TYPE_NVME:
		obj_add_str(r, "status", libnvme_status_to_string(val, false));
		obj_add_str(r, "type", "nvme");
		break;
#ifdef CONFIG_MI
	case NVME_STATUS_TYPE_MI:
		obj_add_str(r, "status", libnvme_mi_status_to_string(val));
		obj_add_str(r, "type", "nvme-mi");
		break;
#endif
	default:
		obj_add_str(r, "type", "Unknown");
		break;
	}

	obj_add_int(r, "value", val);

	obj_print(r);
}

static void json_output_message(bool error, const char *msg, va_list ap)
{
	struct json_object *r = json_r;

	__cleanup_free char *value = NULL;

	if (vasprintf(&value, msg, ap) < 0)
		value = NULL;

	obj_add_str(r, error ? "error" : "result", value ? value : alloc_error);
}

static void json_output_perror(const char *msg, va_list ap)
{
	struct json_object *r = json_r;
	int err = errno;

	__cleanup_free char *error = NULL;

	if (vasprintf(&error, msg, ap) < 0)
		error = NULL;

	obj_add_key(r, "error", "%s: %s", error ? error : alloc_error,
		    libnvme_strerror(err));
}

static void json_output_key_value(const char *key, const char *val, va_list ap)
{
	struct json_object *r = json_r;

	__cleanup_free char *value = NULL;
	__cleanup_free char *key_dup = strdup(key);
	char *key_trim = key_dup ? shr_trim(key_dup) : NULL;

	if (vasprintf(&value, val, ap) < 0)
		value = NULL;

	obj_add_str(r, key_trim ? key_trim : key, value ? value : "Could not allocate string");
}

void json_show_init(void)
{
	json_init = true;

	if (!json_r)
		json_r = json_create_object();
}

bool json_empty(struct json_object *obj)
{
	if (!obj)
		return true;

	switch (json_object_get_type(obj)) {
	case json_type_object:
		return json_object_object_length(obj) == 0;
	case json_type_array:
		return json_object_array_length(obj) == 0;
	default:
		return false; /* scalars always have something to print */
	}
}

void json_show_finish(void)
{
	/* nvme_main() finishes even if no command started a document */
	if (!json_init)
		return;
	json_init = false;

	if (!json_empty(json_r))
		json_output_object(json_r);
	else
		json_free_object(json_r);

	json_r = NULL;
}

/*
 * A sandboxed printer: the child inherits the document as it was at the
 * fork. Let the printer write to an object of its own instead, whose
 * members the caller adds to its document.
 */
static int json_capture_begin(void)
{
	if (!json_init)
		return 0;

	json_r = json_create_object();
	return json_r ? 0 : -ENOMEM;
}

static int json_member_put(struct printbuf *pb, const char *s, size_t len)
{
	uint32_t n = len;

	if (len > UINT32_MAX)
		return -EOVERFLOW;
	printbuf_memappend(pb, (const char *)&n, sizeof(n));
	printbuf_memappend(pb, s, len);

	return 0;
}

/*
 * The members the printer added, serialized as pairs of a length and the
 * key, a length and the value. @buf is to free().
 */
static int json_capture_end(void **buf, size_t *len)
{
	struct printbuf *pb;
	const char *v;
	int err = 0;

	*buf = NULL;
	*len = 0;
	if (!json_init)
		return 0;

	pb = printbuf_new();
	if (!pb)
		return -ENOMEM;
	json_object_object_foreach(json_r, key, val) {
		v = json_object_to_json_string_ext(val,
				JSON_C_TO_STRING_PRETTY |
				JSON_C_TO_STRING_NOSLASHESCAPE);
		if (!v || json_member_put(pb, key, strlen(key)) ||
		    json_member_put(pb, v, strlen(v))) {
			err = -ENOMEM;
			break;
		}
	}
	if (!err && printbuf_length(pb)) {
		*buf = malloc(printbuf_length(pb));
		if (*buf) {
			memcpy(*buf, pb->buf, printbuf_length(pb));
			*len = printbuf_length(pb);
		} else {
			err = -ENOMEM;
		}
	}
	printbuf_free(pb);

	return err;
}

/* Writes a serialized value as it is, indented to @level */
static int json_member_serialize(struct json_object *jso,
				 struct printbuf *pb, int level, int flags)
{
	const char *s = json_object_get_string(jso);
	size_t len = json_object_get_string_len(jso), i, start = 0;
	int j;

	for (i = 0; i < len; i++) {
		if (s[i] != '\n')
			continue;
		printbuf_memappend(pb, s + start, i - start + 1);
		start = i + 1;
		if (flags & JSON_C_TO_STRING_PRETTY)
			for (j = 0; j < level; j++)
				printbuf_strappend(pb, "  ");
	}
	printbuf_memappend(pb, s + start, len - start);

	return 0;
}

static bool json_member_get(const char **p, const char *end,
			    const char **s, uint32_t *n)
{
	if ((size_t)(end - *p) < sizeof(*n))
		return false;
	memcpy(n, *p, sizeof(*n));
	*p += sizeof(*n);
	if ((size_t)(end - *p) < *n)
		return false;
	*s = *p;
	*p += *n;

	return true;
}

/*
 * Adds the members of a sandboxed printer to the document. They are added
 * as the child serialized them, not parsed again: a parse would turn 128
 * bit numbers into doubles. A member replaces one of the same key, as when
 * the printer runs in process. The child may have been taken over: check
 * the framing, the values are only copied to the output.
 */
static int json_capture_add(const void *buf, size_t len)
{
	const char *p = buf, *end = p + len, *k, *v;
	struct json_object *val;
	__cleanup_free char *key = NULL;
	uint32_t klen, vlen;

	if (!len)
		return 0;
	if (!json_init || !json_r)
		return -EPROTO;

	while (p < end) {
		if (!json_member_get(&p, end, &k, &klen) ||
		    !json_member_get(&p, end, &v, &vlen) ||
		    memchr(k, '\0', klen))
			return -EPROTO;
		free(key);
		key = strndup(k, klen);
		if (!key)
			return -ENOMEM;
		val = json_object_new_string_len(v, vlen);
		if (!val)
			return -ENOMEM;
		json_object_set_serializer(val, json_member_serialize,
					   NULL, NULL);
		json_object_object_add(json_r, key, val);
	}

	return 0;
}

static struct print_ops json_print_ops = {
	/* libnvme types.h print functions */
	.discovery_log			= json_discovery_log,
	.d				= json_d,
	.show_init			= json_show_init,
	.show_finish			= json_show_finish,

	/* config show */
	.config_conn_list		= json_config_conn_list,

	/* status and error messages */
	.connect_msg			= json_connect_msg,
	.show_message			= json_output_message,
	.show_perror			= json_output_perror,
	.show_status			= json_output_status,
	.show_opcode_status		= json_output_opcode_status,
	.show_error_status		= json_output_error_status,
	.show_key_value			= json_output_key_value,
	.capture_begin			= json_capture_begin,
	.capture_end			= json_capture_end,
	.capture_add			= json_capture_add,
};

/*
 * json-c seeds its string hash on the first lookup. Built without
 * getrandom(), as the meson subproject is, it reads /dev/urandom then,
 * which a printer in the sandbox cannot open.
 */
static void json_seed_hash(void)
{
	struct json_object *o = json_create_object();

	json_object_object_get_ex(o, "", NULL);
	json_free_object(o);
}

struct print_ops *nvme_get_json_print_ops(nvme_print_flags_t flags)
{
	json_seed_hash();
	json_print_ops.flags = flags;
	return &json_print_ops;
}
