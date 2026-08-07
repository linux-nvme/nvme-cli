/* SPDX-License-Identifier: GPL-2.0-or-later */
#pragma once

/* Parsed "nvme connect"/"discover"/"connect-all" argv-style arguments. */
struct nvmf_args {
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

/* Helper text for NVMF_ARGS */
#define DESC_NVMF_TPORT			"transport type"
#define DESC_NVMF_TRADDR		"transport address"
#define DESC_NVMF_NQN			"subsystem nqn"
#define DESC_NVMF_TRSVCID		"transport service id (e.g. IP port)"
#define DESC_NVMF_HTRADDR		"host traddr (e.g. FC WWN's)"
#define DESC_NVMF_HIFACE		"host interface (for tcp transport)"
#define DESC_NVMF_HOSTNQN		"user-defined hostnqn"
#define DESC_NVMF_HOSTID		"user-defined hostid (if default not used)"
#define DESC_NVMF_HOSTKEY		"user-defined kxchap key (if default not used)"
#define DESC_NVMF_CTRLKEY		"user-defined kxchap controller key (for bi-directional authentication)"
#define DESC_NVMF_NR_IO_QUEUES		"number of io queues to use (default is core count)"
#define DESC_NVMF_NR_WRITE_QUEUES	"number of write queues to use (default 0)"
#define DESC_NVMF_NR_POLL_QUEUES	"number of poll queues to use (default 0)"
#define DESC_NVMF_QUEUE_SIZE		"number of io queue elements to use (default 128)"
#define DESC_NVMF_KEEP_ALIVE_TMO	"keep alive timeout period in seconds"
#define DESC_NVMF_RECONNECT_DELAY	"reconnect timeout period in seconds"
#define DESC_NVMF_CTRL_LOSS_TMO		"controller loss timeout period in seconds"
#define DESC_NVMF_FAST_IO_FAIL_TMO	"fast I/O fail timeout (default off)"
#define DESC_NVMF_TOS			"type of service"
#define DESC_NVMF_KEYRING		"Keyring for TLS key lookup (key id or keyring name)"
#define DESC_NVMF_TLS_KEY		"TLS key to use (key id or key in interchange format)"
#define DESC_NVMF_TLS_KEY_LEGACY	"TLS key to use (key id)"
#define DESC_NVMF_TLS_KEY_IDENTITY	"TLS key identity"
#define DESC_NVMF_DUP_CONNECT		"allow duplicate connections between same transport host and subsystem port"
#define DESC_NVMF_DISABLE_SQFLOW	"disable controller sq flow control (default false)"
#define DESC_NVMF_HDR_DIGEST		"enable transport protocol header digest (TCP transport)"
#define DESC_NVMF_DATA_DIGEST		"enable transport protocol data digest (TCP transport)"
#define DESC_NVMF_TLS			"enable TLS"
#define DESC_NVMF_CONCAT		"enable secure concatenation"

/*
 * Common "nvme connect"/"discover"/"connect-all" options, shared by every
 * command that builds a struct nvmf_args from the command line -- including
 * config-create.c, which adds an entry to the INI configuration instead of
 * connecting.
 */
#define NVMF_ARGS(n, f, ...)                                                                  \
	NVME_ARGS(n,                                                                              \
		OPT_STRING("transport",       't', "STR", &f.transport,     DESC_NVMF_TPORT),         \
		OPT_STRING("nqn",             'n', "STR", &f.subsysnqn,     DESC_NVMF_NQN),           \
		OPT_STRING("traddr",          'a', "STR", &f.traddr,        DESC_NVMF_TRADDR),        \
		OPT_STRING("trsvcid",         's', "STR", &f.trsvcid,       DESC_NVMF_TRSVCID),       \
		OPT_STRING("host-traddr",     'w', "STR", &f.host_traddr,   DESC_NVMF_HTRADDR),       \
		OPT_STRING("host-iface",      'f', "STR", &f.host_iface,    DESC_NVMF_HIFACE),        \
		OPT_STRING("hostnqn",         'q', "STR", &f.hostnqn,       DESC_NVMF_HOSTNQN),       \
		OPT_STRING("hostid",          'I', "STR", &f.hostid,        DESC_NVMF_HOSTID),        \
		OPT_STRING("kxchap-secret",   'S', "STR", &f.hostkey,       DESC_NVMF_HOSTKEY),       \
		OPT_STRING("kxchap-ctrl-secret", 'C', "STR", &f.ctrlkey,    DESC_NVMF_CTRLKEY),       \
		OPT_STRING("dhchap-secret",   'S', "STR", &f.hostkey,       DESC_NVMF_HOSTKEY, NULL, true), \
		OPT_STRING("dhchap-ctrl-secret", 'C', "STR", &f.ctrlkey,    DESC_NVMF_CTRLKEY, NULL, true), \
		OPT_STRING("keyring",          0,  "STR", &f.keyring,       DESC_NVMF_KEYRING),       \
		OPT_STRING("tls-key",          0,  "STR", &f.tls_key,       DESC_NVMF_TLS_KEY),       \
		OPT_STRING("tls-key-identity", 0,  "STR", &f.tls_key_identity, DESC_NVMF_TLS_KEY_IDENTITY), \
		OPT_INT("nr-io-queues",       'i', &f.nr_io_queues,       DESC_NVMF_NR_IO_QUEUES),    \
		OPT_INT("nr-write-queues",    'W', &f.nr_write_queues,    DESC_NVMF_NR_WRITE_QUEUES), \
		OPT_INT("nr-poll-queues",     'P', &f.nr_poll_queues,     DESC_NVMF_NR_POLL_QUEUES),  \
		OPT_INT("queue-size",         'Q', &f.queue_size,         DESC_NVMF_QUEUE_SIZE),      \
		OPT_INT("keep-alive-tmo",     'k', &f.keep_alive_tmo,     DESC_NVMF_KEEP_ALIVE_TMO),  \
		OPT_INT("reconnect-delay",    'c', &f.reconnect_delay,    DESC_NVMF_RECONNECT_DELAY), \
		OPT_INT("ctrl-loss-tmo",      'l', &f.ctrl_loss_tmo,      DESC_NVMF_CTRL_LOSS_TMO),   \
		OPT_INT("fast_io_fail_tmo",   'F', &f.fast_io_fail_tmo,   DESC_NVMF_FAST_IO_FAIL_TMO),\
		OPT_INT("tos",                'T', &f.tos,                DESC_NVMF_TOS),             \
		OPT_INT("tls_key",              0, &f.tls_key_id,         DESC_NVMF_TLS_KEY_LEGACY),  \
		OPT_FLAG("duplicate-connect", 'D', &f.duplicate_connect,  DESC_NVMF_DUP_CONNECT),     \
		OPT_FLAG("disable-sqflow",      0, &f.disable_sqflow,     DESC_NVMF_DISABLE_SQFLOW),  \
		OPT_FLAG("hdr-digest",        'g', &f.hdr_digest,         DESC_NVMF_HDR_DIGEST),      \
		OPT_FLAG("data-digest",       'G', &f.data_digest,        DESC_NVMF_DATA_DIGEST),     \
		OPT_FLAG("tls",                 0, &f.tls,                DESC_NVMF_TLS),             \
		OPT_FLAG("concat",              0, &f.concat,             DESC_NVMF_CONCAT),          \
		##__VA_ARGS__                                                                    \
	)

/*
 * Sentinel for an OPT_STRING_OPTIONAL() "--persistent[=no|auto|force]"
 * argument, initialized before parsing so "not given at all" (the pointer
 * still equals this) can be told apart from "given with no value" (optarg
 * is NULL, meaning "auto") and "given=value".
 */
extern char nvmf_persistent_not_given;
#define NVMF_PERSISTENT_NOT_GIVEN (&nvmf_persistent_not_given)

/*
 * Resolve a --persistent argument to the string
 * libnvmf_context_set_persistent()/libnvmf_params_set() expect: NULL if
 * not given at all, "auto" if given bare, or the value as typed otherwise.
 */
const char *nvmf_resolve_persistent_arg(const char *arg);

int fabrics_discover(const char *desc, int argc, char **argv, bool connect);
int fabrics_connect(const char *desc, int argc, char **argv);
int fabrics_disconnect(const char *desc, int argc, char **argv);
int fabrics_disconnect_all(const char *desc, int argc, char **argv);
int fabrics_config_validate(const char *desc, int argc, char **argv);
int fabrics_config_show(const char *desc, int argc, char **argv);
int fabrics_dim(const char *desc, int argc, char **argv);

/* Apply NVMF_ARGS's defaults (tos, ctrl_loss_tmo) before parse_args(). */
void nvmf_default_args(struct nvmf_args *fa);

struct libnvmf_params;

/*
 * Map every tunable/security field of @fa onto @params, using the same key
 * names as the "nvme connect"/"discover" long options. Shared by
 * config-convert.c (legacy migration) and config-create.c (building an
 * entry directly from command-line options).
 */
void nvmf_args_to_params(struct libnvmf_params *params,
		const struct nvmf_args *fa);

/*
 * Legacy config.json/discovery.conf support -- both the explicit converter
 * ("nvme config-convert", config-convert.c/.h) and the implicit fallback
 * (fabrics_discover()/fabrics_connect() auto-converting these files before
 * reading the INI) go away together when legacy config support is
 * eventually dropped; this section (and nvmf_convert_discovery_line() in
 * fabrics.c) goes with them.
 */
struct libnvmf_config_emitter;

#define PATH_NVMF_DISC		SYSCONFDIR "/nvme/discovery.conf"
#define PATH_NVMF_CONFIG	SYSCONFDIR "/nvme/config.json"
#define PATH_NVMF_INI		SYSCONFDIR "/nvme/nvme-fabrics.conf"

/*
 * Parse one discovery.conf line (the argv-style syntax 'nvme discover'
 * accepts) and add it to @emitter as a discovery controller entry. @line is
 * modified in place. Returns 0 for a parsed entry, a skipped blank/comment
 * line, or a malformed one; negative errno only on allocation failure.
 */
int nvmf_convert_discovery_line(struct libnvmf_config_emitter *emitter,
		char *line);
