/* SPDX-License-Identifier: GPL-2.0-or-later */
#pragma once

struct argconfig_commandline_options;

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
	int tls_key_id;
	long tls_configured_key_id;
	bool duplicate_connect;
	bool disable_sqflow;
	bool hdr_digest;
	bool data_digest;
	bool tls;
	bool concat;
};

/* Helper text for the fabrics options */
#define DESC_NVMF_TPORT			"transport type"
#define DESC_NVMF_TRADDR		"transport address"
#define DESC_NVMF_NQN			"subsystem nqn"
#define DESC_NVMF_TRSVCID		"transport service id (e.g. IP port)"
#define DESC_NVMF_HTRADDR		"host traddr (e.g. FC WWN's)"
#define DESC_NVMF_HIFACE		"host interface (for tcp transport)"
#define DESC_NVMF_HOSTNQN		"user-defined hostnqn"
#define DESC_NVMF_HOSTID		"user-defined hostid (if default not used)"
#define DESC_NVMF_HOSTKEY		"user-defined kxchap secret (if default not used)"
#define DESC_NVMF_CTRLKEY		"user-defined kxchap controller secret (for bi-directional authentication)"
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
 * The options which every command shares that builds a struct nvmf_args
 * from the command line -- connect, discover, connect-all, disconnect and
 * config create, which adds an entry to the INI configuration instead of
 * connecting. nvmf_options() returns them bound to @fa, which the
 * command includes with OPT_INCLUDE() and frees. Start @fa with
 * nvmf_args_defaults().
 */
struct argconfig_commandline_options *nvmf_options(struct nvmf_args *fa);
struct nvmf_args nvmf_args_defaults(void);

/*
 * Resolve an OPT_STRING_OPTIONAL() "--persistent[=no|auto|force]" argument
 * to the string libnvmf_context_set_persistent()/libnvmf_params_set()
 * expect: "auto" when the option is absent or given bare, or the value as
 * typed otherwise. Never NULL -- persistence is on by default, and
 * "--persistent=no" is the opt-out. @given is whether the option was
 * given, @arg its value. A caller that has to tell "absent" from "given"
 * apart uses argconfig_given() itself.
 */
const char *nvmf_resolve_persistent_arg(bool given, const char *arg);

int fabrics_discover(const char *desc, int argc, char **argv, bool connect);
int fabrics_connect(const char *desc, int argc, char **argv);
int fabrics_disconnect(const char *desc, int argc, char **argv);
int fabrics_disconnect_all(const char *desc, int argc, char **argv);
int fabrics_config_validate(const char *desc, int argc, char **argv);
int fabrics_config_show(const char *desc, int argc, char **argv);
int fabrics_dim(const char *desc, int argc, char **argv);


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
