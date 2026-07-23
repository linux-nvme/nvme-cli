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

int fabrics_discovery(const char *desc, int argc, char **argv, bool connect);
int fabrics_connect(const char *desc, int argc, char **argv);
int fabrics_disconnect(const char *desc, int argc, char **argv);
int fabrics_disconnect_all(const char *desc, int argc, char **argv);
int fabrics_config_validate(const char *desc, int argc, char **argv);
int fabrics_config_show(const char *desc, int argc, char **argv);
int fabrics_dim(const char *desc, int argc, char **argv);

/*
 * Legacy config.json/discovery.conf support -- both the explicit converter
 * ("nvme config-convert", config-convert.c/.h) and the implicit fallback
 * (fabrics_discovery()/fabrics_connect() auto-converting these files before
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
