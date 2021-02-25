#ifndef _DISCOVER_H
#define _DISCOVER_H

#define NVMF_DEF_DISC_TMO	30

extern char *hostnqn_read(void);

extern int fabrics_discover(const char *desc, int argc, char **argv, bool connect);
extern int fabrics_connect(const char *desc, int argc, char **argv);
extern int fabrics_disconnect(const char *desc, int argc, char **argv);
extern int fabrics_disconnect_all(const char *desc, int argc, char **argv);

/* Symbols used by monitor.c */

const char *arg_str(const char * const *strings, size_t array_size, size_t idx);

struct fabrics_config {
	const char *nqn;
	const char *transport;
	const char *traddr;
	const char *trsvcid;
	const char *host_traddr;
	const char *host_iface;
	const char *hostnqn;
	const char *hostid;
	int  nr_io_queues;
	int  nr_write_queues;
	int  nr_poll_queues;
	int  queue_size;
	int  keep_alive_tmo;
	int  reconnect_delay;
	int  ctrl_loss_tmo;
	int  fast_io_fail_tmo;
	int  tos;
	const char *raw;
	char *device;
	int  duplicate_connect;
	int  disable_sqflow;
	int  hdr_digest;
	int  data_digest;
	bool persistent;
	bool matching_only;
	bool quiet;
	const char *output_format;
};
extern struct fabrics_config fabrics_cfg;

extern const char *const trtypes[];

#define BUF_SIZE 4096
#define PATH_NVMF_CFG_DIR	"/etc/nvme"
#define FILE_NVMF_DISC		"discovery.conf"
#define PATH_NVMF_DISC		PATH_NVMF_CFG_DIR "/" FILE_NVMF_DISC

int build_options(char *argstr, int max_len, bool discover);
int do_discover(char *argstr, bool connect, enum nvme_print_flags flags);
int ctrl_instance(const char *device);
char *parse_conn_arg(const char *conargs, const char delim, const char *field);
int remove_ctrl(int instance);
int discover_from_conf_file(const char *desc, char *argstr, bool connect);

#endif
