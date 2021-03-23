#ifndef _DISCOVER_H
#define _DISCOVER_H

#include "util/list.h"

#define NVMF_DEF_DISC_TMO	30

extern char *hostnqn_read(void);

extern int fabrics_discover(const char *desc, int argc, char **argv, bool connect);
extern int fabrics_connect(const char *desc, int argc, char **argv);
extern int fabrics_disconnect(const char *desc, int argc, char **argv);
extern int fabrics_disconnect_all(const char *desc, int argc, char **argv);

/* Symbols used by monitor.c */

const char *arg_str(const char * const *strings, size_t array_size, size_t idx);

struct subsys_config;
struct host_config;
struct fabrics_config;

struct port_config {
	struct list_head entry;
	struct subsys_config *subsys;
	char *transport;
	char *traddr;
	char *trsvcid;
	char *host_traddr;
	int  nr_io_queues;
	int  nr_write_queues;
	int  nr_poll_queues;
	int  queue_size;
	int  keep_alive_tmo;
	int  reconnect_delay;
	int  ctrl_loss_tmo;
	int  tos;
	char *device;
	int  duplicate_connect;
	int  disable_sqflow;
	int  hdr_digest;
	int  data_digest;
	bool persistent;
};

struct subsys_config {
	struct list_head entry;
	struct host_config *host;
	char *nqn;
	struct list_head port_list;
};

struct host_config {
	struct list_head entry;
	struct fabrics_config *fabrics;
	char *hostnqn;
	char *hostid;
	struct list_head subsys_list;
};

struct fabrics_config {
	struct list_head host_list;
	char *raw;
	bool quiet;
	bool matching_only;
	bool writeconfig;
	char *output_format;
};

extern const char *const trtypes[];

#define BUF_SIZE 4096

int build_options(struct port_config *port_cfg, char *argstr,
		  int max_len, bool discover);
int do_discover(struct port_config *port_cfg, char *argstr,
		bool connect, enum nvme_print_flags flags);
int ctrl_instance(const char *device);
char *parse_conn_arg(const char *conargs, const char delim, const char *field);
int remove_ctrl(int instance);

#endif
