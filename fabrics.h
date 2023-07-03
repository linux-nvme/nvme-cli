/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _FABRICS_H
#define _FABRICS_H

struct tr_config {
	const char *subsysnqn;
	const char *transport;
	const char *traddr;
	const char *host_traddr;
	const char *host_iface;
	const char *trsvcid;
};

extern nvme_ctrl_t lookup_ctrl(nvme_host_t h, struct tr_config *trcfg);
extern int nvmf_discover(const char *desc, int argc, char **argv, bool connect);
extern int nvmf_connect(const char *desc, int argc, char **argv);
extern int nvmf_disconnect(const char *desc, int argc, char **argv);
extern int nvmf_disconnect_all(const char *desc, int argc, char **argv);
extern int nvmf_config(const char *desc, int argc, char **argv);
extern int nvmf_dim(const char *desc, int argc, char **argv);

#endif
