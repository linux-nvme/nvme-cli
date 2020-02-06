#ifndef _LIBNVME_FABRICS_H
#define _LIBNVME_FABRICS_H

#include <stdbool.h>
#include <stdint.h>

#include "tree.h"

struct nvme_fabrics_config {
	const char *transport;
	const char *traddr;
	const char *trsvcid;
	const char *nqn;
	const char *hostnqn;
	const char *host_traddr;
	const char *hostid;

	int queue_size;
	int nr_io_queues;
	int reconnect_delay;
	int ctrl_loss_tmo;
	int keep_alive_tmo;
	int nr_write_queues;
	int nr_poll_queues;
	int tos;

	bool duplicate_connect;
	bool disable_sqflow;
	bool hdr_digest;
	bool data_digest;

	uint8_t	rsvd[0x200];
};

int nvmf_add_ctrl_opts(struct nvme_fabrics_config *cfg);
nvme_ctrl_t nvmf_add_ctrl(struct nvme_fabrics_config *cfg);
int nvmf_get_discovery_log(nvme_ctrl_t c, struct nvmf_discovery_log **logp, int max_retries);
char *nvmf_hostnqn_generate();
char *nvmf_hostnqn_from_file();
char *nvmf_hostid_from_file();


const char *nvmf_trtype_str(__u8 trtype);
const char *nvmf_adrfam_str(__u8 adrfam);
const char *nvmf_subtype_str(__u8 subtype);
const char *nvmf_treq_str(__u8 treq);
const char *nvmf_sectype_str(__u8 sectype);
const char *nvmf_prtype_str(__u8 prtype);
const char *nvmf_qptype_str(__u8 qptype);
const char *nvmf_cms_str(__u8 cm);

nvme_ctrl_t nvmf_connect_disc_entry(struct nvmf_disc_log_entry *e,
	const struct nvme_fabrics_config *defcfg, bool *discover);
#endif /* _LIBNVME_FABRICS_H */
