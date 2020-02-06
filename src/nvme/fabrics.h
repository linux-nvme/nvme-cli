#ifndef _LIBNVME_FABRICS_H
#define _LIBNVME_FABRICS_H

#include <stdbool.h>
#include <stdint.h>
#include "tree.h"

/**
 * struct nvme_fabrics_config -
 * @transport:		
 * @traddr:		
 * @trsvcid:		
 * @nqn:		
 * @hostnqn:		
 * @host_traddr:	
 * @hostid:		
 * @queue_size:		
 * @nr_io_queues:	
 * @reconnect_delay:	
 * @ctrl_loss_tmo:	
 * @keep_alive_tmo:	
 * @nr_write_queues:	
 * @nr_poll_queues:	
 * @tos:		
 * @duplicate_connect:	
 * @disable_sqflow:	
 * @hdr_digest:		
 * @data_digest:	
 * @rsvd:		
 */
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

/**
 * nvmf_add_ctrl_opts() -
 */
int nvmf_add_ctrl_opts(struct nvme_fabrics_config *cfg);

/**
 * nvmf_add_ctrl() -
 */
nvme_ctrl_t nvmf_add_ctrl(struct nvme_fabrics_config *cfg);

/**
 * nvmf_get_discovery_log() -
 */
int nvmf_get_discovery_log(nvme_ctrl_t c, struct nvmf_discovery_log **logp,
			   int max_retries);

/**
 * nvmf_hostnqn_generate() -
 */
char *nvmf_hostnqn_generate();

/**
 * nvmf_hostnqn_from_file() -
 */
char *nvmf_hostnqn_from_file();

/**
 * nvmf_hostid_from_file() -
 */
char *nvmf_hostid_from_file();

/**
 * nvmf_trtype_str() -
 */
const char *nvmf_trtype_str(__u8 trtype);

/**
 * nvmf_adrfam_str() -
 */
const char *nvmf_adrfam_str(__u8 adrfam);

/**
 * nvmf_subtype_str() -
 */
const char *nvmf_subtype_str(__u8 subtype);

/**
 * nvmf_treq_str() -
 */
const char *nvmf_treq_str(__u8 treq);

/**
 * nvmf_sectype_str() -
 */
const char *nvmf_sectype_str(__u8 sectype);

/**
 * nvmf_prtype_str() -
 */
const char *nvmf_prtype_str(__u8 prtype);

/**
 * nvmf_qptype_str() -
 */
const char *nvmf_qptype_str(__u8 qptype);

/**
 * nvmf_cms_str() -
 */
const char *nvmf_cms_str(__u8 cm);


/**
 * nvmf_connect_disc_entry() -
 */
nvme_ctrl_t nvmf_connect_disc_entry(struct nvmf_disc_log_entry *e,
	const struct nvme_fabrics_config *defcfg, bool *discover);

#endif /* _LIBNVME_FABRICS_H */
