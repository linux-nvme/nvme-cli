// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2020 Western Digital Corporation or its affiliates.
 *
 * Authors: Keith Busch <keith.busch@wdc.com>
 * 	    Chaitanya Kulkarni <chaitanya.kulkarni@wdc.com>
 */
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
 * @cfg:
 *
 * Return:
 */
int nvmf_add_ctrl_opts(struct nvme_fabrics_config *cfg);

/**
 * nvmf_add_ctrl() -
 * @cfg:
 *
 * Return:
 */
nvme_ctrl_t nvmf_add_ctrl(struct nvme_fabrics_config *cfg);

/**
 * nvmf_get_discovery_log() -
 * @c:
 * @logp:
 * @max_retries:
 *
 * Return:
 */
int nvmf_get_discovery_log(nvme_ctrl_t c, struct nvmf_discovery_log **logp,
			   int max_retries);

/**
 * nvmf_hostnqn_generate() - Generate a machine specific host nqn
 * Returns: An nvm namespace qualifieid name string based on the machine
 * 	    identifier, or NULL if not successful.
 */
char *nvmf_hostnqn_generate();

/**
 * nvmf_hostnqn_from_file() - Reads the host nvm qualified name from the config
 * 			      default location in /etc/nvme/
 * Return: The host nqn, or NULL if unsuccessful. If found, the caller
 * 	   is responsible to free the string.
 */
char *nvmf_hostnqn_from_file();

/**
 * nvmf_hostid_from_file() - Reads the host identifier from the config default
 * 			     location in /etc/nvme/.
 * Return: The host identifier, or NULL if unsuccessful. If found, the caller
 * 	   is responsible to free the string.
 */
char *nvmf_hostid_from_file();

/**
 * nvmf_connect_disc_entry() -
 * @e:
 * @defcfg:
 * @discover:
 *
 * Return:
 */
nvme_ctrl_t nvmf_connect_disc_entry(struct nvmf_disc_log_entry *e,
	const struct nvme_fabrics_config *defcfg, bool *discover);

#endif /* _LIBNVME_FABRICS_H */
