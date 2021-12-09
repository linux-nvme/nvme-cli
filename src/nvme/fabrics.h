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

/* default to 600 seconds of reconnect attempts before giving up */
#define NVMF_DEF_CTRL_LOSS_TMO		600

/**
 * struct nvme_fabrics_config - Defines all linux nvme fabrics initiator options
 * @queue_size:		Number of IO queue entries
 * @nr_io_queues:	Number of controller IO queues to establish
 * @reconnect_delay:	Time between two consecutive reconnect attempts.
 * @ctrl_loss_tmo:	Override the default controller reconnect attempt timeout in seconds
 * @fast_io_fail_tmo:	Set the fast I/O fail timeout in seconds.
 * @keep_alive_tmo:	Override the default keep-alive-timeout to this value in seconds
 * @nr_write_queues:	Number of queues to use for exclusively for writing
 * @nr_poll_queues:	Number of queues to reserve for polling completions
 * @tos:		Type of service
 * @duplicate_connect:	Allow multiple connections to the same target
 * @disable_sqflow:	Disable controller sq flow control
 * @hdr_digest:		Generate/verify header digest (TCP)
 * @data_digest:	Generate/verify data digest (TCP)
 */
struct nvme_fabrics_config {
	int queue_size;
	int nr_io_queues;
	int reconnect_delay;
	int ctrl_loss_tmo;
	int fast_io_fail_tmo;
	int keep_alive_tmo;
	int nr_write_queues;
	int nr_poll_queues;
	int tos;

	bool duplicate_connect;
	bool disable_sqflow;
	bool hdr_digest;
	bool data_digest;
};

/**
 * nvmf_trtype_str() - Decode TRTYPE field
 * @trtype: value to be decoded
 *
 * Decode the transport type field in the discovery
 * log page entry.
 *
 * Return: decoded string
 */
const char *nvmf_trtype_str(__u8 trtype);

/**
 * nvmf_adrfam_str() - Decode ADRFAM field
 * @adrfam: value to be decoded
 *
 * Decode the address family field in the discovery
 * log page entry.
 *
 * Return: decoded string
 */
const char *nvmf_adrfam_str(__u8 adrfam);

/**
 * nvmf_subtype_str() - Decode SUBTYPE field
 * @subtype: value to be decoded
 *
 * Decode the subsystem type field in the discovery
 * log page entry.
 *
 * Return: decoded string
 */
const char *nvmf_subtype_str(__u8 subtype);

/**
 * nvmf_treq_str() - Decode TREQ field
 * @treq: value to be decoded
 *
 * Decode the transport requirements field in the
 * discovery log page entry.
 *
 * Return: decoded string
 */
const char *nvmf_treq_str(__u8 treq);

/**
 * nvmf_eflags_str() - Decode EFLAGS field
 * @eflags: value to be decoded
 *
 * Decode the EFLAGS field in the discovery log page
 * entry.
 *
 * Return: decoded string
 */
const char *nvmf_eflags_str(__u16 eflags);

/**
 * nvmf_sectype_str() -
 * @sectype:
 *
 * Return:
 */
const char *nvmf_sectype_str(__u8 sectype);

/**
 * nvmf_prtype_str() -
 * @prtype:
 *
 * Return:
 */
const char *nvmf_prtype_str(__u8 prtype);

/**
 * nvmf_qptype_str() -
 * @qptype:
 *
 * Return:
 */
const char *nvmf_qptype_str(__u8 qptype);

/**
 * nvmf_cms_str() -
 * @cms:
 *
 * Return:
 */
const char *nvmf_cms_str(__u8 cms);

/**
 * nvmf_default_config - Default values for fabrics configuration
 * @cfg: config values to set
 *
 * Initializes @cfg with default values.
 */
void nvmf_default_config(struct nvme_fabrics_config *cfg);

/**
 * nvmf_add_ctrl_opts() -
 * @c:
 * @cfg:
 *
 * Return:
 */
int nvmf_add_ctrl_opts(nvme_ctrl_t c, struct nvme_fabrics_config *cfg);

/**
 * nvmf_add_ctrl() -
 * @h:
 * @c:
 * @cfg:
 * @disable_sqflow:
 *
 * Return:
 */
int nvmf_add_ctrl(nvme_host_t h, nvme_ctrl_t c,
		  const struct nvme_fabrics_config *cfg,
		  bool disable_sqflow);

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
 * Returns: An nvm namespace qualified name string based on the machine
 * identifier, or NULL if not successful.
 */
char *nvmf_hostnqn_generate();

/**
 * nvmf_hostnqn_from_file() - Reads the host nvm qualified name from the config
 * 			      default location in /etc/nvme/
 * Return: The host nqn, or NULL if unsuccessful. If found, the caller
 * is responsible to free the string.
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
 * @h:
 * @e:
 * @defcfg:
 * @discover:
 *
 * Return: An 
 */
nvme_ctrl_t nvmf_connect_disc_entry(nvme_host_t h,
	struct nvmf_disc_log_entry *e,
	const struct nvme_fabrics_config *defcfg, bool *discover);

/**
 * nvme_chomp() - Strip trailing white space
 * &s: String to strip
 * @l: Maximum length of string
 */
static inline void nvme_chomp(char *s, int l)
{
	while (l && (s[l] == '\0' || s[l] == ' '))
		s[l--] = '\0';
}

#endif /* _LIBNVME_FABRICS_H */
