// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2020 Western Digital Corporation or its affiliates.
 *
 * Authors: Keith Busch <keith.busch@wdc.com>
 *	    Chaitanya Kulkarni <chaitanya.kulkarni@wdc.com>
 */
#pragma once

/**
 * libnvme_generate_hostnqn() - Generate a machine specific host nqn
 * Return: An nvm namespace qualified name string based on the machine
 * identifier, or NULL if not successful.
 */
char *libnvme_generate_hostnqn(void);

/**
 * libnvme_generate_hostnqn_from_hostid() - Generate a host nqn from
 * host identifier
 * @hostid:		Host identifier
 *
 * If @hostid is NULL, the function generates it based on the machine
 * identifier.
 *
 * Return: On success, an NVMe Qualified Name for host identification. This
 * name is based on the given host identifier. On failure, NULL.
 */
char *libnvme_generate_hostnqn_from_hostid(char *hostid);

/**
 * libnvme_generate_hostid() - Generate a machine specific host identifier
 *
 * Return: On success, an identifier string based on the machine identifier to
 * be used as NVMe Host Identifier, or NULL on failure.
 */
char *libnvme_generate_hostid(void);

/**
 * libnvme_read_hostnqn() - Reads the host nvm qualified name from the config
 *			      default location
 *
 * Retrieve the qualified name from the config file located in $SYSCONFDIR/nvme.
 * $SYSCONFDIR is usually /etc.
 *
 * Return: The host nqn, or NULL if unsuccessful. If found, the caller
 * is responsible to free the string.
 */
char *libnvme_read_hostnqn(void);

/**
 * libnvme_read_hostid() - Reads the host identifier from the config default
 *			     location
 *
 * Retrieve the host idenditifer from the config file located in
 * $SYSCONFDIR/nvme/. $SYSCONFDIR is usually /etc.
 *
 * Return: The host identifier, or NULL if unsuccessful. If found, the caller
 *	   is responsible to free the string.
 */
char *libnvme_read_hostid(void);
