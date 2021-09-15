// SPDX-License-Identifier: LGPL-2.1-or-later
/**
 * This file is part of libnvme.
 * Copyright (c) 2021 Code Construct Pty Ltd.
 *
 * Authors: Jeremy Kerr <jk@codeconstruct.com.au>
 */

/**
 * mi-mctp: open a MI connection over MCTP, and query controller info
 */

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libnvme-mi.h>

#include <ccan/array_size/array_size.h>
#include <ccan/endian/endian.h>

static void show_port_pcie(struct nvme_mi_read_port_info *port)
{
	printf("    PCIe max payload: 0x%x\n", 0x80 << port->pcie.mps);
	printf("    PCIe link speeds: 0x%02x\n", port->pcie.sls);
	printf("    PCIe current speed: 0x%02x\n", port->pcie.cls);
	printf("    PCIe max link width: 0x%02x\n", port->pcie.mlw);
	printf("    PCIe neg link width: 0x%02x\n", port->pcie.nlw);
	printf("    PCIe port: 0x%02x\n", port->pcie.pn);
}

static void show_port_smbus(struct nvme_mi_read_port_info *port)
{
	printf("    SMBus address: 0x%02x\n", port->smb.vpd_addr);
	printf("    VPD access freq: 0x%02x\n", port->smb.mvpd_freq);
	printf("    MCTP address: 0x%02x\n", port->smb.mme_addr);
	printf("    MCTP access freq: 0x%02x\n", port->smb.mme_freq);
	printf("    NVMe basic management: %s\n",
	       (port->smb.nvmebm & 0x1) ? "enabled" : "disabled");
}

static struct {
	int typeid;
	const char *name;
	void (*fn)(struct nvme_mi_read_port_info *);
} port_types[] = {
	{ 0x00, "inactive", NULL },
	{ 0x01, "PCIe", show_port_pcie },
	{ 0x02, "SMBus", show_port_smbus },
};

static int show_port(nvme_mi_ep_t ep, int portid)
{
	void (*show_fn)(struct nvme_mi_read_port_info *);
	struct nvme_mi_read_port_info port;
	const char *typestr;
	int rc;

	rc = nvme_mi_mi_read_mi_data_port(ep, portid, &port);
	if (rc)
		return rc;

	if (port.portt < ARRAY_SIZE(port_types)) {
		show_fn = port_types[port.portt].fn;
		typestr = port_types[port.portt].name;
	} else {
		show_fn = NULL;
		typestr = "INVALID";
	}

	printf("  port %d\n", portid);
	printf("    type %s[%d]\n", typestr, port.portt);
	printf("    MCTP MTU: %d\n", port.mmctptus);
	printf("    MEB size: %d\n", port.meb);

	if (show_fn)
		show_fn(&port);

	return 0;
}

int do_info(nvme_mi_ep_t ep)
{
	struct nvme_mi_nvm_ss_health_status ss_health;
	struct nvme_mi_read_nvm_ss_info ss_info;
	int i, rc;

	rc = nvme_mi_mi_read_mi_data_subsys(ep, &ss_info);
	if (rc) {
		warn("can't perform Read MI Data operation");
		return -1;
	}

	printf("NVMe MI subsys info:\n");
	printf(" num ports: %d\n", ss_info.nump + 1);
	printf(" major ver: %d\n", ss_info.mjr);
	printf(" minor ver: %d\n", ss_info.mnr);

	printf("NVMe MI port info:\n");
	for (i = 0; i <= ss_info.nump; i++)
		show_port(ep, i);

	rc = nvme_mi_mi_subsystem_health_status_poll(ep, true, &ss_health);
	if (rc)
		err(EXIT_FAILURE, "can't perform Health Status Poll operation");

	printf("NVMe MI subsys health:\n");
	printf(" subsystem status:  0x%x\n", ss_health.nss);
	printf(" smart warnings:    0x%x\n", ss_health.sw);
	printf(" composite temp:    %d\n", ss_health.ctemp);
	printf(" drive life used:   %d%%\n", ss_health.pdlu);
	printf(" controller status: 0x%04x\n", le16_to_cpu(ss_health.pdlu));

	return 0;
}

enum action {
	ACTION_INFO,
};

int main(int argc, char **argv)
{
	enum action action;
	nvme_root_t root;
	nvme_mi_ep_t ep;
	uint8_t eid;
	int rc, net;

	if (argc < 3) {
		fprintf(stderr,
			"usage: %s <net> <eid> [action] [action args]\n",
			argv[0]);
		fprintf(stderr, "where action is:\n"
			"  info\n");
		return EXIT_FAILURE;
	}

	net = atoi(argv[1]);
	eid = atoi(argv[2]) & 0xff;
	argv += 2;
	argc -= 2;

	if (argc == 1) {
		action = ACTION_INFO;
	} else {
		char *action_str = argv[1];
		argc--;
		argv++;

		if (!strcmp(action_str, "info")) {
			action = ACTION_INFO;
		} else {
			fprintf(stderr, "invalid action '%s'\n", action_str);
			return EXIT_FAILURE;
		}
	}

	root = nvme_mi_create_root(stderr, DEFAULT_LOGLEVEL);
	if (!root)
		err(EXIT_FAILURE, "can't create NVMe root");

	ep = nvme_mi_open_mctp(root, net, eid);
	if (!ep)
		err(EXIT_FAILURE, "can't open MCTP endpoint %d:%d", net, eid);

	switch (action) {
	case ACTION_INFO:
		rc = do_info(ep);
		break;
	}

	nvme_mi_close(ep);

	nvme_mi_free_root(root);

	return rc ? EXIT_FAILURE : EXIT_SUCCESS;
}


