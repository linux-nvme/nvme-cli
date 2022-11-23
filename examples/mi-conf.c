// SPDX-License-Identifier: LGPL-2.1-or-later
/**
 * This file is part of libnvme.
 * Copyright (c) 2022 Code Construct Pty Ltd.
 *
 * Authors: Jeremy Kerr <jk@codeconstruct.com.au>
 */

/**
 * mi-conf: query a device for optimal MTU and set for both the local MCTP
 * route (through dbus to mctpd) and the device itself (through NVMe-MI
 * configuration commands)
 */

#include <err.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <libnvme-mi.h>

#include <ccan/array_size/array_size.h>
#include <ccan/endian/endian.h>

#include <dbus/dbus.h>

#define MCTP_DBUS_NAME "xyz.openbmc_project.MCTP"
#define MCTP_DBUS_PATH "/xyz/openbmc_project/mctp"
#define MCTP_DBUS_EP_IFACE "au.com.CodeConstruct.MCTP.Endpoint"

static int parse_mctp(const char *devstr, unsigned int *net, uint8_t *eid)
{
	int rc;

	rc = sscanf(devstr, "mctp:%u,%hhu", net, eid);
	if (rc != 2)
		return -1;

	return 0;
}

int find_port(nvme_mi_ep_t ep, uint8_t *portp, uint16_t *mtup)
{
	struct nvme_mi_read_nvm_ss_info ss_info;
	struct nvme_mi_read_port_info port_info;
	uint8_t port;
	bool found;
	int rc;

	/* query number of ports */
	rc = nvme_mi_mi_read_mi_data_subsys(ep, &ss_info);
	if (rc) {
		warn("Failed reading subsystem info");
		return -1;
	}

	found = false;
	for (port = 0; port <= ss_info.nump; port++) {
		rc = nvme_mi_mi_read_mi_data_port(ep, port, &port_info);
		if (rc) {
			warn("Failed reading port info for port %ud", port);
			return -1;
		}

		/* skip non-SMBus ports */
		if (port_info.portt != 0x2)
			continue;

		if (found) {
			warn("Mutliple SMBus ports; skipping duplicate");
		} else {
			*portp = port;
			*mtup = port_info.mmctptus;
			found = true;
		}
	}

	return found ? 0 : 1;
}

int set_local_mtu(DBusConnection *bus, unsigned int net, uint8_t eid,
		  uint32_t mtu)
{
	DBusMessage *msg, *resp;
	DBusError berr;
	char *ep_path;
	int rc;

	rc = asprintf(&ep_path, "%s/%u/%hhu", MCTP_DBUS_PATH, net, eid);
	if (rc < 0) {
		warn("Failed to create dbus path");
		return -1;
	}

	/* The NVMe-MI interfaces refer to their MTU as *not* including the
	 * 4-byte MCTP header, whereas the MCTP specs *do* include it. When
	 * we're setting the route MTU, we're using to the MCTP-style MTU,
	 * which needs the extra four bytes included
	 */
	mtu += 4;

	rc = -1;
	dbus_error_init(&berr);
	msg = dbus_message_new_method_call(MCTP_DBUS_NAME, ep_path,
					   MCTP_DBUS_EP_IFACE, "SetMTU");
	if (!msg) {
		warnx("Can't create D-Bus message");
		goto out;
	}

	rc = dbus_message_append_args(msg,
				      DBUS_TYPE_UINT32, &mtu,
				      DBUS_TYPE_INVALID);
	if (!rc) {
		warnx("Can't construct D-Bus message arguments");
		goto out_free_msg;
	}

	resp = dbus_connection_send_with_reply_and_block(bus, msg,
							 2000, &berr);
	if (!resp) {
		warnx("Failed to set local MTU: %s (%s)", berr.message,
		      berr.name);
	} else {
		dbus_message_unref(resp);
		rc = 0;
	}

out_free_msg:
	dbus_message_unref(msg);
out:
	dbus_error_free(&berr);
	return rc;
}

int main(int argc, char **argv)
{
	uint16_t cur_mtu, mtu;
	DBusConnection *bus;
	const char *devstr;
	uint8_t eid, port;
	nvme_root_t root;
	unsigned int net;
	nvme_mi_ep_t ep;
	DBusError berr;
	int rc;

	if (argc != 2) {
		fprintf(stderr, "usage: %s mctp:<net>,<eid>\n", argv[0]);
		return EXIT_FAILURE;
	}

	devstr = argv[1];
	rc = parse_mctp(devstr, &net, &eid);
	if (rc)
		errx(EXIT_FAILURE, "can't parse MI device string '%s'", devstr);

	root = nvme_mi_create_root(stderr, DEFAULT_LOGLEVEL);
	if (!root)
		err(EXIT_FAILURE, "can't create NVMe root");

	ep = nvme_mi_open_mctp(root, net, eid);
	if (!ep) {
		warnx("can't open MCTP endpoint %d:%d", net, eid);
		goto out_free_root;
	}

	dbus_error_init(&berr);
	bus = dbus_bus_get(DBUS_BUS_SYSTEM, &berr);
	if (!bus) {
		warnx("Failed opening D-Bus: %s (%s)\n",
		      berr.message, berr.name);
		rc = -1;
		goto out_close_ep;
	}

	rc = find_port(ep, &port, &mtu);
	if (rc) {
		warnx("Can't find SMBus port information");
		goto out_close_bus;
	}

	rc = nvme_mi_mi_config_get_mctp_mtu(ep, port, &cur_mtu);
	if (rc) {
		cur_mtu = 0;
		warn("Can't query current MTU; no way to revert on failure");
	}

	if (mtu == cur_mtu) {
		printf("Current MTU (%d) is already at max\n", cur_mtu);
		goto out_close_bus;
	}

	rc = nvme_mi_mi_config_set_mctp_mtu(ep, port, mtu);
	if (rc) {
		warn("Can't set MCTP MTU");
		goto out_close_bus;
	}

	rc = set_local_mtu(bus, net, eid, mtu);
	if (rc) {
		/* revert if we have an old setting */
		if (cur_mtu) {
			rc = nvme_mi_mi_config_set_mctp_mtu(ep, port, cur_mtu);
			if (rc)
				warn("Failed to restore previous MTU!");
			rc = -1;
		}
	} else {
		printf("MTU for port %u set to %d (was %d)\n",
		       port, mtu, cur_mtu);
	}

out_close_bus:
	dbus_connection_unref(bus);
out_close_ep:
	dbus_error_free(&berr);
	nvme_mi_close(ep);
out_free_root:
	nvme_mi_free_root(root);

	return rc ? EXIT_FAILURE : EXIT_SUCCESS;
}

