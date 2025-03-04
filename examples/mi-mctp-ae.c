// SPDX-License-Identifier: LGPL-2.1-or-later
/**
 * This file is part of libnvme.
 */

/**
 * mi-mctp-ae: open a MI connection over MCTP, supporting asynchronous event messages
 */

#include <assert.h>
#include <ctype.h>
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <unistd.h> // for usleep

#include <libnvme-mi.h>
#include <poll.h>

#include <ccan/array_size/array_size.h>
#include <ccan/endian/endian.h>
#include <sys/select.h>

struct app_userdata {
	uint32_t count;
};

static void print_byte_array(void *data, size_t len)
{
	uint8_t *byte_data = (uint8_t *)data;

	for (size_t i = 0; i < len; ++i)
		printf("%02X ", byte_data[i]);
	printf("\n");
}

static void print_event_info(struct nvme_mi_event *event)
{
	printf("aeoi: %02X\n", event->aeoi);
	printf("aeocidi: %04X\n", event->aeocidi);
	printf("aessi: %02X\n", event->aessi);

	if (event->spec_info_len && event->spec_info) {
		printf("specific_info: ");
		print_byte_array(event->spec_info, event->spec_info_len);
	}

	if (event->vend_spec_info_len && event->vend_spec_info) {
		printf("vendor_specific_info: ");
		print_byte_array(event->vend_spec_info, event->vend_spec_info_len);
	}
}

enum nvme_mi_aem_handler_next_action aem_handler(nvme_mi_ep_t ep, size_t num_events, void *userdata)
{
	struct app_userdata *data = (struct app_userdata *) userdata;

	data->count++;

	printf("Received notification #%d with %zu events:\n", data->count, num_events);
	for (int i = 0; i < num_events; i++) {
		struct nvme_mi_event *event = nvme_mi_aem_get_next_event(ep);

		if (event == NULL)
			printf("Unexpected NULL event\n");
		else {
			printf("Event:\n");
			print_event_info(event);
			printf("\n");
		}
	}

	return NVME_MI_AEM_HNA_ACK;
}

int main(int argc, char **argv)
{
	nvme_root_t root;
	nvme_mi_ep_t ep;
	uint8_t eid = 0;
	int rc = 0, net = 0;
	struct nvme_mi_aem_config aem_config = {0};
	struct nvme_mi_aem_enabled_map enabled_map = {0};
	struct app_userdata data = {0};

	const uint8_t AEM_FD_INDEX = 0;
	const uint8_t STD_IN_FD_INDEX = 1;

	if (argc == 4) {
		net = atoi(argv[1]);
		eid = atoi(argv[2]) & 0xff;
		argv += 2;
		argc -= 2;

		int event_count = argc - 1;

		for (int i = 0; i < event_count; i++) {
			int event = atoi(argv[1+i]);

			aem_config.enabled_map.enabled[event] = true;
		}
	} else {
		fprintf(stderr,
			"usage: %s <net> <eid> [AE #s separated by spaces]\n",
			argv[0]);
		return EXIT_FAILURE;
	}

	root = nvme_mi_create_root(stderr, DEFAULT_LOGLEVEL);
	if (!root)
		err(EXIT_FAILURE, "can't create NVMe root");

	ep = nvme_mi_open_mctp(root, net, eid);
	if (!ep)
		err(EXIT_FAILURE, "can't open MCTP endpoint %d:%d", net, eid);

	aem_config.aem_handler = aem_handler;
	aem_config.aemd = 1;
	aem_config.aerd = 100;

	rc = nvme_mi_aem_get_enabled(ep, &enabled_map);
	if (rc)
		err(EXIT_FAILURE, "Can't query enabled aems:%d", rc);
	printf("The following events were previously enabled:\n");
	for (int i = 0; i < 256; i++) {
		if (enabled_map.enabled[i])
			printf("Event: %d\n", i);
	}

	rc = nvme_mi_aem_enable(ep, &aem_config, &data);
	if (rc && errno == EOPNOTSUPP)
		errx(EXIT_FAILURE, "MCTP Peer-Bind is required for AEM");
	else if (rc)
		err(EXIT_FAILURE, "Can't enable aem:%d", rc);

	rc = nvme_mi_aem_get_enabled(ep, &enabled_map);
	if (rc)
		err(EXIT_FAILURE, "Can't query enabled aems:%d", rc);

	struct pollfd fds[2];

	fds[AEM_FD_INDEX].fd = nvme_mi_aem_get_fd(ep);
	if (fds[AEM_FD_INDEX].fd < 0)
		errx(EXIT_FAILURE, "Can't get aem fd");

	fds[STD_IN_FD_INDEX].fd = STDIN_FILENO;

	fds[AEM_FD_INDEX].events = POLLIN;
	fds[STD_IN_FD_INDEX].events = POLLIN;

	printf("Press any key to exit\n");
	while (1) {
		rc = poll(fds, 2, -1);

		if (rc == -1) {
			warn("poll");
			break;
		}
		//Time to do the work
		if (fds[AEM_FD_INDEX].revents & POLLIN) {
			rc = nvme_mi_aem_process(ep, &data);
			if (rc)
				err(EXIT_FAILURE,
					"nvme_mi_aem_process failed with:%d", rc);
		}
		if (fds[STD_IN_FD_INDEX].revents & POLLIN)
			break;//we are done
	}

	//Cleanup
	nvme_mi_aem_disable(ep);
	nvme_mi_close(ep);
	nvme_mi_free_root(root);

	return rc ? EXIT_FAILURE : EXIT_SUCCESS;
}


