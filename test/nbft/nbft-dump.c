// SPDX-License-Identifier: LGPL-2.1-or-later
/**
 * This file is part of libnvme.
 * Copyright (c) 2023 Red Hat Inc.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#include "libnvme.h"

static void print_hex(unsigned char *buf, int len)
{
	int i;

	for (i = 0; i < len; i++, buf++)
		printf("%x", *buf);
}

static void print_nbft(struct nbft_info *table)
{
	unsigned int i, j;
	struct nbft_info_hfi **hfi;
	struct nbft_info_security **sec;
	struct nbft_info_discovery **disc;
	struct nbft_info_subsystem_ns **ssns;

	printf("raw_nbft_size=%zd\n", table->raw_nbft_size);

	printf("host.id=");
	print_hex(table->host.id, NVME_UUID_LEN);
	printf("\n");
	printf("host.nqn=%s\n", table->host.nqn);
	printf("host.host_id_configured=%d\n", table->host.host_id_configured);
	printf("host.host_nqn_configured=%d\n", table->host.host_nqn_configured);
	printf("host.primary=%d\n", table->host.primary);

	for (hfi = table->hfi_list, i = 0; hfi && *hfi; hfi++, i++) {
		printf("hfi_list[%u]->index=%d\n", i, (*hfi)->index);
		printf("hfi_list[%u]->transport=%.*s\n", i, (int)sizeof((*hfi)->transport), (*hfi)->transport);
		printf("hfi_list[%u]->tcp_info.pci_sbdf=%"PRIu32"\n", i, (*hfi)->tcp_info.pci_sbdf);
		printf("hfi_list[%u]->tcp_info.mac_addr=", i);
		print_hex((*hfi)->tcp_info.mac_addr, sizeof((*hfi)->tcp_info.mac_addr));
		printf("\n");
		printf("hfi_list[%u]->tcp_info.vlan=%"PRIu16"\n", i, (*hfi)->tcp_info.vlan);
		printf("hfi_list[%u]->tcp_info.ip_origin=%u\n", i, (*hfi)->tcp_info.ip_origin);
		printf("hfi_list[%u]->tcp_info.ipaddr=%s\n", i, (*hfi)->tcp_info.ipaddr);
		printf("hfi_list[%u]->tcp_info.subnet_mask_prefix=%u\n", i, (*hfi)->tcp_info.subnet_mask_prefix);
		printf("hfi_list[%u]->tcp_info.gateway_ipaddr=%s\n", i, (*hfi)->tcp_info.gateway_ipaddr);
		printf("hfi_list[%u]->tcp_info.route_metric=%"PRIu16"\n", i, (*hfi)->tcp_info.route_metric);
		printf("hfi_list[%u]->tcp_info.primary_dns_ipaddr=%s\n", i, (*hfi)->tcp_info.primary_dns_ipaddr);
		printf("hfi_list[%u]->tcp_info.secondary_dns_ipaddr=%s\n", i, (*hfi)->tcp_info.secondary_dns_ipaddr);
		printf("hfi_list[%u]->tcp_info.dhcp_server_ipaddr=%s\n", i, (*hfi)->tcp_info.dhcp_server_ipaddr);
		printf("hfi_list[%u]->tcp_info.host_name=%s\n", i, (*hfi)->tcp_info.host_name);
		printf("hfi_list[%u]->tcp_info.this_hfi_is_default_route=%d\n", i, (*hfi)->tcp_info.this_hfi_is_default_route);
		printf("hfi_list[%u]->tcp_info.dhcp_override=%d\n", i, (*hfi)->tcp_info.dhcp_override);
	}

	for (sec = table->security_list, i = 0; sec && *sec; sec++, i++) {
		printf("security_list[%u]->index=%d\n", i, (*sec)->index);
	}

	for (disc = table->discovery_list, i = 0; disc && *disc; disc++, i++) {
		printf("discovery_list[%u]->index=%d\n", i, (*disc)->index);
		if ((*disc)->security)
			printf("discovery_list[%u]->security->index=%d\n", i, (*disc)->security->index);
		if ((*disc)->hfi)
			printf("discovery_list[%u]->hfi->index=%d\n", i, (*disc)->hfi->index);
		printf("discovery_list[%u]->uri=%s\n", i, (*disc)->uri);
		printf("discovery_list[%u]->nqn=%s\n", i, (*disc)->nqn);
	}

	for (ssns = table->subsystem_ns_list, i = 0; ssns && *ssns; ssns++, i++) {
		printf("subsystem_ns_list[%u]->index=%d\n", i, (*ssns)->index);
		if ((*ssns)->discovery)
			printf("subsystem_ns_list[%u]->discovery->index=%d\n", i, (*ssns)->discovery->index);
		if ((*ssns)->security)
			printf("subsystem_ns_list[%u]->security->index=%d\n", i, (*ssns)->security->index);
		printf("subsystem_ns_list[%u]->num_hfis=%d\n", i, (*ssns)->num_hfis);
		for (hfi = (*ssns)->hfis, j = 0; hfi && *hfi; hfi++, j++)
			printf("subsystem_ns_list[%u]->hfis[%u]->index=%d\n", i, j, (*hfi)->index);
		printf("subsystem_ns_list[%u]->transport=%s\n", i, (*ssns)->transport);
		printf("subsystem_ns_list[%u]->traddr=%s\n", i, (*ssns)->traddr);
		printf("subsystem_ns_list[%u]->trsvcid=%s\n", i, (*ssns)->trsvcid);
		printf("subsystem_ns_list[%u]->subsys_port_id=%"PRIu16"\n", i, (*ssns)->subsys_port_id);
		printf("subsystem_ns_list[%u]->nsid=%"PRIu32"\n", i, (*ssns)->nsid);
		printf("subsystem_ns_list[%u]->nid_type=%d\n", i, (*ssns)->nid_type);
		printf("subsystem_ns_list[%u]->nid=", i);
		print_hex((*ssns)->nid, 16);
		printf("\n");
		printf("subsystem_ns_list[%u]->subsys_nqn=%s\n", i, (*ssns)->subsys_nqn);
		printf("subsystem_ns_list[%u]->pdu_header_digest_required=%d\n", i, (*ssns)->pdu_header_digest_required);
		printf("subsystem_ns_list[%u]->data_digest_required=%d\n", i, (*ssns)->data_digest_required);
		printf("subsystem_ns_list[%u]->controller_id=%d\n", i, (*ssns)->controller_id);
		printf("subsystem_ns_list[%u]->asqsz=%d\n", i, (*ssns)->asqsz);
		printf("subsystem_ns_list[%u]->dhcp_root_path_string=%s\n", i, (*ssns)->dhcp_root_path_string);
	}
}

int main(int argc, char **argv)
{
	struct nbft_info *table = NULL;
	
	if (argc < 2) {
		fprintf(stderr, "Usage: %s TABLE\n", argv[0]);
		return 1;
	}

	if (nvme_nbft_read(&table, argv[1]) != 0) {
		fprintf(stderr, "Error parsing the NBFT table %s: %m\n",
			argv[1]);
		return 2;
	}

	print_nbft(table);

	nvme_nbft_free(table);
	return 0;
}
