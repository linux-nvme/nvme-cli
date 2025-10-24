// SPDX-License-Identifier: GPL-2.0-or-later

#include <errno.h>
#include <stdio.h>
#include <fnmatch.h>

#include <libnvme.h>
#include "nvme-print.h"
#include "nvme.h"
#include "nbft.h"
#include "fabrics.h"
#include "logging.h"

#define CREATE_CMD
#include "nbft-plugin.h"

static const char dash[100] = {[0 ... 98] = '-', [99] = '\0'};

#define PCI_SEGMENT(sbdf) ((sbdf & 0xffff0000) >> 16)
#define PCI_BUS(sbdf) ((sbdf & 0x0000ff00) >> 8)
#define PCI_DEV(sbdf) ((sbdf & 0x000000f8) >> 3)
#define PCI_FUNC(sbdf) ((sbdf & 0x00000007) >> 0)

static const char *pci_sbdf_to_string(__u16 pci_sbdf)
{
	static char pcidev[13];

	snprintf(pcidev, sizeof(pcidev), "%x:%x:%x.%x",
		 PCI_SEGMENT(pci_sbdf),
		 PCI_BUS(pci_sbdf),
		 PCI_DEV(pci_sbdf),
		 PCI_FUNC(pci_sbdf));
	return pcidev;
}

static char *mac_addr_to_string(unsigned char mac_addr[6])
{
	static char mac_string[18];

	snprintf(mac_string, sizeof(mac_string), "%02x:%02x:%02x:%02x:%02x:%02x",
		 mac_addr[0],
		 mac_addr[1],
		 mac_addr[2],
		 mac_addr[3],
		 mac_addr[4],
		 mac_addr[5]);
	return mac_string;
}

#ifdef CONFIG_JSONC
static json_object *hfi_to_json(struct nbft_info_hfi *hfi)
{
	struct json_object *hfi_json;

	hfi_json = json_create_object();
	if (!hfi_json)
		return NULL;

	if (json_object_add_value_int(hfi_json, "index", hfi->index)
	    || json_object_add_value_string(hfi_json, "transport", hfi->transport))
		goto fail;

	if (strcmp(hfi->transport, "tcp") == 0) {
		if (json_object_add_value_string(hfi_json, "pcidev",
						 pci_sbdf_to_string(hfi->tcp_info.pci_sbdf))
		    || json_object_add_value_string(hfi_json, "mac_addr",
						    mac_addr_to_string(hfi->tcp_info.mac_addr))
		    || json_object_add_value_int(hfi_json, "vlan",
						 hfi->tcp_info.vlan)
		    || json_object_add_value_int(hfi_json, "ip_origin",
						 hfi->tcp_info.ip_origin)
		    || json_object_add_value_string(hfi_json, "ipaddr",
						    hfi->tcp_info.ipaddr)
		    || json_object_add_value_int(hfi_json, "subnet_mask_prefix",
						 hfi->tcp_info.subnet_mask_prefix)
		    || json_object_add_value_string(hfi_json, "gateway_ipaddr",
						    hfi->tcp_info.gateway_ipaddr)
		    || json_object_add_value_int(hfi_json, "route_metric",
						 hfi->tcp_info.route_metric)
		    || json_object_add_value_string(hfi_json, "primary_dns_ipaddr",
						    hfi->tcp_info.primary_dns_ipaddr)
		    || json_object_add_value_string(hfi_json, "secondary_dns_ipaddr",
						    hfi->tcp_info.secondary_dns_ipaddr)
		    || json_object_add_value_string(hfi_json, "dhcp_server_ipaddr",
						    hfi->tcp_info.dhcp_server_ipaddr)
		    || (hfi->tcp_info.host_name
			&& json_object_add_value_string(hfi_json, "host_name",
							hfi->tcp_info.host_name))
		    || json_object_add_value_int(hfi_json, "this_hfi_is_default_route",
						 hfi->tcp_info.this_hfi_is_default_route)
		    || json_object_add_value_int(hfi_json, "dhcp_override",
						 hfi->tcp_info.dhcp_override))
			goto fail;
		else
			return hfi_json;
	}
fail:
	json_free_object(hfi_json);
	return NULL;
}

static json_object *ssns_to_json(struct nbft_info_subsystem_ns *ss)
{
	struct json_object *ss_json;
	struct json_object *hfi_array_json;
	char json_str[40];
	char *json_str_p;
	int i;

	ss_json = json_create_object();
	if (!ss_json)
		return NULL;

	hfi_array_json = json_create_array();
	if (!hfi_array_json)
		goto fail;

	for (i = 0; i < ss->num_hfis; i++)
		if (json_array_add_value_object(hfi_array_json,
						json_object_new_int(ss->hfis[i]->index)))
			goto fail;

	if (json_object_add_value_int(ss_json, "index", ss->index)
	    || json_object_add_value_int(ss_json, "num_hfis", ss->num_hfis)
	    || json_object_object_add(ss_json, "hfis", hfi_array_json)
	    || json_object_add_value_string(ss_json, "transport", ss->transport)
	    || json_object_add_value_string(ss_json, "traddr", ss->traddr)
	    || json_object_add_value_string(ss_json, "trsvcid", ss->trsvcid)
	    || json_object_add_value_int(ss_json, "subsys_port_id", ss->subsys_port_id)
	    || json_object_add_value_int(ss_json, "nsid", ss->nsid))
		goto fail;

	memset(json_str, 0, sizeof(json_str));
	json_str_p = json_str;

	switch (ss->nid_type) {
	case NBFT_INFO_NID_TYPE_EUI64:
		if (json_object_add_value_string(ss_json, "nid_type", "eui64"))
			goto fail;
		for (i = 0; i < 8; i++)
			json_str_p += sprintf(json_str_p, "%02x", ss->nid[i]);
		break;

	case NBFT_INFO_NID_TYPE_NGUID:
		if (json_object_add_value_string(ss_json, "nid_type", "nguid"))
			goto fail;
		for (i = 0; i < 16; i++)
			json_str_p += sprintf(json_str_p, "%02x", ss->nid[i]);
		break;

	case NBFT_INFO_NID_TYPE_NS_UUID:
		if (json_object_add_value_string(ss_json, "nid_type", "uuid"))
			goto fail;
		nvme_uuid_to_string(ss->nid, json_str);
		break;

	default:
		break;
	}
	if (json_object_add_value_string(ss_json, "nid", json_str))
		goto fail;

	if ((ss->subsys_nqn
	     && json_object_add_value_string(ss_json, "subsys_nqn", ss->subsys_nqn))
	    || json_object_add_value_int(ss_json, "controller_id", ss->controller_id)
	    || json_object_add_value_int(ss_json, "asqsz", ss->asqsz)
	    || (ss->dhcp_root_path_string
		&& json_object_add_value_string(ss_json, "dhcp_root_path_string",
						ss->dhcp_root_path_string))
	    || json_object_add_value_int(ss_json, "pdu_header_digest_required",
					 ss->pdu_header_digest_required)
	    || json_object_add_value_int(ss_json, "data_digest_required",
					 ss->data_digest_required)
	    || json_object_add_value_int(ss_json, "discovered",
					 ss->discovered)
	    || json_object_add_value_int(ss_json, "unavailable",
					 ss->unavailable))
		goto fail;

	return ss_json;
fail:
	json_free_object(ss_json);
	return NULL;
}

static json_object *discovery_to_json(struct nbft_info_discovery *disc)
{
	struct json_object *disc_json;

	disc_json = json_create_object();
	if (!disc_json)
		return NULL;

	if (json_object_add_value_int(disc_json, "index", disc->index)
	    || (disc->security
		&& json_object_add_value_int(disc_json, "security", disc->security->index))
	    || (disc->hfi
		&& json_object_add_value_int(disc_json, "hfi", disc->hfi->index))
	    || (disc->uri
		&& json_object_add_value_string(disc_json, "uri", disc->uri))
	    || (disc->nqn
		&& json_object_add_value_string(disc_json, "nqn", disc->nqn))) {
		json_free_object(disc_json);
		return NULL;
	} else
		return disc_json;
}

static const char *primary_admin_host_flag_to_str(unsigned int primary)
{
	static const char * const str[] = {
		[NBFT_INFO_PRIMARY_ADMIN_HOST_FLAG_NOT_INDICATED] =	"not indicated",
		[NBFT_INFO_PRIMARY_ADMIN_HOST_FLAG_UNSELECTED] =	"unselected",
		[NBFT_INFO_PRIMARY_ADMIN_HOST_FLAG_SELECTED] =		"selected",
		[NBFT_INFO_PRIMARY_ADMIN_HOST_FLAG_RESERVED] =		"reserved",
	};

	if (primary > NBFT_INFO_PRIMARY_ADMIN_HOST_FLAG_RESERVED)
		return "INVALID";
	return str[primary];
}

static struct json_object *nbft_to_json(struct nbft_info *nbft, bool show_subsys,
					bool show_hfi, bool show_discovery)
{
	struct json_object *nbft_json, *host_json;

	nbft_json = json_create_object();
	if (!nbft_json)
		return NULL;

	if (json_object_add_value_string(nbft_json, "filename", nbft->filename))
		goto fail;

	host_json = json_create_object();
	if (!host_json)
		goto fail;
	if ((nbft->host.nqn
	     && json_object_add_value_string(host_json, "nqn", nbft->host.nqn))
	    || (nbft->host.id
		&& json_object_add_value_string(host_json, "id",
						util_uuid_to_string(nbft->host.id))))
		goto fail;
	json_object_add_value_int(host_json, "host_id_configured",
				  nbft->host.host_id_configured);
	json_object_add_value_int(host_json, "host_nqn_configured",
				  nbft->host.host_nqn_configured);
	json_object_add_value_string(host_json, "primary_admin_host_flag",
				     primary_admin_host_flag_to_str(nbft->host.primary));
	if (json_object_object_add(nbft_json, "host", host_json)) {
		json_free_object(host_json);
		goto fail;
	}

	if (show_subsys) {
		struct json_object *subsys_array_json, *subsys_json;
		struct nbft_info_subsystem_ns **ss;

		subsys_array_json = json_create_array();
		if (!subsys_array_json)
			goto fail;
		for (ss = nbft->subsystem_ns_list; ss && *ss; ss++) {
			subsys_json = ssns_to_json(*ss);
			if (!subsys_json)
				goto fail;
			if (json_object_array_add(subsys_array_json, subsys_json)) {
				json_free_object(subsys_json);
				goto fail;
			}
		}
		if (json_object_object_add(nbft_json, "subsystem", subsys_array_json)) {
			json_free_object(subsys_array_json);
			goto fail;
		}
	}
	if (show_hfi) {
		struct json_object *hfi_array_json, *hfi_json;
		struct nbft_info_hfi **hfi;

		hfi_array_json = json_create_array();
		if (!hfi_array_json)
			goto fail;
		for (hfi = nbft->hfi_list; hfi && *hfi; hfi++) {
			hfi_json = hfi_to_json(*hfi);
			if (!hfi_json)
				goto fail;
			if (json_object_array_add(hfi_array_json, hfi_json)) {
				json_free_object(hfi_json);
				goto fail;
			}
		}
		if (json_object_object_add(nbft_json, "hfi", hfi_array_json)) {
			json_free_object(hfi_array_json);
			goto fail;
		}
	}
	if (show_discovery) {
		struct json_object *discovery_array_json, *discovery_json;
		struct nbft_info_discovery **disc;

		discovery_array_json = json_create_array();
		if (!discovery_array_json)
			goto fail;
		for (disc = nbft->discovery_list; disc && *disc; disc++) {
			discovery_json = discovery_to_json(*disc);
			if (!discovery_json)
				goto fail;
			if (json_object_array_add(discovery_array_json, discovery_json)) {
				json_free_object(discovery_json);
				goto fail;
			}
		}
		if (json_object_object_add(nbft_json, "discovery", discovery_array_json)) {
			json_free_object(discovery_array_json);
			goto fail;
		}
	}
	return nbft_json;
fail:
	json_free_object(nbft_json);
	return NULL;
}

static int json_show_nbfts(struct list_head *nbft_list, bool show_subsys,
			   bool show_hfi, bool show_discovery)
{
	struct json_object *nbft_json_array, *nbft_json;
	struct nbft_file_entry *entry = NULL;

	nbft_json_array = json_create_array();
	if (!nbft_json_array)
		return -ENOMEM;

	list_for_each(nbft_list, entry, node) {
		nbft_json = nbft_to_json(entry->nbft, show_subsys, show_hfi, show_discovery);
		if (!nbft_json)
			goto fail;
		if (json_object_array_add(nbft_json_array, nbft_json)) {
			json_free_object(nbft_json);
			goto fail;
		}
	}

	json_print_object(nbft_json_array, NULL);
	printf("\n");
	json_free_object(nbft_json_array);
	return 0;
fail:
	json_free_object(nbft_json_array);
	return -ENOMEM;
}
#else /* CONFIG_JSONC */
#define json_show_nbfts(nbft_list, show_subsys, show_hfi, show_discovery) -EINVAL
#endif /* CONFIG_JSONC */

static void print_nbft_hfi_info(struct nbft_info *nbft)
{
	struct nbft_info_hfi **hfi;
	unsigned int ip_width = 8, gw_width = 8, dns_width = 8;

	hfi = nbft->hfi_list;
	if (!hfi || !*hfi)
		return;

	for (; *hfi; hfi++) {
		unsigned int len;

		len = strlen((*hfi)->tcp_info.ipaddr);
		if (len > ip_width)
			ip_width = len;
		len = strlen((*hfi)->tcp_info.gateway_ipaddr);
		if (len > gw_width)
			gw_width = len;
		len = strlen((*hfi)->tcp_info.primary_dns_ipaddr);
		if (len > dns_width)
			dns_width = len;
	}

	printf("\nNBFT HFIs:\n\n");
	printf("%-3.3s|%-4.4s|%-10.10s|%-17.17s|%-4.4s|%-*.*s|%-4.4s|%-*.*s|%-*.*s\n",
	       "Idx", "Trsp", "PCI Addr", "MAC Addr", "DHCP",
	       ip_width, ip_width, "IP Addr", "Mask",
	       gw_width, gw_width, "Gateway", dns_width, dns_width, "DNS");
	printf("%-.3s+%-.4s+%-.10s+%-.17s+%-.4s+%-.*s+%-.4s+%-.*s+%-.*s\n",
	       dash, dash, dash, dash, dash, ip_width, dash, dash,
	       gw_width, dash, dns_width, dash);
	for (hfi = nbft->hfi_list; *hfi; hfi++)
		printf("%-3d|%-4.4s|%-10.10s|%-17.17s|%-4.4s|%-*.*s|%-4d|%-*.*s|%-*.*s\n",
		       (*hfi)->index,
		       (*hfi)->transport,
		       pci_sbdf_to_string((*hfi)->tcp_info.pci_sbdf),
		       mac_addr_to_string((*hfi)->tcp_info.mac_addr),
		       (*hfi)->tcp_info.dhcp_override ? "yes" : "no",
		       ip_width, ip_width, (*hfi)->tcp_info.ipaddr,
		       (*hfi)->tcp_info.subnet_mask_prefix,
		       gw_width, gw_width, (*hfi)->tcp_info.gateway_ipaddr,
		       dns_width, dns_width, (*hfi)->tcp_info.primary_dns_ipaddr);
}

static void print_nbft_discovery_info(struct nbft_info *nbft)
{
	struct nbft_info_discovery **disc;
	unsigned int nqn_width = 20, uri_width = 12;

	disc = nbft->discovery_list;
	if (!disc || !*disc)
		return;

	for (; *disc; disc++) {
		size_t len;

		len = strlen((*disc)->uri);
		if (len > uri_width)
			uri_width = len;
		len = strlen((*disc)->nqn);
		if (len > nqn_width)
			nqn_width = len;
	}

	printf("\nNBFT Discovery Controllers:\n\n");
	printf("%-3.3s|%-*.*s|%-*.*s\n", "Idx", uri_width, uri_width, "URI",
	       nqn_width, nqn_width, "NQN");
	printf("%-.3s+%-.*s+%-.*s\n", dash, uri_width, dash, nqn_width, dash);
	for (disc = nbft->discovery_list; *disc; disc++)
		printf("%-3d|%-*.*s|%-*.*s\n", (*disc)->index,
		       uri_width, uri_width, (*disc)->uri,
		       nqn_width, nqn_width, (*disc)->nqn);
}

#define HFIS_LEN 20
static size_t print_hfis(const struct nbft_info_subsystem_ns *ss, char buf[HFIS_LEN])
{
	char hfi_buf[HFIS_LEN];
	size_t len, ofs;
	int i;

	len = snprintf(hfi_buf, sizeof(hfi_buf), "%d", ss->hfis[0]->index);
	for (i = 1; i < ss->num_hfis; i++) {
		ofs = len;
		len += snprintf(hfi_buf + ofs, sizeof(hfi_buf) - ofs, ",%d",
				ss->hfis[i]->index);
		/*
		 * If the list doesn't fit in HFIS_LEN characters,
		 * truncate and end with "..."
		 */
		if (len >= sizeof(hfi_buf)) {
			while (ofs < sizeof(hfi_buf) - 1)
				hfi_buf[ofs++] = '.';
			hfi_buf[ofs] = '\0';
			len = sizeof(hfi_buf) - 1;
			break;
		}
	}
	if (buf)
		memcpy(buf, hfi_buf, len + 1);
	return len;
}


static void print_nbft_subsys_info(struct nbft_info *nbft)
{
	struct nbft_info_subsystem_ns **ss;
	unsigned int nqn_width = 20, adr_width = 8, hfi_width = 4;

	ss = nbft->subsystem_ns_list;
	if (!ss || !*ss)
		return;
	for (; *ss; ss++) {
		size_t len;

		len = strlen((*ss)->subsys_nqn);
		if (len > nqn_width)
			nqn_width = len;
		len = strlen((*ss)->traddr);
		if (len > adr_width)
			adr_width = len;
		len = print_hfis(*ss, NULL);
		if (len > hfi_width)
			hfi_width = len;
	}

	printf("\nNBFT Subsystems:\n\n");
	printf("%-3.3s|%-*.*s|%-4.4s|%-*.*s|%-5.5s|%-*.*s\n",
	       "Idx", nqn_width, nqn_width, "NQN",
	       "Trsp", adr_width, adr_width, "Address", "SvcId", hfi_width, hfi_width, "HFIs");
	printf("%-.3s+%-.*s+%-.4s+%-.*s+%-.5s+%-.*s\n",
	       dash, nqn_width, dash, dash, adr_width, dash, dash, hfi_width, dash);
	for (ss = nbft->subsystem_ns_list; *ss; ss++) {
		char hfi_buf[HFIS_LEN];

		print_hfis(*ss, hfi_buf);
		printf("%-3d|%-*.*s|%-4.4s|%-*.*s|%-5.5s|%-*.*s\n",
		       (*ss)->index, nqn_width, nqn_width, (*ss)->subsys_nqn,
		       (*ss)->transport, adr_width, adr_width, (*ss)->traddr,
		       (*ss)->trsvcid, hfi_width, hfi_width, hfi_buf);
	}
}

static void normal_show_nbft(struct nbft_info *nbft, bool show_subsys,
			     bool show_hfi, bool show_discovery)
{
	printf("%s:\n", nbft->filename);
	if ((!nbft->hfi_list || !*nbft->hfi_list) &&
	    (!nbft->security_list || !*nbft->security_list) &&
	    (!nbft->discovery_list || !*nbft->discovery_list) &&
	    (!nbft->subsystem_ns_list || !*nbft->subsystem_ns_list))
		printf("(empty)\n");
	else {
		if (show_subsys)
			print_nbft_subsys_info(nbft);
		if (show_hfi)
			print_nbft_hfi_info(nbft);
		if (show_discovery)
			print_nbft_discovery_info(nbft);
	}
}

static void normal_show_nbfts(struct list_head *nbft_list, bool show_subsys,
			      bool show_hfi, bool show_discovery)
{
	bool not_first = false;
	struct nbft_file_entry *entry = NULL;

	list_for_each(nbft_list, entry, node) {
		if (not_first)
			printf("\n");
		normal_show_nbft(entry->nbft, show_subsys, show_hfi, show_discovery);
		not_first = true;
	}
}

int show_nbft(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Display contents of the ACPI NBFT files.";
	struct list_head nbft_list;
	char *format = "normal";
	char *nbft_path = NBFT_SYSFS_PATH;
	nvme_print_flags_t flags;
	int ret;
	bool show_subsys = false, show_hfi = false, show_discovery = false;
	unsigned int verbose = 0;

	OPT_ARGS(opts) = {
		OPT_FMT("output-format", 'o', &format, "Output format: normal|json"),
		OPT_FLAG("subsystem", 's', &show_subsys, "show NBFT subsystems"),
		OPT_FLAG("hfi", 'H', &show_hfi, "show NBFT HFIs"),
		OPT_FLAG("discovery", 'd', &show_discovery, "show NBFT discovery controllers"),
		OPT_STRING("nbft-path", 0, "STR", &nbft_path, "user-defined path for NBFT tables"),
		OPT_INCR("verbose", 'v', &verbose, "Increase logging verbosity"),
		OPT_END()
	};

	ret = argconfig_parse(argc, argv, desc, opts);
	if (ret)
		return ret;

	log_level = map_log_level(verbose, false /* quiet */);
	nvme_init_default_logging(stderr, log_level, false, false);

	ret = validate_output_format(format, &flags);
	if (ret < 0)
		return ret;

	if (!(show_subsys || show_hfi || show_discovery))
		show_subsys = show_hfi = show_discovery = true;

	list_head_init(&nbft_list);
	ret = read_nbft_files(&nbft_list, nbft_path);
	if (!ret) {
		if (flags == NORMAL)
			normal_show_nbfts(&nbft_list, show_subsys, show_hfi, show_discovery);
		else if (flags == JSON)
			ret = json_show_nbfts(&nbft_list, show_subsys, show_hfi, show_discovery);
		free_nbfts(&nbft_list);
	}
	return ret;
}
