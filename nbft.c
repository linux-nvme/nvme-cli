// SPDX-License-Identifier: GPL-2.0-or-later

#include <errno.h>
#include <stdio.h>
#include <fnmatch.h>
#include <stdlib.h>

#include <libnvme.h>

#include "nvme.h"
#include "nbft.h"
#include "fabrics.h"
#include "nvme-print.h"

#include "util/types.h"

#define NBFT_SYSFS_FILENAME	"NBFT*"

static void print_connect_msg(nvme_ctrl_t c)
{
	printf("device: %s\n", nvme_ctrl_get_name(c));
}

static void json_connect_msg(nvme_ctrl_t c)
{
#ifdef CONFIG_JSONC
	struct json_object *root;

	root = json_create_object();
	json_object_add_value_string(root, "device", nvme_ctrl_get_name(c));

	json_print_object(root, NULL);
	printf("\n");
	json_free_object(root);
#endif
}

int nbft_filter(const struct dirent *dent)
{
	return !fnmatch(NBFT_SYSFS_FILENAME, dent->d_name, FNM_PATHNAME);
}

int read_nbft_files(struct list_head *nbft_list, char *path)
{
	struct dirent **dent;
	char filename[PATH_MAX];
	int i, count, ret;
	struct nbft_file_entry *entry;
	struct nbft_info *nbft;

	count = scandir(path, &dent, nbft_filter, NULL);
	if (count < 0)
		return -errno;

	for (i = 0; i < count; i++) {
		snprintf(filename, sizeof(filename), "%s/%s", path, dent[i]->d_name);
		ret = nvme_nbft_read(&nbft, filename);
		if (!ret) {
			entry = calloc(1, sizeof(*entry));
			entry->nbft = nbft;
			list_add_tail(nbft_list, &entry->node);
		}
		free(dent[i]);
	}
	free(dent);
	return 0;
}

void free_nbfts(struct list_head *nbft_list)
{
	struct nbft_file_entry *entry;

	while ((entry = list_pop(nbft_list, struct nbft_file_entry, node))) {
		nvme_nbft_free(entry->nbft);
		free(entry);
	}
}

int discover_from_nbft(nvme_root_t r, char *hostnqn_arg, char *hostid_arg,
		       char *hostnqn_sys, char *hostid_sys,
		       const char *desc, bool connect,
		       const struct nvme_fabrics_config *cfg, char *nbft_path,
		       enum nvme_print_flags flags, unsigned int verbose)
{
	char *hostnqn = NULL, *hostid = NULL, *host_traddr = NULL;
	nvme_host_t h;
	nvme_ctrl_t c;
	int ret, i;
	struct list_head nbft_list;
	struct nbft_file_entry *entry = NULL;
	struct nbft_info_subsystem_ns **ss;
	struct nbft_info_hfi *hfi;

	if (!connect)
		/* to do: print discovery-type info from NBFT tables */
		return 0;

	list_head_init(&nbft_list);
	ret = read_nbft_files(&nbft_list, nbft_path);
	if (ret) {
		if (ret != ENOENT)
			nvme_show_perror("Failed to access ACPI tables directory");
		goto out_free_2;
	}

	list_for_each(&nbft_list, entry, node)
		for (ss = entry->nbft->subsystem_ns_list; ss && *ss; ss++)
			for (i = 0; i < (*ss)->num_hfis; i++) {
				nvme_ctrl_t cl;

				hfi = (*ss)->hfis[i];
				if (hostnqn_arg)
					hostnqn = hostnqn_arg;
				else {
					hostnqn = entry->nbft->host.nqn;
					if (!hostnqn)
						hostnqn = hostnqn_sys;
				}

				if (hostid_arg)
					hostid = hostid_arg;
				else if (*entry->nbft->host.id) {
					hostid = (char *)util_uuid_to_string(entry->nbft->host.id);
					if (!hostid)
						hostid = hostid_sys;
				}

				h = nvme_lookup_host(r, hostnqn, hostid);
				if (!h) {
					errno = ENOMEM;
					goto out_free;
				}

				if (!cfg->host_traddr) {
					host_traddr = NULL;
					if (!strncmp((*ss)->transport, "tcp", 3))
						host_traddr = hfi->tcp_info.ipaddr;
				}

				struct tr_config trcfg = {
					.subsysnqn	= (*ss)->subsys_nqn,
					.transport	= (*ss)->transport,
					.traddr		= (*ss)->traddr,
					.host_traddr	= host_traddr,
					.host_iface	= NULL,
					.trsvcid	= (*ss)->trsvcid,
				};

				/* Already connected ? */
				cl = lookup_ctrl(h, &trcfg);
				if (cl && nvme_ctrl_get_name(cl))
					continue;

				c = nvme_create_ctrl(r, (*ss)->subsys_nqn, (*ss)->transport,
						     (*ss)->traddr, host_traddr, NULL,
						     (*ss)->trsvcid);
				if (!c) {
					errno = ENOMEM;
					goto out_free;
				}

				errno = 0;
				ret = nvmf_add_ctrl(h, c, cfg);

				/*
				 * With TCP/DHCP, it can happen that the OS
				 * obtains a different local IP address than the
				 * firmware had. Retry without host_traddr.
				 */
				if (ret == -1 && errno == ENVME_CONNECT_ADDRNOTAVAIL &&
				    !strcmp((*ss)->transport, "tcp") &&
				    strlen(hfi->tcp_info.dhcp_server_ipaddr) > 0) {
					nvme_free_ctrl(c);

					trcfg.host_traddr = NULL;
					cl = lookup_ctrl(h, &trcfg);
					if (cl && nvme_ctrl_get_name(cl))
						continue;

					c = nvme_create_ctrl(r, (*ss)->subsys_nqn, (*ss)->transport,
							     (*ss)->traddr,
							     NULL, NULL, (*ss)->trsvcid);
					if (!c) {
						errno = ENOMEM;
						goto out_free;
					}
					errno = 0;
					ret = nvmf_add_ctrl(h, c, cfg);
					if (ret == 0 && verbose >= 1)
						fprintf(stderr,
							"connect with host_traddr=\"%s\" failed, success after omitting host_traddr\n",
							host_traddr);
				}

				if (ret)
					fprintf(stderr, "no controller found\n");
				else {
					if (flags == NORMAL)
						print_connect_msg(c);
					else if (flags == JSON)
						json_connect_msg(c);
				}
out_free:
				if (errno == ENOMEM)
					goto out_free_2;
			}
out_free_2:
	free_nbfts(&nbft_list);
	return errno;
}
