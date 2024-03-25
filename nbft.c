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
#include "util/logging.h"

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

/* returns 0 for success or negative errno otherwise */
static int do_connect(nvme_root_t r,
		      nvme_host_t h,
		      struct nbft_info_subsystem_ns *ss,
		      struct tr_config *trcfg,
		      const struct nvme_fabrics_config *cfg,
		      enum nvme_print_flags flags,
		      unsigned int verbose)
{
	nvme_ctrl_t c;
	int saved_log_level = log_level;
	bool saved_log_pid = false;
	bool saved_log_tstamp = false;
	int ret;

	/* Already connected ? */
	c = lookup_ctrl(h, trcfg);
	if (c && nvme_ctrl_get_name(c))
		return 0;

	c = nvme_create_ctrl(r, trcfg->subsysnqn, trcfg->transport,
			     trcfg->traddr, trcfg->host_traddr,
			     trcfg->host_iface, trcfg->trsvcid);
	if (!c)
		return -ENOMEM;

	/* Pause logging for unavailable SSNSs */
	if (ss && ss->unavailable && verbose < 1) {
		saved_log_level = nvme_get_logging_level(r,
							 &saved_log_pid,
							 &saved_log_tstamp);
		nvme_init_logging(r, -1, false, false);
	}

	errno = 0;
	ret = nvmf_add_ctrl(h, c, cfg);

	/* Resume logging */
	if (ss && ss->unavailable && verbose < 1)
		nvme_init_logging(r,
				  saved_log_level,
				  saved_log_pid,
				  saved_log_tstamp);

	if (ret == -1) {
		nvme_free_ctrl(c);
		/*
		 * In case this SSNS was marked as 'unavailable' and
		 * our connection attempt has failed, ignore it.
		 */
		if (ss && ss->unavailable) {
			if (verbose >= 1)
				fprintf(stderr,
					"SSNS %d reported as unavailable, skipping\n",
					ss->index);
			return 0;
		}
		return -errno;
	}

	if (flags == NORMAL)
		print_connect_msg(c);
	else if (flags == JSON)
		json_connect_msg(c);

	return 0;
}

int discover_from_nbft(nvme_root_t r, char *hostnqn_arg, char *hostid_arg,
		       char *hostnqn_sys, char *hostid_sys,
		       const char *desc, bool connect,
		       const struct nvme_fabrics_config *cfg, char *nbft_path,
		       enum nvme_print_flags flags, unsigned int verbose)
{
	char *hostnqn = NULL, *hostid = NULL, *host_traddr = NULL;
	nvme_host_t h;
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
		goto out_free;
	}

	list_for_each(&nbft_list, entry, node) {
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
		if (!h)
			goto out_free;

		for (ss = entry->nbft->subsystem_ns_list; ss && *ss; ss++)
			for (i = 0; i < (*ss)->num_hfis; i++) {
				hfi = (*ss)->hfis[i];

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

				ret = do_connect(r, h, *ss, &trcfg,
						 cfg, flags, verbose);

				/*
				 * With TCP/DHCP, it can happen that the OS
				 * obtains a different local IP address than the
				 * firmware had. Retry without host_traddr.
				 */
				if (ret == -ENVME_CONNECT_ADDRNOTAVAIL &&
				    !strcmp((*ss)->transport, "tcp") &&
				    strlen(hfi->tcp_info.dhcp_server_ipaddr) > 0) {
					trcfg.host_traddr = NULL;

					ret = do_connect(r, h, *ss, &trcfg,
							 cfg, flags, verbose);

					if (ret == 0 && verbose >= 1)
						fprintf(stderr,
							"SSNS %d: connect with host_traddr=\"%s\" failed, success after omitting host_traddr\n",
							(*ss)->index,
							host_traddr);
				}

				if (ret)
					fprintf(stderr, "SSNS %d: no controller found\n",
						(*ss)->index);

				if (ret == -ENOMEM)
					goto out_free;
			}
	}
out_free:
	free_nbfts(&nbft_list);
	return errno;
}
