// SPDX-License-Identifier: GPL-2.0-or-later

#include <errno.h>
#include <stdio.h>
#include <fnmatch.h>
#include <stdlib.h>

#include <libnvme.h>

#include "common.h"
#include "nvme.h"
#include "nbft.h"
#include "fabrics.h"
#include "nvme-print.h"

#include "util/types.h"
#include "logging.h"

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

static bool validate_uri(struct nbft_info_discovery *dd,
			 struct nvme_fabrics_uri *uri)
{
	if (!uri) {
		fprintf(stderr,
			"Discovery Descriptor %d: failed to parse URI %s\n",
			dd->index, dd->uri);
		return false;
	}
	if (strcmp(uri->scheme, "nvme") != 0) {
		fprintf(stderr,
			"Discovery Descriptor %d: unsupported scheme '%s'\n",
			dd->index, uri->scheme);
		return false;
	}
	if (!uri->protocol || strcmp(uri->protocol, "tcp") != 0) {
		fprintf(stderr,
			"Discovery Descriptor %d: unsupported transport '%s'\n",
			dd->index, uri->protocol);
		return false;
	}

	return true;
}

/* returns 0 for success or negative errno otherwise */
static int do_connect(nvme_root_t r,
		      nvme_host_t h,
		      struct nvmf_disc_log_entry *e,
		      struct nbft_info_subsystem_ns *ss,
		      struct tr_config *trcfg,
		      struct nvme_fabrics_config *cfg,
		      nvme_print_flags_t flags,
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

	if (e) {
		if (e->trtype == NVMF_TRTYPE_TCP &&
		    e->tsas.tcp.sectype != NVMF_TCP_SECTYPE_NONE)
			cfg->tls = true;
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

static int do_discover(struct nbft_info_discovery *dd,
		       nvme_root_t r,
		       nvme_host_t h,
		       nvme_ctrl_t c,
		       struct nvme_fabrics_config *defcfg,
		       struct tr_config *deftrcfg,
		       nvme_print_flags_t flags,
		       unsigned int verbose)
{
	struct nvmf_discovery_log *log = NULL;
	int i;
	int ret;

	struct nvme_get_discovery_args args = {
		.c = c,
		.args_size = sizeof(args),
		.max_retries = 10 /* MAX_DISC_RETRIES */,
		.result = 0,
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.lsp = 0,
	};

	log = nvmf_get_discovery_wargs(&args);
	if (!log) {
		fprintf(stderr,
			"Discovery Descriptor %d: failed to get discovery log: %s\n",
			dd->index, nvme_strerror(errno));
		return -errno;
	}

	for (i = 0; i < le64_to_cpu(log->numrec); i++) {
		struct nvmf_disc_log_entry *e = &log->entries[i];
		nvme_ctrl_t cl;
		int tmo = defcfg->keep_alive_tmo;

		struct tr_config trcfg = {
			.subsysnqn	= e->subnqn,
			.transport	= nvmf_trtype_str(e->trtype),
			.traddr		= e->traddr,
			.host_traddr	= deftrcfg->host_traddr,
			.host_iface	= deftrcfg->host_iface,
			.trsvcid	= e->trsvcid,
		};

		if (e->subtype == NVME_NQN_CURR)
			continue;

		/* Already connected ? */
		cl = lookup_ctrl(h, &trcfg);
		if (cl && nvme_ctrl_get_name(cl))
			continue;

		/* Skip connect if the transport types don't match */
		if (strcmp(nvme_ctrl_get_transport(c),
			   nvmf_trtype_str(e->trtype)))
			continue;

		if (e->subtype == NVME_NQN_DISC) {
			nvme_ctrl_t child;

			child = nvmf_connect_disc_entry(h, e, defcfg, NULL);
			do_discover(dd, r, h, child, defcfg, &trcfg,
				    flags, verbose);
			nvme_disconnect_ctrl(child);
			nvme_free_ctrl(child);
		} else {
			ret = do_connect(r, h, e, NULL, &trcfg,
					 defcfg, flags, verbose);

			/*
			 * With TCP/DHCP, it can happen that the OS
			 * obtains a different local IP address than the
			 * firmware had. Retry without host_traddr.
			 */
			if (ret == -ENVME_CONNECT_ADDRNOTAVAIL &&
			    !strcmp(trcfg.transport, "tcp") &&
			    strlen(dd->hfi->tcp_info.dhcp_server_ipaddr) > 0) {
				const char *htradr = trcfg.host_traddr;

				trcfg.host_traddr = NULL;
				ret = do_connect(r, h, e, NULL, &trcfg,
						 defcfg, flags, verbose);

				if (ret == 0 && verbose >= 1)
					fprintf(stderr,
						"Discovery Descriptor %d: connect with host_traddr=\"%s\" failed, success after omitting host_traddr\n",
						dd->index,
						htradr);
			}

			if (ret)
				fprintf(stderr, "Discovery Descriptor %d: no controller found\n",
					dd->index);
			if (ret == -ENOMEM)
				break;
		}

		defcfg->keep_alive_tmo = tmo;
	}

	free(log);
	return 0;
}

/* returns negative errno values */
int discover_from_nbft(nvme_root_t r, char *hostnqn_arg, char *hostid_arg,
		       char *hostnqn_sys, char *hostid_sys,
		       const char *desc, bool connect,
		       struct nvme_fabrics_config *cfg, char *nbft_path,
		       nvme_print_flags_t flags, unsigned int verbose)
{
	char *hostnqn = NULL, *hostid = NULL, *host_traddr = NULL;
	nvme_host_t h;
	int ret, rr, i;
	struct list_head nbft_list;
	struct nbft_file_entry *entry = NULL;
	struct nbft_info_subsystem_ns **ss;
	struct nbft_info_hfi *hfi;
	struct nbft_info_discovery **dd;

	if (!connect)
		/* TODO: print discovery-type info from NBFT tables */
		return 0;

	list_head_init(&nbft_list);
	ret = read_nbft_files(&nbft_list, nbft_path);
	if (ret) {
		if (ret != -ENOENT)
			nvme_show_perror("Failed to access ACPI tables directory");
		else
			ret = 0;  /* nothing to connect */
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
		if (!h) {
			ret = -ENOENT;
			goto out_free;
		}

		/* Subsystem Namespace Descriptor List */
		for (ss = entry->nbft->subsystem_ns_list; ss && *ss; ss++)
			for (i = 0; i < (*ss)->num_hfis; i++) {
				hfi = (*ss)->hfis[i];

				/* Skip discovery NQN records */
				if (strcmp((*ss)->subsys_nqn, NVME_DISC_SUBSYS_NAME) == 0) {
					if (verbose >= 1)
						fprintf(stderr,
							"SSNS %d points to well-known discovery NQN, skipping\n",
							(*ss)->index);
					continue;
				}

				host_traddr = NULL;
				if (!cfg->host_traddr &&
				    !strncmp((*ss)->transport, "tcp", 3))
					host_traddr = hfi->tcp_info.ipaddr;

				struct tr_config trcfg = {
					.subsysnqn	= (*ss)->subsys_nqn,
					.transport	= (*ss)->transport,
					.traddr		= (*ss)->traddr,
					.host_traddr	= host_traddr,
					.host_iface	= NULL,
					.trsvcid	= (*ss)->trsvcid,
				};

				rr = do_connect(r, h, NULL, *ss, &trcfg,
						cfg, flags, verbose);

				/*
				 * With TCP/DHCP, it can happen that the OS
				 * obtains a different local IP address than the
				 * firmware had. Retry without host_traddr.
				 */
				if (rr == -ENVME_CONNECT_ADDRNOTAVAIL &&
				    !strcmp(trcfg.transport, "tcp") &&
				    strlen(hfi->tcp_info.dhcp_server_ipaddr) > 0) {
					trcfg.host_traddr = NULL;

					rr = do_connect(r, h, NULL, *ss, &trcfg,
							cfg, flags, verbose);

					if (rr == 0 && verbose >= 1)
						fprintf(stderr,
							"SSNS %d: connect with host_traddr=\"%s\" failed, success after omitting host_traddr\n",
							(*ss)->index,
							host_traddr);
				}

				if (rr) {
					fprintf(stderr, "SSNS %d: no controller found\n",
						(*ss)->index);
					/* report an error */
					ret = rr;
				}

				if (rr == -ENOMEM)
					goto out_free;
			}

		/* Discovery Descriptor List */
		for (dd = entry->nbft->discovery_list; dd && *dd; dd++) {
			nvme_ctrl_t c;
			bool linked = false;
			bool persistent = false;
			_cleanup_uri_ struct nvme_fabrics_uri *uri = NULL;
			_cleanup_free_ char *trsvcid = NULL;

			/* only perform discovery when no SSNS record references it */
			for (ss = entry->nbft->subsystem_ns_list; ss && *ss; ss++)
				if ((*ss)->discovery &&
				    (*ss)->discovery->index == (*dd)->index &&
				    /* unavailable boot attempts are not discovered
				     * and may get transferred along with a well-known
				     * discovery NQN into an SSNS record.
				     */
				    strcmp((*ss)->subsys_nqn, NVME_DISC_SUBSYS_NAME) != 0) {
					linked = true;
					break;
				}
			if (linked)
				continue;

			hfi = (*dd)->hfi;
			uri = nvme_parse_uri((*dd)->uri);
			if (!validate_uri(*dd, uri))
				continue;

			host_traddr = NULL;
			if (!cfg->host_traddr &&
			    !strncmp(uri->protocol, "tcp", 3))
				host_traddr = hfi->tcp_info.ipaddr;
			if (uri->port > 0) {
				if (asprintf(&trsvcid, "%d", uri->port) < 0) {
					ret = -ENOMEM;
					goto out_free;
				}
			} else
				trsvcid = strdup(nvmf_get_default_trsvcid(uri->protocol, true));

			struct tr_config trcfg = {
				.subsysnqn	= NVME_DISC_SUBSYS_NAME,
				.transport	= uri->protocol,
				.traddr		= uri->host,
				.host_traddr	= host_traddr,
				.host_iface	= NULL,
				.trsvcid	= trsvcid,
			};

			/* Lookup existing discovery controller */
			c = lookup_ctrl(h, &trcfg);
			if (c && nvme_ctrl_get_name(c))
				persistent = true;

			if (!c) {
				c = nvmf_create_discover_ctrl(r, h, cfg, &trcfg);
				if (!c && errno == ENVME_CONNECT_ADDRNOTAVAIL &&
				    !strcmp(trcfg.transport, "tcp") &&
				    strlen(hfi->tcp_info.dhcp_server_ipaddr) > 0) {
					trcfg.host_traddr = NULL;
					c = nvmf_create_discover_ctrl(r, h, cfg, &trcfg);
				}
			}

			if (!c) {
				fprintf(stderr,
					"Discovery Descriptor %d: failed to add discovery controller: %s\n",
					(*dd)->index,
					nvme_strerror(errno));
				if (errno == ENOMEM) {
					ret = -ENOMEM;
					goto out_free;
				}
				continue;
			}

			rr = do_discover(*dd, r, h, c, cfg, &trcfg,
					 flags, verbose);
			if (!persistent)
				nvme_disconnect_ctrl(c);
			nvme_free_ctrl(c);
			if (rr == -ENOMEM) {
				ret = rr;
				goto out_free;
			}
		}
	}
out_free:
	free_nbfts(&nbft_list);
	return ret;
}
