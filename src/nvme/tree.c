// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2020 Western Digital Corporation or its affiliates.
 *
 * Authors: Keith Busch <keith.busch@wdc.com>
 * 	    Chaitanya Kulkarni <chaitanya.kulkarni@wdc.com>
 */
#include <dirent.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <libgen.h>
#include <unistd.h>
#include <ifaddrs.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <ccan/endian/endian.h>
#include <ccan/list/list.h>

#include "cleanup.h"
#include "ioctl.h"
#include "linux.h"
#include "filters.h"
#include "tree.h"
#include "filters.h"
#include "util.h"
#include "fabrics.h"
#include "log.h"
#include "private.h"

/**
 * struct candidate_args - Used to look for a controller matching these parameters
 * @transport:		Transport type: loop, fc, rdma, tcp
 * @traddr:		Transport address (destination address)
 * @trsvcid:		Transport service ID
 * @subsysnqn:		Subsystem NQN
 * @host_traddr:	Host transport address (source address)
 * @host_iface:		Host interface for connection (tcp only)
 * @iface_list:		Interface list (tcp only)
 * @addreq:		Address comparison function (for traddr, host-traddr)
 * @well_known_nqn:	Set to "true" when @subsysnqn is the well-known NQN
 */
struct candidate_args {
	const char *transport;
	const char *traddr;
	const char *trsvcid;
	const char *subsysnqn;
	const char *host_traddr;
	const char *host_iface;
	struct ifaddrs *iface_list;
	bool (*addreq)(const char *, const char *);
	bool well_known_nqn;
};
typedef bool (*ctrl_match_t)(struct nvme_ctrl *c, struct candidate_args *candidate);

static struct nvme_host *default_host;

static void __nvme_free_host(nvme_host_t h);
static void __nvme_free_ctrl(nvme_ctrl_t c);
static int nvme_subsystem_scan_namespace(nvme_root_t r,
		struct nvme_subsystem *s, char *name,
		nvme_scan_filter_t f, void *f_args);
static int nvme_init_subsystem(nvme_subsystem_t s, const char *name);
static int nvme_scan_subsystem(nvme_root_t r, const char *name,
			       nvme_scan_filter_t f, void *f_args);
static int nvme_ctrl_scan_namespace(nvme_root_t r, struct nvme_ctrl *c,
				    char *name);
static int nvme_ctrl_scan_path(nvme_root_t r, struct nvme_ctrl *c, char *name);

/**
 * Compare two C strings and handle NULL pointers gracefully.
 * Return true if both pointers are equal (including both set to NULL).
 * Return false if one and only one of the two pointers is NULL.
 * Perform string comparisong only if both pointers are not NULL and
 * return true if both strings are the same, false otherwise.
 */
static bool streq0(const char *s1, const char *s2)
{
	if (s1 == s2)
		return true;
	if (!s1 || !s2)
		return false;
	return !strcmp(s1, s2);
}

/**
 * Same as streq0() but ignore the case of the characters.
 */
static bool streqcase0(const char *s1, const char *s2)
{
	if (s1 == s2)
		return true;
	if (!s1 || !s2)
		return false;
	return !strcasecmp(s1, s2);
}

struct dirents {
	struct dirent **ents;
	int num;
};

static void cleanup_dirents(struct dirents *ents)
{
	while (ents->num > 0)
		free(ents->ents[--ents->num]);
	free(ents->ents);
}

#define _cleanup_dirents_ __cleanup__(cleanup_dirents)

static char *nvme_hostid_from_hostnqn(const char *hostnqn)
{
	const char *uuid;

	uuid = strstr(hostnqn, "uuid:");
	if (!uuid)
		return NULL;

	return strdup(uuid + strlen("uuid:"));
}

int nvme_host_get_ids(nvme_root_t r,
		      char *hostnqn_arg, char *hostid_arg,
		      char **hostnqn, char **hostid)
{
	_cleanup_free_ char *nqn = NULL;
	_cleanup_free_ char *hid = NULL;
	_cleanup_free_ char *hnqn = NULL;
	nvme_host_t h;

	/* command line argumments */
	if (hostid_arg)
		hid = strdup(hostid_arg);
	if (hostnqn_arg)
		hnqn = strdup(hostnqn_arg);

	/* JSON config: assume the first entry is the default host */
	h = nvme_first_host(r);
	if (h) {
		if (!hid)
			hid = strdup(nvme_host_get_hostid(h));
		if (!hnqn)
			hnqn = strdup(nvme_host_get_hostnqn(h));
	}

	/* /etc/nvme/hostid and/or /etc/nvme/hostnqn */
	if (!hid)
		hid = nvmf_hostid_from_file();
	if (!hnqn)
		hnqn = nvmf_hostnqn_from_file();

	/* incomplete configuration, thus derive hostid from hostnqn */
	if (!hid && hnqn)
		hid = nvme_hostid_from_hostnqn(hnqn);

	/*
	 * fallback to use either DMI information or device-tree. If all
	 * fails generate one
	 */
	if (!hid) {
		hid = nvmf_hostid_generate();
		if (!hid) {
			errno = -ENOMEM;
			return -1;
		}

		nvme_msg(r, LOG_DEBUG,
			 "warning: using auto generated hostid and hostnqn\n");
	}

	/* incomplete configuration, thus derive hostnqn from hostid */
	if (!hnqn) {
		hnqn = nvmf_hostnqn_generate_from_hostid(hid);
		if (!hnqn) {
			errno = -ENOMEM;
			return -1;
		}
	}

	/* sanity checks */
	nqn = nvme_hostid_from_hostnqn(hnqn);
	if (nqn && strcmp(nqn, hid)) {
		nvme_msg(r, LOG_DEBUG,
			 "warning: use hostid '%s' which does not match uuid in hostnqn '%s'\n",
			 hid, hnqn);
	}

	*hostid = hid;
	*hostnqn = hnqn;
	hid = NULL;
	hnqn = NULL;

	return 0;
}

nvme_host_t nvme_default_host(nvme_root_t r)
{
	_cleanup_free_ char *hostnqn = NULL;
	_cleanup_free_ char *hostid = NULL;
	struct nvme_host *h;

	if (nvme_host_get_ids(r, NULL, NULL, &hostnqn, &hostid))
		return NULL;

	h = nvme_lookup_host(r, hostnqn, hostid);

	nvme_host_set_hostsymname(h, NULL);

	default_host = h;
	return h;
}

int nvme_scan_topology(struct nvme_root *r, nvme_scan_filter_t f, void *f_args)
{
	_cleanup_dirents_ struct dirents subsys = {}, ctrls = {};
	int i, ret;

	if (!r)
		return 0;

	ctrls.num = nvme_scan_ctrls(&ctrls.ents);
	if (ctrls.num < 0) {
		nvme_msg(r, LOG_DEBUG, "failed to scan ctrls: %s\n",
			 strerror(errno));
		return ctrls.num;
	}

	for (i = 0; i < ctrls.num; i++) {
		nvme_ctrl_t c = nvme_scan_ctrl(r, ctrls.ents[i]->d_name);
		if (!c) {
			nvme_msg(r, LOG_DEBUG, "failed to scan ctrl %s: %s\n",
				 ctrls.ents[i]->d_name, strerror(errno));
			continue;
		}
		if ((f) && !f(NULL, c, NULL, f_args)) {
			nvme_msg(r, LOG_DEBUG, "filter out controller %s\n",
				 ctrls.ents[i]->d_name);
			nvme_free_ctrl(c);
		}
	}

	subsys.num = nvme_scan_subsystems(&subsys.ents);
	if (subsys.num < 0) {
		nvme_msg(r, LOG_DEBUG, "failed to scan subsystems: %s\n",
			 strerror(errno));
		return subsys.num;
	}

	for (i = 0; i < subsys.num; i++) {
		ret = nvme_scan_subsystem(
			r, subsys.ents[i]->d_name, f, f_args);
		if (ret < 0) {
			nvme_msg(r, LOG_DEBUG,
				 "failed to scan subsystem %s: %s\n",
				 subsys.ents[i]->d_name, strerror(errno));
		}
	}

	return 0;
}

nvme_root_t nvme_create_root(FILE *fp, int log_level)
{
	struct nvme_root *r;
	int fd;

	r = calloc(1, sizeof(*r));
	if (!r) {
		errno = ENOMEM;
		return NULL;
	}

	if (fp) {
		fd = fileno(fp);
		if (fd < 0) {
			free(r);
			return NULL;
		}
	} else
		fd = STDERR_FILENO;

	r->log.fd = fd;
	r->log.level = log_level;

	list_head_init(&r->hosts);
	list_head_init(&r->endpoints);

	return r;
}

int nvme_read_config(nvme_root_t r, const char *config_file)
{
	int err = -1;
	int tmp;

	if (!r || !config_file) {
		errno = ENODEV;
		return err;
	}

	r->config_file = strdup(config_file);
	if (!r->config_file) {
		errno = ENOMEM;
		return err;
	}

	tmp = errno;
	err = json_read_config(r, config_file);
	/*
	 * The json configuration file is optional,
	 * so ignore errors when opening the file.
	 */
	if (err < 0 && errno != EPROTO) {
		errno = tmp;
		return 0;
	}

	return err;
}

nvme_root_t nvme_scan(const char *config_file)
{
	nvme_root_t r = nvme_create_root(NULL, DEFAULT_LOGLEVEL);

	nvme_scan_topology(r, NULL, NULL);
	nvme_read_config(r, config_file);
	return r;
}

int nvme_update_config(nvme_root_t r)
{
	if (!r->modified || !r->config_file)
		return 0;

	return json_update_config(r, r->config_file);
}

int nvme_dump_config(nvme_root_t r)
{
	return json_update_config(r, NULL);
}

int nvme_dump_tree(nvme_root_t r)
{
	return json_dump_tree(r);
}

const char *nvme_root_get_application(nvme_root_t r)
{
	return r->application;
}

void nvme_root_set_application(nvme_root_t r, const char *a)
{
	if (r->application) {
		free(r->application);
		r->application = NULL;
	}
	if (a)
		r->application = strdup(a);
}

void nvme_root_skip_namespaces(nvme_root_t r)
{
	r->create_only = true;
}

nvme_host_t nvme_first_host(nvme_root_t r)
{
	return list_top(&r->hosts, struct nvme_host, entry);
}

nvme_host_t nvme_next_host(nvme_root_t r, nvme_host_t h)
{
	return h ? list_next(&r->hosts, h, entry) : NULL;
}

nvme_root_t nvme_host_get_root(nvme_host_t h)
{
	return h->r;
}

const char *nvme_host_get_hostnqn(nvme_host_t h)
{
	return h->hostnqn;
}

const char *nvme_host_get_hostid(nvme_host_t h)
{
	return h->hostid;
}

const char *nvme_host_get_hostsymname(nvme_host_t h)
{
	return h->hostsymname;
}

void nvme_host_set_hostsymname(nvme_host_t h, const char *hostsymname)
{
	if (h->hostsymname) {
		free(h->hostsymname);
		h->hostsymname = NULL;
	}
	if (hostsymname)
		h->hostsymname = strdup(hostsymname);
}

const char *nvme_host_get_dhchap_key(nvme_host_t h)
{
	return h->dhchap_key;
}

void nvme_host_set_dhchap_key(nvme_host_t h, const char *key)
{
	if (h->dhchap_key) {
		free(h->dhchap_key);
		h->dhchap_key = NULL;
	}
	if (key)
		h->dhchap_key = strdup(key);
}

void nvme_host_set_pdc_enabled(nvme_host_t h, bool enabled)
{
	h->pdc_enabled_valid = true;
	h->pdc_enabled = enabled;
}

bool nvme_host_is_pdc_enabled(nvme_host_t h, bool fallback)
{
	if (h->pdc_enabled_valid)
		return h->pdc_enabled;
	return fallback;
}

nvme_subsystem_t nvme_first_subsystem(nvme_host_t h)
{
	return list_top(&h->subsystems, struct nvme_subsystem, entry);
}

nvme_subsystem_t nvme_next_subsystem(nvme_host_t h, nvme_subsystem_t s)
{
	return s ? list_next(&h->subsystems, s, entry) : NULL;
}

void nvme_refresh_topology(nvme_root_t r)
{
	struct nvme_host *h, *_h;

	nvme_for_each_host_safe(r, h, _h)
		__nvme_free_host(h);
	nvme_scan_topology(r, NULL, NULL);
}

void nvme_free_tree(nvme_root_t r)
{
	struct nvme_host *h, *_h;

	if (!r)
		return;

	if (r->options)
		free(r->options);
	nvme_for_each_host_safe(r, h, _h)
		__nvme_free_host(h);
	if (r->config_file)
		free(r->config_file);
	if (r->application)
		free(r->application);
	free(r);
}

void nvme_root_release_fds(nvme_root_t r)
{
	struct nvme_host *h, *_h;

	nvme_for_each_host_safe(r, h, _h)
		nvme_host_release_fds(h);
}

const char *nvme_subsystem_get_nqn(nvme_subsystem_t s)
{
	return s->subsysnqn;
}

const char *nvme_subsystem_get_sysfs_dir(nvme_subsystem_t s)
{
	return s->sysfs_dir;
}

const char *nvme_subsystem_get_name(nvme_subsystem_t s)
{
	return s->name;
}

const char *nvme_subsystem_get_type(nvme_subsystem_t s)
{
	return s->subsystype;
}

const char *nvme_subsystem_get_application(nvme_subsystem_t s)
{
	return s->application;
}

void nvme_subsystem_set_application(nvme_subsystem_t s, const char *a)
{
	if (s->application) {
		free(s->application);
		s->application = NULL;
	}
	if (a)
		s->application = strdup(a);
}

const char *nvme_subsystem_get_iopolicy(nvme_subsystem_t s)
{
	return s->iopolicy;
}

nvme_ctrl_t nvme_subsystem_first_ctrl(nvme_subsystem_t s)
{
	return list_top(&s->ctrls, struct nvme_ctrl, entry);
}

nvme_ctrl_t nvme_subsystem_next_ctrl(nvme_subsystem_t s, nvme_ctrl_t c)
{
	return c ? list_next(&s->ctrls, c, entry) : NULL;
}

nvme_host_t nvme_subsystem_get_host(nvme_subsystem_t s)
{
	return s->h;
}

nvme_ns_t nvme_subsystem_first_ns(nvme_subsystem_t s)
{
	return list_top(&s->namespaces, struct nvme_ns, entry);
}

nvme_ns_t nvme_subsystem_next_ns(nvme_subsystem_t s, nvme_ns_t n)
{
	return n ? list_next(&s->namespaces, n, entry) : NULL;
}

nvme_path_t nvme_namespace_first_path(nvme_ns_t ns)
{
	return list_top(&ns->paths, struct nvme_path, nentry);
}

nvme_path_t nvme_namespace_next_path(nvme_ns_t ns, nvme_path_t p)
{
	return p ? list_next(&ns->paths, p, nentry) : NULL;
}

static void __nvme_free_ns(struct nvme_ns *n)
{
	list_del_init(&n->entry);
	nvme_ns_release_fd(n);
	free(n->generic_name);
	free(n->name);
	free(n->sysfs_dir);
	free(n);
}

/* Stub for SWIG */
void nvme_free_ns(struct nvme_ns *n)
{
	__nvme_free_ns(n);
}

static void __nvme_free_subsystem(struct nvme_subsystem *s)
{
	struct nvme_ctrl *c, *_c;
	struct nvme_ns *n, *_n;

	list_del_init(&s->entry);
	nvme_subsystem_for_each_ctrl_safe(s, c, _c)
		__nvme_free_ctrl(c);

	nvme_subsystem_for_each_ns_safe(s, n, _n)
		__nvme_free_ns(n);

	if (s->name)
		free(s->name);
	free(s->sysfs_dir);
	free(s->subsysnqn);
	if (s->model)
		free(s->model);
	if (s->serial)
		free(s->serial);
	if (s->firmware)
		free(s->firmware);
	if (s->subsystype)
		free(s->subsystype);
	if (s->application)
		free(s->application);
	if (s->iopolicy)
		free(s->iopolicy);
	free(s);
}

void nvme_subsystem_release_fds(struct nvme_subsystem *s)
{
	struct nvme_ctrl *c, *_c;
	struct nvme_ns *n, *_n;

	nvme_subsystem_for_each_ctrl_safe(s, c, _c)
		nvme_ctrl_release_fd(c);

	nvme_subsystem_for_each_ns_safe(s, n, _n)
		nvme_ns_release_fd(n);
}

/*
 * Stub for SWIG
 */
void nvme_free_subsystem(nvme_subsystem_t s)
{
}

struct nvme_subsystem *nvme_alloc_subsystem(struct nvme_host *h,
					    const char *name,
					    const char *subsysnqn)
{
	struct nvme_subsystem *s;

	s = calloc(1, sizeof(*s));
	if (!s)
		return NULL;

	s->h = h;
	s->subsysnqn = strdup(subsysnqn);
	if (name)
		nvme_init_subsystem(s, name);
	list_head_init(&s->ctrls);
	list_head_init(&s->namespaces);
	list_node_init(&s->entry);
	list_add_tail(&h->subsystems, &s->entry);
	h->r->modified = true;
	return s;
}

struct nvme_subsystem *nvme_lookup_subsystem(struct nvme_host *h,
					     const char *name,
					     const char *subsysnqn)
{
	struct nvme_subsystem *s;

	nvme_for_each_subsystem(h, s) {
		if (subsysnqn && s->subsysnqn &&
		    strcmp(s->subsysnqn, subsysnqn))
			continue;
		if (name && s->name &&
		    strcmp(s->name, name))
			continue;
		if (h->r->application) {
			if (!s->application)
				continue;
			if (strcmp(h->r->application, s->application))
				continue;
		}
		return s;
	}
	return nvme_alloc_subsystem(h, name, subsysnqn);
}

static void __nvme_free_host(struct nvme_host *h)
{
	struct nvme_subsystem *s, *_s;

	list_del_init(&h->entry);
	nvme_for_each_subsystem_safe(h, s, _s)
		__nvme_free_subsystem(s);
	free(h->hostnqn);
	if (h->hostid)
		free(h->hostid);
	if (h->dhchap_key)
		free(h->dhchap_key);
	nvme_host_set_hostsymname(h, NULL);
	h->r->modified = true;
	free(h);
}

void nvme_host_release_fds(struct nvme_host *h)
{
	struct nvme_subsystem *s, *_s;

	nvme_for_each_subsystem_safe(h, s, _s)
		nvme_subsystem_release_fds(s);
}

/* Stub for SWIG */
void nvme_free_host(struct nvme_host *h)
{
	__nvme_free_host(h);
}

struct nvme_host *nvme_lookup_host(nvme_root_t r, const char *hostnqn,
				   const char *hostid)
{
	struct nvme_host *h;

	if (!hostnqn)
		return NULL;
	nvme_for_each_host(r, h) {
		if (strcmp(h->hostnqn, hostnqn))
			continue;
		if (hostid && (!h->hostid ||
		    strcmp(h->hostid, hostid)))
			continue;
		return h;
	}
	h = calloc(1,sizeof(*h));
	if (!h)
		return NULL;
	h->hostnqn = strdup(hostnqn);
	if (hostid)
		h->hostid = strdup(hostid);
	list_head_init(&h->subsystems);
	list_node_init(&h->entry);
	h->r = r;
	list_add_tail(&r->hosts, &h->entry);
	r->modified = true;

	return h;
}

static int nvme_subsystem_scan_namespaces(nvme_root_t r, nvme_subsystem_t s,
		nvme_scan_filter_t f, void *f_args)
{
	_cleanup_dirents_ struct dirents namespaces = {};
	int i, ret;

	if (r->create_only) {
		nvme_msg(r, LOG_DEBUG,
			 "skipping namespace scan for subsys %s\n",
			 s->subsysnqn);
		return 0;
	}
	namespaces.num = nvme_scan_subsystem_namespaces(s, &namespaces.ents);
	if (namespaces.num < 0) {
		nvme_msg(r, LOG_DEBUG,
			 "failed to scan namespaces for subsys %s: %s\n",
			 s->subsysnqn, strerror(errno));
		return namespaces.num;
	}

	for (i = 0; i < namespaces.num; i++) {
		ret = nvme_subsystem_scan_namespace(r, s,
				namespaces.ents[i]->d_name, f, f_args);
		if (ret < 0)
			nvme_msg(r, LOG_DEBUG,
				 "failed to scan namespace %s: %s\n",
				 namespaces.ents[i]->d_name, strerror(errno));
	}

	return 0;
}

static int nvme_init_subsystem(nvme_subsystem_t s, const char *name)
{
	char *path;

	if (asprintf(&path, "%s/%s", nvme_subsys_sysfs_dir(), name) < 0)
		return -1;

	s->model = nvme_get_attr(path, "model");
	if (!s->model)
		s->model = strdup("undefined");
	s->serial = nvme_get_attr(path, "serial");
	s->firmware = nvme_get_attr(path, "firmware_rev");
	s->subsystype = nvme_get_attr(path, "subsystype");
	if (!s->subsystype) {
		if (!strcmp(s->subsysnqn, NVME_DISC_SUBSYS_NAME))
			s->subsystype = strdup("discovery");
		else
			s->subsystype = strdup("nvm");
	}
	s->name = strdup(name);
	s->sysfs_dir = (char *)path;
	if (s->h->r->application)
		s->application = strdup(s->h->r->application);
	s->iopolicy = nvme_get_attr(path, "iopolicy");

	return 0;
}

static bool __nvme_scan_subsystem(struct nvme_root *r, nvme_subsystem_t s,
				  nvme_scan_filter_t f, void *f_args)
{
	if (f && !f(s, NULL, NULL, f_args)) {
		nvme_msg(r, LOG_DEBUG, "filter out subsystem %s\n", s->name);
		__nvme_free_subsystem(s);
		return false;
	}
	nvme_subsystem_scan_namespaces(r, s, f, f_args);
	return true;
}

static int nvme_scan_subsystem(struct nvme_root *r, const char *name,
		nvme_scan_filter_t f, void *f_args)
{
	struct nvme_subsystem *s = NULL, *_s;
	_cleanup_free_ char *path = NULL, *subsysnqn = NULL;
	nvme_host_t h = NULL;
	int ret;

	nvme_msg(r, LOG_DEBUG, "scan subsystem %s\n", name);
	ret = asprintf(&path, "%s/%s", nvme_subsys_sysfs_dir(), name);
	if (ret < 0)
		return ret;

	subsysnqn = nvme_get_attr(path, "subsysnqn");
	if (!subsysnqn) {
		errno = ENODEV;
		return -1;
	}
	nvme_for_each_host(r, h) {
		nvme_for_each_subsystem(h, _s) {
			/*
			 * We are always called after nvme_scan_ctrl(),
			 * so any subsystem we're interested at _must_
			 * have a name.
			 */
			if (!_s->name)
				continue;
			if (strcmp(_s->name, name))
				continue;
			if (!__nvme_scan_subsystem(r, _s, f, f_args)) {
				errno = EINVAL;
				return -1;
			}
			s = _s;
		}
	}
	if (!s) {
		/*
		 * Subsystem with non-matching controller. odd.
		 * Create a subsystem with the default host
		 * and hope for the best.
		 */
		nvme_msg(r, LOG_DEBUG, "creating detached subsystem '%s'\n",
			 name);
		h = nvme_default_host(r);
		s = nvme_alloc_subsystem(h, name, subsysnqn);
		if (!s) {
			errno = ENOMEM;
			return -1;
		}
		if (!__nvme_scan_subsystem(r, s, f, f_args)) {
			errno = EINVAL;
			return -1;
		}
	} else if (strcmp(s->subsysnqn, subsysnqn)) {
		nvme_msg(r, LOG_DEBUG, "NQN mismatch for subsystem '%s'\n",
			 name);
		errno = EINVAL;
		return -1;
	}

	return 0;
}

nvme_ctrl_t nvme_path_get_ctrl(nvme_path_t p)
{
	return p->c;
}

nvme_ns_t nvme_path_get_ns(nvme_path_t p)
{
	return p->n;
}

const char *nvme_path_get_sysfs_dir(nvme_path_t p)
{
	return p->sysfs_dir;
}

const char *nvme_path_get_name(nvme_path_t p)
{
	return p->name;
}

const char *nvme_path_get_ana_state(nvme_path_t p)
{
	return p->ana_state;
}

void nvme_free_path(struct nvme_path *p)
{
	list_del_init(&p->entry);
	list_del_init(&p->nentry);
	free(p->name);
	free(p->sysfs_dir);
	free(p->ana_state);
	free(p);
}

static void nvme_subsystem_set_path_ns(nvme_subsystem_t s, nvme_path_t p)
{
	char n_name[32] = { };
	int i, c, nsid, ret;
	nvme_ns_t n;

	ret = sscanf(nvme_path_get_name(p), "nvme%dc%dn%d", &i, &c, &nsid);
	if (ret != 3)
		return;

	sprintf(n_name, "nvme%dn%d", i, nsid);
	nvme_subsystem_for_each_ns(s, n) {
		if (!strcmp(n_name, nvme_ns_get_name(n))) {
			list_add_tail(&n->paths, &p->nentry);
			p->n = n;
		}
	}
}

static int nvme_ctrl_scan_path(nvme_root_t r, struct nvme_ctrl *c, char *name)
{
	struct nvme_path *p;
	_cleanup_free_ char *path = NULL, *grpid = NULL;
	int ret;

	nvme_msg(r, LOG_DEBUG, "scan controller %s path %s\n",
		 c->name, name);
	if (!c->s) {
		errno = ENXIO;
		return -1;
	}
	ret = asprintf(&path, "%s/%s", c->sysfs_dir, name);
	if (ret < 0) {
		errno = ENOMEM;
		return -1;
	}

	p = calloc(1, sizeof(*p));
	if (!p) {
		errno = ENOMEM;
		return -1;
	}

	p->c = c;
	p->name = strdup(name);
	p->sysfs_dir = path;
	path = NULL;
	p->ana_state = nvme_get_path_attr(p, "ana_state");
	if (!p->ana_state)
		p->ana_state = strdup("optimized");

	grpid = nvme_get_path_attr(p, "ana_grpid");
	if (grpid) {
		sscanf(grpid, "%d", &p->grpid);
	}

	list_node_init(&p->nentry);
	nvme_subsystem_set_path_ns(c->s, p);
	list_node_init(&p->entry);
	list_add_tail(&c->paths, &p->entry);
	return 0;
}

int nvme_ctrl_get_fd(nvme_ctrl_t c)
{
	if (c->fd < 0) {
		c->fd = nvme_open(c->name);
		if (c->fd < 0)
			nvme_msg(root_from_ctrl(c), LOG_ERR,
				 "Failed to open ctrl %s, errno %d\n",
				 c->name, errno);
	}
	return c->fd;
}

void nvme_ctrl_release_fd(nvme_ctrl_t c)
{
	if (c->fd < 0)
		return;

	close(c->fd);
	c->fd = -1;
}

nvme_subsystem_t nvme_ctrl_get_subsystem(nvme_ctrl_t c)
{
	return c->s;
}

const char *nvme_ctrl_get_name(nvme_ctrl_t c)
{
	return c->name;
}

const char *nvme_ctrl_get_sysfs_dir(nvme_ctrl_t c)
{
	return c->sysfs_dir;
}

const char *nvme_ctrl_get_subsysnqn(nvme_ctrl_t c)
{
	return c->s ? c->s->subsysnqn : c->subsysnqn;
}

const char *nvme_ctrl_get_address(nvme_ctrl_t c)
{
	return c->address ? c->address : "";
}

char *nvme_ctrl_get_src_addr(nvme_ctrl_t c, char *src_addr, size_t src_addr_len)
{
	size_t l;
	char *p;

	if (!c->address)
		return NULL;

	p = strstr(c->address, "src_addr=");
	if (!p)
		return NULL;

	p += strlen("src_addr=");
	l = strcspn(p, ",%"); /* % to eliminate IPv6 scope (if present) */
	if (l >= src_addr_len) {
		nvme_msg(root_from_ctrl(c), LOG_ERR,
			 "Buffer for src_addr is too small (%zu must be > %zu)\n",
			 src_addr_len, l);
		return NULL;
	}

	strncpy(src_addr, p, l);
	src_addr[l] = '\0';
	return src_addr;
}

const char *nvme_ctrl_get_phy_slot(nvme_ctrl_t c)
{
	return c->phy_slot ? c->phy_slot : "";
}

const char *nvme_ctrl_get_firmware(nvme_ctrl_t c)
{
	return c->firmware;
}

const char *nvme_ctrl_get_model(nvme_ctrl_t c)
{
	return c->model;
}

const char *nvme_ctrl_get_state(nvme_ctrl_t c)
{
	char *state = c->state;

	c->state = nvme_get_ctrl_attr(c, "state");
	if (state)
		free(state);
	return c->state;
}

const char *nvme_ctrl_get_numa_node(nvme_ctrl_t c)
{
	return c->numa_node;
}

const char *nvme_ctrl_get_queue_count(nvme_ctrl_t c)
{
	return c->queue_count;
}

const char *nvme_ctrl_get_serial(nvme_ctrl_t c)
{
	return c->serial;
}

const char *nvme_ctrl_get_sqsize(nvme_ctrl_t c)
{
	return c->sqsize;
}

const char *nvme_ctrl_get_transport(nvme_ctrl_t c)
{
	return c->transport;
}

const char *nvme_ctrl_get_traddr(nvme_ctrl_t c)
{
	return c->traddr;
}

const char *nvme_ctrl_get_trsvcid(nvme_ctrl_t c)
{
	return c->trsvcid;
}

const char *nvme_ctrl_get_host_traddr(nvme_ctrl_t c)
{
	return c->cfg.host_traddr;
}

const char *nvme_ctrl_get_host_iface(nvme_ctrl_t c)
{
	return c->cfg.host_iface;
}

struct nvme_fabrics_config *nvme_ctrl_get_config(nvme_ctrl_t c)
{
	return &c->cfg;
}

const char *nvme_ctrl_get_dhchap_host_key(nvme_ctrl_t c)
{
	return c->dhchap_key;
}

const char *nvme_ctrl_get_cntlid(nvme_ctrl_t c)
{
	return c->cntlid;
}

void nvme_ctrl_set_dhchap_host_key(nvme_ctrl_t c, const char *key)
{
	if (c->dhchap_key) {
		free(c->dhchap_key);
		c->dhchap_key = NULL;
	}
	if (key)
		c->dhchap_key = strdup(key);
}

const char *nvme_ctrl_get_dhchap_key(nvme_ctrl_t c)
{
	return c->dhchap_ctrl_key;
}

void nvme_ctrl_set_dhchap_key(nvme_ctrl_t c, const char *key)
{
	if (c->dhchap_ctrl_key) {
		free(c->dhchap_ctrl_key);
		c->dhchap_ctrl_key = NULL;
	}
	if (key)
		c->dhchap_ctrl_key = strdup(key);
}

void nvme_ctrl_set_discovered(nvme_ctrl_t c, bool discovered)
{
	c->discovered = discovered;
}

bool nvme_ctrl_is_discovered(nvme_ctrl_t c)
{
	return c->discovered;
}

void nvme_ctrl_set_persistent(nvme_ctrl_t c, bool persistent)
{
	c->persistent = persistent;
}

bool nvme_ctrl_is_persistent(nvme_ctrl_t c)
{
	return c->persistent;
}

void nvme_ctrl_set_discovery_ctrl(nvme_ctrl_t c, bool discovery)
{
	c->discovery_ctrl = discovery;
}

bool nvme_ctrl_is_discovery_ctrl(nvme_ctrl_t c)
{
	return c->discovery_ctrl;
}

void nvme_ctrl_set_unique_discovery_ctrl(nvme_ctrl_t c, bool unique)
{
	c->unique_discovery_ctrl = unique;
}

bool nvme_ctrl_is_unique_discovery_ctrl(nvme_ctrl_t c)
{
	return c->unique_discovery_ctrl;
}

int nvme_ctrl_identify(nvme_ctrl_t c, struct nvme_id_ctrl *id)
{
	return nvme_identify_ctrl(nvme_ctrl_get_fd(c), id);
}

nvme_ns_t nvme_ctrl_first_ns(nvme_ctrl_t c)
{
	return list_top(&c->namespaces, struct nvme_ns, entry);
}

nvme_ns_t nvme_ctrl_next_ns(nvme_ctrl_t c, nvme_ns_t n)
{
	return n ? list_next(&c->namespaces, n, entry) : NULL;
}

nvme_path_t nvme_ctrl_first_path(nvme_ctrl_t c)
{
	return list_top(&c->paths, struct nvme_path, entry);
}

nvme_path_t nvme_ctrl_next_path(nvme_ctrl_t c, nvme_path_t p)
{
	return p ? list_next(&c->paths, p, entry) : NULL;
}

#define FREE_CTRL_ATTR(a) \
	do { if (a) { free(a); (a) = NULL; } } while (0)
void nvme_deconfigure_ctrl(nvme_ctrl_t c)
{
	nvme_ctrl_release_fd(c);
	FREE_CTRL_ATTR(c->name);
	FREE_CTRL_ATTR(c->sysfs_dir);
	FREE_CTRL_ATTR(c->firmware);
	FREE_CTRL_ATTR(c->model);
	FREE_CTRL_ATTR(c->state);
	FREE_CTRL_ATTR(c->numa_node);
	FREE_CTRL_ATTR(c->queue_count);
	FREE_CTRL_ATTR(c->serial);
	FREE_CTRL_ATTR(c->sqsize);
	FREE_CTRL_ATTR(c->dhchap_key);
	FREE_CTRL_ATTR(c->dhchap_ctrl_key);
	FREE_CTRL_ATTR(c->address);
	FREE_CTRL_ATTR(c->dctype);
	FREE_CTRL_ATTR(c->cntrltype);
	FREE_CTRL_ATTR(c->cntlid);
	FREE_CTRL_ATTR(c->phy_slot);
}

int nvme_disconnect_ctrl(nvme_ctrl_t c)
{
	nvme_root_t r = c->s && c->s->h ? c->s->h->r : NULL;
	int ret;

	ret = nvme_set_attr(nvme_ctrl_get_sysfs_dir(c),
			    "delete_controller", "1");
	if (ret < 0) {
		nvme_msg(r, LOG_ERR, "%s: failed to disconnect, error %d\n",
			 c->name, errno);
		return ret;
	}
	nvme_msg(r, LOG_INFO, "%s: %s disconnected\n", c->name, c->subsysnqn);
	nvme_deconfigure_ctrl(c);
	return 0;
}

void nvme_unlink_ctrl(nvme_ctrl_t c)
{
	list_del_init(&c->entry);
	c->s = NULL;
}

static void __nvme_free_ctrl(nvme_ctrl_t c)
{
	struct nvme_path *p, *_p;
	struct nvme_ns *n, *_n;

	nvme_unlink_ctrl(c);

	nvme_ctrl_for_each_path_safe(c, p, _p)
		nvme_free_path(p);

	nvme_ctrl_for_each_ns_safe(c, n, _n)
		__nvme_free_ns(n);

	nvme_deconfigure_ctrl(c);

	FREE_CTRL_ATTR(c->transport);
	FREE_CTRL_ATTR(c->subsysnqn);
	FREE_CTRL_ATTR(c->traddr);
	FREE_CTRL_ATTR(c->cfg.host_traddr);
	FREE_CTRL_ATTR(c->cfg.host_iface);
	FREE_CTRL_ATTR(c->trsvcid);
	free(c);
}

void nvme_free_ctrl(nvme_ctrl_t c)
{
	__nvme_free_ctrl(c);
}

static bool traddr_is_hostname(const char *transport, const char *traddr)
{
	char addrstr[NVMF_TRADDR_SIZE];

	if (!traddr || !transport)
		return false;
	if (!strcmp(traddr, "none"))
		return false;
	if (strcmp(transport, "tcp") &&
	    strcmp(transport, "rdma"))
		return false;
	if (inet_pton(AF_INET, traddr, addrstr) > 0 ||
	    inet_pton(AF_INET6, traddr, addrstr) > 0)
		return false;
	return true;
}

struct nvme_ctrl *nvme_create_ctrl(nvme_root_t r,
				   const char *subsysnqn, const char *transport,
				   const char *traddr, const char *host_traddr,
				   const char *host_iface, const char *trsvcid)
{
	struct nvme_ctrl *c;

	if (!transport) {
		nvme_msg(r, LOG_ERR, "No transport specified\n");
		errno = EINVAL;
		return NULL;
	}
	if (strncmp(transport, "loop", 4) &&
	    strncmp(transport, "pcie", 4) && !traddr) {
		nvme_msg(r, LOG_ERR, "No transport address for '%s'\n",
			 transport);
	       errno = EINVAL;
	       return NULL;
	}
	if (!subsysnqn) {
		nvme_msg(r, LOG_ERR, "No subsystem NQN specified\n");
		errno = EINVAL;
		return NULL;
	}
	c = calloc(1, sizeof(*c));
	if (!c) {
		errno = ENOMEM;
		return NULL;
	}
	c->fd = -1;
	nvmf_default_config(&c->cfg);
	list_head_init(&c->namespaces);
	list_head_init(&c->paths);
	list_node_init(&c->entry);
	c->transport = strdup(transport);
	c->subsysnqn = strdup(subsysnqn);
	if (traddr)
		c->traddr = strdup(traddr);
	if (host_traddr) {
		if (traddr_is_hostname(transport, host_traddr))
			c->cfg.host_traddr = hostname2traddr(r, host_traddr);
		if (!c->cfg.host_traddr)
			c->cfg.host_traddr = strdup(host_traddr);
	}
	if (host_iface)
		c->cfg.host_iface = strdup(host_iface);
	if (trsvcid)
		c->trsvcid = strdup(trsvcid);

	return c;
}

/**
 * _tcp_ctrl_match_host_traddr_no_src_addr() - Match host_traddr w/o src_addr
 * @c:	An existing controller instance
 * @candidate:	Candidate ctrl we're trying to match with @c.
 *
 * On kernels prior to 6.1 (i.e. src_addr is not available), try to match
 * a candidate controller's host_traddr to that of an existing controller.
 *
 * This function takes an optimistic approach. In doubt, it will declare a
 * match and return true.
 *
 * Return: true if @c->host_traddr matches @candidate->host_traddr. false otherwise.
 */
static bool _tcp_ctrl_match_host_traddr_no_src_addr(struct nvme_ctrl *c, struct candidate_args *candidate)
{
	if (c->cfg.host_traddr)
		return candidate->addreq(candidate->host_traddr, c->cfg.host_traddr);

	/* If c->cfg.host_traddr is NULL, then the controller (c)
	 * uses the interface's primary address as the source
	 * address. If c->cfg.host_iface is defined we can
	 * determine the primary address associated with that
	 * interface and compare that to the candidate->host_traddr.
	 */
	if (c->cfg.host_iface)
		return nvme_iface_primary_addr_matches(candidate->iface_list,
						       c->cfg.host_iface,
						       candidate->host_traddr);

	/* If both c->cfg.host_traddr and c->cfg.host_iface are
	 * NULL, we don't have enough information to make a
	 * 100% positive match. Regardless, let's be optimistic
	 * and assume that we have a match.
	 */
	nvme_msg(root_from_ctrl(c), LOG_DEBUG,
		 "Not enough data, but assume %s matches candidate's host_traddr: %s\n",
		 nvme_ctrl_get_name(c), candidate->host_traddr);

	return true;
}

/**
 * _tcp_ctrl_match_host_iface_no_src_addr() - Match host_iface w/o src_addr
 * @c:	An existing controller instance
 * @candidate:	Candidate ctrl we're trying to match with @c.
 *
 * On kernels prior to 6.1 (i.e. src_addr is not available), try to match
 * a candidate controller's host_iface to that of an existing controller.
 *
 * This function takes an optimistic approach. In doubt, it will declare a
 * match and return true.
 *
 * Return: true if @c->host_iface matches @candidate->host_iface. false otherwise.
 */
static bool _tcp_ctrl_match_host_iface_no_src_addr(struct nvme_ctrl *c, struct candidate_args *candidate)
{
	if (c->cfg.host_iface)
		return streq0(candidate->host_iface, c->cfg.host_iface);

	/* If c->cfg.host_traddr is not NULL we can infer the controller's (c)
	 * interface from it and compare it to the candidate->host_iface.
	 */
	if (c->cfg.host_traddr) {
		const char *c_host_iface;

		c_host_iface = nvme_iface_matching_addr(candidate->iface_list, c->cfg.host_traddr);
		return streq0(candidate->host_iface, c_host_iface);
	}

	/* If both c->cfg.host_traddr and c->cfg.host_iface are
	 * NULL, we don't have enough information to make a
	 * 100% positive match. Regardless, let's be optimistic
	 * and assume that we have a match.
	 */
	nvme_msg(root_from_ctrl(c), LOG_DEBUG,
		 "Not enough data, but assume %s matches candidate's host_iface: %s\n",
		 nvme_ctrl_get_name(c), candidate->host_iface);

	return true;
}

/**
 * _tcp_opt_params_match_no_src_addr() - Match optional host_traddr/host_iface w/o src_addr
 * @c:	An existing controller instance
 * @candidate:	Candidate ctrl we're trying to match with @c.
 *
 * Before kernel 6.1, the src_addr was not reported by the kernel which makes
 * it hard to match a candidate's host_traddr and host_iface to an existing
 * controller if that controller was created without specifying the
 * host_traddr and/or host_iface. This function tries its best in the absense
 * of a src_addr to match @c to @candidate. This may not be 100% accurate.
 * Only the src_addr can provide 100% accuracy.
 *
 * This function takes an optimistic approach. In doubt, it will declare a
 * match and return true.
 *
 * Return: true if @c matches @candidate. false otherwise.
 */
static bool _tcp_opt_params_match_no_src_addr(struct nvme_ctrl *c, struct candidate_args *candidate)
{
	/* Check host_traddr only if candidate is interested */
	if (candidate->host_traddr) {
		if (!_tcp_ctrl_match_host_traddr_no_src_addr(c, candidate))
			return false;
	}

	/* Check host_iface only if candidate is interested */
	if (candidate->host_iface) {
		if (!_tcp_ctrl_match_host_iface_no_src_addr(c, candidate))
			return false;
	}

	return true;
}

/**
 * _tcp_opt_params_match() - Match optional host_traddr/host_iface
 * @c:	An existing controller instance
 * @candidate:	Candidate ctrl we're trying to match with @c.
 *
 * The host_traddr and host_iface are optional for TCP. When they are not
 * specified, the kernel looks up the destination IP address (traddr) in the
 * routing table to determine the best interface for the connection. The
 * kernel then retrieves the primary IP address assigned to that interface
 * and uses that as the connection’s source address.
 *
 * An interface’s primary address is the default source address used for
 * all connections made on that interface unless host-traddr is used to
 * override the default. Kernel-selected interfaces and/or source addresses
 * are hidden from user-space applications unless the kernel makes that
 * information available through the "src_addr" attribute in the
 * sysfs (kernel 6.1 or later).
 *
 * Sometimes, an application may force the interface by specifying the
 * "host-iface" or may force a different source address (instead of the
 * primary address) by providing the "host-traddr".
 *
 * If the candidate specifies the host_traddr and/or host_iface but they
 * do not match the existing controller's host_traddr and/or host_iface
 * (they could be NULL), we may still be able to find a match by taking
 * the existing controller's src_addr into consideration since that
 * parameter identifies the actual source address of the connection and
 * therefore can be used to infer the interface of the connection. However,
 * the src_addr can only be read from the nvme device's sysfs "address"
 * attribute starting with kernel 6.1 (or kernels that backported the
 * src_addr patch).
 *
 * For legacy kernels that do not provide the src_addr we must use a
 * different algorithm to match the host_traddr and host_iface, but
 * it's not 100% accurate.
 *
 * Return: true if @c matches @candidate. false otherwise.
 */
static bool _tcp_opt_params_match(struct nvme_ctrl *c, struct candidate_args *candidate)
{
	char *src_addr, buffer[INET6_ADDRSTRLEN];

	/* Check if src_addr is available (kernel 6.1 or later) */
	src_addr = nvme_ctrl_get_src_addr(c, buffer, sizeof(buffer));
	if (!src_addr)
		return _tcp_opt_params_match_no_src_addr(c, candidate);

	/* Check host_traddr only if candidate is interested */
	if (candidate->host_traddr &&
	    !candidate->addreq(candidate->host_traddr, src_addr))
		return false;

	/* Check host_iface only if candidate is interested */
	if (candidate->host_iface &&
	    !streq0(candidate->host_iface,
		    nvme_iface_matching_addr(candidate->iface_list, src_addr)))
		return false;

	return true;
}

/**
 * _tcp_match_ctrl() - Check if controller matches candidate (TCP only)
 * @c:	An existing controller instance
 * @candidate:	Candidate ctrl we're trying to match with @c.
 *
 * We want to determine if an existing controller can be re-used
 * for the candidate controller we're trying to instantiate.
 *
 * For TCP, we do not have a match if the candidate's transport, traddr,
 * trsvcid are not identical to those of the the existing controller.
 * These 3 parameters are mandatory for a match.
 *
 * The host_traddr and host_iface are optional. When the candidate does
 * not specify them (both NULL), we can ignore them. Otherwise, we must
 * employ advanced investigation techniques to determine if there's a match.
 *
 * Return: true if a match is found, false otherwise.
 */
static bool _tcp_match_ctrl(struct nvme_ctrl *c, struct candidate_args *candidate)
{
	if (!streq0(c->transport, candidate->transport))
		return false;

	if (!streq0(c->trsvcid, candidate->trsvcid))
		return false;

	if (!candidate->addreq(c->traddr, candidate->traddr))
		return false;

	if (candidate->well_known_nqn && !nvme_ctrl_is_discovery_ctrl(c))
		return false;

	if (candidate->subsysnqn && !streq0(c->subsysnqn, candidate->subsysnqn))
		return false;

	/* Check host_traddr / host_iface only if candidate is interested */
	if ((candidate->host_iface || candidate->host_traddr) &&
	    !_tcp_opt_params_match(c, candidate))
		return false;

	return true;
}

/**
 * _match_ctrl() - Check if controller matches candidate (non TCP transport)
 * @c:	An existing controller instance
 * @candidate:	Candidate ctrl we're trying to match with @c.
 *
 * We want to determine if an existing controller can be re-used
 * for the candidate controller we're trying to instantiate. This function
 * is used for all transports except TCP.
 *
 * Return: true if a match is found, false otherwise.
 */
static bool _match_ctrl(struct nvme_ctrl *c, struct candidate_args *candidate)
{
	if (!streq0(c->transport, candidate->transport))
		return false;

	if (candidate->traddr && c->traddr &&
	    !candidate->addreq(c->traddr, candidate->traddr))
		return false;

	if (candidate->host_traddr && c->cfg.host_traddr &&
	    !candidate->addreq(c->cfg.host_traddr, candidate->host_traddr))
		return false;

	if (candidate->host_iface && c->cfg.host_iface &&
	    !streq0(c->cfg.host_iface, candidate->host_iface))
		return false;

	if (candidate->trsvcid && c->trsvcid &&
	    !streq0(c->trsvcid, candidate->trsvcid))
		return false;

	if (candidate->well_known_nqn && !nvme_ctrl_is_discovery_ctrl(c))
		return false;

	if (candidate->subsysnqn && !streq0(c->subsysnqn, candidate->subsysnqn))
		return false;

	return true;
}
/**
 * _candidate_init() - Init candidate and get the matching function
 *
 * @candidate:		Candidate struct to initialize
 * @transport:		Transport name
 * @traddr:		Transport address
 * @trsvcid:		Transport service identifier
 * @subsysnqn:		Subsystem NQN
 * @host_traddr:	Host transport address
 * @host_iface:		Host interface name
 * @host_iface:		Host interface name
 *
 * The function _candidate_free() must be called to release resources once
 * the candidate object is not longer required.
 *
 * Return: The matching function to use when comparing an existing
 * controller to the candidate controller.
 */
static ctrl_match_t _candidate_init(struct candidate_args *candidate,
				    const char *transport,
				    const char *traddr,
				    const char *trsvcid,
				    const char *subsysnqn,
				    const char *host_traddr,
				    const char *host_iface)
{
	memset(candidate, 0, sizeof(*candidate));

	candidate->traddr = traddr;
	candidate->trsvcid = trsvcid;
	candidate->transport = transport;
	candidate->subsysnqn = subsysnqn;
	candidate->host_iface = host_iface;
	candidate->host_traddr = host_traddr;

	if (streq0(subsysnqn, NVME_DISC_SUBSYS_NAME)) {
		/* Since TP8013, the NQN of discovery controllers can be the
		 * well-known NQN (i.e. nqn.2014-08.org.nvmexpress.discovery) or
		 * a unique NQN. A DC created using the well-known NQN may later
		 * display a unique NQN when looked up in the sysfs. Therefore,
		 * ignore (i.e. set to NULL) the well-known NQN when looking for
		 * a match.
		 */
		candidate->subsysnqn = NULL;
		candidate->well_known_nqn = true;
	}

	if (streq0(transport, "tcp")) {
		/* For TCP we may need to access the interface map.
		 * Let's retrieve and cache the map.
		 */
		if (getifaddrs(&candidate->iface_list) == -1)
			candidate->iface_list = NULL;

		candidate->addreq = nvme_ipaddrs_eq;
		return _tcp_match_ctrl;
	}

	if (streq0(transport, "rdma")) {
		candidate->addreq = nvme_ipaddrs_eq;
		return _match_ctrl;
	}

	/* All other transport types */
	candidate->addreq = streqcase0;
	return _match_ctrl;
}

/**
 * _candidate_free() - Release resources allocated by _candidate_init()
 *
 * @candidate:	data to free.
 */
static void _candidate_free(struct candidate_args *candidate)
{
	freeifaddrs(candidate->iface_list); /* This is NULL-safe */
}

#define _cleanup_candidate_ __cleanup__(_candidate_free)

nvme_ctrl_t __nvme_lookup_ctrl(nvme_subsystem_t s, const char *transport,
			       const char *traddr, const char *host_traddr,
			       const char *host_iface, const char *trsvcid,
			       const char *subsysnqn, nvme_ctrl_t p)
{
	_cleanup_candidate_ struct candidate_args candidate = {};
	struct nvme_ctrl *c, *matching_c = NULL;
	ctrl_match_t ctrl_match;

	/* Init candidate and get the matching function to use */
	ctrl_match = _candidate_init(&candidate, transport, traddr, trsvcid,
				     subsysnqn, host_traddr, host_iface);

	c = p ? nvme_subsystem_next_ctrl(s, p) : nvme_subsystem_first_ctrl(s);
	for (; c != NULL; c = nvme_subsystem_next_ctrl(s, c)) {
		if (ctrl_match(c, &candidate)) {
			matching_c = c;
			break;
		}
	}

	return matching_c;
}

bool nvme_ctrl_config_match(struct nvme_ctrl *c, const char *transport,
			    const char *traddr, const char *trsvcid,
			    const char *subsysnqn, const char *host_traddr,
			    const char *host_iface)
{
	_cleanup_candidate_ struct candidate_args candidate = {};
	ctrl_match_t ctrl_match;

	/* Init candidate and get the matching function to use */
	ctrl_match = _candidate_init(&candidate, transport, traddr, trsvcid,
				     subsysnqn, host_traddr, host_iface);

	return ctrl_match(c, &candidate);
}

nvme_ctrl_t nvme_ctrl_find(nvme_subsystem_t s, const char *transport,
			   const char *traddr, const char *trsvcid,
			   const char *subsysnqn, const char *host_traddr,
			   const char *host_iface)
{
	return __nvme_lookup_ctrl(s, transport, traddr, host_traddr, host_iface,
				  trsvcid, subsysnqn, NULL/*p*/);
}

nvme_ctrl_t nvme_lookup_ctrl(nvme_subsystem_t s, const char *transport,
			     const char *traddr, const char *host_traddr,
			     const char *host_iface, const char *trsvcid,
			     nvme_ctrl_t p)
{
	nvme_root_t r;
	struct nvme_ctrl *c;

	if (!s || !transport)
		return NULL;

	c = __nvme_lookup_ctrl(s, transport, traddr, host_traddr,
			       host_iface, trsvcid, NULL, p);
	if (c)
		return c;

	r = s->h ? s->h->r : NULL;
	c = nvme_create_ctrl(r, s->subsysnqn, transport, traddr,
			     host_traddr, host_iface, trsvcid);
	if (c) {
		c->s = s;
		list_add_tail(&s->ctrls, &c->entry);
		s->h->r->modified = true;
	}
	return c;
}

static int nvme_ctrl_scan_paths(nvme_root_t r, struct nvme_ctrl *c)
{
	_cleanup_dirents_ struct dirents paths = {};
	int i;

	if (r->create_only) {
		nvme_msg(r, LOG_DEBUG,
			 "skipping path scan for ctrl %s\n", c->name);
		return 0;
	}
	paths.num = nvme_scan_ctrl_namespace_paths(c, &paths.ents);
	if (paths.num < 0)
		return paths.num;

	for (i = 0; i < paths.num; i++)
		nvme_ctrl_scan_path(r, c, paths.ents[i]->d_name);

	return 0;
}

static int nvme_ctrl_scan_namespaces(nvme_root_t r, struct nvme_ctrl *c)
{
	_cleanup_dirents_ struct dirents namespaces = {};
	int i;

	if (r->create_only) {
		nvme_msg(r, LOG_DEBUG, "skipping namespace scan for ctrl %s\n",
			 c->name);
		return 0;
	}
	namespaces.num = nvme_scan_ctrl_namespaces(c, &namespaces.ents);
	for (i = 0; i < namespaces.num; i++)
		nvme_ctrl_scan_namespace(r, c, namespaces.ents[i]->d_name);

	return 0;
}

static char *nvme_ctrl_lookup_subsystem_name(nvme_root_t r,
					     const char *ctrl_name)
{
	const char *subsys_dir = nvme_subsys_sysfs_dir();
	_cleanup_dirents_ struct dirents subsys = {};
	int i;

	subsys.num = nvme_scan_subsystems(&subsys.ents);
	if (subsys.num < 0)
		return NULL;
	for (i = 0; i < subsys.num; i++) {
		struct stat st;
		_cleanup_free_ char *path = NULL;

		if (asprintf(&path, "%s/%s/%s", subsys_dir,
			     subsys.ents[i]->d_name, ctrl_name) < 0) {
			errno = ENOMEM;
			return NULL;
		}
		nvme_msg(r, LOG_DEBUG, "lookup subsystem %s\n", path);
		if (stat(path, &st) < 0) {
			continue;
		}
		return strdup(subsys.ents[i]->d_name);
	}
	return NULL;
}

static char *nvme_ctrl_lookup_phy_slot(nvme_root_t r, const char *address)
{
	const char *slots_sysfs_dir = nvme_slots_sysfs_dir();
	_cleanup_free_ char *target_addr = NULL;
	_cleanup_dir_ DIR *slots_dir = NULL;
	int ret;
	struct dirent *entry;

	if (!address)
		return NULL;

	slots_dir = opendir(slots_sysfs_dir);
	if (!slots_dir) {
		nvme_msg(r, LOG_WARNING, "failed to open slots dir %s\n",
		slots_sysfs_dir);
		return NULL;
	}

	target_addr = strndup(address, 10);
	while ((entry = readdir(slots_dir))) {
		if (entry->d_type == DT_DIR &&
		    strncmp(entry->d_name, ".", 1) != 0 &&
		    strncmp(entry->d_name, "..", 2) != 0) {
			_cleanup_free_ char *path = NULL;
			_cleanup_free_ char *addr = NULL;

			ret = asprintf(&path, "%s/%s",
				       slots_sysfs_dir, entry->d_name);
			if (ret < 0) {
				errno = ENOMEM;
				return NULL;
			}
			addr = nvme_get_attr(path, "address");

			/* some directories don't have an address entry */
			if (!addr)
				continue;
			if (strcmp(addr, target_addr) == 0)
				return strdup(entry->d_name);
		}
	}
	return NULL;
}

static int nvme_configure_ctrl(nvme_root_t r, nvme_ctrl_t c, const char *path,
			       const char *name)
{
	DIR *d;
	char *host_key, *ctrl_key;

	_cleanup_free_ char *tls_psk = NULL;

	d = opendir(path);
	if (!d) {
		nvme_msg(r, LOG_ERR, "Failed to open ctrl dir %s, error %d\n",
			 path, errno);
		errno = ENODEV;
		return -1;
	}
	closedir(d);

	c->fd = -1;
	c->name = strdup(name);
	c->sysfs_dir = (char *)path;
	c->firmware = nvme_get_ctrl_attr(c, "firmware_rev");
	c->model = nvme_get_ctrl_attr(c, "model");
	c->state = nvme_get_ctrl_attr(c, "state");
	c->numa_node = nvme_get_ctrl_attr(c, "numa_node");
	c->queue_count = nvme_get_ctrl_attr(c, "queue_count");
	c->serial = nvme_get_ctrl_attr(c, "serial");
	c->sqsize = nvme_get_ctrl_attr(c, "sqsize");

	host_key = nvme_get_ctrl_attr(c, "dhchap_secret");
	if (host_key && c->s && c->s->h && c->s->h->dhchap_key &&
			(!strcmp(c->s->h->dhchap_key, host_key) ||
			 !strcmp("none", host_key))) {
		free(host_key);
		host_key = NULL;
	}
	if (host_key) {
		nvme_ctrl_set_dhchap_host_key(c, NULL);
		c->dhchap_key = host_key;
	}

	ctrl_key = nvme_get_ctrl_attr(c, "dhchap_ctrl_secret");
	if (ctrl_key && !strcmp(ctrl_key, "none")) {
		free(ctrl_key);
		ctrl_key = NULL;
	}
	if (ctrl_key) {
		nvme_ctrl_set_dhchap_key(c, NULL);
		c->dhchap_ctrl_key = ctrl_key;
	}

	tls_psk = nvme_get_ctrl_attr(c, "tls_key");
	if (tls_psk) {
		char *endptr;
		long key_id = strtol(tls_psk, &endptr, 16);

		if (endptr != tls_psk) {
			c->cfg.tls_key = key_id;
			c->cfg.tls = true;
		}
	}

	c->cntrltype = nvme_get_ctrl_attr(c, "cntrltype");
	c->cntlid = nvme_get_ctrl_attr(c, "cntlid");
	c->dctype = nvme_get_ctrl_attr(c, "dctype");
	c->phy_slot = nvme_ctrl_lookup_phy_slot(r, c->address);

	errno = 0; /* cleanup after nvme_get_ctrl_attr() */
	return 0;
}

int nvme_init_ctrl(nvme_host_t h, nvme_ctrl_t c, int instance)
{
	_cleanup_free_ char *subsys_name = NULL;
	_cleanup_free_ char *name = NULL;
	nvme_subsystem_t s;
	char *path;
	int ret;

	ret = asprintf(&name, "nvme%d", instance);
	if (ret < 0) {
		errno = ENOMEM;
		return -1;
	}
	ret = asprintf(&path, "%s/%s", nvme_ctrl_sysfs_dir(), name);
	if (ret < 0) {
		errno = ENOMEM;
		return ret;
	}

	ret = nvme_configure_ctrl(h->r, c, path, name);
	if (ret < 0) {
		free(path);
		return ret;
	}

	c->address = nvme_get_attr(path, "address");
	if (!c->address && strcmp(c->transport, "loop")) {
		errno = ENVME_CONNECT_INVAL_TR;
		return -1;
	}

	subsys_name = nvme_ctrl_lookup_subsystem_name(h->r, name);
	if (!subsys_name) {
		nvme_msg(h->r, LOG_ERR,
			 "Failed to lookup subsystem name for %s\n",
			 c->name);
		errno = ENVME_CONNECT_LOOKUP_SUBSYS_NAME;
		return -1;
	}
	s = nvme_lookup_subsystem(h, subsys_name, c->subsysnqn);
	if (!s) {
		errno = ENVME_CONNECT_LOOKUP_SUBSYS;
		return -1;
	}
	if (s->subsystype && !strcmp(s->subsystype, "discovery"))
		c->discovery_ctrl = true;
	c->s = s;
	list_add_tail(&s->ctrls, &c->entry);
	return ret;
}

static nvme_ctrl_t nvme_ctrl_alloc(nvme_root_t r, nvme_subsystem_t s,
				   const char *path, const char *name)
{
	nvme_ctrl_t c, p;
	_cleanup_free_ char *addr = NULL, *address = NULL;
	char *a = NULL, *e = NULL;
	_cleanup_free_ char *transport = NULL;
	char *traddr = NULL, *trsvcid = NULL;
	char *host_traddr = NULL, *host_iface = NULL;
	int ret;

	transport = nvme_get_attr(path, "transport");
	if (!transport) {
		errno = ENXIO;
		return NULL;
	}
	/* Parse 'address' string into components */
	addr = nvme_get_attr(path, "address");
	if (!addr) {
		_cleanup_free_ char *rpath = NULL;
		char *p = NULL, *_a = NULL;

		/* loop transport might not have an address */
		if (!strcmp(transport, "loop"))
			goto skip_address;

		/* Older kernel don't support pcie transport addresses */
		if (strcmp(transport, "pcie")) {
			errno = ENXIO;
			return NULL;
		}
		/* Figure out the PCI address from the attribute path */
		rpath = realpath(path, NULL);
		if (!rpath) {
			errno = ENOMEM;
			return NULL;
		}
		a = strtok_r(rpath, "/", &e);
		while(a && strlen(a)) {
		    if (_a)
			p = _a;
		    _a = a;
		    if (!strncmp(a, "nvme", 4))
			break;
		    a = strtok_r(NULL, "/", &e);
		}
		if (p)
			addr = strdup(p);
	} else if (!strcmp(transport, "pcie")) {
		/* The 'address' string is the transport address */
		traddr = addr;
	} else {
		address = strdup(addr);
		a = strtok_r(address, ",", &e);
		while (a && strlen(a)) {
			if (!strncmp(a, "traddr=", 7))
				traddr = a + 7;
			else if (!strncmp(a, "trsvcid=", 8))
				trsvcid = a + 8;
			else if (!strncmp(a, "host_traddr=", 12))
				host_traddr = a + 12;
			else if (!strncmp(a, "host_iface=", 11))
				host_iface = a + 11;
			a = strtok_r(NULL, ",", &e);
		}
	}
skip_address:
	p = NULL;
	do {
		c = nvme_lookup_ctrl(s, transport, traddr,
				     host_traddr, host_iface, trsvcid, p);
		if (c) {
			if (!c->name)
				break;
			if (!strcmp(c->name, name)) {
				nvme_msg(r, LOG_DEBUG,
					 "found existing ctrl %s\n", c->name);
				break;
			}
			nvme_msg(r, LOG_DEBUG, "skipping ctrl %s\n", c->name);
			p = c;
		}
	} while (c);
	if (!c)
		c = p;
	if (!c && !p) {
		nvme_msg(r, LOG_ERR, "failed to lookup ctrl\n");
		errno = ENODEV;
		return NULL;
	}
	c->address = addr;
	addr = NULL;
	if (s->subsystype && !strcmp(s->subsystype, "discovery"))
		c->discovery_ctrl = true;
	ret = nvme_configure_ctrl(r, c, path, name);
	return (ret < 0) ? NULL : c;
}

nvme_ctrl_t nvme_scan_ctrl(nvme_root_t r, const char *name)
{
	nvme_host_t h;
	nvme_subsystem_t s;
	nvme_ctrl_t c;
	_cleanup_free_ char *path = NULL;
	_cleanup_free_ char *hostnqn = NULL, *hostid = NULL;
	_cleanup_free_ char *subsysnqn = NULL, *subsysname = NULL;
	int ret;

	nvme_msg(r, LOG_DEBUG, "scan controller %s\n", name);
	ret = asprintf(&path, "%s/%s", nvme_ctrl_sysfs_dir(), name);
	if (ret < 0) {
		errno = ENOMEM;
		return NULL;
	}

	hostnqn = nvme_get_attr(path, "hostnqn");
	hostid = nvme_get_attr(path, "hostid");
	h = nvme_lookup_host(r, hostnqn, hostid);
	if (h) {
		if (h->dhchap_key)
			free(h->dhchap_key);
		h->dhchap_key = nvme_get_attr(path, "dhchap_secret");
		if (h->dhchap_key && !strcmp(h->dhchap_key, "none")) {
			free(h->dhchap_key);
			h->dhchap_key = NULL;
		}
	}
	if (!h) {
		h = nvme_default_host(r);
		if (!h) {
			errno = ENOMEM;
			return NULL;
		}
	}

	subsysnqn = nvme_get_attr(path, "subsysnqn");
	if (!subsysnqn) {
		errno = ENXIO;
		return NULL;
	}
	subsysname = nvme_ctrl_lookup_subsystem_name(r, name);
	if (!subsysname) {
		nvme_msg(r, LOG_DEBUG,
			 "failed to lookup subsystem for controller %s\n",
			 name);
		errno = ENXIO;
		return NULL;
	}
	s = nvme_lookup_subsystem(h, subsysname, subsysnqn);

	if (!s) {
		errno = ENOMEM;
		return NULL;
	}

	c = nvme_ctrl_alloc(r, s, path, name);
	if (!c)
		return NULL;

	path = NULL;
	nvme_ctrl_scan_namespaces(r, c);
	nvme_ctrl_scan_paths(r, c);
	return c;
}

void nvme_rescan_ctrl(struct nvme_ctrl *c)
{
	nvme_root_t r = c->s && c->s->h ? c->s->h->r : NULL;
	if (!c->s)
		return;
	nvme_ctrl_scan_namespaces(r, c);
	nvme_ctrl_scan_paths(r, c);
	nvme_subsystem_scan_namespaces(r, c->s, NULL, NULL);
}

static int nvme_bytes_to_lba(nvme_ns_t n, off_t offset, size_t count,
			    __u64 *lba, __u16 *nlb)
{
	int bs;

	bs = nvme_ns_get_lba_size(n);
	if (!count || offset & (bs - 1) || count & (bs - 1)) {
		errno = EINVAL;
		return -1;
	}

	*lba = offset >> n->lba_shift;
	*nlb = (count >> n->lba_shift) - 1;
	return 0;
}

int nvme_ns_get_fd(nvme_ns_t n)
{
	if (n->fd < 0) {
		n->fd = nvme_open(n->name);
		if (n->fd < 0)
			nvme_msg(root_from_ns(n), LOG_ERR,
				 "Failed to open ns %s, errno %d\n",
				 n->name, errno);
	}

	return n->fd;
}

void nvme_ns_release_fd(nvme_ns_t n)
{
	if (n->fd < 0)
		return;

	close(n->fd);
	n->fd = -1;
}

nvme_subsystem_t nvme_ns_get_subsystem(nvme_ns_t n)
{
	return n->s;
}

nvme_ctrl_t nvme_ns_get_ctrl(nvme_ns_t n)
{
	return n->c;
}

int nvme_ns_get_nsid(nvme_ns_t n)
{
	return n->nsid;
}

const char *nvme_ns_get_sysfs_dir(nvme_ns_t n)
{
	return n->sysfs_dir;
}

const char *nvme_ns_get_name(nvme_ns_t n)
{
	return n->name;
}

const char *nvme_ns_get_generic_name(nvme_ns_t n)
{
	return n->generic_name;
}

const char *nvme_ns_get_model(nvme_ns_t n)
{
	return n->c ? n->c->model : n->s->model;
}

const char *nvme_ns_get_serial(nvme_ns_t n)
{
	return n->c ? n->c->serial : n->s->serial;
}

const char *nvme_ns_get_firmware(nvme_ns_t n)
{
	return n->c ? n->c->firmware : n->s->firmware;
}

int nvme_ns_get_lba_size(nvme_ns_t n)
{
	return n->lba_size;
}

int nvme_ns_get_meta_size(nvme_ns_t n)
{
	return n->meta_size;
}

uint64_t nvme_ns_get_lba_count(nvme_ns_t n)
{
	return n->lba_count;
}

uint64_t nvme_ns_get_lba_util(nvme_ns_t n)
{
	return n->lba_util;
}

enum nvme_csi nvme_ns_get_csi(nvme_ns_t n)
{
	return n->csi;
}

const uint8_t *nvme_ns_get_eui64(nvme_ns_t n)
{
	return n->eui64;
}

const uint8_t *nvme_ns_get_nguid(nvme_ns_t n)
{
	return n->nguid;
}

void nvme_ns_get_uuid(nvme_ns_t n, unsigned char out[NVME_UUID_LEN])
{
	memcpy(out, n->uuid, NVME_UUID_LEN);
}

int nvme_ns_identify(nvme_ns_t n, struct nvme_id_ns *ns)
{
	return nvme_identify_ns(nvme_ns_get_fd(n), nvme_ns_get_nsid(n), ns);
}

int nvme_ns_identify_descs(nvme_ns_t n, struct nvme_ns_id_desc *descs)
{
	return nvme_identify_ns_descs(nvme_ns_get_fd(n), nvme_ns_get_nsid(n), descs);
}

int nvme_ns_verify(nvme_ns_t n, off_t offset, size_t count)
{
	struct nvme_io_args args = {
		.args_size = sizeof(args),
		.fd = nvme_ns_get_fd(n),
		.nsid = nvme_ns_get_nsid(n),
		.control = 0,
		.dsm = 0,
		.dspec = 0,
		.reftag = 0,
		.apptag = 0,
		.appmask = 0,
		.storage_tag = 0,
		.data_len = 0,
		.data = NULL,
		.metadata_len = 0,
		.metadata = NULL,
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.result = NULL,
	};

	if (nvme_bytes_to_lba(n, offset, count, &args.slba, &args.nlb))
		return -1;

	return nvme_verify(&args);
}

int nvme_ns_write_uncorrectable(nvme_ns_t n, off_t offset, size_t count)
{
	struct nvme_io_args args = {
		.args_size = sizeof(args),
		.fd = nvme_ns_get_fd(n),
		.nsid = nvme_ns_get_nsid(n),
		.control = 0,
		.dsm = 0,
		.dspec = 0,
		.reftag = 0,
		.apptag = 0,
		.appmask = 0,
		.storage_tag = 0,
		.data_len = 0,
		.data = NULL,
		.metadata_len = 0,
		.metadata = NULL,
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.result = NULL,
	};

	if (nvme_bytes_to_lba(n, offset, count, &args.slba, &args.nlb))
		return -1;

	return nvme_write_uncorrectable(&args);
}

int nvme_ns_write_zeros(nvme_ns_t n, off_t offset, size_t count)
{
	struct nvme_io_args args = {
		.args_size = sizeof(args),
		.fd = nvme_ns_get_fd(n),
		.nsid = nvme_ns_get_nsid(n),
		.control = 0,
		.dsm = 0,
		.dspec = 0,
		.reftag = 0,
		.apptag = 0,
		.appmask = 0,
		.storage_tag = 0,
		.data_len = 0,
		.data = NULL,
		.metadata_len = 0,
		.metadata = NULL,
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.result = NULL,
	};

	if (nvme_bytes_to_lba(n, offset, count, &args.slba, &args.nlb))
		return -1;

	return nvme_write_zeros(&args);
}

int nvme_ns_write(nvme_ns_t n, void *buf, off_t offset, size_t count)
{
	struct nvme_io_args args = {
		.args_size = sizeof(args),
		.fd = nvme_ns_get_fd(n),
		.nsid = nvme_ns_get_nsid(n),
		.control = 0,
		.dsm = 0,
		.dspec = 0,
		.reftag = 0,
		.apptag = 0,
		.appmask = 0,
		.storage_tag = 0,
		.data_len = count,
		.data = buf,
		.metadata_len = 0,
		.metadata = NULL,
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.result = NULL,
	};

	if (nvme_bytes_to_lba(n, offset, count, &args.slba, &args.nlb))
		return -1;

	return nvme_write(&args);
}

int nvme_ns_read(nvme_ns_t n, void *buf, off_t offset, size_t count)
{
	struct nvme_io_args args = {
		.args_size = sizeof(args),
		.fd = nvme_ns_get_fd(n),
		.nsid = nvme_ns_get_nsid(n),
		.control = 0,
		.dsm = 0,
		.dspec = 0,
		.reftag = 0,
		.apptag = 0,
		.appmask = 0,
		.storage_tag = 0,
		.data_len = count,
		.data = buf,
		.metadata_len = 0,
		.metadata = NULL,
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.result = NULL,
	};

	if (nvme_bytes_to_lba(n, offset, count, &args.slba, &args.nlb))
		return -1;

	return nvme_read(&args);
}

int nvme_ns_compare(nvme_ns_t n, void *buf, off_t offset, size_t count)
{
	struct nvme_io_args args = {
		.args_size = sizeof(args),
		.fd = nvme_ns_get_fd(n),
		.nsid = nvme_ns_get_nsid(n),
		.control = 0,
		.dsm = 0,
		.dspec = 0,
		.reftag = 0,
		.apptag = 0,
		.appmask = 0,
		.storage_tag = 0,
		.data_len = count,
		.data = buf,
		.metadata_len = 0,
		.metadata = NULL,
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.result = NULL,
	};

	if (nvme_bytes_to_lba(n, offset, count, &args.slba, &args.nlb))
		return -1;

	return nvme_compare(&args);
}

int nvme_ns_flush(nvme_ns_t n)
{
	return nvme_flush(nvme_ns_get_fd(n), nvme_ns_get_nsid(n));
}

static int nvme_strtou64(const char *str, void *res)
{
	char *endptr;
	__u64 v;

	errno = 0;
	v = strtoull(str, &endptr, 0);

	if (errno != 0)
		return -errno;

	if (endptr == str) {
		/* no digits found */
		return -EINVAL;
	}

	*(__u64 *)res = v;
	return 0;
}

static int nvme_strtou32(const char *str, void *res)
{
	char *endptr;
	__u32 v;

	errno = 0;
	v = strtol(str, &endptr, 0);

	if (errno != 0)
		return -errno;

	if (endptr == str) {
		/* no digits found */
		return -EINVAL;
	}

	*(__u32 *)res = v;
	return 0;
}

static int nvme_strtoi(const char *str, void *res)
{
	char *endptr;
	int v;

	errno = 0;
	v = strtol(str, &endptr, 0);

	if (errno != 0)
		return -errno;

	if (endptr == str) {
		/* no digits found */
		return -EINVAL;
	}

	*(int *)res = v;
	return 0;
}

static int nvme_strtoeuid(const char *str, void *res)
{
	memcpy(res, str, 8);
	return 0;
}

static int nvme_strtouuid(const char *str, void *res)
{
	memcpy(res, str, NVME_UUID_LEN);
	return 0;
}

struct sysfs_attr_table {
	void *var;
	int (*parse)(const char *str, void *res);
	bool mandatory;
	const char *name;
};

#define GETSHIFT(x) (__builtin_ffsll(x) - 1)
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

static int parse_attrs(const char *path, struct sysfs_attr_table *tbl, int size)
{
	char *str;
	int ret, i;

	for (i = 0; i < size; i++) {
		struct sysfs_attr_table *e = &tbl[i];

		str = nvme_get_attr(path, e->name);
		if (!str) {
			if (!e->mandatory)
				continue;
			return -ENOENT;
		}
		ret = e->parse(str, e->var);
		free(str);
		if (ret)
			return ret;
	}

	return 0;
}

static int nvme_ns_init(const char *path, struct nvme_ns *ns)
{
	_cleanup_free_ char *attr = NULL;
	struct stat sb;
	uint64_t size;
	int ret;

	struct sysfs_attr_table base[] = {
		{ &ns->nsid,      nvme_strtou32,  true, "nsid" },
		{ &size,          nvme_strtou64,  true, "size" },
		{ &ns->lba_size,  nvme_strtou32,  true, "queue/logical_block_size" },
		{ ns->eui64,      nvme_strtoeuid, false, "eui" },
		{ ns->nguid,      nvme_strtouuid, false, "nguid" },
		{ ns->uuid,       nvme_strtouuid, false, "uuid" }
	};

	ret = parse_attrs(path, base, ARRAY_SIZE(base));
	if (ret)
		return ret;

	ns->lba_shift = GETSHIFT(ns->lba_size);
	/*
	 * size is in 512 bytes units and lba_count is in lba_size which are not
	 * necessarily the same.
	 */
	ns->lba_count = size >> (ns->lba_shift -  SECTOR_SHIFT);

	if (asprintf(&attr, "%s/csi", path) < 0)
		return -errno;
	ret = stat(attr, &sb);
	if (ret == 0) {
		/* only available on kernels >= 6.8 */
		struct sysfs_attr_table ext[] = {
			{ &ns->csi,       nvme_strtoi,	 true, "csi" },
			{ &ns->lba_util,  nvme_strtou64, true, "nuse" },
			{ &ns->meta_size, nvme_strtoi,	 true, "metadata_bytes"},

		};

		ret = parse_attrs(path, ext, ARRAY_SIZE(ext));
		if (ret)
			return ret;
	} else {
		_cleanup_free_ struct nvme_id_ns *id = NULL;
		uint8_t flbas;

		id = __nvme_alloc(sizeof(*ns));
		if (!id)
			return -ENOMEM;

		ret = nvme_ns_identify(ns, id);
		if (ret)
			return ret;

		nvme_id_ns_flbas_to_lbaf_inuse(id->flbas, &flbas);
		ns->lba_count = le64_to_cpu(id->nsze);
		ns->lba_util = le64_to_cpu(id->nuse);
		ns->meta_size = le16_to_cpu(id->lbaf[flbas].ms);
	}

	return 0;
}

static void nvme_ns_set_generic_name(struct nvme_ns *n, const char *name)
{
	char generic_name[PATH_MAX];
	int instance, head_instance;
	int ret;

	ret = sscanf(name, "nvme%dn%d", &instance, &head_instance);
	if (ret != 2)
		return;

	sprintf(generic_name, "ng%dn%d", instance, head_instance);
	n->generic_name = strdup(generic_name);
}

static nvme_ns_t nvme_ns_open(const char *sys_path, const char *name)
{
	struct nvme_ns *n;

	n = calloc(1, sizeof(*n));
	if (!n) {
		errno = ENOMEM;
		return NULL;
	}

	n->fd = -1;
	n->name = strdup(name);

	nvme_ns_set_generic_name(n, name);

	if (nvme_ns_init(sys_path, n) != 0)
		goto free_ns;

	list_head_init(&n->paths);
	list_node_init(&n->entry);

	nvme_ns_release_fd(n); /* Do not leak fds */
	return n;

free_ns:
	free(n->generic_name);
	free(n->name);
	free(n);
	return NULL;
}

static inline bool nvme_ns_is_generic(const char *name)
{
	int instance, head_instance;

	if (sscanf(name, "ng%dn%d", &instance, &head_instance) != 2)
		return false;
	return true;
}

static char *nvme_ns_generic_to_blkdev(const char *generic)
{

	int instance, head_instance;
	char blkdev[PATH_MAX];

	if (!nvme_ns_is_generic(generic))
		return strdup(generic);

	sscanf(generic, "ng%dn%d", &instance, &head_instance);
	sprintf(blkdev, "nvme%dn%d", instance, head_instance);

	return strdup(blkdev);
}

static struct nvme_ns *__nvme_scan_namespace(const char *sysfs_dir, const char *name)
{
	struct nvme_ns *n;
	_cleanup_free_ char *path = NULL;
	int ret;
	_cleanup_free_ char *blkdev = NULL;

	blkdev = nvme_ns_generic_to_blkdev(name);
	if (!blkdev) {
		errno = ENOMEM;
		return NULL;
	}

	ret = asprintf(&path, "%s/%s", sysfs_dir, blkdev);
	if (ret < 0) {
		errno = ENOMEM;
		return NULL;
	}

	n = nvme_ns_open(path, blkdev);
	if (!n)
		return NULL;

	n->sysfs_dir = path;
	path = NULL;

	return n;
}

nvme_ns_t nvme_scan_namespace(const char *name)
{
	return __nvme_scan_namespace(nvme_ns_sysfs_dir(), name);
}

static int nvme_ctrl_scan_namespace(nvme_root_t r, struct nvme_ctrl *c,
				    char *name)
{
	struct nvme_ns *n, *_n, *__n;

	nvme_msg(r, LOG_DEBUG, "scan controller %s namespace %s\n",
		 c->name, name);
	if (!c->s) {
		nvme_msg(r, LOG_DEBUG, "no subsystem for %s\n", name);
		errno = EINVAL;
		return -1;
	}
	n = __nvme_scan_namespace(c->sysfs_dir, name);
	if (!n) {
		nvme_msg(r, LOG_DEBUG, "failed to scan namespace %s\n", name);
		return -1;
	}
	nvme_ctrl_for_each_ns_safe(c, _n, __n) {
		if (strcmp(n->name, _n->name))
			continue;
		__nvme_free_ns(_n);
	}
	n->s = c->s;
	n->c = c;
	list_add_tail(&c->namespaces, &n->entry);
	return 0;
}

static void nvme_subsystem_set_ns_path(nvme_subsystem_t s, nvme_ns_t n)
{
	nvme_ctrl_t c;
	nvme_path_t p;
	int ns_ctrl, ns_nsid, ret;

	ret = sscanf(nvme_ns_get_name(n), "nvme%dn%d", &ns_ctrl, &ns_nsid);
	if (ret != 2)
		return;

	nvme_subsystem_for_each_ctrl(s, c) {
		nvme_ctrl_for_each_path(c, p) {
			int p_subsys, p_ctrl, p_nsid;

			ret = sscanf(nvme_path_get_name(p), "nvme%dc%dn%d",
				     &p_subsys, &p_ctrl, &p_nsid);
			if (ret != 3)
				continue;
			if (ns_ctrl == p_subsys && ns_nsid == p_nsid) {
				list_add_tail(&n->paths, &p->nentry);
				p->n = n;
			}
		}
	}
}

static int nvme_subsystem_scan_namespace(nvme_root_t r, nvme_subsystem_t s,
		char *name, nvme_scan_filter_t f, void *f_args)
{
	struct nvme_ns *n, *_n, *__n;

	nvme_msg(r, LOG_DEBUG, "scan subsystem %s namespace %s\n",
		 s->name, name);
	n = __nvme_scan_namespace(s->sysfs_dir, name);
	if (!n) {
		nvme_msg(r, LOG_DEBUG, "failed to scan namespace %s\n", name);
		return -1;
	}
	if (f && !f(NULL, NULL, n, f_args)) {
		nvme_msg(r, LOG_DEBUG, "filter out namespace %s\n", name);
		__nvme_free_ns(n);
		return 0;
	}
	nvme_subsystem_for_each_ns_safe(s, _n, __n) {
		struct nvme_path *p, *_p;

		if (strcmp(n->name, _n->name))
			continue;
		/* Detach paths */
		nvme_namespace_for_each_path_safe(_n, p, _p) {
			list_del_init(&p->nentry);
			p->n = NULL;
		}
		list_head_init(&_n->paths);
		__nvme_free_ns(_n);
	}
	n->s = s;
	list_add_tail(&s->namespaces, &n->entry);
	nvme_subsystem_set_ns_path(s, n);
	return 0;
}

struct nvme_ns *nvme_subsystem_lookup_namespace(struct nvme_subsystem *s,
						__u32 nsid)
{
	struct nvme_ns *n;

	nvme_subsystem_for_each_ns(s, n) {
		if (nvme_ns_get_nsid(n) == nsid)
			return n;
	}
	return NULL;
}
