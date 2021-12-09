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

#include <sys/types.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <ccan/endian/endian.h>
#include <ccan/list/list.h>

#include "ioctl.h"
#include "linux.h"
#include "filters.h"
#include "tree.h"
#include "filters.h"
#include "util.h"
#include "fabrics.h"
#include "log.h"
#include "private.h"

static struct nvme_host *default_host;

static void __nvme_free_host(nvme_host_t h);
static void __nvme_free_ctrl(nvme_ctrl_t c);
static int nvme_subsystem_scan_namespace(struct nvme_subsystem *s, char *name);
static int nvme_scan_subsystem(struct nvme_root *r, char *name,
			       nvme_scan_filter_t f);
static int nvme_subsystem_scan_ctrl(struct nvme_subsystem *s, char *name);
static int nvme_ctrl_scan_namespace(struct nvme_ctrl *c, char *name);
static int nvme_ctrl_scan_path(struct nvme_ctrl *c, char *name);

static inline void nvme_free_dirents(struct dirent **d, int i)
{
	while (i-- > 0)
		free(d[i]);
	free(d);
}

nvme_host_t nvme_default_host(nvme_root_t r)
{
	struct nvme_host *h;
	char *hostnqn, *hostid;

	hostnqn = nvmf_hostnqn_from_file();
	if (!hostnqn)
		hostnqn = nvmf_hostnqn_generate();
	hostid = nvmf_hostid_from_file();

	h = nvme_lookup_host(r, hostnqn, hostid);
	default_host = h;
	free(hostnqn);
	if (hostid)
		free(hostid);
	return h;
}

static int nvme_scan_topology(struct nvme_root *r, nvme_scan_filter_t f)
{
	struct dirent **subsys;
	int i, num_subsys, ret;

	num_subsys = nvme_scan_subsystems(&subsys);
	if (num_subsys < 0) {
		nvme_msg(LOG_DEBUG, "failed to scan subsystems: %s\n",
			 strerror(errno));
		return num_subsys;
	}

	for (i = 0; i < num_subsys; i++) {
		ret = nvme_scan_subsystem(r, subsys[i]->d_name, f);
		if (ret < 0) {
			nvme_msg(LOG_DEBUG, "failed to scan subsystem %s: %s\n",
				 subsys[i]->d_name, strerror(errno));
		}
	}

	nvme_free_dirents(subsys, i);
	return 0;
}

nvme_root_t nvme_scan_filter(nvme_scan_filter_t f)
{
	struct nvme_root *r = calloc(1, sizeof(*r));

	if (!r) {
		errno = ENOMEM;
		return NULL;
	}

	list_head_init(&r->hosts);
	nvme_scan_topology(r, f);
	return r;
}

nvme_root_t nvme_scan(const char *config_file)
{
	nvme_root_t r = nvme_scan_filter(NULL);

#ifdef CONFIG_JSONC
	if (r && config_file) {
		json_read_config(r, config_file);
		r->config_file = strdup(config_file);
	}
#endif
	return r;
}

int nvme_update_config(nvme_root_t r)
{
	if (!r->modified || !r->config_file)
		return 0;
#ifdef CONFIG_JSONC
	return json_update_config(r, r->config_file);
#else
	errno = ENOTSUP;
	return -1;
#endif
}

int nvme_dump_config(nvme_root_t r)
{
#ifdef CONFIG_JSONC
	return json_update_config(r, NULL);
#else
	errno = ENOTSUP;
	return -1;
#endif
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
	nvme_scan_topology(r, NULL);
}

void nvme_reset_topology(nvme_root_t r)
{
	struct nvme_host *h, *_h;

	nvme_for_each_host_safe(r, h, _h)
		__nvme_free_host(h);
	nvme_scan_topology(r, NULL);
}

void nvme_free_tree(nvme_root_t r)
{
	struct nvme_host *h, *_h;

	nvme_for_each_host_safe(r, h, _h)
		__nvme_free_host(h);
	if (r->config_file)
		free(r->config_file);
	free(r);
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

static void __nvme_free_ns(struct nvme_ns *n)
{
	list_del_init(&n->entry);
	close(n->fd);
	free(n->name);
	free(n->sysfs_dir);
	free(n);
}

/* Stub for SWIG */
void nvme_free_ns(struct nvme_ns *n)
{
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
	free(s);
}

/*
 * Stub for SWIG
 */
void nvme_free_subsystem(nvme_subsystem_t s)
{
}

struct nvme_subsystem *nvme_lookup_subsystem(struct nvme_host *h,
					     const char *name,
					     const char *subsysnqn)
{
	struct nvme_subsystem *s;

	nvme_for_each_subsystem(h, s) {
		if (strcmp(s->subsysnqn, subsysnqn))
			continue;
		if (name && s->name &&
		    strcmp(s->name, name))
			continue;
		return s;
	}
	s = calloc(1, sizeof(*s));
	if (!s)
		return NULL;

	s->h = h;
	s->subsysnqn = strdup(subsysnqn);
	list_head_init(&s->ctrls);
	list_head_init(&s->namespaces);
	list_node_init(&s->entry);
	list_add(&h->subsystems, &s->entry);
	h->r->modified = true;
	return s;
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
	h->r->modified = true;
	free(h);
}

/* Stub for SWIG */
void nvme_free_host(struct nvme_host *h)
{
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
	list_add(&r->hosts, &h->entry);
	r->modified = true;

	return h;
}

static int nvme_subsystem_scan_namespaces(struct nvme_subsystem *s)
{
	struct dirent **namespaces;
	int i, num_ns, ret;

	num_ns = nvme_scan_subsystem_namespaces(s, &namespaces);
	if (num_ns < 0) {
		nvme_msg(LOG_DEBUG,
			 "failed to scan namespaces for subsys %s: %s\n",
			 s->subsysnqn, strerror(errno));
		return num_ns;
	}

	for (i = 0; i < num_ns; i++) {
		ret = nvme_subsystem_scan_namespace(s, namespaces[i]->d_name);
		if (ret < 0)
			nvme_msg(LOG_DEBUG,
				 "failed to scan namespace %s: %s\n",
				 namespaces[i]->d_name, strerror(errno));
	}

	nvme_free_dirents(namespaces, i);
	return 0;
}

static int nvme_subsystem_scan_ctrls(struct nvme_subsystem *s)
{
	struct dirent **ctrls;
	int i, num_ctrls, ret;

	num_ctrls = nvme_scan_subsystem_ctrls(s, &ctrls);
	if (num_ctrls < 0) {
		nvme_msg(LOG_DEBUG,
			 "failed to scan ctrls for subsys %s: %s\n",
			 s->subsysnqn, strerror(errno));
		return num_ctrls;
	}

	for (i = 0; i < num_ctrls; i++) {
		ret = nvme_subsystem_scan_ctrl(s, ctrls[i]->d_name);
		if (ret < 0)
			nvme_msg(LOG_DEBUG,
				 "failed to scan ctrl %s: %s\n",
				 ctrls[i]->d_name, strerror(errno));
	}

	nvme_free_dirents(ctrls, i);
	return 0;
}

static int nvme_init_subsystem(nvme_subsystem_t s, const char *name,
			       const char *path)
{
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

	return 0;
}

static int nvme_scan_subsystem(struct nvme_root *r, char *name,
			       nvme_scan_filter_t f)
{
	struct nvme_subsystem *s;
	char *path, *subsysnqn;
	char *hostnqn, *hostid = NULL;
	nvme_host_t h = NULL;
	int ret;

	ret = asprintf(&path, "%s/%s", nvme_subsys_sysfs_dir, name);
	if (ret < 0)
		return ret;

	hostnqn = nvme_get_attr(path, "hostnqn");
	if (hostnqn) {
		hostid = nvme_get_attr(path, "hostid");
		h = nvme_lookup_host(r, hostnqn, hostid);
		free(hostnqn);
		if (hostid)
			free(hostid);
		if (h) {
			if (h->dhchap_key)
				free(h->dhchap_key);
			h->dhchap_key = nvme_get_attr(path, "dhchap_secret");
		}
	}
	if (!h)
		h = nvme_default_host(r);
	if (!h) {
		errno = ENOMEM;
		return -1;
	}
	subsysnqn = nvme_get_attr(path, "subsysnqn");
	if (!subsysnqn) {
		errno = ENODEV;
		goto free_path;
	}
	s = nvme_lookup_subsystem(h, name, subsysnqn);
	free(subsysnqn);
	if (!s) {
		errno = ENOMEM;
		goto free_path;
	}
	if (!s->name) {
		ret = nvme_init_subsystem(s, name, path);
		if (ret < 0)
			goto free_path;
	}

	nvme_subsystem_scan_namespaces(s);
	nvme_subsystem_scan_ctrls(s);

	if (f && !f(s)) {
		__nvme_free_subsystem(s);
		return -1;
	}

	return 0;

free_path:
	free(path);
	return -1;
}

nvme_ctrl_t nvme_path_get_subsystem(nvme_path_t p)
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
			list_add(&n->paths, &p->nentry);
			p->n = n;
		}
	}
}

static int nvme_ctrl_scan_path(struct nvme_ctrl *c, char *name)
{
	struct nvme_path *p;
	char *path, *grpid;
	int ret;

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
		goto free_path;
	}

	p->c = c;
	p->name = strdup(name);
	p->sysfs_dir = path;
	p->ana_state = nvme_get_path_attr(p, "ana_state");
	if (!p->ana_state)
		p->ana_state = strdup("optimized");

	grpid = nvme_get_path_attr(p, "ana_grpid");
	if (grpid) {
		sscanf(grpid, "%d", &p->grpid);
		free(grpid);
	}

	list_node_init(&p->nentry);
	nvme_subsystem_set_path_ns(c->s, p);
	list_node_init(&p->entry);
	list_add(&c->paths, &p->entry);
	return 0;

free_path:
	free(path);
	return -1;
}

int nvme_ctrl_get_fd(nvme_ctrl_t c)
{
	return c->fd;
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
	return c->address;
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
	return c->host_traddr;
}

const char *nvme_ctrl_get_host_iface(nvme_ctrl_t c)
{
	return c->host_iface;
}

struct nvme_fabrics_config *nvme_ctrl_get_config(nvme_ctrl_t c)
{
	return &c->cfg;
}

const char *nvme_ctrl_get_dhchap_key(nvme_ctrl_t c)
{
	return c->dhchap_key;
}

void nvme_ctrl_set_dhchap_key(nvme_ctrl_t c, const char *key)
{
	if (c->dhchap_key) {
		free(c->dhchap_key);
		c->dhchap_key = NULL;
	}
	if (key)
		c->dhchap_key = strdup(key);
}

void nvme_ctrl_disable_sqflow(nvme_ctrl_t c, bool disable_sqflow)
{
	c->cfg.disable_sqflow = disable_sqflow;
	if (c->s && c->s->h && c->s->h->r)
		c->s->h->r->modified = true;
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
	if (c->fd >= 0) {
		close(c->fd);
		c->fd = -1;
	}
	FREE_CTRL_ATTR(c->name);
	FREE_CTRL_ATTR(c->sysfs_dir);
	FREE_CTRL_ATTR(c->firmware);
	FREE_CTRL_ATTR(c->model);
	FREE_CTRL_ATTR(c->state);
	FREE_CTRL_ATTR(c->numa_node);
	FREE_CTRL_ATTR(c->queue_count);
	FREE_CTRL_ATTR(c->serial);
	FREE_CTRL_ATTR(c->sqsize);
	FREE_CTRL_ATTR(c->address);
}

int nvme_disconnect_ctrl(nvme_ctrl_t c)
{
	int ret;

	ret = nvme_set_attr(nvme_ctrl_get_sysfs_dir(c),
			    "delete_controller", "1");
	if (ret < 0) {
		nvme_msg(LOG_ERR, "%s: failed to disconnect, error %d\n",
			 c->name, errno);
		return ret;
	}
	nvme_msg(LOG_INFO, "%s: disconnected\n", c->name);
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
	FREE_CTRL_ATTR(c->host_traddr);
	FREE_CTRL_ATTR(c->host_iface);
	FREE_CTRL_ATTR(c->trsvcid);
	free(c);
}

void nvme_free_ctrl(nvme_ctrl_t c)
{
	__nvme_free_ctrl(c);
}

#define ____stringify(x...) #x
#define __stringify(x...) ____stringify(x)

static void discovery_trsvcid(nvme_ctrl_t c)
{
	if (!strcmp(c->transport, "tcp")) {
		/* Default port for NVMe/TCP discovery controllers */
		c->trsvcid = strdup(__stringify(NVME_DISC_IP_PORT));
	} else if (!strcmp(c->transport, "rdma")) {
		/* Default port for NVMe/RDMA controllers */
		c->trsvcid = strdup(__stringify(NVME_RDMA_IP_PORT));
	}
}

static bool traddr_is_hostname(const char *transport, const char *traddr)
{
	char addrstr[NVMF_TRADDR_SIZE];

	if (!traddr || !transport)
		return false;
	if (strcmp(transport, "tcp") &&
	    strcmp(transport, "rdma"))
		return false;
	if (inet_pton(AF_INET, traddr, addrstr) > 0 ||
	    inet_pton(AF_INET6, traddr, addrstr) > 0)
		return false;
	return true;
}

void hostname2traddr(nvme_ctrl_t c, const char *host_traddr)
{
	struct addrinfo *host_info, hints = {.ai_family = AF_UNSPEC};
	char addrstr[NVMF_TRADDR_SIZE];
	const char *p;
	int ret;

	ret = getaddrinfo(host_traddr, NULL, &hints, &host_info);
	if (ret) {
		nvme_msg(LOG_DEBUG, "failed to resolve host %s info\n",
			 host_traddr);
		c->host_traddr = strdup(host_traddr);
		return;
	}

	switch (host_info->ai_family) {
	case AF_INET:
		p = inet_ntop(host_info->ai_family,
			&(((struct sockaddr_in *)host_info->ai_addr)->sin_addr),
			addrstr, NVMF_TRADDR_SIZE);
		break;
	case AF_INET6:
		p = inet_ntop(host_info->ai_family,
			&(((struct sockaddr_in6 *)host_info->ai_addr)->sin6_addr),
			addrstr, NVMF_TRADDR_SIZE);
		break;
	default:
		nvme_msg(LOG_DEBUG, "unrecognized address family (%d) %s\n",
			 host_info->ai_family, c->traddr);
		c->host_traddr = strdup(host_traddr);
		goto free_addrinfo;
	}
	if (!p) {
		nvme_msg(LOG_DEBUG, "failed to get traddr for %s\n",
			 c->traddr);
		c->host_traddr = strdup(host_traddr);
	} else
		c->host_traddr = strdup(addrstr);

free_addrinfo:
	freeaddrinfo(host_info);
}

struct nvme_ctrl *nvme_create_ctrl(const char *subsysnqn, const char *transport,
				   const char *traddr, const char *host_traddr,
				   const char *host_iface, const char *trsvcid)
{
	struct nvme_ctrl *c;
	bool discovery = false;

	if (!transport) {
		nvme_msg(LOG_ERR, "No transport specified\n");
		errno = EINVAL;
		return NULL;
	}
	if (strncmp(transport, "loop", 4) &&
	    strncmp(transport, "pcie", 4) && !traddr) {
               nvme_msg(LOG_ERR, "No transport address for '%s'\n", transport);
	       errno = EINVAL;
	       return NULL;
	}
	if (!subsysnqn) {
		nvme_msg(LOG_ERR, "No subsystem NQN specified\n");
		errno = EINVAL;
		return NULL;
	} else if (!strcmp(subsysnqn, NVME_DISC_SUBSYS_NAME))
		discovery = true;
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
			hostname2traddr(c, host_traddr);
		else
			c->host_traddr = strdup(host_traddr);
	}
	if (host_iface)
		c->host_iface = strdup(host_iface);
	if (trsvcid)
		c->trsvcid = strdup(trsvcid);
	else if (discovery)
		discovery_trsvcid(c);
	else if (!strncmp(transport, "rdma", 4) ||
		 !strncmp(transport, "tcp", 3)) {
		nvme_msg(LOG_ERR, "No trsvcid specified for '%s'\n",
			 transport);
		errno = EINVAL;
		__nvme_free_ctrl(c);
		c = NULL;
	}

	return c;
}

struct nvme_ctrl *nvme_lookup_ctrl(struct nvme_subsystem *s, const char *transport,
				   const char *traddr, const char *host_traddr,
				   const char *host_iface, const char *trsvcid)
{
	struct nvme_ctrl *c;

	if (!s || !transport)
		return NULL;
	nvme_subsystem_for_each_ctrl(s, c) {
		if (strcmp(c->transport, transport))
			continue;
		if (traddr && c->traddr &&
		    strcmp(c->traddr, traddr))
			continue;
		if (host_traddr && c->host_traddr &&
		    strcmp(c->host_traddr, host_traddr))
			continue;
		if (host_iface && c->host_iface &&
		    strcmp(c->host_iface, host_iface))
			continue;
		if (trsvcid && c->trsvcid &&
		    strcmp(c->trsvcid, trsvcid))
			continue;
		return c;
	}
	c = nvme_create_ctrl(s->subsysnqn, transport, traddr,
			     host_traddr, host_iface, trsvcid);
	if (c) {
		c->s = s;
		list_add(&s->ctrls, &c->entry);
		s->h->r->modified = true;
	}
	return c;
}

static int nvme_ctrl_scan_paths(struct nvme_ctrl *c)
{
	struct dirent **paths;
	int i, ret;

	ret = nvme_scan_ctrl_namespace_paths(c, &paths);
	if (ret < 0)
		return ret;

	for (i = 0; i < ret; i++)
		nvme_ctrl_scan_path(c, paths[i]->d_name);

	nvme_free_dirents(paths, i);
	return 0;
}

static int nvme_ctrl_scan_namespaces(struct nvme_ctrl *c)
{
	struct dirent **namespaces;
	int i, ret;

	ret = nvme_scan_ctrl_namespaces(c, &namespaces);
	for (i = 0; i < ret; i++)
		nvme_ctrl_scan_namespace(c, namespaces[i]->d_name);

	nvme_free_dirents(namespaces, i);
	return 0;
}

static char *nvme_ctrl_lookup_subsystem_name(nvme_ctrl_t c)
{
	struct dirent **subsys;
	char *subsys_name = NULL;
	int ret, i;
	char path[PATH_MAX];

	ret = nvme_scan_subsystems(&subsys);
	if (ret < 0)
		return NULL;
	for (i = 0; i < ret; i++) {
		struct stat st;

		sprintf(path, "%s/%s/%s", nvme_subsys_sysfs_dir,
			subsys[i]->d_name, c->name);
		nvme_msg(LOG_DEBUG, "lookup subsystem %s\n", path);
		if (stat(path, &st) < 0)
			continue;
		subsys_name = strdup(subsys[i]->d_name);
		break;
	}
	nvme_free_dirents(subsys, ret);
	return subsys_name;
}

static int nvme_configure_ctrl(nvme_ctrl_t c, const char *path,
			       const char *name)
{
	DIR *d;

	d = opendir(path);
	if (!d) {
		errno = ENODEV;
		return -1;
	}
	closedir(d);

	c->fd = nvme_open(name);
	if (c->fd < 0)
		return c->fd;

	c->name = strdup(name);
	c->sysfs_dir = (char *)path;
	c->firmware = nvme_get_ctrl_attr(c, "firmware_rev");
	c->model = nvme_get_ctrl_attr(c, "model");
	c->state = nvme_get_ctrl_attr(c, "state");
	c->numa_node = nvme_get_ctrl_attr(c, "numa_node");
	c->queue_count = nvme_get_ctrl_attr(c, "queue_count");
	c->serial = nvme_get_ctrl_attr(c, "serial");
	c->sqsize = nvme_get_ctrl_attr(c, "sqsize");
	c->dhchap_key = nvme_get_ctrl_attr(c, "dhchap_ctrl_secret");
	return 0;
}

int nvme_init_ctrl(nvme_host_t h, nvme_ctrl_t c, int instance)
{
	nvme_subsystem_t s;
	char *subsys_name = NULL;
	char *path, *name;
	int ret;

	ret = asprintf(&name, "nvme%d", instance);
	if (ret < 0) {
		errno = ENOMEM;
		return -1;
	}
	ret = asprintf(&path, "%s/nvme%d", nvme_ctrl_sysfs_dir, instance);
	if (ret < 0) {
		errno = ENOMEM;
		goto out_free_name;
	}

	ret = nvme_configure_ctrl(c, path, name);
	if (ret < 0) {
		free(path);
		goto out_free_name;
	}

	if (strcmp(c->transport, "loop")) {
		c->address = nvme_get_attr(path, "address");
		if (!c->address) {
			errno = ENXIO;
			ret = -1;
			goto out_free_name;
		}
	}

	subsys_name = nvme_ctrl_lookup_subsystem_name(c);
	if (!subsys_name) {
		nvme_msg(LOG_ERR, "Failed to lookup subsystem name for %s\n",
			 c->name);
		errno = ENXIO;
		ret = -1;
		goto out_free_name;
	}
	s = nvme_lookup_subsystem(h, subsys_name, c->subsysnqn);
	if (!s) {
		errno = ENXIO;
		ret = -1;
		goto out_free_subsys;
	}
	if (!s->name) {
		ret = asprintf(&path, "%s/%s", nvme_subsys_sysfs_dir,
			       subsys_name);
		if (ret > 0)
			ret = nvme_init_subsystem(s, subsys_name, path);
		else
			path = NULL;
		if (ret < 0) {
			nvme_msg(LOG_ERR, "Failed to init subsystem %s/%s\n",
				 nvme_subsys_sysfs_dir, subsys_name);
			if (path)
				free(path);
			goto out_free_subsys;
		}
	}
	if (s->subsystype && !strcmp(s->subsystype, "discovery"))
		c->discovery_ctrl = true;
	c->s = s;
	list_add(&s->ctrls, &c->entry);
out_free_subsys:
	free(subsys_name);
 out_free_name:
	free(name);
	return ret;
}

static nvme_ctrl_t nvme_ctrl_alloc(nvme_subsystem_t s, const char *path,
				   const char *name)
{
	nvme_ctrl_t c;
	char *addr = NULL, *address = NULL, *a, *e;
	char *transport, *traddr = NULL, *trsvcid = NULL;
	char *host_traddr = NULL, *host_iface = NULL;
	int ret;

	transport = nvme_get_attr(path, "transport");
	if (!transport) {
		errno = ENXIO;
		return NULL;
	}
	if (!strcmp(transport, "loop"))
		goto skip_address;
	/* Parse 'address' string into components */
	addr = nvme_get_attr(path, "address");
	if (!addr) {
		char *rpath = NULL, *p = NULL, *_a = NULL;

		/* Older kernel don't support pcie transport addresses */
		if (strcmp(transport, "pcie")) {
			free(transport);
			errno = ENXIO;
			return NULL;
		}
		/* Figure out the PCI address from the attribute path */
		rpath = realpath(path, NULL);
		if (!rpath) {
			free(transport);
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
		free(rpath);
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
	c = nvme_lookup_ctrl(s, transport, traddr,
			     host_traddr, host_iface, trsvcid);
	free(transport);
	if (address)
		free(address);
	if (!c) {
		errno = ENOMEM;
		return NULL;
	}
	c->address = addr;
	if (s->subsystype && !strcmp(s->subsystype, "discovery"))
		c->discovery_ctrl = true;
	ret = nvme_configure_ctrl(c, path, name);
	return (ret < 0) ? NULL : c;
}

nvme_ctrl_t nvme_scan_ctrl(nvme_root_t r, const char *name)
{
	nvme_host_t h;
	nvme_subsystem_t s;
	nvme_ctrl_t c;
	char *path;
	char *hostnqn, *hostid, *subsysnqn;
	int ret;

	ret = asprintf(&path, "%s/%s", nvme_ctrl_sysfs_dir, name);
	if (ret < 0) {
		errno = ENOMEM;
		return NULL;
	}

	hostnqn = nvme_get_attr(path, "hostnqn");
	hostid = nvme_get_attr(path, "hostid");
	h = nvme_lookup_host(r, hostnqn, hostid);
	if (hostnqn)
		free(hostnqn);
	if (hostid)
		free(hostid);
	if (h) {
		if (h->dhchap_key)
			free(h->dhchap_key);
		h->dhchap_key = nvme_get_attr(path, "dhchap_secret");
	}
	if (!h) {
		h = nvme_default_host(r);
		if (!h) {
			free(path);
			errno = ENOMEM;
			return NULL;
		}
	}

	subsysnqn = nvme_get_attr(path, "subsysnqn");
	if (!subsysnqn) {
		free(path);
		errno = ENXIO;
		return NULL;
	}
	s = nvme_lookup_subsystem(h, NULL, subsysnqn);
	free(subsysnqn);
	if (!s) {
		free(path);
		errno = ENOMEM;
		return NULL;
	}
	c = nvme_ctrl_alloc(s, path, name);
	if (!c)
		free(path);

	return c;
}

static int nvme_subsystem_scan_ctrl(struct nvme_subsystem *s, char *name)
{
	nvme_ctrl_t c;
	char *path;

	if (asprintf(&path, "%s/%s", s->sysfs_dir, name) < 0) {
		errno = ENOMEM;
		return -1;
	}

	c = nvme_ctrl_alloc(s, path, name);
	if (!c) {
		free(path);
		return -1;
	}
	nvme_ctrl_scan_namespaces(c);
	nvme_ctrl_scan_paths(c);
	return 0;
}

void nvme_rescan_ctrl(struct nvme_ctrl *c)
{
	if (!c->s)
		return;
	nvme_subsystem_scan_namespaces(c->s);
	nvme_ctrl_scan_namespaces(c);
	nvme_ctrl_scan_paths(c);
}

static int nvme_bytes_to_lba(nvme_ns_t n, off_t offset, size_t count,
			    __u64 *lba, __u16 *nlb)
{
	int bs;

	bs = nvme_ns_get_lba_size(n);
	if (!count || offset & bs || count & bs) {
		errno = EINVAL;
		return -1;
	}

	*lba = offset >> n->lba_shift;
	*nlb = (count >> n->lba_shift) - 1;
	return 0;
}

int nvme_ns_get_fd(nvme_ns_t n)
{
	return n->fd;
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

#ifdef CONFIG_LIBUUID
void nvme_ns_get_uuid(nvme_ns_t n, uuid_t out)
{
	uuid_copy(out, n->uuid);
}
#else
void nvme_ns_get_uuid(nvme_ns_t n, uint8_t *out)
{
	memcpy(out, n, 16);
}
#endif

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
	__u64 slba;
	__u16 nlb;

	if (nvme_bytes_to_lba(n, offset, count, &slba, &nlb))
		return -1;

	return nvme_verify(nvme_ns_get_fd(n), nvme_ns_get_nsid(n), slba, nlb,
			   0, 0, 0, 0, 0, NVME_DEFAULT_IOCTL_TIMEOUT);
}

int nvme_ns_write_uncorrectable(nvme_ns_t n, off_t offset, size_t count)
{
	__u64 slba;
	__u16 nlb;

	if (nvme_bytes_to_lba(n, offset, count, &slba, &nlb))
		return -1;

	return nvme_write_uncorrectable(nvme_ns_get_fd(n), nvme_ns_get_nsid(n),
					slba, nlb, NVME_DEFAULT_IOCTL_TIMEOUT);
}

int nvme_ns_write_zeros(nvme_ns_t n, off_t offset, size_t count)
{
	__u64 slba;
	__u16 nlb;

	if (nvme_bytes_to_lba(n, offset, count, &slba, &nlb))
		return -1;

	return nvme_write_zeros(nvme_ns_get_fd(n), nvme_ns_get_nsid(n), slba,
				nlb, 0, 0, 0, 0, 0, NVME_DEFAULT_IOCTL_TIMEOUT);
}

int nvme_ns_write(nvme_ns_t n, void *buf, off_t offset, size_t count)
{
	__u64 slba;
	__u16 nlb;

	if (nvme_bytes_to_lba(n, offset, count, &slba, &nlb))
		return -1;

	return nvme_write(nvme_ns_get_fd(n), nvme_ns_get_nsid(n), slba, nlb, 0,
			  0, 0, 0, 0, 0, 0, count, buf, 0, NULL,
			  NVME_DEFAULT_IOCTL_TIMEOUT);
}

int nvme_ns_read(nvme_ns_t n, void *buf, off_t offset, size_t count)
{
	__u64 slba;
	__u16 nlb;

	if (nvme_bytes_to_lba(n, offset, count, &slba, &nlb))
		return -1;

	return nvme_read(nvme_ns_get_fd(n), nvme_ns_get_nsid(n), slba, nlb, 0,
			 0, 0, 0, 0, 0, count, buf, 0, NULL,
			 NVME_DEFAULT_IOCTL_TIMEOUT);
}

int nvme_ns_compare(nvme_ns_t n, void *buf, off_t offset, size_t count)
{
	__u64 slba;
	__u16 nlb;

	if (nvme_bytes_to_lba(n, offset, count, &slba, &nlb))
		return -1;

	return nvme_compare(nvme_ns_get_fd(n), nvme_ns_get_nsid(n), slba, nlb,
			    0, 0, 0, 0, count, buf, 0, NULL,
			    NVME_DEFAULT_IOCTL_TIMEOUT);
}

int nvme_ns_flush(nvme_ns_t n)
{
	return nvme_flush(nvme_ns_get_fd(n), nvme_ns_get_nsid(n));
}

static void nvme_ns_parse_descriptors(struct nvme_ns *n,
				      struct nvme_ns_id_desc *descs)
{
	void *d = descs;
	int i, len;

	for (i = 0; i < NVME_IDENTIFY_DATA_SIZE; i += len) {
		struct nvme_ns_id_desc *desc = d + i;

		if (!desc->nidl)
			break;
		len = desc->nidl + sizeof(*desc);

		switch (desc->nidt) {
		case NVME_NIDT_EUI64:
			memcpy(n->eui64, desc->nid, sizeof(n->eui64));
			break;
		case NVME_NIDT_NGUID:
			memcpy(n->nguid, desc->nid, sizeof(n->nguid));
			break;
		case NVME_NIDT_UUID:
			memcpy(n->uuid, desc->nid, sizeof(n->uuid));
			break;
		case NVME_NIDT_CSI:
			memcpy(&n->csi, desc->nid, sizeof(n->csi));
			break;
		}
	}
}

static int nvme_ns_init(struct nvme_ns *n)
{
	struct nvme_id_ns ns = { };
	uint8_t buffer[NVME_IDENTIFY_DATA_SIZE] = { };
	struct nvme_ns_id_desc *descs = (void *)buffer;
	int flbas;
	int ret;

	ret = nvme_ns_identify(n, &ns);
	if (ret)
		return ret;

	flbas = ns.flbas & NVME_NS_FLBAS_LBA_MASK;
	n->lba_shift = ns.lbaf[flbas].ds;
	n->lba_size = 1 << n->lba_shift;
	n->lba_count = le64_to_cpu(ns.nsze);
	n->lba_util = le64_to_cpu(ns.nuse);
	n->meta_size = le16_to_cpu(ns.lbaf[flbas].ms);

	if (!nvme_ns_identify_descs(n, descs))
		nvme_ns_parse_descriptors(n, descs);

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

static nvme_ns_t nvme_ns_open(const char *name)
{
	struct nvme_ns *n;

	n = calloc(1, sizeof(*n));
	if (!n) {
		errno = ENOMEM;
		return NULL;
	}

	n->name = strdup(name);
	n->fd = nvme_open(n->name);
	if (n->fd < 0)
		goto free_ns;

	nvme_ns_set_generic_name(n, name);

	if (nvme_get_nsid(n->fd, &n->nsid) < 0)
		goto close_fd;

	if (nvme_ns_init(n) != 0)
		goto close_fd;

	list_head_init(&n->paths);
	list_node_init(&n->entry);

	return n;

close_fd:
	close(n->fd);
free_ns:
	free(n->name);
	free(n);
	return NULL;
}

static struct nvme_ns *__nvme_scan_namespace(const char *sysfs_dir, const char *name)
{
	struct nvme_ns *n;
	char *path;
	int ret;

	ret = asprintf(&path, "%s/%s", sysfs_dir, name);
	if (ret < 0) {
		errno = ENOMEM;
		return NULL;
	}

	n = nvme_ns_open(name);
	if (!n)
		goto free_path;

	n->sysfs_dir = path;
	return n;

free_path:
	free(path);
	return NULL;
}

nvme_ns_t nvme_scan_namespace(const char *name)
{
	return __nvme_scan_namespace(nvme_ns_sysfs_dir, name);
}

static int nvme_ctrl_scan_namespace(struct nvme_ctrl *c, char *name)
{
	struct nvme_ns *n;

	if (!c->s) {
		nvme_msg(LOG_DEBUG, "%s: no subsystem for %s\n",
			 __func__, name);
		errno = EINVAL;
		return -1;
	}
	n = __nvme_scan_namespace(c->sysfs_dir, name);
	if (!n) {
		nvme_msg(LOG_DEBUG, "%s: failed to scan namespace %s\n",
			 __func__, name);
		return -1;
	}

	n->s = c->s;
	n->c = c;
	list_add(&c->namespaces, &n->entry);
	return 0;
}

static int nvme_subsystem_scan_namespace(struct nvme_subsystem *s, char *name)
{
	struct nvme_ns *n;

	n = __nvme_scan_namespace(s->sysfs_dir, name);
	if (!n) {
		nvme_msg(LOG_DEBUG, "%s: failed to scan namespace %s\n",
			 __func__, name);
		return -1;
	}

	n->s = s;
	list_add(&s->namespaces, &n->entry);
	return 0;
}

struct nvme_ns *nvme_subsystem_lookup_namespace(struct nvme_subsystem *s,
						__u32 nsid)
{
	struct nvme_ns *n;
	char *name;
	int ret;

	ret = asprintf(&name, "%sn%u", s->name, nsid);
	if (ret < 0)
		return NULL;
	n = __nvme_scan_namespace(s->sysfs_dir, name);
	if (!n) {
		nvme_msg(LOG_DEBUG, "%s: failed to scan namespace %d\n",
			 __func__, nsid);
		free(name);
		return NULL;
	}

	n->s = s;
	list_add(&s->namespaces, &n->entry);
	return n;
}
