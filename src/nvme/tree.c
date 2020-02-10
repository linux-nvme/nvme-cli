#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#include "ioctl.h"
#include "filters.h"
#include "tree.h"
#include "private.h"
#include "filters.h"
#include "util.h"
#include "cmd.h"

static int nvme_scan_topology(struct nvme_root *r, nvme_scan_filter_t f)
{
	struct dirent **subsys;
	int i, ret;

	ret = nvme_scan_subsystems(&subsys);
	if (ret < 0)
		return ret;

	for (i = 0; i < ret; i++)
		nvme_scan_subsystem(r, subsys[i]->d_name, f);

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

	list_head_init(&r->subsystems);
	nvme_scan_topology(r, f);
	return r;
}

nvme_root_t nvme_scan()
{
	return nvme_scan_filter(NULL);
}

nvme_subsystem_t nvme_first_subsystem(nvme_root_t r)
{
	return list_top(&r->subsystems, struct nvme_subsystem, entry);
}

nvme_subsystem_t nvme_next_subsystem(nvme_root_t r, nvme_subsystem_t s)
{
	return s ? list_next(&r->subsystems, s, entry) : NULL;
}

void nvme_refresh_topology(nvme_root_t r)
{
	struct nvme_subsystem *s, *_s;

	nvme_for_each_subsystem_safe(r, s, _s)
		nvme_free_subsystem(s);
	nvme_scan_topology(r, NULL);
}

void nvme_reset_topology(nvme_root_t r)
{
	struct nvme_subsystem *s, *_s;

	nvme_for_each_subsystem_safe(r, s, _s)
		nvme_free_subsystem(s);
	nvme_scan_topology(r, NULL);
}

void nvme_free_tree(nvme_root_t r)
{
	struct nvme_subsystem *s, *_s;

	nvme_for_each_subsystem_safe(r, s, _s)
		nvme_free_subsystem(s);
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

nvme_ctrl_t nvme_subsystem_first_ctrl(nvme_subsystem_t s)
{
	return list_top(&s->ctrls, struct nvme_ctrl, entry);
}

nvme_ctrl_t nvme_subsystem_next_ctrl(nvme_subsystem_t s, nvme_ctrl_t c)
{
	return c ? list_next(&s->ctrls, c, entry) : NULL;
}

nvme_ns_t nvme_subsystem_first_ns(nvme_subsystem_t s)
{
	return list_top(&s->namespaces, struct nvme_ns, entry);
}

nvme_ns_t nvme_subsystem_next_ns(nvme_subsystem_t s, nvme_ns_t n)
{
	return n ? list_next(&s->namespaces, n, entry) : NULL;
}

static void nvme_free_ns(struct nvme_ns *n)
{
	list_del_init(&n->entry);
	close(n->fd);
	free(n->name);
	free(n->sysfs_dir);
	free(n);
}

void nvme_free_subsystem(struct nvme_subsystem *s)
{
	struct nvme_ctrl *c, *_c;
	struct nvme_ns *n, *_n;

	list_del_init(&s->entry);
	nvme_subsystem_for_each_ctrl_safe(s, c, _c)
		nvme_free_ctrl(c);

	nvme_subsystem_for_each_ns_safe(s, n, _n)
		nvme_free_ns(n);

	free(s->name);
	free(s->sysfs_dir);
	free(s->subsysnqn);
	free(s);
}

static int nvme_subsystem_scan_namespaces(struct nvme_subsystem *s)
{
	struct dirent **namespaces;
	int i, ret;

	ret = nvme_scan_subsystem_namespaces(s, &namespaces);
	if (ret < 0)
		return ret;

	for (i = 0; i < ret; i++)
		nvme_subsystem_scan_namespace(s, namespaces[i]->d_name);

	nvme_free_dirents(namespaces, i);
	return 0;
}

int nvme_subsystem_scan_ctrls(struct nvme_subsystem *s)
{
	struct dirent **ctrls;
	int i, ret;

	ret = nvme_scan_subsystem_ctrls(s, &ctrls);
	if (ret < 0)
		return ret;

	for (i = 0; i < ret; i++)
		nvme_subsystem_scan_ctrl(s, ctrls[i]->d_name);

	nvme_free_dirents(ctrls, i);
	return 0;
}

int nvme_scan_subsystem(struct nvme_root *r, char *name, nvme_scan_filter_t f)
{
	struct nvme_subsystem *s;
	char *path;
	int ret;

	ret = asprintf(&path, "%s/%s", nvme_subsys_sysfs_dir, name);
	if (ret < 0)
		return ret;

	s = calloc(1, sizeof(*s));
	if (!s) {
		errno = ENOMEM;
		goto free_path;
	}

	s->r = r;
	s->name = strdup(name);;
	s->sysfs_dir = path;
	s->subsysnqn = nvme_get_subsys_attr(s, "subsysnqn");
	list_head_init(&s->ctrls);
	list_head_init(&s->namespaces);

	nvme_subsystem_scan_namespaces(s);
	nvme_subsystem_scan_ctrls(s);
	list_add(&r->subsystems, &s->entry);

	if (f && !f(s)) {
		nvme_free_subsystem(s);
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
	char n_name[32] = { 0 };
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

int nvme_ctrl_scan_path(struct nvme_ctrl *c, char *name)
{
	struct nvme_path *p;
	char *path, *grpid;
	int ret;

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
	nvme_subsystem_set_path_ns(c->s, p);

	grpid = nvme_get_path_attr(p, "ana_grpid");
	if (grpid) {
		sscanf(grpid, "%d", &p->grpid);
		free(grpid);
	}

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
	return c->subsysnqn;
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

int nvme_ctrl_disconnect(nvme_ctrl_t c)
{
	return nvme_set_attr(nvme_ctrl_get_sysfs_dir(c),
			     "delete_controller", "1");
}

void nvme_unlink_ctrl(nvme_ctrl_t c)
{
	list_del_init(&c->entry);
	c->s = NULL;
}

void nvme_free_ctrl(nvme_ctrl_t c)
{
	struct nvme_path *p, *_p;
	struct nvme_ns *n, *_n;

	nvme_unlink_ctrl(c);

	nvme_ctrl_for_each_path_safe(c, p, _p)
		nvme_free_path(p);

	nvme_ctrl_for_each_ns_safe(c, n, _n)
		nvme_free_ns(n);

	close(c->fd);
	free(c->name);
	free(c->sysfs_dir);
	free(c->subsysnqn);
	free(c->address);
	free(c->firmware);
	free(c->model);
	free(c->state);
	free(c->numa_node);
	free(c->queue_count);
	free(c->serial);
	free(c->sqsize);
	free(c->transport);
	free(c);
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

static nvme_ctrl_t __nvme_ctrl_alloc(const char *path, const char *name)
{
	DIR *d;
	nvme_ctrl_t c;

	d = opendir(path);
	if (!d)
		return NULL;
	closedir(d);

	c = calloc(1, sizeof(*c));
	if (!c) {
		errno = ENOMEM;
		return NULL;
	}

	c->fd = nvme_open(name);
	if (c->fd < 0)
		goto free_ctrl;

	list_head_init(&c->namespaces);
	list_head_init(&c->paths);
	list_node_init(&c->entry);
	c->name = strdup(name);
	c->sysfs_dir = (char *)path;
	c->subsysnqn = nvme_get_ctrl_attr(c, "subsysnqn");
	c->address = nvme_get_ctrl_attr(c, "address");
	c->firmware = nvme_get_ctrl_attr(c, "firmware_rev");
	c->model = nvme_get_ctrl_attr(c, "model");
	c->state = nvme_get_ctrl_attr(c, "state");
	c->numa_node = nvme_get_ctrl_attr(c, "numa_node");
	c->queue_count = nvme_get_ctrl_attr(c, "queue_count");
	c->serial = nvme_get_ctrl_attr(c, "serial");
	c->sqsize = nvme_get_ctrl_attr(c, "sqsize");
	c->transport = nvme_get_ctrl_attr(c, "transport");

	return c;

free_ctrl:
	free(c);
	return NULL;
}

static nvme_ctrl_t nvme_ctrl_alloc(const char *sysfs, const char *name)
{
	nvme_ctrl_t c;
	char *path;
	int ret;

	ret = asprintf(&path, "%s/%s", sysfs, name);
	if (ret < 0) {
		errno = ENOMEM;
		return NULL;
	}

	c = __nvme_ctrl_alloc(path, name);
	if (!c)
		free(path);
	return c;
}

nvme_ctrl_t nvme_scan_ctrl(const char *name)
{
	return nvme_ctrl_alloc(nvme_ctrl_sysfs_dir, name);
}

int nvme_subsystem_scan_ctrl(struct nvme_subsystem *s, char *name)
{
	nvme_ctrl_t c;

	c = nvme_ctrl_alloc(s->sysfs_dir, name);
	if (!c)
		return -1;

	c->s = s;
	nvme_ctrl_scan_namespaces(c);
	nvme_ctrl_scan_paths(c);
	list_add(&s->ctrls, &c->entry);

	return 0;
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

	*lba = offset / bs;
	*nlb = (count / bs) - 1;
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

int nvme_ns_get_lba_size(nvme_ns_t n)
{
	return n->lba_size;
}

uint64_t nvme_ns_get_lba_count(nvme_ns_t n)
{
	return n->lba_count;
}

uint64_t nvme_ns_get_lba_util(nvme_ns_t n)
{
	return n->lba_util;
}

int nvme_ns_identify(nvme_ns_t n, struct nvme_id_ns *ns)
{
	return nvme_identify_ns(nvme_ns_get_fd(n), nvme_ns_get_nsid(n), ns);
}

int nvme_ns_verify(nvme_ns_t n, off_t offset, size_t count)
{
	__u64 slba;
	__u16 nlb;

	if (nvme_bytes_to_lba(n, offset, count, &slba, &nlb))
		return -1;

	return nvme_verify(nvme_ns_get_fd(n), nvme_ns_get_nsid(n), slba, nlb,
			   0, 0, 0, 0);
}

int nvme_ns_write_uncorrectable(nvme_ns_t n, off_t offset, size_t count)
{
	__u64 slba;
	__u16 nlb;

	if (nvme_bytes_to_lba(n, offset, count, &slba, &nlb))
		return -1;

	return nvme_write_uncorrectable(nvme_ns_get_fd(n), nvme_ns_get_nsid(n),
					slba, nlb);
}

int nvme_ns_write_zeros(nvme_ns_t n, off_t offset, size_t count)
{
	__u64 slba;
	__u16 nlb;

	if (nvme_bytes_to_lba(n, offset, count, &slba, &nlb))
		return -1;

	return nvme_write_zeros(nvme_ns_get_fd(n), nvme_ns_get_nsid(n), slba,
				nlb, 0, 0, 0, 0);
}

int nvme_ns_write(nvme_ns_t n, void *buf, off_t offset, size_t count)
{
	__u64 slba;
	__u16 nlb;

	if (nvme_bytes_to_lba(n, offset, count, &slba, &nlb))
		return -1;

	return nvme_write(nvme_ns_get_fd(n), nvme_ns_get_nsid(n), slba, nlb, 0,
			  0, 0, 0, 0, 0, count, buf, 0, NULL);
}

int nvme_ns_read(nvme_ns_t n, void *buf, off_t offset, size_t count)
{
	__u64 slba;
	__u16 nlb;

	if (nvme_bytes_to_lba(n, offset, count, &slba, &nlb))
		return -1;

	return nvme_read(nvme_ns_get_fd(n), nvme_ns_get_nsid(n), slba, nlb, 0,
			 0, 0, 0, 0, count, buf, 0, NULL);
}

int nvme_ns_compare(nvme_ns_t n, void *buf, off_t offset, size_t count)
{
	__u64 slba;
	__u16 nlb;

	if (nvme_bytes_to_lba(n, offset, count, &slba, &nlb))
		return -1;

	return nvme_compare(nvme_ns_get_fd(n), nvme_ns_get_nsid(n), slba, nlb,
			    0, 0, 0, 0, count, buf, 0, NULL);
}

int nvme_ns_flush(nvme_ns_t n)
{
	return nvme_flush(nvme_ns_get_fd(n), nvme_ns_get_nsid(n));
}

static void nvme_ns_init(struct nvme_ns *n)
{
	struct nvme_id_ns ns = { 0 };

	if (nvme_ns_identify(n, &ns) != 0)
		return;

	n->lba_size = 1 << ns.lbaf[ns.flbas & NVME_NS_FLBAS_LBA_MASK].ds;
	n->lba_count = le64_to_cpu(ns.nsze);
	n->lba_util = le64_to_cpu(ns.nuse);
}

static struct nvme_ns *__nvme_scan_namespace(const char *sysfs_dir, char *name)
{
	struct nvme_ns *n;
	char *path;
	int ret;

	ret = asprintf(&path, "%s/%s", sysfs_dir, name);
	if (ret < 0) {
		errno = ENOMEM;
		return NULL;
	}

	n = calloc(1, sizeof(*n));
	if (!n) {
		errno = ENOMEM;
		goto free_path;
	}

	n->name = strdup(name);
	n->sysfs_dir = path;
	n->fd = nvme_open(name);
	if (n->fd < 0)
		goto free_ns;

	n->nsid = nvme_get_nsid(n->fd);
	if (n->nsid < 0)
		goto close_fd;

	list_head_init(&n->paths);
	nvme_ns_init(n);

	return n;

close_fd:
	close(n->fd);
free_ns:
	free(n);
free_path:
	free(path);
	return NULL;
}

int nvme_ctrl_scan_namespace(struct nvme_ctrl *c, char *name)
{
	struct nvme_ns *n;

	n = __nvme_scan_namespace(c->sysfs_dir, name);
	if (!n)
		return -1;

	n->s = c->s;
	n->c = c;
	list_add(&c->namespaces, &n->entry);
	return 0;
}

int nvme_subsystem_scan_namespace(struct nvme_subsystem *s, char *name)
{
	struct nvme_ns *n;

	n = __nvme_scan_namespace(s->sysfs_dir, name);
	if (!n)
		return -1;

	n->s = s;
	list_add(&s->namespaces, &n->entry);
	return 0;
}
