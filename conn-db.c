/*
 * Copyright (C) 2021 SUSE LLC
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *
 * This file implements a simple registry for NVMe connections, i.e.
 * (transport type, host_traddr, traddr, trsvcid) tuples.
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <syslog.h>
#include <time.h>

#include "common.h"
#include "util/cleanup.h"
#include "list.h"
#include "nvme.h"
#include "fabrics.h"
#include "conn-db.h"

#define LOG_FUNCNAME 1
#include "util/log.h"

struct conn_int {
	struct nvme_connection c;
	struct list_head lst;
};

#define conn2internal(co) container_of(co, struct conn_int, c)

static LIST_HEAD(connections);

static const char * const _status_str[] = {
	[CS_NEW] = "new",
	[CS_DISC_RUNNING] = "discovery-running",
	[CS_ONLINE] = "online",
	[CS_FAILED] = "failed",
};

const char *conn_status_str(int status)
{
	return arg_str(_status_str, ARRAY_SIZE(_status_str), status);
}

void __attribute__((format(printf, 4, 5)))
_conn_msg(int lvl, const char *func, const struct nvme_connection *c,
	  const char *fmt, ...)
{
	char *fbuf __cleanup__(cleanup_charp) = NULL;
	char *cbuf __cleanup__(cleanup_charp) = NULL;
	char *mbuf __cleanup__(cleanup_charp) = NULL;
	va_list ap;

	if (asprintf(&cbuf, "[%s]%s->%s(%s): ",
		     c->transport,
		     c->host_traddr ? c->host_traddr : "localhost",
		     c->traddr ? c->traddr : "<no traddr>",
		     c->trsvcid ? c->trsvcid : "") == -1) {
		cbuf = NULL;
		return;
	}

	va_start(ap, fmt);
	if (vasprintf(&mbuf, fmt, ap) == -1)
		mbuf = NULL;
	va_end(ap);
	__msg(lvl, func, "%s%s\n", cbuf, mbuf);
}

static void conn_free(struct conn_int *ci)
{
	if (!ci)
		return;
	if (ci->c.traddr)
		free(ci->c.traddr);
	if (ci->c.trsvcid)
		free(ci->c.trsvcid);
	if (ci->c.host_traddr)
		free(ci->c.host_traddr);
	free(ci);
}

static int conn_del(struct conn_int *ci)
{
	if (!ci)
		return -ENOENT;
	if (list_empty(&ci->lst))
		return -EINVAL;
	conn_msg(LOG_DEBUG, &ci->c, "forgetting connection\n");
	list_del(&ci->lst);
	conn_free(ci);
	return 0;
}

static int get_trtype(const char *transport)
{
	if (!transport)
		return -EINVAL;
	if (!strcmp(transport, trtypes[NVMF_TRTYPE_RDMA]))
		return NVMF_TRTYPE_RDMA;
	else if (!strcmp(transport, trtypes[NVMF_TRTYPE_FC]))
		return NVMF_TRTYPE_FC;
	else if (!strcmp(transport, trtypes[NVMF_TRTYPE_TCP]))
		return NVMF_TRTYPE_TCP;
	else if (!strcmp(transport, trtypes[NVMF_TRTYPE_LOOP]))
		return NVMF_TRTYPE_LOOP;
	else
		return -ENOENT;
}

static bool transport_params_ok(const char *transport, const char *traddr,
				const char *host_traddr)
{
	int trtype = get_trtype(transport);

	/* same as "required_opts" in the kernel code */
	switch(trtype) {
	case NVMF_TRTYPE_FC:
		return traddr && *traddr && host_traddr && *host_traddr;
	case NVMF_TRTYPE_RDMA:
	case NVMF_TRTYPE_TCP:
		return traddr && *traddr;
	case NVMF_TRTYPE_LOOP:
		return true;
	default:
		return false;
	}
}

static bool prop_matches(const char *p1, const char *p2, size_t len)
{
	/* treat NULL and empty string as equivalent */
	if ((!p1 && !p2) || (!p1 && !*p2) || (!p2 && !*p1))
		return true;
	if (p1 && p2 && !strncmp(p1, p2, len))
		return true;
	return false;
}

bool conndb_matches(const char *transport, const char *traddr,
		    const char *trsvcid, const char *host_traddr,
		    const struct nvme_connection *co)
{
	if (!co)
		return false;
	if (!transport_params_ok(transport, traddr, host_traddr))
		return NULL;
	if (strcmp(transport, co->transport))
		return false;
	if (!prop_matches(traddr, co->traddr, NVMF_TRADDR_SIZE))
		return false;
	if (!prop_matches(trsvcid, co->trsvcid, NVMF_TRSVCID_SIZE))
		return false;
	if (!prop_matches(host_traddr, co->host_traddr, NVMF_TRADDR_SIZE))
		return false;
	return true;
}

static struct conn_int *conn_find(const char *transport, const char *traddr,
				  const char *trsvcid, const char *host_traddr)
{
	struct conn_int *ci;

	if (!transport_params_ok(transport, traddr, host_traddr))
		return NULL;
	list_for_each_entry(ci, &connections, lst) {
		if (conndb_matches(transport, traddr, trsvcid, host_traddr, &ci->c))
			return ci;
	}
	return NULL;
}

static DEFINE_CLEANUP_FUNC(conn_free_p, struct conn_int *, conn_free);

static int _conn_add(const char *transport, const char *traddr,
		     const char *trsvcid, const char *host_traddr,
		     struct conn_int **new_ci)
{
	struct conn_int *ci __cleanup__(conn_free_p) = NULL;

	if (!transport_params_ok(transport, traddr, host_traddr)) {
		msg(LOG_ERR, "invalid %s transport parameters: traddr=%s host_traddr=%s\n",
		    transport, traddr, host_traddr);
		return -EINVAL;
	}

	if (!(ci = calloc(1, sizeof(*ci))) ||
	    (traddr && *traddr &&
	     !(ci->c.traddr = strndup(traddr, NVMF_TRADDR_SIZE))) ||
	    (host_traddr && *host_traddr &&
	     !(ci->c.host_traddr = strndup(host_traddr, NVMF_TRADDR_SIZE))) ||
	    (trsvcid && *trsvcid &&
	     !(ci->c.trsvcid = strndup(trsvcid, NVMF_TRSVCID_SIZE))))
		return -ENOMEM;
	memccpy(ci->c.transport, transport, '\0', sizeof(ci->c.transport));
	ci->c.status = CS_NEW;
	ci->c.discovery_instance = -1;
	list_add(&ci->lst, &connections);
	*new_ci = ci;
	ci = NULL;
	return 0;
}

static int conn_add(const char *transport, const char *traddr,
		    const char *trsvcid, const char *host_traddr,
		    struct conn_int **new_ci)
{
	struct conn_int *ci = conn_find(transport, traddr, trsvcid, host_traddr);
	int rc;

	if (ci) {
		*new_ci = ci;
		return -EEXIST;
	}
	rc = _conn_add(transport, traddr, trsvcid, host_traddr, new_ci);
	if (!rc)
		conn_msg(LOG_DEBUG, &(*new_ci)->c, "added connection\n");
	else
		msg(LOG_ERR, "failed to add %s connection\n", transport);
	return rc;
}

int conndb_add(const char *transport, const char *traddr,
	       const char *trsvcid, const char *host_traddr,
	       struct nvme_connection **new_conn)
{
	struct conn_int *ci = NULL;
	int rc = conn_add(transport, traddr, trsvcid, host_traddr, &ci);

	if (rc != 0 && rc != -EEXIST)
		return rc;
	if (new_conn)
		*new_conn = &ci->c;
	return rc;
}

int conndb_add_disc_ctrl(const char *addrstr, struct nvme_connection **new_conn)
{
	char *subsysnqn __cleanup__(cleanup_charp) = NULL;
	char *transport __cleanup__(cleanup_charp) = NULL;
	char *traddr __cleanup__(cleanup_charp) = NULL;
	char *trsvcid __cleanup__(cleanup_charp) = NULL;
	char *host_traddr __cleanup__(cleanup_charp) = NULL;

	subsysnqn = parse_conn_arg(addrstr, ',', "nqn");
	if (strcmp(subsysnqn, NVME_DISC_SUBSYS_NAME)) {
		msg(LOG_WARNING, "%s is not a discovery subsystem\n", subsysnqn);
		return -EINVAL;
	}
	transport = parse_conn_arg(addrstr, ',', "transport");
	traddr = parse_conn_arg(addrstr, ',', "traddr");
	trsvcid = parse_conn_arg(addrstr, ',', "trsvcid");
	host_traddr = parse_conn_arg(addrstr, ',', "host_traddr");
	return conndb_add(transport, traddr, trsvcid, host_traddr, new_conn);
}

struct nvme_connection *conndb_find(const char *transport, const char *traddr,
				    const char *trsvcid, const char *host_traddr)
{
	struct conn_int *ci;

	ci = conn_find(transport, traddr, trsvcid, host_traddr);
	if (ci)
		return &ci->c;
	else
		return NULL;
}

struct nvme_connection *conndb_find_by_pid(pid_t pid)
{
	struct conn_int *ci;

	list_for_each_entry(ci, &connections, lst) {
		if (ci->c.status == CS_DISC_RUNNING &&
		    ci->c.discovery_task == pid)
			return &ci->c;
	}
	return NULL;
}

struct nvme_connection *conndb_find_by_ctrl(const char *devname)
{
	struct conn_int *ci;
	int instance;

	instance = ctrl_instance(devname);
	if (instance < 0)
		return NULL;

	list_for_each_entry(ci, &connections, lst) {
		if (ci->c.discovery_instance == instance)
			return &ci->c;
	}
	return NULL;
}

int conndb_delete(struct nvme_connection *co)
{
	if (!co)
		return -ENOENT;
	return conn_del(conn2internal(co));
}

void conndb_free(void)
{
	struct conn_int *ci, *next;

	list_for_each_entry_safe(ci, next, &connections, lst)
		conn_del(ci);
}

int conndb_init_from_sysfs(void)
{
	struct dirent **devices;
	int i, n, ret = 0;
	char syspath[PATH_MAX];

	n = scandir(SYS_NVME, &devices, scan_ctrls_filter, alphasort);
	if (n <= 0)
		return n;

	for (i = 0; i < n; i++) {
		int len, rc;
		struct conn_int *ci;
		char *transport __cleanup__(cleanup_charp) = NULL;
		char *address __cleanup__(cleanup_charp) = NULL;
		char *traddr __cleanup__(cleanup_charp) = NULL;
		char *trsvcid __cleanup__(cleanup_charp) = NULL;
		char *host_traddr __cleanup__(cleanup_charp) = NULL;
		char *subsysnqn __cleanup__(cleanup_charp) = NULL;

		len = snprintf(syspath, sizeof(syspath), SYS_NVME "/%s",
			       devices[i]->d_name);
		if (len < 0 || len >= sizeof(syspath))
			continue;

		transport = nvme_get_ctrl_attr(syspath, "transport");
		address = nvme_get_ctrl_attr(syspath, "address");
		if (!transport || !address)
			continue;
		traddr = parse_conn_arg(address, ' ', "traddr");
		trsvcid = parse_conn_arg(address, ' ', "trsvcid");
		host_traddr = parse_conn_arg(address, ' ', "host_traddr");

		rc = conn_add(transport, traddr, trsvcid, host_traddr, &ci);
		if (rc != 0 && rc != -EEXIST)
			continue;

		if (rc == 0)
			ret++;

		subsysnqn = nvme_get_ctrl_attr(syspath, "subsysnqn");
		if (subsysnqn && !strcmp(subsysnqn, NVME_DISC_SUBSYS_NAME)) {
			int instance;
			char *kato_attr __cleanup__(cleanup_charp) = NULL;

			kato_attr = nvme_get_ctrl_attr(syspath, "kato");
			if (kato_attr) {
				char dummy;
				unsigned int kato;
				/*
				 * The kernel supports the "kato" attribute, and
				 * this controller isn't persistent. Skip it.
				 */
				if (sscanf(kato_attr, "%u%c", &kato, &dummy) == 1
				    && kato == 0)
					continue;
			}

			instance =ctrl_instance(devices[i]->d_name);
			if (instance >= 0) {
				ci->c.discovery_instance = instance;
				ci->c.discovery_ctrl_existed = 1;
				msg(LOG_DEBUG, "found discovery controller %s\n",
				    devices[i]->d_name);
			}
		}
	}

	for (i = 0; i < n; i++)
		free(devices[i]);
	free(devices);

	return ret;
}

int conndb_for_each(int (*callback)(struct nvme_connection *co, void *arg),
		    void *arg)
{
	struct conn_int *ci, *next;
	int ret = 0;

	list_for_each_entry_safe(ci, next, &connections, lst) {
		int rc = callback(&ci->c, arg);

		if (rc & ~(CD_CB_ERR|CD_CB_DEL|CD_CB_BREAK)) {
			msg(LOG_ERR,
			    "invalid return value 0x%x from callback\n", rc);
			ret = -EINVAL;
			continue;
		}
		if (rc & CD_CB_ERR) {
			msg(LOG_WARNING, "callback returned error\n");
			if (!ret)
				ret = errno ? -errno : -EIO;
		}
		if (rc & CD_CB_DEL)
			conn_del(ci);
		if (rc & CD_CB_BREAK)
			break;
	}
	return ret;
}
