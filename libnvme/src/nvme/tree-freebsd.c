// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2026 SUSE Software Solutions
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysctl.h>
#include <sys/types.h>

#include <ccan/endian/endian.h>
#include <ccan/list/list.h>

#include <shared/compiler-attributes-util.h>

#include <libnvme.h>

#include "cleanup.h"
#include "private-tree.h"
#include "private.h"
#include "util.h"

/*
 * FreeBSD has no sysfs, so unlike tree-linux.c a controller's identity
 * (subsysnqn) is learned by opening the device and issuing an Identify
 * Controller command rather than by reading an attribute file. This
 * mirrors tree-win.c in spirit, but without Windows' PhysicalDriveN/
 * ctrl-map indirection: FreeBSD's nvme(4) driver already names
 * controller and namespace device nodes the way libnvme_open() expects
 * (/dev/nvmeX, /dev/nvmeXnY), so they can be opened directly by name.
 */

int libnvme_reconfigure_ctrl(__shr_unused struct libnvme_global_ctx *ctx,
		libnvme_ctrl_t c, const char *path, const char *name)
{
	/*
	 * It's necessary to release any resources first because a ctrl
	 * can be reused.
	 */
	libnvme_ctrl_release_transport_handle(c);
	FREE_CTRL_ATTR(c->name);
	FREE_CTRL_ATTR(c->sysfs_dir);
	libnvme_ctrl_attrs_reset(c->attrs);

	c->hdl = NULL;
	c->name = shr_xstrdup(name);
	c->sysfs_dir = shr_xstrdup(path);
	if (!c->name || !c->sysfs_dir) {
		FREE_CTRL_ATTR(c->name);
		FREE_CTRL_ATTR(c->sysfs_dir);
		return -ENOMEM;
	}

	if (!libnvme_ctrl_get_transport_handle(c))
		return -ENODEV;

	return 0;
}

__shr_public const char *libnvme_ctrl_get_state(libnvme_ctrl_t c)
{
	char *state = c->state;

	c->state = strdup("");
	free(state);
	return c->state;
}

__shr_public int libnvme_init_ctrl(__shr_unused libnvme_host_t h,
		__shr_unused libnvme_ctrl_t c,
		__shr_unused int instance)
{
	return -ENOTSUP;
}

/*
 * Look up the "domain:bus:slot.func" PCI address nvme(4) publishes for
 * @name (e.g. "nvme0") via the dev.nvme.<N>.%location sysctl -- the
 * closest FreeBSD equivalent of Linux's sysfs "address" attribute.
 * Returns NULL if the instance can't be parsed out of @name or the
 * sysctl isn't there to read.
 */
static char *pci_traddr_from_ctrl_name(const char *name)
{
	unsigned int instance, domain, bus, slot, func;
	char oid[64], location[128] = "";
	size_t len = sizeof(location) - 1;
	char *dbsf, *traddr;

	if (sscanf(name, "nvme%u", &instance) != 1)
		return NULL;

	snprintf(oid, sizeof(oid), "dev.nvme.%u.%%location", instance);
	if (sysctlbyname(oid, location, &len, NULL, 0) < 0)
		return NULL;
	location[len] = '\0';

	dbsf = strstr(location, "dbsf=pci");
	if (!dbsf)
		return NULL;

	if (sscanf(dbsf, "dbsf=pci%u:%u:%u:%u",
			&domain, &bus, &slot, &func) != 4)
		return NULL;

	if (asprintf(&traddr, "%04x:%02x:%02x.%x",
			domain, bus, slot, func) < 0)
		return NULL;

	return traddr;
}

int libnvme_get_ctrl_transport(__shr_unused struct libnvme_global_ctx *ctx,
		__shr_unused const char *path,
		const char *name, char **transport,
		char **traddr, char **addr, char **trsvcid,
		char **host_traddr, char **host_iface)
{
	*addr = NULL;
	*trsvcid = NULL;
	*host_traddr = NULL;
	*host_iface = NULL;

	/*
	 * Every other accessor of libnvme_ctrl_get_traddr() assumes a
	 * non-NULL return once the controller is known (e.g. printing it
	 * unconditionally), so fall back to "" rather than leaving this
	 * NULL when the sysctl lookup doesn't pan out.
	 */
	*traddr = pci_traddr_from_ctrl_name(name);
	if (!*traddr)
		*traddr = strdup("");
	if (!*traddr)
		return -ENOMEM;

	/*
	 * Fabrics aren't wired up on FreeBSD yet (want_fabrics is
	 * Linux-only, see top-level meson.build), so every controller
	 * nvme(4) exposes is a local PCIe one.
	 */
	*transport = strdup("pcie");
	if (!*transport) {
		free(*traddr);
		*traddr = NULL;
		return -ENOMEM;
	}

	return 0;
}

/*
 * Trim an NVMe spec ASCII field (space-padded, not NUL-terminated) of up
 * to @len characters into a newly allocated, NUL-terminated string.
 */
static char *dup_ascii_field(const char *field, size_t len)
{
	while (len > 0 && field[len - 1] == ' ')
		len--;

	return strndup(field, len);
}

__shr_public int libnvme_scan_ctrl(
		struct libnvme_global_ctx *ctx,
		const char *name,
		libnvme_ctrl_t *cp)
{
	__cleanup_libnvme_free struct nvme_id_ctrl *id = NULL;
	struct libnvme_transport_handle *hdl;
	struct libnvme_passthru_cmd cmd;
	__cleanup_free char *subsysnqn = NULL;
	libnvme_host_t h;
	libnvme_subsystem_t s;
	libnvme_ctrl_t c;
	int ret;

	libnvme_msg(ctx, LIBNVME_LOG_DEBUG, "scan controller %s\n", name);

	ret = libnvme_open(ctx, name, O_RDONLY, &hdl);
	if (ret)
		return ret;

	id = libnvme_alloc(sizeof(*id));
	if (!id) {
		libnvme_close(hdl);
		return -ENOMEM;
	}

	nvme_init_identify_ctrl(&cmd, id);
	ret = libnvme_exec_admin_passthru(hdl, &cmd);
	libnvme_close(hdl);
	if (ret)
		return ret;

	if (id->subnqn[0])
		subsysnqn = dup_ascii_field(id->subnqn, sizeof(id->subnqn));
	else {
		__cleanup_free char *model =
			dup_ascii_field(id->mn, sizeof(id->mn));
		__cleanup_free char *serial =
			dup_ascii_field(id->sn, sizeof(id->sn));

		/*
		 * Same "no subsysnqn reported" placeholder scheme the
		 * Linux kernel and nvme-cli already use for bare PCIe
		 * controllers that predate mandatory SUBNQN support.
		 */
		ret = asprintf(&subsysnqn,
			"nqn.2014.08.org.nvmexpress:%04x%04x%*s%*s",
			le16_to_cpu(id->vid), le16_to_cpu(id->ssvid),
			(int)sizeof(id->mn), model ? model : "",
			(int)sizeof(id->sn), serial ? serial : "");
		if (ret < 0)
			return -ENOMEM;
	}
	if (!subsysnqn)
		return -ENOMEM;

	ret = libnvme_get_host(ctx, NULL, NULL, &h);
	if (ret)
		return ret;

	/*
	 * No sysfs, hence no "nvme-subsysN" directory name to key the
	 * subsystem by -- every other caller of libnvme_subsystem_get_name()
	 * assumes non-NULL (e.g. nvme-print-stdout.c hashes it unconditionally),
	 * so this can't just pass NULL through like the FreeBSD stub used to.
	 * The controller name is as good a stand-in as any for the common
	 * single-controller-per-subsystem PCIe case.
	 */
	ret = libnvme_get_subsystem(ctx, h, name, subsysnqn, &s);
	if (ret)
		return ret;

	ret = libnvme_ctrl_alloc(ctx, s, name, name, &c);
	if (ret)
		return ret;

	ret = libnvme_ctrl_scan_paths(ctx, c);
	if (ret) {
		libnvme_free_ctrl(c);
		return ret;
	}

	ret = libnvme_ctrl_scan_namespaces(ctx, c);
	if (ret) {
		libnvme_free_ctrl(c);
		return ret;
	}

	*cp = c;
	return 0;
}

__shr_public char *libnvme_get_subsys_attr(
		__shr_unused libnvme_subsystem_t s,
		__shr_unused const char *attr)
{
	return NULL;
}

__shr_public char *libnvme_get_path_attr(
		__shr_unused libnvme_path_t p,
		__shr_unused const char *attr)
{
	return NULL;
}

__shr_public char *libnvme_get_attr(
		__shr_unused const char *dir,
		__shr_unused const char *attr)
{
	return NULL;
}

__shr_public char *libnvme_get_ctrl_attr(
		__shr_unused libnvme_ctrl_t c,
		__shr_unused const char *attr)
{
	return NULL;
}

__shr_public char *libnvme_get_ns_attr(
		__shr_unused libnvme_ns_t n,
		__shr_unused const char *attr)
{
	return NULL;
}

const char *libnvme_subsys_sysfs_dir(
		__shr_unused struct libnvme_global_ctx *ctx)
{
	return NULL;
}

const char *libnvme_ns_sysfs_dir(
		__shr_unused struct libnvme_global_ctx *ctx)
{
	return NULL;
}

int libnvme_ns_init(__shr_unused const char *path, struct libnvme_ns *ns)
{
	ns->attrs = libnvme_ns_attrs_alloc();
	if (!ns->attrs)
		return -ENOMEM;

	return 0;
}

int libnvme_ns_open(struct libnvme_global_ctx *ctx,
		__shr_unused const char *sys_path,
		const char *name, libnvme_ns_t *ns)
{
	struct libnvme_transport_handle *hdl;
	struct libnvme_ns_head *head;
	struct libnvme_ns *n;
	int ret;

	n = calloc(1, sizeof(*n));
	if (!n)
		return -ENOMEM;

	head = calloc(1, sizeof(*head));
	if (!head) {
		free(n);
		return -ENOMEM;
	}

	head->n = n;
	list_head_init(&head->paths);

	n->ctx = ctx;
	n->head = head;
	n->hdl = NULL;
	n->name = strdup(name);
	n->generic_name = strdup(name);
	if (!n->name || !n->generic_name) {
		ret = -ENOMEM;
		goto free_ns;
	}

	/* Open the device to query the namespace ID */
	ret = libnvme_open(ctx, name, O_RDONLY, &hdl);
	if (ret)
		goto free_ns;

	ret = libnvme_get_nsid(hdl, &n->nsid);
	libnvme_close(hdl);
	if (ret)
		goto free_ns;

	ret = libnvme_ns_init(name, n);
	if (ret)
		goto free_ns;

	list_node_init(&n->entry);

	libnvme_ns_release_transport_handle(n);

	*ns = n;
	return 0;

free_ns:
	free(n->generic_name);
	free(n->name);
	free(head);
	free(n);
	return ret;
}

int __libnvme_scan_namespace(struct libnvme_global_ctx *ctx,
		__shr_unused const char *sysfs_dir,
		const char *name, libnvme_ns_t *ns)
{
	struct libnvme_ns *n = NULL;
	int ret;

	ret = libnvme_ns_open(ctx, NULL, name, &n);
	if (ret)
		return ret;

	n->sysfs_dir = strdup(name);
	if (!n->sysfs_dir) {
		libnvme_free_ns(n);
		return -ENOMEM;
	}

	*ns = n;
	return 0;
}

int libnvme_init_subsystem(libnvme_subsystem_t s, const char *name)
{
	s->subsystype = strdup("nvm");
	if (!s->subsystype)
		return -ENOMEM;

	s->name = strdup(name);
	if (!s->name) {
		free(s->subsystype);
		return -ENOMEM;
	}

	return 0;
}
