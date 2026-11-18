// SPDX-License-Identifier: GPL-2.0-or-later

#include <stdlib.h>
#include <unistd.h>

#include <libnvme.h>

#include <ccan/str/str.h>

#include "cleanup.h"
#include "cmds-list-print.h"
#include "global-ctx.h"
#include "nvme-iostat.h"
#include "nvme-json.h"
#include "nvme-print.h"
#include "nvme-print-json.h"

#define NAME_LEN 128

static struct cmds_list_print_ops json_list_print_ops;

static bool verbose_mode(void)
{
	return json_list_print_ops.flags & VERBOSE;
}

static void obj_add_ctrl_address(struct json_object *o, struct libnvme_ctrl *c)
{
	const char *address = libnvme_ctrl_get_address(c);

	/* controllers without an address, e.g. loop, don't report one */
	obj_add_str(o, "Address", address ? address : "");
}

static void obj_add_ctrl_address_details(struct json_object *o, const char *k,
					 struct libnvme_ctrl *c)
{
	struct json_object *address_details = json_create_object();
	const char *value;
	bool has_value = false;

	value = libnvme_ctrl_get_traddr(c);
	if (value) {
		obj_add_str(address_details, "traddr", value);
		has_value = true;
	}

	value = libnvme_ctrl_get_host_traddr(c);
	if (value) {
		obj_add_str(address_details, "host_traddr", value);
		has_value = true;
	}

	value = libnvme_ctrl_get_host_iface(c);
	if (value) {
		obj_add_str(address_details, "host_iface", value);
		has_value = true;
	}

	value = libnvme_ctrl_get_trsvcid(c);
	if (value) {
		obj_add_str(address_details, "trsvcid", value);
		has_value = true;
	}

	if (!has_value) {
		json_free_object(address_details);
		return;
	}

	obj_add_obj(o, k, address_details);
}


static unsigned int
json_print_nvme_subsystem_multipath(struct libnvme_subsystem *s,
				    json_object *paths)
{
	struct libnvme_ns *n;
	struct libnvme_path *p;
	unsigned int i = 0;

	n = libnvme_subsystem_first_ns(s);
	if (!n)
		return 0;

	libnvme_namespace_for_each_path(n, p) {
		struct json_object *path_attrs;
		struct libnvme_ctrl *c = libnvme_path_get_ctrl(p);
		const char *ana_state;

		libnvme_path_get_ana_state(p, &ana_state, "");
		path_attrs = json_create_object();
		obj_add_str(path_attrs, "Name", libnvme_ctrl_get_name(c));
		obj_add_str(path_attrs, "Transport",
			    libnvme_ctrl_get_transport(c));
		obj_add_ctrl_address(path_attrs, c);
		obj_add_ctrl_address_details(path_attrs, "AddressDetails", c);
		obj_add_str(path_attrs, "State", libnvme_ctrl_get_state(c));
		obj_add_str(path_attrs, "ANAState", ana_state);
		array_add_obj(paths, path_attrs);
		i++;
	}

	return i;
}

static void json_print_nvme_subsystem_ctrls(struct libnvme_subsystem *s,
					    json_object *paths)
{
	struct libnvme_ctrl *c;

	libnvme_subsystem_for_each_ctrl(s, c) {
		struct json_object *path_attrs;

		path_attrs = json_create_object();
		obj_add_str(path_attrs, "Name", libnvme_ctrl_get_name(c));
		obj_add_str(path_attrs, "Transport",
			    libnvme_ctrl_get_transport(c));
		obj_add_ctrl_address(path_attrs, c);
		obj_add_ctrl_address_details(path_attrs, "AddressDetails", c);
		obj_add_str(path_attrs, "State", libnvme_ctrl_get_state(c));
		array_add_obj(paths, path_attrs);
	}
}

static void json_print_nvme_subsystem_list(struct libnvme_global_ctx *ctx,
					   bool show_ana)
{
	struct json_object *host_attrs, *subsystem_attrs;
	struct json_object *subsystems, *paths;
	struct json_object *a = json_create_array();
	struct libnvme_host *h;

	libnvme_for_each_host(ctx, h) {
		struct libnvme_subsystem *s;
		const char *hostid;

		host_attrs = json_create_object();
		obj_add_str(host_attrs, "HostNQN", libnvme_host_get_hostnqn(h));
		hostid = libnvme_host_get_hostid(h);
		if (hostid)
			obj_add_str(host_attrs, "HostID", hostid);
		subsystems = json_create_array();
		libnvme_for_each_subsystem(h, s) {
			struct libnvme_ctrl *c;
			bool no_ctrl = true;

			libnvme_subsystem_for_each_ctrl(s, c)
				no_ctrl = false;
			if (no_ctrl)
				continue;

			subsystem_attrs = json_create_object();
			obj_add_str(subsystem_attrs, "Name",
				    libnvme_subsystem_get_name(s));
			obj_add_str(subsystem_attrs, "NQN",
				    libnvme_subsystem_get_subsysnqn(s));

			if (verbose_mode()) {
				const char *model;
				const char *serial;
				const char *firmware;
				const char *iopolicy;

				libnvme_subsystem_get_model(s, &model, "");
				libnvme_subsystem_get_serial(s, &serial, "");
				libnvme_subsystem_get_firmware(s, &firmware,
								"");
				libnvme_subsystem_get_iopolicy(s, &iopolicy,
								"");

				obj_add_str(subsystem_attrs, "Model", model);
				obj_add_str(subsystem_attrs, "Serial", serial);
				obj_add_str(subsystem_attrs, "Firmware",
						firmware);
				obj_add_str(subsystem_attrs, "IOPolicy",
						iopolicy);
				obj_add_str(subsystem_attrs, "Type",
					libnvme_subsystem_get_subsystype(s));
			}

			array_add_obj(subsystems, subsystem_attrs);
			paths = json_create_array();

			if (!show_ana ||
			    !json_print_nvme_subsystem_multipath(s, paths))
				json_print_nvme_subsystem_ctrls(s, paths);

			obj_add_array(subsystem_attrs, "Paths", paths);
		}
		obj_add_array(host_attrs, "Subsystems", subsystems);
		array_add_obj(a, host_attrs);
	}

	json_print(a);
}

static void json_print_detail_list_multipath(struct libnvme_subsystem *s,
		struct json_object *jss)
{
	struct libnvme_ns *n;
	struct libnvme_path *p;
	struct json_object *jnss = json_create_array();

	libnvme_subsystem_for_each_ns(s, n) {
		struct json_object *jns = json_create_object();
		struct json_object *jpaths = json_create_array();
		int lba;
		uint64_t lba_count, nsze, nuse;

		libnvme_ns_get_lba_size(n, &lba, 0);
		libnvme_ns_get_lba_count(n, &lba_count, 0);
		nsze = lba_count * lba;
		libnvme_ns_get_lba_util(n, &nuse, 0);
		nuse *= lba;

		obj_add_str(jns, "NameSpace", libnvme_ns_get_name(n));
		obj_add_str(jns, "Generic", libnvme_ns_get_generic_name(n));
		obj_add_int(jns, "NSID", libnvme_ns_get_nsid(n));
		obj_add_uint64(jns, "UsedBytes", nuse);
		obj_add_uint64(jns, "MaximumLBA", lba_count);
		obj_add_uint64(jns, "PhysicalSize", nsze);
		obj_add_int(jns, "SectorSize", lba);

		libnvme_namespace_for_each_path(n, p) {
			struct libnvme_ctrl *c;
			struct json_object *jpath = json_create_object();
			const char *slot;
			const char *cntlid;
			const char *serial;
			const char *model;
			const char *firmware;
			const char *ana_state;

			libnvme_path_get_ana_state(p, &ana_state, "");
			obj_add_str(jpath, "Path", libnvme_path_get_name(p));
			obj_add_str(jpath, "ANAState", ana_state);

			/*
			 * For multipath, each path maps to one controller.
			 * So get the controller from the path and then add
			 * controller  attributes.
			 */
			c = libnvme_path_get_ctrl(p);
			libnvme_ctrl_get_phy_slot(c, &slot, "");
			libnvme_ctrl_get_cntlid(c, &cntlid, "");
			libnvme_ctrl_get_serial(c, &serial, "");
			libnvme_ctrl_get_model(c, &model, "");
			libnvme_ctrl_get_firmware(c, &firmware, "");
			obj_add_str(jpath, "Controller",
				    libnvme_ctrl_get_name(c));
			obj_add_str(jpath, "Cntlid", cntlid);
			obj_add_str(jpath, "SerialNumber", serial);
			obj_add_str(jpath, "ModelNumber", model);
			obj_add_str(jpath, "Firmware", firmware);
			obj_add_str(jpath, "Transport",
				    libnvme_ctrl_get_transport(c));
			obj_add_ctrl_address(jpath, c);
			obj_add_ctrl_address_details(jpath, "AddressDetails",
						     c);
			obj_add_str(jpath, "Slot", slot ? slot : "");

			array_add_obj(jpaths, jpath);
		}

		obj_add_obj(jns, "Paths", jpaths);
		array_add_obj(jnss, jns);
	}
	obj_add_obj(jss, "Namespaces", jnss);
}

static void json_print_detail_list(struct libnvme_subsystem *s,
				   struct json_object *jss)
{
	struct libnvme_ctrl *c;
	struct libnvme_ns *n;
	struct json_object *jctrls = json_create_array();

	libnvme_subsystem_for_each_ctrl(s, c) {
		struct json_object *jctrl = json_create_object();
		struct json_object *jnss = json_create_array();
		const char *slot;
		const char *cntlid;
		const char *serial;
		const char *model;
		const char *firmware;

		libnvme_ctrl_get_phy_slot(c, &slot, "");
		libnvme_ctrl_get_cntlid(c, &cntlid, "");
		libnvme_ctrl_get_serial(c, &serial, "");
		libnvme_ctrl_get_model(c, &model, "");
		libnvme_ctrl_get_firmware(c, &firmware, "");

		obj_add_str(jctrl, "Controller", libnvme_ctrl_get_name(c));
		obj_add_str(jctrl, "Cntlid", cntlid);
		obj_add_str(jctrl, "SerialNumber", serial);
		obj_add_str(jctrl, "ModelNumber", model);
		obj_add_str(jctrl, "Firmware", firmware);
		obj_add_str(jctrl, "Transport", libnvme_ctrl_get_transport(c));
		obj_add_ctrl_address(jctrl, c);
		obj_add_ctrl_address_details(jctrl, "AddressDetails", c);
		obj_add_str(jctrl, "Slot", slot ? slot : "");

		libnvme_ctrl_for_each_ns(c, n) {
			struct json_object *jns = json_create_object();
			int lba;
			uint64_t lba_count, nsze, nuse;

			libnvme_ns_get_lba_size(n, &lba, 0);
			libnvme_ns_get_lba_count(n, &lba_count, 0);
			nsze = lba_count * lba;
			libnvme_ns_get_lba_util(n, &nuse, 0);
			nuse *= lba;

			obj_add_str(jns, "NameSpace", libnvme_ns_get_name(n));
			obj_add_str(jns, "Generic",
				    libnvme_ns_get_generic_name(n));
			obj_add_int(jns, "NSID", libnvme_ns_get_nsid(n));
			obj_add_uint64(jns, "UsedBytes", nuse);
			obj_add_uint64(jns, "MaximumLBA", lba_count);
			obj_add_uint64(jns, "PhysicalSize", nsze);
			obj_add_int(jns, "SectorSize", lba);

			array_add_obj(jnss, jns);
		}

		obj_add_obj(jctrl, "Namespaces", jnss);
		array_add_obj(jctrls, jctrl);
	}

	obj_add_obj(jss, "Controllers", jctrls);
}

static void json_detail_list_v2(struct libnvme_global_ctx *ctx)
{
	struct json_object *r = json_root();
	struct json_object *jdev = json_create_array();

	struct libnvme_host *h;
	struct libnvme_subsystem *s;

	libnvme_for_each_host(ctx, h) {
		struct json_object *hss = json_create_object();
		struct json_object *jsslist = json_create_array();
		const char *hostid;

		obj_add_str(hss, "HostNQN", libnvme_host_get_hostnqn(h));
		hostid = libnvme_host_get_hostid(h);
		if (hostid)
			obj_add_str(hss, "HostID", hostid);

		libnvme_for_each_subsystem(h, s) {
			struct json_object *jss = json_create_object();

			obj_add_str(jss, "Subsystem",
				    libnvme_subsystem_get_name(s));
			obj_add_str(jss, "SubsystemNQN",
				    libnvme_subsystem_get_subsysnqn(s));

			if (nvme_is_multipath(s))
				json_print_detail_list_multipath(s, jss);
			else
				json_print_detail_list(s, jss);

			array_add_obj(jsslist, jss);
		}

		obj_add_obj(hss, "Subsystems", jsslist);
		array_add_obj(jdev, hss);
	}

	obj_add_array(r, "Devices", jdev);
}

static void json_detail_list(struct libnvme_global_ctx *ctx)
{
	struct json_object *r = json_root();
	struct json_object *jdev = json_create_array();

	struct libnvme_host *h;
	struct libnvme_subsystem *s;
	struct libnvme_ctrl *c;
	struct libnvme_path *p;
	struct libnvme_ns *n;

	libnvme_for_each_host(ctx, h) {
		struct json_object *hss = json_create_object();
		struct json_object *jsslist = json_create_array();
		const char *hostid;

		obj_add_str(hss, "HostNQN", libnvme_host_get_hostnqn(h));
		hostid = libnvme_host_get_hostid(h);
		if (hostid)
			obj_add_str(hss, "HostID", hostid);

		libnvme_for_each_subsystem(h, s) {
			struct json_object *jss = json_create_object();
			struct json_object *jctrls = json_create_array();
			struct json_object *jnss = json_create_array();

			obj_add_str(jss, "Subsystem",
				    libnvme_subsystem_get_name(s));
			obj_add_str(jss, "SubsystemNQN",
				    libnvme_subsystem_get_subsysnqn(s));

			libnvme_subsystem_for_each_ctrl(s, c) {
				struct json_object *jctrl =
					json_create_object();
				struct json_object *jnss = json_create_array();
				struct json_object *jpaths =
					json_create_array();
				const char *cntlid;
				const char *serial;
				const char *model;
				const char *firmware;
				const char *slot;

				libnvme_ctrl_get_cntlid(c, &cntlid, "");
				libnvme_ctrl_get_serial(c, &serial, "");
				libnvme_ctrl_get_model(c, &model, "");
				libnvme_ctrl_get_firmware(c, &firmware, "");
				libnvme_ctrl_get_phy_slot(c, &slot, "");

				obj_add_str(jctrl, "Controller",
					    libnvme_ctrl_get_name(c));
				obj_add_str(jctrl, "Cntlid", cntlid);
				obj_add_str(jctrl, "SerialNumber", serial);
				obj_add_str(jctrl, "ModelNumber", model);
				obj_add_str(jctrl, "Firmware", firmware);
				obj_add_str(jctrl, "Transport",
					    libnvme_ctrl_get_transport(c));
				obj_add_ctrl_address(jctrl, c);
				obj_add_ctrl_address_details(jctrl,
							     "AddressDetails",
							     c);
				obj_add_str(jctrl, "Slot", slot);

				libnvme_ctrl_for_each_ns(c, n) {
					struct json_object *jns =
						json_create_object();
					int lba;
					uint64_t lba_count, nsze, nuse;

					libnvme_ns_get_lba_size(n, &lba, 0);
					libnvme_ns_get_lba_count(n,
							&lba_count, 0);
					nsze = lba_count * lba;
					libnvme_ns_get_lba_util(n, &nuse, 0);
					nuse *= lba;

					obj_add_str(jns, "NameSpace",
						    libnvme_ns_get_name(n));
					obj_add_str(jns, "Generic",
						libnvme_ns_get_generic_name(n));
					obj_add_int(jns, "NSID",
						    libnvme_ns_get_nsid(n));
					obj_add_uint64(jns, "UsedBytes", nuse);
					obj_add_uint64(jns, "MaximumLBA",
							lba_count);
					obj_add_uint64(jns, "PhysicalSize",
						       nsze);
					obj_add_int(jns, "SectorSize", lba);

					array_add_obj(jnss, jns);
				}
				obj_add_obj(jctrl, "Namespaces", jnss);

				libnvme_ctrl_for_each_path(c, p) {
					struct json_object *jpath =
						json_create_object();
					const char *ana_state;

					libnvme_path_get_ana_state(p,
							&ana_state, "");
					obj_add_str(jpath, "Path",
						    libnvme_path_get_name(p));
					obj_add_str(jpath, "ANAState",
							ana_state);

					array_add_obj(jpaths, jpath);
				}
				obj_add_obj(jctrl, "Paths", jpaths);

				array_add_obj(jctrls, jctrl);
			}
			obj_add_obj(jss, "Controllers", jctrls);

			libnvme_subsystem_for_each_ns(s, n) {
				struct json_object *jns = json_create_object();
				int lba;
				uint64_t lba_count, nsze, nuse;

				libnvme_ns_get_lba_size(n, &lba, 0);
				libnvme_ns_get_lba_count(n, &lba_count, 0);
				nsze = lba_count * lba;
				libnvme_ns_get_lba_util(n, &nuse, 0);
				nuse *= lba;

				obj_add_str(jns, "NameSpace",
					    libnvme_ns_get_name(n));
				obj_add_str(jns, "Generic",
					    libnvme_ns_get_generic_name(n));
				obj_add_int(jns, "NSID",
					    libnvme_ns_get_nsid(n));
				obj_add_uint64(jns, "UsedBytes", nuse);
				obj_add_uint64(jns, "MaximumLBA", lba_count);
				obj_add_uint64(jns, "PhysicalSize", nsze);
				obj_add_int(jns, "SectorSize", lba);

				array_add_obj(jnss, jns);
			}
			obj_add_obj(jss, "Namespaces", jnss);

			array_add_obj(jsslist, jss);
		}

		obj_add_obj(hss, "Subsystems", jsslist);
		array_add_obj(jdev, hss);
	}

	obj_add_array(r, "Devices", jdev);
}

static struct json_object *json_list_item_obj(struct libnvme_ns *n)
{
	struct json_object *r = json_create_object();
	char devname[NAME_LEN] = { 0 };
	char genname[NAME_LEN] = { 0 };
	int lba;
	uint64_t lba_count, nsze, nuse;

	libnvme_ns_get_lba_size(n, &lba, 0);
	libnvme_ns_get_lba_count(n, &lba_count, 0);
	nsze = lba_count * lba;
	libnvme_ns_get_lba_util(n, &nuse, 0);
	nuse *= lba;

	nvme_dev_full_path(n, devname, sizeof(devname));
	nvme_generic_full_path(n, genname, sizeof(genname));

	obj_add_int(r, "NameSpace", libnvme_ns_get_nsid(n));
	obj_add_str(r, "DevicePath", devname);
	obj_add_str(r, "GenericPath", genname);
	obj_add_str(r, "Firmware", libnvme_ns_get_firmware(n));
	obj_add_str(r, "ModelNumber", libnvme_ns_get_model(n));
	obj_add_str(r, "SerialNumber", libnvme_ns_get_serial(n));
	obj_add_uint64(r, "UsedBytes", nuse);
	obj_add_uint64(r, "MaximumLBA", lba_count);
	obj_add_uint64(r, "PhysicalSize", nsze);
	obj_add_int(r, "SectorSize", lba);

	return r;
}

static void json_simple_list(struct libnvme_global_ctx *ctx)
{
	struct json_object *r = json_root();
	struct json_object *jdevices = json_create_array();

	struct libnvme_host *h;
	struct libnvme_subsystem *s;
	struct libnvme_ctrl *c;
	struct libnvme_ns *n;

	libnvme_for_each_host(ctx, h) {
		libnvme_for_each_subsystem(h, s) {
			libnvme_subsystem_for_each_ns(s, n)
				array_add_obj(jdevices, json_list_item_obj(n));

			libnvme_subsystem_for_each_ctrl(s, c) {
				libnvme_ctrl_for_each_ns(c, n)
					array_add_obj(jdevices,
						      json_list_item_obj(n));
			}
		}
	}

	obj_add_array(r, "Devices", jdevices);
}

static void json_list_item(struct libnvme_ns *n, struct shr_table *t)
{
	struct json_object *r = json_list_item_obj(n);

	json_print(r);
}

static void json_print_list_items(struct libnvme_global_ctx *ctx)
{
	if (json_list_print_ops.flags & VERBOSE) {
		if (nvme_args.output_format_ver == 2)
			json_detail_list_v2(ctx);
		else
			json_detail_list(ctx);
	} else
		json_simple_list(ctx);
}

static unsigned int
json_subsystem_topology_multipath(struct libnvme_subsystem *s,
				  json_object *namespaces)
{
	struct libnvme_ns *n;
	struct libnvme_path *p;
	unsigned int i = 0;
	const char *iopolicy;

	libnvme_subsystem_get_iopolicy(s, &iopolicy, "");

	libnvme_subsystem_for_each_ns(s, n) {
		struct json_object *ns_attrs;
		struct json_object *paths;

		ns_attrs = json_create_object();
		obj_add_int(ns_attrs, "NSID", libnvme_ns_get_nsid(n));
		obj_add_str(ns_attrs, "Name", libnvme_ns_get_name(n));

		paths = json_create_array();
		libnvme_namespace_for_each_path(n, p) {
			struct json_object *path_attrs;
			struct json_object *ctrls, *ctrl_attrs;
			struct libnvme_ctrl *c;
			const char *ana_state;

			libnvme_path_get_ana_state(p, &ana_state, "");
			path_attrs = json_create_object();
			obj_add_str(path_attrs, "Path",
				    libnvme_path_get_name(p));
			obj_add_str(path_attrs, "ANAState", ana_state);

			/*
			 * For iopolicy numa exclude "Qdepth", for iopolicy
			 * queue-depth exclude "NUMANodes" and for iopolicy
			 * round-robin exclude both "Qdepth" and "NUMANodes".
			 */
			if (streq(iopolicy, "numa")) {
				const char *numa_nodes;

				libnvme_path_get_numa_nodes(p, &numa_nodes,
							     "");
				obj_add_str(path_attrs, "NUMANodes",
						numa_nodes);
			} else if (streq(iopolicy, "queue-depth")) {
				int queue_depth;

				libnvme_path_get_queue_depth(p, &queue_depth,
							      0);
				obj_add_int(path_attrs, "Qdepth", queue_depth);
			}

			c = libnvme_path_get_ctrl(p);
			ctrls = json_create_array();
			ctrl_attrs = json_create_object();
			obj_add_str(ctrl_attrs, "Name",
				    libnvme_ctrl_get_name(c));
			obj_add_str(ctrl_attrs, "Transport",
				    libnvme_ctrl_get_transport(c));
			obj_add_ctrl_address(ctrl_attrs, c);
			obj_add_ctrl_address_details(ctrl_attrs,
						     "AddressDetails", c);
			obj_add_str(ctrl_attrs, "State",
				    libnvme_ctrl_get_state(c));
			array_add_obj(ctrls, ctrl_attrs);
			obj_add_array(path_attrs, "Controller", ctrls);

			array_add_obj(paths, path_attrs);
		}
		obj_add_array(ns_attrs, "Paths", paths);
		array_add_obj(namespaces, ns_attrs);
		i++;
	}

	return i;
}

static void json_print_nvme_subsystem_topology(struct libnvme_subsystem *s,
					       json_object *namespaces)
{
	struct libnvme_ctrl *c;
	struct libnvme_ns *n;

	libnvme_subsystem_for_each_ctrl(s, c) {
		libnvme_ctrl_for_each_ns(c, n) {
			struct json_object *ctrl_attrs;
			struct json_object *ns_attrs;
			struct json_object *ctrl;

			ns_attrs = json_create_object();
			obj_add_int(ns_attrs, "NSID", libnvme_ns_get_nsid(n));
			obj_add_str(ns_attrs, "Name", libnvme_ns_get_name(n));

			ctrl = json_create_array();
			ctrl_attrs = json_create_object();
			obj_add_str(ctrl_attrs, "Name",
						     libnvme_ctrl_get_name(c));
			obj_add_str(ctrl_attrs, "Transport",
						 libnvme_ctrl_get_transport(c));
			obj_add_ctrl_address(ctrl_attrs, c);
			obj_add_ctrl_address_details(ctrl_attrs,
						     "AddressDetails", c);
			obj_add_str(ctrl_attrs, "State",
						     libnvme_ctrl_get_state(c));

			array_add_obj(ctrl, ctrl_attrs);
			obj_add_array(ns_attrs, "Controller", ctrl);
			array_add_obj(namespaces, ns_attrs);
		}
	}
}

static void json_simple_topology(struct libnvme_global_ctx *ctx)
{
	struct json_object *host_attrs, *subsystem_attrs;
	struct json_object *subsystems, *namespaces;
	struct json_object *a = json_create_array();
	struct libnvme_host *h;

	libnvme_for_each_host(ctx, h) {
		struct libnvme_subsystem *s;
		const char *hostid;

		host_attrs = json_create_object();
		obj_add_str(host_attrs, "HostNQN", libnvme_host_get_hostnqn(h));
		hostid = libnvme_host_get_hostid(h);
		if (hostid)
			obj_add_str(host_attrs, "HostID", hostid);
		subsystems = json_create_array();
		libnvme_for_each_subsystem(h, s) {
			const char *iopolicy;

			subsystem_attrs = json_create_object();
			obj_add_str(subsystem_attrs, "Name",
				    libnvme_subsystem_get_name(s));
			obj_add_str(subsystem_attrs, "NQN",
				    libnvme_subsystem_get_subsysnqn(s));
			libnvme_subsystem_get_iopolicy(s, &iopolicy, "");
			obj_add_str(subsystem_attrs, "IOPolicy", iopolicy);

			if (verbose_mode()) {
				const char *model;
				const char *serial;
				const char *firmware;

				libnvme_subsystem_get_model(s, &model, "");
				libnvme_subsystem_get_serial(s, &serial, "");
				libnvme_subsystem_get_firmware(s, &firmware,
								"");

				obj_add_str(subsystem_attrs, "Model", model);
				obj_add_str(subsystem_attrs, "Serial", serial);
				obj_add_str(subsystem_attrs, "Firmware",
						firmware);
				obj_add_str(subsystem_attrs, "Type",
					libnvme_subsystem_get_subsystype(s));
			}

			array_add_obj(subsystems, subsystem_attrs);
			namespaces = json_create_array();

			if (!json_subsystem_topology_multipath(s, namespaces))
				json_print_nvme_subsystem_topology(s,
								   namespaces);

			obj_add_array(subsystem_attrs, "Namespaces",
				      namespaces);
		}
		obj_add_array(host_attrs, "Subsystems", subsystems);
		array_add_obj(a, host_attrs);
	}

	json_print(a);
}

#ifdef CONFIG_TOP
/* A rate with two decimals, as nvme top shows it */
static void obj_add_rate(struct json_object *o, const char *k, double v)
{
	char buf[64];

	snprintf(buf, sizeof(buf), "%.2f", v);
	json_object_object_add(o, k, json_object_new_double_s(v, buf));
}

/* An attribute of a kernel which may not have it is left out */
static void obj_add_count(struct json_object *o, const char *k, int ret,
			  long v)
{
	if (!ret)
		json_object_object_add(o, k, json_object_new_int64(v));
}

static void obj_add_iostat(struct json_object *o, const struct nvme_iostat *st)
{
	struct json_object *r = json_create_object();

	obj_add_rate(r, "ReadIOPS", st->r_iops);
	obj_add_rate(r, "WriteIOPS", st->w_iops);
	obj_add_rate(r, "ReadLatencyMs", st->r_lat);
	obj_add_rate(r, "WriteLatencyMs", st->w_lat);
	obj_add_rate(r, "ReadBytesPerSec", st->r_bw);
	obj_add_rate(r, "WriteBytesPerSec", st->w_bw);
	obj_add_uint(r, "Inflights", st->inflights);
	obj_add_rate(r, "UtilPercent", st->util);

	obj_add_obj(o, "Stats", r);
}

/* The sum of the rates, and the highest latencies and utilization */
static void obj_add_iostat_aggr(struct json_object *o,
				const struct nvme_iostat *st)
{
	struct json_object *r = json_create_object();

	obj_add_rate(r, "ReadIOPS", st->r_iops);
	obj_add_rate(r, "WriteIOPS", st->w_iops);
	obj_add_rate(r, "MaxReadLatencyMs", st->r_lat);
	obj_add_rate(r, "MaxWriteLatencyMs", st->w_lat);
	obj_add_rate(r, "ReadBytesPerSec", st->r_bw);
	obj_add_rate(r, "WriteBytesPerSec", st->w_bw);
	obj_add_rate(r, "MaxUtilPercent", st->util);

	obj_add_obj(o, "Stats", r);
}

static struct json_object *json_top_path(struct libnvme_path *p)
{
	struct json_object *r = json_create_object();
	struct nvme_iostat st;
	const char *str;
	int qdepth, ret;
	long v;

	obj_add_str(r, "Name", libnvme_path_get_name(p));
	obj_add_str(r, "Controller",
		    libnvme_ctrl_get_name(libnvme_path_get_ctrl(p)));
	if (!libnvme_path_get_ana_state(p, &str, NULL))
		obj_add_str(r, "ANAState", str);
	if (!libnvme_path_get_numa_nodes(p, &str, NULL))
		obj_add_str(r, "NUMANodes", str);
	if (!libnvme_path_get_queue_depth(p, &qdepth, 0))
		obj_add_int(r, "Qdepth", qdepth);
	ret = libnvme_path_get_command_retry_count(p, &v, 0);
	obj_add_count(r, "Retries", ret, v);
	ret = libnvme_path_get_multipath_failover_count(p, &v, 0);
	obj_add_count(r, "Failovers", ret, v);
	ret = libnvme_path_get_command_error_count(p, &v, 0);
	obj_add_count(r, "Errors", ret, v);

	nvme_iostat_path(p, &st);
	obj_add_iostat(r, &st);

	return r;
}

static struct json_object *json_top_nshead(struct libnvme_ns *n,
					   struct nvme_iostat *aggr)
{
	struct json_object *r = json_create_object();
	struct json_object *paths = json_create_array();
	struct libnvme_path *p;
	struct nvme_iostat st;
	int ret;
	long v;

	obj_add_str(r, "Name", libnvme_ns_get_name(n));
	obj_add_uint(r, "NSID", libnvme_ns_get_nsid(n));
	ret = libnvme_ns_get_io_requeue_no_usable_path_count(n, &v, 0);
	obj_add_count(r, "RequeueIO", ret, v);
	ret = libnvme_ns_get_io_fail_no_available_path_count(n, &v, 0);
	obj_add_count(r, "FailIO", ret, v);

	nvme_iostat_ns(n, &st);
	nvme_iostat_aggr(aggr, &st);
	obj_add_iostat(r, &st);

	libnvme_namespace_for_each_path(n, p)
		array_add_obj(paths, json_top_path(p));
	obj_add_array(r, "Paths", paths);

	return r;
}

static struct json_object *json_top_ns(struct libnvme_ns *n,
				       struct libnvme_ctrl *c,
				       struct nvme_iostat *aggr)
{
	struct json_object *r = json_create_object();
	struct nvme_iostat st;
	int ret;
	long v;

	obj_add_str(r, "Name", libnvme_ns_get_name(n));
	obj_add_uint(r, "NSID", libnvme_ns_get_nsid(n));
	obj_add_str(r, "Controller", libnvme_ctrl_get_name(c));
	ret = libnvme_ns_get_command_retry_count(n, &v, 0);
	obj_add_count(r, "Retries", ret, v);
	ret = libnvme_ns_get_command_error_count(n, &v, 0);
	obj_add_count(r, "Errors", ret, v);

	nvme_iostat_ns(n, &st);
	nvme_iostat_aggr(aggr, &st);
	obj_add_iostat(r, &st);

	return r;
}

static struct json_object *json_top_ctrl(struct libnvme_ctrl *c,
					 bool multipath)
{
	struct json_object *r = json_create_object();
	struct nvme_iostat aggr = { 0 }, st;
	struct libnvme_path *p;
	struct libnvme_ns *n;
	const char *node;
	int npaths = 0, ret;
	long v;

	obj_add_str(r, "Name", libnvme_ctrl_get_name(c));
	obj_add_str(r, "Transport", libnvme_ctrl_get_transport(c));
	obj_add_ctrl_address(r, c);
	obj_add_str(r, "State", libnvme_ctrl_get_state(c));
	if (!libnvme_ctrl_get_numa_node(c, &node, NULL))
		obj_add_int(r, "NUMANode", atoi(node));
	ret = libnvme_ctrl_get_reset_count(c, &v, 0);
	obj_add_count(r, "Resets", ret, v);
	ret = libnvme_ctrl_get_reconnect_count(c, &v, 0);
	obj_add_count(r, "Reconnects", ret, v);
	ret = libnvme_ctrl_get_command_error_count(c, &v, 0);
	obj_add_count(r, "Errors", ret, v);

	if (multipath) {
		libnvme_ctrl_for_each_path(c, p) {
			npaths++;
			nvme_iostat_path(p, &st);
			nvme_iostat_aggr(&aggr, &st);
		}
		obj_add_int(r, "Paths", npaths);
	} else {
		libnvme_ctrl_for_each_ns(c, n) {
			nvme_iostat_ns(n, &st);
			nvme_iostat_aggr(&aggr, &st);
		}
	}
	obj_add_iostat_aggr(r, &aggr);

	return r;
}

static struct json_object *json_top_subsys(struct libnvme_subsystem *s)
{
	struct json_object *r = json_create_object();
	struct json_object *namespaces = json_create_array();
	struct json_object *ctrls = json_create_array();
	bool multipath = nvme_is_multipath(s);
	struct nvme_iostat aggr = { 0 };
	struct libnvme_ctrl *c;
	struct libnvme_ns *n;
	const char *str;

	obj_add_str(r, "Name", libnvme_subsystem_get_name(s));
	obj_add_str(r, "NQN", libnvme_subsystem_get_subsysnqn(s));
	obj_add_str(r, "HostNQN",
		    libnvme_host_get_hostnqn(libnvme_subsystem_get_host(s)));
	if (!libnvme_subsystem_get_iopolicy(s, &str, NULL))
		obj_add_str(r, "IOPolicy", str);
	if (!libnvme_subsystem_get_model(s, &str, NULL))
		obj_add_str(r, "Model", str);
	if (!libnvme_subsystem_get_serial(s, &str, NULL))
		obj_add_str(r, "Serial", str);
	if (!libnvme_subsystem_get_firmware(s, &str, NULL))
		obj_add_str(r, "Firmware", str);
	obj_add_str(r, "Type", libnvme_subsystem_get_subsystype(s));

	if (multipath) {
		libnvme_subsystem_for_each_ns(s, n)
			array_add_obj(namespaces, json_top_nshead(n, &aggr));
	} else {
		libnvme_subsystem_for_each_ctrl(s, c)
			libnvme_ctrl_for_each_ns(c, n)
				array_add_obj(namespaces,
					      json_top_ns(n, c, &aggr));
	}
	obj_add_iostat_aggr(r, &aggr);
	obj_add_array(r, "Namespaces", namespaces);

	libnvme_subsystem_for_each_ctrl(s, c)
		array_add_obj(ctrls, json_top_ctrl(c, multipath));
	obj_add_array(r, "Controllers", ctrls);

	return r;
}

static void json_top_update(struct libnvme_global_ctx *ctx)
{
	struct libnvme_subsystem *s;
	struct libnvme_host *h;

	libnvme_for_each_host(ctx, h)
		libnvme_for_each_subsystem(h, s)
			nvme_iostat_update_subsys(s, nvme_is_multipath(s));
}

/* Takes two samples @interval seconds apart and prints the rates */
static void json_top(int interval)
{
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	struct json_object *r, *subsystems;
	struct libnvme_subsystem *s;
	struct libnvme_host *h;
	int err;

	err = nvme_create_global_ctx(&ctx);
	if (err)
		return;

	if (libnvme_scan_topology(ctx, NULL, NULL)) {
		nvme_show_error("Failed to scan topology");
		return;
	}

	json_top_update(ctx);
	sleep(interval);
	json_top_update(ctx);

	r = json_create_object();
	obj_add_int(r, "Interval", interval);
	subsystems = json_create_array();
	libnvme_for_each_host(ctx, h)
		libnvme_for_each_subsystem(h, s)
			array_add_obj(subsystems, json_top_subsys(s));
	obj_add_array(r, "Subsystems", subsystems);

	json_print(r);
}
#endif /* CONFIG_TOP */

static struct cmds_list_print_ops json_list_print_ops = {
	.list_item			= json_list_item,
	.list_items			= json_print_list_items,
	.print_nvme_subsystem_list	= json_print_nvme_subsystem_list,
	.topology_ctrl			= json_simple_topology,
	.topology_namespace		= json_simple_topology,
	.topology_multipath		= json_simple_topology,
#ifdef CONFIG_TOP
	.top				= json_top,
#endif
};

struct cmds_list_print_ops *
cmds_list_get_json_print_ops(nvme_print_flags_t flags)
{
	json_list_print_ops.flags = flags;
	return &json_list_print_ops;
}
