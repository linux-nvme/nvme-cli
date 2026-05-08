// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 *
 * Copyright (c) 2021 SUSE Software Solutions
 * Authors: Hannes Reinecke <hare@suse.de>
 *
 * Copyright (c) 2026, Dell Technologies Inc. or its subsidiaries.
 * Authors: Martin Belanger <Martin.Belanger@dell.com>
 */
%begin %{
/* WORKAROUND: The top-level meson.build defines the macro "fallthrough", which
               clashes with the same macro defined in Python.h.
 */
#undef fallthrough

#include <Python.h>

/* WORKAROUND: Py_NewRef() was introduced in Python 3.10. SWIG >= 4.1 generates
               calls to it in its runtime boilerplate, which breaks older
               distributions (e.g. SLES 15.6/15.7 with Python 3.6).
 */
#if PY_VERSION_HEX < 0x030a0000
static inline PyObject *Py_NewRef(PyObject *obj)
{
	Py_INCREF(obj);
	return obj;
}
#endif
%}

%define MODULE_DOCSTRING
"Python bindings for libnvme — the Linux NVMe management library.\n"
"\n"
"Classes\n"
"-------\n"
"GlobalCtx     Root context; owns the device tree and configuration.\n"
"Host          Host (initiator) identity — NQN, host ID, credentials.\n"
"Subsystem     An NVMe subsystem visible to a host.\n"
"Ctrl          An NVMe or NVMe-oF controller; connect, discover, disconnect.\n"
"Namespace     A namespace within a subsystem or controller.\n"
"\n"
"Scan attached NVMe devices::\n"
"\n"
"    import nvme\n"
"    ctx = nvme.GlobalCtx()\n"
"    for host in ctx.hosts():\n"
"        for sub in host.subsystems():\n"
"            for ctrl in sub.controllers():\n"
"                print(ctrl.name, ctrl.transport)\n"
"\n"
"Discover NVMe-oF controllers at a remote target::\n"
"\n"
"    with nvme.Ctrl(ctx, {\n"
"        'subsysnqn': nvme.NVME_DISC_SUBSYS_NAME,\n"
"        'transport': 'tcp',\n"
"        'traddr':    '192.168.1.100',\n"
"        'trsvcid':   '8009',\n"
"    }) as c:\n"
"        c.connect(host)\n"
"        log = c.discover()\n"
"\n"
"All classes support the context manager protocol (the ``with`` statement).\n"
"read_hostnqn() and read_hostid() return the system-wide host NQN and ID.\n"
%enddef
%module(docstring=MODULE_DOCSTRING) nvme
%feature("autodoc", "1");

%include "exception.i"

%allowexception;

PyObject *read_hostnqn();
PyObject *read_hostid();

/*******************************************************************************
 * This is the single C implementation block. All pure C code — headers,
 * #defines, static helpers, and callback implementations — belongs here.
 * Do not introduce additional %{...%} blocks elsewhere in this file.
 * SWIG-specific directives (%typemap, %extend, %exception, %include)
 * follow this block.
 ******************************************************************************/
%{
#include <ccan/list/list.h>
#include <ccan/endian/endian.h>
#include <libnvme.h>
#include "nvme/private.h"
#include "nvme/private-fabrics.h"

#define STR_OR_NONE(str) (!(str) ? "None" : str)

static PyObject *NvmeError             = NULL;
static PyObject *NvmeConnectError      = NULL;
static PyObject *NvmeDisconnectError   = NULL;
static PyObject *NvmeDiscoverError     = NULL;
static PyObject *NvmeNotConnectedError = NULL;

static void raise_nvme(PyObject *cls, int err) {
	const char *s = libnvme_errno_to_string(err < 0 ? -err : err);
	PyObject *args = Py_BuildValue("(is)", err, s ? s : "unknown");
	PyErr_SetObject(cls, args);
	Py_DECREF(args);
}

static void raise_not_connected(void) {
	PyErr_SetString(NvmeNotConnectedError, "Not connected");
}

static void PyDict_SetItemStringDecRef(PyObject * p, const char *key, PyObject *val) {
	PyDict_SetItemString(p, key, val); /* Does NOT steal reference to val .. */
	Py_XDECREF(val);                   /* .. therefore decrement ref. count. */
}
PyObject *read_hostnqn() {
	char * val = libnvme_read_hostnqn();
	PyObject * obj = val ? PyUnicode_FromString(val) : Py_NewRef(Py_None);
	free(val);
	return obj;
}
PyObject *read_hostid() {
	char * val = libnvme_read_hostid();
	PyObject * obj = val ? PyUnicode_FromString(val) : Py_NewRef(Py_None);
	free(val);
	return obj;
}

static const char *dict_get_str(PyObject *dict, const char *key)
{
	PyObject *val = PyDict_GetItemString(dict, key);

	if (!val || val == Py_None)
		return NULL;
	return PyUnicode_AsUTF8(val);
}

static int set_fctx_from_dict(struct libnvmf_context *fctx, PyObject *dict)
{
	struct libnvme_fabrics_config *cfg;
	const char *subsysnqn, *transport;
	const char *hostnqn = NULL, *hostid = NULL;
	const char *hostkey = NULL, *ctrlkey = NULL;
	const char *keyring = NULL, *tls_key = NULL, *tls_key_identity = NULL;
	bool persistent = false;
	bool has_persistent = false;
	Py_ssize_t pos = 0;
	PyObject *key, *value;

	subsysnqn = dict_get_str(dict, "subsysnqn");
	transport = dict_get_str(dict, "transport");

	if (!subsysnqn || !transport) {
		PyErr_SetString(PyExc_KeyError,
				"'subsysnqn' and 'transport' are required");
		return -1;
	}

	libnvmf_context_set_connection(fctx, subsysnqn, transport,
				       dict_get_str(dict, "traddr"),
				       dict_get_str(dict, "trsvcid"),
				       dict_get_str(dict, "host_traddr"),
				       dict_get_str(dict, "host_iface"));

	cfg = libnvmf_context_get_fabrics_config(fctx);

	while (PyDict_Next(dict, &pos, &key, &value)) {
		/* Already consumed above via dict_get_str() */
		if (!PyUnicode_CompareWithASCIIString(key, "subsysnqn") ||
		    !PyUnicode_CompareWithASCIIString(key, "transport") ||
		    !PyUnicode_CompareWithASCIIString(key, "traddr") ||
		    !PyUnicode_CompareWithASCIIString(key, "trsvcid") ||
		    !PyUnicode_CompareWithASCIIString(key, "host_traddr") ||
		    !PyUnicode_CompareWithASCIIString(key, "host_iface"))
			continue;
		if (!PyUnicode_CompareWithASCIIString(key, "queue_size")) {
			cfg->queue_size = PyLong_AsLong(value);
			continue;
		}
		if (!PyUnicode_CompareWithASCIIString(key, "nr_io_queues")) {
			cfg->nr_io_queues = PyLong_AsLong(value);
			continue;
		}
		if (!PyUnicode_CompareWithASCIIString(key, "reconnect_delay")) {
			cfg->reconnect_delay = PyLong_AsLong(value);
			continue;
		}
		if (!PyUnicode_CompareWithASCIIString(key, "ctrl_loss_tmo")) {
			cfg->ctrl_loss_tmo = PyLong_AsLong(value);
			continue;
		}
		if (!PyUnicode_CompareWithASCIIString(key, "fast_io_fail_tmo")) {
			cfg->fast_io_fail_tmo = PyLong_AsLong(value);
			continue;
		}
		if (!PyUnicode_CompareWithASCIIString(key, "keep_alive_tmo")) {
			cfg->keep_alive_tmo = PyLong_AsLong(value);
			continue;
		}
		if (!PyUnicode_CompareWithASCIIString(key, "nr_write_queues")) {
			cfg->nr_write_queues = PyLong_AsLong(value);
			continue;
		}
		if (!PyUnicode_CompareWithASCIIString(key, "nr_poll_queues")) {
			cfg->nr_poll_queues = PyLong_AsLong(value);
			continue;
		}
		if (!PyUnicode_CompareWithASCIIString(key, "tos")) {
			cfg->tos = PyLong_AsLong(value);
			continue;
		}
		if (!PyUnicode_CompareWithASCIIString(key, "keyring_id")) {
			cfg->keyring_id = PyLong_AsLong(value);
			continue;
		}
		if (!PyUnicode_CompareWithASCIIString(key, "tls_key_id")) {
			cfg->tls_key_id = PyLong_AsLong(value);
			continue;
		}
		if (!PyUnicode_CompareWithASCIIString(key, "tls_configured_key_id")) {
			cfg->tls_configured_key_id = PyLong_AsLong(value);
			continue;
		}
		if (!PyUnicode_CompareWithASCIIString(key, "duplicate_connect")) {
			cfg->duplicate_connect = PyObject_IsTrue(value) ? true : false;
			continue;
		}
		if (!PyUnicode_CompareWithASCIIString(key, "disable_sqflow")) {
			cfg->disable_sqflow = PyObject_IsTrue(value) ? true : false;
			continue;
		}
		if (!PyUnicode_CompareWithASCIIString(key, "hdr_digest")) {
			cfg->hdr_digest = PyObject_IsTrue(value) ? true : false;
			continue;
		}
		if (!PyUnicode_CompareWithASCIIString(key, "data_digest")) {
			cfg->data_digest = PyObject_IsTrue(value) ? true : false;
			continue;
		}
		if (!PyUnicode_CompareWithASCIIString(key, "tls")) {
			cfg->tls = PyObject_IsTrue(value) ? true : false;
			continue;
		}
		if (!PyUnicode_CompareWithASCIIString(key, "concat")) {
			cfg->concat = PyObject_IsTrue(value) ? true : false;
			continue;
		}
		if (!PyUnicode_CompareWithASCIIString(key, "hostnqn")) {
			hostnqn = (value != Py_None) ? PyUnicode_AsUTF8(value) : NULL;
			continue;
		}
		if (!PyUnicode_CompareWithASCIIString(key, "hostid")) {
			hostid = (value != Py_None) ? PyUnicode_AsUTF8(value) : NULL;
			continue;
		}
		if (!PyUnicode_CompareWithASCIIString(key, "hostkey")) {
			hostkey = (value != Py_None) ? PyUnicode_AsUTF8(value) : NULL;
			continue;
		}
		if (!PyUnicode_CompareWithASCIIString(key, "ctrlkey")) {
			ctrlkey = (value != Py_None) ? PyUnicode_AsUTF8(value) : NULL;
			continue;
		}
		if (!PyUnicode_CompareWithASCIIString(key, "keyring")) {
			keyring = (value != Py_None) ? PyUnicode_AsUTF8(value) : NULL;
			continue;
		}
		if (!PyUnicode_CompareWithASCIIString(key, "tls_key")) {
			tls_key = (value != Py_None) ? PyUnicode_AsUTF8(value) : NULL;
			continue;
		}
		if (!PyUnicode_CompareWithASCIIString(key, "tls_key_identity")) {
			tls_key_identity = (value != Py_None) ? PyUnicode_AsUTF8(value) : NULL;
			continue;
		}
		if (!PyUnicode_CompareWithASCIIString(key, "persistent")) {
			persistent = PyObject_IsTrue(value) ? true : false;
			has_persistent = true;
			continue;
		}
		PyErr_Format(PyExc_KeyError, "unknown ctrl config key: '%U'", key);
		return -1;
	}

	if (hostnqn || hostid)
		libnvmf_context_set_hostnqn(fctx, hostnqn, hostid);
	if (hostkey || ctrlkey || keyring || tls_key || tls_key_identity)
		libnvmf_context_set_crypto(fctx, hostkey, ctrlkey,
					   keyring, tls_key,
					   tls_key_identity);
	if (has_persistent)
		libnvmf_context_set_persistent(fctx, persistent);

	return 0;
}

/******
NBFT
******/
static PyObject *ssns_to_dict(struct libnbft_subsystem_ns *ss)
{
	unsigned int i;
	PyObject *output = PyDict_New();
	PyObject *hfis = PyList_New(ss->num_hfis);

	for (i = 0; i < ss->num_hfis; i++)
		PyList_SetItem(hfis, i, PyLong_FromLong(ss->hfis[i]->index - 1)); /* steals ref. to object - no need to decref */

	PyDict_SetItemStringDecRef(output, "hfi_indexes", hfis);

	PyDict_SetItemStringDecRef(output, "trtype", PyUnicode_FromString(ss->transport));
	PyDict_SetItemStringDecRef(output, "traddr", PyUnicode_FromString(ss->traddr));
	PyDict_SetItemStringDecRef(output, "trsvcid", PyUnicode_FromString(ss->trsvcid));
	PyDict_SetItemStringDecRef(output, "subsys_port_id", PyLong_FromLong(ss->subsys_port_id));
	PyDict_SetItemStringDecRef(output, "nsid", PyLong_FromLong(ss->nsid));

	{
		PyObject *nid;
		switch (ss->nid_type) {
		case LIBNBFT_NID_TYPE_EUI64:
			PyDict_SetItemStringDecRef(output, "nid_type", PyUnicode_FromString("eui64"));
			nid = PyUnicode_FromFormat("%02x%02x%02x%02x%02x%02x%02x%02x",
						   ss->nid[0], ss->nid[1], ss->nid[2], ss->nid[3],
						   ss->nid[4], ss->nid[5], ss->nid[6], ss->nid[7]);
			break;

		case LIBNBFT_NID_TYPE_NGUID:
			PyDict_SetItemStringDecRef(output, "nid_type", PyUnicode_FromString("nguid"));
			nid = PyUnicode_FromFormat("%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
						   ss->nid[0], ss->nid[1], ss->nid[2], ss->nid[3],
						   ss->nid[4], ss->nid[5], ss->nid[6], ss->nid[7],
						   ss->nid[8], ss->nid[9], ss->nid[10], ss->nid[11],
						   ss->nid[12], ss->nid[13], ss->nid[14], ss->nid[15]);
			break;

		case LIBNBFT_NID_TYPE_NS_UUID:
		{
			char uuid_str[NVME_UUID_LEN_STRING];
			PyDict_SetItemStringDecRef(output, "nid_type", PyUnicode_FromString("uuid"));
			libnvme_uuid_to_string(ss->nid, uuid_str);
			nid = PyUnicode_FromString(uuid_str);
			break;
		}

		default:
			nid = NULL;
			break;
		}
		if (nid)
			PyDict_SetItemStringDecRef(output, "nid", nid);
	}

	if (ss->subsys_nqn)
		PyDict_SetItemStringDecRef(output, "subsys_nqn", PyUnicode_FromString(ss->subsys_nqn));

	PyDict_SetItemStringDecRef(output, "controller_id", PyLong_FromLong(ss->controller_id));
	PyDict_SetItemStringDecRef(output, "asqsz", PyLong_FromLong(ss->asqsz));

	if (ss->dhcp_root_path_string)
		PyDict_SetItemStringDecRef(output, "dhcp_root_path_string", PyUnicode_FromString(ss->dhcp_root_path_string));

	PyDict_SetItemStringDecRef(output, "pdu_header_digest_required", PyBool_FromLong(ss->pdu_header_digest_required));
	PyDict_SetItemStringDecRef(output, "data_digest_required", PyBool_FromLong(ss->data_digest_required));

	return output;
}

static PyObject *hfi_to_dict(struct libnbft_hfi *hfi)
{
	PyObject *output = PyDict_New();

	PyDict_SetItemStringDecRef(output, "trtype", PyUnicode_FromString(hfi->transport));

	if (!strcmp(hfi->transport, "tcp")) {
		PyDict_SetItemStringDecRef(output, "pcidev",
					   PyUnicode_FromFormat("%x:%x:%x.%x",
								((hfi->tcp_info.pci_sbdf & 0xffff0000) >> 16),
								((hfi->tcp_info.pci_sbdf & 0x0000ff00) >> 8),
								((hfi->tcp_info.pci_sbdf & 0x000000f8) >> 3),
								((hfi->tcp_info.pci_sbdf & 0x00000007) >> 0)));

		PyDict_SetItemStringDecRef(output, "mac_addr",
					   PyUnicode_FromFormat("%02x:%02x:%02x:%02x:%02x:%02x",
								hfi->tcp_info.mac_addr[0],
								hfi->tcp_info.mac_addr[1],
								hfi->tcp_info.mac_addr[2],
								hfi->tcp_info.mac_addr[3],
								hfi->tcp_info.mac_addr[4],
								hfi->tcp_info.mac_addr[5]));

		PyDict_SetItemStringDecRef(output, "vlan", PyLong_FromLong(hfi->tcp_info.vlan));
		PyDict_SetItemStringDecRef(output, "ip_origin", PyLong_FromLong(hfi->tcp_info.ip_origin));
		PyDict_SetItemStringDecRef(output, "ipaddr", PyUnicode_FromString(hfi->tcp_info.ipaddr));
		PyDict_SetItemStringDecRef(output, "subnet_mask_prefix", PyLong_FromLong(hfi->tcp_info.subnet_mask_prefix));
		PyDict_SetItemStringDecRef(output, "gateway_ipaddr", PyUnicode_FromString(hfi->tcp_info.gateway_ipaddr));
		PyDict_SetItemStringDecRef(output, "route_metric", PyLong_FromLong(hfi->tcp_info.route_metric));
		PyDict_SetItemStringDecRef(output, "primary_dns_ipaddr", PyUnicode_FromString(hfi->tcp_info.primary_dns_ipaddr));
		PyDict_SetItemStringDecRef(output, "secondary_dns_ipaddr", PyUnicode_FromString(hfi->tcp_info.secondary_dns_ipaddr));
		PyDict_SetItemStringDecRef(output, "dhcp_server_ipaddr", PyUnicode_FromString(hfi->tcp_info.dhcp_server_ipaddr));

		if (hfi->tcp_info.host_name)
			PyDict_SetItemStringDecRef(output, "host_name", PyUnicode_FromString(hfi->tcp_info.host_name));

		PyDict_SetItemStringDecRef(output, "this_hfi_is_default_route", PyBool_FromLong(hfi->tcp_info.this_hfi_is_default_route));
		PyDict_SetItemStringDecRef(output, "dhcp_override", PyBool_FromLong(hfi->tcp_info.dhcp_override));
	}

	return output;
}

static PyObject *discovery_to_dict(struct libnbft_discovery *disc)
{
	PyObject *output = PyDict_New();

	if (disc->security)
		PyDict_SetItemStringDecRef(output, "security_index", PyLong_FromLong(disc->security->index));
	if (disc->hfi)
		PyDict_SetItemStringDecRef(output, "hfi_index", PyLong_FromLong(disc->hfi->index - 1));
	if (disc->uri)
		PyDict_SetItemStringDecRef(output, "uri", PyUnicode_FromString(disc->uri));
	if (disc->nqn)
		PyDict_SetItemStringDecRef(output, "nqn", PyUnicode_FromString(disc->nqn));

	return output;
}

static PyObject *nbft_to_pydict(struct libnbft_info *nbft)
{
	PyObject *val;
	PyObject *output = PyDict_New();

	{
		PyObject *host = PyDict_New();

		if (nbft->host.nqn)
			PyDict_SetItemStringDecRef(host, "nqn", PyUnicode_FromString(nbft->host.nqn));
		if (nbft->host.id) {
			char uuid_str[NVME_UUID_LEN_STRING];
			libnvme_uuid_to_string((unsigned char *)nbft->host.id, uuid_str);
			PyDict_SetItemStringDecRef(host, "id", PyUnicode_FromString(uuid_str));
		}

		PyDict_SetItemStringDecRef(host, "host_id_configured", PyBool_FromLong(nbft->host.host_id_configured));
		PyDict_SetItemStringDecRef(host, "host_nqn_configured", PyBool_FromLong(nbft->host.host_nqn_configured));

		val = PyUnicode_FromString(nbft->host.primary == LIBNBFT_PRIMARY_ADMIN_HOST_FLAG_NOT_INDICATED ? "not indicated" :
					   nbft->host.primary == LIBNBFT_PRIMARY_ADMIN_HOST_FLAG_UNSELECTED ? "unselected" :
					   nbft->host.primary == LIBNBFT_PRIMARY_ADMIN_HOST_FLAG_SELECTED ? "selected" : "reserved");
		PyDict_SetItemStringDecRef(host, "primary_admin_host_flag", val);

		PyDict_SetItemStringDecRef(output, "host", host);
	}

	{
		size_t ss_num = 0;
		struct libnbft_subsystem_ns **ss;
		PyObject *subsystem;

		/* First, let's find how many entries there are */
		for (ss = nbft->subsystem_ns_list; ss && *ss; ss++)
			ss_num++;

		/* Now, let's fill the list using "(*ss)->index - 1"
		   as the index for writing to the list */
		subsystem = PyList_New(ss_num);
		for (ss = nbft->subsystem_ns_list; ss && *ss; ss++)
			PyList_SetItem(subsystem, (*ss)->index - 1, ssns_to_dict(*ss)); /* steals ref. to object - no need to decref */

		PyDict_SetItemStringDecRef(output, "subsystem", subsystem);
	}

	{
		size_t hfi_num = 0;
		struct libnbft_hfi **hfi;
		PyObject *hfis;

		/* First, let's find how many entries there are */
		for (hfi = nbft->hfi_list; hfi && *hfi; hfi++)
			hfi_num++;

		/* Now, let's fill the list using "(*hfi)->index - 1"
		   as the index for writing to the list */
		hfis = PyList_New(hfi_num);
		for (hfi = nbft->hfi_list; hfi && *hfi; hfi++)
			PyList_SetItem(hfis, (*hfi)->index-1, hfi_to_dict(*hfi)); /* steals ref. to object - no need to decref */

		PyDict_SetItemStringDecRef(output, "hfi", hfis);
	}

	{
		size_t disc_num = 0;
		struct libnbft_discovery **disc;
		PyObject *discovery;

		/* First, let's find how many entries there are */
		for (disc = nbft->discovery_list; disc && *disc; disc++)
			disc_num++;

		/* Now, let's fill the list using "(*disc)->index - 1"
		   as the index for writing to the list */
		discovery = PyList_New(disc_num);
		for (disc = nbft->discovery_list; disc && *disc; disc++)
			PyList_SetItem(discovery, (*disc)->index - 1, discovery_to_dict(*disc)); /* steals ref. to object - no need to decref */

		PyDict_SetItemStringDecRef(output, "discovery", discovery);
	}

	/* Security profiles are currently not implemented. */

	return output;
}

PyObject *nbft_get(struct libnvme_global_ctx *ctx, const char * filename)
{
	struct libnbft_info *nbft;
	PyObject *output;
	int ret;

	ret = libnvme_read_nbft(ctx, &nbft, filename);
	if (ret) {
		Py_RETURN_NONE;
	}

	output = nbft_to_pydict(nbft);
	libnvme_free_nbft(ctx, nbft);
	return output;
}
%} /* --------- end C implementation block --------- */

%init %{
	PyObject *_exc = PyImport_ImportModule("libnvme._exceptions");
	NvmeError             = PyObject_GetAttrString(_exc, "NvmeError");
	NvmeConnectError      = PyObject_GetAttrString(_exc, "ConnectError");
	NvmeDisconnectError   = PyObject_GetAttrString(_exc, "DisconnectError");
	NvmeDiscoverError     = PyObject_GetAttrString(_exc, "DiscoverError");
	NvmeNotConnectedError = PyObject_GetAttrString(_exc, "NotConnectedError");
	Py_DECREF(_exc);
%}

%pythoncode %{
from libnvme._exceptions import (
	NvmeError,
	ConnectError,
	DisconnectError,
	DiscoverError,
	NotConnectedError,
)
%}

//##############################################################################

/* All typemaps must be defined before the %include statements below so that
 * they are in scope when SWIG processes the struct and method declarations.
 */

/* Override SWIG's default char * struct-member setter.  SWIG's built-in
 * uses memcpy(malloc(...)) which leaks the old value and triggers
 * -Wdiscarded-qualifiers for const char *.  Use free + strdup instead.
 */
%typemap(memberin) char * {
	free($1);
	$1 = $input ? strdup($input) : NULL;
}
%typemap(memberin) const char * {
	free((char *)$1);
	$1 = $input ? strdup($input) : NULL;
}

/* Convert a Python dict to a struct libnvmf_context * automatically.
 * arg1 is the libnvme_global_ctx * (first argument of the enclosing function).
 * The context is created here and freed by %typemap(freearg) after the call.
 */
%typemap(in) struct libnvmf_context * (struct libnvmf_context *temp = NULL) {
	if (!PyDict_Check($input)) {
		PyErr_SetString(PyExc_TypeError,
				"expected a dict for fabrics context argument");
		SWIG_fail;
	}
	if (libnvmf_context_create(arg1, NULL, NULL, NULL, NULL, &temp)) {
		PyErr_SetString(PyExc_RuntimeError,
				"failed to create fabrics context");
		SWIG_fail;
	}
	if (set_fctx_from_dict(temp, $input)) {
		libnvmf_context_free(temp);
		temp = NULL;
		SWIG_fail;
	}
	$1 = temp;
}

%typemap(freearg) struct libnvmf_context * {
	libnvmf_context_free($1);
}

%typemap(out) uint8_t [8] {
	$result = PyBytes_FromStringAndSize((char *)$1, 8);
};

%typemap(out) uint8_t [16] {
	$result = PyBytes_FromStringAndSize((char *)$1, 16);
};

%typemap(newfree) struct nvmf_discovery_log * {
	free($1);
}

%typemap(out) struct nvmf_discovery_log * {
	struct nvmf_discovery_log *log = $1;
	int numrec = log ? log->numrec : 0, i;
	PyObject *obj = PyList_New(numrec);
	if (!obj) return NULL;

	for (i = 0; i < numrec; i++) {
		struct nvmf_disc_log_entry *e = &log->entries[i];
		PyObject *entry = PyDict_New(), *val;

		switch (e->trtype) {
		case NVMF_TRTYPE_UNSPECIFIED:
			val = PyUnicode_FromString("unspecified");
			break;
		case NVMF_TRTYPE_RDMA:
			val = PyUnicode_FromString("rdma");
			break;
		case NVMF_TRTYPE_FC:
			val = PyUnicode_FromString("fc");
			break;
		case NVMF_TRTYPE_TCP:
			val = PyUnicode_FromString("tcp");
			break;
		case NVMF_TRTYPE_LOOP:
			val = PyUnicode_FromString("loop");
			break;
		default:
			val = PyLong_FromLong(e->trtype);
		}
		PyDict_SetItemStringDecRef(entry, "trtype", val);

		switch (e->adrfam) {
		case NVMF_ADDR_FAMILY_PCI:
			val = PyUnicode_FromString("pci");
			break;
		case NVMF_ADDR_FAMILY_IP4:
			val = PyUnicode_FromString("ipv4");
			break;
		case NVMF_ADDR_FAMILY_IP6:
			val = PyUnicode_FromString("ipv6");
			break;
		case NVMF_ADDR_FAMILY_IB:
			val = PyUnicode_FromString("infiniband");
			break;
		case NVMF_ADDR_FAMILY_FC:
			val = PyUnicode_FromString("fc");
			break;
		default:
			val = PyLong_FromLong(e->adrfam);
		}
		PyDict_SetItemStringDecRef(entry, "adrfam", val);

		val = PyUnicode_FromString(e->traddr);
		PyDict_SetItemStringDecRef(entry, "traddr", val);
		val = PyUnicode_FromString(e->trsvcid);
		PyDict_SetItemStringDecRef(entry, "trsvcid", val);
		val = PyUnicode_FromString(e->subnqn);
		PyDict_SetItemStringDecRef(entry, "subnqn", val);

		switch (e->subtype) {
		case NVME_NQN_DISC:
			val = PyUnicode_FromString("referral");
			break;
		case NVME_NQN_NVME:
			val = PyUnicode_FromString("nvme");
			break;
		case NVME_NQN_CURR:
			val = PyUnicode_FromString("discovery");
			break;
		default:
			val = PyLong_FromLong(e->subtype);
		}
		PyDict_SetItemStringDecRef(entry, "subtype", val);

		switch (e->treq) {
		case NVMF_TREQ_NOT_SPECIFIED:
			val = PyUnicode_FromString("not specified");
			break;
		case NVMF_TREQ_REQUIRED:
			val = PyUnicode_FromString("required");
			break;
		case NVMF_TREQ_NOT_REQUIRED:
			val = PyUnicode_FromString("not required");
			break;
		case NVMF_TREQ_DISABLE_SQFLOW:
			val = PyUnicode_FromString("disable sqflow");
			break;
		default:
			val = PyLong_FromLong(e->treq);
		}
		PyDict_SetItemStringDecRef(entry, "treq", val);

		if (e->trtype ==  NVMF_TRTYPE_TCP) {
			PyObject *tsas = PyDict_New();

			switch (e->tsas.tcp.sectype) {
			case NVMF_TCP_SECTYPE_NONE:
				val = PyUnicode_FromString("none");
				break;
			case NVMF_TCP_SECTYPE_TLS:
				val = PyUnicode_FromString("tls");
				break;
			case NVMF_TCP_SECTYPE_TLS13:
				val = PyUnicode_FromString("tls1.3");
				break;
			default:
				val = PyUnicode_FromString("reserved");
				break;
			}
			PyDict_SetItemStringDecRef(tsas, "sectype", val);
			PyDict_SetItemStringDecRef(entry, "tsas", tsas);
		} else if (e->trtype == NVMF_TRTYPE_RDMA) {
			PyObject *tsas = PyDict_New();

			switch (e->tsas.rdma.qptype) {
			case NVMF_RDMA_QPTYPE_CONNECTED:
				val = PyUnicode_FromString("connected");
				break;
			case NVMF_RDMA_QPTYPE_DATAGRAM:
				val = PyUnicode_FromString("datagram");
				break;
			default:
				val = PyUnicode_FromString("reserved");
				break;
			}
			PyDict_SetItemStringDecRef(tsas, "qptype", val);

			switch (e->tsas.rdma.prtype) {
			case NVMF_RDMA_PRTYPE_NOT_SPECIFIED:
				val = PyUnicode_FromString("not specified");
				break;
			case NVMF_RDMA_PRTYPE_IB:
				val = PyUnicode_FromString("infiniband");
				break;
			case NVMF_RDMA_PRTYPE_ROCE:
				val = PyUnicode_FromString("roce");
				break;
			case NVMF_RDMA_PRTYPE_ROCEV2:
				val = PyUnicode_FromString("rocev2");
				break;
			case NVMF_RDMA_PRTYPE_IWARP:
				val = PyUnicode_FromString("iwarp");
				break;
			default:
				val = PyUnicode_FromString("reserved");
				break;
			}
			PyDict_SetItemStringDecRef(tsas, "prtype", val);

			switch (e->tsas.rdma.cms) {
			case NVMF_RDMA_CMS_RDMA_CM:
				val = PyUnicode_FromString("cm");
				break;
			default:
				val = PyUnicode_FromString("reserved");
				break;
			}
			PyDict_SetItemStringDecRef(tsas, "cms", val);
			PyDict_SetItemStringDecRef(entry, "tsas", tsas);
		}

		val = PyLong_FromLong(e->portid);
		PyDict_SetItemStringDecRef(entry, "portid", val);
		val = PyLong_FromLong(e->cntlid);
		PyDict_SetItemStringDecRef(entry, "cntlid", val);
		val = PyLong_FromLong(e->asqsz);
		PyDict_SetItemStringDecRef(entry, "asqsz", val);
		val = PyLong_FromLong(e->eflags);
		PyDict_SetItemStringDecRef(entry, "eflags", val);
		PyList_SetItem(obj, i, entry); /* steals ref. to object - no need to decref */
	}
	$result = obj;
};

// These %include statements must be located after the main %{...%} block and
// all %typemap directives above, so that typemaps are in scope when SWIG
// processes the struct and method declarations in the included files.
%include "nvme-manual-bridges.i"
%include "accessors.i"
%include "accessors-fabrics.i"

/* Propagate any Python exception set inside the helper function.
 * raise_nvme() sets the exception; SWIG_fail jumps to the fail: label
 * in the wrapper (not in the extracted SWIGINTERN helper), so it must
 * live here rather than inside the %extend function body. */
%exception libnvme_ctrl::connect {
	$action
	if (PyErr_Occurred()) SWIG_fail;
}
%exception libnvme_ctrl::disconnect {
	$action
	if (PyErr_Occurred()) SWIG_fail;
}
%exception libnvme_ctrl::discover {
	$action
	if (PyErr_Occurred()) SWIG_fail;
}

#include "tree.h"
#include "fabrics.h"

%feature("autodoc", "Read an NBFT binary table from disk.\n"
		"\n"
		"Args:\n"
		"    filename: Path to the NBFT binary file.\n"
		"\n"
		"Returns:\n"
		"    A dict containing the NBFT data, or None on failure.") nbft_get;
PyObject *nbft_get(struct libnvme_global_ctx *ctx, const char * filename);

%rename(_libnvme_first_host)        libnvme_first_host;
%rename(_libnvme_next_host)         libnvme_next_host;
%rename(_libnvme_first_subsystem)   libnvme_first_subsystem;
%rename(_libnvme_next_subsystem)    libnvme_next_subsystem;
%rename(_libnvme_subsystem_first_ctrl) libnvme_subsystem_first_ctrl;
%rename(_libnvme_subsystem_next_ctrl)  libnvme_subsystem_next_ctrl;
%rename(_libnvme_subsystem_first_ns)   libnvme_subsystem_first_ns;
%rename(_libnvme_subsystem_next_ns)    libnvme_subsystem_next_ns;
%rename(_libnvme_ctrl_first_ns)     libnvme_ctrl_first_ns;
%rename(_libnvme_ctrl_next_ns)      libnvme_ctrl_next_ns;
struct libnvme_host * libnvme_first_host(struct libnvme_global_ctx * ctx);
struct libnvme_host * libnvme_next_host(struct libnvme_global_ctx *ctx, struct libnvme_host * h);
struct libnvme_subsystem * libnvme_first_subsystem(struct libnvme_host * h);
struct libnvme_subsystem * libnvme_next_subsystem(struct libnvme_host * h, struct libnvme_subsystem * s);
struct libnvme_ctrl * libnvme_subsystem_first_ctrl(struct libnvme_subsystem * s);
struct libnvme_ctrl * libnvme_subsystem_next_ctrl(struct libnvme_subsystem * s, struct libnvme_ctrl * c);
struct libnvme_ns * libnvme_subsystem_first_ns(struct libnvme_subsystem * s);
struct libnvme_ns * libnvme_subsystem_next_ns(struct libnvme_subsystem * s, struct libnvme_ns * n);
struct libnvme_ns * libnvme_ctrl_first_ns(struct libnvme_ctrl * c);
struct libnvme_ns * libnvme_ctrl_next_ns(struct libnvme_ctrl * c, struct libnvme_ns * n);

%extend libnvme_global_ctx {
	%feature("autodoc", "__init__(self, config_file=None)\n"
		"\n"
		"Create the root context for the libnvme device tree.\n"
		"\n"
		"Scans the NVMe topology and loads configuration on creation.\n"
		"Supports use as a context manager (``with GlobalCtx() as ctx:``).\n"
		"\n"
		"Args:\n"
		"    config_file: Path to a JSON config file, or None for defaults.") libnvme_global_ctx;
	libnvme_global_ctx(const char *config_file = NULL) {
		struct libnvme_global_ctx *ctx;

		ctx = libnvme_create_global_ctx(stdout, LIBNVME_DEFAULT_LOGLEVEL);
		if (!ctx)
			return NULL;

		libnvme_scan_topology(ctx, NULL, NULL);
		libnvme_read_config(ctx, config_file);

		return ctx;
	}
	~libnvme_global_ctx() {
		libnvme_free_global_ctx($self);
	}
	struct libnvme_global_ctx* __enter__() {
		return $self;
	}
	struct libnvme_global_ctx* __exit__(PyObject *type, PyObject *value, PyObject *traceback) {
		return $self;
	}
	%feature("autodoc", "Set the libnvme logging verbosity.\n"
		"\n"
		"Args:\n"
		"    level: One of 'debug', 'info', 'warning', or 'err'.") log_level;
	void log_level(const char *level) {
		int log_level = LIBNVME_DEFAULT_LOGLEVEL;
		if (!strcmp(level, "debug")) log_level = LIBNVME_LOG_DEBUG;
		else if (!strcmp(level, "info")) log_level = LIBNVME_LOG_INFO;
		else if (!strcmp(level, "warning")) log_level = LIBNVME_LOG_WARN;
		else if (!strcmp(level, "err")) log_level = LIBNVME_LOG_ERR;
		libnvme_set_logging_level($self, log_level, false, false);
	}
	%pythoncode %{
	def hosts(self):
	    """Yield each Host in this context."""
	    h = _libnvme_first_host(self)
	    while h:
	        yield h
	        h = _libnvme_next_host(self, h)
	%}
	%feature("autodoc", "Rescan the NVMe topology and update the device tree.") refresh_topology;
	void refresh_topology() {
		libnvme_refresh_topology($self);
	}
	void dump_config() {
		libnvme_dump_config($self, STDERR_FILENO);
	}
}



%pythonappend libnvme_host::libnvme_host(struct libnvme_global_ctx *ctx,
				   const char *hostnqn,
				   const char *hostid,
				   const char *hostkey,
				   const char *hostsymname) {
	self.__parent = ctx  # Keep a reference to parent to ensure garbage collection happens in the right order}
%extend libnvme_host {
	%feature("autodoc", "__init__(self, ctx, hostnqn=None, hostid=None, hostkey=None, hostsymname=None)\n"
		"\n"
		"Create a host (initiator) identity object.\n"
		"\n"
		"Supports use as a context manager (``with Host(ctx) as h:``).\n"
		"\n"
		"Args:\n"
		"    ctx:         Global context.\n"
		"    hostnqn:     Host NQN. Defaults to the system-wide value.\n"
		"    hostid:      Host UUID. Defaults to the system-wide value.\n"
		"    hostkey:     DH-HMAC-CHAP host key.\n"
		"    hostsymname: Symbolic host name.") libnvme_host;
	libnvme_host(struct libnvme_global_ctx *ctx,
		     const char *hostnqn = NULL,
		     const char *hostid = NULL,
		     const char *hostkey = NULL,
		     const char *hostsymname = NULL) {
		libnvme_host_t h;

		if (libnvme_get_host(ctx, hostnqn, hostid, &h))
			return NULL;
		if (hostsymname)
			libnvme_host_set_hostsymname(h, hostsymname);
		if (hostkey)
			libnvme_host_set_dhchap_host_key(h, hostkey);

		return h;
	}
	~libnvme_host() {
		libnvme_free_host($self);
	}
	struct libnvme_host* __enter__() {
		return $self;
	}
	struct libnvme_host* __exit__(PyObject *type, PyObject *value, PyObject *traceback) {
		return $self;
	}
	PyObject* __str__() {
		return PyUnicode_FromFormat("nvme.Host(%s,%s)", STR_OR_NONE($self->hostnqn), STR_OR_NONE($self->hostid));
	}
	%pythoncode %{
	def subsystems(self):
	    """Yield each Subsystem under this host."""
	    s = _libnvme_first_subsystem(self)
	    while s:
	        yield s
	        s = _libnvme_next_subsystem(self, s)
	%}
}


%pythonappend libnvme_subsystem::libnvme_subsystem(struct libnvme_global_ctx *ctx,
					     struct libnvme_host *host,
					     const char *subsysnqn,
					     const char *name) {
    self.__parent = host  # Keep a reference to parent to ensure garbage collection happens in the right order}
%extend libnvme_subsystem {
	%feature("autodoc", "__init__(self, ctx, host, subsysnqn, name=None)\n"
		"\n"
		"Look up or create a subsystem entry under the given host.\n"
		"\n"
		"Args:\n"
		"    ctx:       Global context.\n"
		"    host:      Parent Host object.\n"
		"    subsysnqn: Subsystem NQN.\n"
		"    name:      Optional subsystem device name.") libnvme_subsystem;
	libnvme_subsystem(struct libnvme_global_ctx *ctx,
			  struct libnvme_host *host,
			  const char *subsysnqn,
			  const char *name = NULL) {
		struct libnvme_subsystem *s;

		if (libnvme_get_subsystem(ctx, host, name, subsysnqn, &s))
			return NULL;

		return s;
	}
	~libnvme_subsystem() {
		libnvme_free_subsystem($self);
	}
	struct libnvme_subsystem* __enter__() {
		return $self;
	}
	struct libnvme_subsystem* __exit__(PyObject *type, PyObject *value, PyObject *traceback) {
		return $self;
	}
	PyObject *__str__() {
		return PyUnicode_FromFormat("nvme.Subsystem(%s,%s)", STR_OR_NONE($self->name), STR_OR_NONE($self->subsysnqn));
	}
	%pythoncode %{
	def controllers(self):
	    """Yield each Ctrl under this subsystem."""
	    c = _libnvme_subsystem_first_ctrl(self)
	    while c:
	        yield c
	        c = _libnvme_subsystem_next_ctrl(self, c)
	%}
	%pythoncode %{
	def namespaces(self):
	    """Yield each Namespace under this subsystem."""
	    ns = _libnvme_subsystem_first_ns(self)
	    while ns:
	        yield ns
	        ns = _libnvme_subsystem_next_ns(self, ns)
	%}
	%immutable host;
	struct libnvme_host *host;
}


%pythonappend libnvme_ctrl::connect(struct libnvme_host *h) {
    self.__host = h  # Keep a reference to parent to ensure ctrl obj gets GCed before host}
%pythonappend libnvme_ctrl::load_from_device(struct libnvme_host *h, int instance) {
    self.__host = h  # Keep a reference to parent to ensure ctrl obj gets GCed before host}
%extend libnvme_ctrl {
	%feature("autodoc", "__init__(self, ctx, cfg)\n"
		"\n"
		"Create a new NVMe-oF controller object.\n"
		"\n"
		"``cfg`` is a flat dict — all keys are at the top level, no nesting.\n"
		"An unknown key raises KeyError immediately.\n"
		"\n"
		"  cfg keys:\n"
		"\n"
		"    Required:\n"
		"      subsysnqn (str)  -- Subsystem NQN\n"
		"      transport (str)  -- Transport type: 'tcp', 'rdma', 'loop', 'fc'\n"
		"\n"
		"    Connection (optional):\n"
		"      traddr (str)       -- Transport address\n"
		"      trsvcid (str)      -- Service ID (port number)\n"
		"      host_traddr (str)  -- Host transport address\n"
		"      host_iface (str)   -- Host network interface\n"
		"\n"
		"    Fabrics config (optional):\n"
		"      queue_size (int)             -- IO queue entries\n"
		"      nr_io_queues (int)           -- Number of IO queues\n"
		"      reconnect_delay (int)        -- Reconnect interval in seconds\n"
		"      ctrl_loss_tmo (int)          -- Controller loss timeout in seconds\n"
		"      fast_io_fail_tmo (int)       -- Fast I/O fail timeout in seconds\n"
		"      keep_alive_tmo (int)         -- Keep-alive timeout in seconds\n"
		"      nr_write_queues (int)        -- Queues reserved for writes only\n"
		"      nr_poll_queues (int)         -- Queues reserved for polling\n"
		"      tos (int)                    -- Type of service\n"
		"      keyring_id (int)             -- Keyring ID for key lookup\n"
		"      tls_key_id (int)             -- TLS PSK key ID\n"
		"      tls_configured_key_id (int)  -- TLS PSK key ID for connect command\n"
		"      duplicate_connect (bool)     -- Allow duplicate connections\n"
		"      disable_sqflow (bool)        -- Disable SQ flow control\n"
		"      hdr_digest (bool)            -- Header digest (TCP only)\n"
		"      data_digest (bool)           -- Data digest (TCP only)\n"
		"      tls (bool)                   -- Enable TLS (TCP only)\n"
		"      concat (bool)                -- Secure concatenation (TCP only)\n"
		"\n"
		"    Host identity (optional):\n"
		"      hostnqn (str)  -- Host NQN, overrides the system-wide default\n"
		"      hostid (str)   -- Host ID, overrides the system-wide default\n"
		"\n"
		"    Authentication and TLS (optional):\n"
		"      hostkey (str)           -- Host DH-HMAC-CHAP key\n"
		"      ctrlkey (str)           -- Controller DH-HMAC-CHAP key\n"
		"      keyring (str)           -- Keyring identifier\n"
		"      tls_key (str)           -- TLS key, or 'pin:<value>' for PIN-derived key\n"
		"      tls_key_identity (str)  -- TLS key identity string\n"
		"\n"
		"    Persistence (optional):\n"
		"      persistent (bool)  -- Keep connection alive after process exit\n"
		"\n"
		"  Examples::\n"
		"\n"
		"    import nvme\n"
		"\n"
		"    ctx = nvme.GlobalCtx()\n"
		"\n"
		"    # Discover controllers at a remote target\n"
		"    with nvme.Ctrl(ctx, {\n"
		"        'subsysnqn': 'nqn.2014-08.org.nvmexpress.discovery',\n"
		"        'transport': 'tcp',\n"
		"        'traddr':    '192.168.1.100',\n"
		"        'trsvcid':   '8009',\n"
		"    }) as c:\n"
		"        log = c.discover()\n"
		"\n"
		"    # Connect to a subsystem with TLS and header digest\n"
		"    host = nvme.Host(ctx)\n"
		"    with nvme.Ctrl(ctx, {\n"
		"        'subsysnqn':  'nqn.2019-08.org.nvmexpress:uuid:...',\n"
		"        'transport':  'tcp',\n"
		"        'traddr':     '192.168.1.100',\n"
		"        'trsvcid':    '4420',\n"
		"        'hdr_digest': True,\n"
		"        'tls':        True,\n"
		"    }) as c:\n"
		"        c.connect(host)\n"
	) libnvme_ctrl;
	libnvme_ctrl(struct libnvme_global_ctx *ctx, struct libnvmf_context *fctx) {
		struct libnvme_ctrl *c;

		if (libnvmf_create_ctrl(ctx, fctx, &c)) {
			PyErr_SetString(PyExc_RuntimeError,
					"failed to create ctrl");
			return NULL;
		}
		return c;
	}
	~libnvme_ctrl() {
		libnvme_free_ctrl($self);
	}
	struct libnvme_ctrl* __enter__() {
		return $self;
	}
	struct libnvme_ctrl* __exit__(PyObject *type, PyObject *value, PyObject *traceback) {
		if (libnvme_ctrl_get_name($self))
			libnvmf_disconnect_ctrl($self);
		return $self;
	}

	%feature("autodoc", "Bind this controller object to an existing kernel NVMe device.\n"
		"\n"
		"Associates the object with the kernel device identified by\n"
		"``instance`` (e.g. 0 for /dev/nvme0).\n"
		"\n"
		"Args:\n"
		"    h:        Host object.\n"
		"    instance: Kernel device instance number.\n"
		"\n"
		"Returns:\n"
		"    True on success, False on failure.") load_from_device;
	bool load_from_device(struct libnvme_host *h, int instance) {
		return libnvme_init_ctrl(h, $self, instance) == 0;
	}

	%feature("autodoc", "Connect this controller to an NVMe-oF target.\n"
		"\n"
		"Establishes the kernel connection. This call may block while\n"
		"performing network operations. Other Python threads continue\n"
		"to run during this time.\n"
		"\n"
		"Args:\n"
		"    h: Host object to associate with the connection.\n"
		"\n"
		"Raises:\n"
		"    ConnectError: Connection failed.") connect;
	void connect(struct libnvme_host *h) {
		int ret;

		Py_BEGIN_ALLOW_THREADS  /* Release Python GIL */
		ret = libnvmf_add_ctrl(h, $self);
		Py_END_ALLOW_THREADS    /* Reacquire Python GIL */

		if (ret) {
			raise_nvme(NvmeConnectError, ret);
			return;
		}
	}
	%feature("autodoc", "Rescan this controller and refresh its namespace list.") rescan;
	void rescan() {
		libnvme_rescan_ctrl($self);
	}
	%feature("autodoc", "Disconnect this controller from the NVMe-oF target.\n"
		"\n"
		"Raises:\n"
		"    NotConnectedError: Controller is not currently connected.\n"
		"    DisconnectError: Disconnect failed.") disconnect;
	void disconnect() {
		int ret;
		const char *dev;

		dev = libnvme_ctrl_get_name($self);
		if (!dev) {
			raise_not_connected();
			return;
		}
		Py_BEGIN_ALLOW_THREADS  /* Release Python GIL */
		ret = libnvmf_disconnect_ctrl($self);
		Py_END_ALLOW_THREADS    /* Reacquire Python GIL */
		if (ret < 0) {
			raise_nvme(NvmeDisconnectError, ret);
			return;
		}
	}

	bool _registration_supported() {
		return libnvmf_is_registration_supported($self);
	}
	bool _connected() {
		return libnvme_ctrl_get_name($self) != NULL;
	}
	%pythoncode %{
	@property
	def connected(self):
		"""True if this controller is currently connected."""
		return self._connected()
	@property
	def registration_supported(self):
		"""True if this controller supports explicit host registration."""
		return self._registration_supported()
	%}

	%feature("autodoc", "Register this controller with the NVMe-oF DIM service.\n"
		"\n"
		"Returns:\n"
		"    None on success, or an error string describing the failure.") registration_control;
	PyObject *registration_control(enum nvmf_dim_tas tas) {
		__u32 result;
		int   status;

		Py_BEGIN_ALLOW_THREADS  /* Release Python GIL */
		    status = libnvmf_register_ctrl($self, NVMF_DIM_TAS_REGISTER, &result);
		Py_END_ALLOW_THREADS    /* Reacquire Python GIL */

		if (status != NVME_SC_SUCCESS) {
			/* On error, return an error message */
			return (status < 0) ?
			    PyUnicode_FromFormat("Status:0x%04x - %s", status, libnvme_status_to_string(status, false)) :
			    PyUnicode_FromFormat("Result:0x%04x, Status:0x%04x - %s", result, status, libnvme_status_to_string(status, false));
		}

		/* On success, return None */
		Py_RETURN_NONE;
	}

	%feature("autodoc", "Retrieve the discovery log page from a connected discovery controller.\n"
		"\n"
		"This call may block while performing network operations.\n"
		"Other Python threads continue to run during this time.\n"
		"\n"
		"Args:\n"
		"    lsp:         Log Specific Parameter (default 0).\n"
		"    max_retries: Maximum number of retries (default 6).\n"
		"\n"
		"Returns:\n"
		"    A list of discovery log entries. Each entry is a dictionary\n"
		"    describing a reachable controller or referral, with keys such\n"
		"    as ``trtype``, ``traddr``, ``trsvcid``, ``subnqn``, and\n"
		"    ``subtype``.\n"
		"\n"
		"Raises:\n"
		"    NotConnectedError: Controller is not connected.\n"
		"    DiscoverError: Discovery failed.") discover;
	%newobject discover;
	struct nvmf_discovery_log *discover(int lsp = 0, int max_retries = 6) {
		struct nvmf_discovery_log *logp = NULL;
		struct libnvmf_discovery_args *args = NULL;
		int ret;

		if (!libnvme_ctrl_get_name($self)) {
			raise_not_connected();
			return NULL;
		}
		ret = libnvmf_discovery_args_new(&args);
		if (ret) {
			raise_nvme(NvmeDiscoverError, ret);
			return NULL;
		}
		libnvmf_discovery_args_set_lsp(args, lsp);
		libnvmf_discovery_args_set_max_retries(args, max_retries);
		Py_BEGIN_ALLOW_THREADS  /* Release Python GIL */
		    ret = libnvmf_get_discovery_log($self, args, &logp);
		Py_END_ALLOW_THREADS    /* Reacquire Python GIL */
		libnvmf_discovery_args_free(args);

		if (ret || logp == NULL) {
			raise_nvme(NvmeDiscoverError, ret);
			return NULL;
		}
		return logp;
	}

	%feature("autodoc", "Fetch the Supported Log Pages log.\n"
		"\n"
		"Args:\n"
		"    rae: Retain Asynchronous Events (default True).\n"
		"\n"
		"Returns:\n"
		"    A list of integers, one per Log Identifier, encoding its\n"
		"    supported features.\n"
		"\n"
		"Raises:\n"
		"    NvmeError: The command failed.") get_supported_log_pages;
	PyObject *get_supported_log_pages(bool rae = true) {
		struct nvme_supported_log_pages log;
		struct libnvme_passthru_cmd cmd;
		PyObject *obj = NULL;
		int ret = 0;

		Py_BEGIN_ALLOW_THREADS  /* Release Python GIL */
		    nvme_init_get_log_supported_log_pages(&cmd, NVME_CSI_NVM, &log);
		    ret = libnvme_get_log(libnvme_ctrl_get_transport_handle($self), &cmd, rae, NVME_LOG_PAGE_PDU_SIZE);
		Py_END_ALLOW_THREADS    /* Reacquire Python GIL */

		if (ret) {
			raise_nvme(NvmeError, ret);
			return NULL;
		}

		obj = PyList_New(NVME_LOG_SUPPORTED_LOG_PAGES_MAX);
		if (!obj) return NULL;

		for (int i = 0; i < NVME_LOG_SUPPORTED_LOG_PAGES_MAX; i++)
			PyList_SetItem(obj, i, PyLong_FromLong(le32_to_cpu(log.lid_support[i]))); /* steals ref. to object - no need to decref */

		return obj;
	}

	PyObject* __str__() {
		return $self->address ?
		       PyUnicode_FromFormat("nvme.Ctrl(transport=%s,%s)", STR_OR_NONE($self->transport), STR_OR_NONE($self->address)) :
		       PyUnicode_FromFormat("nvme.Ctrl(transport=%s)", STR_OR_NONE($self->transport));
	}

	%pythoncode %{
	def namespaces(self):
	    """Yield each Namespace under this controller."""
	    ns = _libnvme_ctrl_first_ns(self)
	    while ns:
	        yield ns
	        ns = _libnvme_ctrl_next_ns(self, ns)
	%}
}


%pythonappend libnvme_ns::libnvme_ns(struct libnvme_subsystem *s,
			       unsigned int nsid) {
    self.__parent = s  # Keep a reference to parent to ensure garbage collection happens in the right order}
%extend libnvme_ns {
	%feature("autodoc", "__init__(self, subsystem, nsid)\n"
		"\n"
		"Look up a namespace by ID within a subsystem.\n"
		"\n"
		"Args:\n"
		"    subsystem: Parent Subsystem object.\n"
		"    nsid:      Namespace identifier.") libnvme_ns;
	libnvme_ns(struct libnvme_subsystem *s,
		unsigned int nsid) {
		return libnvme_subsystem_lookup_namespace(s, nsid);
	}
	~libnvme_ns() {
		libnvme_free_ns($self);
	}
	struct libnvme_ns* __enter__() {
		return $self;
	}
	struct libnvme_ns* __exit__(PyObject *type, PyObject *value, PyObject *traceback) {
		return $self;
	}
	PyObject *__str__() {
		return PyUnicode_FromFormat("nvme.Namespace(%u)", $self->nsid);
	}
}


// We want to swig all the #define and enum from nvme-types.h, but none of the structs.
#pragma SWIG nowarn=503             // Supress warnings about unnamed struct
#define __attribute__(x)
%rename($ignore, %$isclass) "";     // ignore all classes/structs
%rename($ignore, %$isfunction) "";  // ignore all functions
%rename($ignore, %$isunion) "";     // ignore all unions
%rename($ignore, %$isvariable) "";  // ignore all variables

%include "../src/nvme/nvme-types.h"
