// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2021 SUSE Software Solutions
 *
 * Authors: Hannes Reinecke <hare@suse.de>
 */

%module(docstring="Python bindings for libnvme") nvme
%feature("autodoc", "1");

%include "exception.i"

%allowexception;

%rename(root)      nvme_root;
%rename(host)      nvme_host;
%rename(ctrl)      nvme_ctrl;
%rename(subsystem) nvme_subsystem;
%rename(ns)        nvme_ns;

%{
	#include <ccan/list/list.h>
	#include <ccan/endian/endian.h>
	#include "nvme/tree.h"
	#include "nvme/fabrics.h"
	#include "nvme/private.h"
	#include "nvme/log.h"
	#include "nvme/ioctl.h"
	#include "nvme/types.h"
	#include "nvme/nbft.h"

	static int host_iter_err = 0;
	static int subsys_iter_err = 0;
	static int ctrl_iter_err = 0;
	static int ns_iter_err = 0;
	static int connect_err = 0;
	static int discover_err = 0;

	static void PyDict_SetItemStringDecRef(PyObject * p, const char *key, PyObject *val) {
		PyDict_SetItemString(p, key, val); /* Does NOT steal reference to val .. */
		Py_XDECREF(val);                   /* .. therefore decrement ref. count. */
	}
	PyObject *hostnqn_from_file() {
		char * val = nvmf_hostnqn_from_file();
		PyObject * obj = PyUnicode_FromString(val);
		free(val);
		return obj;
	}
	PyObject *hostid_from_file() {
		char * val = nvmf_hostid_from_file();
		PyObject * obj = PyUnicode_FromString(val);
		free(val);
		return obj;
	}
%}
PyObject *hostnqn_from_file();
PyObject *hostid_from_file();

%inline %{
	struct host_iter {
		struct nvme_root *root;
		struct nvme_host *pos;
	};

	struct subsystem_iter {
		struct nvme_host *host;
		struct nvme_subsystem *pos;
	};

	struct ctrl_iter {
		struct nvme_subsystem *subsystem;
		struct nvme_ctrl *pos;
	};

	struct ns_iter {
		struct nvme_subsystem *subsystem;
		struct nvme_ctrl *ctrl;
		struct nvme_ns *pos;
	};
%}

%exception host_iter::__next__ {
	host_iter_err = 0;
	$action  /* $action sets host_iter_err to non-zero value on failure */
	if (host_iter_err) {
		PyErr_SetString(PyExc_StopIteration, "End of list");
		return NULL;
	}
}

%exception subsystem_iter::__next__ {
	subsys_iter_err = 0;
	$action  /* $action sets subsys_iter_err to non-zero value on failure */
	if (subsys_iter_err) {
		PyErr_SetString(PyExc_StopIteration, "End of list");
		return NULL;
	}
}

%exception ctrl_iter::__next__ {
	ctrl_iter_err = 0;
	$action  /* $action sets ctrl_iter_err to non-zero value on failure */
	if (ctrl_iter_err) {
		PyErr_SetString(PyExc_StopIteration, "End of list");
		return NULL;
	}
}

%exception ns_iter::__next__ {
	ns_iter_err = 0;
	$action  /* $action sets ns_iter_err to non-zero value on failure */
	if (ns_iter_err) {
		PyErr_SetString(PyExc_StopIteration, "End of list");
		return NULL;
	}
}

%exception nvme_ctrl::connect {
	connect_err = 0;
	errno = 0;
	$action  /* $action sets connect_err to non-zero value on failure */
	if (connect_err == 1) {
		SWIG_exception(SWIG_AttributeError, "Existing controller connection");
	} else if (connect_err) {
		const char *errstr = nvme_errno_to_string(errno);
		if (errstr) {
			SWIG_exception(SWIG_RuntimeError, errstr);
		} else {
			SWIG_exception(SWIG_RuntimeError, "Connect failed");
		}
	}
}

%exception nvme_ctrl::discover {
	discover_err = 0;
	$action  /* $action sets discover_err to non-zero value on failure */
	if (discover_err == 1) {
		SWIG_exception(SWIG_AttributeError, "No controller connection");
	} else if (discover_err) {
		SWIG_exception(SWIG_RuntimeError, "Discover failed");
	}
}

%typemap(in) struct nvme_fabrics_config *($*1_type temp){
	Py_ssize_t pos = 0;
	PyObject * key,*value;
	memset(&temp, 0, sizeof(temp));
	temp.tos = -1;
	temp.ctrl_loss_tmo = NVMF_DEF_CTRL_LOSS_TMO;
	while (PyDict_Next($input, &pos, &key, &value)) {
		if (!PyUnicode_CompareWithASCIIString(key, "host_traddr")) {
			temp.host_traddr = PyBytes_AsString(value);
			continue;
		}
		if (!PyUnicode_CompareWithASCIIString(key, "host_iface")) {
			temp.host_iface = PyBytes_AsString(value);
			continue;
		}
		if (!PyUnicode_CompareWithASCIIString(key, "nr_io_queues")) {
			temp.nr_io_queues = PyLong_AsLong(value);
			continue;
		}
		if (!PyUnicode_CompareWithASCIIString(key, "reconnect_delay")) {
			temp.reconnect_delay = PyLong_AsLong(value);
			continue;
		}
		if (!PyUnicode_CompareWithASCIIString(key, "ctrl_loss_tmo")) {
			temp.ctrl_loss_tmo = PyLong_AsLong(value);
			continue;
		}
		if (!PyUnicode_CompareWithASCIIString(key, "keep_alive_tmo")) {
			temp.keep_alive_tmo = PyLong_AsLong(value);
			continue;
		}
		if (!PyUnicode_CompareWithASCIIString(key, "nr_write_queues")) {
			temp.nr_write_queues = PyLong_AsLong(value);
			continue;
		}
		if (!PyUnicode_CompareWithASCIIString(key, "nr_poll_queues")) {
			temp.nr_poll_queues = PyLong_AsLong(value);
			continue;
		}
		if (!PyUnicode_CompareWithASCIIString(key, "tos")) {
			temp.tos = PyLong_AsLong(value);
			continue;
		}
		if (!PyUnicode_CompareWithASCIIString(key, "duplicate_connect")) {
			temp.duplicate_connect = PyObject_IsTrue(value) ? true : false;
			continue;
		}
		if (!PyUnicode_CompareWithASCIIString(key, "disable_sqflow")) {
			temp.disable_sqflow = PyObject_IsTrue(value) ? true : false;
			continue;
		}
		if (!PyUnicode_CompareWithASCIIString(key, "hdr_digest")) {
			temp.hdr_digest = PyObject_IsTrue(value) ? true : false;
			continue;
		}
		if (!PyUnicode_CompareWithASCIIString(key, "data_digest")) {
			temp.data_digest = PyObject_IsTrue(value) ? true : false;
			continue;
		}
	}
	$1 = &temp;
};

%typemap(out) uint8_t [8] {
	$result = PyBytes_FromStringAndSize((char *)$1, 8);
};

%typemap(out) uint8_t [16] {
	$result = PyBytes_FromStringAndSize((char *)$1, 16);
};

%typemap(newfree) struct nvmf_discovery_log * {
	if ($1) free($1);
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

#include "tree.h"
#include "fabrics.h"
#define STR_OR_NONE(str) (!(str) ? "None" : str)

struct nvme_root {
	%immutable config_file;
	%immutable application;
	char *config_file;
	char *application;
};

struct nvme_host {
	%immutable hostnqn;
	%immutable hostid;
	%immutable hostsymname;
	char *hostnqn;
	char *hostid;
	char *hostsymname;
	%extend {
		char *dhchap_key;
	}
};

struct nvme_subsystem {
	%immutable subsysnqn;
	%immutable model;
	%immutable serial;
	%immutable firmware;
	%immutable application;
	char *subsysnqn;
	char *model;
	char *serial;
	char *firmware;
	char *application;
};

struct nvme_ctrl {
	%immutable name;
	%immutable subsystem;
	%immutable state;
	%immutable sysfs_dir;
	%immutable address;
	%immutable firmware;
	%immutable model;
	%immutable numa_node;
	%immutable queue_count;
	%immutable serial;
	%immutable sqsize;
	%immutable transport;
	%immutable subsysnqn;
	%immutable traddr;
	%immutable trsvcid;
	%immutable cntrltype;
	%immutable cntlid;
	%immutable dctype;
	%immutable phy_slot;
	%immutable discovered;

	const char *cntrltype;  // Do not put in %extend because there's no getter method in libnvme.map
	const char *dctype;     // Do not put in %extend because there's no getter method in libnvme.map
	const bool discovered;  // Do not put in %extend because there's no getter method in libnvme.map

	%extend {
		/**
		 * By putting these attributes in an %extend block, we're
		 * forcing SWIG to invoke getter/setter methods instead of
		 * accessing the members directly.
		 *
		 * For example, SWIG will generate code like this:
		 *    name = nvme_ctrl_name_get(ctrl)
		 *
		 * instead of that:
		 *    name = ctrl->name
		 */
		const char *name;
		const char *state;
		const char *sysfs_dir;
		const char *address;
		const char *firmware;
		const char *model;
		const char *numa_node;
		const char *queue_count;
		const char *serial;
		const char *sqsize;
		const char *transport;
		const char *subsysnqn;
		const char *traddr;
		const char *trsvcid;
		const char *cntlid;
		const char *phy_slot;

		bool unique_discovery_ctrl;
		bool discovery_ctrl;
		bool persistent;

		char *keyring;
		char *tls_key_identity;
		char *tls_key;

		/**
		 * We are remapping the following members of the C code's
		 * nvme_ctrl_t to different names in Python. Here's the mapping:
		 *
		 * C code                 Python (SWIG)
		 * =====================  =====================
		 * ctrl->s                ctrl->subsystem
		 * ctrl->dhchap_key       ctrl->dhchap_host_key
		 * ctrl->dhchap_ctrl_key  ctrl->dhchap_key
		 */
		struct nvme_subsystem *subsystem; // Maps to "s" in the C code
		char *dhchap_host_key;            // Maps to "dhchap_key" in the C code
		char *dhchap_key;                 // Maps to "dhchap_ctrl_key" in the C code
	}
};

struct nvme_ns {
	%immutable nsid;
	%immutable eui64;
	%immutable nguid;
	%immutable uuid;
	unsigned int nsid;
	uint8_t eui64[8];
	uint8_t nguid[16];
	uint8_t uuid[16];
};

%extend nvme_root {
	nvme_root(const char *config_file = NULL) {
		return nvme_scan(config_file);
	}
	~nvme_root() {
		nvme_free_tree($self);
	}
	void log_level(const char *level) {
		int log_level = DEFAULT_LOGLEVEL;
		if (!strcmp(level, "debug")) log_level = LOG_DEBUG;
		else if (!strcmp(level, "info")) log_level = LOG_INFO;
		else if (!strcmp(level, "notice")) log_level = LOG_NOTICE;
		else if (!strcmp(level, "warning")) log_level = LOG_WARNING;
		else if (!strcmp(level, "err")) log_level = LOG_ERR;
		else if (!strcmp(level, "crit")) log_level = LOG_CRIT;
		else if (!strcmp(level, "alert")) log_level = LOG_ALERT;
		else if (!strcmp(level, "emerg")) log_level = LOG_EMERG;
		nvme_init_logging($self, log_level, false, false);
	}
	struct nvme_host *hosts() {
		return nvme_first_host($self);
	}
	void refresh_topology() {
		nvme_refresh_topology($self);
	}
	void update_config() {
		nvme_update_config($self);
	}
	void dump_config() {
		nvme_dump_config($self);
	}
}

%extend host_iter {
	struct host_iter *__iter__() {
		return $self;
	}
	struct nvme_host *__next__() {
		struct nvme_host *this = $self->pos;

		if (!this) {
			host_iter_err = 1;
			return NULL;
		}
		$self->pos = nvme_next_host($self->root, this);
		return this;
	}
}

%define SET_SYMNAME_DOCSTRING
"@brief Set or Clear Host's Symbolic Name

@param hostsymname: A symbolic name, or None to clear the symbolic name.
@type hostsymname: str|None

@return: None"
%enddef

%pythonappend nvme_host::nvme_host(struct nvme_root *r,
				   const char *hostnqn,
				   const char *hostid,
				   const char *hostkey,
				   const char *hostsymname) {
	self.__parent = r  # Keep a reference to parent to ensure garbage collection happens in the right order}
%extend nvme_host {
	nvme_host(struct nvme_root *r,
		  const char *hostnqn = NULL,
		  const char *hostid = NULL,
		  const char *hostkey = NULL,
		  const char *hostsymname = NULL) {
		nvme_host_t h = hostnqn ? nvme_lookup_host(r, hostnqn, hostid) : nvme_default_host(r);
		if (hostsymname)
			nvme_host_set_hostsymname(h, hostsymname);
		if (hostkey)
			nvme_host_set_dhchap_key(h, hostkey);
		return h;
	}
	~nvme_host() {
		nvme_free_host($self);
	}
	%feature("autodoc", SET_SYMNAME_DOCSTRING) set_symname;
	void set_symname(const char *hostsymname) {
		nvme_host_set_hostsymname($self, hostsymname);
	}

	PyObject* __str__() {
		return PyUnicode_FromFormat("nvme.host(%s,%s)", STR_OR_NONE($self->hostnqn), STR_OR_NONE($self->hostid));
	}
	struct host_iter __iter__() {
		struct host_iter ret = {
			.root = nvme_host_get_root($self),
			.pos = $self
		};
		return ret;
	}
	struct nvme_subsystem* subsystems() {
		return nvme_first_subsystem($self);
	}
}

%{
	const char *nvme_host_dhchap_key_get(struct nvme_host *h) {
		return nvme_host_get_dhchap_key(h);
	}
	void nvme_host_dhchap_key_set(struct nvme_host *h, char *key) {
		nvme_host_set_dhchap_key(h, key);
	}
%};

%extend subsystem_iter {
	struct subsystem_iter *__iter__() {
		return $self;
	}
	struct nvme_subsystem *__next__() {
		struct nvme_subsystem *this = $self->pos;

		if (!this) {
			subsys_iter_err = 1;
			return NULL;
		}
		$self->pos = nvme_next_subsystem($self->host, this);
		return this;
	}
}

%extend ns_iter {
	struct ns_iter *__iter__() {
		return $self;
	}
	struct nvme_ns *__next__() {
		struct nvme_ns *this = $self->pos;

		if (!this) {
			ns_iter_err = 1;
			return NULL;
		}
		if ($self->ctrl)
			$self->pos = nvme_ctrl_next_ns($self->ctrl, this);
		else
			$self->pos = nvme_subsystem_next_ns($self->subsystem, this);
		return this;
	}
}

%pythonappend nvme_subsystem::nvme_subsystem(struct nvme_host *host,
					     const char *subsysnqn,
					     const char *name) {
    self.__parent = host  # Keep a reference to parent to ensure garbage collection happens in the right order}
%extend nvme_subsystem {
	nvme_subsystem(struct nvme_host *host,
		       const char *subsysnqn,
		       const char *name = NULL) {
		return nvme_lookup_subsystem(host, name, subsysnqn);
	}
	~nvme_subsystem() {
		nvme_free_subsystem($self);
	}
	PyObject *__str__() {
		return PyUnicode_FromFormat("nvme.subsystem(%s,%s)", STR_OR_NONE($self->name), STR_OR_NONE($self->subsysnqn));
	}
	struct subsystem_iter __iter__() {
		struct subsystem_iter ret = {
			.host = nvme_subsystem_get_host($self),
			.pos = $self
		};
		return ret;
	}
	struct nvme_ctrl *controllers() {
		return nvme_subsystem_first_ctrl($self);
	}
	struct nvme_ns *namespaces() {
		return nvme_subsystem_first_ns($self);
	}
	%immutable name;
	const char *name;
	%immutable host;
	struct nvme_host *host;
}

%{
	const char *nvme_subsystem_name_get(struct nvme_subsystem *s) {
		return nvme_subsystem_get_name(s);
	}
	struct nvme_host *nvme_subsystem_host_get(struct nvme_subsystem *s) {
		return nvme_subsystem_get_host(s);
	}
%};

%extend ctrl_iter {
	struct ctrl_iter *__iter__() {
		return $self;
	}
	struct nvme_ctrl *__next__() {
		struct nvme_ctrl *this = $self->pos;

		if (!this) {
			ctrl_iter_err = 1;
			return NULL;
		}
		$self->pos = nvme_subsystem_next_ctrl($self->subsystem, this);
		return this;
	}
}

%pythonappend nvme_ctrl::connect(struct nvme_host *h,
				 struct nvme_fabrics_config *cfg) {
    self.__host = h  # Keep a reference to parent to ensure ctrl obj gets GCed before host}
%pythonappend nvme_ctrl::init(struct nvme_host *h, int instance) {
    self.__host = h  # Keep a reference to parent to ensure ctrl obj gets GCed before host}
%extend nvme_ctrl {
	nvme_ctrl(struct nvme_root *r,
		  const char *subsysnqn,
		  const char *transport,
		  const char *traddr = NULL,
		  const char *host_traddr = NULL,
		  const char *host_iface = NULL,
		  const char *trsvcid = NULL) {
		return nvme_create_ctrl(r, subsysnqn, transport, traddr,
					host_traddr, host_iface, trsvcid);
	}
	~nvme_ctrl() {
		nvme_free_ctrl($self);
	}

	%pythoncode %{
	def discovery_ctrl_set(self, discovery: bool):
	    r"""DEPRECATED METHOD: Use property setter instead (e.g. ctrl.discovery_ctrl = True)"""
	    import warnings
	    warnings.warn("Use property setter instead (e.g. ctrl_obj.discovery_ctrl = True)", DeprecationWarning, stacklevel=2)
	    return _nvme.ctrl_discovery_ctrl_set(self, discovery)
	%}

	bool init(struct nvme_host *h, int instance) {
		return nvme_init_ctrl(h, $self, instance) == 0;
	}

	void connect(struct nvme_host *h,
		     struct nvme_fabrics_config *cfg = NULL) {
		int ret;
		const char *dev;

		dev = nvme_ctrl_get_name($self);
		if (dev && !cfg->duplicate_connect) {
			connect_err = 1;
			return;
		}

		Py_BEGIN_ALLOW_THREADS  /* Release Python GIL */
		    ret = nvmf_add_ctrl(h, $self, cfg);
		Py_END_ALLOW_THREADS    /* Reacquire Python GIL */

		if (ret < 0) {
			connect_err = 2;
			return;
		}
	}
	bool connected() {
		return nvme_ctrl_get_name($self) != NULL;
	}
	%pythoncode %{
	def persistent_set(self, persistent: bool):
	    r"""DEPRECATED METHOD: Use property setter instead (e.g. ctrl.persistent = True)"""
	    import warnings
	    warnings.warn("Use property setter instead (e.g. ctrl_obj.persistent = True)", DeprecationWarning, stacklevel=2)
	    return _nvme.ctrl_persistent_set(self, persistent)
	%}
	void rescan() {
		nvme_rescan_ctrl($self);
	}
	void disconnect() {
		Py_BEGIN_ALLOW_THREADS  /* Release Python GIL */
		    nvme_disconnect_ctrl($self);
		Py_END_ALLOW_THREADS    /* Reacquire Python GIL */
	}

	%feature("autodoc", "@return: True if controller supports explicit registration. False otherwise.") is_registration_supported;
	bool is_registration_supported() {
		return nvmf_is_registration_supported($self);
	}

	%feature("autodoc", "@return None on success or Error string on error.") registration_ctlr;
	PyObject *registration_ctlr(enum nvmf_dim_tas tas) {
		__u32 result;
		int   status;

		Py_BEGIN_ALLOW_THREADS  /* Release Python GIL */
		    status = nvmf_register_ctrl($self, NVMF_DIM_TAS_REGISTER, &result);
		Py_END_ALLOW_THREADS    /* Reacquire Python GIL */

			if (status != NVME_SC_SUCCESS) {
				/* On error, return an error message */
				return (status < 0) ?
				       PyUnicode_FromFormat("Status:0x%04x - %s", status, nvme_status_to_string(status, false)) :
				       PyUnicode_FromFormat("Result:0x%04x, Status:0x%04x - %s", result, status, nvme_status_to_string(status, false));
			}

		/* On success, return None */
		Py_RETURN_NONE;
	}

	%newobject discover;
	struct nvmf_discovery_log *discover(int lsp = 0, int max_retries = 6) {
		const char *dev;
		struct nvmf_discovery_log *logp;
		struct nvme_get_discovery_args args = {
			.c = $self,
			.args_size = sizeof(args),
			.max_retries = max_retries,
			.result = NULL,
			.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
			.lsp = lsp,
		};

		dev = nvme_ctrl_get_name($self);
		if (dev) {
			discover_err = 1;
			return NULL;
		}
		Py_BEGIN_ALLOW_THREADS  /* Release Python GIL */
		    logp = nvmf_get_discovery_wargs(&args);
		Py_END_ALLOW_THREADS    /* Reacquire Python GIL */

		if (logp == NULL) discover_err = 2;
		return logp;
	}

	%feature("autodoc", "@return: List of supported log pages") supported_log_pages;
	PyObject *supported_log_pages(bool rae = true) {
		struct nvme_supported_log_pages log;
		PyObject *obj = NULL;
		int ret = 0;

		Py_BEGIN_ALLOW_THREADS  /* Release Python GIL */
		    ret = nvme_get_log_supported_log_pages(nvme_ctrl_get_fd($self), rae, &log);
		Py_END_ALLOW_THREADS    /* Reacquire Python GIL */

		if (ret < 0) {
			Py_RETURN_NONE;
		}

		obj = PyList_New(NVME_LOG_SUPPORTED_LOG_PAGES_MAX);
		if (!obj) Py_RETURN_NONE;

		for (int i = 0; i < NVME_LOG_SUPPORTED_LOG_PAGES_MAX; i++)
			PyList_SetItem(obj, i, PyLong_FromLong(le32_to_cpu(log.lid_support[i]))); /* steals ref. to object - no need to decref */

		return obj;
	}

	PyObject* __str__() {
		return $self->address ?
		       PyUnicode_FromFormat("nvme_ctrl(transport=%s,%s)", STR_OR_NONE($self->transport), STR_OR_NONE($self->address)) :
		       PyUnicode_FromFormat("nvme_ctrl(transport=%s)", STR_OR_NONE($self->transport));
	}
	struct ctrl_iter __iter__() {
		struct ctrl_iter ret = {
			.subsystem = nvme_ctrl_get_subsystem($self),
			.pos = $self
		};
		return ret;
	}
	struct nvme_ns* namespaces() {
		return nvme_ctrl_first_ns($self);
	}
}

%{
	/**********************************************************************
	 * SWIG automatically generates getter and setter methods using
	 * the syntax: [class]_[member]_[get|set]. These need to be mapped
	 * to the matching methods in libnvme (i.e. those that are defined
	 * publicly in libnvme.map). Typically, we get the following mapping:
	 *
	 * SWIG                       libnvme.map
	 * ======================     =======================
	 * nvme_ctrl_[member]_get  -> nvme_ctrl_get_[member]
	 * nvme_ctrl_[member]_set  -> nvme_ctrl_set_[member]
	 *
	 */

	const char *nvme_ctrl_name_get(struct nvme_ctrl *c) {
		return nvme_ctrl_get_name(c);
	}
	struct nvme_subsystem *nvme_ctrl_subsystem_get(struct nvme_ctrl *c) {
		return nvme_ctrl_get_subsystem(c);
	}
	const char *nvme_ctrl_state_get(struct nvme_ctrl *c) {
		return nvme_ctrl_get_state(c);
	}
	const char *nvme_ctrl_dhchap_key_get(struct nvme_ctrl *c) {
		return nvme_ctrl_get_dhchap_key(c);
	}
	void nvme_ctrl_dhchap_key_set(struct nvme_ctrl *c, const char *key) {
		nvme_ctrl_set_dhchap_key(c, key);
	}
	const char *nvme_ctrl_dhchap_host_key_get(struct nvme_ctrl *c) {
		return nvme_ctrl_get_dhchap_host_key(c);
	}
	void nvme_ctrl_dhchap_host_key_set(struct nvme_ctrl *c, const char *key) {
		nvme_ctrl_set_dhchap_host_key(c, key);
	}

	const char *nvme_ctrl_cntlid_get(nvme_ctrl_t c) {
		return nvme_ctrl_get_cntlid(c);
	}

	bool nvme_ctrl_persistent_get(struct nvme_ctrl *c) {
		return nvme_ctrl_is_persistent(c);
	}
	void nvme_ctrl_persistent_set(struct nvme_ctrl *c, bool persistent) {
		nvme_ctrl_set_persistent(c, persistent);
	}

	const char *nvme_ctrl_phy_slot_get(nvme_ctrl_t c) {
		return nvme_ctrl_get_phy_slot(c);
	}

	const char *nvme_ctrl_trsvcid_get(nvme_ctrl_t c) {
		return nvme_ctrl_get_trsvcid(c);
	}

	const char *nvme_ctrl_traddr_get(nvme_ctrl_t c) {
		return nvme_ctrl_get_traddr(c);
	}

	const char *nvme_ctrl_subsysnqn_get(nvme_ctrl_t c) {
		return nvme_ctrl_get_subsysnqn(c);
	}

	const char *nvme_ctrl_transport_get(nvme_ctrl_t c) {
		return nvme_ctrl_get_transport(c);
	}

	const char *nvme_ctrl_sqsize_get(nvme_ctrl_t c) {
		return nvme_ctrl_get_sqsize(c);
	}

	const char *nvme_ctrl_serial_get(nvme_ctrl_t c) {
		return nvme_ctrl_get_serial(c);
	}

	const char *nvme_ctrl_queue_count_get(nvme_ctrl_t c) {
		return nvme_ctrl_get_queue_count(c);
	}

	const char *nvme_ctrl_numa_node_get(nvme_ctrl_t c) {
		return nvme_ctrl_get_numa_node(c);
	}

	const char *nvme_ctrl_model_get(nvme_ctrl_t c) {
		return nvme_ctrl_get_model(c);
	}

	const char *nvme_ctrl_firmware_get(nvme_ctrl_t c) {
		return nvme_ctrl_get_firmware(c);
	}

	const char *nvme_ctrl_address_get(nvme_ctrl_t c) {
		return nvme_ctrl_get_address(c);
	}

	const char *nvme_ctrl_sysfs_dir_get(nvme_ctrl_t c) {
		return nvme_ctrl_get_sysfs_dir(c);
	}

	bool nvme_ctrl_discovery_ctrl_get(struct nvme_ctrl *c) {
		return nvme_ctrl_is_discovery_ctrl(c);
	}
	void nvme_ctrl_discovery_ctrl_set(struct nvme_ctrl *c, bool discovery) {
		nvme_ctrl_set_discovery_ctrl(c, discovery);
	}

	bool nvme_ctrl_unique_discovery_ctrl_get(nvme_ctrl_t c) {
		return nvme_ctrl_is_unique_discovery_ctrl(c);
	}
	void nvme_ctrl_unique_discovery_ctrl_set(nvme_ctrl_t c, bool unique) {
		nvme_ctrl_set_unique_discovery_ctrl(c, unique);
	}

	const char *nvme_ctrl_keyring_get(nvme_ctrl_t c) {
		return nvme_ctrl_get_keyring(c);
	}
	void nvme_ctrl_keyring_set(nvme_ctrl_t c, const char *keyring) {
		nvme_ctrl_set_keyring(c, keyring);
	}

	const char *nvme_ctrl_tls_key_identity_get(nvme_ctrl_t c) {
		return nvme_ctrl_get_tls_key_identity(c);
	}
	void nvme_ctrl_tls_key_identity_set(nvme_ctrl_t c, const char *identity) {
		nvme_ctrl_set_tls_key_identity(c, identity);
	}

	const char *nvme_ctrl_tls_key_get(nvme_ctrl_t c) {
		return nvme_ctrl_get_tls_key(c);
	}
	void nvme_ctrl_tls_key_set(nvme_ctrl_t c, const char *key) {
		nvme_ctrl_set_tls_key(c, key);
	}
%}

%pythonappend nvme_ns::nvme_ns(struct nvme_subsystem *s,
			       unsigned int nsid) {
    self.__parent = s  # Keep a reference to parent to ensure garbage collection happens in the right order}
%extend nvme_ns {
	nvme_ns(struct nvme_subsystem *s,
		unsigned int nsid) {
		return nvme_subsystem_lookup_namespace(s, nsid);
	}
	~nvme_ns() {
		nvme_free_ns($self);
	}
	PyObject *__str__() {
		return PyUnicode_FromFormat("nvme.ns(%u)", $self->nsid);
	}
	struct ns_iter __iter__() {
		struct ns_iter ret = { .ctrl = nvme_ns_get_ctrl($self),
			.subsystem = nvme_ns_get_subsystem($self),
			.pos = $self };
		return ret;
	}
	%immutable name;
	const char *name;
}

%{
	const char *nvme_ns_name_get(struct nvme_ns *n) {
		return nvme_ns_get_name(n);
	}
%};

/******
  NBFT
 ******/
%{
	static PyObject *ssns_to_dict(struct nbft_info_subsystem_ns *ss)
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
			case NBFT_INFO_NID_TYPE_EUI64:
				PyDict_SetItemStringDecRef(output, "nid_type", PyUnicode_FromString("eui64"));
				nid = PyUnicode_FromFormat("%02x%02x%02x%02x%02x%02x%02x%02x",
							   ss->nid[0], ss->nid[1], ss->nid[2], ss->nid[3],
							   ss->nid[4], ss->nid[5], ss->nid[6], ss->nid[7]);
				break;

			case NBFT_INFO_NID_TYPE_NGUID:
				PyDict_SetItemStringDecRef(output, "nid_type", PyUnicode_FromString("nguid"));
				nid = PyUnicode_FromFormat("%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
							   ss->nid[0], ss->nid[1], ss->nid[2], ss->nid[3],
							   ss->nid[4], ss->nid[5], ss->nid[6], ss->nid[7],
							   ss->nid[8], ss->nid[9], ss->nid[10], ss->nid[11],
							   ss->nid[12], ss->nid[13], ss->nid[14], ss->nid[15]);
				break;

			case NBFT_INFO_NID_TYPE_NS_UUID:
			{
				char uuid_str[NVME_UUID_LEN_STRING];
				PyDict_SetItemStringDecRef(output, "nid_type", PyUnicode_FromString("uuid"));
				nvme_uuid_to_string(ss->nid, uuid_str);
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

	static PyObject *hfi_to_dict(struct nbft_info_hfi *hfi)
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

	static PyObject *discovery_to_dict(struct nbft_info_discovery *disc)
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

	static PyObject *nbft_to_pydict(struct nbft_info *nbft)
	{
		PyObject *val;
		PyObject *output = PyDict_New();

		{
			PyObject *host = PyDict_New();

			if (nbft->host.nqn)
				PyDict_SetItemStringDecRef(host, "nqn", PyUnicode_FromString(nbft->host.nqn));
			if (nbft->host.id) {
				char uuid_str[NVME_UUID_LEN_STRING];
				nvme_uuid_to_string((unsigned char *)nbft->host.id, uuid_str);
				PyDict_SetItemStringDecRef(host, "id", PyUnicode_FromString(uuid_str));
			}

			PyDict_SetItemStringDecRef(host, "host_id_configured", PyBool_FromLong(nbft->host.host_id_configured));
			PyDict_SetItemStringDecRef(host, "host_nqn_configured", PyBool_FromLong(nbft->host.host_nqn_configured));

			val = PyUnicode_FromString(nbft->host.primary == NBFT_INFO_PRIMARY_ADMIN_HOST_FLAG_NOT_INDICATED ? "not indicated" :
						   nbft->host.primary == NBFT_INFO_PRIMARY_ADMIN_HOST_FLAG_UNSELECTED ? "unselected" :
						   nbft->host.primary == NBFT_INFO_PRIMARY_ADMIN_HOST_FLAG_SELECTED ? "selected" : "reserved");
			PyDict_SetItemStringDecRef(host, "primary_admin_host_flag", val);

			PyDict_SetItemStringDecRef(output, "host", host);
		}

		{
			size_t ss_num = 0;
			struct nbft_info_subsystem_ns **ss;
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
			struct nbft_info_hfi **hfi;
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
			struct nbft_info_discovery **disc;
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

	PyObject *nbft_get(const char * filename)
	{
		struct nbft_info *nbft;
		PyObject *output;
		int ret;

		ret = nvme_nbft_read(&nbft, filename);
		if (ret) {
			Py_RETURN_NONE;
		}

		output = nbft_to_pydict(nbft);
		nvme_nbft_free(nbft);
		return output;
	}
%};

%feature("autodoc", "@return an NBFT table as a dict on success, None otherwise.\n"
		    "@param filename: file to read") nbft_get;
PyObject *nbft_get(const char * filename);

// We want to swig all the #define and enum from types.h, but none of the structs.
#pragma SWIG nowarn=503             // Supress warnings about unnamed struct
#define __attribute__(x)
%rename($ignore, %$isclass) "";     // ignore all classes/structs
%rename($ignore, %$isfunction) "";  // ignore all functions
%rename($ignore, %$isunion) "";     // ignore all unions
%rename($ignore, %$isvariable) "";  // ignore all variables

%include "../src/nvme/types.h"
