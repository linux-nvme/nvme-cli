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

static int host_iter_err = 0;
static int subsys_iter_err = 0;
static int ctrl_iter_err = 0;
static int ns_iter_err = 0;
static int connect_err = 0;
static int discover_err = 0;
%}

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
  if (discover_err) {
    SWIG_exception(SWIG_RuntimeError,"Discover failed");
  }
}

#include "tree.h"
#include "fabrics.h"

%typemap(in) struct nvme_fabrics_config * ($*1_type temp) {
  Py_ssize_t pos = 0;
  PyObject *key, *value;
  memset(&temp, 0, sizeof(temp));
  temp.tos = -1;
  temp.ctrl_loss_tmo = NVMF_DEF_CTRL_LOSS_TMO;
  while (PyDict_Next($input, &pos, &key, &value)) {
    if (!PyUnicode_CompareWithASCIIString(key, "host_traddr"))
      temp.host_traddr = PyBytes_AsString(value);
    if (!PyUnicode_CompareWithASCIIString(key, "host_iface"))
      temp.host_iface = PyBytes_AsString(value);
    if (!PyUnicode_CompareWithASCIIString(key, "nr_io_queues"))
      temp.nr_io_queues = PyLong_AsLong(value);
    if (!PyUnicode_CompareWithASCIIString(key, "reconnect_delay"))
      temp.reconnect_delay = PyLong_AsLong(value);
    if (!PyUnicode_CompareWithASCIIString(key, "ctrl_loss_tmo"))
      temp.ctrl_loss_tmo = PyLong_AsLong(value);
    if (!PyUnicode_CompareWithASCIIString(key, "keep_alive_tmo"))
      temp.keep_alive_tmo = PyLong_AsLong(value);
    if (!PyUnicode_CompareWithASCIIString(key, "nr_write_queues"))
      temp.nr_write_queues = PyLong_AsLong(value);
    if (!PyUnicode_CompareWithASCIIString(key, "nr_poll_queues"))
      temp.nr_poll_queues = PyLong_AsLong(value);
    if (!PyUnicode_CompareWithASCIIString(key, "tos"))
      temp.tos = PyLong_AsLong(value);
    if (!PyUnicode_CompareWithASCIIString(key, "duplicate_connect"))
      temp.duplicate_connect = PyObject_IsTrue(value) ? true : false;
    if (!PyUnicode_CompareWithASCIIString(key, "disable_sqflow"))
      temp.disable_sqflow = PyObject_IsTrue(value) ? true : false;
    if (!PyUnicode_CompareWithASCIIString(key, "hdr_digest"))
      temp.hdr_digest = PyObject_IsTrue(value) ? true : false;
    if (!PyUnicode_CompareWithASCIIString(key, "data_digest"))
      temp.data_digest = PyObject_IsTrue(value) ? true : false;
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

%{
static void PyDict_SetItemStringDecRef(PyObject *p, const char *key, PyObject *val) {
    PyDict_SetItemString(p, key, val); /* Does NOT steal reference to val .. */
    Py_XDECREF(val);                   /* .. therefore decrement ref. count. */
}
%}

%typemap(out) struct nvmf_discovery_log * {
  struct nvmf_discovery_log *log = $1;
  int numrec = log? log->numrec : 0, i;
  PyObject *obj = PyList_New(numrec);
  if (!obj)
    return NULL;
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
    val = PyLong_FromLong(e->portid);
    PyDict_SetItemStringDecRef(entry, "portid", val);
    val = PyLong_FromLong(e->cntlid);
    PyDict_SetItemStringDecRef(entry, "cntlid", val);
    val = PyLong_FromLong(e->asqsz);
    PyDict_SetItemStringDecRef(entry, "asqsz", val);
    val = PyLong_FromLong(e->eflags);
    PyDict_SetItemStringDecRef(entry, "eflags", val);
    PyList_SetItem(obj, i, entry); /* steals ref. to entry */
  }
  $result = obj;
 };
struct nvme_root {
  %immutable config_file;
  char *config_file;
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
  char *subsysnqn;
  char *model;
  char *serial;
  char *firmware;
};

struct nvme_ctrl {
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
  %immutable dhchap_host_key;
  %immutable dhchap_key;
  %immutable cntrltype;
  %immutable dctype;
  %immutable discovery_ctrl;
  %immutable discovered;
  %immutable persistent;
  char *sysfs_dir;
  char *address;
  char *firmware;
  char *model;
  char *numa_node;
  char *queue_count;
  char *serial;
  char *sqsize;
  char *transport;
  char *subsysnqn;
  char *traddr;
  char *trsvcid;
  %extend {
    char *dhchap_host_key:
    char *dhchap_key;
  }
  char *cntrltype;
  char *dctype;
  bool discovery_ctrl;
  bool discovered;
  bool persistent;
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
    if (!strcmp(level,"debug"))
      log_level = LOG_DEBUG;
    else if (!strcmp(level, "info"))
      log_level = LOG_INFO;
    else if (!strcmp(level, "notice"))
      log_level = LOG_NOTICE;
    else if (!strcmp(level, "warning"))
      log_level = LOG_WARNING;
    else if (!strcmp(level, "err"))
      log_level = LOG_ERR;
    else if (!strcmp(level, "crit"))
      log_level = LOG_CRIT;
    else if (!strcmp(level, "alert"))
      log_level = LOG_ALERT;
    else if (!strcmp(level, "emerg"))
      log_level = LOG_EMERG;
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

%extend nvme_host {
  nvme_host(struct nvme_root *r, const char *hostnqn = NULL,
	    const char *hostid = NULL, const char *hostsymname = NULL) {

    nvme_host_t h = hostnqn ? nvme_lookup_host(r, hostnqn, hostid) : nvme_default_host(r);
    if (hostsymname)
        nvme_host_set_hostsymname(h, hostsymname);
    return h;
  }
  ~nvme_host() {
    nvme_free_host($self);
  }
%define SET_SYMNAME_DOCSTRING
"@brief Set or Clear Host's Symbolic Name

@param hostsymname: A symbolic name, or None to clear the symbolic name.
@type hostsymname: str|None

@return: None"
%enddef
  %feature("autodoc", SET_SYMNAME_DOCSTRING) set_symname;
  void set_symname(const char *hostsymname) {
    nvme_host_set_hostsymname($self, hostsymname);
  }
  char *__str__() {
    static char tmp[2048];

    sprintf(tmp, "nvme_host(%s,%s)", $self->hostnqn, $self->hostid);
    return tmp;
  }
  struct host_iter __iter__() {
    struct host_iter ret = { .root = nvme_host_get_root($self),
			     .pos = $self };
    return ret;
  }
  struct nvme_subsystem *subsystems() {
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

%extend nvme_subsystem {
  nvme_subsystem(struct nvme_host *host, const char *subsysnqn,
		 const char *name = NULL) {
    return nvme_lookup_subsystem(host, name, subsysnqn);
  }
  ~nvme_subsystem() {
    nvme_free_subsystem($self);
  }
  char *__str__() {
    static char tmp[1024];

    sprintf(tmp, "nvme_subsystem(%s,%s)", $self->name,$self->subsysnqn);
    return tmp;
  }
  struct subsystem_iter __iter__() {
    struct subsystem_iter ret = { .host = nvme_subsystem_get_host($self),
				  .pos = $self };
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

%extend nvme_ctrl {
  nvme_ctrl(struct nvme_root *r, const char *subsysnqn, const char *transport,
	    const char *traddr = NULL, const char *host_traddr = NULL,
	    const char *host_iface = NULL, const char *trsvcid = NULL) {
    return nvme_create_ctrl(r, subsysnqn, transport, traddr,
			    host_traddr, host_iface, trsvcid);
  }
  ~nvme_ctrl() {
    nvme_free_ctrl($self);
  }

  void discovery_ctrl_set(bool discovery) {
      nvme_ctrl_set_discovery_ctrl($self, discovery);
  }

  bool init(struct nvme_host *h, int instance) {
      return nvme_init_ctrl(h, $self, instance) == 0;
  }

  void connect(struct nvme_host *h, struct nvme_fabrics_config *cfg = NULL) {
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
  void persistent_set(bool persistent) {
    nvme_ctrl_set_persistent($self, persistent);
  }
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
      if (status < 0)
        return PyUnicode_FromFormat("Status:0x%04x - %s", status, nvme_status_to_string(status, false));
      else
        return PyUnicode_FromFormat("Result:0x%04x, Status:0x%04x - %s", result, status, nvme_status_to_string(status, false));
    }

    /* On success, return None */
    Py_RETURN_NONE;
  }

  %newobject discover;
  struct nvmf_discovery_log *discover(int lsp = 0, int max_retries = 6) {
    struct nvmf_discovery_log *logp;
    struct nvme_get_discovery_args args = {
      .c = $self,
      .args_size = sizeof(args),
      .max_retries = max_retries,
      .result = NULL,
      .timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
      .lsp = lsp,
    };

    Py_BEGIN_ALLOW_THREADS  /* Release Python GIL */
    logp = nvmf_get_discovery_wargs(&args);
    Py_END_ALLOW_THREADS    /* Reacquire Python GIL */

    if (logp == NULL)
      discover_err = 1;
    return logp;
  }

  %feature("autodoc", "@return: List of supported log pages") supported_log_pages;
  PyObject * supported_log_pages(bool rae=true) {
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
    if (!obj)
      Py_RETURN_NONE;

    for (int i = 0; i < NVME_LOG_SUPPORTED_LOG_PAGES_MAX; i++)
      PyList_SetItem(obj, i, PyLong_FromLong(le32_to_cpu(log.lid_support[i]))); /* steals ref. */

    return obj;
  }

  PyObject *__str__() {
    return $self->address ?
      PyUnicode_FromFormat("nvme_ctrl(transport=%s,%s)", $self->transport, $self->address) :
      PyUnicode_FromFormat("nvme_ctrl(transport=%s)", $self->transport);
  }
  struct ctrl_iter __iter__() {
    struct ctrl_iter ret = { .subsystem = nvme_ctrl_get_subsystem($self),
			     .pos = $self };
    return ret;
  }
  struct nvme_ns *namespaces() {
    return nvme_ctrl_first_ns($self);
  }
  %immutable name;
  const char *name;
  %immutable subsystem;
  struct nvme_subsystem *subsystem;
  %immutable state;
  const char *state;
}

%{
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
  const char *nvme_ctrl_dhchap_host_key_get(struct nvme_ctrl *c) {
    return nvme_ctrl_get_dhchap_host_key(c);
  }
%};

%extend nvme_ns {
  nvme_ns(struct nvme_subsystem *s, unsigned int nsid) {
    return nvme_subsystem_lookup_namespace(s, nsid);
  }
  ~nvme_ns() {
    nvme_free_ns($self);
  }
  char *__str__() {
    static char tmp[1024];

    sprintf(tmp, "nvme_ns(%u)", $self->nsid);
    return tmp;
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


// We want to swig all the #define and enum from types.h, but none of the structs.
#define __attribute__(x)
%rename($ignore, %$isclass) "";     // ignore all classes/structs
%rename($ignore, %$isfunction) "";  // ignore all functions
%rename($ignore, %$isunion) "";     // ignore all unions
%rename($ignore, %$isvariable ) ""; // ignore all variables

%include "../src/nvme/types.h"
