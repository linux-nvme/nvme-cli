// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2021 SUSE Software Solutions
 *
 * Authors: Hannes Reinecke <hare@suse.de>
 */

%module libnvme

%include "exception.i"

%allowexception;

%{
#include <assert.h>
#include <ccan/list/list.h>
#include "tree.h"
#include "fabrics.h"
#include "private.h"

static int host_iter_err = 0;
static int subsys_iter_err = 0;
static int ctrl_iter_err = 0;
static int ns_iter_err = 0;
static int connect_err = 0;
static int discover_err = 0;
%}

%inline %{
  struct nvme_host_iter {
    struct nvme_root *root;
    struct nvme_host *pos;
  };

  struct nvme_subsystem_iter {
    struct nvme_host *host;
    struct nvme_subsystem *pos;
  };

  struct nvme_ctrl_iter {
    struct nvme_subsystem *subsystem;
    struct nvme_ctrl *pos;
  };

  struct nvme_ns_iter {
    struct nvme_subsystem *subsystem;
    struct nvme_ctrl *ctrl;
    struct nvme_ns *pos;
  };
%}

%exception nvme_host_iter::__next__ {
  assert(!host_iter_err);
  $action
  if (host_iter_err) {
    host_iter_err = 0;
    PyErr_SetString(PyExc_StopIteration, "End of list");
    return NULL;
  }
}

%exception nvme_subsystem_iter::__next__ {
  assert(!subsys_iter_err);
  $action
  if (subsys_iter_err) {
    subsys_iter_err = 0;
    PyErr_SetString(PyExc_StopIteration, "End of list");
    return NULL;
  }
}

%exception nvme_ctrl_iter::__next__ {
  assert(!ctrl_iter_err);
  $action
  if (ctrl_iter_err) {
    ctrl_iter_err = 0;
    PyErr_SetString(PyExc_StopIteration, "End of list");
    return NULL;
  }
}

%exception nvme_ns_iter::__next__ {
  assert(!ns_iter_err);
  $action
  if (ns_iter_err) {
    ns_iter_err = 0;
    PyErr_SetString(PyExc_StopIteration, "End of list");
    return NULL;
  }
}

%exception nvme_ctrl::connect {
  $action
  if (connect_err == 1) {
    connect_err = 0;
    SWIG_exception(SWIG_AttributeError, "Existing controller connection");
  } else if (connect_err) {
    connect_err = 0;
    SWIG_exception(SWIG_RuntimeError, "Connect failed");
  }
}

%exception nvme_ctrl::discover {
  $action
  if (discover_err) {
    discover_err = 0;
    SWIG_exception(SWIG_RuntimeError,"Discover failed");
  }
}

#include "tree.h"
#include "fabrics.h"

%typemap(in) struct nvme_fabrics_config * ($*1_type temp) {
  Py_ssize_t pos = 0;
  PyObject *key, *value;
  char *keystr;
  memset(&temp, 0, sizeof(struct nvme_fabrics_config));
  temp.tos = -1;
  temp.ctrl_loss_tmo = NVMF_DEF_CTRL_LOSS_TMO;
  while (PyDict_Next($input, &pos, &key, &value)) {
    keystr = PyString_AsString(key);
    if (!keystr)
      continue;
    if (!strcmp(keystr, "nr_io_queues"))
      temp.nr_io_queues = PyLong_AsLong(value);
    if (!strcmp(keystr, "reconnect_delay"))
      temp.reconnect_delay = PyLong_AsLong(value);
    if (!strcmp(keystr, "ctrl_loss_tmo"))
      temp.ctrl_loss_tmo = PyLong_AsLong(value);
    if (!strcmp(keystr, "keep_alive_tmo"))
      temp.keep_alive_tmo = PyLong_AsLong(value);
    if (!strcmp(keystr, "nr_write_queues"))
      temp.nr_write_queues = PyLong_AsLong(value);
    if (!strcmp(keystr, "nr_poll_queues"))
      temp.nr_poll_queues = PyLong_AsLong(value);
    if (!strcmp(keystr, "tos"))
      temp.tos = PyLong_AsLong(value);
    if (!strcmp(keystr, "duplicate_connect"))
      temp.duplicate_connect = PyLong_AsLong(value);
    if (!strcmp(keystr, "disable_sqflow"))
      temp.disable_sqflow = PyLong_AsLong(value);
    if (!strcmp(keystr, "hdr_digest"))
      temp.hdr_digest = PyLong_AsLong(value);
    if (!strcmp(keystr, "data_digest"))
      temp.data_digest = PyLong_AsLong(value);
  }
  $1 = &temp;
 };

%typemap(out) uint8_t [8] {
  $result = PyBytes_FromStringAndSize((char *)$1, 8);
};

%typemap(out) uint8_t [16] {
  $result = PyBytes_FromStringAndSize((char *)$1, 16);
};

%typemap(out) struct nvmf_discovery_log * {
  struct nvmf_discovery_log *log = $1;
  int numrec = log? log->numrec : 0, i;
  PyObject *obj = PyList_New(numrec);
  if (!obj)
    return NULL;
  for (i = 0; i < numrec; i++) {
    struct nvmf_disc_log_entry *e = &log->entries[i];
    PyObject *entry = PyDict_New(), *val;

    val = PyLong_FromLong(e->trtype);
    PyDict_SetItemString(entry, "trtype", val);
    val = PyLong_FromLong(e->adrfam);
    PyDict_SetItemString(entry, "adrfam", val);
    val = PyUnicode_FromString(e->traddr);
    PyDict_SetItemString(entry, "traddr", val);
    val = PyUnicode_FromString(e->trsvcid);
    PyDict_SetItemString(entry, "trsvcid", val);
    val = PyUnicode_FromString(e->subnqn);
    PyDict_SetItemString(entry, "subnqn", val);
    val = PyLong_FromLong(e->subtype);
    PyDict_SetItemString(entry, "subtype", val);
    val = PyLong_FromLong(e->treq);
    PyDict_SetItemString(entry, "treq", val);
    val = PyLong_FromLong(e->portid);
    PyDict_SetItemString(entry, "portid", val);
    val = PyLong_FromLong(e->cntlid);
    PyDict_SetItemString(entry, "cntlid", val);
    val = PyLong_FromLong(e->asqsz);
    PyDict_SetItemString(entry, "asqsz", val);
    PyList_SetItem(obj, i, entry);
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
  char *hostnqn;
  char *hostid;
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
  %immutable transport;
  %immutable subsysnqn;
  %immutable traddr;
  %immutable host_traddr;
  %immutable trsvcid;
  %immutable address;
  %immutable firmware;
  %immutable model;
  %immutable numa_node;
  %immutable queue_count;
  %immutable serial;
  %immutable sqsize;
  char *transport;
  char *subsysnqn;
  char *traddr;
  char *host_traddr;
  char *trsvcid;
  char *address;
  char *firmware;
  char *model;
  char *numa_node;
  char *queue_count;
  char *serial;
  char *sqsize;
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
  struct nvme_host *hosts() {
    return nvme_first_host($self);
  }
  void refresh_topology() {
    nvme_refresh_topology($self);
  }
  void update_config() {
    nvme_update_config($self);
  }
}

%extend nvme_host_iter {
  struct nvme_host_iter *__iter__() {
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
	    const char *hostid = NULL) {
    if (!hostnqn)
      return nvme_default_host(r);
    return nvme_lookup_host(r, hostnqn, hostid);
  }
  ~nvme_host() {
    nvme_free_host($self);
  }
  char *__str__() {
    static char tmp[2048];

    sprintf(tmp, "nvme_host(%s,%s)", $self->hostnqn, $self->hostid);
    return tmp;
  }
  struct nvme_host_iter __iter__() {
    struct nvme_host_iter ret = { .root = nvme_host_get_root($self),
				     .pos = $self };
    return ret;
  }
  struct nvme_subsystem *subsystems() {
    return nvme_first_subsystem($self);
  }
}

%extend nvme_subsystem_iter {
  struct nvme_subsystem_iter *__iter__() {
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

%extend nvme_ns_iter {
  struct nvme_ns_iter *__iter__() {
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
  struct nvme_subsystem_iter __iter__() {
    struct nvme_subsystem_iter ret = { .host = nvme_subsystem_get_host($self),
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

%extend nvme_ctrl_iter {
  struct nvme_ctrl_iter *__iter__() {
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
  nvme_ctrl(const char *subsysnqn, const char *transport,
	    const char *traddr = NULL, const char *host_traddr = NULL,
	    const char *host_iface = NULL, const char *trsvcid = NULL) {
    return nvme_create_ctrl(subsysnqn, transport, traddr,
			    host_traddr, host_iface, trsvcid);
  }
  ~nvme_ctrl() {
    nvme_free_ctrl($self);
  }
  void connect(struct nvme_host *h, struct nvme_fabrics_config *cfg = NULL) {
    int ret;
    const char *dev;

    dev = nvme_ctrl_get_name($self);
    if (dev && !cfg->duplicate_connect) {
      connect_err = 1;
      return;
    }
    ret = nvmf_add_ctrl(h, $self, cfg, cfg->disable_sqflow);
    if (ret < 0) {
      connect_err = 2;
      return;
    }
  }
  bool connected() {
    return nvme_ctrl_get_name($self) != NULL;
  }
  void rescan() {
    nvme_rescan_ctrl($self);
  }
  void disconnect() {
    nvme_disconnect_ctrl($self);
  }
  struct nvmf_discovery_log *discover(int max_retries = 6) {
    struct nvmf_discovery_log *logp = NULL;
    int ret = 0;
    ret = nvmf_get_discovery_log($self, &logp, max_retries);
    if (ret < 0) {
      discover_err = 1;
      return NULL;
    }
    return logp;
  }
  char *__str__() {
    static char tmp[1024];

    if ($self->address)
      sprintf(tmp, "nvme_ctrl(transport=%s,%s)", $self->transport,
	      $self->address);
    else
      sprintf(tmp, "nvme_ctrl(transport=%s)", $self->transport);
    return tmp;
  }
  struct nvme_ctrl_iter __iter__() {
    struct nvme_ctrl_iter ret = { .subsystem = nvme_ctrl_get_subsystem($self),
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
  struct nvme_ns_iter __iter__() {
    struct nvme_ns_iter ret = { .ctrl = nvme_ns_get_ctrl($self),
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
