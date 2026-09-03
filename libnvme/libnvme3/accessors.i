// SPDX-License-Identifier: LGPL-2.1-or-later

/*
 * This file is part of libnvme.
 *
 * Copyright (c) 2025, Dell Technologies Inc. or its subsidiaries.
 * Authors: Martin Belanger <Martin.Belanger@dell.com>
 *
 *   ____                           _           _    ____          _
 *  / ___| ___ _ __   ___ _ __ __ _| |_ ___  __| |  / ___|___   __| | ___
 * | |  _ / _ \ '_ \ / _ \ '__/ _` | __/ _ \/ _` | | |   / _ \ / _` |/ _ \
 * | |_| |  __/ | | |  __/ | | (_| | ||  __/ (_| | | |__| (_) | (_| |  __/
 *  \____|\___|_| |_|\___|_|  \__,_|\__\___|\__,_|  \____\___/ \__,_|\___|
 *
 * Auto-generated struct member accessors (setter/getter)
 *
 * To update run: meson compile -C [BUILD-DIR] update-accessors
 * Or:            make update-accessors
 */
%pythoncode %{
def _nvme_guarded_setattr(self, name, value):
    """Reject writes to unknown attributes.

    Typos like ``ctrl.nqn = x`` (should be ``ctrl.subsysnqn``) are
    silently ignored by default Python ``__setattr__``.  This guard
    raises ``AttributeError`` for any name not already present on the
    object, keeping the struct-like API strict.
    """
    if name.startswith('_') or name in ('this', 'thisown') or hasattr(type(self), name):
        object.__setattr__(self, name, value)
    else:
        raise AttributeError(
            f"{type(self).__name__!r} has no attribute {name!r}")
%}

/* struct libnvme_path */
%rename(Path) libnvme_path;
struct libnvme_path {
	const char * name;
	const char * sysfs_dir;
};

%pythoncode %{
Path.__setattr__ = _nvme_guarded_setattr
%}

/* struct libnvme_ns */
%rename(Namespace) libnvme_ns;
struct libnvme_ns {
	__u32 nsid;
	%immutable name;
	const char * name;
	%immutable generic_name;
	const char * generic_name;
	const char * sysfs_dir;
};

%pythoncode %{
Namespace.__setattr__ = _nvme_guarded_setattr
%}

/* struct libnvme_ctrl */
%rename(Ctrl) libnvme_ctrl;
%rename(libnvme_ctrl_state_get) libnvme_ctrl_get_state;
%{
	#define libnvme_ctrl_state_get libnvme_ctrl_get_state
%}
struct libnvme_ctrl {
	%immutable name;
	const char * name;
	%immutable sysfs_dir;
	const char * sysfs_dir;
	%immutable address;
	const char * address;
	%immutable transport;
	const char * transport;
	%immutable subsysnqn;
	const char * subsysnqn;
	%immutable traddr;
	const char * traddr;
	%immutable trsvcid;
	const char * trsvcid;
	const char * tls_key_identity;
	const char * tls_key;
	%immutable host_traddr;
	const char * host_traddr;
	%immutable host_iface;
	const char * host_iface;
	bool discovery_ctrl;
	bool unique_discovery_ctrl;
	bool discovered;
	bool persistent;
	%extend {
		%immutable state;
		const char * state;
	}
};

%pythoncode %{
Ctrl.__setattr__ = _nvme_guarded_setattr
%}

/* struct libnvme_subsystem */
%rename(Subsystem) libnvme_subsystem;
struct libnvme_subsystem {
	%immutable name;
	const char * name;
	%immutable sysfs_dir;
	const char * sysfs_dir;
	%immutable subsysnqn;
	const char * subsysnqn;
	%immutable subsystype;
	const char * subsystype;
};

%pythoncode %{
Subsystem.__setattr__ = _nvme_guarded_setattr
%}

/* struct libnvme_host */
%rename(Host) libnvme_host;
struct libnvme_host {
	%immutable hostnqn;
	const char * hostnqn;
	%immutable hostid;
	const char * hostid;
	const char * kxchap_host_key;
	const char * hostsymname;
};

%pythoncode %{
Host.__setattr__ = _nvme_guarded_setattr
%}

/* struct libnvme_global_ctx */
%rename(GlobalCtx) libnvme_global_ctx;
struct libnvme_global_ctx {
	bool dry_run;
	bool force_4k;
	bool mi_probe_enabled;
	bool ioctl_probing;
	const char * hostnqn;	// no C getter; SWIG emits one anyway
	const char * hostid;	// no C getter; SWIG emits one anyway
};

%pythoncode %{
GlobalCtx.__setattr__ = _nvme_guarded_setattr
%}

