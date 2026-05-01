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

/* struct libnvme_ns */
%rename(Namespace) libnvme_ns;
%rename(libnvme_ns_command_retry_count_get) libnvme_ns_get_command_retry_count;
%rename(libnvme_ns_command_error_count_get) libnvme_ns_get_command_error_count;
%rename(libnvme_ns_requeue_no_usable_path_count_get) libnvme_ns_get_requeue_no_usable_path_count;
%rename(libnvme_ns_fail_no_available_path_count_get) libnvme_ns_get_fail_no_available_path_count;
%{
	#define libnvme_ns_command_retry_count_get libnvme_ns_get_command_retry_count
	#define libnvme_ns_command_error_count_get libnvme_ns_get_command_error_count
	#define libnvme_ns_requeue_no_usable_path_count_get libnvme_ns_get_requeue_no_usable_path_count
	#define libnvme_ns_fail_no_available_path_count_get libnvme_ns_get_fail_no_available_path_count
%}
struct libnvme_ns {
	__u32 nsid;
	%immutable name;
	const char * name;
	%immutable generic_name;
	const char * generic_name;
	const char * sysfs_dir;
	int lba_shift;
	int lba_size;
	int meta_size;
	uint64_t lba_count;
	uint64_t lba_util;
	%immutable eui64;
	uint8_t eui64[8];
	%immutable nguid;
	uint8_t nguid[16];
	%immutable csi;
	enum nvme_csi csi;
	%extend {
		%immutable command_retry_count;
		long command_retry_count;
		%immutable command_error_count;
		long command_error_count;
		%immutable requeue_no_usable_path_count;
		long requeue_no_usable_path_count;
		%immutable fail_no_available_path_count;
		long fail_no_available_path_count;
	}
};

%pythoncode %{
Namespace.__setattr__ = _nvme_guarded_setattr
%}

/* struct libnvme_ctrl */
%rename(Ctrl) libnvme_ctrl;
%rename(libnvme_ctrl_state_get) libnvme_ctrl_get_state;
%rename(libnvme_ctrl_command_error_count_get) libnvme_ctrl_get_command_error_count;
%rename(libnvme_ctrl_reset_count_get) libnvme_ctrl_get_reset_count;
%rename(libnvme_ctrl_reconnect_count_get) libnvme_ctrl_get_reconnect_count;
%{
	#define libnvme_ctrl_state_get libnvme_ctrl_get_state
	#define libnvme_ctrl_command_error_count_get libnvme_ctrl_get_command_error_count
	#define libnvme_ctrl_reset_count_get libnvme_ctrl_get_reset_count
	#define libnvme_ctrl_reconnect_count_get libnvme_ctrl_get_reconnect_count
%}
struct libnvme_ctrl {
	%immutable name;
	const char * name;
	%immutable sysfs_dir;
	const char * sysfs_dir;
	%immutable address;
	const char * address;
	%immutable firmware;
	const char * firmware;
	%immutable model;
	const char * model;
	%immutable numa_node;
	const char * numa_node;
	%immutable queue_count;
	const char * queue_count;
	%immutable serial;
	const char * serial;
	%immutable sqsize;
	const char * sqsize;
	%immutable transport;
	const char * transport;
	%immutable subsysnqn;
	const char * subsysnqn;
	%immutable traddr;
	const char * traddr;
	%immutable trsvcid;
	const char * trsvcid;
	const char * dhchap_host_key;
	const char * dhchap_ctrl_key;
	const char * keyring;
	const char * tls_key_identity;
	const char * tls_key;
	%immutable cntrltype;
	const char * cntrltype;
	%immutable cntlid;
	const char * cntlid;
	%immutable dctype;
	const char * dctype;
	%immutable phy_slot;
	const char * phy_slot;
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
		%immutable command_error_count;
		long command_error_count;
		%immutable reset_count;
		long reset_count;
		%immutable reconnect_count;
		long reconnect_count;
	}
};

%pythoncode %{
Ctrl.__setattr__ = _nvme_guarded_setattr
%}

/* struct libnvme_subsystem */
%rename(Subsystem) libnvme_subsystem;
%rename(libnvme_subsystem_iopolicy_get) libnvme_subsystem_get_iopolicy;
%{
	#define libnvme_subsystem_iopolicy_get libnvme_subsystem_get_iopolicy
%}
struct libnvme_subsystem {
	%immutable name;
	const char * name;
	%immutable sysfs_dir;
	const char * sysfs_dir;
	%immutable subsysnqn;
	const char * subsysnqn;
	%immutable model;
	const char * model;
	%immutable serial;
	const char * serial;
	%immutable firmware;
	const char * firmware;
	%immutable subsystype;
	const char * subsystype;
	const char * application;
	%extend {
		%immutable iopolicy;
		const char * iopolicy;
	}
};

%pythoncode %{
Subsystem.__setattr__ = _nvme_guarded_setattr
%}

/* struct libnvme_host */
%rename(Host) libnvme_host;
%rename(libnvme_host_pdc_enabled_set) libnvme_host_set_pdc_enabled;
%{
	#define libnvme_host_pdc_enabled_set libnvme_host_set_pdc_enabled
%}
struct libnvme_host {
	%immutable hostnqn;
	const char * hostnqn;
	%immutable hostid;
	const char * hostid;
	const char * dhchap_host_key;
	const char * hostsymname;
};

%pythoncode %{
Host.__setattr__ = _nvme_guarded_setattr
%}

/* struct libnvme_global_ctx */
%rename(GlobalCtx) libnvme_global_ctx;
struct libnvme_global_ctx {
};

%pythoncode %{
GlobalCtx.__setattr__ = _nvme_guarded_setattr
%}

