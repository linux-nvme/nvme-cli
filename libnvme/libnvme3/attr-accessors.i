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

/* struct libnvme_ctrl -- lazily-loaded properties */
%rename(libnvme_ctrl_firmware_set) libnvme_ctrl_set_firmware;
%rename(libnvme_ctrl_model_set) libnvme_ctrl_set_model;
%rename(libnvme_ctrl_serial_set) libnvme_ctrl_set_serial;
%rename(libnvme_ctrl_cntrltype_set) libnvme_ctrl_set_cntrltype;
%rename(libnvme_ctrl_cntlid_set) libnvme_ctrl_set_cntlid;
%rename(libnvme_ctrl_dctype_set) libnvme_ctrl_set_dctype;
%rename(libnvme_ctrl_kxchap_host_key_set) libnvme_ctrl_set_kxchap_host_key;
%rename(libnvme_ctrl_kxchap_ctrl_key_set) libnvme_ctrl_set_kxchap_ctrl_key;
%rename(libnvme_ctrl_keyring_set) libnvme_ctrl_set_keyring;
%{
	#define libnvme_ctrl_firmware_set libnvme_ctrl_set_firmware
	#define libnvme_ctrl_model_set libnvme_ctrl_set_model
	#define libnvme_ctrl_serial_set libnvme_ctrl_set_serial
	#define libnvme_ctrl_cntrltype_set libnvme_ctrl_set_cntrltype
	#define libnvme_ctrl_cntlid_set libnvme_ctrl_set_cntlid
	#define libnvme_ctrl_dctype_set libnvme_ctrl_set_dctype
	#define libnvme_ctrl_kxchap_host_key_set libnvme_ctrl_set_kxchap_host_key
	#define libnvme_ctrl_kxchap_ctrl_key_set libnvme_ctrl_set_kxchap_ctrl_key
	#define libnvme_ctrl_keyring_set libnvme_ctrl_set_keyring
	static const char *libnvme_ctrl_numa_node_get(const struct libnvme_ctrl *p)
	{
		const char *val;
		int ret = libnvme_ctrl_get_numa_node(p, &val, NULL);

		if (ret == 0)
			return val;
		if (ret == -ENOENT)
			return NULL;

		raise_nvme(NvmeError, ret);
		return NULL;
	}
	static const char *libnvme_ctrl_queue_count_get(const struct libnvme_ctrl *p)
	{
		const char *val;
		int ret = libnvme_ctrl_get_queue_count(p, &val, NULL);

		if (ret == 0)
			return val;
		if (ret == -ENOENT)
			return NULL;

		raise_nvme(NvmeError, ret);
		return NULL;
	}
	static const char *libnvme_ctrl_sqsize_get(const struct libnvme_ctrl *p)
	{
		const char *val;
		int ret = libnvme_ctrl_get_sqsize(p, &val, NULL);

		if (ret == 0)
			return val;
		if (ret == -ENOENT)
			return NULL;

		raise_nvme(NvmeError, ret);
		return NULL;
	}
	static PyObject *libnvme_ctrl_command_error_count_get(const struct libnvme_ctrl *p)
	{
		long val;
		int ret = libnvme_ctrl_get_command_error_count(p, &val, 0);

		if (ret == -ENOENT)
			Py_RETURN_NONE;
		if (ret) {
			raise_nvme(NvmeError, ret);
			return NULL;
		}

		return PyLong_FromLong(val);
	}
	static PyObject *libnvme_ctrl_reset_count_get(const struct libnvme_ctrl *p)
	{
		long val;
		int ret = libnvme_ctrl_get_reset_count(p, &val, 0);

		if (ret == -ENOENT)
			Py_RETURN_NONE;
		if (ret) {
			raise_nvme(NvmeError, ret);
			return NULL;
		}

		return PyLong_FromLong(val);
	}
	static PyObject *libnvme_ctrl_reconnect_count_get(const struct libnvme_ctrl *p)
	{
		long val;
		int ret = libnvme_ctrl_get_reconnect_count(p, &val, 0);

		if (ret == -ENOENT)
			Py_RETURN_NONE;
		if (ret) {
			raise_nvme(NvmeError, ret);
			return NULL;
		}

		return PyLong_FromLong(val);
	}
	static const char *libnvme_ctrl_firmware_get(const struct libnvme_ctrl *p)
	{
		const char *val;
		int ret = libnvme_ctrl_get_firmware(p, &val, NULL);

		if (ret == 0)
			return val;
		if (ret == -ENOENT)
			return NULL;

		raise_nvme(NvmeError, ret);
		return NULL;
	}
	static const char *libnvme_ctrl_model_get(const struct libnvme_ctrl *p)
	{
		const char *val;
		int ret = libnvme_ctrl_get_model(p, &val, NULL);

		if (ret == 0)
			return val;
		if (ret == -ENOENT)
			return NULL;

		raise_nvme(NvmeError, ret);
		return NULL;
	}
	static const char *libnvme_ctrl_serial_get(const struct libnvme_ctrl *p)
	{
		const char *val;
		int ret = libnvme_ctrl_get_serial(p, &val, NULL);

		if (ret == 0)
			return val;
		if (ret == -ENOENT)
			return NULL;

		raise_nvme(NvmeError, ret);
		return NULL;
	}
	static const char *libnvme_ctrl_cntrltype_get(const struct libnvme_ctrl *p)
	{
		const char *val;
		int ret = libnvme_ctrl_get_cntrltype(p, &val, NULL);

		if (ret == 0)
			return val;
		if (ret == -ENOENT)
			return NULL;

		raise_nvme(NvmeError, ret);
		return NULL;
	}
	static const char *libnvme_ctrl_cntlid_get(const struct libnvme_ctrl *p)
	{
		const char *val;
		int ret = libnvme_ctrl_get_cntlid(p, &val, NULL);

		if (ret == 0)
			return val;
		if (ret == -ENOENT)
			return NULL;

		raise_nvme(NvmeError, ret);
		return NULL;
	}
	static const char *libnvme_ctrl_dctype_get(const struct libnvme_ctrl *p)
	{
		const char *val;
		int ret = libnvme_ctrl_get_dctype(p, &val, NULL);

		if (ret == 0)
			return val;
		if (ret == -ENOENT)
			return NULL;

		raise_nvme(NvmeError, ret);
		return NULL;
	}
	static const char *libnvme_ctrl_phy_slot_get(const struct libnvme_ctrl *p)
	{
		const char *val;
		int ret = libnvme_ctrl_get_phy_slot(p, &val, NULL);

		if (ret == 0)
			return val;
		if (ret == -ENOENT)
			return NULL;

		raise_nvme(NvmeError, ret);
		return NULL;
	}
	static const char *libnvme_ctrl_kxchap_host_key_get(const struct libnvme_ctrl *p)
	{
		const char *val;
		int ret = libnvme_ctrl_get_kxchap_host_key(p, &val, NULL);

		if (ret == 0)
			return val;
		if (ret == -ENOENT)
			return NULL;

		raise_nvme(NvmeError, ret);
		return NULL;
	}
	static const char *libnvme_ctrl_kxchap_ctrl_key_get(const struct libnvme_ctrl *p)
	{
		const char *val;
		int ret = libnvme_ctrl_get_kxchap_ctrl_key(p, &val, NULL);

		if (ret == 0)
			return val;
		if (ret == -ENOENT)
			return NULL;

		raise_nvme(NvmeError, ret);
		return NULL;
	}
	static const char *libnvme_ctrl_keyring_get(const struct libnvme_ctrl *p)
	{
		const char *val;
		int ret = libnvme_ctrl_get_keyring(p, &val, NULL);

		if (ret == 0)
			return val;
		if (ret == -ENOENT)
			return NULL;

		raise_nvme(NvmeError, ret);
		return NULL;
	}
%}

%exception libnvme_ctrl::numa_node {
	$action
	if (PyErr_Occurred()) SWIG_fail;
}
%exception libnvme_ctrl::queue_count {
	$action
	if (PyErr_Occurred()) SWIG_fail;
}
%exception libnvme_ctrl::sqsize {
	$action
	if (PyErr_Occurred()) SWIG_fail;
}
%exception libnvme_ctrl::command_error_count {
	$action
	if (PyErr_Occurred()) SWIG_fail;
}
%exception libnvme_ctrl::reset_count {
	$action
	if (PyErr_Occurred()) SWIG_fail;
}
%exception libnvme_ctrl::reconnect_count {
	$action
	if (PyErr_Occurred()) SWIG_fail;
}
%exception libnvme_ctrl::firmware {
	$action
	if (PyErr_Occurred()) SWIG_fail;
}
%exception libnvme_ctrl::model {
	$action
	if (PyErr_Occurred()) SWIG_fail;
}
%exception libnvme_ctrl::serial {
	$action
	if (PyErr_Occurred()) SWIG_fail;
}
%exception libnvme_ctrl::cntrltype {
	$action
	if (PyErr_Occurred()) SWIG_fail;
}
%exception libnvme_ctrl::cntlid {
	$action
	if (PyErr_Occurred()) SWIG_fail;
}
%exception libnvme_ctrl::dctype {
	$action
	if (PyErr_Occurred()) SWIG_fail;
}
%exception libnvme_ctrl::phy_slot {
	$action
	if (PyErr_Occurred()) SWIG_fail;
}
%exception libnvme_ctrl::kxchap_host_key {
	$action
	if (PyErr_Occurred()) SWIG_fail;
}
%exception libnvme_ctrl::kxchap_ctrl_key {
	$action
	if (PyErr_Occurred()) SWIG_fail;
}
%exception libnvme_ctrl::keyring {
	$action
	if (PyErr_Occurred()) SWIG_fail;
}

%extend struct libnvme_ctrl {
	%immutable numa_node;
	const char * numa_node;
	%immutable queue_count;
	const char * queue_count;
	%immutable sqsize;
	const char * sqsize;
	%immutable command_error_count;
	PyObject * command_error_count;
	%immutable reset_count;
	PyObject * reset_count;
	%immutable reconnect_count;
	PyObject * reconnect_count;
	const char * firmware;
	const char * model;
	const char * serial;
	const char * cntrltype;
	const char * cntlid;
	const char * dctype;
	%immutable phy_slot;
	const char * phy_slot;
	const char * kxchap_host_key;
	const char * kxchap_ctrl_key;
	const char * keyring;
}

/* struct libnvme_path -- lazily-loaded properties */
%{
	static const char *libnvme_path_ana_state_get(const struct libnvme_path *p)
	{
		const char *val;
		int ret = libnvme_path_get_ana_state(p, &val, NULL);

		if (ret == 0)
			return val;
		if (ret == -ENOENT)
			return NULL;

		raise_nvme(NvmeError, ret);
		return NULL;
	}
	static const char *libnvme_path_numa_nodes_get(const struct libnvme_path *p)
	{
		const char *val;
		int ret = libnvme_path_get_numa_nodes(p, &val, NULL);

		if (ret == 0)
			return val;
		if (ret == -ENOENT)
			return NULL;

		raise_nvme(NvmeError, ret);
		return NULL;
	}
	static PyObject *libnvme_path_grpid_get(const struct libnvme_path *p)
	{
		int val;
		int ret = libnvme_path_get_grpid(p, &val, 0);

		if (ret == -ENOENT)
			Py_RETURN_NONE;
		if (ret) {
			raise_nvme(NvmeError, ret);
			return NULL;
		}

		return PyLong_FromLong(val);
	}
	static PyObject *libnvme_path_queue_depth_get(const struct libnvme_path *p)
	{
		int val;
		int ret = libnvme_path_get_queue_depth(p, &val, 0);

		if (ret == -ENOENT)
			Py_RETURN_NONE;
		if (ret) {
			raise_nvme(NvmeError, ret);
			return NULL;
		}

		return PyLong_FromLong(val);
	}
	static PyObject *libnvme_path_multipath_failover_count_get(const struct libnvme_path *p)
	{
		long val;
		int ret = libnvme_path_get_multipath_failover_count(p, &val, 0);

		if (ret == -ENOENT)
			Py_RETURN_NONE;
		if (ret) {
			raise_nvme(NvmeError, ret);
			return NULL;
		}

		return PyLong_FromLong(val);
	}
	static PyObject *libnvme_path_command_retry_count_get(const struct libnvme_path *p)
	{
		long val;
		int ret = libnvme_path_get_command_retry_count(p, &val, 0);

		if (ret == -ENOENT)
			Py_RETURN_NONE;
		if (ret) {
			raise_nvme(NvmeError, ret);
			return NULL;
		}

		return PyLong_FromLong(val);
	}
	static PyObject *libnvme_path_command_error_count_get(const struct libnvme_path *p)
	{
		long val;
		int ret = libnvme_path_get_command_error_count(p, &val, 0);

		if (ret == -ENOENT)
			Py_RETURN_NONE;
		if (ret) {
			raise_nvme(NvmeError, ret);
			return NULL;
		}

		return PyLong_FromLong(val);
	}
%}

%exception libnvme_path::ana_state {
	$action
	if (PyErr_Occurred()) SWIG_fail;
}
%exception libnvme_path::numa_nodes {
	$action
	if (PyErr_Occurred()) SWIG_fail;
}
%exception libnvme_path::grpid {
	$action
	if (PyErr_Occurred()) SWIG_fail;
}
%exception libnvme_path::queue_depth {
	$action
	if (PyErr_Occurred()) SWIG_fail;
}
%exception libnvme_path::multipath_failover_count {
	$action
	if (PyErr_Occurred()) SWIG_fail;
}
%exception libnvme_path::command_retry_count {
	$action
	if (PyErr_Occurred()) SWIG_fail;
}
%exception libnvme_path::command_error_count {
	$action
	if (PyErr_Occurred()) SWIG_fail;
}

%extend struct libnvme_path {
	%immutable ana_state;
	const char * ana_state;
	%immutable numa_nodes;
	const char * numa_nodes;
	%immutable grpid;
	PyObject * grpid;
	%immutable queue_depth;
	PyObject * queue_depth;
	%immutable multipath_failover_count;
	PyObject * multipath_failover_count;
	%immutable command_retry_count;
	PyObject * command_retry_count;
	%immutable command_error_count;
	PyObject * command_error_count;
}

/* struct libnvme_ns -- lazily-loaded properties */
%{
	static PyObject *libnvme_ns_lba_size_get(const struct libnvme_ns *p)
	{
		int val;
		int ret = libnvme_ns_get_lba_size(p, &val, 0);

		if (ret == -ENOENT)
			Py_RETURN_NONE;
		if (ret) {
			raise_nvme(NvmeError, ret);
			return NULL;
		}

		return PyLong_FromLong(val);
	}
	static PyObject *libnvme_ns_lba_shift_get(const struct libnvme_ns *p)
	{
		int val;
		int ret = libnvme_ns_get_lba_shift(p, &val, 0);

		if (ret == -ENOENT)
			Py_RETURN_NONE;
		if (ret) {
			raise_nvme(NvmeError, ret);
			return NULL;
		}

		return PyLong_FromLong(val);
	}
	static PyObject *libnvme_ns_lba_count_get(const struct libnvme_ns *p)
	{
		uint64_t val;
		int ret = libnvme_ns_get_lba_count(p, &val, 0);

		if (ret == -ENOENT)
			Py_RETURN_NONE;
		if (ret) {
			raise_nvme(NvmeError, ret);
			return NULL;
		}

		return PyLong_FromUnsignedLongLong(val);
	}
	static PyObject *libnvme_ns_lba_util_get(const struct libnvme_ns *p)
	{
		uint64_t val;
		int ret = libnvme_ns_get_lba_util(p, &val, 0);

		if (ret == -ENOENT)
			Py_RETURN_NONE;
		if (ret) {
			raise_nvme(NvmeError, ret);
			return NULL;
		}

		return PyLong_FromUnsignedLongLong(val);
	}
	static PyObject *libnvme_ns_meta_size_get(const struct libnvme_ns *p)
	{
		int val;
		int ret = libnvme_ns_get_meta_size(p, &val, 0);

		if (ret == -ENOENT)
			Py_RETURN_NONE;
		if (ret) {
			raise_nvme(NvmeError, ret);
			return NULL;
		}

		return PyLong_FromLong(val);
	}
	static PyObject *libnvme_ns_csi_get(const struct libnvme_ns *p)
	{
		enum nvme_csi val;
		int ret = libnvme_ns_get_csi(p, &val, 0);

		if (ret == -ENOENT)
			Py_RETURN_NONE;
		if (ret) {
			raise_nvme(NvmeError, ret);
			return NULL;
		}

		return PyLong_FromLong(val);
	}
	static PyObject *libnvme_ns_command_retry_count_get(const struct libnvme_ns *p)
	{
		long val;
		int ret = libnvme_ns_get_command_retry_count(p, &val, 0);

		if (ret == -ENOENT)
			Py_RETURN_NONE;
		if (ret) {
			raise_nvme(NvmeError, ret);
			return NULL;
		}

		return PyLong_FromLong(val);
	}
	static PyObject *libnvme_ns_command_error_count_get(const struct libnvme_ns *p)
	{
		long val;
		int ret = libnvme_ns_get_command_error_count(p, &val, 0);

		if (ret == -ENOENT)
			Py_RETURN_NONE;
		if (ret) {
			raise_nvme(NvmeError, ret);
			return NULL;
		}

		return PyLong_FromLong(val);
	}
	static PyObject *libnvme_ns_io_requeue_no_usable_path_count_get(const struct libnvme_ns *p)
	{
		long val;
		int ret = libnvme_ns_get_io_requeue_no_usable_path_count(p, &val, 0);

		if (ret == -ENOENT)
			Py_RETURN_NONE;
		if (ret) {
			raise_nvme(NvmeError, ret);
			return NULL;
		}

		return PyLong_FromLong(val);
	}
	static PyObject *libnvme_ns_io_fail_no_available_path_count_get(const struct libnvme_ns *p)
	{
		long val;
		int ret = libnvme_ns_get_io_fail_no_available_path_count(p, &val, 0);

		if (ret == -ENOENT)
			Py_RETURN_NONE;
		if (ret) {
			raise_nvme(NvmeError, ret);
			return NULL;
		}

		return PyLong_FromLong(val);
	}
%}

%exception libnvme_ns::lba_size {
	$action
	if (PyErr_Occurred()) SWIG_fail;
}
%exception libnvme_ns::lba_shift {
	$action
	if (PyErr_Occurred()) SWIG_fail;
}
%exception libnvme_ns::lba_count {
	$action
	if (PyErr_Occurred()) SWIG_fail;
}
%exception libnvme_ns::lba_util {
	$action
	if (PyErr_Occurred()) SWIG_fail;
}
%exception libnvme_ns::meta_size {
	$action
	if (PyErr_Occurred()) SWIG_fail;
}
%exception libnvme_ns::csi {
	$action
	if (PyErr_Occurred()) SWIG_fail;
}
%exception libnvme_ns::command_retry_count {
	$action
	if (PyErr_Occurred()) SWIG_fail;
}
%exception libnvme_ns::command_error_count {
	$action
	if (PyErr_Occurred()) SWIG_fail;
}
%exception libnvme_ns::io_requeue_no_usable_path_count {
	$action
	if (PyErr_Occurred()) SWIG_fail;
}
%exception libnvme_ns::io_fail_no_available_path_count {
	$action
	if (PyErr_Occurred()) SWIG_fail;
}

%extend struct libnvme_ns {
	%immutable lba_size;
	PyObject * lba_size;
	%immutable lba_shift;
	PyObject * lba_shift;
	%immutable lba_count;
	PyObject * lba_count;
	%immutable lba_util;
	PyObject * lba_util;
	%immutable meta_size;
	PyObject * meta_size;
	%immutable csi;
	PyObject * csi;
	%immutable command_retry_count;
	PyObject * command_retry_count;
	%immutable command_error_count;
	PyObject * command_error_count;
	%immutable io_requeue_no_usable_path_count;
	PyObject * io_requeue_no_usable_path_count;
	%immutable io_fail_no_available_path_count;
	PyObject * io_fail_no_available_path_count;
}

/* struct libnvme_subsystem -- lazily-loaded properties */
%rename(libnvme_subsystem_model_set) libnvme_subsystem_set_model;
%rename(libnvme_subsystem_serial_set) libnvme_subsystem_set_serial;
%rename(libnvme_subsystem_firmware_set) libnvme_subsystem_set_firmware;
%{
	#define libnvme_subsystem_model_set libnvme_subsystem_set_model
	#define libnvme_subsystem_serial_set libnvme_subsystem_set_serial
	#define libnvme_subsystem_firmware_set libnvme_subsystem_set_firmware
	static const char *libnvme_subsystem_model_get(const struct libnvme_subsystem *p)
	{
		const char *val;
		int ret = libnvme_subsystem_get_model(p, &val, NULL);

		if (ret == 0)
			return val;
		if (ret == -ENOENT)
			return NULL;

		raise_nvme(NvmeError, ret);
		return NULL;
	}
	static const char *libnvme_subsystem_serial_get(const struct libnvme_subsystem *p)
	{
		const char *val;
		int ret = libnvme_subsystem_get_serial(p, &val, NULL);

		if (ret == 0)
			return val;
		if (ret == -ENOENT)
			return NULL;

		raise_nvme(NvmeError, ret);
		return NULL;
	}
	static const char *libnvme_subsystem_firmware_get(const struct libnvme_subsystem *p)
	{
		const char *val;
		int ret = libnvme_subsystem_get_firmware(p, &val, NULL);

		if (ret == 0)
			return val;
		if (ret == -ENOENT)
			return NULL;

		raise_nvme(NvmeError, ret);
		return NULL;
	}
	static const char *libnvme_subsystem_iopolicy_get(const struct libnvme_subsystem *p)
	{
		const char *val;
		int ret = libnvme_subsystem_get_iopolicy(p, &val, NULL);

		if (ret == 0)
			return val;
		if (ret == -ENOENT)
			return NULL;

		raise_nvme(NvmeError, ret);
		return NULL;
	}
%}

%exception libnvme_subsystem::model {
	$action
	if (PyErr_Occurred()) SWIG_fail;
}
%exception libnvme_subsystem::serial {
	$action
	if (PyErr_Occurred()) SWIG_fail;
}
%exception libnvme_subsystem::firmware {
	$action
	if (PyErr_Occurred()) SWIG_fail;
}
%exception libnvme_subsystem::iopolicy {
	$action
	if (PyErr_Occurred()) SWIG_fail;
}

%extend struct libnvme_subsystem {
	const char * model;
	const char * serial;
	const char * firmware;
	%immutable iopolicy;
	const char * iopolicy;
}

