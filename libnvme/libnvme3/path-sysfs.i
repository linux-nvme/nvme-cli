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

/* struct libnvme_path -- sysfs-backed properties */
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
