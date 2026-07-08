// SPDX-License-Identifier: LGPL-2.1-or-later

/*
 * This file is part of libnvme.
 *
 * Copyright (c) 2025, Dell Technologies Inc. or its subsidiaries.
 * Authors: Martin Belanger <Martin.Belanger@dell.com>
 *
 * Hand-maintained SWIG accessor bridges.
 *
 * These members expose nested struct pointers and cannot be expressed
 * as generated accessors — they must be kept here, manually.
 */

/* ctrl.subsystem: exposes the parent libnvme_subsystem pointer */
%rename(libnvme_ctrl_subsystem_get) libnvme_ctrl_get_subsystem;

/* subsystem.host: exposes the parent libnvme_host pointer */
%rename(libnvme_subsystem_host_get) libnvme_subsystem_get_host;

%{
	#define libnvme_ctrl_subsystem_get libnvme_ctrl_get_subsystem
	#define libnvme_subsystem_host_get libnvme_subsystem_get_host
%}
