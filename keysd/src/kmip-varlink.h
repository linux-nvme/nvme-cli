/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */
#pragma once

/* The Varlink interface of nvme-keysd-kmip. */

#define KMIP_VARLINK_ADDRESS		RUNDIR "/nvme/keysd/kmip"
#define KMIP_VARLINK_INTERFACE		"io.nvme.keysd.Kmip"

#define KMIP_VARLINK_GET_KEY		KMIP_VARLINK_INTERFACE ".GetKey"

#define KMIP_VARLINK_NO_SUCH_KMS	KMIP_VARLINK_INTERFACE ".NoSuchKms"
#define KMIP_VARLINK_NO_SUCH_KEY	KMIP_VARLINK_INTERFACE ".NoSuchKey"
#define KMIP_VARLINK_KEY_NOT_UNIQUE	KMIP_VARLINK_INTERFACE ".KeyNotUnique"
#define KMIP_VARLINK_INVALID_KEY	KMIP_VARLINK_INTERFACE ".InvalidKey"
#define KMIP_VARLINK_KMS_FAILED		KMIP_VARLINK_INTERFACE ".KmsFailed"
