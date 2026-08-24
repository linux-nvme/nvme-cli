/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 SUSE Software Solutions
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */
#pragma once

/**
 * enum cli_error_codes - nvme-cli internal error codes
 * @ECLI_INVALID_TAGS: the requested reference/storage tag is invalid for
 *		        the namespace's protection information format
 * @ECLI_INVALID_PI_FORMAT: the namespace's protection information format,
 *			     as reported by Identify NVM CS NS, is internally
 *			     inconsistent (e.g. LBSTM disagrees with PIFA's
 *			     masking level)
 * @ECLI_IDENTIFY_NS_FAILED: the base Identify Namespace command failed
 */
enum cli_error_codes {
	ECLI_INVALID_TAGS = 2000,
	ECLI_INVALID_PI_FORMAT = 2001,
	ECLI_IDENTIFY_NS_FAILED = 2002,
};
