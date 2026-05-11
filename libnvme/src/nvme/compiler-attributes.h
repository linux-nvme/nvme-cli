// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2026, Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <Martin.Belanger@dell.com>
 */
#pragma once

/**
 * __public - mark a symbol as part of the public API.
 *
 * When the library is built with -fvisibility=hidden all symbols are hidden
 * by default.  Annotating a function with __public overrides that and makes
 * the symbol visible in the shared library ABI.
 */
#define __public __attribute__((visibility("default")))

/**
 * __weak - Declares a symbol as "weak"
 *
 * A weak symbol provides a default implementation that can be
 * replaced by another (strong) definition during linking. Useful for
 * optional overrides and platform hooks.
 */
#define __weak __attribute__((weak))

/**
 * __unused - Mark a symbol or parameter as intentionally unused.
 *
 * Suppresses compiler warnings for symbols or parameters that are unused
 * by design (e.g. no-op stubs that must match a specific signature).
 */
#define __unused __attribute__((__unused__))
