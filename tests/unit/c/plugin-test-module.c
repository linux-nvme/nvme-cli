// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * A plugin module for test-plugin-loader, TEST_NAME with the symbols of
 * TEST_ID. The defines make the variants: TEST_ABI the interface it
 * claims, TEST_NO_INIT without an init function, TEST_UNRESOLVED with a
 * symbol nobody defines.
 */
#include <shared/compiler-attributes-util.h>

#include "plugin-test-module.h"

#ifdef TEST_UNRESOLVED
void plugin_test_undefined(void);
#endif

#define __SYM(id, sym)	nvme_plugin_##id##_##sym
#define SYM(id, sym)	__SYM(id, sym)

__shr_public const char SYM(TEST_ID, abi)[] = TEST_ABI;

#ifndef TEST_NO_INIT
__shr_public void SYM(TEST_ID, init)(void);
void SYM(TEST_ID, init)(void)
{
#ifdef TEST_UNRESOLVED
	plugin_test_undefined();
#endif
	plugin_test_init(TEST_NAME);
}
#endif
