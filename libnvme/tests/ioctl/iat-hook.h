/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Import Address Table patching: the Windows stand-in for LD_PRELOAD.
 *
 * On Linux the ioctl mock is injected with LD_PRELOAD and finds the real
 * function with dlsym(RTLD_NEXT). Neither exists on Windows, and the obvious
 * alternative -- ld --wrap -- does not work here: libnvme is a DLL, so its
 * call to DeviceIoControl is resolved through its own import thunk at load
 * time and never passes through a wrappable symbol in the test executable.
 *
 * What does work is rewriting that thunk. Every PE image that calls an
 * imported function reaches it through a slot in its Import Address Table,
 * so overwriting libnvme's IAT slot for DeviceIoControl redirects the call
 * without touching libnvme's code. Verified on both x86_64 and aarch64.
 */
#pragma once

#include <windows.h>
#include <stdbool.h>

/**
 * iat_patch() - redirect a module's imported function to a replacement
 * @module: handle of the module whose imports are rewritten (the *caller*
 *          of @symbol, not the DLL that exports it)
 * @symbol: name of the imported function, e.g. "DeviceIoControl"
 * @replacement: function to call instead
 * @saved: if not NULL, receives the original target so it can be restored
 *
 * Return: true if the import was found and patched.
 *
 * Only rewrites data (one IAT slot), never code, so it is safe to apply and
 * undo repeatedly. Note that the patch is per-module: other modules calling
 * the same function are unaffected, which is exactly what a test wants.
 */
bool iat_patch(HMODULE module, const char *symbol, void *replacement,
	       void **saved);
