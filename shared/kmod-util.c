// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 SUSE Software Solutions
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */
#ifdef NVME_HAVE_LIBKMOD_DLOPEN
#include <dlfcn.h>
#endif
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>

#include <libkmod.h>

#include <ccan/array_size/array_size.h>

#include "cleanup-util.h"
#include "kmod-util.h"

#ifdef NVME_HAVE_LIBKMOD_DLOPEN
/*
 * libkmod is loaded when the first module is loaded, so that nvme doesn't
 * depend on it. The functions below are called through pointers of the
 * same type, taken from libkmod's header.
 */
static typeof(kmod_new) *sym_kmod_new;
static typeof(kmod_unref) *sym_kmod_unref;
static typeof(kmod_module_new_from_name) *sym_kmod_module_new_from_name;
static typeof(kmod_module_unref) *sym_kmod_module_unref;
static typeof(kmod_module_get_initstate) *sym_kmod_module_get_initstate;
static typeof(kmod_module_probe_insert_module)
	*sym_kmod_module_probe_insert_module;

static const struct {
	const char *name;
	void **ptr;
} kmod_syms[] = {
	{ "kmod_new", (void **)&sym_kmod_new },
	{ "kmod_unref", (void **)&sym_kmod_unref },
	{ "kmod_module_new_from_name",
	  (void **)&sym_kmod_module_new_from_name },
	{ "kmod_module_unref", (void **)&sym_kmod_module_unref },
	{ "kmod_module_get_initstate",
	  (void **)&sym_kmod_module_get_initstate },
	{ "kmod_module_probe_insert_module",
	  (void **)&sym_kmod_module_probe_insert_module },
};

#define kmod_new (*sym_kmod_new)
#define kmod_unref (*sym_kmod_unref)
#define kmod_module_new_from_name (*sym_kmod_module_new_from_name)
#define kmod_module_unref (*sym_kmod_module_unref)
#define kmod_module_get_initstate (*sym_kmod_module_get_initstate)
#define kmod_module_probe_insert_module \
	(*sym_kmod_module_probe_insert_module)

/*
 * The optional dependency for packaging tools and initrd generators, see
 * https://uapi-group.org/specifications/specs/elf_dlopen_metadata/
 */
#define DLOPEN_NOTE_OWNER "FDO"
#define DLOPEN_NOTE_TYPE 0x407c0c0a
#define DLOPEN_NOTE_JSON						\
	"[{\"feature\":\"kmod\","					\
	"\"description\":\"Loading the nvme-fabrics module\","		\
	"\"priority\":\"suggested\","					\
	"\"soname\":[\"" LIBKMOD_SONAME "\"]}]"

static const struct {
	uint32_t n_namesz;
	uint32_t n_descsz;
	uint32_t n_type;
	char name[sizeof(DLOPEN_NOTE_OWNER)];
	char desc[sizeof(DLOPEN_NOTE_JSON)] __attribute__((aligned(4)));
} dlopen_note __attribute__((used, section(".note.dlopen"), aligned(4))) = {
	.n_namesz = sizeof(DLOPEN_NOTE_OWNER),
	.n_descsz = sizeof(DLOPEN_NOTE_JSON),
	.n_type = DLOPEN_NOTE_TYPE,
	.name = DLOPEN_NOTE_OWNER,
	.desc = DLOPEN_NOTE_JSON,
};

/*
 * Load libkmod once and keep it loaded.
 *
 * Return: 0 on success, -ENOTSUP when libkmod is not installed or lacks a
 * function.
 */
static int kmod_load(void)
{
	static int ret = 1;
	void *handle;
	size_t i;

	if (ret <= 0)
		return ret;

	ret = -ENOTSUP;
	handle = dlopen(LIBKMOD_SONAME, RTLD_NOW | RTLD_LOCAL);
	if (!handle)
		return ret;

	for (i = 0; i < ARRAY_SIZE(kmod_syms); i++) {
		*kmod_syms[i].ptr = dlsym(handle, kmod_syms[i].name);
		if (!*kmod_syms[i].ptr) {
			dlclose(handle);
			return ret;
		}
	}

	ret = 0;
	return ret;
}
#else
static int kmod_load(void)
{
	return 0;
}
#endif

static inline void cleanup_kmod_ctx(struct kmod_ctx **ctx)
{
	if (*ctx)
		kmod_unref(*ctx);
}
#define __cleanup_kmod_ctx __cleanup(cleanup_kmod_ctx)

static inline void cleanup_kmod_module(struct kmod_module **mod)
{
	if (*mod)
		kmod_module_unref(*mod);
}
#define __cleanup_kmod_module __cleanup(cleanup_kmod_module)

int shr_kmod_load_module(const char *name)
{
	__cleanup_kmod_ctx struct kmod_ctx *ctx = NULL;
	__cleanup_kmod_module struct kmod_module *mod = NULL;
	int timeout = 20; /* 2 seconds */
	int err, state;

	err = kmod_load();
	if (err)
		return err;

	ctx = kmod_new(NULL, NULL);
	if (!ctx)
		return -ENOTSUP;

	err = kmod_module_new_from_name(ctx, name, &mod);
	if (err)
		return err;

	state = kmod_module_get_initstate(mod);
	if (state == KMOD_MODULE_LIVE || state == KMOD_MODULE_BUILTIN)
		return 0;

	err = kmod_module_probe_insert_module(mod, KMOD_PROBE_APPLY_BLACKLIST,
					      NULL, NULL, NULL, NULL);
	if (err < 0)
		return err;
	/* The module is blacklisted. */
	if (err > 0)
		return -EPERM;

	while (timeout--) {
		state = kmod_module_get_initstate(mod);
		if (state == KMOD_MODULE_LIVE)
			return 0;

		/* 100 ms */
		usleep(100 * 1000);
	}

	return -ENOENT;
}
