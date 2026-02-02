/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Platform compatibility for linux/types.h
 */
#ifndef _PLATFORM_TYPES_H
#define _PLATFORM_TYPES_H

#ifdef _WIN32

#include <stdint.h>

/* Windows type definitions to replace linux/types.h */
typedef uint8_t  __u8;
typedef uint16_t __u16;
typedef uint32_t __u32;
typedef uint64_t __u64;
typedef int8_t   __s8;
typedef int16_t  __s16;
typedef int32_t  __s32;
typedef int64_t  __s64;

/* Little-endian types (Windows is little-endian) */
typedef __u16    __le16;
typedef __u32    __le32;
typedef __u64    __le64;
typedef __s16    __le16s;
typedef __s32    __le32s;
typedef __s64    __le64s;

/* Big-endian types for completeness */
typedef __u16    __be16;
typedef __u32    __be32;
typedef __u64    __be64;
typedef __s16    __be16s;
typedef __s32    __be32s;
typedef __s64    __be64s;

#else

#include <linux/types.h>

#endif

#endif /* _PLATFORM_TYPES_H */
