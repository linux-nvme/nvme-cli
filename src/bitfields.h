/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 SUSE LLC
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */
#pragma once

#include <stddef.h>
#include <stdint.h>

/*
 * A field of bits in a value of up to 64 bits, like a field of a
 * register: its name, where it is and how to show it. A table of them
 * describes a value, which bitfield_str() decodes field by field for any
 * output format.
 */

enum bitfield_fmt {
	BF_DEC,		/* the value in decimal */
	BF_DEC1,	/* a 0's based count: the value + 1 */
	BF_HEX,		/* the value in hex */
	BF_ADDR,	/* an address: the field in place, in hex */
	BF_YESNO,	/* a bit: "Yes" or "No" */
	BF_SUPPORTED,	/* a bit: "Supported" or "Not Supported" */
	BF_ENABLED,	/* a bit: "Enabled" or "Disabled" */
	BF_STR,		/* a name from @strs, "Reserved" past it */
	BF_POW2,	/* 2 ^ (@arg + value) bytes */
	BF_MS500,	/* a time in 500 millisecond units, in ms */
};

struct bitfield {
	const char *name;
	uint8_t shift;
	uint64_t mask;			/* of the field, shifted to bit 0 */
	enum bitfield_fmt fmt;
	unsigned int arg;		/* BF_POW2: the exponent of 0 */
	const char * const *strs;	/* BF_STR: by value */
	unsigned int nr_strs;
};

#define BITFIELD(_name, _shift, _mask, _fmt)				\
	{ .name = (_name), .shift = (_shift), .mask = (_mask),		\
	  .fmt = (_fmt) }

#define BITFIELD_POW2(_name, _shift, _mask, _exp)			\
	{ .name = (_name), .shift = (_shift), .mask = (_mask),		\
	  .fmt = BF_POW2, .arg = (_exp) }

#define BITFIELD_STR(_name, _shift, _mask, _strs)			\
	{ .name = (_name), .shift = (_shift), .mask = (_mask),		\
	  .fmt = BF_STR, .strs = (_strs),				\
	  .nr_strs = sizeof(_strs) / sizeof((_strs)[0]) }

/* The field @f of @value, shifted to bit 0 */
static inline uint64_t bitfield_get(const struct bitfield *f, uint64_t value)
{
	return (value >> f->shift) & f->mask;
}

/*
 * Writes the field @f of @value, decoded, into @buf of @len bytes.
 * Return: the length of the text, like snprintf(), which truncates it to
 * fit @buf.
 */
int bitfield_str(const struct bitfield *f, uint64_t value, char *buf,
		 size_t len);
