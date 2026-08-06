/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * This file is part of nvme-cli.
 */
#pragma once

#define SHR_ABSOLUTE_ZERO_CELSIUS -273

static inline long shr_kelvin_to_celsius(long t)
{
	return t + SHR_ABSOLUTE_ZERO_CELSIUS;
}

static inline long shr_celsius_to_fahrenheit(long t)
{
	return t * 9 / 5 + 32;
}

static inline long shr_kelvin_to_fahrenheit(long t)
{
	return shr_celsius_to_fahrenheit(shr_kelvin_to_celsius(t));
}
