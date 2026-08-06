/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * This file is part of nvme-cli.
 */
#pragma once

#include <stdio.h>

/*
 * Print a progress spinner to stream, e.g. for label "LogDump" and
 * percent 0.5:
 *
 *   LogDump [========================-                         ]  50%
 *
 * percent is clamped to [0, 1.0]. Intended to be called repeatedly (each
 * call overwrites the previous line via '\r').
 */
void shr_spinner(const char *label, float percent, FILE *stream);
