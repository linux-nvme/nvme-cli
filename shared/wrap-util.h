/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 SUSE Software Solutions
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */
#pragma once

#include <stdio.h>

/*
 * Print s to stream, word-wrapping at 76 columns and indenting every
 * wrapped line by indent spaces. start is the current column the cursor
 * is already at (e.g. after printing a label before the text).
 */
void shr_print_word_wrapped(const char *s, int indent, int start, FILE *stream);
