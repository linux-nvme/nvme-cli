/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 SUSE Software Solutions
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */
#pragma once

/*
 * Print @prompt and read a password from the terminal without echoing it,
 * like getpass(3). Falls back to reading a line from stdin when there is
 * no terminal.
 * Return: the password in a static buffer, overwritten by the next call,
 * or NULL on error or end of input.
 */
char *shr_getpass(const char *prompt);
