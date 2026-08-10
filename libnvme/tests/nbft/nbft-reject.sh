#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later

"$1" "$2"
status=$?

test "$status" -eq 2
