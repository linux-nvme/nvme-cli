#!/bin/bash
# SPDX-License-Identifier: LGPL-2.1-or-later

file=$1

# kernel-doc takes the identifier from the line after '/**'. Plain '/*'
# comments, e.g. on opaque structs, have no page.
sed -n '\|^/\*\*$|{n;p}' "$file" |
	sed -n -e 's/^ \* \([a-z_][a-z_0-9]*\)() -.*/\1/p' \
	       -e 's/^ \* \(struct\|enum\) \([a-z_][a-z_0-9]*\) -.*/\2/p'
