#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Run the semantic patches in scripts/coccinelle/ and print the changes
# they would make. Exit 1 if there is any: new code should use the
# helper the rule names.
#
# Usage: $0 [--fix]  (or: make coccicheck, make coccicheck-fix)
#   --fix  apply the changes to the source tree

set -e

cd "$(dirname "$0")/.."

if ! command -v spatch >/dev/null 2>&1; then
	echo "coccicheck: spatch not found, install coccinelle" >&2
	exit 2
fi

mode=""
if [ "$1" = "--fix" ]; then
	mode="--in-place"
fi

dirs="libnvme/src src discoverd/src keysd/src shared daemon-util"
out=$(mktemp)
res=$(mktemp)
trap 'rm -f "$out" "$res"' EXIT

# Each rule has a test: tests/<rule>.c must turn into tests/<rule>.res.
for rule in scripts/coccinelle/*.cocci; do
	name=$(basename "$rule" .cocci)
	test=scripts/coccinelle/tests/$name.c
	spatch --very-quiet --sp-file "$rule" "$test" -o "$res" >/dev/null
	if ! diff -u "scripts/coccinelle/tests/$name.res" "$res"; then
		echo "coccicheck: $rule fails its test" >&2
		exit 2
	fi
done

# One file per group (groups are separated by a blank line). Tests and
# generated files are left out.
groups=$(mktemp)
trap 'rm -f "$out" "$res" "$groups"' EXIT
git ls-files -- $dirs | grep '\.c$' | grep -v -e '/tests/' -e '/generated/' | \
	awk '{ print; print "" }' > "$groups"

for rule in scripts/coccinelle/*.cocci; do
	spatch --very-quiet $mode --sp-file "$rule" --file-groups "$groups" \
		-I . -I libnvme/src -I ccan >> "$out"
done

if [ -n "$mode" ] || [ ! -s "$out" ]; then
	exit 0
fi

cat "$out"
echo "coccicheck: apply the changes above (make coccicheck-fix)" >&2
exit 1
