#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Run the semantic patches in scripts/coccinelle/ and print what they
# find. Exit 1 if there is anything: new code should use the helper the
# rule names. A rule with a fix shows it as a diff. A rule that only
# reports marks the lines it found with '-'.
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

# Each rule has a test. A rule with a fix must turn tests/<rule>.c into
# tests/<rule>.res. A rule that only reports must print tests/<rule>.out,
# without the file names and trailing whitespace.
for rule in scripts/coccinelle/*.cocci; do
	name=$(basename "$rule" .cocci)
	test=scripts/coccinelle/tests/$name
	if [ -f "$test.res" ]; then
		spatch --very-quiet --sp-file "$rule" "$test.c" -o "$res" \
			>/dev/null
		expected=$test.res
	else
		spatch --very-quiet --sp-file "$rule" "$test.c" | \
			grep -v -e '^---' -e '^+++' | sed 's/[[:space:]]*$//' \
			> "$res"
		expected=$test.out
	fi
	if ! diff -u "$expected" "$res"; then
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
echo "coccicheck: change the code above. 'make coccicheck-fix' applies" \
	"the rules that have a fix." >&2
exit 1
