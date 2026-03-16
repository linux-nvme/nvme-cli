#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# update-accessors.sh - Regenerate accessor files only when they change.
#
# This file is part of libnvme.
# Copyright (c) 2025, Dell Technologies Inc. or its subsidiaries.
# Authors: Martin Belanger <Martin.Belanger@dell.com>
#
# This script is invoked via: meson compile -C <build-dir> update-accessors
# It is NOT run during a normal build.
#
# accessors.h and accessors.c are updated automatically when the generator
# produces different output.
#
# accessors.ld is NOT updated automatically because its version section labels
# (e.g. LIBNVME_ACCESSORS_3) must be assigned by the maintainer.  Instead,
# this script reports which symbols have been added or removed so the maintainer
# knows exactly what to change in accessors.ld.
#
# Arguments (supplied by the Meson run_target):
#   $1      path to the compiled generate-accessors binary
#   $2      source directory for accessors.c and accessors.h (src/nvme/)
#   $3      source directory for accessors.ld (src/)
#   $4      path to generate-accessors-include.list
#   $5      path to generate-accessors-exclude.list
#   $6 ...  one or more input headers (wildcards are accepted)

set -euo pipefail

GENERATOR="${1:?missing generator binary}"
NVME_SRCDIR="${2:?missing nvme source directory}"
LD_SRCDIR="${3:?missing ld source directory}"
INCL_FILE="${4:?missing file generate-accessors-include.list}"
EXCL_FILE="${5:?missing file generate-accessors-exclude.list}"
shift 5
INPUT_HEADERS=("$@")
[ ${#INPUT_HEADERS[@]} -gt 0 ] || { echo "error: no input headers specified" >&2; exit 1; }

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

echo "Regenerating accessor files..."

"$GENERATOR" \
    --h-out  "$TMPDIR/accessors.h"  \
    --c-out  "$TMPDIR/accessors.c"  \
    --ld-out "$TMPDIR/accessors.ld" \
    --incl   "$INCL_FILE"           \
    --excl   "$EXCL_FILE"           \
    "${INPUT_HEADERS[@]}"

# ---------------------------------------------------------------------------
# Update accessors.h and accessors.c atomically when content changes.
# ---------------------------------------------------------------------------
changed=0
for f in accessors.h accessors.c; do
    dest="$NVME_SRCDIR/$f"
    if [ -f "$dest" ] && cmp -s "$TMPDIR/$f" "$dest"; then
        printf "  unchanged: %s\n" "$f"
    else
        # Write to a sibling temp file then rename for atomicity
        tmp_dest=$(mktemp "$NVME_SRCDIR/.${f}.XXXXXX")
        cp "$TMPDIR/$f" "$tmp_dest"
        mv -f "$tmp_dest" "$dest"
        printf "  updated:   %s\n" "$f"
        changed=$((changed + 1))
    fi
done

echo ""
if [ "$changed" -gt 0 ]; then
    printf "%d file(s) updated in %s\n" "$changed" "$NVME_SRCDIR"
    echo "Don't forget to commit the updated files."
else
    echo "All accessor source files are up to date."
fi

# ---------------------------------------------------------------------------
# Compare symbol lists to detect accessors.ld drift.
#
# accessors.ld is manually maintained because its version section labels
# (e.g. LIBNVME_ACCESSORS_3) must be assigned by a human.  We therefore
# only report what has changed; we never overwrite the file.
#
# Symbol lines in an ld version script look like:
#   <whitespace> symbol_name ;
# ---------------------------------------------------------------------------
extract_syms() {
    grep -E '^\s+[a-zA-Z_][a-zA-Z0-9_]*;' "$1" \
        | sed 's/[[:space:]]//g; s/;//' \
        | sort
}

extract_syms "$TMPDIR/accessors.ld"  > "$TMPDIR/syms_new.txt"
extract_syms "$LD_SRCDIR/accessors.ld"  > "$TMPDIR/syms_old.txt"

added=$(comm   -23 "$TMPDIR/syms_new.txt" "$TMPDIR/syms_old.txt")
removed=$(comm -13 "$TMPDIR/syms_new.txt" "$TMPDIR/syms_old.txt")

if [ -z "$added" ] && [ -z "$removed" ]; then
    echo "accessors.ld: symbol list is up to date."
else
    echo "WARNING: accessors.ld needs manual attention."
    echo ""
    if [ -n "$added" ]; then
        echo "  Symbols to ADD (place in a new version section, e.g. LIBNVME_ACCESSORS_X_Y):"
        printf '%s\n' "$added" | sed 's/^/    /'
    fi
    if [ -n "$removed" ]; then
        echo ""
        echo "  Symbols to REMOVE from accessors.ld:"
        printf '%s\n' "$removed" | sed 's/^/    /'
    fi
fi
