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
# The .h and .c files are updated automatically when the generator produces
# different output.
#
# The .ld file is NOT updated automatically because its version section
# label (e.g. LIBNVME_ACCESSORS_3, LIBNVMF_ACCESSORS_3) must be assigned by
# the maintainer.  Instead, this script reports which symbols have been added
# or removed so the maintainer knows exactly what to change.
#
# Arguments (supplied by the Meson run_target):
#   $1      path to the python3 interpreter
#   $2      path to generate-accessors.py
#   $3      full path of the output .h file
#   $4      full path of the output .c file
#   $5      full path of the output .ld file
#   $6 ...  one or more input headers scanned for
#           //!generate-accessors structs

set -euo pipefail

PYTHON="${1:?missing python3 interpreter}"
GENERATOR="${2:?missing generator script}"
H_OUT="${3:?missing .h output path}"
C_OUT="${4:?missing .c output path}"
LD_OUT="${5:?missing .ld output path}"
shift 5

if [ $# -eq 0 ]; then
    echo "error: no input headers provided" >&2
    exit 1
fi

TMPDIR_WORK=$(mktemp -d)
trap 'rm -rf "$TMPDIR_WORK"' EXIT

LABEL=$(basename "$H_OUT")   # e.g. "accessors.h" or "nvmf-accessors.h"
BASE="${LABEL%.h}"            # e.g. "accessors"    or "nvmf-accessors"

TMP_H="$TMPDIR_WORK/${BASE}.h"
TMP_C="$TMPDIR_WORK/${BASE}.c"
TMP_LD="$TMPDIR_WORK/${BASE}.ld"

# ---------------------------------------------------------------------------
# Helper: update a source file atomically when content changes.
# ---------------------------------------------------------------------------
update_if_changed() {
    local src="$1"   # generated file in TMPDIR_WORK
    local dest="$2"  # target path in the source tree

    if [ -f "$dest" ] && cmp -s "$src" "$dest"; then
        printf "  unchanged: %s\n" "$(basename "$dest")"
    else
        local tmp_dest
        tmp_dest=$(mktemp "$(dirname "$dest")/.$(basename "$dest").XXXXXX")
        cp "$src" "$tmp_dest"
        mv -f "$tmp_dest" "$dest"
        printf "  updated:   %s\n" "$(basename "$dest")"
        CHANGED=$((CHANGED + 1))
    fi
}

# ---------------------------------------------------------------------------
# Helper: compare symbol lists and report ld drift.
# ---------------------------------------------------------------------------
extract_syms() {
    grep -E '^\s+[a-zA-Z_][a-zA-Z0-9_]*;' "$1" \
        | sed 's/[[:space:]]//g; s/;//' \
        | sort
}

check_ld_drift() {
    local new_ld="$1"
    local old_ld="$2"
    local ld_name
    ld_name=$(basename "$old_ld")

    extract_syms "$new_ld" > "$TMPDIR_WORK/syms_new.txt"
    extract_syms "$old_ld" > "$TMPDIR_WORK/syms_old.txt"

    local added removed
    added=$(comm  -23 "$TMPDIR_WORK/syms_new.txt" "$TMPDIR_WORK/syms_old.txt")
    removed=$(comm -13 "$TMPDIR_WORK/syms_new.txt" "$TMPDIR_WORK/syms_old.txt")

    if [ -z "$added" ] && [ -z "$removed" ]; then
        echo "${ld_name}: symbol list is up to date."
    else
        echo "WARNING: $(realpath --relative-to=.. ${old_ld}) needs manual attention."
        echo ""
        if [ -n "$added" ]; then
            echo "  Symbols to ADD (new version section, e.g. <PREFIX>_ACCESSORS_X_Y):"
            printf '%s\n' "$added" | sed 's/^/\t\t/' | sed 's/$/;/'
        fi
        if [ -n "$removed" ]; then
            echo ""
            echo "  Symbols to REMOVE from ${ld_name}:"
            printf '%s\n' "$removed" | sed 's/^/    /'
        fi
    fi
}

# ---------------------------------------------------------------------------
# Run generator
# ---------------------------------------------------------------------------
echo "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
echo "--- ${BASE}: begin generation ---"
echo ""
"$PYTHON" "$GENERATOR" \
    --h-out  "$TMP_H"  \
    --c-out  "$TMP_C"  \
    --ld-out "$TMP_LD" \
    "$@"

CHANGED=0
update_if_changed "$TMP_H" "$H_OUT"
update_if_changed "$TMP_C" "$C_OUT"
echo ""
if [ "$CHANGED" -gt 0 ]; then
    printf "%d file(s) updated in %s\n" "$CHANGED" "$(dirname "$H_OUT")"
    echo "Don't forget to commit the updated files."
else
    echo "All accessor source files are up to date."
fi
echo ""
check_ld_drift "$TMP_LD" "$LD_OUT"
echo ""
echo "--- ${BASE}: generation complete ---"
echo "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
echo ""
