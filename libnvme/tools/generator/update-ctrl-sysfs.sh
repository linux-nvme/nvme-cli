#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# update-ctrl-sysfs.sh - Regenerate ctrl-sysfs.{h,c,i} only when they change;
# report ctrl-sysfs.ld symbol drift instead of rewriting it.
#
# This file is part of libnvme.
# Copyright (c) 2026, Dell Technologies Inc. or its subsidiaries.
# Authors: Martin Belanger <Martin.Belanger@dell.com>
#
# Invoked via:
#   meson compile -C <build-dir> update-accessors   (developer, updates files)
#   meson compile -C <build-dir> update-accessors   (CI, read-only:
#                                                     configure with
#                                                     -Dcheck-accessors=true)
#
# It is NOT run during a normal build.
#
# Which version section a new symbol belongs to is a maintainer decision,
# so ctrl-sysfs.ld is handled the same way as accessors.ld/
# accessors-fabrics.ld: it is never rewritten automatically.
# The generator runs into a scratch directory; .h/.c/.i are copied into the
# tree when they differ, and .ld is only diffed, symbol by symbol.
#
# Arguments (supplied by the Meson run_target):
#   $1   path to the python3 interpreter
#   $2   path to generate_sysfs_accessors.py
#   $3   path to sysfs_accessors_specs.py (CTRL_SYSFS input)
#   $4   output directory for ctrl-sysfs.h/.c
#   $5   output directory for ctrl-sysfs.ld
#   $6   output directory for ctrl-sysfs.i
#   [--check]   optional: CI mode; read-only, exit non-zero on drift

set -euo pipefail

PYTHON="${1:?missing python3 interpreter}"
GENERATOR="${2:?missing generator script}"
SPECS="${3:?missing sysfs_accessors_specs.py path}"
OUT_DIR="${4:?missing output directory}"
LD_OUT_DIR="${5:?missing ld output directory}"
SWIG_OUT_DIR="${6:?missing swig output directory}"
shift 6

CHECK_MODE=0
if [ "${1-}" = "--check" ]; then
    CHECK_MODE=1
    shift
fi

H_OUT="$OUT_DIR/ctrl-sysfs.h"
C_OUT="$OUT_DIR/ctrl-sysfs.c"
LD_OUT="$LD_OUT_DIR/ctrl-sysfs.ld"
I_OUT="$SWIG_OUT_DIR/ctrl-sysfs.i"

TMPDIR_WORK=$(mktemp -d)
trap 'rm -rf "$TMPDIR_WORK"' EXIT

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
# Helper (check mode): report whether a source file is current.
# ---------------------------------------------------------------------------
check_if_current() {
    local src="$1"
    local dest="$2"

    if [ -f "$dest" ] && cmp -s "$src" "$dest"; then
        printf "  up to date: %s\n" "$(basename "$dest")"
    else
        printf "  STALE:      %s\n" "$(basename "$dest")"
        DRIFT=$((DRIFT + 1))
    fi
}

# ---------------------------------------------------------------------------
# Helper: compare symbol lists and report ld drift.
# Returns 1 if drift is detected, 0 if the symbol list is current.
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
        return 0
    fi

    echo "WARNING: $(realpath --relative-to=.. "$old_ld") needs manual" \
         "attention."
    echo ""
    if [ -n "$added" ]; then
        echo "  Symbols to ADD to LIBNVME_CTRL_SYSFS_3 (pre-3.0: existing"
        echo "  section; after a stable release: new chained section, e.g."
        echo "  LIBNVME_CTRL_SYSFS_3_1):"
        printf '%s\n' "$added" | sed 's/^/\t\t/' | sed 's/$/;/'
    fi
    if [ -n "$removed" ]; then
        echo ""
        echo "  Symbols to REMOVE from ${ld_name}:"
        printf '%s\n' "$removed" | sed 's/^/    /'
    fi
    return 1
}

# ---------------------------------------------------------------------------
# Run generator into the scratch directory
# ---------------------------------------------------------------------------
echo "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
echo "--- ctrl-sysfs: begin generation ---"
echo ""

"$PYTHON" "$GENERATOR" --specs "$SPECS" --out-dir "$TMPDIR_WORK" \
	--ld-out-dir "$TMPDIR_WORK" --swig-out-dir "$TMPDIR_WORK" >/dev/null

TMP_H="$TMPDIR_WORK/ctrl-sysfs.h"
TMP_C="$TMPDIR_WORK/ctrl-sysfs.c"
TMP_LD="$TMPDIR_WORK/ctrl-sysfs.ld"
TMP_I="$TMPDIR_WORK/ctrl-sysfs.i"

if [ "$CHECK_MODE" -eq 1 ]; then
    # ------------------------------------------------------------------
    # Check mode: read-only.  Report all drift, then exit non-zero if
    # anything is out of sync.
    # ------------------------------------------------------------------
    DRIFT=0
    check_if_current "$TMP_H" "$H_OUT"
    check_if_current "$TMP_C" "$C_OUT"
    check_if_current "$TMP_I" "$I_OUT"
    echo ""
    check_ld_drift "$TMP_LD" "$LD_OUT" || DRIFT=$((DRIFT + 1))
    echo ""
    if [ "$DRIFT" -gt 0 ]; then
        echo "ERROR: generated files are out of sync with the source."
        echo "Run 'meson compile -C <build-dir> update-accessors' and commit."
        echo "(.ld symbol changes require manual version-script edits;" \
             "see WARNING above.)"
        echo ""
        echo "--- ctrl-sysfs: check FAILED ---"
        echo "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
        echo ""
        exit 1
    fi
    echo "All generated files are up to date."
else
    # ------------------------------------------------------------------
    # Update mode: auto-update .h/.c/.i; report .ld drift as advisory.
    # ------------------------------------------------------------------
    CHANGED=0
    update_if_changed "$TMP_H" "$H_OUT"
    update_if_changed "$TMP_C" "$C_OUT"
    update_if_changed "$TMP_I" "$I_OUT"
    echo ""
    if [ "$CHANGED" -gt 0 ]; then
        printf "%d file(s) updated in %s\n" "$CHANGED" "$OUT_DIR"
        echo "Don't forget to commit the updated files."
    else
        echo "All ctrl-sysfs source files are up to date."
    fi
    echo ""
    check_ld_drift "$TMP_LD" "$LD_OUT" || true
fi

echo ""
echo "--- ctrl-sysfs: generation complete ---"
echo "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
echo ""
