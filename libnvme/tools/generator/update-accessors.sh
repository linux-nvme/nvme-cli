#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# update-accessors.sh - Regenerate accessor files only when they change.
#
# This file is part of libnvme.
# Copyright (c) 2025, Dell Technologies Inc. or its subsidiaries.
# Authors: Martin Belanger <Martin.Belanger@dell.com>
#
# Invoked via:
#   meson compile -C <build-dir> update-accessors   (developer, updates files)
#   meson compile -C <build-dir> check-accessors    (CI, read-only)
#
# It is NOT run during a normal build.
#
# The .h, .c, and .i files are updated automatically when the generator
# produces different output.
#
# The .ld file is NOT updated automatically because its version section
# label (e.g. LIBNVME_ACCESSORS_3, LIBNVMF_ACCESSORS_3) must be assigned by
# the maintainer.  Instead, this script reports which symbols have been added
# or removed so the maintainer knows exactly what to change.
#
# With --check (used by CI), the script is read-only: it never modifies the
# source tree.  It exits non-zero if any .h/.c/.i file is out of date or if
# the .ld symbol list has drifted.
#
# Arguments (supplied by the Meson run_target):
#   $1             path to the python3 interpreter
#   $2             path to generate-accessors.py
#   $3             full path of the output .h file
#   $4             full path of the output .c file
#   $5             full path of the output .ld file
#   [--check]      optional: CI mode — read-only, exit non-zero on any drift
#   [--swig-out F] optional: full path of the output SWIG fragment (.i file)
#   $6 (or $8) ... one or more input headers scanned for
#                  // !generate-accessors and // !generate-python structs

set -euo pipefail

PYTHON="${1:?missing python3 interpreter}"
GENERATOR="${2:?missing generator script}"
H_OUT="${3:?missing .h output path}"
C_OUT="${4:?missing .c output path}"
LD_OUT="${5:?missing .ld output path}"
shift 5

CHECK_MODE=0
if [ "${1-}" = "--check" ]; then
    CHECK_MODE=1
    shift
fi

SWIG_OUT=""
if [ "${1-}" = "--swig-out" ]; then
    SWIG_OUT="${2:?--swig-out requires a path argument}"
    shift 2
fi

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
TMP_I="$TMPDIR_WORK/${BASE}.i"

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
# Sets DRIFT to a non-zero value if the file is stale.
# ---------------------------------------------------------------------------
check_if_current() {
    local src="$1"   # newly generated file in TMPDIR_WORK
    local dest="$2"  # committed file in the source tree

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

    echo "WARNING: $(realpath --relative-to=.. "$old_ld") needs manual attention."
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
    return 1
}

# ---------------------------------------------------------------------------
# Run generator
# ---------------------------------------------------------------------------
echo "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
echo "--- ${BASE}: begin generation ---"
echo ""

SWIG_ARGS=()
[ -n "$SWIG_OUT" ] && SWIG_ARGS=(--swig-out "$TMP_I")

"$PYTHON" "$GENERATOR" \
    --h-out  "$TMP_H"  \
    --c-out  "$TMP_C"  \
    --ld-out "$TMP_LD" \
    "${SWIG_ARGS[@]}"  \
    "$@"

if [ "$CHECK_MODE" -eq 1 ]; then
    # ------------------------------------------------------------------
    # Check mode: read-only.  Report all drift, then exit non-zero if
    # anything is out of sync.
    # ------------------------------------------------------------------
    DRIFT=0
    check_if_current "$TMP_H" "$H_OUT"
    check_if_current "$TMP_C" "$C_OUT"
    [ -n "$SWIG_OUT" ] && check_if_current "$TMP_I" "$SWIG_OUT"
    echo ""
    check_ld_drift "$TMP_LD" "$LD_OUT" || DRIFT=$((DRIFT + 1))
    echo ""
    if [ "$DRIFT" -gt 0 ]; then
        echo "ERROR: generated files are out of sync with the source."
        echo "Run 'meson compile -C <build-dir> update-accessors' and commit."
        echo "(.ld symbol changes require manual version-script edits; see WARNING above.)"
        echo ""
        echo "--- ${BASE}: check FAILED ---"
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
    [ -n "$SWIG_OUT" ] && update_if_changed "$TMP_I" "$SWIG_OUT"
    echo ""
    if [ "$CHANGED" -gt 0 ]; then
        printf "%d file(s) updated in %s\n" "$CHANGED" "$(dirname "$H_OUT")"
        echo "Don't forget to commit the updated files."
    else
        echo "All accessor source files are up to date."
    fi
    echo ""
    check_ld_drift "$TMP_LD" "$LD_OUT" || true
fi

echo ""
echo "--- ${BASE}: generation complete ---"
echo "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
echo ""
