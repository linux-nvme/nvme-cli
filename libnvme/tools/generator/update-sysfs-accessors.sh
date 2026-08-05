#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# update-sysfs-accessors.sh - Regenerate every spec in
# sysfs_accessors_specs.py's SYSFS_SPECS list (.h/.c/.i per spec, one, two,
# or three .c files depending on whether it has per-OS-divergent members)
# only when they change; report .ld symbol drift instead of rewriting it.
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
# This script does not know any spec's name or output filenames -- it
# just diffs whatever generate_sysfs_accessors.py actually wrote into a
# scratch directory against the same-named file in the source tree, by
# extension: .h/.c auto-update, .i auto-updates, .ld is diffed and
# reported but never rewritten (which version section a symbol belongs
# to is a maintainer decision, same as accessors.ld/accessors-fabrics.ld).
# Adding a spec to SYSFS_SPECS therefore needs no change here.
#
# Arguments (supplied by the Meson run_target):
#   $1   path to the python3 interpreter
#   $2   path to generate_sysfs_accessors.py
#   $3   path to sysfs_accessors_specs.py (SYSFS_SPECS input)
#   $4   output directory for every spec's .h/.c files
#   $5   output directory for every spec's .ld file
#   $6   output directory for every spec's .i file
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
    ld_name=$(basename "$new_ld")

    extract_syms "$new_ld" > "$TMPDIR_WORK/syms_new.txt"
    if [ -f "$old_ld" ]; then
        extract_syms "$old_ld" > "$TMPDIR_WORK/syms_old.txt"
    else
        : > "$TMPDIR_WORK/syms_old.txt"
    fi

    local added removed
    added=$(comm  -23 "$TMPDIR_WORK/syms_new.txt" "$TMPDIR_WORK/syms_old.txt")
    removed=$(comm -13 "$TMPDIR_WORK/syms_new.txt" "$TMPDIR_WORK/syms_old.txt")

    if [ -z "$added" ] && [ -z "$removed" ]; then
        echo "${ld_name}: symbol list is up to date."
        return 0
    fi

    if [ ! -f "$old_ld" ]; then
        echo "WARNING: $ld_name does not exist yet."
        echo ""
        echo "  This is a new spec's first .ld file -- create it by hand"
        echo "  with a top-level version-script tag matching the spec's"
        echo "  ld_section, listing every symbol below:"
        printf '%s\n' "$added" | sed 's/^/\t\t/' | sed 's/$/;/'
        return 1
    fi

    echo "WARNING: $(realpath --relative-to=.. "$old_ld") needs manual" \
         "attention."
    echo ""
    if [ -n "$added" ]; then
        echo "  Symbols to ADD (existing version section pre-3.0; a new"
        echo "  chained section after a stable release):"
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
# Run generator into the scratch directory -- one run generates every spec
# in SYSFS_SPECS.
# ---------------------------------------------------------------------------
echo "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
echo "--- sysfs-accessors: begin generation ---"
echo ""

"$PYTHON" "$GENERATOR" --specs "$SPECS" --out-dir "$TMPDIR_WORK" \
	--ld-out-dir "$TMPDIR_WORK" --swig-out-dir "$TMPDIR_WORK" >/dev/null

if [ "$CHECK_MODE" -eq 1 ]; then
    # ------------------------------------------------------------------
    # Check mode: read-only.  Report all drift, then exit non-zero if
    # anything is out of sync.
    # ------------------------------------------------------------------
    DRIFT=0
    for f in "$TMPDIR_WORK"/*.h "$TMPDIR_WORK"/*.c; do
        [ -e "$f" ] || continue
        check_if_current "$f" "$OUT_DIR/$(basename "$f")"
    done
    for f in "$TMPDIR_WORK"/*.i; do
        [ -e "$f" ] || continue
        check_if_current "$f" "$SWIG_OUT_DIR/$(basename "$f")"
    done
    echo ""
    for f in "$TMPDIR_WORK"/*.ld; do
        [ -e "$f" ] || continue
        check_ld_drift "$f" "$LD_OUT_DIR/$(basename "$f")" \
            || DRIFT=$((DRIFT + 1))
    done
    echo ""
    if [ "$DRIFT" -gt 0 ]; then
        echo "ERROR: generated files are out of sync with the source."
        echo "Run 'meson compile -C <build-dir> update-accessors' and commit."
        echo "(.ld symbol changes require manual version-script edits;" \
             "see WARNING above.)"
        echo ""
        echo "--- sysfs-accessors: check FAILED ---"
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
    for f in "$TMPDIR_WORK"/*.h "$TMPDIR_WORK"/*.c; do
        [ -e "$f" ] || continue
        update_if_changed "$f" "$OUT_DIR/$(basename "$f")"
    done
    for f in "$TMPDIR_WORK"/*.i; do
        [ -e "$f" ] || continue
        update_if_changed "$f" "$SWIG_OUT_DIR/$(basename "$f")"
    done
    echo ""
    if [ "$CHANGED" -gt 0 ]; then
        printf "%d file(s) updated in %s\n" "$CHANGED" "$OUT_DIR"
        echo "Don't forget to commit the updated files."
    else
        echo "All sysfs-accessor source files are up to date."
    fi
    echo ""
    for f in "$TMPDIR_WORK"/*.ld; do
        [ -e "$f" ] || continue
        check_ld_drift "$f" "$LD_OUT_DIR/$(basename "$f")" || true
    done
fi

echo ""
echo "--- sysfs-accessors: generation complete ---"
echo "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
echo ""
