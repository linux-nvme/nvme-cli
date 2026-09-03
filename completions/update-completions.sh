#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (c) 2026 Micron Technology, Inc.
#
# update-completions.sh - Regenerate the committed shell completions from the
# built nvme binary, or (with --check) verify they are in sync.
#
# The completion files (bash-nvme-completion.sh, _nvme, nvme-completion.ps1)
# are pre-generated and committed to the source tree.  They are NOT
# regenerated during a normal build.
#
# Invoked via the Meson run_targets:
#   meson compile -C <build-dir> update-completions   (developer, updates files)
#   meson compile -C <build-dir> check-completions    (CI, read-only)
#
# In --check mode the script never modifies the source tree: it exits non-zero
# if any committed completion file differs from freshly generated output.
#
# Arguments (supplied by the Meson run_target):
#   $1  path to the built nvme binary
#   $2  path to the python3 interpreter
#   $3  path to generate-completions.py
#   $4  the completions source directory (holds the committed files)
#   [--check]  optional: CI mode; read-only, exit non-zero on drift

set -euo pipefail

NVME="${1:?missing nvme binary path}"
PYTHON="${2:?missing python3 interpreter}"
GENERATOR="${3:?missing generator script}"
SRCDIR="${4:?missing completions source dir}"
shift 4

CHECK_MODE=0
if [ "${1-}" = "--check" ]; then
    CHECK_MODE=1
    shift
fi

BASH_OUT="$SRCDIR/bash-nvme-completion.sh"
ZSH_OUT="$SRCDIR/_nvme"
PS_OUT="$SRCDIR/nvme-completion.ps1"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

TMP_BASH="$WORK/bash-nvme-completion.sh"
TMP_ZSH="$WORK/_nvme"
TMP_PS="$WORK/nvme-completion.ps1"

echo "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
echo "--- completions: begin generation ---"
echo ""

# The metadata dump lives in the "utils" plugin and needs json-c; the Meson
# target that calls this script is only defined when both are present.
if ! "$NVME" utils dump-command-metadata > "$WORK/metadata.json" 2> "$WORK/metadata.err"; then
    echo "error: 'nvme utils dump-command-metadata' failed; is nvme built with json-c?" >&2
    cat "$WORK/metadata.err" >&2
    exit 1
fi

"$PYTHON" "$GENERATOR" \
    --bash "$TMP_BASH" \
    --zsh "$TMP_ZSH" \
    --powershell "$TMP_PS" \
    < "$WORK/metadata.json"

# ---------------------------------------------------------------------------
# Helper: update a committed file atomically when content changes.
# ---------------------------------------------------------------------------
update_if_changed() {
    local src="$1"   # generated file in $WORK
    local dest="$2"  # committed file in the source tree

    if [ -f "$dest" ] && cmp -s "$src" "$dest"; then
        printf "  unchanged: %s\n" "$(basename "$dest")"
    else
        local tmp_dest
        tmp_dest=$(mktemp "$(dirname "$dest")/.$(basename "$dest").XXXXXX")
        cp "$src" "$tmp_dest"
        # mktemp creates 0600; mirror the existing file's mode so a regen
        # never perturbs it (0644 for a brand-new file).
        if [ -f "$dest" ]; then
            chmod --reference="$dest" "$tmp_dest"
        else
            chmod 0644 "$tmp_dest"
        fi
        mv -f "$tmp_dest" "$dest"
        printf "  updated:   %s\n" "$(basename "$dest")"
        CHANGED=$((CHANGED + 1))
    fi
}

# ---------------------------------------------------------------------------
# Helper (check mode): report whether a committed file is current.
# ---------------------------------------------------------------------------
check_if_current() {
    local src="$1"   # newly generated file in $WORK
    local dest="$2"  # committed file in the source tree

    if [ -f "$dest" ] && cmp -s "$src" "$dest"; then
        printf "  up to date: %s\n" "$(basename "$dest")"
    else
        printf "  STALE:      %s\n" "$(basename "$dest")"
        DRIFT=$((DRIFT + 1))
    fi
}

echo ""
if [ "$CHECK_MODE" -eq 1 ]; then
    DRIFT=0
    check_if_current "$TMP_BASH" "$BASH_OUT"
    check_if_current "$TMP_ZSH" "$ZSH_OUT"
    check_if_current "$TMP_PS" "$PS_OUT"
    echo ""
    if [ "$DRIFT" -gt 0 ]; then
        echo "ERROR: committed completions are out of sync with the nvme binary."
        echo "Run 'meson compile -C <build-dir> update-completions' and commit."
        echo ""
        echo "--- completions: check FAILED ---"
        echo "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
        exit 1
    fi
    echo "All committed completions are up to date."
else
    CHANGED=0
    update_if_changed "$TMP_BASH" "$BASH_OUT"
    update_if_changed "$TMP_ZSH" "$ZSH_OUT"
    update_if_changed "$TMP_PS" "$PS_OUT"
    echo ""
    if [ "$CHANGED" -gt 0 ]; then
        printf "%d file(s) updated in %s\n" "$CHANGED" "$SRCDIR"
        echo "Don't forget to commit the updated files."
    else
        echo "All completion files are up to date."
    fi
fi

echo ""
echo "--- completions: generation complete ---"
echo "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
