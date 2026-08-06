#!/bin/zsh
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (c) 2026 Micron Technology, Inc.
#
# Unit tests for the generated zsh completion (_nvme).
#
# zsh completion runs inside the completion system (_arguments, _values,
# _describe, compadd), which needs a live completion context we cannot create
# from a plain script. Instead we stub those builtins to CAPTURE what the
# completion would offer, then drive the real _nvme function with a simulated
# word array.

autoload -Uz compinit
compinit -u 2>/dev/null

source "${0:A:h}/_nvme"

RED=$'\033[0;31m'
GREEN=$'\033[0;32m'
NC=$'\033[0m'

TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

# ---------------------------------------------------------------------------
# Capture harness -- stub the zsh completion builtins the generated script
# calls so that, instead of talking to the completion system, they record what
# they were asked to offer. Each stub appends to $captured so a single command
# clause that offers both values and options is captured in full.
# ---------------------------------------------------------------------------
typeset -a captured
typeset -i saw_files

# _values '' v1 v2 ...  -> the candidate values (skip the leading spec arg).
_values() { shift; captured+=("$@"); }

# _describe -t TAG DESC VARNAME  -> the option list lives in the named array.
# Quote the (@P) expansion so each element is captured whole (no word-splitting
# on descriptions with spaces, no globbing).
_describe() {
    local varname=${@[-1]}
    captured+=("${(@P)varname}")
}

# compadd -- /dev/nvme*(N)  -> record the device-completion intent. The generated
# script's only compadd call is this device candidate, so any invocation means a
# device was offered. The (N) glob has already expanded by the time we are called:
# to a device list on a host with NVMe nodes, or to nothing on a host without --
# either way the completion asked for a device, so record it unconditionally.
compadd() {
    captured+=("/dev/nvme*")
}

# _files -> record that file completion was requested.
_files() { saw_files=1; }

# compset -> no-op; the real builtin adjusts the value prefix (e.g. strips
# '--opt=') before _files, which the capture harness does not model.
compset() { return 0; }

# The real `_arguments '*:: :->subcmds'` strips the command word and decrements
# CURRENT so the case statement sees the sub-command context. Emulate just that.
#
# LIMITATION: the real _arguments can return 0 and complete options itself,
# short-circuiting the code that follows it in each command clause. This stub
# always returns 1 (fall through) so the generated logic downstream is
# exercised. That means these tests verify our generator's routing and value
# lists, NOT that the real completion system renders them identically. Behavior
# that depends on the real _arguments (e.g. how option descriptions are
# displayed) must be spot-checked in a live shell or via zsh/zpty.
_arguments() {
    if [[ $1 == "*:: :->subcmds" ]]; then
        words=("${words[@]:1}")
        (( CURRENT-- ))
    fi
    return 1
}

# Drive _nvme against a command line, leaving the offered candidates in
# $captured and the file-fallback flag in $saw_files.
run_completion() {
    captured=()
    saw_files=0
    words=("${(z)1}")
    [[ $1 == *" " ]] && words+=("")
    CURRENT=${#words}
    _nvme
}

_check() {
    local ok=$1 desc=$2 detail=$3
    (( TESTS_RUN++ ))
    print ""
    print "TEST $TESTS_RUN: $desc"
    if (( ok == 0 )); then
        print "  ${GREEN}PASS${NC}: $detail"
        (( TESTS_PASSED++ ))
    else
        print "  ${RED}FAIL${NC}: $detail"
        (( TESTS_FAILED++ ))
    fi
}

# ---------------------------------------------------------------------------
# Assertions
# ---------------------------------------------------------------------------

# The completion offers something matching <pattern>.
expect_match() {
    local desc=$1 cmdline=$2 pattern=$3
    run_completion "$cmdline"
    local got="${captured[*]}"
    if [[ "$got" =~ $pattern ]]; then
        _check 0 "$desc" "'$cmdline<TAB>' -> '$got'"
    else
        _check 1 "$desc" "'$cmdline<TAB>' expected /$pattern/, got '$got'"
    fi
}

# The completion offers nothing matching <pattern>.
expect_no_match() {
    local desc=$1 cmdline=$2 pattern=$3
    run_completion "$cmdline"
    local got="${captured[*]}"
    if [[ "$got" =~ $pattern ]]; then
        _check 1 "$desc" "'$cmdline<TAB>' should not offer /$pattern/, got '$got'"
    else
        _check 0 "$desc" "'$cmdline<TAB>' -> '$got'"
    fi
}

# The completion offers a /dev/nvme* device candidate.
expect_device() {
    local desc=$1 cmdline=$2
    run_completion "$cmdline"
    if (( ${captured[(I)/dev/nvme*]} )); then
        _check 0 "$desc" "'$cmdline<TAB>' offered a device candidate"
    else
        _check 1 "$desc" "'$cmdline<TAB>' expected /dev/nvme*, got '${captured[*]}'"
    fi
}

# The completion does NOT offer a device candidate.
expect_no_device() {
    local desc=$1 cmdline=$2
    run_completion "$cmdline"
    if (( ${captured[(I)/dev/nvme*]} )); then
        _check 1 "$desc" "'$cmdline<TAB>' unexpectedly offered a device: '${captured[*]}'"
    else
        _check 0 "$desc" "'$cmdline<TAB>' offered no device"
    fi
}

# The completion offers file completion.
expect_files() {
    local desc=$1 cmdline=$2
    run_completion "$cmdline"
    if (( saw_files )); then
        _check 0 "$desc" "'$cmdline<TAB>' offered file completion"
    else
        _check 1 "$desc" "'$cmdline<TAB>' expected file completion, got '${captured[*]}'"
    fi
}

# The completion does NOT fall through to file completion.
expect_no_files() {
    local desc=$1 cmdline=$2
    run_completion "$cmdline"
    if (( saw_files )); then
        _check 1 "$desc" "'$cmdline<TAB>' unexpectedly fell through to _files"
    else
        _check 0 "$desc" "'$cmdline<TAB>' did not fall through to _files"
    fi
}

# The completion offers no candidates at all (no values, options, or files).
expect_nothing() {
    local desc=$1 cmdline=$2
    run_completion "$cmdline"
    if (( ${#captured} == 0 && saw_files == 0 )); then
        _check 0 "$desc" "'$cmdline<TAB>' offered nothing"
    else
        local files_note=""
        (( saw_files )) && files_note=" +files"
        _check 1 "$desc" "'$cmdline<TAB>' expected nothing, got '${captured[*]}'$files_note"
    fi
}

echo "========================================"
echo "Zsh Completion Tests"
echo "========================================"

# ---------------------------------------------------------------------------
# Top-level command dispatch
# ---------------------------------------------------------------------------
expect_match \
    "top-level list offers builtin commands" \
    "nvme " \
    "id-ctrl"

expect_match \
    "top-level list includes plugin names" \
    "nvme " \
    "feat"

expect_match \
    "top-level list includes the help built-in" \
    "nvme " \
    "help"

expect_match \
    "top-level list includes the version built-in" \
    "nvme " \
    "version"

# A command alias is listed alongside its primary name (fw-activate is an alias
# of fw-commit).
expect_match \
    "top-level list includes a command alias" \
    "nvme " \
    "fw-activate"

# A plugin lists its sub-commands.
expect_match \
    "a plugin lists its sub-commands" \
    "nvme feat " \
    "power-mgmt"

# A different plugin, to prove sub-command routing isn't hardcoded to one name.
expect_match \
    "sub-command routing works for any plugin" \
    "nvme zns " \
    "report-zones"

# A plugin sub-command alias is listed alongside its primary name (dera defines
# alias 'stat' for 'smart-log-add').
expect_match \
    "a plugin lists a sub-command alias" \
    "nvme dera " \
    "stat"

# ---------------------------------------------------------------------------
# Option-name completion
# ---------------------------------------------------------------------------
# Regression: builtin commands complete their options at the first option word.
# The dispatch once guarded on CURRENT > 2, so a builtin's first option (e.g.
# 'nvme id-ctrl -<TAB>', CURRENT == 2) fell through to file completion and
# offered nothing. Only plugin sub-command options (CURRENT >= 3) worked.
expect_match \
    "a builtin command offers its options at the first option word" \
    "nvme id-ctrl -" \
    "--output-format"

# A command invoked by its alias completes the same options (fw-activate is an
# alias of fw-commit).
expect_match \
    "a command invoked by its alias completes options" \
    "nvme fw-activate -" \
    "--action"

# -h/--help is offered for every command (added explicitly; it is not in the
# metadata option list).
expect_match \
    "--help is always offered" \
    "nvme id-ctrl -" \
    "--help"

# Global options are offered per command, straight from the metadata -- so a
# command that takes them gets them, and one that does not (intel
# lat-stats-tracking) is not wrongly offered them.
expect_match \
    "a command with global options offers them" \
    "nvme id-ctrl -" \
    "--output-format"

expect_no_match \
    "a command without global options is not offered them" \
    "nvme intel lat-stats-tracking -" \
    "--output-format"

# ---------------------------------------------------------------------------
# Option-value completion (enumerated values)
# ---------------------------------------------------------------------------
expect_match \
    "a value option lists its values (--opt= form)" \
    "nvme id-ctrl --output-format=" \
    "normal.*json.*binary.*tabular"

expect_match \
    "a value option lists its values (space form)" \
    "nvme id-ctrl --output-format " \
    "normal.*json.*binary.*tabular"

expect_match \
    "the short-option form lists the same values" \
    "nvme id-ctrl -o " \
    "normal.*json.*binary.*tabular"

# --sel values come from the generator's VALUE_HINTS table, reached through the
# plugin sub-command routing path.
expect_match \
    "an enumerated option on a plugin sub-command lists its values (--opt= form)" \
    "nvme feat power-meas --sel=" \
    "0.*1.*2.*3"

expect_match \
    "an enumerated option on a plugin sub-command lists its values (space form)" \
    "nvme feat power-meas --sel " \
    "0.*1.*2.*3"

expect_match \
    "an enumerated option on a plugin sub-command lists its values (short opt)" \
    "nvme feat power-meas -S " \
    "0.*1.*2.*3"

# A command-local enumerated option whose values come from the metadata
# (fw-commit --action has an OPT_VALS table).
expect_match \
    "a command-local enumerated option lists its metadata values" \
    "nvme fw-commit --action " \
    "replace.*set-active"

expect_match \
    "a command-local enumerated option lists its values (short opt)" \
    "nvme fw-commit -a " \
    "replace.*set-active"

# ---------------------------------------------------------------------------
# File-valued options (metavar FILE/DIRECTORY)
# ---------------------------------------------------------------------------
# A file-valued option completes filenames in both --opt val and --opt=val
# forms, and via its short spelling.
expect_files \
    "a file-valued option completes filenames (space form)" \
    "nvme fw-download --fw "

expect_files \
    "a file-valued option completes filenames (--opt= form)" \
    "nvme fw-download --fw="

expect_files \
    "a file-valued option completes filenames (short opt)" \
    "nvme fw-download -f "

# A non-file value option must NOT trigger file completion (it lists values).
expect_no_files \
    "an enumerated option does not offer files" \
    "nvme id-ctrl --output-format "

# ---------------------------------------------------------------------------
# Device-argument injection
# ---------------------------------------------------------------------------
expect_device \
    "a command that takes a device offers /dev/nvme*" \
    "nvme id-ctrl "

expect_device \
    "a plugin sub-command that takes a device offers /dev/nvme*" \
    "nvme feat power-meas "

# help and version never offer a device.
expect_no_device \
    "help takes no device" \
    "nvme help "

expect_no_device \
    "version takes no device" \
    "nvme version "

# ---------------------------------------------------------------------------
# help / version built-ins
# ---------------------------------------------------------------------------
# 'help CMD' prints CMD's help, so 'nvme help <TAB>' completes a command name
# (the same _cmds list offered at top level) rather than falling through to
# file completion.
expect_match \
    "help completes a command name" \
    "nvme help " \
    "id-ctrl"

expect_no_files \
    "help does not fall through to file completion" \
    "nvme help "

# 'help CMD' takes exactly one command argument, so nothing is offered past it
# (and it must not fall through to file completion).
expect_nothing \
    "help offers nothing past its one command argument" \
    "nvme help id-ctrl "

# 'version' takes no argument, so it offers nothing at all -- in particular it
# does not fall through to file completion.
expect_nothing \
    "version offers no completions" \
    "nvme version "

# Once a device is on the line the injection is suppressed (_nvme_has_device).
expect_no_device \
    "a device already on the line is not offered again" \
    "nvme id-ctrl /dev/nvme0 "

# ---------------------------------------------------------------------------
# Generated-output assertions
# ---------------------------------------------------------------------------
# _nvme is a generated artifact, so its text is a legitimate thing to test: the
# generator must not tag the option groups with the reserved 'options' tag.
# Alongside the device candidate, the completion system suppresses that tag's
# group at an empty prefix, so '--help' etc. rendered only after a '-' was
# typed. The live rendering is what breaks, but the stubbed harness above cannot
# observe it -- the enforceable generator contract is "don't emit that tag".
(( TESTS_RUN++ ))
print ""
print "TEST $TESTS_RUN: option groups avoid the reserved 'options' tag"
if grep -Eq $'_describe -t options|_describe -t eq-options' "${0:A:h}/_nvme"; then
    print "  ${RED}FAIL${NC}: _nvme uses the reserved 'options'/'eq-options' tag"
    (( TESTS_FAILED++ ))
else
    print "  ${GREEN}PASS${NC}: no reserved option tag in _nvme"
    (( TESTS_PASSED++ ))
fi

echo ""
echo "========================================"
echo "Results: $TESTS_PASSED/$TESTS_RUN passed"
if (( TESTS_FAILED > 0 )); then
    echo "${RED}$TESTS_FAILED tests failed${NC}"
    exit 1
else
    echo "${GREEN}All tests passed${NC}"
    exit 0
fi
