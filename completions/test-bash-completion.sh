#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Unit tests for the generated bash completion (bash-nvme-completion.sh).
#
# Every test drives the real completion entry point, _nvme_subcmds, the same way
# bash does: populate COMP_WORDS/COMP_CWORD, invoke the dispatcher, then inspect
# the resulting COMPREPLY and any compopt requests. Tests never call the
# per-command opts functions directly -- routing to the correct builtin or
# plugin handler is itself part of what we verify.

# Programmable completion may be off in a non-interactive shell; the sourced
# script's `complete` call needs it on to register without error.
shopt -s progcomp

source "$(dirname "$0")/bash-nvme-completion.sh"

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

# ---------------------------------------------------------------------------
# Test harness
# ---------------------------------------------------------------------------

# Split a command line into a COMP_WORDS-style array, treating '=' as its own
# word (bash keeps '=' in COMP_WORDBREAKS). Appends an empty trailing word when
# the line ends in a space or '=', matching what bash presents mid-completion.
# Result is left in the caller's `words` array.
parse_words() {
    local cmdline="$1"
    words=()
    local current_word="" char i
    for (( i=0; i<${#cmdline}; i++ )); do
        char="${cmdline:$i:1}"
        if [[ "$char" == "=" ]]; then
            [[ -n "$current_word" ]] && words+=("$current_word")
            words+=("=")
            current_word=""
        elif [[ "$char" == " " || "$char" == $'\t' ]]; then
            [[ -n "$current_word" ]] && words+=("$current_word")
            current_word=""
        else
            current_word+="$char"
        fi
    done
    [[ -n "$current_word" ]] && words+=("$current_word")

    if [[ "$cmdline" == *" " ]] || [[ "$cmdline" == *"=" ]]; then
        words+=("")
    fi
}

# _nvme_subcmds calls _init_completion to populate its cur/prev/words/cword
# locals, but the bash-completion package only provides that function in
# interactive shells. Stub it here to set those same variables from the
# COMP_WORDS/COMP_CWORD we set up per test. The stub can assign _nvme_subcmds'
# locals because bash uses dynamic scoping: a function sees the local variables
# of the function that called it.
_init_completion() {
    words=("${COMP_WORDS[@]}")
    cword=$COMP_CWORD
    cur="${COMP_WORDS[$COMP_CWORD]}"
    prev="${COMP_WORDS[$((COMP_CWORD - 1))]:-}"
    return 0
}

# Result state populated by the run_completion* helpers below.
COMPREPLY=()
_compopt_calls=""

# Drive _nvme_subcmds against an explicit COMP_WORDS array (each argument is one
# word, exactly as bash would present it). compopt is stubbed -- the real
# builtin only works inside an active completion -- and its arguments recorded.
run_completion_words() {
    COMPREPLY=()
    COMP_WORDS=("$@")
    COMP_CWORD=$(( $# - 1 ))
    _compopt_calls=""
    compopt() { _compopt_calls+="$* "; }
    _nvme_subcmds
    unset -f compopt
}

# Same, but from a command-line string (split via parse_words).
run_completion() {
    local -a words
    parse_words "$1"
    run_completion_words "${words[@]}"
}

# Record a PASS/FAIL result. $1: 0 for pass, non-zero for fail.
_check() {
    local ok=$1 desc=$2 detail=$3
    TESTS_RUN=$((TESTS_RUN + 1))
    echo ""
    echo "TEST $TESTS_RUN: $desc"
    if [[ $ok -eq 0 ]]; then
        echo -e "  ${GREEN}PASS${NC}: $detail"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        echo -e "  ${RED}FAIL${NC}: $detail"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
}

# ---------------------------------------------------------------------------
# Assertions -- each runs a completion and checks one property of the result.
# ---------------------------------------------------------------------------

# The completion offers something matching <regex>.
expect_match() {
    local desc=$1 cmdline=$2 regex=$3
    run_completion "$cmdline"
    local got="${COMPREPLY[*]}"
    if [[ "$got" =~ $regex ]]; then
        _check 0 "$desc" "'$cmdline<TAB>' -> '$got'"
    else
        _check 1 "$desc" "'$cmdline<TAB>' expected /$regex/, got '$got'"
    fi
}

# The completion offers nothing matching <regex>.
expect_no_match() {
    local desc=$1 cmdline=$2 regex=$3
    run_completion "$cmdline"
    local got="${COMPREPLY[*]}"
    if [[ "$got" =~ $regex ]]; then
        _check 1 "$desc" "'$cmdline<TAB>' should not offer /$regex/, got '$got'"
    else
        _check 0 "$desc" "'$cmdline<TAB>' -> '$got'"
    fi
}

# Like expect_match, but the command line is given as explicit COMP_WORDS: the
# description, then the regex, then the words. Use this for '=' token splits that
# the string-based parse_words would collapse (e.g. a bare '=' word).
expect_match_words() {
    local desc=$1 regex=$2
    shift 2
    run_completion_words "$@"
    local got="${COMPREPLY[*]}"
    if [[ "$got" =~ $regex ]]; then
        _check 0 "$desc" "[$*] -> '$got'"
    else
        _check 1 "$desc" "[$*] expected /$regex/, got '$got'"
    fi
}

# True if the current COMPREPLY contains a /dev/nvme* candidate. compgen -W
# pathname-expands the glob, so the result is host-dependent: real devices
# (/dev/nvme0, ...) on a host that has them, or the literal /dev/nvme* pattern on
# one that doesn't. Both match the glob pattern /dev/nvme*, so testing for that
# is deterministic either way.
_compreply_has_device() {
    local w
    for w in "${COMPREPLY[@]}"; do
        [[ "$w" == /dev/nvme* ]] && return 0
    done
    return 1
}

# The completion injects the /dev/nvme* device glob.
expect_device() {
    local desc=$1 cmdline=$2
    run_completion "$cmdline"
    if _compreply_has_device; then
        _check 0 "$desc" "'$cmdline<TAB>' injected a device candidate"
    else
        _check 1 "$desc" "'$cmdline<TAB>' expected a /dev/nvme* candidate, got '${COMPREPLY[*]}'"
    fi
}

# Like expect_device, but the command line is given as explicit COMP_WORDS (for
# '=' splits that parse_words would collapse). Args: desc, then the words.
expect_device_words() {
    local desc=$1
    shift
    run_completion_words "$@"
    if _compreply_has_device; then
        _check 0 "$desc" "[$*] injected a device candidate"
    else
        _check 1 "$desc" "[$*] expected a /dev/nvme* candidate, got '${COMPREPLY[*]}'"
    fi
}

# The completion does NOT inject the device glob (commands that take no device).
expect_no_device() {
    local desc=$1 cmdline=$2
    run_completion "$cmdline"
    local w
    for w in "${COMPREPLY[@]}"; do
        if [[ "$w" == /dev/nvme* ]]; then
            _check 1 "$desc" "'$cmdline<TAB>' unexpectedly offered a device: '${COMPREPLY[*]}'"
            return
        fi
    done
    _check 0 "$desc" "'$cmdline<TAB>' offered no device path"
}

# Assert the completion called the compopt builtin with args containing
# <substr>, e.g. '-o nospace' to suppress the trailing space after 'name='.
expect_compopt() {
    local desc=$1 cmdline=$2 substr=$3
    run_completion "$cmdline"
    if [[ "$_compopt_calls" == *"$substr"* ]]; then
        _check 0 "$desc" "'$cmdline<TAB>' requested 'compopt $substr'"
    else
        _check 1 "$desc" "'$cmdline<TAB>' expected 'compopt $substr', got [$_compopt_calls]"
    fi
}

# A value whose type has no candidate list (e.g. a NUM) must add nothing AND
# suppress readline's '-o default' file-name fallback.
expect_suppresses_files() {
    local desc=$1 cmdline=$2
    run_completion "$cmdline"
    if [[ ${#COMPREPLY[@]} -eq 0 && "$_compopt_calls" == *"+o default"* ]]; then
        _check 0 "$desc" "'$cmdline<TAB>' offered nothing and suppressed file completion"
    else
        _check 1 "$desc" "'$cmdline<TAB>' COMPREPLY=(${COMPREPLY[*]}) compopt=[$_compopt_calls]"
    fi
}

# A value that IS a filename (metavar FILE) must add nothing itself but leave
# the '-o default' fallback in place so readline lists files.
expect_allows_files() {
    local desc=$1 cmdline=$2
    run_completion "$cmdline"
    if [[ ${#COMPREPLY[@]} -eq 0 && "$_compopt_calls" != *"+o default"* ]]; then
        _check 0 "$desc" "'$cmdline<TAB>' left file completion enabled"
    else
        _check 1 "$desc" "'$cmdline<TAB>' COMPREPLY=(${COMPREPLY[*]}) compopt=[$_compopt_calls]"
    fi
}

# The completion did NOT call compopt with args containing <substr>.
expect_no_compopt() {
    local desc=$1 cmdline=$2 substr=$3
    run_completion "$cmdline"
    if [[ "$_compopt_calls" != *"$substr"* ]]; then
        _check 0 "$desc" "'$cmdline<TAB>' did not request 'compopt $substr'"
    else
        _check 1 "$desc" "'$cmdline<TAB>' unexpectedly requested 'compopt $substr' (COMPREPLY=${COMPREPLY[*]})"
    fi
}

# The completion must not leak <var> into the caller's scope. Completion
# functions run in the user's shell, so any variable they use has to be local;
# a bare loop counter or temporary would otherwise clobber the user's variable
# of the same name. Seed <var> with a sentinel, run the completion, check it.
expect_no_var_leak() {
    local desc=$1 cmdline=$2 var=$3
    printf -v "$var" '%s' "__sentinel__"
    run_completion "$cmdline"
    if [[ "${!var}" == "__sentinel__" ]]; then
        _check 0 "$desc" "'$cmdline<TAB>' left \$$var untouched"
    else
        _check 1 "$desc" "'$cmdline<TAB>' clobbered \$$var to '${!var}' (missing 'local $var')"
    fi
}

echo "========================================"
echo "Bash Completion Tests"
echo "========================================"

# ---------------------------------------------------------------------------
# Top-level command dispatch
# ---------------------------------------------------------------------------
expect_match \
    "top-level list offers builtin commands" \
    "nvme " \
    "id-ctrl.*smart-log"

expect_match \
    "top-level list is filtered by the typed prefix" \
    "nvme id-" \
    "id-ctrl.*id-ns"

expect_match \
    "top-level list includes plugin names" \
    "nvme " \
    "feat.*zns"

# A command's alias is offered alongside its primary name (fw-commit/fw-activate)
# and its options complete when invoked by the alias.
expect_match \
    "top-level list includes a command alias" \
    "nvme fw-a" \
    "fw-activate"

expect_match \
    "a command invoked by its alias completes options" \
    "nvme fw-activate --" \
    "--action"

# help and version are dispatcher built-ins (not in the metadata) but are still
# completable top-level commands.
expect_match \
    "top-level list includes the help built-in" \
    "nvme he" \
    "help"

expect_match \
    "top-level list includes the version built-in" \
    "nvme ver" \
    "version"

# ---------------------------------------------------------------------------
# Plugin sub-command dispatch
# ---------------------------------------------------------------------------
expect_match \
    "a plugin lists its sub-commands" \
    "nvme feat " \
    "arbitration.*power-mgmt"

expect_match \
    "plugin sub-commands are filtered by the typed prefix" \
    "nvme feat power-" \
    "power-mgmt.*power-meas"

# A different plugin, to prove routing isn't hardcoded to one name.
expect_match \
    "sub-command routing works for any plugin" \
    "nvme zns " \
    "report-zones.*reset-zone"

# A plugin sub-command alias is listed alongside its primary name (dera defines
# alias 'stat' for 'smart-log-add').
expect_match \
    "a plugin lists a sub-command alias" \
    "nvme dera " \
    "smart-log-add.*stat"

# ---------------------------------------------------------------------------
# Device-argument injection
# ---------------------------------------------------------------------------
expect_device \
    "a builtin command that takes a device offers /dev/nvme*" \
    "nvme id-ctrl "

# Plugin sub-commands sit one word later, so their opts functions inject the
# device at a higher non-option-argument threshold (3 vs 2). Cover that path.
expect_device \
    "a plugin sub-command that takes a device offers /dev/nvme*" \
    "nvme feat power-meas "

expect_no_device \
    "help takes no device" \
    "nvme help "

expect_no_device \
    "version takes no device" \
    "nvme version "

# Once a device is on the line the injection is suppressed. (readline's
# -o default still does filename completion of a partial path, but that's bash,
# not us, so it isn't exercised here.)
expect_no_device \
    "a device already on the line is not offered again" \
    "nvme id-ctrl /dev/nvme0 "

# A non-NVMe /dev/* path as an option value (e.g. --output-file /dev/null) is not
# the device argument, so device injection must still happen.
expect_device \
    "a /dev/* option value is not mistaken for the device argument" \
    "nvme telemetry-log --output-file /dev/null "

# Even a /dev/nvme* path given as an option value is not the positional device
# argument, so injection must still happen.
expect_device \
    "a /dev/nvme* option value is not mistaken for the device argument" \
    "nvme telemetry-log --output-file /dev/nvme0 "

# Same, but the '=' value form split by bash into '--output-file = /dev/nvme0'.
# The /dev/nvme0 must still be recognised as the option's value, not the device.
expect_device_words \
    "a /dev/nvme* value after a split '=' is not mistaken for the device" \
    nvme telemetry-log --output-file = /dev/nvme0 ""

# And the unsplit-option form '--output-file=' as its own word: the trailing '='
# must be stripped so the option still matches $valopts and its value is not
# counted as the device.
expect_device_words \
    "a /dev/nvme* value after an unsplit '--opt=' token is not the device" \
    nvme telemetry-log "--output-file=" /dev/nvme0 ""

# ---------------------------------------------------------------------------
# Option-name completion
# ---------------------------------------------------------------------------
expect_match \
    "-h/--help is always offered" \
    "nvme id-ctrl -" \
    "(^| )--help( |\$)"

expect_match \
    "a partial option name completes to the full option" \
    "nvme id-ctrl --output-f" \
    "--output-format"

# Global options are offered per command, straight from the metadata -- so a
# command that takes them gets them, and one that does not (e.g. intel
# lat-stats-tracking) is not wrongly offered them.
expect_match \
    "a command with global options offers them" \
    "nvme id-ctrl -" \
    "--output-format"

expect_no_match \
    "a command without global options is not offered them" \
    "nvme intel lat-stats-tracking -" \
    "--output-format"

# An option that takes a value completes to 'name=' with no trailing space, so
# the user can type the value immediately.
expect_compopt \
    "a value-taking option completes with a trailing '=' and no space" \
    "nvme id-ctrl --timeout" \
    "-o nospace"

# But nospace must NOT fire when a prefix matches several options -- e.g.
# '--output-format' matches both '--output-format=' and '--output-format-version='.
# bash appends nothing for an ambiguous completion, and suppressing the space
# would be wrong. (Regression: the check once looked only at COMPREPLY[0].)
expect_no_compopt \
    "no nospace when a prefix matches multiple options" \
    "nvme id-ctrl --output-format" \
    "-o nospace"

# Regression: the generated opts functions once used their loop counter i
# without declaring it local, silently clobbering the user's own $i. It must
# stay local so a completion never leaks into the caller's shell.
expect_no_var_leak \
    "completion does not leak loop variable i" \
    "nvme id-ctrl " \
    i

# A flag option takes no value, so completing after it (empty word, i.e. a
# trailing space) must resume normal option completion, not enter value mode
# (which offers nothing and suppresses files). Covers both long and short flags.
expect_match \
    "completion resumes after a long flag option" \
    "nvme id-ctrl --verbose " \
    "--help"

expect_match \
    "completion resumes after a short flag option" \
    "nvme id-ctrl -v " \
    "--help"

# The complement stays correct: a value-taking flagless option still completes
# its value (guard against the fix over-reaching and disabling value mode).
expect_match \
    "a value option still completes its value after the fix" \
    "nvme id-ctrl --output-format " \
    "normal.*json"

# ---------------------------------------------------------------------------
# Option-value completion (enumerated values)
# ---------------------------------------------------------------------------
# --output-format is a global option available on every command.
expect_match \
    "a global option lists its values (--opt= form)" \
    "nvme id-ctrl --output-format=" \
    "normal.*json.*binary.*tabular"

expect_match \
    "a global option lists its values (--opt <space> form)" \
    "nvme id-ctrl --output-format " \
    "normal.*json.*binary.*tabular"

expect_match \
    "a partial value is filtered against the value list" \
    "nvme id-ctrl --output-format j" \
    "json"

expect_match \
    "a partial value is filtered after '=' too" \
    "nvme id-ctrl --output-format=j" \
    "json"

expect_match \
    "the short-option form lists the same values" \
    "nvme id-ctrl -o " \
    "normal.*json.*binary.*tabular"

expect_match \
    "the short-option form filters a partial value" \
    "nvme id-ctrl -o j" \
    "json"

# nvme's getopt also accepts the short-option '=' form ('-o=json'). When bash
# splits on '=', that arrives as '-o = [partial]'; the value list must appear
# just as it does for the long-option '=' form.
expect_match \
    "the short-option '=' form lists values" \
    "nvme id-ctrl -o=" \
    "normal.*json.*binary.*tabular"

expect_match \
    "the short-option '=' form filters a partial value" \
    "nvme id-ctrl -o=j" \
    "json"

# Depending on COMP_WORDBREAKS, bash may present 'nvme id-ctrl --output-format='
# as three tokens ending in a bare '=' (option is the previous word) OR as a
# single unsplit '--output-format=' token. The string helpers always split on
# '=', so drive both forms explicitly to prove the value list appears either way.
expect_match_words \
    "value list appears when '=' is the current word (split form)" \
    "normal.*json.*binary.*tabular" \
    nvme feat power-meas --output-format =

expect_match_words \
    "value list appears for an unsplit '--opt=' token" \
    "normal.*json.*binary.*tabular" \
    nvme id-ctrl "--output-format="

# Same unsplit form but with a partial value ('--output-format=j'), which occurs
# when '=' is removed from COMP_WORDBREAKS. The partial must still filter the
# value list down to the match.
expect_match_words \
    "partial value filters for an unsplit '--opt=partial' token" \
    "json" \
    nvme id-ctrl "--output-format=j"

# Trailing space after an unsplit '--opt=' token: the previous word is the whole
# '--output-format=' (with '='), so the value list must still appear -- the
# detector has to strip the '=' before matching option names.
expect_match_words \
    "value list appears after an unsplit '--opt= ' with trailing space" \
    "normal.*json.*binary.*tabular" \
    nvme id-ctrl "--output-format=" ""

# --sel is an enumerated option carried by feat's sub-commands. Its values come
# from the generator's VALUE_HINTS table (the arg parser leaves --sel
# unconstrained, so the command metadata carries no values). This also exercises
# value completion reached through the plugin sub-command routing path.
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

# A command-LOCAL enumerated option whose values DO come from the metadata
# (fw-commit --action has an OPT_VALS table). Regression guard: the generator
# once emitted the per-command value clause only for global options, so local
# option values silently never completed.
expect_match \
    "a command-local enumerated option lists its metadata values" \
    "nvme fw-commit --action " \
    "replace.*set-active"

expect_match \
    "a command-local enumerated option lists its values (short opt)" \
    "nvme fw-commit -a " \
    "replace.*set-active"

# ---------------------------------------------------------------------------
# File-vs-no-file fallback for value-taking options
# ---------------------------------------------------------------------------
# A NUM value (e.g. --timeout, a freeform millisecond count that will never get
# an OPT_VALS table) must not fall back to listing files.
expect_suppresses_files \
    "a numeric value offers nothing and suppresses files (--opt= form)" \
    "nvme id-ctrl --timeout="

expect_suppresses_files \
    "a numeric value offers nothing and suppresses files (space form)" \
    "nvme id-ctrl --timeout "

# A FILE value (e.g. fw-download --fw) must leave readline's file completion on.
expect_allows_files \
    "a FILE value keeps file completion enabled (--opt= form)" \
    "nvme fw-download --fw="

expect_allows_files \
    "a FILE value keeps file completion enabled (space form)" \
    "nvme fw-download --fw "

echo ""
echo "========================================"
echo "Results: $TESTS_PASSED/$TESTS_RUN passed"
if [[ $TESTS_FAILED -gt 0 ]]; then
    echo -e "${RED}$TESTS_FAILED tests failed${NC}"
    exit 1
else
    echo -e "${GREEN}All tests passed${NC}"
    exit 0
fi
