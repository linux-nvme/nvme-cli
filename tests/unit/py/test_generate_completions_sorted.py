#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (c) 2026 Micron Technology, Inc.
#
# This file is part of nvme-cli.
"""Test that generate-completions.py emits commands and options alphabetically.

Complements test_generate_completions_stable.py (order-invariance): this checks
the canonical order the generator settles on is actually sorted. Works at the
generated-output level, one extractor per shell, pulling out the top-level
command list, each plugin's sub-command list, and each command's option list and
asserting each is ascending (C-locale / ordinal). The generator appends --help
last rather than sorting it in, so the option check asserts that placement --
sorted long options with --help (where present) as the sole final entry.

Usage: test_generate_completions_sorted.py <generate-completions.py> <fixture.json>
"""
import re
import subprocess
import sys
import unittest

SHELLS = ("bash", "zsh", "powershell")

# A broken extractor that finds nothing would pass every "is sorted" check
# vacuously. Require at least this many option groups with 2+ long options so a
# silent extraction regression fails loudly instead.
MIN_MULTI_OPTION_GROUPS = 3


def long_options(tokens):
    """Reduce a raw option token list to the comparable long-option names in
    emission order: keep '--foo', strip any '=' suffix, drop shorts. --help is
    kept so the ordering check can confirm the generator appends it last."""
    return [tok.rstrip("=") for tok in tokens if tok.startswith("--")]


class ExtractedLists:
    """The ordered lists pulled from one shell's generated output.

    Each member is a Python list. `commands` and `plugin_names` are flat lists
    of name strings; `subcommands` and `options` are lists of (label, names)
    tuples, one tuple per plugin / per command:

    commands     -- list of name strings, e.g. ['alpha-cmd', 'beta-plug', ...]
    plugin_names -- list of plugin-name strings, e.g. ['beta-plug', 'zeta-plug'];
                    None if the shell does not emit them as an ordered list
    subcommands  -- list of (label, [sub-command names]), one per plugin,
                    e.g. [('zeta-plug', ['no-opt-sub', 'report', 'rpt'])]
    options      -- list of (label, [long option names]), one per command,
                    e.g. [('alpha-cmd', ['--dry-run', '--format', ...])]

    `label` only identifies the group in an assertion failure message; its form
    varies by shell (a plugin/command name, or the shell array it came from) and
    is never used for logic.
    """

    def __init__(self, commands, plugin_names, subcommands, options):
        self.commands = commands
        self.plugin_names = plugin_names
        self.subcommands = subcommands
        self.options = options


def extract_powershell(text):
    """PowerShell emits a clean data model: an array of commands and two
    hashtables (plugin -> sub-commands, command -> options)."""
    m = re.search(r"NvmeCommands = @\((.*?)\)", text, re.S)
    commands = re.findall(r"'([^']+)'", m.group(1))

    m = re.search(r"NvmePluginCommands = @\{(.*?)\n\}", text, re.S)
    plugin_names, subcommands = [], []
    for line in m.group(1).strip().splitlines():
        mm = re.match(r"\s*'([^']+)'\s*=\s*@\((.*)\)", line)
        plugin_names.append(mm.group(1))
        subcommands.append((mm.group(1), re.findall(r"'([^']+)'", mm.group(2))))

    m = re.search(r"NvmeOptions = @\{(.*?)\n\}", text, re.S)
    options = []
    for line in m.group(1).strip().splitlines():
        mm = re.match(r"\s*'([^']+)'\s*=\s*@\((.*)\)", line)
        toks = re.findall(r"'([^']+)'", mm.group(2))
        options.append((mm.group(1), long_options(toks)))

    return ExtractedLists(commands, plugin_names, subcommands, options)


def extract_bash(text):
    """bash lists commands in a `_cmds=(...)` array, plugin sub-commands in a
    `_plugin_subcmds=([plug]="a b c")` map, and each command's options in an
    `opts+=" --foo= -f ..."` line under a `case "$1" in` arm."""
    m = re.search(r"_cmds=\((.*?)\)", text, re.S)
    commands = m.group(1).split()

    m = re.search(r"_plugin_subcmds=\((.*?)\n\t*\)", text, re.S)
    plugin_names, subcommands = [], []
    for line in m.group(1).strip().splitlines():
        mm = re.match(r'\s*\[([^\]]+)\]="([^"]*)"', line)
        plugin_names.append(mm.group(1))
        subcommands.append((mm.group(1), mm.group(2).split()))

    # The command name(s) live on the preceding case arm (e.g. `"report"|"rpt")`);
    # use it as the group label. The shared `_nvme_finish_completion` helper also
    # holds an `opts+=" -h --help"`, but it sits before any arm, so a None label
    # skips it rather than mislabelling it.
    options = []
    label = None
    for line in text.splitlines():
        s = line.strip()
        arm = re.match(r'("[^"]+"(?:\|"[^"]+")*)\)$', s)
        if arm:
            label = "|".join(re.findall(r'"([^"]+)"', arm.group(1)))
        elif s.startswith('opts+="') and "--" in s and label is not None:
            toks = s[len('opts+="'):].rstrip('"').split()
            options.append((label, long_options(toks)))
            label = None

    return ExtractedLists(commands, plugin_names, subcommands, options)


def _zsh_name(entry):
    """A zsh command entry is `'name:description'` or `'name'`."""
    return entry.strip().strip("'").split(":", 1)[0]


def extract_zsh(text):
    """zsh embeds each list in a `NAME=( ... )` array. `_cmds` holds the
    top-level commands, each `_sub` a plugin's sub-commands, and per-command
    arrays (e.g. `_alpha_cmd`) the options -- classified by whether the entries
    are command tokens (`'name:desc'`) or option tokens (`--foo=':desc'`).

    zsh does not emit the plugin names as their own ordered list (they are case
    arms), so plugin_names is None -- their order is covered by `_cmds`.
    """
    commands, subcommands, options = [], [], []
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        m = re.match(r"\s*([A-Za-z_][A-Za-z0-9_]*)=\(\s*$", lines[i])
        if not m:
            i += 1
            continue
        name = m.group(1)
        entries, j = [], i + 1
        while j < len(lines) and not re.match(r"\s*\)\s*$", lines[j]):
            entries.append(lines[j].strip())
            j += 1
        i = j
        if not entries:
            continue
        if name == "_cmds":
            commands = [_zsh_name(e) for e in entries]
        elif name == "_sub":
            subcommands.append((name, [_zsh_name(e) for e in entries]))
        elif entries[0].startswith("-"):
            toks = [re.match(r"(-{1,2}[A-Za-z0-9-]+=?)", e).group(1) for e in entries]
            options.append((name, long_options(toks)))

    return ExtractedLists(commands, None, subcommands, options)


EXTRACTORS = {
    "bash": extract_bash,
    "zsh": extract_zsh,
    "powershell": extract_powershell,
}


def assert_sorted(testcase, label, names):
    testcase.assertEqual(
        names, sorted(names), msg="%s not in alphabetical order: %r" % (label, names)
    )


def assert_options_sorted(testcase, label, opts):
    """Long options must be alphabetical, except --help, which the generator
    appends last (after the sorted list) rather than sorting in. Where it
    appears -- zsh and PowerShell attach it per command; bash adds it in a shared
    helper, so it is absent from the bash-extracted groups -- it must be the sole
    final entry, and everything before it must be sorted."""
    body = opts
    if "--help" in opts:
        testcase.assertEqual(
            opts[-1], "--help", msg="%s: --help must be last, got %r" % (label, opts)
        )
        body = opts[:-1]
        testcase.assertNotIn(
            "--help", body, msg="%s: --help appears more than once: %r" % (label, opts)
        )
    assert_sorted(testcase, label + " (excluding trailing --help)", body)


class GenerateCompletionsSortedTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(FIXTURE) as f:
            model = f.read()
        cls.by_shell = {}
        for shell in SHELLS:
            r = subprocess.run(
                [sys.executable, GENERATOR, "-", "--%s" % shell, "-"],
                input=model,
                capture_output=True,
                text=True,
            )
            if r.returncode != 0:
                raise RuntimeError(r.stderr)
            cls.by_shell[shell] = EXTRACTORS[shell](r.stdout)

    def test_command_sets_agree_across_shells(self):
        """Guard the extractors: every shell must yield the same, non-empty set
        of top-level commands (a broken parser would diverge here)."""
        sets = {shell: frozenset(self.by_shell[shell].commands) for shell in SHELLS}
        self.assertTrue(all(sets.values()), msg="a shell yielded no commands: %r" % sets)
        self.assertEqual(len(set(sets.values())), 1, msg="command sets differ: %r" % sets)

    def test_extraction_is_substantive(self):
        """Guard against vacuous passes: each shell must expose several option
        groups with more than one long option to actually order-check."""
        for shell in SHELLS:
            multi = [
                o
                for _, o in self.by_shell[shell].options
                if len([x for x in o if x != "--help"]) >= 2
            ]
            self.assertGreaterEqual(
                len(multi),
                MIN_MULTI_OPTION_GROUPS,
                msg="%s exposed too few multi-option groups (%d); extractor broken?"
                % (shell, len(multi)),
            )

    def test_commands_are_sorted(self):
        for shell in SHELLS:
            assert_sorted(self, "%s commands" % shell, self.by_shell[shell].commands)

    def test_plugin_names_are_sorted(self):
        for shell in SHELLS:
            keys = self.by_shell[shell].plugin_names
            if keys is not None:
                assert_sorted(self, "%s plugin names" % shell, keys)

    def test_plugin_subcommands_are_sorted(self):
        for shell in SHELLS:
            for label, subs in self.by_shell[shell].subcommands:
                assert_sorted(self, "%s sub-commands of %s" % (shell, label), subs)

    def test_options_are_sorted(self):
        for shell in SHELLS:
            for label, opts in self.by_shell[shell].options:
                assert_options_sorted(self, "%s options of %s" % (shell, label), opts)


if __name__ == "__main__":
    if len(sys.argv) < 3:
        sys.exit("usage: %s <generate-completions.py> <fixture.json>" % sys.argv[0])
    FIXTURE = sys.argv.pop(2)
    GENERATOR = sys.argv.pop(1)
    unittest.main()
