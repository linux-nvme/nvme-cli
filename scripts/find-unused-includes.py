#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme.
# Copyright (c) 2026 SUSE LLC
#
# Authors: Daniel Wagner <dwagner@suse.de>
"""Find (and optionally remove) local project headers that a .c file
includes but doesn't actually need.

Only local project headers (quoted, or a bare basename matching a file
under plugins/, src/, tests/) are considered. <system>, <libnvme.h>,
<ccan/*> and <shared/*> includes are never touched: whether a file still
compiles without them can't distinguish "genuinely unused" from "used,
but transitively supplied by some unrelated header" -- and for those
tiers that transitive supply is common and not something to rely on.

For each candidate include, in order:

  1. Skip it if it's behind a #ifdef/#ifndef/#if guard -- we'd need a
     build config that flips that specific guard to test it safely, and
     we don't try to match guards to configs here.
  2. Skip it if it's the file's own matching header (foo.c -> foo.h):
     that's what makes the compiler check this file's own definitions
     against their declared prototypes, independent of whether anything
     in the file's body "needs" it.
  3. Skip it if it's still reachable via some other include the file
     keeps (per header-graph.py's static #include graph): a compile
     that still succeeds in that case only proves transitive luck, not
     absence of a real dependency.
  4. Otherwise, actually remove the line and try to compile the file
     (as -fsyntax-only, straight from compile_commands.json, bypassing
     ninja's mtime cache) under every build directory that builds this
     file. Keep the removal only if all of them still compile clean.

Requires one or more build directories with compile_commands.json
(`meson setup --werror <dir>` and at least one `ninja -C <dir>`, so the
compile database exists and reflects a working baseline). Passing build
dirs for more than one config (e.g. default and -Dfabrics=disabled) is
strongly recommended: an include only used under a config you didn't
test looks unused here, and this tool skips over #ifdef'd includes
precisely because it doesn't try to match guards to configs.

Defaults to a dry run; pass --apply to actually edit files.
"""
import argparse
import json
import os
import re
import shlex
import subprocess
import sys

sys.path.insert(0, os.path.dirname(__file__))
import importlib
header_graph = importlib.import_module('header-graph')

REPO_ROOT = header_graph.REPO_ROOT

INC_RE = re.compile(r'^\s*#\s*include\s*([<"])([^">]+)([>"])\s*$')
COND_START_RE = re.compile(r'^\s*#\s*(if|ifdef|ifndef)\b')
COND_END_RE = re.compile(r'^\s*#\s*endif\b')


def default_targets():
    files = []
    for root in ['plugins', 'src', 'tests']:
        for dirpath, _dirnames, filenames in os.walk(os.path.join(REPO_ROOT, root)):
            if 'subprojects' in dirpath:
                continue
            for fn in filenames:
                if fn.endswith('.c'):
                    files.append(os.path.relpath(os.path.join(dirpath, fn), REPO_ROOT))
    return sorted(files)


def local_header_basenames():
    return {os.path.basename(f) for f in header_graph.collect_files()
            if f.endswith('.h') and not f.startswith(('shared/', 'ccan/'))}


class Sweeper:
    def __init__(self, builddirs, local_headers):
        self.graph = header_graph.HeaderGraph()
        self.local_headers = local_headers
        self.file_cmds = {b: self._load_file_cmd_map(b) for b in builddirs}

    @staticmethod
    def _load_file_cmd_map(builddir):
        path = os.path.join(builddir, 'compile_commands.json')
        cc = json.load(open(path))
        m = {}
        for e in cc:
            f = e['file']
            if f.startswith('../'):
                f = f[3:]
            m[f] = e
        return m

    def is_local_include(self, line):
        m = INC_RE.match(line)
        if not m:
            return False
        bracket, path, _ = m.groups()
        if path in ('libnvme.h', 'libnvme-mi.h'):
            return False
        if path.startswith('ccan/') or path.startswith('shared/'):
            return False
        return os.path.basename(path) in self.local_headers or bracket == '"'

    @staticmethod
    def is_self_header(relpath, line):
        m = INC_RE.match(line)
        if not m:
            return False
        _, raw_path, _ = m.groups()
        base_c = os.path.splitext(os.path.basename(relpath))[0]
        base_h = os.path.splitext(os.path.basename(raw_path))[0]
        return base_c == base_h

    def find_candidates(self, relpath, lines):
        depth = 0
        candidates = []
        for i, line in enumerate(lines):
            if COND_START_RE.match(line):
                depth += 1
                continue
            if COND_END_RE.match(line):
                depth = max(0, depth - 1)
                continue
            if depth == 0 and self.is_local_include(line) and not self.is_self_header(relpath, line):
                candidates.append(i)
        return candidates

    def applicable_commands(self, relpath):
        out = []
        for builddir, cmds in self.file_cmds.items():
            e = cmds.get(relpath)
            if not e:
                continue
            argv = shlex.split(e['command'])
            new_argv = []
            skip_next = False
            for a in argv:
                if skip_next:
                    skip_next = False
                    continue
                if a == '-o':
                    skip_next = True
                    continue
                new_argv.append(a)
            new_argv.append('-fsyntax-only')
            out.append((builddir, e['directory'], new_argv))
        return out

    @staticmethod
    def try_compile(directory, argv):
        r = subprocess.run(argv, cwd=directory, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        return r.returncode == 0, r.stdout.decode(errors='replace')

    def resolved_paths_of(self, relpath, lines):
        out = set()
        for line in lines:
            m = INC_RE.match(line)
            if not m:
                continue
            _, raw_path, _ = m.groups()
            r = self.graph.resolve_include(relpath, raw_path)
            if r:
                out.add(r)
        return out

    @staticmethod
    def cleanup_blank_runs(lines):
        out = []
        blank_run = 0
        for l in lines:
            if l.strip() == '':
                blank_run += 1
                if blank_run <= 1:
                    out.append(l)
            else:
                blank_run = 0
                out.append(l)
        return out

    def process_file(self, relpath, log, apply):
        full = os.path.join(REPO_ROOT, relpath)
        original_lines = open(full, encoding='utf-8', errors='ignore').read().split('\n')

        cmds = self.applicable_commands(relpath)
        if not cmds:
            return []

        for (builddir, d, argv) in cmds:
            ok, out = self.try_compile(d, argv)
            if not ok:
                log(f'{relpath}: baseline fails to compile under {builddir}, skipping file')
                log(out[-1500:])
                return []

        candidates = self.find_candidates(relpath, original_lines)
        if not candidates:
            return []

        removed = set()
        findings = []

        for idx in sorted(candidates, reverse=True):
            candidate_line = original_lines[idx]
            m = INC_RE.match(candidate_line)
            _, raw_path, _ = m.groups()
            candidate_resolved = self.graph.resolve_include(relpath, raw_path)

            trial = [l for j, l in enumerate(original_lines) if j not in removed and j != idx]

            if candidate_resolved:
                remaining = self.resolved_paths_of(relpath, trial)
                if self.graph.reachable(remaining, candidate_resolved):
                    continue

            with open(full, 'w', encoding='utf-8') as f:
                f.write('\n'.join(trial))

            ok_all = True
            for (builddir, d, argv) in cmds:
                ok, out = self.try_compile(d, argv)
                if not ok:
                    ok_all = False
                    break

            if ok_all:
                removed.add(idx)
                findings.append((idx + 1, candidate_line.strip()))
            else:
                restore = [l for j, l in enumerate(original_lines) if j not in removed]
                with open(full, 'w', encoding='utf-8') as f:
                    f.write('\n'.join(restore))

        if not removed:
            with open(full, 'w', encoding='utf-8') as f:
                f.write('\n'.join(original_lines))
            return findings

        final_lines = [l for j, l in enumerate(original_lines) if j not in removed]
        last_candidate = max(candidates)
        boundary = sum(1 for j in range(last_candidate + 1) if j not in removed)
        final_lines = self.cleanup_blank_runs(final_lines[:boundary]) + final_lines[boundary:]

        if not apply:
            with open(full, 'w', encoding='utf-8') as f:
                f.write('\n'.join(original_lines))
            return findings

        with open(full, 'w', encoding='utf-8') as f:
            f.write('\n'.join(final_lines))

        for (builddir, d, argv) in cmds:
            ok, out = self.try_compile(d, argv)
            if not ok:
                log(f'{relpath}: final verify failed on {builddir} after cleanup, restoring original')
                log(out[-1500:])
                with open(full, 'w', encoding='utf-8') as f:
                    f.write('\n'.join(original_lines))
                return []

        return findings


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--builddir', action='append', required=True,
                     help='meson build dir with compile_commands.json; repeat for multiple configs')
    ap.add_argument('--files', metavar='FILE',
                     help='file with one repo-relative .c path per line (default: all of plugins/, src/, tests/)')
    ap.add_argument('--apply', action='store_true', help='actually edit files (default: dry run, report only)')
    args = ap.parse_args()

    if args.files:
        targets = [l.strip() for l in open(args.files) if l.strip()]
    else:
        targets = default_targets()

    sweeper = Sweeper(args.builddir, local_header_basenames())

    def log(msg):
        print(msg, file=sys.stderr)

    total = 0
    for relpath in targets:
        findings = sweeper.process_file(relpath, log, args.apply)
        for lineno, text in findings:
            total += 1
            verb = 'removed' if args.apply else 'would remove'
            print(f'{relpath}:{lineno}: {verb}  {text}')

    print(f'\n{total} unused local include(s) {"removed" if args.apply else "found (dry run, use --apply to edit)"}',
          file=sys.stderr)


if __name__ == '__main__':
    sys.exit(main())
