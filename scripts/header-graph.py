#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme.
# Copyright (c) 2026 SUSE LLC
#
# Authors: Daniel Wagner <dwagner@suse.de>
"""Static #include graph for nvme-cli's own sources.

Walks plugins/, src/, tests/, shared/, ccan/ and resolves every #include
line to a repo-relative path using the same search order the actual build
uses (own directory first, then repo root, src/, ccan/, libnvme/src/).
System headers and libnvme's own installed headers (<libnvme.h>,
<libnvme-mi.h>, <nvme/...>) are left unresolved -- they're leaves, not
something we can (or need to) reason about here.

Used as a library by find-unused-includes.py to tell "genuinely unused"
apart from "compiles fine because some other header drags it in anyway".
Also usable standalone to inspect the graph directly.
"""
import argparse
import json
import os
import re
import sys

REPO_ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), '..'))
GRAPH_ROOTS = ['plugins', 'src', 'tests', 'shared', 'ccan']

INC_RE = re.compile(r'^\s*#\s*include\s*([<"])([^">]+)([>"])')


def collect_files(repo_root=REPO_ROOT):
    files = []
    for root in GRAPH_ROOTS:
        for dirpath, _dirnames, filenames in os.walk(os.path.join(repo_root, root)):
            if 'subprojects' in dirpath:
                continue
            for fn in filenames:
                if fn.endswith(('.c', '.h')):
                    full = os.path.join(dirpath, fn)
                    files.append(os.path.relpath(full, repo_root))
    return files


class HeaderGraph:
    def __init__(self, repo_root=REPO_ROOT):
        self.repo_root = repo_root
        self.all_files = set(collect_files(repo_root))
        self.graph = self._build_graph()

    def resolve_include(self, includer_relpath, raw_path):
        if raw_path.startswith('shared/') or raw_path.startswith('ccan/'):
            return raw_path if raw_path in self.all_files else None
        if raw_path in ('libnvme.h', 'libnvme-mi.h'):
            return None
        if raw_path.startswith('nvme/'):
            return None
        includer_dir = os.path.dirname(includer_relpath)
        for d in (includer_dir, '.', 'src', 'ccan', 'libnvme/src'):
            candidate = os.path.normpath(os.path.join(d, raw_path)) if d else os.path.normpath(raw_path)
            if candidate in self.all_files:
                return candidate
        return None

    def _build_graph(self):
        graph = {}
        for relpath in self.all_files:
            full = os.path.join(self.repo_root, relpath)
            try:
                text = open(full, encoding='utf-8', errors='ignore').read()
            except OSError:
                continue
            edges = set()
            for line in text.split('\n'):
                m = INC_RE.match(line)
                if not m:
                    continue
                _bracket, raw_path, _ = m.groups()
                resolved = self.resolve_include(relpath, raw_path)
                if resolved:
                    edges.add(resolved)
            graph[relpath] = edges
        return graph

    def direct_includes(self, relpath):
        return set(self.graph.get(relpath, ()))

    def transitive_includes(self, relpath):
        seen = set()
        stack = list(self.graph.get(relpath, ()))
        while stack:
            node = stack.pop()
            if node in seen:
                continue
            seen.add(node)
            stack.extend(self.graph.get(node, ()))
        return seen

    def reachable(self, start_paths, target):
        """Is `target` reachable from any node in start_paths, walking the
        #include graph. Caller excludes target from start_paths itself."""
        seen = set()
        stack = list(start_paths)
        while stack:
            node = stack.pop()
            if node in seen:
                continue
            seen.add(node)
            for nxt in self.graph.get(node, ()):
                if nxt == target:
                    return True
                if nxt not in seen:
                    stack.append(nxt)
        return False

    def to_dot(self):
        lines = ['digraph includes {', '  rankdir=LR;']
        for node, edges in sorted(self.graph.items()):
            for e in sorted(edges):
                lines.append(f'  "{node}" -> "{e}";')
        lines.append('}')
        return '\n'.join(lines)

    def to_json(self):
        return json.dumps({k: sorted(v) for k, v in self.graph.items()}, indent=2, sort_keys=True)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--dot', metavar='FILE', help='dump the full graph as Graphviz DOT')
    ap.add_argument('--json', metavar='FILE', help='dump the full graph as JSON')
    ap.add_argument('--includes', metavar='FILE', help='list direct+transitive includes of a repo-relative file')
    ap.add_argument('--reachable', nargs=2, metavar=('FILE', 'TARGET'),
                     help='is TARGET reachable from FILE via the include graph?')
    ap.add_argument('--stats', action='store_true', help='print node/edge counts (default if no other action given)')
    args = ap.parse_args()

    g = HeaderGraph()

    did_something = False
    if args.dot:
        open(args.dot, 'w').write(g.to_dot() + '\n')
        print(f'wrote {args.dot}')
        did_something = True
    if args.json:
        open(args.json, 'w').write(g.to_json() + '\n')
        print(f'wrote {args.json}')
        did_something = True
    if args.includes:
        direct = g.direct_includes(args.includes)
        trans = g.transitive_includes(args.includes) - direct
        print(f'direct includes of {args.includes}:')
        for d in sorted(direct):
            print(f'  {d}')
        print(f'transitively reachable (not direct):')
        for t in sorted(trans):
            print(f'  {t}')
        did_something = True
    if args.reachable:
        f, target = args.reachable
        r = g.reachable(g.direct_includes(f), target)
        print('yes' if r else 'no')
        did_something = True

    if args.stats or not did_something:
        n_edges = sum(len(v) for v in g.graph.values())
        print(f'{len(g.all_files)} files, {n_edges} resolved include edges')


if __name__ == '__main__':
    sys.exit(main())
