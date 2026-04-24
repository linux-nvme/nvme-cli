#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# This file is part of libnvme.
# Copyright (c) 2026, Dell Technologies Inc. or its subsidiaries.
#
# Authors: Martin Belanger <Martin.Belanger@dell.com>
#
# Verify that nvme.i is consistent with the accessor annotations in
# private.h and private-fabrics.h.
#
# Three invariants are enforced:
#
#   Rule 1 (error):   A field annotated !accessors:readonly that is exposed
#                     in nvme.i must be declared %immutable.
#
#   Rule 2 (error):   A field with an auto-generated or bridged accessor
#                     that is exposed as a direct struct member (not inside
#                     %extend {}) is not going through the public API.
#
#   Rule 3 (error):   A field declared inside %extend {} must have a getter
#                     bridge (SWIG name → actual function name) whose target
#                     function is declared in at least one public header.
#
# Additional checks:
#
#   Check 4 (error):  A bridge entry's target function is not found in any
#                     public header — stale or misspelled bridge.
#
#   Check 5 (error):  A %immutable declaration in nvme.i refers to a field
#                     that does not exist in the corresponding C struct.
#
#   Check 6 (warning): A field that has an accessor but is not exposed in
#                      nvme.i at all (may be intentional, but worth knowing).
#
# Usage (via meson — preferred):
#   python3 tools/check-nvme-i-consistency.py \
#       --private-header src/nvme/private.h \
#       --private-header src/nvme/private-fabrics.h \
#       --public-header  src/nvme/accessors.h \
#       --public-header  src/nvme/tree.h \
#       [--public-header ...] \
#       --swig-interface  libnvme/nvme.i \
#       --swig-accessors  libnvme/nvme-swig-accessors.i
#
# Usage (standalone, auto-discovers files from the source root):
#   python3 tools/check-nvme-i-consistency.py [LIBNVME-SOURCE-ROOT]

import argparse
import re
import sys
import pathlib


# ---------------------------------------------------------------------------
# Compiled patterns
# ---------------------------------------------------------------------------

_RE_BRIDGE       = re.compile(r'^\s*#define\s+(libnvme_\w+|libnvmf_\w+)\s+(\w+)')
_RE_FUNC_NAME    = re.compile(r'\b(libnvme_\w+|libnvmf_\w+)\s*\(')
_RE_STRUCT_OPEN  = re.compile(r'^struct\s+(\w+)\s*\{.*!generate-accessors')
_RE_EXTEND_OPEN  = re.compile(r'^%extend\s+(\w+)\s*\{')
_RE_INLINE_EXT   = re.compile(r'^%extend\s*\{')
_RE_IMMUTABLE    = re.compile(r'^%immutable\s+(\w+)\s*;')
_RE_FIELD        = re.compile(
    r'^'
    r'(?P<type>'
    r'(?:const\s+)?'
    r'(?:(?:unsigned|signed|long)\s+)*'
    r'(?:struct\s+\w+|enum\s+\w+|\w+)'
    r'\s*\*?)\s*'
    r'(?P<name>\w+)'
    r'\s*(?:\[[^\]]*\])?'
    r'\s*;$'
)
_RE_PRIV_FIELD   = re.compile(
    r'^\s+'
    r'(?P<type>'
    r'(?:(?:const|volatile)\s+)*'
    r'(?:(?:unsigned|signed|long)\s+)*'
    r'(?:struct\s+\w+|enum\s+\w+|\w+)'
    r'\s*\*?)\s*'
    r'(?P<name>\w+)'
    r'\s*(?:\[[^\]]*\])?'
    r'\s*;'
)
_RE_IFDEF_SKIP   = re.compile(r'^#ifdef\s+(CONFIG_LIBURING)\b')
_RE_ENDIF        = re.compile(r'^#endif\b')
_RE_VERBATIM     = re.compile(r'^%(\w+\s+)?%\{')


# ---------------------------------------------------------------------------
# Type normalization
# ---------------------------------------------------------------------------

# Kernel-style integer typedefs and their C99 equivalents. Used so that
# a field typed '__u32' in private.h and 'unsigned int' in nvme.i are
# treated as the same type in Check 7.
_TYPE_ALIASES = {
    '__u8':               'uint8_t',
    '__u16':              'uint16_t',
    '__u32':              'uint32_t',
    '__u64':              'uint64_t',
    '__s8':               'int8_t',
    '__s16':              'int16_t',
    '__s32':              'int32_t',
    '__s64':              'int64_t',
    'unsigned char':      'uint8_t',
    'unsigned short':     'uint16_t',
    'unsigned int':       'uint32_t',
    'unsigned long long': 'uint64_t',
}


def _normalize_type(t):
    t = re.sub(r'\s+', ' ', t).strip()
    t = re.sub(r'\s*\*', ' *', t).strip()
    is_const = t.startswith('const ')
    has_ptr  = t.endswith(' *')
    base = t
    if is_const:
        base = base[6:]
    if has_ptr:
        base = base[:-2]
    base = _TYPE_ALIASES.get(base, base)
    if has_ptr:
        base += ' *'
    if is_const:
        base = 'const ' + base
    return base


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def parse_args():
    p = argparse.ArgumentParser(
        description='Check nvme.i consistency with private header annotations.')
    p.add_argument(
        'root', nargs='?',
        help='libnvme source root for auto-discovery (defaults to the parent '
             'of this script); ignored when explicit --*-header flags are given')
    p.add_argument(
        '--private-header', action='append', metavar='FILE',
        dest='private_headers',
        help='private header file to read struct annotations from '
             '(may be repeated)')
    p.add_argument(
        '--public-header', action='append', metavar='FILE',
        dest='public_headers',
        help='public header file to search for accessor function declarations '
             '(may be repeated)')
    p.add_argument(
        '--swig-interface', metavar='FILE', dest='swig_iface',
        help='SWIG interface file to check (nvme.i)')
    p.add_argument(
        '--swig-accessors', metavar='FILE', dest='swig_accessors',
        help='auto-generated SWIG accessor bridge file (nvme-swig-accessors.i)')
    return p.parse_args()


# ---------------------------------------------------------------------------
# Bridge collection: #define SWIG_NAME ACTUAL_NAME inside %{ %} blocks
# ---------------------------------------------------------------------------

def collect_bridges(path):
    """Return dict[swig_func_name → actual_func_name] from %{...%} blocks."""
    bridges = {}
    in_block = False
    for line in path.read_text().splitlines():
        s = line.strip()
        if not in_block:
            if _RE_VERBATIM.match(s) or s == '%{':
                in_block = True
        elif s == '%}':
            in_block = False
        else:
            m = _RE_BRIDGE.match(line)
            if m:
                bridges[m.group(1)] = m.group(2)
    return bridges


# ---------------------------------------------------------------------------
# Known function names from public headers
# ---------------------------------------------------------------------------

def collect_known_funcs(paths):
    """Return set of libnvme_*/libnvmf_* function names declared in headers."""
    funcs = set()
    for path in paths:
        for m in _RE_FUNC_NAME.finditer(path.read_text()):
            funcs.add(m.group(1))
    return funcs


# ---------------------------------------------------------------------------
# Private header parser
# ---------------------------------------------------------------------------

def parse_private_headers(paths):
    """
    Parse private.h and private-fabrics.h for !generate-accessors structs.

    Returns dict[struct_name → dict[field_name → annotation]] where
    annotation is 'readonly', 'none', or 'rw'.

    Fields inside #ifdef CONFIG_LIBURING blocks are skipped because liburing
    is an optional dependency that is independent of the Python bindings.
    Fields inside #ifdef CONFIG_MI blocks are parsed and checked normally.
    """
    result = {}

    for path in paths:
        lines = path.read_text().splitlines()
        i = 0
        while i < len(lines):
            s = lines[i].strip()
            m = _RE_STRUCT_OPEN.match(s)
            if not m:
                i += 1
                continue

            struct_name = m.group(1)
            fields = {}
            depth = 1          # inside the opening brace of the struct
            in_skip = False    # inside a CONFIG_MI/CONFIG_LIBURING block
            skip_depth = 0
            i += 1

            while i < len(lines) and depth > 0:
                raw  = lines[i]
                s    = raw.strip()
                opens   = s.count('{')
                closes  = s.count('}')

                if _RE_IFDEF_SKIP.match(s):
                    in_skip    = True
                    skip_depth = depth
                elif in_skip and _RE_ENDIF.match(s) and depth == skip_depth:
                    in_skip = False
                elif depth == 1 and not in_skip and opens == 0:
                    mf = _RE_PRIV_FIELD.match(raw)
                    if mf:
                        fname = mf.group('name')
                        ftype = _normalize_type(mf.group('type'))
                        if '!accessors:readonly' in raw:
                            fields[fname] = ('readonly', ftype)
                        elif '!accessors:none' in raw:
                            fields[fname] = ('none', ftype)
                        else:
                            fields[fname] = ('rw', ftype)

                depth += opens - closes
                i += 1

            result[struct_name] = fields

    return result


# ---------------------------------------------------------------------------
# nvme.i parser
# ---------------------------------------------------------------------------

def _strip_verbatim_blocks(text):
    """Remove %{...%} and %pythoncode %{...%} blocks from SWIG source."""
    out   = []
    in_block = False
    for line in text.splitlines():
        s = line.strip()
        if not in_block:
            if _RE_VERBATIM.match(s) or s == '%{':
                in_block = True
            else:
                out.append(line)
        elif s == '%}':
            in_block = False
    return out


def parse_nvme_i(path):
    """
    Parse nvme.i and return per-struct field membership.

    Returns dict[struct_name → {'immutable': set, 'extend': set, 'direct': set}].

    'immutable': fields declared %immutable
    'extend':    fields declared inside a %extend {} block
    'direct':    fields declared directly in the struct body
    """
    result = {}

    def ensure(name):
        if name not in result:
            result[name] = {'immutable': set(), 'extend': set(), 'direct': set(), 'types': {}}

    lines = _strip_verbatim_blocks(path.read_text())
    i = 0

    while i < len(lines):
        s = lines[i].strip()

        # ----------------------------------------------------------------
        # struct STRUCTNAME { ... };
        # ----------------------------------------------------------------
        m = re.match(r'^struct\s+(\w+)\s*\{', s)
        if m:
            struct_name = m.group(1)
            ensure(struct_name)
            # A struct closed on its own opening line (e.g. "struct X {};")
            # has nothing to parse; skip it.
            net = s.count('{') - s.count('}')
            if net <= 0:
                i += 1
                continue
            i += 1
            depth            = net   # 1 for the normal "struct X {" case
            in_inline_ext    = False
            inline_ext_depth = 0

            while i < len(lines) and depth > 0:
                raw = lines[i]
                s2  = raw.strip()

                opens  = s2.count('{')
                closes = s2.count('}')

                # Inline %extend { } sub-block
                if _RE_INLINE_EXT.match(s2):
                    in_inline_ext    = True
                    inline_ext_depth = depth + opens
                    depth           += opens - closes
                    i += 1
                    continue

                depth += opens - closes

                # Leaving the inline %extend sub-block
                if in_inline_ext and depth < inline_ext_depth:
                    in_inline_ext = False

                if depth > 0:
                    mi = _RE_IMMUTABLE.match(s2)
                    if mi:
                        result[struct_name]['immutable'].add(mi.group(1))
                    elif not s2.startswith('%') and '(' not in s2:
                        # Strip trailing inline C comment before matching so
                        # that lines like "const char *foo;  // comment" work.
                        s_nocomment = re.sub(r'\s*//.*$', '', s2)
                        mf = _RE_FIELD.match(s_nocomment)
                        if mf:
                            fname = mf.group('name')
                            bucket = 'extend' if in_inline_ext else 'direct'
                            result[struct_name][bucket].add(fname)
                            result[struct_name]['types'][fname] = _normalize_type(mf.group('type'))

                i += 1
            continue  # outer while

        # ----------------------------------------------------------------
        # %extend STRUCTNAME { ... }   (standalone method/property block)
        # ----------------------------------------------------------------
        m = _RE_EXTEND_OPEN.match(s)
        if m:
            struct_name = m.group(1)
            ensure(struct_name)
            i += 1
            depth = 1

            while i < len(lines) and depth > 0:
                raw = lines[i]
                s2  = raw.strip()

                opens  = s2.count('{')
                closes = s2.count('}')
                depth += opens - closes

                # Only field declarations appear at depth == 1
                if depth == 1:
                    mi = _RE_IMMUTABLE.match(s2)
                    if mi:
                        result[struct_name]['immutable'].add(mi.group(1))
                    elif not s2.startswith('%') and '(' not in s2:
                        s_nocomment = re.sub(r'\s*//.*$', '', s2)
                        mf = _RE_FIELD.match(s_nocomment)
                        if mf:
                            fname = mf.group('name')
                            result[struct_name]['extend'].add(fname)
                            result[struct_name]['types'][fname] = _normalize_type(mf.group('type'))

                i += 1
            continue  # outer while

        i += 1

    return result


# ---------------------------------------------------------------------------
# Consistency checks
# ---------------------------------------------------------------------------

def run_checks(private_structs, known_funcs, all_bridges, swig_data):
    """
    Returns (errors, warnings) as sorted lists of human-readable strings.
    """
    errors   = []
    warnings = []

    for struct_name, fields in private_structs.items():
        swig      = swig_data.get(struct_name)
        if swig is None:
            # Struct is not exposed in nvme.i at all — that is fine.
            continue

        immutable    = swig['immutable']
        extend       = swig['extend']
        direct       = swig['direct']
        all_exposed  = extend | direct

        for fname, (ann, priv_type) in fields.items():
            swig_get   = f'{struct_name}_{fname}_get'
            swig_set   = f'{struct_name}_{fname}_set'
            get_target = all_bridges.get(swig_get)
            set_target = all_bridges.get(swig_set)
            get_exists = get_target in known_funcs if get_target else False

            # Rule 1: !accessors:readonly and exposed → must be %immutable
            if ann == 'readonly' and fname in all_exposed:
                if fname not in immutable:
                    errors.append(
                        f'Rule 1: {struct_name}.{fname} is annotated '
                        f'!accessors:readonly but is not declared %%immutable '
                        f'in nvme.i')

            # Rule 3: field in %extend{} → getter bridge must exist and resolve
            if fname in extend:
                if not get_target:
                    errors.append(
                        f'Rule 3: {struct_name}.{fname} is in %%extend{{}} '
                        f'but has no getter bridge '
                        f'(expected a #define for "{swig_get}")')
                elif not get_exists:
                    errors.append(
                        f'Check 4: {struct_name}.{fname}: getter bridge '
                        f'"{swig_get}" maps to "{get_target}" which is not '
                        f'declared in any public header')

            # Rule 2 (error): field has accessor but is direct (bypasses API)
            if fname in direct and get_target and get_exists:
                errors.append(
                    f'Rule 2: {struct_name}.{fname} has a getter accessor '
                    f'("{get_target}") but is exposed as a direct struct '
                    f'member, not via %%extend{{}} — direct access bypasses '
                    f'the public API')

            # Check 6 (warning): has accessor but not exposed at all
            if fname not in all_exposed and get_exists and ann != 'none':
                warnings.append(
                    f'Check 6: {struct_name}.{fname} has a getter accessor '
                    f'("{get_target}") but is not exposed in nvme.i')

            # Check 7 (warning): type in nvme.i differs from private header
            swig_type = swig['types'].get(fname)
            if swig_type is not None and swig_type != priv_type:
                warnings.append(
                    f'Check 7: {struct_name}.{fname} type mismatch: '
                    f'private header "{priv_type}", nvme.i "{swig_type}"')

        # Check 5: %immutable for a field that doesn't exist in the C struct.
        # Skip virtual/renamed fields — those are in extend and already
        # covered by the Check 5 warning below.
        for fname in immutable:
            if fname not in fields and fname not in extend:
                errors.append(
                    f'Check 5: {struct_name}: %%immutable {fname} is declared '
                    f'in nvme.i but "{fname}" does not exist in the C struct')

        # Check 5 (warning variant): field in %extend{} not in private headers
        # (may be a virtual/renamed property — warn rather than error)
        for fname in extend:
            if fname not in fields:
                warnings.append(
                    f'Check 5: {struct_name}: "{fname}" is in %%extend{{}} in '
                    f'nvme.i but does not appear in the C struct '
                    f'(virtual/renamed property?)')

    return errors, warnings


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    args = parse_args()

    if args.private_headers or args.public_headers or args.swig_iface:
        if not (args.private_headers and args.public_headers and args.swig_iface):
            sys.exit('error: --private-header, --public-header, and '
                     '--swig-interface must all be provided together')
        private_hdrs   = [pathlib.Path(f) for f in args.private_headers]
        public_hdrs    = [pathlib.Path(f) for f in args.public_headers]
        swig_iface     = pathlib.Path(args.swig_iface)
        swig_accessors = (pathlib.Path(args.swig_accessors)
                          if args.swig_accessors else None)
    else:
        root = (pathlib.Path(args.root) if args.root
                else pathlib.Path(__file__).resolve().parent.parent)
        src          = root / 'src' / 'nvme'
        libnvme_dir  = root / 'libnvme'
        private_hdrs = [src / 'private.h', src / 'private-fabrics.h']
        public_hdrs  = sorted(h for h in src.glob('*.h')
                              if 'private' not in h.name)
        swig_iface     = libnvme_dir / 'nvme.i'
        swig_accessors = libnvme_dir / 'nvme-swig-accessors.i'

    # Bridges: auto-generated (nvme-swig-accessors.i) + hand-written (nvme.i)
    all_bridges = {}
    if swig_accessors and swig_accessors.exists():
        all_bridges.update(collect_bridges(swig_accessors))
    all_bridges.update(collect_bridges(swig_iface))

    known_funcs     = collect_known_funcs(public_hdrs)
    private_structs = parse_private_headers(private_hdrs)
    swig_data       = parse_nvme_i(swig_iface)

    errors, warnings = run_checks(private_structs, known_funcs,
                                  all_bridges, swig_data)

    for msg in warnings:
        print(f'WARNING: {msg}')
    for msg in errors:
        print(f'ERROR:   {msg}', file=sys.stderr)

    n_structs = sum(1 for s in private_structs if s in swig_data)
    n_fields  = sum(len(private_structs[s]) for s in private_structs
                    if s in swig_data)

    if warnings:
        print(f'\n{len(warnings)} warning(s).')
    if errors:
        print(f'{len(errors)} error(s) found.', file=sys.stderr)
        sys.exit(1)

    print(f'OK: {n_structs} structs, {n_fields} fields checked — '
          f'no errors.')


if __name__ == '__main__':
    main()
