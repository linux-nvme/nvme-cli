#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""
generate_sysfs_accessors.py — Generate an opaque, sysfs-backed struct and its
accessors from a Python dict, instead of parsing an annotated header.

Generates every struct spec dict in the SYSFS_SPECS list of the module
passed via --specs (e.g. sysfs_accessors_specs.py), in one run -- no
per-struct invocation, no per-struct command-line selection.

See ../../design/tooling/generate_sysfs_accessors.md for the full design
rationale (why this is a separate generator from generate_accessors.py,
the CTRL_SYSFS schema, and how to add a new member).

Example usage:
  ./generate_sysfs_accessors.py --out-dir ../../src/nvme \
          --specs ../../src/nvme/sysfs_accessors_specs.py
"""

import argparse
import importlib.util
import io
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location(
    'generate_accessors', os.path.join(_HERE, 'generate_accessors.py')
)
generate_accessors = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(generate_accessors)

Member = generate_accessors.Member

SPDX_C = generate_accessors.SPDX_C
SPDX_H = generate_accessors.SPDX_H
SPDX_LD = generate_accessors.SPDX_LD
BANNER = generate_accessors.BANNER
LD_BANNER = generate_accessors.LD_BANNER


def load_specs(path):
    """Import the module at path and return its SYSFS_SPECS list."""
    spec = importlib.util.spec_from_file_location('sysfs_accessors_specs',
                                                    path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.SYSFS_SPECS


# ---------------------------------------------------------------------------
# dict -> Member
# ---------------------------------------------------------------------------


def build_members(spec):
    """Turn CTRL_SYSFS into a flat list of Member objects.

    field_path uses '->' throughout (e.g. 'sysfs->model'): the owner
    struct holds a pointer to this struct, not an embedded value.
    """
    owner_field = spec['owner_field']
    members = []

    for m in spec['members']:
        # Member.type is the *public* API type, not the storage type:
        # a "char *" field is exposed as "const char *" (see
        # generate_accessors.parse_members's identical translation for
        # annotated headers) -- generate_hdr()'s generic getter/setter
        # emitters use member.type verbatim for the public signature.
        pub_type = 'const char *' if m['type'] == 'char *' else m['type']
        field_path = f"{owner_field}->{m['name']}"
        write_mode = 'generated' if m.get('writable') else 'none'
        members.append(
            Member(
                name=m['name'],
                type_str=pub_type,
                read_mode='generated',
                write_mode=write_mode,
                is_char_array=False,
                is_char_ptr_array=False,
                is_scalar_array=False,
                array_size=None,
                field_path=field_path,
                is_sysfs_lazy=True,
                sysfs_attr=m.get('attr'),
                is_volatile=m.get('volatile', False),
            )
        )

    for g in spec['groups']:
        write_mode = 'generated' if g.get('writable') else 'none'
        for name in g['members']:
            field_path = f"{owner_field}->{name}"
            members.append(
                Member(
                    name=name,
                    type_str='const char *',
                    read_mode='generated',
                    write_mode=write_mode,
                    is_char_array=False,
                    is_char_ptr_array=False,
                    is_scalar_array=False,
                    array_size=None,
                    field_path=field_path,
                    is_sysfs_lazy=True,
                    sysfs_loader=g['loader'],
                )
            )

    return members


def reconfigure_reset_field_paths(spec):
    """Field paths freed by the internal _reset() function (the rescan
    path)."""
    owner_field = spec['owner_field']
    paths = []
    for m in spec['members']:
        if m.get('reconfigure_reset') and not m.get('volatile'):
            paths.append(f"{owner_field}->{m['name']}")
    for g in spec['groups']:
        if g.get('reconfigure_reset'):
            for name in g['members']:
                paths.append(f"{owner_field}->{name}")
    return paths


def final_free_field_paths(spec):
    """Field paths only freed when the controller itself is destroyed."""
    owner_field = spec['owner_field']
    paths = []
    for m in spec['members']:
        if not m.get('reconfigure_reset') and not m.get('volatile'):
            paths.append(f"{owner_field}->{m['name']}")
    for g in spec['groups']:
        if not g.get('reconfigure_reset'):
            for name in g['members']:
                paths.append(f"{owner_field}->{name}")
    return paths


def loader_names(spec):
    seen = []
    for g in spec['groups']:
        if g['loader'] not in seen:
            seen.append(g['loader'])
    return seen


# ---------------------------------------------------------------------------
# Struct definition emission (the piece generate_accessors.py has no
# equivalent for: it always assumes the struct already exists in a
# header it parsed, never emits the definition itself).
# ---------------------------------------------------------------------------


def emit_struct_def(f, spec):
    f.write(f"struct {spec['struct_name']} {{\n")
    for m in spec['members']:
        qualifier = 'volatile ' if m.get('volatile') else ''
        sep = generate_accessors.type_sep(m['type'])
        f.write(f"\t{qualifier}{m['type']}{sep}{m['name']};\n")
    for g in spec['groups']:
        for name in g['members']:
            f.write(f'\tchar *{name};\n')
    f.write('};\n\n')


def emit_alloc_free(f, spec):
    struct_name = spec['struct_name']
    owner_type = spec['owner_type']
    owner_field = spec['owner_field']

    f.write(
        f'struct {struct_name} *{owner_type}_{owner_field}_alloc(void)\n'
        '{\n'
        f'\treturn calloc(1, sizeof(struct {struct_name}));\n'
        '}\n\n'
    )

    f.write(
        f'void {owner_type}_{owner_field}_reset(\n'
        f'\t\tstruct {struct_name} *{owner_field})\n'
        '{\n'
        f'\tif (!{owner_field})\n'
        '\t\treturn;\n\n'
    )
    for path in reconfigure_reset_field_paths(spec):
        name = path.split('->', 1)[1]
        f.write(f'\tSYSFS_FREE({owner_field}->{name});\n')
    f.write('}\n\n')

    f.write(
        f'void {owner_type}_{owner_field}_free(\n'
        f'\t\tstruct {struct_name} *{owner_field})\n'
        '{\n'
        f'\tif (!{owner_field})\n'
        '\t\treturn;\n\n'
    )
    for path in final_free_field_paths(spec):
        name = path.split('->', 1)[1]
        f.write(f'\tSYSFS_FREE({owner_field}->{name});\n')
    f.write(f'\tfree({owner_field});\n')
    f.write('}\n\n')


# ---------------------------------------------------------------------------
# Header
# ---------------------------------------------------------------------------


def generate_header(spec, members):
    struct_name = spec['struct_name']
    owner_type = spec['owner_type']
    owner_field = spec['owner_field']

    buf = io.StringIO()
    buf.write(f'{SPDX_H}\n\n{BANNER}\n\n#pragma once\n\n')
    buf.write(
        f'/* Opaque: defined only in the generated {spec["source"]}. No\n'
        ' * other file may see its layout -- every field is reachable\n'
        ' * only through the accessors below.\n'
        ' */\n'
        f'struct {struct_name};\n\n'
    )

    buf.write(
        '/* Internal: allocate/reset/free the opaque struct. Not part\n'
        ' * of the public API, not listed in any .ld.\n'
        ' */\n'
        f'struct {struct_name} *{owner_type}_{owner_field}_alloc(void);\n'
        f'void {owner_type}_{owner_field}_reset(\n'
        f'\t\tstruct {struct_name} *{owner_field});\n'
        f'void {owner_type}_{owner_field}_free(\n'
        f'\t\tstruct {struct_name} *{owner_field});\n\n'
    )

    buf.write(
        '/* Internal: loader callbacks, one per group above. Each\n'
        ' * fills every member of its group in a single call, returning\n'
        ' * 0 on success or a negative errno. Defined in whichever\n'
        ' * hand-written ctrl-sysfs-custom-*.c matches the build (see\n'
        ' * that file\'s own #ifdef/#include selection).\n'
        ' */\n'
    )
    for fn in loader_names(spec):
        buf.write(f'int {fn}(struct {owner_type} *c);\n')
    buf.write('\n')

    generate_accessors.generate_hdr(buf, '', owner_type, owner_type, members)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Source
# ---------------------------------------------------------------------------


def generate_source(spec, members):
    owner_type = spec['owner_type']
    buf = io.StringIO()
    buf.write(
        f'{SPDX_C}\n\n{BANNER}\n\n'
        '#include <stdio.h>\n'
        '#include <stdlib.h>\n'
        '#include <string.h>\n\n'
        '#include <compiler-attributes.h>\n\n'
        '#include "private.h"\n'
        '#include "private-tree.h"\n'
        f'#include "{spec["header"]}"\n\n'
    )

    emit_struct_def(buf, spec)
    emit_alloc_free(buf, spec)
    generate_accessors.generate_src(buf, '', owner_type, owner_type, members)

    return buf.getvalue()


# ---------------------------------------------------------------------------
# SWIG fragment
# ---------------------------------------------------------------------------


def generate_swig(spec, members):
    """SWIG fragment: extend the already-wrapped struct libnvme_ctrl
    (declared in accessors.i) with these sysfs-backed properties.

    Every member here goes through %extend, unconditionally -- SWIG's
    generated glue can no more reach a field behind the opaque sysfs
    pointer than any other C caller can, the same reason a hand-written
    'custom' accessor in generate_accessors.py's own SWIG emitter needs
    %extend instead of a plain struct field. This is a bespoke, minimal
    emitter rather than a reuse of generate_swig_fragment() -- that
    function's job is declaring a *new* SWIG struct body (for a struct
    it parsed from a header); here there is no new struct, only more
    properties on one SWIG has already wrapped, so its "Pass 2: plain
    field vs. %extend" struct-declaration logic does not apply.
    """
    owner_type = spec['owner_type']
    buf = io.StringIO()
    buf.write(f'/* struct {owner_type} -- sysfs-backed properties */\n')

    for m in members:
        if m.read_mode != 'none':
            buf.write(
                f'%rename({owner_type}_{m.name}_get) ' f'{owner_type}_get_{m.name};\n'
            )
        if m.write_mode != 'none':
            buf.write(
                f'%rename({owner_type}_{m.name}_set) ' f'{owner_type}_set_{m.name};\n'
            )

    buf.write('%{\n')
    for m in members:
        if m.read_mode != 'none':
            buf.write(
                f'\t#define {owner_type}_{m.name}_get ' f'{owner_type}_get_{m.name}\n'
            )
        if m.write_mode != 'none':
            buf.write(
                f'\t#define {owner_type}_{m.name}_set ' f'{owner_type}_set_{m.name}\n'
            )
    buf.write('%}\n\n')

    buf.write(f'%extend struct {owner_type} {{\n')
    for m in members:
        if m.write_mode == 'none':
            buf.write(f'\t%immutable {m.name};\n')
        buf.write(f'\t{m.type} {m.name};\n')
    buf.write('}\n')

    return buf.getvalue()


# ---------------------------------------------------------------------------
# Linker version-script
# ---------------------------------------------------------------------------


def generate_ld(spec, members):
    buf = io.StringIO()
    buf.write(
        f'{SPDX_LD}\n\n{LD_BANNER}\n\n' f"{spec['ld_section']} {{\n" '\tglobal:\n'
    )
    generate_accessors.generate_ld(buf, '', spec['owner_type'], members, None, None)
    buf.write('};\n')
    return buf.getvalue()


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        '--specs',
        required=True,
        help='Path to the Python module providing SYSFS_SPECS, a list of '
        'struct spec dicts (e.g. sysfs_accessors_specs.py)',
    )
    parser.add_argument(
        '--out-dir',
        required=True,
        help='Directory to write generated .c/.h files into',
    )
    parser.add_argument(
        '--ld-out-dir',
        help='Directory to write the generated .ld file into '
        '(default: same as --out-dir)',
    )
    parser.add_argument(
        '--swig-out-dir',
        help='Directory to write the generated .i file into '
        '(default: same as --out-dir)',
    )
    parser.add_argument(
        '--check',
        action='store_true',
        help='Read-only: exit non-zero if output is stale',
    )
    args = parser.parse_args()
    ld_out_dir = args.ld_out_dir or args.out_dir
    swig_out_dir = args.swig_out_dir or args.out_dir

    outputs = {}
    for spec in load_specs(args.specs):
        members = build_members(spec)
        outputs[spec['source']] = (
            args.out_dir, generate_source(spec, members))
        outputs[spec['header']] = (
            args.out_dir, generate_header(spec, members))
        outputs[spec['ld']] = (ld_out_dir, generate_ld(spec, members))
        outputs[spec['swig']] = (swig_out_dir, generate_swig(spec, members))

    stale = []
    for name, (out_dir, content) in outputs.items():
        path = os.path.join(out_dir, name)
        existing = None
        if os.path.exists(path):
            with open(path) as f:
                existing = f.read()
        if existing == content:
            continue
        stale.append(name)
        if not args.check:
            with open(path, 'w') as f:
                f.write(content)

    if args.check:
        if stale:
            print('stale: ' + ', '.join(stale), file=sys.stderr)
            return 1
        print('all sysfs-accessor generated files up to date.')
        return 0

    if stale:
        print('updated: ' + ', '.join(stale))
    else:
        print('all sysfs-accessor generated files unchanged.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
