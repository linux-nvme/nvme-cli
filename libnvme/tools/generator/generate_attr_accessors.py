#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""
generate_attr_accessors.py — Generate an opaque, lazily-loaded struct and
its accessors from a Python dict, instead of parsing an annotated header.

Generates every struct spec dict in the ATTR_SPECS list of the module
passed via --specs (e.g. attr_accessors_specs.py), in one run -- no
per-struct invocation, no per-struct command-line selection.

See ../../design/tooling/generate_attr_accessors.md for the full design
rationale (why this is a separate generator from generate_accessors.py,
the CTRL_ATTRS schema, and how to add a new member).

Generated .c/.h files are written to a 'generated' subdirectory of
--out-dir, keeping them visually separate from the hand-written
*-attrs-custom-*.c files that #include them -- see that same design doc.

Example usage:
  ./generate_attr_accessors.py --out-dir ../../src/nvme \
          --specs ../../src/nvme/attr_accessors_specs.py
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
    """Import the module at path and return its ATTR_SPECS list."""
    spec = importlib.util.spec_from_file_location('attr_accessors_specs',
                                                    path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.ATTR_SPECS


# ---------------------------------------------------------------------------
# dict -> Member
# ---------------------------------------------------------------------------


def _resolve_os(m, os_key):
    """Return m's resolved definition dict for one OS.

    The base dict merged with m[os_key] (the 'linux' or 'win' sub-dict),
    if present -- the override wins on any key it names. 'type' and
    'writable' are never valid inside an override: a member's public
    signature must be identical on every platform, only *where its
    value comes from* (attr / group / absent) may vary.
    """
    resolved = {k: v for k, v in m.items() if k not in ('linux', 'win')}
    resolved.update(m.get(os_key, {}))
    return resolved


def _os_variants_equal(m):
    """True when a member's Linux and Windows resolution are identical.

    Most members are OS-common for free: libnvme_get_{ctrl,ns,path,
    subsys}_attr() already has a Windows implementation that
    unconditionally returns NULL, so a plain 'attr' member needs no
    override at all -- Windows absence falls out of the existing
    attr-reader stub, not from anything this generator does. A member
    only needs 'linux'/'win' keys when its *loader or grouping* itself
    differs (a different function gets called, not just a different
    result from the same one).
    """
    return _resolve_os(m, 'linux') == _resolve_os(m, 'win')


def _pub_type(raw_type):
    """Public API type for a raw storage type.

    A raw pointer storage type is a mutable field the cache fills in
    once (see emit_struct_def()'s matching "already a pointer, don't
    box it again" branch); the public getter hands back a read-only
    view into that cache, so it is exposed as pointer-to-const. "char
    *" -> "const char *" is the original, single-type version of this
    rule (see generate_accessors.parse_members's identical translation
    for annotated headers); generalized here so any raw pointer type
    (e.g. "uint8_t *" for a cached fixed-size byte buffer) gets the
    same treatment, not just strings.
    """
    if raw_type.endswith('*') and not raw_type.startswith('const '):
        return f'const {raw_type}'
    return raw_type


def _make_member(spec, resolved, is_absent=False):
    owner_field = spec['owner_field']
    name = resolved['name']
    # Member.type is the *public* API type, not the storage type --
    # generate_hdr()'s generic getter/setter emitters use member.type
    # verbatim for the public signature. See _pub_type()'s docstring.
    pub_type = _pub_type(resolved['type'])
    field_path = f"{owner_field}->{name}"
    write_mode = 'generated' if resolved.get('writable') else 'none'
    read_mode = 'custom' if resolved.get('custom') else 'generated'
    return Member(
        name=name,
        type_str=pub_type,
        read_mode=read_mode,
        write_mode=write_mode,
        is_char_array=False,
        is_char_ptr_array=False,
        is_scalar_array=False,
        array_size=None,
        field_path=field_path,
        is_attr_lazy=True,
        attr_name=resolved.get('attr'),
        is_volatile=resolved.get('volatile', False),
        attr_reader=spec['attr_reader'],
        is_absent=is_absent,
    )


def build_members(spec):
    """Resolve a spec's members and groups into canonical and per-OS
    Member lists.

    Returns a dict with four keys:
      'all'    -- one Member per member/group-member, using its
                  OS-invariant definition (name/type/writable never
                  vary per OS). Drives the header, .ld and SWIG
                  fragment, none of which depend on where a value
                  actually comes from.
      'shared' -- members whose Linux and Windows resolution is
                  identical; their getter body goes in the spec's
                  shared .c file.
      'linux'  -- the Linux-resolved Member for every member whose
                  resolution differs, for the spec's Linux-only .c file.
      'win'    -- likewise, for the Windows-only .c file.

    field_path uses '->' throughout (e.g. 'attrs->model'): the owner
    struct holds a pointer to this struct, not an embedded value.

    Groups are not yet OS-resolved (spec['groups'] is a single,
    OS-invariant list) -- no current spec needs a group whose loader or
    membership differs per OS. Extend this the same way member
    resolution works, when one does.
    """
    all_members = []
    shared_members = []
    linux_members = []
    win_members = []

    for m in spec['members']:
        base = {k: v for k, v in m.items() if k not in ('linux', 'win')}
        all_members.append(_make_member(spec, base))

        if _os_variants_equal(m):
            shared_members.append(_make_member(spec, _resolve_os(m, 'linux')))
            continue

        for os_key, bucket in (('linux', linux_members), ('win', win_members)):
            resolved = _resolve_os(m, os_key)
            bucket.append(_make_member(spec, resolved,
                                        is_absent=resolved.get('absent', False)))

    owner_field = spec['owner_field']
    for g in spec['groups']:
        write_mode = 'generated' if g.get('writable') else 'none'
        for name in g['members']:
            field_path = f"{owner_field}->{name}"
            member = Member(
                name=name,
                type_str='const char *',
                read_mode='generated',
                write_mode=write_mode,
                is_char_array=False,
                is_char_ptr_array=False,
                is_scalar_array=False,
                array_size=None,
                field_path=field_path,
                is_attr_lazy=True,
                attr_loader=g['loader'],
            )
            all_members.append(member)
            shared_members.append(member)

    return {
        'all': all_members,
        'shared': shared_members,
        'linux': linux_members,
        'win': win_members,
    }


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
        if m.get('volatile'):
            # Never reset() (nothing to invalidate -- every getter call
            # re-reads sysfs), but a volatile *string* member still
            # caches its last value for change comparison and holds a
            # real strdup() allocation that must still be freed at final
            # teardown -- unlike a volatile numeric, a plain value with
            # nothing to leak.
            if m['type'] == 'char *':
                paths.append(f"{owner_field}->{m['name']}")
            continue
        if not m.get('reconfigure_reset'):
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
        if m['type'].endswith('*'):
            # Already a pointer (a string, or a cached fixed-size
            # buffer like eui64/nguid/uuid) -- stored directly, one
            # level, not boxed again. Never volatile-qualified even for
            # a volatile *string* member: "volatile char *" qualifies
            # the pointed-to chars, not the pointer -- not what a
            # re-strdup'd cache wants. The 'volatile' spec flag means
            # "no caching" at the generator level; it does not always
            # map to the C keyword.
            f.write(f"\t{m['type']}{m['name']};\n")
        elif m.get('volatile'):
            # Never cached, so never boxed either: a plain value
            # re-read on every call. Not C `volatile`-qualified: every
            # access is a write (via sscanf(), address taken) followed
            # immediately by a read in the same function, so the
            # compiler can never prove the two don't alias and the
            # keyword's reordering-barrier semantics were never load-
            # bearing here. The 'volatile' spec flag means "no caching"
            # at the generator level only, same as the string-member
            # case above.
            f.write(f"\t{m['type']} {m['name']};\n")
        else:
            # Cached numeric: boxed as TYPE * so the field can carry the
            # same NULL/NO_ATTR/real-value tri-state a string member
            # already uses -- the type itself has no spare value to
            # mean "not loaded" (0 is a legitimate reading).
            f.write(f"\t{m['type']} *{m['name']};\n")
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
        f.write(f'\tATTR_FREE({owner_field}->{name});\n')
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
        f.write(f'\tATTR_FREE({owner_field}->{name});\n')
    f.write(f'\tfree({owner_field});\n')
    f.write('}\n\n')


# ---------------------------------------------------------------------------
# Header
# ---------------------------------------------------------------------------


def generate_header(buf, spec, members):
    """Append one spec's opaque struct decl and prototypes to buf.

    No SPDX/banner/#pragma once here -- every spec shares one merged
    header file, so main() writes that preamble once, not per spec.
    """
    struct_name = spec['struct_name']
    owner_type = spec['owner_type']
    owner_field = spec['owner_field']

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

    loaders = loader_names(spec)
    if loaders:
        buf.write(
            '/* Internal: loader callbacks, one per group above. Each\n'
            ' * fills every member of its group in a single call,\n'
            ' * returning 0 on success or a negative errno. Defined in\n'
            ' * whichever hand-written attr-accessors-custom-*.c matches\n'
            ' * the build (see that file\'s own #ifdef/#include selection).\n'
            ' */\n'
        )
        for fn in loaders:
            buf.write(f'int {fn}(struct {owner_type} *c);\n')
        buf.write('\n')

    generate_accessors.generate_hdr(buf, '', owner_type, owner_type, members)
    buf.write('\n')


# ---------------------------------------------------------------------------
# Source
# ---------------------------------------------------------------------------


def generate_source_shared(buf, spec, shared_members):
    """Append one spec's struct def, alloc/reset/free, and every
    OS-common member's getter/setter to buf.

    No SPDX/banner/includes here -- every spec shares one merged .c
    file, so main() writes that preamble once, not per spec.
    """
    owner_type = spec['owner_type']
    emit_struct_def(buf, spec)
    emit_alloc_free(buf, spec)
    generate_accessors.generate_src(buf, '', owner_type, owner_type,
                                    shared_members)


def generate_source_os(buf, spec, os_members):
    """Append one spec's OS-divergent getters/setters (members whose
    Linux and Windows resolution differ) to buf.

    No SPDX/banner here -- every spec sharing this OS's file shares one
    preamble, written once by main(). No struct definition or
    alloc/reset/free either way -- this file is never compiled on its
    own. It relies on being #include'd *after* the shared .c in the
    hand-written attr-accessors-custom-<os>.c, which brings the struct
    definition and everything else into scope first -- see
    generate_attr_accessors.md's "generated file layout" section for
    the full #include chain.
    """
    owner_type = spec['owner_type']
    generate_accessors.generate_src(buf, '', owner_type, owner_type,
                                    os_members)


# ---------------------------------------------------------------------------
# SWIG fragment
# ---------------------------------------------------------------------------


# Python conversion for each non-string lazy getter type this generator
# has ever needed. Deliberately not a general type->conversion mapper --
# add an entry only when a real member needs it (see generate_accessors.py's
# own restraint on generalizing emit_src_getter_volatile_num's "%ld").
_PY_FROM = {
    'long': 'PyLong_FromLong',
    'int': 'PyLong_FromLong',
    'uint64_t': 'PyLong_FromUnsignedLongLong',
    'enum nvme_csi': 'PyLong_FromLong',
}


def emit_swig_getter_wrapper(owner_type, m):
    """Return the C source of one SWIG getter-property wrapper.

    SWIG's %extend member-variable convention expects a getter shaped
    like ``TYPE owner_member_get(const struct owner *)`` -- the real
    lazy getter's shape (int return, out-param) cannot be wrapped that
    way directly, so this interposes a small function with the name
    SWIG expects, resolving the three states a lazy read can produce:
    a value (return it), -ENOENT (Python None), any other error (raise
    NvmeError). raise_nvme()/NvmeError come from nvme.i's own preamble;
    the %exception block emitted alongside this wrapper is what turns
    the pending Python exception into an actual failure -- see the
    comment above the existing libnvme_ctrl::connect/disconnect/discover
    %exception blocks in nvme.i for why that check cannot live in the
    wrapper body itself.
    """
    fn = f'{owner_type}_get_{m.name}'
    getter = f'{owner_type}_{m.name}_get'

    if m.type == 'const char *':
        return (
            f'\tstatic const char *{getter}(const struct {owner_type} *p)\n'
            '\t{\n'
            '\t\tconst char *val;\n'
            f'\t\tint ret = {fn}(p, &val, NULL);\n\n'
            '\t\tif (ret == 0)\n'
            '\t\t\treturn val;\n'
            '\t\tif (ret == -ENOENT)\n'
            '\t\t\treturn NULL;\n\n'
            '\t\traise_nvme(NvmeError, ret);\n'
            '\t\treturn NULL;\n'
            '\t}\n'
        )

    py_from = _PY_FROM[m.type]
    return (
        f'\tstatic PyObject *{getter}(const struct {owner_type} *p)\n'
        '\t{\n'
        f'\t\t{m.type} val;\n'
        f'\t\tint ret = {fn}(p, &val, 0);\n\n'
        '\t\tif (ret == -ENOENT)\n'
        '\t\t\tPy_RETURN_NONE;\n'
        '\t\tif (ret) {\n'
        '\t\t\traise_nvme(NvmeError, ret);\n'
        '\t\t\treturn NULL;\n'
        '\t\t}\n\n'
        f'\t\treturn {py_from}(val);\n'
        '\t}\n'
    )


def generate_swig(buf, spec, members):
    """Append one spec's SWIG fragment to buf: extend the already-
    wrapped struct libnvme_ctrl (declared in accessors.i) with these
    lazily-loaded properties.

    No SPDX/banner here -- every spec shares one merged .i file, so
    main() writes that preamble once, not per spec.

    Every member here goes through %extend, unconditionally -- SWIG's
    generated glue can no more reach a field behind the opaque attrs
    pointer than any other C caller can, the same reason a hand-written
    'custom' accessor in generate_accessors.py's own SWIG emitter needs
    %extend instead of a plain struct field. This is a bespoke, minimal
    emitter rather than a reuse of generate_swig_fragment() -- that
    function's job is declaring a *new* SWIG struct body (for a struct
    it parsed from a header); here there is no new struct, only more
    properties on one SWIG has already wrapped, so its "Pass 2: plain
    field vs. %extend" struct-declaration logic does not apply.

    Readable members get a hand-written getter wrapper (emit_swig_getter_
    wrapper()) rather than the %rename+#define alias used everywhere
    else in this file -- the real getter's int-return/out-param shape
    does not match SWIG's member-variable property convention, so a
    plain alias cannot work here. Writable members are unaffected: a
    setter's shape has not changed, so it keeps the alias.

    Readable members whose type emit_swig_getter_wrapper() has no
    conversion for (not 'const char *', not in _PY_FROM -- e.g. a
    pointer-to-cached-buffer member like eui64/nguid/uuid) are dropped
    entirely, not just left out of 'readable': declaring a property
    with no matching getter wrapper would reference an undefined SWIG
    symbol. Left unexposed to Python -- no prior pointer-to-buffer
    accessor in this codebase was ever SWIG-wrapped either.
    """
    owner_type = spec['owner_type']

    def _py_representable(m):
        return m.type == 'const char *' or m.type in _PY_FROM

    members = [m for m in members
               if m.read_mode == 'none' or _py_representable(m)]
    readable = [m for m in members if m.read_mode != 'none']
    writable = [m for m in members if m.write_mode != 'none']

    buf.write(f'/* struct {owner_type} -- lazily-loaded properties */\n')

    for m in writable:
        buf.write(
            f'%rename({owner_type}_{m.name}_set) ' f'{owner_type}_set_{m.name};\n'
        )

    buf.write('%{\n')
    for m in writable:
        buf.write(
            f'\t#define {owner_type}_{m.name}_set ' f'{owner_type}_set_{m.name}\n'
        )
    for m in readable:
        buf.write(emit_swig_getter_wrapper(owner_type, m))
    buf.write('%}\n\n')

    for m in readable:
        buf.write(
            f'%exception {owner_type}::{m.name} {{\n'
            '\t$action\n'
            '\tif (PyErr_Occurred()) SWIG_fail;\n'
            '}\n'
        )
    if readable:
        buf.write('\n')

    buf.write(f'%extend struct {owner_type} {{\n')
    for m in members:
        if m.write_mode == 'none':
            buf.write(f'\t%immutable {m.name};\n')
        # SWIG's member-variable wrapper picks its typemap from the type
        # declared here, not from the getter wrapper's own C return type
        # -- for a non-string readable member that wrapper always returns
        # PyObject* (see emit_swig_getter_wrapper()), so the member must
        # be declared PyObject* too, or SWIG force-casts the pointer to
        # the real type (e.g. `(long)a_PyObject_pointer`), corrupting it.
        decl_type = m.type
        if m.read_mode != 'none' and m.type != 'const char *':
            decl_type = 'PyObject *'
        buf.write(f'\t{decl_type} {m.name};\n')
    buf.write('}\n\n')


# ---------------------------------------------------------------------------
# Linker version-script
# ---------------------------------------------------------------------------


def generate_ld(buf, spec, members):
    """Append one spec's exported symbols to buf.

    No SPDX/banner/version-script tag here -- every spec shares one
    merged .ld file under one tag, written once by main().
    """
    generate_accessors.generate_ld(buf, '', spec['owner_type'], members, None, None)


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        '--specs',
        required=True,
        help='Path to the Python module providing ATTR_SPECS, a list of '
        'struct spec dicts (e.g. attr_accessors_specs.py)',
    )
    parser.add_argument(
        '--out-dir',
        required=True,
        help="Directory whose 'generated' subdirectory receives the "
        'generated .c/.h files',
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
    # .c/.h are the only fully generator-owned outputs (never hand-
    # touched, unlike the hand-maintained .ld or the *-custom-*.c files
    # that #include them) -- kept in their own subdirectory so they
    # don't clutter src/nvme/ alongside hand-written files.
    generated_dir = os.path.join(args.out_dir, 'generated')
    ld_out_dir = args.ld_out_dir or args.out_dir
    swig_out_dir = args.swig_out_dir or args.out_dir

    specs = load_specs(args.specs)

    # Every spec shares one merged .c/.h/.ld/.i file -- enforced here so
    # a future spec with a typo'd filename fails loudly instead of
    # silently splitting off its own file.
    for key in ('source', 'header', 'ld', 'swig', 'ld_section'):
        values = {spec[key] for spec in specs}
        assert len(values) == 1, (
            f"every ATTR_SPECS entry must share the same {key!r} "
            f"(got {sorted(values)})")

    src_name = specs[0]['source']
    hdr_name = specs[0]['header']
    ld_name = specs[0]['ld']
    ld_section = specs[0]['ld_section']
    swig_name = specs[0]['swig']

    c_buf = io.StringIO()
    c_buf.write(
        f'{SPDX_C}\n\n{BANNER}\n\n'
        '#include <errno.h>\n'
        '#include <stdio.h>\n'
        '#include <stdlib.h>\n'
        '#include <string.h>\n\n'
        '#include <shared/compiler-attributes-util.h>\n\n'
        '#include "../private.h"\n'
        '#include "../private-tree.h"\n'
        f'#include "{hdr_name}"\n\n'
    )

    h_buf = io.StringIO()
    h_buf.write(f'{SPDX_H}\n\n{BANNER}\n\n#pragma once\n\n')

    ld_buf = io.StringIO()
    ld_buf.write(f'{SPDX_LD}\n\n{LD_BANNER}\n\n{ld_section} {{\n\tglobal:\n')

    swig_buf = io.StringIO()
    swig_buf.write(f'{SPDX_C}\n\n{BANNER}\n\n')

    # Per-OS bodies, keyed by output filename (only specs with real
    # OS-divergent members contribute -- today just PATH_ATTRS).
    os_bufs = {}

    for spec in specs:
        resolved = build_members(spec)
        generate_source_shared(c_buf, spec, resolved['shared'])
        if resolved['linux']:
            name = spec['source_linux']
            generate_source_os(
                os_bufs.setdefault(name, io.StringIO()),
                spec, resolved['linux'])
        if resolved['win']:
            name = spec['source_win']
            generate_source_os(
                os_bufs.setdefault(name, io.StringIO()),
                spec, resolved['win'])
        generate_header(h_buf, spec, resolved['all'])
        generate_ld(ld_buf, spec, resolved['all'])
        generate_swig(swig_buf, spec, resolved['all'])

    ld_buf.write('};\n')

    outputs = {
        src_name: (generated_dir, c_buf.getvalue()),
        hdr_name: (generated_dir, h_buf.getvalue()),
        ld_name: (ld_out_dir, ld_buf.getvalue()),
        swig_name: (swig_out_dir, swig_buf.getvalue()),
    }
    for name, buf in os_bufs.items():
        outputs[name] = (
            generated_dir, f'{SPDX_C}\n\n{BANNER}\n\n' + buf.getvalue())

    if not args.check:
        os.makedirs(generated_dir, exist_ok=True)

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
        print('all attr-accessor generated files up to date.')
        return 0

    if stale:
        print('updated: ' + ', '.join(stale))
    else:
        print('all attr-accessor generated files unchanged.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
