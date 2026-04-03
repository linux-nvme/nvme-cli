#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""
generate-accessors.py — Generate setter/getter accessor functions for C structs.

This file is part of libnvme.
Copyright (c) 2025, Dell Technologies Inc. or its subsidiaries.
Authors: Martin Belanger <Martin.Belanger@dell.com>

Parses C header files and produces:
  accessors.h   — function declarations with KernelDoc comments
  accessors.c   — function implementations
  accessors.ld  — linker version-script entries

Limitations:
  - Does not support typedef struct.
  - Does not support struct within struct.

Struct inclusion — annotate the opening brace line of the struct:
  struct nvme_ctrl { /*!generate-accessors*/
  struct nvme_ctrl { //!generate-accessors

Member exclusion — annotate the member declaration line:
  char *model; /*!accessors:none*/
  char *model; //!accessors:none

Read-only members (getter only, setter suppressed):
  - Members declared with the 'const' qualifier, or
  - Annotate the member declaration line:
      char *state; /*!accessors:readonly*/
      char *state; //!accessors:readonly

Example usage:
  ./generate-accessors.py private.h
  ./generate-accessors.py --prefix nvme_ private.h
"""

import argparse
import glob as glob_module
import io
import os
import re
import sys

# ---------------------------------------------------------------------------
# Output format — controls getter/setter function naming.
#   {pre} = "{prefix}{struct_name}",  {mem} = member name
#   Alternate style: "{pre}_{mem}_set" / "{pre}_{mem}_get"
# ---------------------------------------------------------------------------
SET_FMT = "{pre}_set_{mem}"
GET_FMT = "{pre}_get_{mem}"

SPDX_C  = "// SPDX-License-Identifier: LGPL-2.1-or-later"
SPDX_H  = "/* SPDX-License-Identifier: LGPL-2.1-or-later */"
SPDX_LD = "# SPDX-License-Identifier: LGPL-2.1-or-later"

BANNER = (
    "/**\n"
    " * This file is part of libnvme.\n"
    " *\n"
    " * Copyright (c) 2025, Dell Technologies Inc. or its subsidiaries.\n"
    " * Authors: Martin Belanger <Martin.Belanger@dell.com>\n"
    " *\n"
    " *   ____                           _           _    ____          _\n"
    " *  / ___| ___ _ __   ___ _ __ __ _| |_ ___  __| |  / ___|___   __| | ___\n"
    " * | |  _ / _ \\ '_ \\ / _ \\ '__/ _` | __/ _ \\/ _` | | |   / _ \\ / _` |/ _ \\\n"
    " * | |_| |  __/ | | |  __/ | | (_| | ||  __/ (_| | | |__| (_) | (_| |  __/\n"
    " *  \\____|\\___|_| |_|\\___|_|  \\__,_|\\__\\___|\\__,_|  \\____\\___/ \\__,_|\\___|\n"
    " *\n"
    " * Auto-generated struct member accessors (setter/getter)\n"
    " *\n"
    " * To update run: meson compile -C [BUILD-DIR] update-accessors\n"
    " * Or:            make update-accessors\n"
    " */"
)

# ---------------------------------------------------------------------------
# Regular expressions
# ---------------------------------------------------------------------------

# Matches:  struct name { body };
# [^}]* matches any character except '}', including newlines.
STRUCT_RE = re.compile(
    r'struct\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{([^}]*)\}\s*;'
)

# Matches:  [const] char name[size];
CHAR_ARRAY_RE = re.compile(
    r'^(const\s+)?char\s+([A-Za-z_][A-Za-z0-9_]*)\s*\[\s*([A-Za-z0-9_]+)\s*\]\s*;'
)

# Matches:  [const] type[*] name;
MEMBER_RE = re.compile(
    r'^(const\s+)?([A-Za-z_][A-Za-z0-9_]*)([*\s]+)([A-Za-z_][A-Za-z0-9_]*)\s*;'
)


# ---------------------------------------------------------------------------
# Annotation helpers
# ---------------------------------------------------------------------------

def has_annotation(text, annotation):
    """Return True if *text* contains /*!annotation*/ or //!annotation."""
    return f'/*!{annotation}*/' in text or f'//!{annotation}' in text


def strip_block_comments(text):
    """Remove /* ... */ block comments (replaced with a single space each)."""
    return re.sub(r'/\*.*?\*/', ' ', text, flags=re.DOTALL)


def strip_inline_comment(line):
    """Remove a // comment and everything after it."""
    idx = line.find('//')
    return line[:idx] if idx >= 0 else line


# ---------------------------------------------------------------------------
# Misc helpers
# ---------------------------------------------------------------------------

def sanitize_identifier(s):
    """Replace characters that are invalid in a C identifier with '_'."""
    if not s:
        return s
    chars = list(s)
    if not (chars[0].isalpha() or chars[0] == '_'):
        chars[0] = '_'
    for i in range(1, len(chars)):
        if not (chars[i].isalnum() or chars[i] == '_'):
            chars[i] = '_'
    return ''.join(chars)


def type_sep(type_str):
    """Return '' when *type_str* ends with '*', else ' '.

    checkpatch.pl requires that '*' in a pointer return type is attached to
    the function name, not the type keyword (e.g. ``const char *foo(...)``
    not ``const char * foo(...)``).
    """
    return '' if type_str.endswith('*') else ' '


def makedirs_for(filepath):
    """Create all intermediate directories needed to hold *filepath*."""
    os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)


# ---------------------------------------------------------------------------
# Line-length helpers
#
# checkpatch.pl enforces an 80-column limit.  Because generated function
# names vary in length we must measure before committing to a layout.
#
# fits_80(s)          — True when len(s) <= 80.
# fits_80_ntabs(n, s) — True when the line would be <= 80 visible columns
#                       given that it starts with n hard tabs (each tab
#                       expands to 8 spaces, costing 7 extra visible columns
#                       beyond the 1 byte that len() counts).
# ---------------------------------------------------------------------------

def fits_80(s):
    return len(s) <= 80


def fits_80_ntabs(n, s):
    return len(s) + n * 7 <= 80


# ---------------------------------------------------------------------------
# Member data class
# ---------------------------------------------------------------------------

class Member:
    """Represents one member of a parsed C struct."""

    __slots__ = ('name', 'type', 'is_const', 'is_char_array', 'array_size')

    def __init__(self, name, type_str, is_const, is_char_array, array_size):
        self.name = name
        self.type = type_str        # e.g. "const char *", "int", "__u32"
        self.is_const = is_const    # True → getter only (no setter generated)
        self.is_char_array = is_char_array
        self.array_size = array_size  # only valid when is_char_array is True


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def parse_members(struct_name, raw_body, verbose):
    """Parse *raw_body* and return a list of Member objects.

    Annotations are detected on the **raw** (un-stripped) line so that
    comment masking cannot hide them.  Comments are stripped only afterwards,
    for regex matching.
    """
    members = []

    for raw_line in raw_body.splitlines():
        # ----------------------------------------------------------------
        # Annotation checks on the raw line — BEFORE stripping comments.
        # ----------------------------------------------------------------
        if has_annotation(raw_line, 'accessors:none'):
            continue
        readonly = has_annotation(raw_line, 'accessors:readonly')

        # ----------------------------------------------------------------
        # Strip comments for member-declaration parsing.
        # ----------------------------------------------------------------
        clean = strip_inline_comment(strip_block_comments(raw_line)).strip()

        if not clean or ';' not in clean:
            continue
        if 'static' in clean or 'struct' in clean:
            continue

        # --- char array: [const] char name[size]; -----------------------
        m = CHAR_ARRAY_RE.match(clean)
        if m:
            members.append(Member(
                name=m.group(2),
                type_str='const char *',
                is_const=readonly or bool(m.group(1)),
                is_char_array=True,
                array_size=m.group(3),
            ))
            continue

        # --- general member: [const] type[*] name; ----------------------
        m = MEMBER_RE.match(clean)
        if m:
            is_const_qual = bool(m.group(1))
            type_base = m.group(2)
            ptr_part  = m.group(3)
            name      = m.group(4)

            is_ptr = '*' in ptr_part
            if is_ptr:
                if type_base != 'char':
                    continue  # only char* pointers are supported
                type_str = 'const char *'
            else:
                type_str = type_base

            members.append(Member(
                name=name,
                type_str=type_str,
                is_const=readonly or is_const_qual,
                is_char_array=False,
                array_size=None,
            ))

    return members


def parse_file(text, verbose):
    """Return list of (struct_name, [Member]) tuples found in *text*.

    Only structs annotated with ``/*!generate-accessors*/`` or
    ``//!generate-accessors`` as the first token inside the opening brace
    are processed.
    """
    result = []

    for match in STRUCT_RE.finditer(text):
        struct_name = match.group(1)
        raw_body    = match.group(2)

        # The annotation must be the first token after the opening '{'.
        first_token = raw_body.lstrip()
        if not (first_token.startswith('/*!generate-accessors*/') or
                first_token.startswith('//!generate-accessors')):
            continue

        members = parse_members(struct_name, raw_body, verbose)

        if verbose and members:
            print(f"Found struct: {struct_name} ({len(members)} members)")

        if members:
            result.append((struct_name, members))

    return result


# ---------------------------------------------------------------------------
# Header (*.h) code emitters
# ---------------------------------------------------------------------------

def _set_name(prefix, sname, mname):
    return SET_FMT.format(pre=f'{prefix}{sname}', mem=mname)


def _get_name(prefix, sname, mname):
    return GET_FMT.format(pre=f'{prefix}{sname}', mem=mname)


def emit_hdr_setter_str(f, prefix, sname, mname, is_dyn_str):
    """Emit a header declaration for a string setter."""
    f.write(
        f'/**\n'
        f' * {_set_name(prefix, sname, mname)}() - Set {mname}.\n'
        f' * @p: The &struct {sname} instance to update.\n'
    )
    if is_dyn_str:
        f.write(
            f' * @{mname}: New string; a copy is stored. Pass NULL to clear.\n'
        )
    else:
        f.write(
            f' * @{mname}: New string; truncated to fit, always NUL-terminated.\n'
        )
    f.write(' */\n')

    single = (f'void {_set_name(prefix, sname, mname)}'
              f'(struct {sname} *p, const char *{mname});')
    if fits_80(single):
        f.write(single + '\n\n')
    else:
        f.write(
            f'void {_set_name(prefix, sname, mname)}(\n'
            f'\t\tstruct {sname} *p,\n'
            f'\t\tconst char *{mname});\n\n'
        )


def emit_hdr_setter_val(f, prefix, sname, mname, mtype):
    """Emit a header declaration for a value setter."""
    f.write(
        f'/**\n'
        f' * {_set_name(prefix, sname, mname)}() - Set {mname}.\n'
        f' * @p: The &struct {sname} instance to update.\n'
        f' * @{mname}: Value to assign to the {mname} field.\n'
        f' */\n'
    )

    single = (f'void {_set_name(prefix, sname, mname)}'
              f'(struct {sname} *p, {mtype} {mname});')
    if fits_80(single):
        f.write(single + '\n\n')
    else:
        f.write(
            f'void {_set_name(prefix, sname, mname)}(\n'
            f'\t\tstruct {sname} *p,\n'
            f'\t\t{mtype} {mname});\n\n'
        )


def emit_hdr_getter(f, prefix, sname, mname, mtype, is_dyn_str):
    """Emit a header declaration for a getter."""
    tail = ', or NULL if not set.' if is_dyn_str else '.'
    f.write(
        f'/**\n'
        f' * {_get_name(prefix, sname, mname)}() - Get {mname}.\n'
        f' * @p: The &struct {sname} instance to query.\n'
        f' *\n'
        f' * Return: The value of the {mname} field{tail}\n'
        f' */\n'
    )

    sep    = type_sep(mtype)
    single = (f'{mtype}{sep}{_get_name(prefix, sname, mname)}'
              f'(const struct {sname} *p);')
    if fits_80(single):
        f.write(single + '\n\n')
    else:
        f.write(
            f'{mtype}{sep}{_get_name(prefix, sname, mname)}(\n'
            f'\t\tconst struct {sname} *p);\n\n'
        )


def generate_hdr(f, prefix, struct_name, members):
    """Write header declarations for all members of one struct."""
    for member in members:
        is_dyn_str = (not member.is_char_array and
                      member.type == 'const char *')
        if not member.is_const:
            if member.is_char_array or is_dyn_str:
                emit_hdr_setter_str(f, prefix, struct_name,
                                    member.name, is_dyn_str)
            else:
                emit_hdr_setter_val(f, prefix, struct_name,
                                    member.name, member.type)
        emit_hdr_getter(f, prefix, struct_name,
                        member.name, member.type, is_dyn_str)


# ---------------------------------------------------------------------------
# Source (*.c) code emitters
# ---------------------------------------------------------------------------

PUB = '__public '


def emit_src_setter_dynstr(f, prefix, sname, mname):
    """Emit a dynamic-string setter (free old + strdup new)."""
    sig = (f'{PUB}void {_set_name(prefix, sname, mname)}'
           f'(struct {sname} *p, const char *{mname})')
    if fits_80(sig):
        f.write(sig + '\n')
    else:
        f.write(
            f'{PUB}void {_set_name(prefix, sname, mname)}(\n'
            f'\t\tstruct {sname} *p,\n'
            f'\t\tconst char *{mname})\n'
        )

    f.write(f'{{\n\tfree(p->{mname});\n')
    body = f'\tp->{mname} = {mname} ? strdup({mname}) : NULL;'
    if fits_80_ntabs(1, body):
        f.write(body + '\n')
    else:
        f.write(f'\tp->{mname} =\n\t\t{mname} ? strdup({mname}) : NULL;\n')
    f.write('}\n\n')


def emit_src_setter_chararray(f, prefix, sname, mname, array_size):
    """Emit a fixed char-array setter (snprintf)."""
    sig = (f'{PUB}void {_set_name(prefix, sname, mname)}'
           f'(struct {sname} *p, const char *{mname})')
    if fits_80(sig):
        f.write(sig + '\n')
    else:
        f.write(
            f'{PUB}void {_set_name(prefix, sname, mname)}(\n'
            f'\t\tstruct {sname} *p,\n'
            f'\t\tconst char *{mname})\n'
        )

    if array_size.isdigit():
        f.write(
            f'{{\n\tsnprintf(p->{mname}, {int(array_size)}, "%s", {mname});\n}}\n\n'
        )
    else:
        f.write(
            f'{{\n\tsnprintf(p->{mname}, {array_size}, "%s", {mname});\n}}\n\n'
        )


def emit_src_setter_val(f, prefix, sname, mname, mtype):
    """Emit a value setter (direct assignment)."""
    sig = (f'{PUB}void {_set_name(prefix, sname, mname)}'
           f'(struct {sname} *p, {mtype} {mname})')
    if fits_80(sig):
        f.write(
            sig + '\n'
            f'{{\n\tp->{mname} = {mname};\n}}\n\n'
        )
    else:
        f.write(
            f'{PUB}void {_set_name(prefix, sname, mname)}(\n'
            f'\t\tstruct {sname} *p,\n'
            f'\t\t{mtype} {mname})\n'
            f'{{\n\tp->{mname} = {mname};\n}}\n\n'
        )


def emit_src_getter(f, prefix, sname, mname, mtype):
    """Emit a getter (return member value)."""
    sep = type_sep(mtype)
    sig = (f'{PUB}{mtype}{sep}{_get_name(prefix, sname, mname)}'
           f'(const struct {sname} *p)')
    if fits_80(sig):
        f.write(
            sig + '\n'
            f'{{\n\treturn p->{mname};\n}}\n\n'
        )
    else:
        f.write(
            f'{PUB}{mtype}{sep}{_get_name(prefix, sname, mname)}(\n'
            f'\t\tconst struct {sname} *p)\n'
            f'{{\n\treturn p->{mname};\n}}\n\n'
        )


def generate_src(f, prefix, struct_name, members):
    """Write source implementations for all members of one struct."""
    for member in members:
        if not member.is_const:
            is_dyn_str = (not member.is_char_array and
                          member.type == 'const char *')
            if is_dyn_str:
                emit_src_setter_dynstr(f, prefix, struct_name, member.name)
            elif member.is_char_array:
                emit_src_setter_chararray(f, prefix, struct_name,
                                          member.name, member.array_size)
            else:
                emit_src_setter_val(f, prefix, struct_name,
                                    member.name, member.type)
        emit_src_getter(f, prefix, struct_name, member.name, member.type)


# ---------------------------------------------------------------------------
# Linker script (*.ld) emitter
# ---------------------------------------------------------------------------

def generate_ld(f, prefix, struct_name, members):
    """Write linker version-script entries for all members of one struct."""
    for member in members:
        f.write(
            f'\t\t{_get_name(prefix, struct_name, member.name)};\n'
            f'\t\t{_set_name(prefix, struct_name, member.name)};\n'
        )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description='Generate C struct accessor functions.',
        add_help=False,   # -h is reserved for --h-out
    )
    parser.add_argument('-c', '--c-out',   default='accessors.c',
                        dest='c_fname',   metavar='FILE',
                        help='Generated *.c file. Default: accessors.c')
    parser.add_argument('-h', '--h-out',   default='accessors.h',
                        dest='h_fname',   metavar='FILE',
                        help='Generated *.h file. Default: accessors.h')
    parser.add_argument('-l', '--ld-out',  default='accessors.ld',
                        dest='l_fname',   metavar='FILE',
                        help='Generated *.ld file. Default: accessors.ld')
    parser.add_argument('-p', '--prefix',  default='',
                        dest='prefix',    metavar='STR',
                        help='Prefix prepended to every generated function name.')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Verbose output.')
    parser.add_argument('-H', '--help',    action='help',
                        default=argparse.SUPPRESS,
                        help='Show this message and exit.')
    parser.add_argument('headers', nargs='+',
                        help='Header files to parse (wildcards accepted).')
    args = parser.parse_args()

    # Expand wildcards in the header file arguments.
    header_files = []
    for pattern in args.headers:
        expanded = glob_module.glob(pattern)
        if expanded:
            header_files.extend(os.path.realpath(p) for p in sorted(expanded))
        else:
            print(f"Warning: No match for {pattern}", file=sys.stderr)

    if not header_files:
        print("error: no input headers found", file=sys.stderr)
        sys.exit(1)

    # -----------------------------------------------------------------------
    # Pass 1 — parse all header files, accumulate generated fragments.
    # -----------------------------------------------------------------------
    files_to_include = []   # basenames of headers that contributed structs
    forward_declares = []   # struct names needing forward declarations
    hdr_parts = []          # fragments for accessors.h
    src_parts = []          # fragments for accessors.c
    ld_parts  = []          # fragments for accessors.ld

    for in_hdr in header_files:
        if args.verbose:
            print(f"\nProcessing {in_hdr}")

        try:
            with open(in_hdr) as f:
                text = f.read()
        except OSError as e:
            print(f"error: cannot read '{in_hdr}': {e}", file=sys.stderr)
            sys.exit(1)

        structs = parse_file(text, args.verbose)

        if not structs:
            if args.verbose:
                print(f"No annotated structs found in {in_hdr}.")
            continue

        files_to_include.append(os.path.basename(in_hdr))

        for struct_name, members in structs:
            forward_declares.append(struct_name)

            section_banner = (
                f'/****************************************************************************\n'
                f' * Accessors for: struct {struct_name}\n'
                f' ****************************************************************************/\n'
                f'\n'
            )

            hdr_buf = io.StringIO()
            hdr_buf.write(section_banner)
            generate_hdr(hdr_buf, args.prefix, struct_name, members)
            hdr_parts.append(hdr_buf.getvalue())

            src_buf = io.StringIO()
            src_buf.write(section_banner)
            generate_src(src_buf, args.prefix, struct_name, members)
            src_parts.append(src_buf.getvalue())

            ld_buf = io.StringIO()
            generate_ld(ld_buf, args.prefix, struct_name, members)
            ld_parts.append(ld_buf.getvalue())

    # -----------------------------------------------------------------------
    # Pass 2 — write output files.
    # -----------------------------------------------------------------------

    # --- accessors.h -------------------------------------------------------
    guard = '_' + sanitize_identifier(os.path.basename(args.h_fname).upper()) + '_'

    makedirs_for(args.h_fname)
    with open(args.h_fname, 'w') as f:
        f.write(
            f'{SPDX_H}\n'
            f'\n'
            f'{BANNER}\n'
            f'#ifndef {guard}\n'
            f'#define {guard}\n'
            f'\n'
            f'#include <stdlib.h>\n'
            f'#include <string.h>\n'
            f'#include <stdbool.h>\n'
            f'#include <stdint.h>\n'
            f'#include <platform/types.h> /* __u32, __u64, etc. */\n'
            f'\n'
        )
        f.write('/* Forward declarations. These are internal (opaque) structs. */\n')
        for s in forward_declares:
            f.write(f'struct {s};\n')
        f.write('\n')
        f.write(''.join(hdr_parts))
        f.write(f'#endif /* {guard} */\n')

    # --- accessors.c -------------------------------------------------------
    makedirs_for(args.c_fname)
    with open(args.c_fname, 'w') as f:
        f.write(
            f'{SPDX_C}\n'
            f'\n'
            f'{BANNER}\n'
            f'#include <stdlib.h>\n'
            f'#include <string.h>\n'
            f'#include "{os.path.basename(args.h_fname)}"\n'
            f'\n'
        )
        for fname in files_to_include:
            f.write(f'#include "{fname}"\n')
        f.write('#include "compiler_attributes.h"\n')
        f.write('\n')
        f.write(''.join(src_parts))

    # --- accessors.ld ------------------------------------------------------
    makedirs_for(args.l_fname)
    with open(args.l_fname, 'w') as f:
        f.write(
            f'{SPDX_LD}\n'
            f'\n'
            f'{BANNER}\n'
            f'\n'
            f'LIBNVME_ACCESSORS_3 {{\n'
            f'\tglobal:\n'
        )
        f.write(''.join(ld_parts))
        f.write('};\n')

    if args.verbose:
        print(f"\nGenerated {args.h_fname} and {args.c_fname}")


if __name__ == '__main__':
    main()
