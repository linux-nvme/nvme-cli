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

Annotations use // line-comment style.  After '//', each '!keyword' token
(optionally followed by ':qualifier' or ':VALUE') is a command.  Multiple
annotations can appear in one comment:
  struct nvme_ctrl { //!generate-accessors !generate-lifecycle

Struct inclusion — annotate the opening brace line of the struct.
The optional mode qualifier sets the default for all members of the struct:
  struct nvme_ctrl { //!generate-accessors            — default: both getter and setter
  struct nvme_ctrl { //!generate-accessors:none       — default: no accessors
  struct nvme_ctrl { //!generate-accessors:readonly   — default: getter only
  struct nvme_ctrl { //!generate-accessors:writeonly  — default: setter only

Lifecycle (constructor + destructor) — annotate the opening brace line:
  struct nvme_ctrl { //!generate-lifecycle
The two annotations are independent and may appear in the same comment:
  struct nvme_ctrl { //!generate-accessors !generate-lifecycle

Lifecycle member exclusion — annotate the member declaration line:
  char *cache; //!lifecycle:none     — skip this member in the destructor

Defaults — annotate the member declaration line with a value to assign:
  int max_retries;  //!default:6
  __u8 lsp;         //!default:NVMF_LOG_DISC_LSP_NONE
  char *transport;  //!default:"tcp"
When any member carries a default annotation, an init_defaults function is
generated. If generate-lifecycle is also present, the constructor calls it.
The init_defaults function is also useful standalone to re-initialise a
struct to its defaults without reallocating it.
For scalar members the value is assigned directly. For char* members the
generated code avoids unnecessary work by comparing the current value with
the default first (strcmp); if they differ it frees the old value and
strdup()s the new one. const char* members are assigned directly (no
strdup) since they are assumed to point to externally owned storage.

Member exclusion — annotate the member declaration line:
  char *model; //!accessors:none

Read-only members (getter only, setter suppressed):
  - Members declared with the 'const' qualifier, or
  - Annotate the member declaration line:
      char *state; //!accessors:readonly

Write-only members (setter only, getter suppressed):
  - Annotate the member declaration line:
      char *state; //!accessors:writeonly

Both getter and setter (override a restrictive struct-level default):
  - Annotate the member declaration line:
      char *state; //!accessors:readwrite

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

LD_BANNER = (
    "/**\n"
    " * This file is part of libnvme.\n"
    " *\n"
    " * Copyright (c) 2025, Dell Technologies Inc. or its subsidiaries.\n"
    " * Authors: Martin Belanger <Martin.Belanger@dell.com>\n"
    " *\n"
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

def _comment_text(text):
    """Return the portion of *text* after the first '//', or None.

    This is the raw comment payload — the text the parser scans for
    ``!keyword`` annotation tokens.
    """
    idx = text.find('//')
    return text[idx + 2:] if idx >= 0 else None


def has_annotation(text, annotation):
    """Return True if *text* carries ``!annotation`` inside a ``//`` comment.

    Annotations are ``!keyword`` tokens that appear anywhere after ``//`` on
    the same line.  A single comment may carry several annotations, e.g.::

        struct foo { //!generate-accessors !generate-lifecycle

    The match is token-delimited: ``!generate-accessors`` will not match
    inside ``!generate-accessors:none``.
    """
    comment = _comment_text(text)
    if comment is None:
        return False
    return bool(re.search(
        rf'!{re.escape(annotation)}(?=[\s!]|$)', comment))


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


def kdoc_summary(fn, *descriptions):
    """Return a KernelDoc summary line that fits within 80 columns.

    Tries each description in order and returns the first that fits as
    ' * fn() - description'.  Falls back to ' * fn()' if none fit.
    """
    for desc in descriptions:
        line = f' * {fn}() - {desc}'
        if fits_80(line):
            return line
    return f' * {fn}()'


# ---------------------------------------------------------------------------
# Member data class
# ---------------------------------------------------------------------------

class Member:
    """Represents one member of a parsed C struct."""

    __slots__ = ('name', 'type', 'gen_getter', 'gen_setter',
                 'is_char_array', 'is_char_ptr_array', 'array_size')

    def __init__(self, name, type_str, gen_getter, gen_setter,
                 is_char_array, is_char_ptr_array, array_size):
        self.name = name
        self.type = type_str          # e.g. "const char *", "int", "__u32"
        self.gen_getter = gen_getter  # True → emit getter
        self.gen_setter = gen_setter  # True → emit setter
        self.is_char_array = is_char_array
        self.is_char_ptr_array = is_char_ptr_array
        self.array_size = array_size  # only for fixed-size char arrays (char[N])


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def parse_members(struct_name, raw_body, struct_mode, verbose):
    """Parse *raw_body* and return a list of Member objects.

    *struct_mode* is the default access mode for all members of this struct,
    derived from the generate-accessors annotation qualifier:
      'both'      — generate getter and setter (default when no qualifier)
      'readonly'  — generate getter only
      'writeonly' — generate setter only
      'none'      — generate nothing unless a per-member annotation overrides

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

        if has_annotation(raw_line, 'accessors:readwrite'):
            member_mode = 'both'
        elif has_annotation(raw_line, 'accessors:readonly'):
            member_mode = 'readonly'
        elif has_annotation(raw_line, 'accessors:writeonly'):
            member_mode = 'writeonly'
        else:
            member_mode = struct_mode

        gen_getter = member_mode in ('both', 'readonly')
        gen_setter = member_mode in ('both', 'writeonly')

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
            is_const_qual = bool(m.group(1))
            members.append(Member(
                name=m.group(2),
                type_str='const char *',
                gen_getter=gen_getter,
                gen_setter=gen_setter and not is_const_qual,
                is_char_array=True,
                is_char_ptr_array=False,
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

            ptr_depth = ptr_part.count('*')
            if ptr_depth:
                if type_base != 'char':
                    continue  # only char* pointers are supported
                if ptr_depth == 1:
                    type_str = 'const char *'
                elif ptr_depth == 2:
                    type_str = 'const char *const *'
                else:
                    continue
            else:
                type_str = type_base

            members.append(Member(
                name=name,
                type_str=type_str,
                gen_getter=gen_getter,
                gen_setter=gen_setter and not is_const_qual,
                is_char_array=False,
                is_char_ptr_array=(ptr_depth == 2),
                array_size=None,
            ))

    return members


_VALID_MODES = frozenset(('both', 'none', 'readonly', 'writeonly'))


def parse_struct_annotation(raw_body):
    """Return the default mode for a struct from its generate-accessors annotation.

    Recognises the ``//!`` comment style with an optional mode qualifier:
      //!generate-accessors             → 'both'
      //!generate-accessors:none        → 'none'
      //!generate-accessors:readonly    → 'readonly'
      //!generate-accessors:writeonly   → 'writeonly'

    Returns None when the annotation is absent.
    Prints a warning and falls back to 'both' for unrecognised qualifiers.
    """
    first_token = raw_body.lstrip()

    m = re.match(r'//!generate-accessors(?::([a-z]+))?', first_token)
    if m:
        qualifier = m.group(1) or 'both'
        if qualifier not in _VALID_MODES:
            print(
                f"warning: unknown generate-accessors qualifier "
                f"'{qualifier}'; valid values are: "
                f"{', '.join(sorted(_VALID_MODES))}. "
                f"Defaulting to 'both'.",
                file=sys.stderr,
            )
            qualifier = 'both'
        return qualifier

    return None


def parse_lifecycle_annotation(raw_body):
    """Return True when *raw_body* carries a ``!generate-lifecycle`` annotation.

    The annotation must appear inside a ``//`` comment on the struct's opening
    brace line.  It may share the comment with other annotations::

        struct foo { //!generate-accessors !generate-lifecycle
    """
    for line in raw_body.splitlines():
        if has_annotation(line, 'generate-lifecycle'):
            return True
    return False


# ---------------------------------------------------------------------------
# Lifecycle member: name + whether it is a char** (string array)
# ---------------------------------------------------------------------------

class LifecycleMember:
    """A char* or char** member that the destructor must free."""

    __slots__ = ('name', 'is_char_ptr_array')

    def __init__(self, name, is_char_ptr_array):
        self.name = name
        self.is_char_ptr_array = is_char_ptr_array


def parse_members_for_lifecycle(raw_body):
    """Return a list of LifecycleMember for every char* or char** member.

    Unlike parse_members(), this function:
      - ignores ``accessors:none`` (the destructor must free all heap strings)
      - respects ``lifecycle:none`` to let callers opt a member out
      - collects only char* and char** members (the only types that need
        explicit freeing)
    """
    members = []

    for raw_line in raw_body.splitlines():
        if has_annotation(raw_line, 'lifecycle:none'):
            continue

        clean = strip_inline_comment(strip_block_comments(raw_line)).strip()

        if not clean or ';' not in clean:
            continue
        if 'static' in clean or 'struct' in clean:
            continue

        m = MEMBER_RE.match(clean)
        if not m:
            continue

        is_const  = bool(m.group(1))
        type_base = m.group(2)
        ptr_part  = m.group(3)
        name      = m.group(4)

        # const char * members are not owned by the struct (no strdup),
        # so the destructor must not free them.
        if is_const:
            continue

        ptr_depth = ptr_part.count('*')
        if not ptr_depth or type_base != 'char':
            continue

        if ptr_depth > 2:
            continue

        members.append(LifecycleMember(
            name=name,
            is_char_ptr_array=(ptr_depth == 2),
        ))

    return members


# ---------------------------------------------------------------------------
# Default member: name + default value expression
# ---------------------------------------------------------------------------

class DefaultMember:
    """A member that carries a ``//!default:VALUE`` annotation."""

    __slots__ = ('name', 'value', 'is_char_ptr')

    def __init__(self, name, value, is_char_ptr=False):
        self.name       = name
        self.value      = value       # raw value string, emitted verbatim
        self.is_char_ptr = is_char_ptr  # True → emit strdup/free pattern


def parse_default_annotation(raw_line):
    """Return the default value string from a ``!default:VALUE`` annotation.

    The annotation must appear inside a ``//`` comment::

        int port;   //!default:4420
        char *host; //!default:"localhost"

    VALUE may be a quoted C string literal (``"foo bar"``), which may contain
    spaces, or any non-whitespace token (integer literal, macro name, etc.).

    Returns None when no annotation is found.
    """
    comment = _comment_text(raw_line)
    if comment is None:
        return None
    # Quoted string (double-quoted, with basic escape support) or bare token.
    _val = r'"(?:[^"\\]|\\.)*"|\S+'
    m = re.search(rf'!default:({_val})', comment)
    return m.group(1) if m else None


def parse_members_for_defaults(raw_body):
    """Return a list of DefaultMember for every member with a default annotation.

    Any member in the struct body that carries ``//!default:VALUE`` is
    collected here, regardless of its accessor or lifecycle status.
    The value is emitted verbatim in the generated assignment, so any
    valid C expression (integer literal, macro name, etc.) is accepted.
    """
    defaults = []

    for raw_line in raw_body.splitlines():
        value = parse_default_annotation(raw_line)
        if value is None:
            continue

        clean = strip_inline_comment(strip_block_comments(raw_line)).strip()

        if not clean or ';' not in clean:
            continue
        if 'static' in clean or 'struct' in clean:
            continue

        # Try char array first, then general member regex.
        m = CHAR_ARRAY_RE.match(clean)
        if m:
            defaults.append(DefaultMember(name=m.group(2), value=value,
                                          is_char_ptr=False))
            continue

        m = MEMBER_RE.match(clean)
        if m:
            is_const  = bool(m.group(1))
            type_base = m.group(2)
            ptr_part  = m.group(3)
            name      = m.group(4)
            is_char_ptr = (type_base == 'char'
                           and ptr_part.count('*') == 1
                           and not is_const)
            defaults.append(DefaultMember(name=name, value=value,
                                          is_char_ptr=is_char_ptr))

    return defaults


def parse_file(text, verbose):
    """Return list of (struct_name, [Member], [LifecycleMember],
    [DefaultMember]) tuples.

    Only structs annotated with ``//!generate-accessors`` as the first token
    inside the opening brace, or with ``//!generate-lifecycle`` anywhere
    inside the opening brace line, are processed.
    """
    result = []

    for match in STRUCT_RE.finditer(text):
        struct_name = match.group(1)
        raw_body    = match.group(2)

        struct_mode    = parse_struct_annotation(raw_body)
        want_lifecycle = parse_lifecycle_annotation(raw_body)

        if struct_mode is None and not want_lifecycle:
            continue

        members = []
        if struct_mode is not None:
            members = parse_members(
                struct_name, raw_body, struct_mode, verbose)

        lc_members = None
        if want_lifecycle:
            lc_members = parse_members_for_lifecycle(raw_body)

        default_members = parse_members_for_defaults(raw_body)

        if verbose and (members or lc_members is not None or default_members):
            acc = f"{len(members)} members [mode: {struct_mode}]" \
                  if members else "no accessors"
            lc = (f"{len(lc_members)} lifecycle members"
                  if lc_members is not None else "no lifecycle")
            df = (f"{len(default_members)} defaults" if default_members
                  else "no defaults")
            print(f"Found struct: {struct_name} — {acc}, {lc}, {df}")

        if members or lc_members is not None or default_members:
            result.append((struct_name, members, lc_members, default_members))

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
    fn = _set_name(prefix, sname, mname)
    f.write(
        f'/**\n'
        f'{kdoc_summary(fn, f"Set {mname}.", "Setter.")}\n'
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


def emit_hdr_setter_str_array(f, prefix, sname, mname):
    """Emit a header declaration for a string-array setter."""
    fn = _set_name(prefix, sname, mname)
    f.write(
        f'/**\n'
        f'{kdoc_summary(fn, f"Set {mname}.", "Setter.")}\n'
        f' * @p: The &struct {sname} instance to update.\n'
        f' * @{mname}: New NULL-terminated string array; deep-copied.\n'
        f' */\n'
    )

    single = (f'void {_set_name(prefix, sname, mname)}'
              f'(struct {sname} *p, const char *const *{mname});')
    if fits_80(single):
        f.write(single + '\n\n')
    else:
        f.write(
            f'void {_set_name(prefix, sname, mname)}(\n'
            f'\t\tstruct {sname} *p,\n'
            f'\t\tconst char *const *{mname});\n\n'
        )


def emit_hdr_setter_val(f, prefix, sname, mname, mtype):
    """Emit a header declaration for a value setter."""
    fn = _set_name(prefix, sname, mname)
    f.write(
        f'/**\n'
        f'{kdoc_summary(fn, f"Set {mname}.", "Setter.")}\n'
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
    fn = _get_name(prefix, sname, mname)
    tail = ', or NULL if not set.' if is_dyn_str else '.'
    f.write(
        f'/**\n'
        f'{kdoc_summary(fn, f"Get {mname}.", "Getter.")}\n'
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
                      not member.is_char_ptr_array and
                      member.type == 'const char *')
        if member.gen_setter:
            if member.is_char_ptr_array:
                emit_hdr_setter_str_array(f, prefix, struct_name, member.name)
            elif member.is_char_array or is_dyn_str:
                emit_hdr_setter_str(f, prefix, struct_name,
                                    member.name, is_dyn_str)
            else:
                emit_hdr_setter_val(f, prefix, struct_name,
                                    member.name, member.type)
        if member.gen_getter:
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

    f.write(
        f'{{\n\tsnprintf(p->{mname}, {array_size}, "%s", {mname});\n}}\n\n'
    )


def emit_src_setter_str_array(f, prefix, sname, mname):
    """Emit a NULL-terminated string-array setter (deep copy)."""
    sig = (f'{PUB}void {_set_name(prefix, sname, mname)}'
           f'(struct {sname} *p, const char *const *{mname})')
    if fits_80(sig):
        f.write(sig + '\n')
    else:
        f.write(
            f'{PUB}void {_set_name(prefix, sname, mname)}(\n'
            f'\t\tstruct {sname} *p,\n'
            f'\t\tconst char *const *{mname})\n'
        )

    f.write(
        '{\n'
        '\tchar **new_array = NULL;\n'
        '\tsize_t i;\n\n'
        f'\tif ({mname}) {{\n'
        f'\t\tfor (i = 0; {mname}[i]; i++)\n'
        '\t\t\t;\n'
        '\n'
        '\t\tnew_array = calloc(i + 1, sizeof(char *));\n'
        '\t\tif (new_array != NULL) {\n'
        f'\t\t\tfor (i = 0; {mname}[i]; i++) {{\n'
        f'\t\t\t\tnew_array[i] = strdup({mname}[i]);\n'
        '\t\t\t\tif (!new_array[i]) {\n'
        '\t\t\t\t\twhile (i > 0)\n'
        '\t\t\t\t\t\tfree(new_array[--i]);\n'
        '\t\t\t\t\tfree(new_array);\n'
        '\t\t\t\t\tnew_array = NULL;\n'
        '\t\t\t\t\tbreak;\n'
        '\t\t\t\t}\n'
        '\t\t\t}\n'
        '\t\t}\n'
        '\t}\n\n'
        f'\tfor (i = 0; p->{mname} && p->{mname}[i]; i++)\n'
        f'\t\tfree(p->{mname}[i]);\n'
        f'\tfree(p->{mname});\n'
        f'\tp->{mname} = new_array;\n'
        '}\n\n'
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


def emit_src_getter(f, prefix, sname, mname, mtype, cast=None):
    """Emit a getter (return member value).

    *cast* is an optional C cast expression (e.g. ``'(const char *const *)'``)
    inserted before ``p->mname`` in the return statement.  Required when the
    declared return type differs from the member's raw storage type (e.g. a
    ``char **`` field exposed as ``const char *const *``).
    """
    sep = type_sep(mtype)
    sig = (f'{PUB}{mtype}{sep}{_get_name(prefix, sname, mname)}'
           f'(const struct {sname} *p)')
    ret = f'\treturn {cast}p->{mname};\n' if cast else f'\treturn p->{mname};\n'
    if fits_80(sig):
        f.write(sig + '\n' f'{{\n{ret}}}\n\n')
    else:
        f.write(
            f'{PUB}{mtype}{sep}{_get_name(prefix, sname, mname)}(\n'
            f'\t\tconst struct {sname} *p)\n'
            f'{{\n{ret}}}\n\n'
        )


def generate_src(f, prefix, struct_name, members):
    """Write source implementations for all members of one struct."""
    for member in members:
        is_dyn_str = (not member.is_char_array and
                      not member.is_char_ptr_array and
                      member.type == 'const char *')
        if member.gen_setter:
            if is_dyn_str:
                emit_src_setter_dynstr(f, prefix, struct_name, member.name)
            elif member.is_char_ptr_array:
                emit_src_setter_str_array(f, prefix, struct_name, member.name)
            elif member.is_char_array:
                emit_src_setter_chararray(f, prefix, struct_name,
                                          member.name, member.array_size)
            else:
                emit_src_setter_val(f, prefix, struct_name,
                                    member.name, member.type)
        if member.gen_getter:
            cast = '(const char *const *)' if member.is_char_ptr_array else None
            emit_src_getter(f, prefix, struct_name, member.name, member.type,
                            cast=cast)


# ---------------------------------------------------------------------------
# Lifecycle (constructor / destructor) emitters
# ---------------------------------------------------------------------------

def _new_name(prefix, sname):
    return f'{prefix}{sname}_new'


def _free_name(prefix, sname):
    return f'{prefix}{sname}_free'


def _init_defaults_name(prefix, sname):
    return f'{prefix}{sname}_init_defaults'


def emit_hdr_defaults(f, prefix, sname, default_members):
    """Emit header declaration for the init_defaults function."""
    fn = _init_defaults_name(prefix, sname)
    new_fn = _new_name(prefix, sname)
    f.write(
        f'/**\n'
        f'{kdoc_summary(fn, f"Apply default values to a {sname} instance.", "Set fields to their defaults.", "Initialise to defaults.")}\n'
        f' * @p: The &struct {sname} instance to initialise.\n'
        f' *\n'
        f' * Sets each field that carries a default annotation to its\n'
        f' * compile-time default value.  Called automatically by\n'
        f' * {new_fn}() but may also be called directly to reset an\n'
        f' * instance to its defaults without reallocating it.\n'
        f' */\n'
    )
    single = f'void {fn}(struct {sname} *p);'
    if fits_80(single):
        f.write(single + '\n\n')
    else:
        f.write(f'void {fn}(\n\t\tstruct {sname} *p);\n\n')


def emit_src_defaults(f, prefix, sname, default_members):
    """Emit the init_defaults function implementation."""
    fn = _init_defaults_name(prefix, sname)
    sig = f'{PUB}void {fn}(struct {sname} *p)'
    if fits_80(sig):
        f.write(sig + '\n')
    else:
        f.write(f'{PUB}void {fn}(\n\t\tstruct {sname} *p)\n')

    f.write('{\n')
    f.write('\tif (!p)\n\t\treturn;\n')
    for dm in default_members:
        if dm.is_char_ptr:
            # Skip the assignment when the string is already at its default
            # value; otherwise free the old value and strdup the new one.
            cmp = f'\tif (!p->{dm.name} || strcmp(p->{dm.name}, {dm.value}) != 0) {{'
            if fits_80_ntabs(1, cmp.lstrip()):
                f.write(cmp + '\n')
            else:
                f.write(
                    f'\tif (!p->{dm.name} ||\n'
                    f'\t    strcmp(p->{dm.name}, {dm.value}) != 0) {{\n'
                )
            f.write(f'\t\tfree(p->{dm.name});\n')
            f.write(f'\t\tp->{dm.name} = strdup({dm.value});\n')
            f.write('\t}\n')
        else:
            f.write(f'\tp->{dm.name} = {dm.value};\n')
    f.write('}\n\n')


def emit_hdr_lifecycle(f, prefix, sname, lc_members):
    """Emit header declarations for the constructor and destructor."""

    # --- constructor -------------------------------------------------------
    new_fn = _new_name(prefix, sname)
    f.write(
        f'/**\n'
        f'{kdoc_summary(new_fn, f"Allocate and initialise a {sname} object.", "Allocate and initialise a new instance.", "Constructor.")}\n'
        f' * @pp: On success, *pp is set to the newly allocated object.\n'
        f' *\n'
        f' * Allocates a zeroed &struct {sname} on the heap.\n'
        f' * The caller must release it with {_free_name(prefix, sname)}().\n'
        f' *\n'
        f' * Return: 0 on success, -EINVAL if @pp is NULL,\n'
        f' *         -ENOMEM if allocation fails.\n'
        f' */\n'
    )
    single = f'int {new_fn}(struct {sname} **pp);'
    if fits_80(single):
        f.write(single + '\n\n')
    else:
        f.write(f'int {new_fn}(\n\t\tstruct {sname} **pp);\n\n')

    # --- destructor --------------------------------------------------------
    free_fn = _free_name(prefix, sname)
    f.write(
        f'/**\n'
        f'{kdoc_summary(free_fn, f"Release a {sname} object.", "Release this instance.", "Destructor.")}\n'
        f' * @p: Object previously returned by {new_fn}().\n'
        f' *     A NULL pointer is silently ignored.\n'
        f' */\n'
    )
    single = f'void {free_fn}(struct {sname} *p);'
    if fits_80(single):
        f.write(single + '\n\n')
    else:
        f.write(f'void {free_fn}(\n\t\tstruct {sname} *p);\n\n')


def emit_src_lifecycle(f, prefix, sname, lc_members, default_members):
    """Emit constructor and destructor implementations."""

    # --- constructor -------------------------------------------------------
    new_fn = _new_name(prefix, sname)
    sig = f'{PUB}int {new_fn}(struct {sname} **pp)'
    if fits_80(sig):
        f.write(sig + '\n')
    else:
        f.write(f'{PUB}int {new_fn}(\n\t\tstruct {sname} **pp)\n')

    if default_members:
        init_fn = _init_defaults_name(prefix, sname)
        f.write(
            '{\n'
            '\tif (!pp)\n'
            '\t\treturn -EINVAL;\n'
            f'\t*pp = calloc(1, sizeof(struct {sname}));\n'
            '\tif (!*pp)\n'
            '\t\treturn -ENOMEM;\n'
            f'\t{init_fn}(*pp);\n'
            '\treturn 0;\n'
            '}\n\n'
        )
    else:
        f.write(
            '{\n'
            '\tif (!pp)\n'
            '\t\treturn -EINVAL;\n'
            f'\t*pp = calloc(1, sizeof(struct {sname}));\n'
            '\treturn *pp ? 0 : -ENOMEM;\n'
            '}\n\n'
        )

    # --- destructor --------------------------------------------------------
    free_fn = _free_name(prefix, sname)
    sig = f'{PUB}void {free_fn}(struct {sname} *p)'
    if fits_80(sig):
        f.write(sig + '\n')
    else:
        f.write(f'{PUB}void {free_fn}(\n\t\tstruct {sname} *p)\n')

    f.write('{\n')

    if lc_members:
        # Members must be dereferenced, so guard against NULL p.
        f.write('\tif (!p)\n\t\treturn;\n')
        for m in lc_members:
            if m.is_char_ptr_array:
                # free each element then the container
                loop = (f'\tfor (size_t i = 0;'
                        f' p->{m.name} && p->{m.name}[i]; i++)')
                free = f'\t\tfree(p->{m.name}[i]);'
                if fits_80_ntabs(1, loop.lstrip()):
                    f.write(loop + '\n')
                else:
                    f.write(
                        f'\tfor (size_t i = 0;\n'
                        f'\t     p->{m.name} && p->{m.name}[i]; i++)\n'
                    )
                f.write(free + '\n')
                f.write(f'\tfree(p->{m.name});\n')
            else:
                f.write(f'\tfree(p->{m.name});\n')

    # free(NULL) is safe — no NULL check needed when there are no members.
    f.write('\tfree(p);\n}\n\n')


# ---------------------------------------------------------------------------
# Linker script (*.ld) emitter
# ---------------------------------------------------------------------------

def generate_ld(f, prefix, struct_name, members, lc_members, default_members):
    """Write linker version-script entries for all members of one struct."""
    if lc_members is not None:
        f.write(f'\t\t{_new_name(prefix, struct_name)};\n')
        f.write(f'\t\t{_free_name(prefix, struct_name)};\n')
    if default_members:
        f.write(f'\t\t{_init_defaults_name(prefix, struct_name)};\n')
    for member in members:
        if member.gen_getter:
            f.write(f'\t\t{_get_name(prefix, struct_name, member.name)};\n')
        if member.gen_setter:
            f.write(f'\t\t{_set_name(prefix, struct_name, member.name)};\n')


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

        for struct_name, members, lc_members, default_members in structs:
            forward_declares.append(struct_name)

            section_banner = (
                f'/****************************************************************************\n'
                f' * Accessors for: struct {struct_name}\n'
                f' ****************************************************************************/\n'
                f'\n'
            )

            hdr_buf = io.StringIO()
            hdr_buf.write(section_banner)
            if lc_members is not None:
                emit_hdr_lifecycle(hdr_buf, args.prefix, struct_name,
                                   lc_members)
            if default_members:
                emit_hdr_defaults(hdr_buf, args.prefix, struct_name,
                                  default_members)
            generate_hdr(hdr_buf, args.prefix, struct_name, members)
            hdr_parts.append(hdr_buf.getvalue())

            src_buf = io.StringIO()
            src_buf.write(section_banner)
            if lc_members is not None:
                emit_src_lifecycle(src_buf, args.prefix, struct_name,
                                   lc_members, default_members)
            if default_members:
                emit_src_defaults(src_buf, args.prefix, struct_name,
                                  default_members)
            generate_src(src_buf, args.prefix, struct_name, members)
            src_parts.append(src_buf.getvalue())

            ld_buf = io.StringIO()
            generate_ld(ld_buf, args.prefix, struct_name, members,
                        lc_members, default_members)
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
            f'#include <stdint.h>\n\n'
            f'#include <nvme/types.h>\n'
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
            f'#include <errno.h>\n'
            f'#include <stdlib.h>\n'
            f'#include <string.h>\n'
            f'#include "{os.path.basename(args.h_fname)}"\n'
            f'\n'
        )
        for fname in files_to_include:
            f.write(f'#include "{fname}"\n')
        f.write('#include "compiler-attributes.h"\n')
        f.write('\n')
        f.write(''.join(src_parts))

    # --- accessors.ld ------------------------------------------------------
    makedirs_for(args.l_fname)
    with open(args.l_fname, 'w') as f:
        f.write(
            f'{SPDX_LD}\n'
            f'\n'
            f'{LD_BANNER}\n'
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
