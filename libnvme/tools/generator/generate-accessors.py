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
(optionally followed by ':metadata') is a command.  The ':metadata' portion
carries extra parameters such as 'read=generated,write=none'.  Multiple
annotations can appear in one comment:
  struct nvme_ctrl { // !generate-accessors !generate-lifecycle

Optional whitespace between // and ! is accepted, so // !token, //!token,
and //\t!token are all equivalent.  The canonical form used in this
project's headers is "// !token" (one space).

ACCESS MODEL — TWO INDEPENDENT AXES
-----------------------------------
Each struct member has two independent axes:
  read  — whether a getter exists, and how
  write — whether a setter exists, and how

Each axis takes one of three modes:
  generated — the generator emits the accessor
  custom    — an accessor exists but is provided elsewhere as a hand-written
              function in the public API; the generator emits nothing
  none      — no accessor exists for this axis; the generator
              emits nothing

Only the 'generated' mode produces output in this generator.  'custom'
and 'none' are semantic declarations for downstream consumers (the
Python-binding generator, the nvme.i consistency check) that need to
know the difference between "no accessor at all" and "accessor provided
by hand".

Struct inclusion — annotate the opening brace line of the struct.
The optional spec sets the default mode for each axis of every member
of the struct:
  struct nvme_ctrl { // !generate-accessors
    — shorthand for read=generated, write=generated
  struct nvme_ctrl { // !generate-accessors:read=generated,write=generated
    — explicit form of the same default
  struct nvme_ctrl { // !generate-accessors:read=none,write=none
    — include struct but emit nothing by default
  struct nvme_ctrl { // !generate-accessors:read=generated
    — read=generated, write inherits the built-in default (generated)

Only structs carrying this annotation are processed.  Members of other
structs are ignored.

Member-level override — annotate the member declaration line.  Any axis
not named in the spec is inherited from the struct-level default:
  char *state;     // !access:read=custom,write=none
    — custom getter, no setter
  char *token;     // !access:read=none,write=custom
    — no getter, custom setter
  char *secret;    // !access:read=none,write=none
    — no accessor of any kind
  char *name;      // !access:read=custom
    — custom getter; write axis inherited from struct default
  char *pw;        // !access:write=custom
    — custom setter; read axis inherited from struct default

The 'const' qualifier on a member forces write=none regardless of the
annotation (you cannot generate a setter for a const member).  'const
char *' members are also never freed by the destructor — they are
assumed to point to externally owned storage.

Lifecycle (constructor + destructor) — annotate the opening brace line:
  struct nvme_ctrl { // !generate-lifecycle
The two annotations are independent and may appear in the same comment:
  struct nvme_ctrl { // !generate-accessors !generate-lifecycle

Lifecycle member exclusion — annotate the member declaration line:
  char *cache; // !lifecycle:none     — skip this member in the destructor

Defaults — annotate the member declaration line with a value to assign:
  int max_retries;  // !default:6
  __u8 lsp;         // !default:NVMF_LOG_DISC_LSP_NONE
  char *transport;  // !default:"tcp"
When any member carries a default annotation, an init_defaults function is
generated. If generate-lifecycle is also present, the constructor calls it.
The init_defaults function is also useful standalone to re-initialise a
struct to its defaults without reallocating it.
For scalar members the value is assigned directly. For char* members the
generated code avoids unnecessary work by comparing the current value with
the default first (strcmp); if they differ it frees the old value and
strdup()s the new one. const char* members are assigned directly (no
strdup) since they are assumed to point to externally owned storage.

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
SPDX_I  = SPDX_C
SPDX_LD = "# SPDX-License-Identifier: LGPL-2.1-or-later"

BANNER = (
    "/*\n"
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
    "/*\n"
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

# Matches:  [const] type_word [type_word ...] [*[*]] name ;
# Supports multi-word types such as "enum tag", "unsigned int", and
# "unsigned long long".  Backtracking resolves the ambiguity between the
# final type word and the member name: the engine tries the longest type
# first and retreats until the pointer/space group and name can be satisfied.
MEMBER_RE = re.compile(
    r'^(const\s+)?'
    r'((?:[A-Za-z_][A-Za-z0-9_]*)(?:\s+[A-Za-z_][A-Za-z0-9_]*)*)'
    r'([*\s]+)'
    r'([A-Za-z_][A-Za-z0-9_]*)\s*;'
)

# Matches:  [const] type_word [type_word ...] name[size] ;
# For fixed-size arrays of scalar types (e.g. uint8_t eui64[8],
# unsigned char uuid[NVME_UUID_LEN]).  char arrays are caught first
# by CHAR_ARRAY_RE and never reach this regex.
SCALAR_ARRAY_RE = re.compile(
    r'^(const\s+)?'
    r'((?:[A-Za-z_][A-Za-z0-9_]*)(?:\s+[A-Za-z_][A-Za-z0-9_]*)*)'
    r'\s+'
    r'([A-Za-z_][A-Za-z0-9_]*)'
    r'\s*\[\s*([A-Za-z0-9_]+)\s*\]\s*;'
)


# ---------------------------------------------------------------------------
# Annotation helpers
# ---------------------------------------------------------------------------

def _comment_text(text):
    """Return the portion of *text* after the first '//', or None.

    This is the raw comment payload — the text the parser scans for
    ``!keyword`` annotation tokens.  Leading whitespace is stripped so that
    '// !token', '//!token', and '//\\t!token' are all equivalent.
    """
    idx = text.find('//')
    return text[idx + 2:].lstrip() if idx >= 0 else None


def has_annotation(text, annotation):
    """Return True if *text* carries ``!annotation`` inside a ``//`` comment.

    Annotations are ``!keyword`` tokens that appear anywhere after ``//`` on
    the same line.  A single comment may carry several annotations, e.g.::

        struct foo { // !generate-accessors !generate-lifecycle

    Accepts '// !annotation', '//!annotation', '//\\t!annotation', etc.
    The match is token-delimited: ``!generate-accessors`` will not match
    inside ``!generate-accessors:read=none,write=none`` (the ':' is not
    whitespace, '!', or end-of-string).
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
    """Represents one member of a parsed C struct.

    read_mode and write_mode each take one of:
      'generated'  — this generator emits the accessor
      'custom'     — an accessor exists elsewhere (hand-written or bridge)
      'none'       — no accessor exists for this axis

    Only 'generated' produces C accessor output in this generator.  Members
    with at least one non-'none' axis are retained for the SWIG emitter.

    py_visible: False when annotated with ``// !python:none``.
    py_alias: alternate Python attribute name from ``// !python:alias=NAME``,
              or None to use the C member name.
    """

    __slots__ = ('name', 'type', 'read_mode', 'write_mode',
                 'is_char_array', 'is_char_ptr_array', 'is_scalar_array',
                 'array_size', 'py_visible', 'py_alias')

    def __init__(self, name, type_str, read_mode, write_mode,
                 is_char_array, is_char_ptr_array, is_scalar_array, array_size,
                 py_visible=True, py_alias=None):
        self.name = name
        self.type = type_str          # e.g. "const char *", "int", "__u32"
        self.read_mode = read_mode    # 'generated' | 'custom' | 'none'
        self.write_mode = write_mode  # 'generated' | 'custom' | 'none'
        self.is_char_array = is_char_array
        self.is_char_ptr_array = is_char_ptr_array
        self.is_scalar_array = is_scalar_array
        self.array_size = array_size  # for fixed-size arrays (char[N] or type[N])
        self.py_visible = py_visible  # False → excluded from SWIG fragment
        self.py_alias = py_alias      # str → rename Python attribute; None → use C name

    @property
    def has_accessor(self):
        """True when at least one axis has a real accessor (generated or custom)."""
        return self.read_mode != 'none' or self.write_mode != 'none'

    @property
    def is_custom_accessor(self):
        return self.read_mode == 'custom' or self.write_mode == 'custom'

    @property
    def gen_getter(self):
        return self.read_mode == 'generated'

    @property
    def gen_setter(self):
        return self.write_mode == 'generated'


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def parse_members(struct_name, raw_body, struct_defaults, verbose):
    """Parse *raw_body* and return a list of Member objects.

    *struct_defaults* is a (read_mode, write_mode) tuple taken from the
    struct-level ``!generate-accessors`` annotation.  Each member inherits
    these defaults and may override one or both axes with
    ``// !access:read=...,write=...``.

    Modes: 'generated' | 'custom' | 'none'.

    Members where both axes are 'none' are dropped entirely.  Members with
    at least one non-'none' axis are retained so the SWIG fragment emitter
    can see 'custom' axes alongside 'generated' ones.

    Per-member Python hints:
      ``// !python:none``        → Member.py_visible = False (exclude from SWIG)
      ``// !python:alias=NAME``  → Member.py_alias = 'NAME' (rename in Python)

    Annotations are detected on the **raw** (un-stripped) line so that
    comment masking cannot hide them.  Comments are stripped only afterwards,
    for regex matching.
    """
    struct_read, struct_write = struct_defaults
    members = []

    _py_none_re  = re.compile(r'!python:none(?=[\s!]|$)')
    _py_alias_re = re.compile(r'!python:alias=(\w+)(?=[\s!]|$)')

    for raw_line in raw_body.splitlines():
        # ----------------------------------------------------------------
        # Annotation checks on the raw line — BEFORE stripping comments.
        # ----------------------------------------------------------------
        override = parse_access_override(raw_line)
        if override is None:
            read_mode = struct_read
            write_mode = struct_write
        else:
            read_mode  = override.get('read',  struct_read)
            write_mode = override.get('write', struct_write)

        # Retain members that have any accessor (generated or custom) so the
        # SWIG emitter can see them.  Only drop members with no accessor at
        # all on either axis.
        if read_mode == 'none' and write_mode == 'none':
            continue

        comment = _comment_text(raw_line) or ''
        py_visible = _py_none_re.search(comment) is None
        m_alias    = _py_alias_re.search(comment)
        py_alias   = m_alias.group(1) if m_alias else None

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
                read_mode=read_mode,
                # const forces write=none — you cannot generate a setter
                # for a const member.
                write_mode='none' if is_const_qual else write_mode,
                is_char_array=True,
                is_char_ptr_array=False,
                is_scalar_array=False,
                array_size=m.group(3),
                py_visible=py_visible,
                py_alias=py_alias,
            ))
            continue

        # --- fixed-size scalar array: [const] type name[size]; ----------
        m = SCALAR_ARRAY_RE.match(clean)
        if m:
            is_const_qual = bool(m.group(1))
            members.append(Member(
                name=m.group(3),
                type_str=m.group(2),
                read_mode=read_mode,
                write_mode='none' if is_const_qual else write_mode,
                is_char_array=False,
                is_char_ptr_array=False,
                is_scalar_array=True,
                array_size=m.group(4),
                py_visible=py_visible,
                py_alias=py_alias,
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
                read_mode=read_mode,
                write_mode='none' if is_const_qual else write_mode,
                is_char_array=False,
                is_char_ptr_array=(ptr_depth == 2),
                is_scalar_array=False,
                array_size=None,
                py_visible=py_visible,
                py_alias=py_alias,
            ))

    return members


_VALID_MODES = frozenset(('generated', 'custom', 'none'))


def parse_access_spec(spec, origin):
    """Parse a spec body like ``read=generated,write=custom``.

    Returns a dict mapping axis names ('read', 'write') to mode strings.
    Partial specs are allowed — any axis not named in the spec is absent
    from the returned dict.  Unknown axes or modes trigger a warning and
    are dropped from the result.

    *origin* is a human-readable description of where the spec came from,
    used only for warning messages (e.g. "!generate-accessors" or
    "!access").
    """
    result = {}
    for part in spec.split(','):
        part = part.strip()
        if not part:
            continue
        if '=' not in part:
            print(f"warning: {origin} spec token '{part}' has no '='; "
                  f"expected 'read=MODE' or 'write=MODE'.",
                  file=sys.stderr)
            continue
        key, value = part.split('=', 1)
        key   = key.strip()
        value = value.strip()
        if key not in ('read', 'write'):
            print(f"warning: {origin} spec axis '{key}' is unknown; "
                  f"expected 'read' or 'write'.",
                  file=sys.stderr)
            continue
        if value not in _VALID_MODES:
            print(f"warning: {origin} spec mode '{value}' for axis "
                  f"'{key}' is unknown; expected one of: "
                  f"{', '.join(sorted(_VALID_MODES))}.",
                  file=sys.stderr)
            continue
        result[key] = value
    return result


def parse_struct_annotation(raw_body):
    """Return the (read_mode, write_mode) defaults for a struct.

    Recognises::

      // !generate-accessors
          → ('generated', 'generated')  [shorthand]
      // !generate-accessors:read=X,write=Y
          → (X, Y)                      [explicit, both axes]
      // !generate-accessors:read=X
          → (X, 'generated')            [partial — write inherits built-in]
      // !generate-accessors:write=Y
          → ('generated', Y)            [partial — read inherits built-in]

    Returns None when the annotation is absent.

    The built-in default for any axis not named at the struct level is
    'generated'.
    """
    # Bare form first: "!generate-accessors" with no ':spec'.
    bare_re = re.compile(r'!generate-accessors(?=[\s!]|$)')
    # Specced form: "!generate-accessors:spec".
    spec_re = re.compile(r'!generate-accessors:(\S+)(?=[\s!]|$)')

    m = spec_re.search(raw_body)
    if m:
        parsed = parse_access_spec(m.group(1), '!generate-accessors')
        return (parsed.get('read',  'generated'),
                parsed.get('write', 'generated'))

    if bare_re.search(raw_body):
        return ('generated', 'generated')

    return None


def parse_access_override(raw_line):
    """Parse a member-level ``!access:<spec>`` annotation.

    Returns a dict ``{'read': mode}`` / ``{'write': mode}`` / both, or
    ``None`` when no ``!access`` annotation is present on the line.  A
    partial spec yields a dict with only the named axes — missing axes
    are the caller's responsibility to fill in (typically from the
    struct-level default).
    """
    comment = _comment_text(raw_line)
    if comment is None:
        return None
    m = re.search(r'!access:(\S+)(?=[\s!]|$)', comment)
    if not m:
        return None
    return parse_access_spec(m.group(1), '!access')


def parse_lifecycle_annotation(raw_body):
    """Return True if ``!generate-lifecycle`` is present, else None.

    Recognises (on the struct's opening brace line)::

        // !generate-lifecycle   → True  (emit constructor + destructor)

    Returns None when the annotation is absent.
    """
    _lc_re = re.compile(r'!generate-lifecycle(?=[\s!]|$)')
    for line in raw_body.splitlines():
        comment = _comment_text(line)
        if comment is None:
            continue
        if _lc_re.search(comment):
            return True
    return None


_GEN_PYTHON_RE = re.compile(r'!generate-python(?::alias=(\w+))?(?=[\s!]|$)')


def parse_generate_python(raw_body):
    """Return ``(emit_py, alias)`` from a ``// !generate-python[:alias=NAME]`` annotation.

    *emit_py* is True when ``!generate-python`` is present on any line of
    *raw_body*.  *alias* is the NAME string from ``:alias=NAME``, or None
    when the option is absent.
    """
    for line in raw_body.splitlines():
        comment = _comment_text(line)
        if comment is None:
            continue
        m = _GEN_PYTHON_RE.search(comment)
        if m:
            return True, m.group(1)
    return False, None


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
      - ignores the ``!access`` annotation entirely (the destructor must
        free all heap strings regardless of accessor mode)
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
    """A member that carries a ``// !default:VALUE`` annotation."""

    __slots__ = ('name', 'value', 'is_char_ptr')

    def __init__(self, name, value, is_char_ptr=False):
        self.name       = name
        self.value      = value       # raw value string, emitted verbatim
        self.is_char_ptr = is_char_ptr  # True → emit strdup/free pattern


def parse_default_annotation(raw_line):
    """Return the default value string from a ``!default:VALUE`` annotation.

    The annotation must appear inside a ``//`` comment::

        int port;   // !default:4420
        char *host; // !default:"localhost"

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

    Any member in the struct body that carries ``// !default:VALUE`` is
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
    [DefaultMember], emit_py_fragment) tuples.

    Only structs annotated with ``// !generate-accessors`` as the first token
    inside the opening brace, or with ``// !generate-lifecycle`` anywhere
    inside the opening brace line, are processed.

    *emit_py_fragment* is True when the struct also carries ``!generate-python``.
    """
    result = []

    for match in STRUCT_RE.finditer(text):
        struct_name = match.group(1)
        raw_body    = match.group(2)

        struct_defaults             = parse_struct_annotation(raw_body)
        lifecycle_mode              = parse_lifecycle_annotation(raw_body)
        emit_py_fragment, struct_alias = parse_generate_python(raw_body)

        if struct_defaults is None and lifecycle_mode is None and not emit_py_fragment:
            continue

        # If the struct has !generate-python but no !generate-accessors, parse
        # members with default mode (none, none) so the SWIG emitter can see
        # any explicit !access: overrides on individual members.
        members = []
        acc_defaults = struct_defaults if struct_defaults is not None else ('none', 'none')
        if struct_defaults is not None or emit_py_fragment:
            members = parse_members(
                struct_name, raw_body, acc_defaults, verbose)

        lc_members = None
        if lifecycle_mode:
            lc_members = parse_members_for_lifecycle(raw_body)

        default_members = parse_members_for_defaults(raw_body)

        if verbose and (members or lc_members is not None or default_members
                        or emit_py_fragment):
            if struct_defaults is not None and members:
                sr, sw = struct_defaults
                acc = (f"{len(members)} members "
                       f"[defaults: read={sr}, write={sw}]")
            elif struct_defaults is not None:
                acc = "no accessors"
            else:
                acc = "no accessors (python-only)"
            if lifecycle_mode:
                lc = f"{len(lc_members)} lifecycle members"
            else:
                lc = "no lifecycle"
            df = (f"{len(default_members)} defaults" if default_members
                  else "no defaults")
            py = "generate-python" if emit_py_fragment else "no python"
            print(f"Found struct: {struct_name} — {acc}, {lc}, {df}, {py}")

        if members or lc_members is not None or default_members or emit_py_fragment:
            result.append((struct_name, members, lc_members, default_members,
                           emit_py_fragment, struct_alias))

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


def emit_hdr_setter_scalar_array(f, prefix, sname, mname, elem_type, array_size):
    """Emit a header declaration for a fixed-size scalar-array setter."""
    fn = _set_name(prefix, sname, mname)
    f.write(
        f'/**\n'
        f'{kdoc_summary(fn, f"Set {mname}.", "Setter.")}\n'
        f' * @p: The &struct {sname} instance to update.\n'
        f' * @{mname}: Array of {array_size} elements; copied into the struct.\n'
        f' */\n'
    )
    single = (f'void {_set_name(prefix, sname, mname)}'
              f'(struct {sname} *p, const {elem_type} {mname}[{array_size}]);')
    if fits_80(single):
        f.write(single + '\n\n')
    else:
        f.write(
            f'void {_set_name(prefix, sname, mname)}(\n'
            f'\t\tstruct {sname} *p,\n'
            f'\t\tconst {elem_type} {mname}[{array_size}]);\n\n'
        )


def emit_hdr_getter_scalar_array(f, prefix, sname, mname, elem_type, array_size):
    """Emit a header declaration for a fixed-size scalar-array getter."""
    fn = _get_name(prefix, sname, mname)
    ret_type = f'const {elem_type} *'
    f.write(
        f'/**\n'
        f'{kdoc_summary(fn, f"Get {mname}.", "Getter.")}\n'
        f' * @p: The &struct {sname} instance to query.\n'
        f' *\n'
        f' * Return: Pointer to the {mname} array'
        f' of {array_size} {elem_type} elements.\n'
        f' */\n'
    )
    single = (f'{ret_type}{_get_name(prefix, sname, mname)}'
              f'(const struct {sname} *p);')
    if fits_80(single):
        f.write(single + '\n\n')
    else:
        f.write(
            f'{ret_type}{_get_name(prefix, sname, mname)}(\n'
            f'\t\tconst struct {sname} *p);\n\n'
        )


def generate_hdr(f, prefix, struct_name, members):
    """Write header declarations for all members of one struct."""
    for member in members:
        if member.is_scalar_array:
            if member.write_mode == 'generated':
                emit_hdr_setter_scalar_array(f, prefix, struct_name,
                                             member.name, member.type,
                                             member.array_size)
            if member.read_mode == 'generated':
                emit_hdr_getter_scalar_array(f, prefix, struct_name,
                                             member.name, member.type,
                                             member.array_size)
            continue
        is_dyn_str = (not member.is_char_array and
                      not member.is_char_ptr_array and
                      member.type == 'const char *')
        if member.write_mode == 'generated':
            if member.is_char_ptr_array:
                emit_hdr_setter_str_array(f, prefix, struct_name, member.name)
            elif member.is_char_array or is_dyn_str:
                emit_hdr_setter_str(f, prefix, struct_name,
                                    member.name, is_dyn_str)
            else:
                emit_hdr_setter_val(f, prefix, struct_name,
                                    member.name, member.type)
        if member.read_mode == 'generated':
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


def emit_src_setter_scalar_array(f, prefix, sname, mname, elem_type, array_size):
    """Emit a fixed-size scalar-array setter (memcpy)."""
    sig = (f'{PUB}void {_set_name(prefix, sname, mname)}'
           f'(struct {sname} *p, const {elem_type} {mname}[{array_size}])')
    if fits_80(sig):
        f.write(sig + '\n')
    else:
        f.write(
            f'{PUB}void {_set_name(prefix, sname, mname)}(\n'
            f'\t\tstruct {sname} *p,\n'
            f'\t\tconst {elem_type} {mname}[{array_size}])\n'
        )
    f.write(f'{{\n\tmemcpy(p->{mname}, {mname}, sizeof(p->{mname}));\n}}\n\n')


def emit_src_getter_scalar_array(f, prefix, sname, mname, elem_type):
    """Emit a fixed-size scalar-array getter (return pointer to first element)."""
    ret_type = f'const {elem_type} *'
    sig = (f'{PUB}{ret_type}{_get_name(prefix, sname, mname)}'
           f'(const struct {sname} *p)')
    if fits_80(sig):
        f.write(sig + '\n')
    else:
        f.write(
            f'{PUB}{ret_type}{_get_name(prefix, sname, mname)}(\n'
            f'\t\tconst struct {sname} *p)\n'
        )
    f.write(f'{{\n\treturn p->{mname};\n}}\n\n')


def generate_src(f, prefix, struct_name, members):
    """Write source implementations for all members of one struct."""
    for member in members:
        if member.is_scalar_array:
            if member.write_mode == 'generated':
                emit_src_setter_scalar_array(f, prefix, struct_name,
                                             member.name, member.type,
                                             member.array_size)
            if member.read_mode == 'generated':
                emit_src_getter_scalar_array(f, prefix, struct_name,
                                             member.name, member.type)
            continue
        is_dyn_str = (not member.is_char_array and
                      not member.is_char_ptr_array and
                      member.type == 'const char *')
        if member.write_mode == 'generated':
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
        if member.read_mode == 'generated':
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
        if member.read_mode == 'generated':
            f.write(f'\t\t{_get_name(prefix, struct_name, member.name)};\n')
        if member.write_mode == 'generated':
            f.write(f'\t\t{_set_name(prefix, struct_name, member.name)};\n')


# ---------------------------------------------------------------------------
# SWIG fragment emitters
# ---------------------------------------------------------------------------

def generate_swig_prelude(f):
    """Emit the shared ``_nvme_guarded_setattr`` helper.

    Written once at the top of the first (common) generated fragment.
    The fabrics fragment imports it from the common module at runtime.
    """
    f.write(
        '%pythoncode %{\n'
        'def _nvme_guarded_setattr(self, name, value):\n'
        '    """Reject writes to unknown attributes.\n\n'
        '    Typos like ``ctrl.nqn = x`` (should be ``ctrl.subsysnqn``) are\n'
        '    silently ignored by default Python ``__setattr__``.  This guard\n'
        '    raises ``AttributeError`` for any name not already present on the\n'
        '    object, keeping the struct-like API strict.\n'
        '    """\n'
        '    if name.startswith(\'_\') or name in (\'this\', \'thisown\') or hasattr(type(self), name):\n'
        '        object.__setattr__(self, name, value)\n'
        '    else:\n'
        '        raise AttributeError(\n'
        '            f"{type(self).__name__!r} has no attribute {name!r}")\n'
        '%}\n\n'
    )


def generate_swig_fragment(f, prefix, struct_name, members, errors,
                           struct_alias=None):
    """Emit SWIG struct decl with per-axis read/write routing.

    Access routing per member:

      is_custom_accessor (read==custom OR write==custom)
          → member goes inside ``%extend {}`` so SWIG calls the hand-written
            accessor function.  A ``%rename`` directive maps the function to
            SWIG's expected ``prefix_name_get`` / ``prefix_name_set`` name.

      all-generated (neither axis is custom, at least one is non-none)
          → plain struct field declaration (outside ``%extend``); SWIG reads/
            writes the field directly via ``p->member``.

      write == none (on either kind)
          → ``%immutable name;`` immediately before the field declaration
            makes the attribute read-only.

      both axes == none  →  member is not Python-visible; already excluded
                             by the ``has_accessor`` filter.

    SWIG does not support mixed mechanisms (direct read + accessor write) on
    a single member, so any ``custom`` axis forces the whole member into
    ``%extend``.

    ``%extend {}`` is omitted entirely when no member needs it.

    Struct-level naming:
      struct_alias=NAME → emits ``%rename(NAME) struct_name;`` before the
                          struct body, and uses NAME in ``%pythoncode``.
      struct_alias=None → no struct-level ``%rename``; C struct name used
                          everywhere.

    Invariant: the number of ``%rename`` directives emitted equals the number
    of ``custom`` axes among Python-visible members, plus one when struct_alias
    is set.
    """
    py_class = struct_alias or struct_name
    pre = f'{prefix}{struct_name}'
    f.write(f'/* struct {struct_name} */\n')
    if struct_alias:
        f.write(f'%rename({struct_alias}) {struct_name};\n')

    # Collect Python-visible members (has accessor AND py_visible flag set).
    visible = [m for m in members if m.py_visible and m.has_accessor]

    # Collision detection — report all collisions before emitting anything.
    seen = {}
    for m in visible:
        py_name = m.py_alias or m.name
        if py_name in seen:
            errors.append(
                f"error: struct {struct_name}: Python name '{py_name}' "
                f"is used by both '{seen[py_name]}' and '{m.name}'")
        else:
            seen[py_name] = m.name

    # Pass 1 — %rename directives.  Emitted ONLY for 'custom' axes.
    for m in visible:
        if not m.is_custom_accessor:
            continue
        py_name = m.py_alias or m.name
        if m.read_mode == 'custom':
            f.write(f'%rename({pre}_{py_name}_get) {pre}_get_{m.name};\n')
        if m.write_mode == 'custom':
            f.write(f'%rename({pre}_{py_name}_set) {pre}_set_{m.name};\n')

    # Pass 1.5 — #define bridges for custom members.
    # SWIG generates wrapper code that calls <struct>_<member>_get/set (SWIG
    # naming convention), but the hand-written C accessors follow the libnvme
    # convention <struct>_get/set_<member>.  A #define makes the generated C
    # code compile without requiring the hand-written functions to be renamed.
    bridges = []
    for m in visible:
        if not m.is_custom_accessor:
            continue
        py_name = m.py_alias or m.name
        if m.read_mode == 'custom':
            bridges.append(
                f'#define {pre}_{py_name}_get {pre}_get_{m.name}')
        if m.write_mode == 'custom':
            bridges.append(
                f'#define {pre}_{py_name}_set {pre}_set_{m.name}')
    if bridges:
        f.write('%{\n')
        for bridge in bridges:
            f.write(f'\t{bridge}\n')
        f.write('%}\n')

    # Pass 2 — struct body.
    f.write(f'struct {struct_name} {{\n')

    # Generated members: plain struct fields — SWIG accesses p->member directly.
    for m in visible:
        if m.is_custom_accessor:
            continue
        py_name = m.py_alias or m.name
        if m.write_mode == 'none':
            f.write(f'\t%immutable {py_name};\n')
        if m.is_scalar_array:
            f.write(f'\t{m.type} {py_name}[{m.array_size}];\n')
        else:
            f.write(f'\t{m.type} {py_name};\n')

    # Custom members: inside %extend — SWIG calls the hand-written accessor.
    # Members with read=none are excluded: SWIG always generates a getter for
    # %extend members, and there is no C function to call for a read=none axis.
    custom = [m for m in visible if m.is_custom_accessor and m.read_mode != 'none']
    if custom:
        f.write('\t%extend {\n')
        for m in custom:
            py_name = m.py_alias or m.name
            if m.write_mode == 'none':
                f.write(f'\t\t%immutable {py_name};\n')
            if m.is_scalar_array:
                f.write(f'\t\t{m.type} {py_name}[{m.array_size}];\n')
            else:
                f.write(f'\t\t{m.type} {py_name};\n')
        f.write('\t}\n')

    f.write('};\n\n')

    # Install __setattr__ guard at module import time.
    f.write(
        f'%pythoncode %{{\n'
        f'{py_class}.__setattr__ = _nvme_guarded_setattr\n'
        f'%}}\n\n'
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
    parser.add_argument('-s', '--swig-out', default=None,
                        dest='s_fname',   metavar='FILE',
                        help='Generated SWIG fragment (*.i). Omit to skip.')
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
    swig_parts = []         # fragments for accessors.i (if --swig-out given)
    swig_errors = []        # deferred SWIG validation errors
    swig_aliases = set()    # alias names seen so far — uniqueness guard

    emit_swig   = args.s_fname is not None
    first_swig  = True      # prelude emitted once, before first struct

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

        for struct_name, members, lc_members, default_members, emit_py, struct_alias in structs:
            has_c_output = bool(members or lc_members is not None
                                or default_members)

            if has_c_output:
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

            if emit_swig and emit_py:
                if struct_alias is not None:
                    if not struct_alias.isidentifier():
                        swig_errors.append(
                            f"error: struct {struct_name}: "
                            f"alias={struct_alias!r} is not a valid "
                            f"Python identifier")
                    elif struct_alias in swig_aliases:
                        swig_errors.append(
                            f"error: struct {struct_name}: "
                            f"alias={struct_alias!r} is already used by "
                            f"another struct")
                    else:
                        swig_aliases.add(struct_alias)
                swig_buf = io.StringIO()
                if first_swig:
                    generate_swig_prelude(swig_buf)
                    first_swig = False
                generate_swig_fragment(swig_buf, args.prefix, struct_name,
                                       members, swig_errors, struct_alias)
                swig_parts.append(swig_buf.getvalue())

    if swig_errors:
        for msg in swig_errors:
            print(msg, file=sys.stderr)
        sys.exit(1)

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
            f'#include <nvme/nvme-types.h>\n'
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

    # --- accessors.i (SWIG fragment) ---------------------------------------
    if emit_swig and args.s_fname:
        makedirs_for(args.s_fname)
        with open(args.s_fname, 'w') as f:
            f.write(
                f'{SPDX_I}\n'
                f'\n'
                f'{BANNER}\n'
            )
            f.write(''.join(swig_parts))

    if args.verbose:
        print(f"\nGenerated {args.h_fname} and {args.c_fname}")
        if emit_swig and args.s_fname:
            print(f"Generated {args.s_fname}")


if __name__ == '__main__':
    main()
