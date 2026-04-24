# Implementation plan — libnvme Python bindings redesign (v10)

## About this document

This document is structured as a phased implementation plan intended to be fed directly to an AI coding assistant (e.g. Claude) to carry out the work. Each phase is a discrete, self-contained unit of work that can be handed to the AI as a single session. The level of detail — invariants, truth tables, code snippets, validation rules — is intentional: it gives the AI enough context to implement each phase correctly without requiring human re-explanation at every step.

The document also serves as a design reference: the decisions and rationale recorded here explain *why* the system is shaped the way it is, not just *what* to build.

---

## Direction in one paragraph

Treat `nvme.i` as **almost entirely generated** from the same `// !generate-accessors` annotations that already drive C accessor generation. Extend `generate-accessors.py` to emit a fourth output (`accessors.i`) that SWIG includes directly — no post-processing, no intermediate `#define` bridge file, no consistency-checker tool. Because these SWIG fragments wrap **private** structs, the Python bindings access struct members **directly** (`p->member`) for any axis whose mode is `generated`; they call the hand-written (custom) accessor only when the axis is `custom`. `%rename` / bridge directives are emitted **only** for `custom` axes — `generated` axes get none. Generated C accessors remain for the public C API's ABI stability, but they add no value inside the Python binding and so the binding does not route through them. The **public Python API is dict-in**: users never see `libnvmf_context`, `libnvme_fabrics_config`, or any other fabrics-layer struct. Internal nested structs (like `libnvmf_context::cfg`) are populated via a table-driven dict traversal in the SWIG typemap, using the native C field reference (`&temp->cfg`) — no accessor indirection. Callbacks are passed inside the cfg dict under a reserved `"callbacks"` key (`{"callbacks": {"on_connected": fn, ...}}`); the fctx stays hidden, and the Python callback receives only semantic arguments. Python classes follow PascalCase: `nvme.Ctrl`, `nvme.Host`, `nvme.Subsystem`, `nvme.Namespace`, `nvme.GlobalCtx`. Code generation is unconditional — the generator always processes all annotated headers; the Meson build system decides what gets compiled. This is a breaking v3.0 release — no aliases, no transitional shims.

**Non-goal.** Generated C accessors remain part of the public C API but are **not** used by the Python bindings. The binding never routes through a generated getter/setter, and the generator never emits `%rename`/bridge directives for `generated` axes.

Priority: **generated-everything > dict-based public API > zero-cost hidden internals > callbacks > Pythonic polish.**

---

## 1. Public Python API

### 1.1 Classes exposed (exactly five)

`nvme.GlobalCtx`, `nvme.Host`, `nvme.Subsystem`, `nvme.Ctrl`, `nvme.Namespace`. PascalCase, following Python class naming conventions.

**Hidden from Python entirely:** `libnvmf_context`, `libnvme_fabrics_config`, `libnvmf_discovery_args`, `libnvmf_uri`, `libnvme_path`, and every other type in `private.h` / `private-fabrics.h`. These exist as SWIG-internal types so typemaps can construct/destruct them transparently, but they are not reachable from Python code.

### 1.2 Attribute model

- C accessor members with a getter → Python read-only `@property`.
- C accessor members with a getter + setter → writable `@property`.
- Methods **only** for operations that do work: `connect`, `disconnect`, `discover`, `rescan`, `init`, `register`, `refresh_topology`, `dump_config`, `get_supported_log_pages`.
- Zero-arg state queries are properties: `ctrl.connected`, `ctrl.registration_supported`.
- Optional string fields return `str | None` (no `'nvme?'`-style sentinels).

### 1.3 Input shape (dict-based)

Single dict, with a nested `"cfg"` sub-dict for fabrics options:

```python
cfg = {
    # Connection (required: subsysnqn, transport)
    "transport": "tcp",
    "subsysnqn": "...",
    "traddr": "...",
    "trsvcid": "4420",
    "host_traddr": "...",
    "host_iface": "eth0",

    # Host identity (optional)
    "hostnqn": "...",
    "hostid": "...",

    # Crypto (optional)
    "hostkey": "...",
    "ctrlkey": "...",
    "keyring": "...",
    "tls_key": "...",
    "tls_key_identity": "...",

    # Persistence (optional)
    "persistent": True,

    # Fabrics config — nested sub-dict, optional
    "cfg": {
        "queue_size": 1000,
        "nr_io_queues": 4,
        "keep_alive_tmo": 10,
        "hdr_digest": True,
        "data_digest": False,
        # ... any libnvme_fabrics_config field
    },

    # Callbacks — optional; value must be a dict of callables
    "callbacks": {
        "decide_retry": fn,
        "on_connected": fn,
        "on_already_connected": fn,
    },
}
ctrl = nvme.Ctrl(ctx, cfg)
```

Rationale: dicts are serializable (JSON / TOML / D-Bus), append-only for new libnvme options without Python churn, and match how `nvme-stas/staslib/ctrl.py:_get_cfg()` already builds them. Objects for `FabricsContext` / `FabricsConfig` were rejected as verbose boilerplate.

### 1.4 Error handling

New exception hierarchy in a new file `libnvme/_exc.py`:

```
NvmeError                  (base, errno + message)
├── ConnectError
├── DisconnectError
├── DiscoverError
└── NotConnectedError      (special: no errno)
```

`ctrl.connect()` / `ctrl.disconnect()` / `ctrl.discover()` raise the matching subclass on failure. The module-level `connect_err` / `discover_err` globals and the `%exception` shim that reads them are deleted; their replacement is a single `raise_nvme(cls, err)` helper called directly from each method body.

`ctrl.get_supported_log_pages()` now raises `NvmeError` on failure instead of returning `None`. (Renamed from `supported_log_pages()` to read as an action — it performs a controller request.) Callers lose the `except (TypeError, IndexError)` guard. This remains a method (not a property) because it performs a controller command.

### 1.5 Callbacks (new)

Passed inside the cfg dict under the reserved `"callbacks"` key; the Python callback receives only semantic arguments (never the internal `fctx`):

```python
def decide_retry(err):
    return err in (errno.ETIMEDOUT, errno.ECONNREFUSED)

def on_connected(ctrl):
    logging.info("connected: %s", ctrl.name)

def on_already_connected(host, subsysnqn, transport, traddr, trsvcid):
    ...

cfg = {
    "transport": "tcp",
    "subsysnqn": "...",
    # ... other fields ...
    "callbacks": {
        "decide_retry": decide_retry,
        "on_connected": on_connected,
        "on_already_connected": on_already_connected,
    },
}
ctrl = nvme.Ctrl(ctx, cfg)
```

Typemap validation: `"callbacks"` value must be a `dict`; each entry must be callable.

See §4 and §5 for the mechanism.

---

## 2. SWIG interface (`nvme.i`)

### 2.1 Files after refactor

```
libnvme/libnvme/
  nvme.i                  hand-written top-level glue (~400 lines)
  nvme-manual-bridges.i   hand-written aliases with inline justifications (≤50 lines)
  accessors.i             GENERATED — common-layer struct decls + %rename (custom axes only)
  accessors-fabrics.i     GENERATED — fabrics-layer struct decls + %rename (custom axes only)
```

`nvme.i` `%include`s in this order: **manual bridges** (first, so aliases are visible), then **common generated**, then **fabrics generated** (conditional on the `fabrics` build option via `#ifdef CONFIG_FABRICS`).

### 2.2 Deletions

| Delete | Approx. lines | Why |
|---|---|---|
| `libnvme/nvme-swig-accessors.i` | 231 | Replaced by `%rename`s inside `accessors*.i` |
| `tools/generator/generate-swig-accessors.py` | 149 | No second-stage post-processing needed |
| `tools/check-nvme-i-consistency.py` + meson test | 553 | `nvme.i` no longer duplicates struct declarations |
| All `#define libnvme_X_Y_get libnvme_X_get_Y` bridges (L57–L92) | ~35 | Emitted as `%rename` directives by generator (for `custom` accessors only) |
| All `struct libnvme_X { %immutable ...; %extend { ... } }` blocks | ~120 | Emitted by generator into `accessors.i` |
| `set_fctx_from_dict` + `%typemap(in) struct libnvmf_context *` chain-of-strcmp | ~170 | Replaced by ~60-line table-driven version (§4 — dict typemap) |
| Four duplicated `%pythoncode %{ def __setattr__ ... %}` blocks | ~60 | Single generated definition + per-class decoration (§2.5) |
| `connect_err` / `discover_err` globals + `%exception` blocks | ~50 | Replaced by direct `raise_nvme()` calls |

### 2.3 Keep (hand-written, by design)

- `%typemap(out) nvmf_discovery_log *` — custom serialization of variable-length C buffer to Python list-of-dicts. No clean 1:1 mapping; legitimate custom converter.
- `uint8_t[8]` / `uint8_t[16]` → `PyBytes` typemaps. Tiny, correct.
- `nbft_get()` and its `ssns_to_dict` / `hfi_to_dict` / `discovery_to_dict` helpers. Same rationale.
- `%rename(GlobalCtx) libnvme_global_ctx;` family — class-level renames (PascalCase, one per exposed class).
- All methods that do work (`connect`, `disconnect`, `discover`, `register`, `init`, `rescan`, `refresh_topology`, `dump_config`, `log_level`, `__str__`, `__enter__` / `__exit__`, iterators). One `%extend` block per class.

### 2.4 Exception shim

```swig
%{
static PyObject *NvmeError              = NULL;
static PyObject *NvmeConnectError       = NULL;
static PyObject *NvmeDisconnectError    = NULL;
static PyObject *NvmeDiscoverError      = NULL;
static PyObject *NvmeNotConnectedError  = NULL;

static void raise_nvme(PyObject *cls, int err) {
    const char *s = libnvme_errno_to_string(err < 0 ? -err : err);
    PyObject *args = Py_BuildValue("(is)", err, s ? s : "unknown");
    PyErr_SetObject(cls, args);
    Py_DECREF(args);
}
%}

%init %{
    PyObject *mod = PyImport_ImportModule("libnvme._exc");
    NvmeError             = PyObject_GetAttrString(mod, "NvmeError");
    NvmeConnectError      = PyObject_GetAttrString(mod, "ConnectError");
    NvmeDisconnectError   = PyObject_GetAttrString(mod, "DisconnectError");
    NvmeDiscoverError     = PyObject_GetAttrString(mod, "DiscoverError");
    NvmeNotConnectedError = PyObject_GetAttrString(mod, "NotConnectedError");
    Py_DECREF(mod);
%}
```

Connect becomes:

```swig
void connect(struct libnvme_host *h) {
    int ret;
    Py_BEGIN_ALLOW_THREADS;
    ret = libnvmf_add_ctrl(h, $self);
    Py_END_ALLOW_THREADS;
    if (ret) { raise_nvme(NvmeConnectError, ret); SWIG_fail; }
}
```

No globals, no two-step `%exception`.

### 2.5 `__setattr__` guard (SWIG-based, centralised)

Emitted exactly once at the top of the generated `accessors.i`:

```swig
%pythoncode %{
def _nvme_guarded_setattr(self, name, value):
    if name == 'this' or name.startswith('_'):
        object.__setattr__(self, name, value); return
    for klass in type(self).__mro__:
        attr = klass.__dict__.get(name)
        if attr is not None:
            if isinstance(attr, property) and attr.fset is not None:
                attr.fset(self, value); return
            break
    raise AttributeError(
        f"'{type(self).__name__}' object has no writable attribute '{name}'"
    )
%}
```

One class-level decoration per exposed struct, emitted by the generator at the bottom of each fragment:

```swig
%pythoncode %{
libnvme_ctrl.__setattr__ = _nvme_guarded_setattr
%}
```

This runs once at module import, covers every subclass (including the hand-written `Ctrl` in §5.3), and sidesteps the `%pythonappend`-through-factory problem entirely. The guard is installed on the SWIG base classes and is inherited by subclasses via normal Python MRO. The fabrics fragment reuses the common fragment's definition via `from libnvme.nvme import _nvme_guarded_setattr` inside its own `%pythoncode` — single definition, no duplication. `nvme.py` is never modified post-generation.

---

## 3. Code generator architecture (dual-pass)

### 3.1 Constraint

`generate-accessors.py` runs **twice**, always, regardless of build configuration:

1. First pass: common headers → `accessors.{h,c,ld,i}`
2. Second pass: fabrics headers → `accessors-fabrics.{h,c,ld,i}`

Both passes always run. Generation is unconditional — it processes all annotated headers unconditionally; inclusion and compilation are build-controlled. The Meson build system decides whether to compile and link `accessors-fabrics.{c,i}` based on the `fabrics` option; the generator doesn't know or care. Fragments must be **independently usable** and **composable**.  

### 3.2 New output: `accessors.i`

Add `-s / --swig-out PATH` to the generator. Each invocation writes one SWIG fragment; a fragment contains struct declarations for every Python-visible struct in its input headers, plus `%rename` directives for `custom` accessor axes only (never for `generated` axes). Fragments have no cross-references. Both `accessors.i` and `accessors-fabrics.i` are always generated; Meson decides whether to compile and include `accessors-fabrics.i` via the `fabrics` build option.

Composability rules:
- Common fragment declares Python-exposed common structs: `libnvme_host`, `libnvme_subsystem`, `libnvme_ctrl`, `libnvme_ns`, `libnvme_global_ctx` (all `!generate-python`).
- Fabrics fragment declares `libnvme_fabric_options` (`!generate-python`) for system-capability introspection from Python. The other fabrics-layer structs (`libnvmf_context`, `libnvme_fabrics_config`, `libnvmf_discovery_args`, `libnvmf_uri`) are `!generate-accessors` only — their C accessors land in `accessors-fabrics.{h,c}` but produce no SWIG fragment entry.
- Neither fragment references a struct declared in the other.
- Both are idempotent under re-inclusion during iterative builds.

### 3.3 Annotation model — two independent dimensions

C accessor generation and Python binding exposure are **fully independent**. A struct may opt into either, both, or neither.

**Dimension A — C accessor generation** (existing):
- `!generate-accessors[:read=M,write=M]` (struct-level) — opts the struct in; optional spec sets the struct-level default mode for each axis. Bare form is shorthand for `read=generated,write=generated`. Partial specs inherit the built-in default (`generated`) for the unnamed axis.
- `!access:read=M,write=M` (member-level) — overrides the struct-level default per axis. Partial specs inherit from the struct-level default.
- Modes: `M ∈ {generated, custom, none}` where:
  - `generated` — the generator emits the C accessor; the Python binding **does not call it** and instead accesses the field directly (`p->member`)
  - `custom`    — an accessor exists but is hand-written elsewhere; the generator emits nothing; the Python binding **calls the hand-written accessor**
  - `none`      — no accessor exists for this axis; no read/write path
- Generated setters implement **type-appropriate assignment**:
  - scalar types → direct assignment (`p->m = v`)
  - `char *` (owned string) → free existing value and assign a duplicated copy
    ```c
    free(p->field);
    p->field = value ? strdup(value) : NULL;
    ```
  - This is the standard generated behavior for owned string fields; the generator is responsible for emitting this logic. Custom setters remain available for special cases (e.g. fields with validation or side-effects).
- `!default:VALUE` (member-level) — applied by the generated constructor (see §3.3.2)
- `!lifecycle:none` (member-level) — tells the generated destructor to skip this member (see §3.3.2)
- `!generate-lifecycle=generated|custom` (struct-level) — controls constructor/destructor emission; omit the annotation for lifecycle = `none` (see §3.3.2)

**Dimension B — Python binding exposure** (new):
- `!generate-python` (struct-level) — emit SWIG fragment for this struct
- `!python:none` (member-level) — exclude from SWIG fragment
- `!python:alias=NAME` (member-level) — rename the Python-visible attribute

**Access routing (per axis, inside the SWIG fragment):**

```
read  == generated  → direct field read        p->member
read  == custom     → call hand-written getter libnvme_*_get_member(p)
read  == none       → no getter
write == generated  → direct field assignment  p->member = value
write == custom     → call hand-written setter libnvme_*_set_member(p, value)
write == none       → %immutable
```

**`%rename` / bridge-emission rule (single source of truth).**

- `%rename` / bridge directives are emitted **only** for members whose axis is `custom` (i.e. `read == custom` and/or `write == custom`). Such a directive exposes the hand-written accessor under the SWIG-recognized name (`pre_py_name_get` / `pre_py_name_set`) so it is picked up as the getter/setter for the Python-visible attribute.
- Members with `generated` access use direct struct access (`p->member`) and **must not** use accessor functions in the SWIG layer. **No `%rename`, no `#define` bridge, no `%extend` wrapper is emitted for them.** SWIG's default get/set of a struct member (triggered by declaring the field inside the fragment) is the sole mechanism.
- Members with `none` on an axis produce nothing for that axis; `write == none` additionally triggers `%immutable`.

This rule is deterministic and admits no conditional ambiguity: count of emitted `%rename`/bridge directives per struct equals the number of `custom` axes among its Python-visible members.

Rationale. Generated C accessors are a trivial field-read / field-assign wrapper; inside the Python binding they add an indirection with no gain, because the SWIG fragment wraps the *private* struct and already has direct field access. Calling the generated accessor would also cross the shared-library boundary unnecessarily. The public C API still uses the generated accessors for ABI stability — that is not changed by this rule.

**Derived properties** (from the two-axis spec; used by the generator):

```
gen_getter         = (read  == "generated")   # → direct field read in SWIG
gen_setter         = (write == "generated")   # → direct field assign in SWIG
has_accessor       = (read  != "none") or (write != "none")
is_custom_accessor = (read  == "custom") or (write == "custom")
```

**Invariants:**

1. **Struct exposure (opt-in, strict).** A struct is Python-exposed **if and only if** it carries `!generate-python`. There is no default and no implicit exposure.

2. **Access-path prerequisite.** A member can be exposed to Python only if it has a usable access path, defined as at least one axis provides access (i.e. `has_accessor == true` → `read != none` or `write != none`). SWIG has nothing to wrap otherwise. The access path may be either direct field access (for `generated` axes) or an accessor call (for `custom` axes) — the invariant is agnostic to which.

3. **Member exposure (conjunctive).** A member is Python-exposed **if and only if** all of the following hold:
   - its containing struct carries `!generate-python`, AND
   - `has_accessor == true`, AND
   - the member does **not** carry `!python:none`.

4. **Read/write mode** derives **only** from the `!access:read=,write=` spec (with struct-level inheritance). No `!python:readonly` / `!python:writeonly` exists.

5. **Generated-setter semantics.** A generated setter performs a type-appropriate assignment. For scalar types, this is a direct field write. For owned string types (`char *`), the generator emits `free(p->m); p->m = value ? strdup(value) : NULL;`. `const` members always force `write == none`. Fields that require validation, invariants, or side-effects beyond free+strdup must use `write == custom`.

6. **Uniqueness.** Within one struct, no two Python-visible members may resolve to the same Python name after alias resolution.

**Examples:**

```c
/* Exposed to Python AND has C accessors: */
struct libnvme_ctrl {                   // !generate-accessors !generate-python
    char *name;                         // !access:read=generated,write=none   → Ctrl.name (ro, direct read)
    char *traddr;                       // !access:read=generated,write=none   → Ctrl.traddr (ro, direct read)
    char *state;                        // !access:read=custom,write=none      → Ctrl.state (ro, hand-written getter)
    long  command_error_count;          // !access:read=none,write=none        → neither C nor Py
    char *dhchap_host_key;              // !access:read=generated,write=generated → Ctrl.dhchap_host_key (rw)
                                        //   read via p->dhchap_host_key
                                        //   write via generated setter (free + strdup)
    struct libnvme_fabrics_config cfg;  // (no annotation needed — typemap uses &p->cfg)
};

/* C-only — consumed by the dict typemap, never exposed to Python: */
struct libnvme_fabrics_config {         // !generate-accessors
    bool hdr_digest;
    int  queue_size;
    /* no !generate-python → no SWIG fragment */
};

/* C-only container; the typemap reaches the nested cfg as &fctx->cfg —
 * no accessor, no annotation needed on the nested member: */
struct libnvmf_context {                // !generate-accessors
    struct libnvme_fabrics_config cfg;
    /* ... */
};
```

### 3.3.1 Validation — fail fast at generation time

The generator MUST surface every invalid annotation combination at generation time and exit non-zero. No warnings. No silent skips. No partial output files on disk when validation fails.

**Hard errors:**

| # | Condition | Rationale |
|---|---|---|
| V1 | Struct carries `!generate-python` but resolves to zero Python-visible members | Empty SWIG fragment is always a mistake |
| V2 | `!python:alias=NAME` on a member with `has_accessor == false` (effective `read=none` AND `write=none`) | Nothing to rename |
| V3 | `!python:none` on a member of a struct that lacks `!generate-python` | Contradictory intent — no Python binding exists either way; annotation indicates confusion |
| V4 | `!python:alias=NAME` on a member that also carries `!python:none` | Contradictory: cannot both rename and hide |
| V5 | Two Python-visible members in the same struct resolve to the same Python name (natural name or via alias) | Collision per invariant #6 |
| V6 | `!python:alias=NAME` where `NAME` does not match `[A-Za-z_][A-Za-z0-9_]*` | Invalid Python identifier |
| V7 | Struct carries `!generate-python` without `!generate-accessors`, and no member has `is_custom_accessor == true` (no member has `read=custom` or `write=custom`) | No access path to wrap (per invariant #2) |
| V8 | Unknown key inside `cfg["callbacks"]` (not in the set of recognised callback names) | Silent typos would be impossible to debug. The set of valid callback keys is defined in the generator and emitted into both validation logic and typemap. This same generated set is used for runtime validation. |

**Error behavior:**

- Each diagnostic includes file path, line number, struct name, member name (where applicable), and the violating annotation text.
- Multiple errors in one run are collected and reported together; the generator exits non-zero after reporting.
- No partial output files are written when any validation error is raised — the build fails cleanly, not with stale fragments on disk.

**Invariant:** every invalid annotation combination is a build-time error, not a runtime surprise.

### 3.3.2 Lifecycle annotation (struct-level)

**Syntax** — on the struct's brace line; only two forms are accepted:

    // !generate-lifecycle=generated
    // !generate-lifecycle=custom

**Semantics:**

- `generated` — the generator emits both a constructor and a destructor for the struct.
- `custom`    — lifecycle functions exist but are hand-written elsewhere; the generator emits nothing.

**Default.** If `!generate-lifecycle` is absent, lifecycle mode is `none` — no lifecycle functions exist for the struct and the generator emits nothing. There is no explicit `!generate-lifecycle=none` form; omit the annotation instead.

**Generated constructor** (when `!generate-lifecycle=generated`):

1. Allocate the struct.
2. Initialize all fields to zero / `NULL`.
3. Apply every member-level `!default:VALUE` initializer.

**Generated destructor** (when `!generate-lifecycle=generated`):

1. For each member, in declaration order:
   - `char *` → `free(p->m)`
   - skip members annotated `!lifecycle:none`
   - skip `const`-qualified members
2. Free the struct itself.

**Separation of concerns:**

- **Lifecycle is struct-level** (create / delete).
- **Access is member-level** (read / write).
- No member-level lifecycle *modes* exist. The only member-level lifecycle annotation is `!lifecycle:none`, a per-member flag that excludes a member from the generated destructor — it is not a mode selector, and it has no effect on access routing.

**SWIG emission truth table:**

"SWIG read path" and "SWIG write path" describe how the emitted fragment actually reads or writes the member — direct field access for `generated` (no `%rename`, no bridge), accessor call via `%rename` for `custom`. "C accessor emitted?" refers separately to whether `generate-accessors.py` emits the C-level getter/setter into `accessors.{h,c,ld}` for ABI purposes, which is independent of the SWIG-layer path.

| Struct | Member | C accessor emitted? | SWIG read path | SWIG write path | SWIG entry? |
|---|---|---|---|---|---|
| `!generate-accessors` + `!generate-python` | default (struct default `read=generated,write=generated`) | yes, rw (setter is scalar-assign or free+strdup depending on type) | direct `p->m` | direct `p->m = v` | yes, rw |
| `!generate-accessors` + `!generate-python` | `!access:read=generated,write=none` | yes, getter only | direct `p->m` | `%immutable` | yes, ro |
| `!generate-accessors` + `!generate-python` | `!access:read=none,write=generated` | yes, setter only (scalar-assign or free+strdup depending on type) | — | direct `p->m = v` | yes, wo |
| `!generate-accessors` + `!generate-python` | `!access:read=none,write=none` | no | — | — | no |
| `!generate-accessors` + `!generate-python` | `!access:read=custom,write=none` | no (hand-written externally) | call `libnvme_*_get_m(p)` | `%immutable` | yes, ro, under member name (or alias) |
| `!generate-accessors` + `!generate-python` | `!access:read=none,write=custom` | no (hand-written externally) | — | call `libnvme_*_set_m(p,v)` | yes, wo, under member name (or alias) |
| `!generate-accessors` + `!generate-python` | `!access:read=custom,write=custom` | no (hand-written externally) | call `libnvme_*_get_m(p)` | call `libnvme_*_set_m(p,v)` | yes, rw, under member name (or alias) |
| `!generate-accessors` + `!generate-python` | `!access:read=generated,write=custom` (special-case setters with side-effects) | yes, getter only (setter is hand-written) | direct `p->m` | call `libnvme_*_set_m(p,v)` | yes, rw |
| `!generate-accessors` + `!generate-python` | `!python:none` | per spec | — | — | no |
| `!generate-accessors` + `!generate-python` | `!python:alias=X` | per spec | per spec | per spec | yes, under name `X` |
| `!generate-accessors` only | any | per spec | — | — | no |
| `!generate-python` only | at least one member with `read=custom` or `write=custom` | no (hand-written externally) | per spec | per spec | yes (Note 1) |
| `!generate-python` only | no member with `read=custom` or `write=custom` | n/a | — | — | ERROR V7 (no access path to wrap) |
| neither | any | no | — | — | no |

Note 1: A struct satisfies the access-path requirement if at least one member has `has_accessor == true` (some axis is `generated` or `custom`). Direct field access via the SWIG fragment is sufficient; no generated C accessor is required.

### 3.4 Generator code additions

```python
# In generate-accessors.py

class Member:
    __slots__ = (..., 'read_mode', 'write_mode',
                 'py_visible', 'py_alias')
    # read_mode / write_mode:  'generated' | 'custom' | 'none'
    #                          Derived from the effective !access:read=...,write=...
    #                          spec (member-level override layered on the
    #                          struct-level default; `const` qualifier forces
    #                          write_mode='none').
    # py_visible:              False if member carries !python:none
    # py_alias:                'NAME' from !python:alias=NAME, else None

    # Derived — computed at use-site, not stored:
    @property
    def gen_getter(self):         return self.read_mode  == 'generated'
    @property
    def gen_setter(self):         return self.write_mode == 'generated'
    @property
    def has_accessor(self):       return self.read_mode != 'none' or self.write_mode != 'none'
    @property
    def is_custom_accessor(self): return self.read_mode == 'custom'    or self.write_mode == 'custom'

# --- struct-level parsing -------------------------------------------------
want_accessors   = has_annotation(brace_line, 'generate-accessors')
emit_py_fragment = has_annotation(brace_line, 'generate-python')
# Both derive from header annotations — no CLI flags or build-time gates.
# The two dimensions are independent; a struct may have one, both, or neither.
# Struct-level !generate-accessors[:read=M,write=M] sets the default modes;
# built-in default for any axis not named is 'generated'.

# --- member-level parsing -------------------------------------------------
# !access:read=M,write=M overrides struct-level defaults per axis.  Partial
# specs inherit the axis not named.
py_visible = not has_annotation(raw_line, 'python:none')
py_alias   = parse_kv_annotation(raw_line, 'python:alias')  # 'NAME' or None

# --- validation collector -------------------------------------------------
# One shared list of diagnostics — the generator never raises mid-parse.
# After the whole run, if errors is non-empty, print all and exit(1) WITHOUT
# writing any output file.  Ensures V1–V8 all surface in a single run.
errors: list[Diagnostic] = []

def generate_swig_fragment(f, prefix, struct_name, members):
    """Emit struct decl with per-axis read/write routing.

    Routing per axis:
      generated → direct field access (SWIG's default getset for a declared
                  struct member).  No %rename, no bridge, no wrapper.
      custom    → %rename of the hand-written accessor to SWIG's expected
                  getter/setter name so SWIG uses it as the attribute
                  implementation.
      none      → read: no getter declared; write: %immutable.

    Precondition: caller only invokes this when the struct is annotated
    !generate-python.  Invariant violations are appended to the shared
    `errors` list (V1–V8); emission continues so all errors surface
    together.

    Emission invariant: the count of %rename / bridge directives emitted
    for this struct equals the number of 'custom' axes among its
    Python-visible members.  'generated' axes never cause emission.
    """
    pre = f"{prefix}{struct_name}"
    f.write(f'/* struct {struct_name} */\n')

    # Collision detection — performed before any emission.
    seen = {}
    for m in members:
        if not m.py_visible or not m.has_accessor:
            continue
        name = m.py_alias or m.name
        if name in seen:
            errors.append(Diagnostic(
                code='V5', file=m.file, line=m.line, struct=struct_name,
                member=m.name,
                msg=f"Python name collision: '{m.name}' and "
                    f"'{seen[name]}' both map to '{name}'"))
            continue
        seen[name] = m.name

    # Pass 1 — %rename directives.  Emitted ONLY for 'custom' axes.
    # 'generated' axes emit nothing here (the field declaration below
    # gives SWIG direct access).
    for m in members:
        if not m.py_visible or not m.has_accessor:
            continue
        py_name = m.py_alias or m.name
        if m.read_mode == 'custom':
            f.write(f'%rename({pre}_{py_name}_get) {pre}_get_{m.name};\n')
        if m.write_mode == 'custom':
            f.write(f'%rename({pre}_{py_name}_set) {pre}_set_{m.name};\n')

    # Pass 2 — struct body.  Declaring the field inside %extend triggers
    # SWIG's default field get/set (direct access for 'generated' axes)
    # while the %rename directives above route 'custom' axes to the
    # hand-written accessor functions.
    f.write(f'struct {struct_name} {{\n')

    for m in members:
        if not m.py_visible or not m.has_accessor:
            continue
        if m.write_mode == 'none':
            f.write(f'\t%immutable {m.py_alias or m.name};\n')

    f.write('\t%extend {\n')
    for m in members:
        if not m.py_visible or not m.has_accessor:
            continue
        f.write(f'\t\t{m.type} {m.py_alias or m.name};\n')
    f.write('\t}\n};\n\n')

    # Installer for __setattr__ guard — class-level decoration at
    # module import (covers subclasses including the hand-written Ctrl).
    f.write(
        f'%pythoncode %{{\n'
        f'{struct_name}.__setattr__ = _nvme_guarded_setattr\n'
        f'%}}\n\n'
    )

def generate_swig_prelude(f):
    """Emitted once at top of each fragment."""
    f.write('%pythoncode %{\n'
            'def _nvme_guarded_setattr(self, name, value):\n'
            '    ...\n'
            '%}\n\n')

# --- main loop ------------------------------------------------------------
# C accessors:      emit IFF want_accessors   (dimension A)
# SWIG fragment:    emit IFF emit_py_fragment  (dimension B)
# The two emission paths are independent and run on the same parsed struct.
```

`meson.build` declares `accessors.i` and `accessors-fabrics.i` as always-present outputs — the generator is never gated by build options. `nvme.i` conditionally includes `accessors-fabrics.i` via `#ifdef CONFIG_FABRICS`; the `fabrics` Meson option controls the preprocessor flag and linker step, not generation.

### 3.5 Retirements

- `tools/generator/generate-swig-accessors.py` — deleted. Its sole job (emit `#define` bridges) is now handled by `%rename` directives emitted inline — restricted to `custom` axes only.
- `tools/check-nvme-i-consistency.py` — deleted. With `nvme.i` no longer duplicating struct declarations, there is nothing to verify.

---

## 4. Dict typemap (table-driven)

Replace the 170-line chain-of-`strcmp` in `set_fctx_from_dict` with a ~60-line table-driven dispatcher. The field tables are **generated** at build time from accessor annotations (small helper script reusing `generate-accessors.py`'s parser writes `fctx_field_tables.c`).

Each table entry's `apply` function follows the same per-axis routing as the SWIG fragment: for members with `write == generated` it assigns directly to the C field (`target->m = v`); for members with `write == custom` it calls the hand-written setter. The typemap itself reaches the nested `cfg` sub-struct via `&temp->cfg` — no accessor indirection, since the typemap is compiled inside the libnvme SWIG module and has direct access to the private struct layout.

```c
struct fctx_field {
    const char *key;
    enum { FLD_STR, FLD_INT, FLD_BOOL } type;
    void (*apply)(struct libnvmf_context *fctx, PyObject *val);
};

/* Generated from annotations: */
static const struct fctx_field CONN_FIELDS[]   = { ... };   /* traddr, trsvcid, ... */
static const struct fctx_field HOST_FIELDS[]   = { ... };   /* hostnqn, hostid */
static const struct fctx_field CRYPTO_FIELDS[] = { ... };
static const struct fctx_field CFG_FIELDS[]    = { ... };   /* applied to fctx->cfg */

static int apply_table(void *target, PyObject *dict,
                       const struct fctx_field *table, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        PyObject *val = PyDict_GetItemString(dict, table[i].key);
        if (val && val != Py_None)
            table[i].apply(target, val);
    }
    return 0;
}

/* Top-level typemap body: */
%typemap(in) struct libnvmf_context * (struct libnvmf_context *temp = NULL) {
    if (!PyDict_Check($input)) { /* TypeError */ SWIG_fail; }
    if (libnvmf_context_create(arg1, NULL, NULL, NULL, NULL, &temp)) { SWIG_fail; }

    apply_table(temp, $input, CONN_FIELDS,   N_CONN);
    apply_table(temp, $input, HOST_FIELDS,   N_HOST);
    apply_table(temp, $input, CRYPTO_FIELDS, N_CRYPTO);

    /* Nested "cfg" sub-dict — direct field reference, no accessor. */
    PyObject *sub = PyDict_GetItemString($input, "cfg");
    if (sub) {
        if (!PyDict_Check(sub)) { /* TypeError */ SWIG_fail; }
        apply_table(&temp->cfg, sub, CFG_FIELDS, N_CFG);
    }

    /* Callbacks — extracted early, before field dispatch */
    PyObject *cbs_dict = PyDict_GetItemString($input, "callbacks");
    if (cbs_dict) {
        if (!PyDict_Check(cbs_dict)) {
            PyErr_SetString(PyExc_TypeError,
                "'callbacks' must be a dict of callables");
            SWIG_fail;
        }
        PyObject *cb_key, *cb_val;
        Py_ssize_t cb_pos = 0;
        while (PyDict_Next(cbs_dict, &cb_pos, &cb_key, &cb_val)) {
            if (!PyCallable_Check(cb_val)) {
                PyErr_Format(PyExc_TypeError,
                    "callbacks['%U'] is not callable", cb_key);
                SWIG_fail;
            }
        }
    }

    /* persistent, etc. — handled explicitly */

    /* Reject unknown keys. Collect all of them and report as a set. */
    validate_keys_or_fail($input, ALL_KNOWN_KEYS);

    $1 = temp;
}
```

Unknown keys produce `KeyError("unknown key(s): {'foo', 'bar'}")` — reports every unrecognised key at once, not just the first. Unknown keys *inside* `"callbacks"` are a separate hard error (V8 equivalent at runtime): `KeyError("unknown callback(s): {'on_whatever'}")`.

**The typemap is the sole dict-extraction path.** The `Ctrl` factory (§5.3) takes `struct libnvmf_context *fctx` as its effective C input; SWIG fires this typemap to convert the Python `cfg` dict transparently. There is no duplicate extraction in the constructor body — validation of `"callbacks"` values and of every other field lives here and only here.

### 4.1 Dual lifetime paths

Two branches at typemap time, selected by whether the `"callbacks"` sub-dict is present and non-empty:

- **Dict-only path** (no callbacks) — `%typemap(freearg)` frees the fctx immediately after `libnvmf_create_ctrl` returns. Current behavior, preserved.
- **Callback-bearing path** — fctx is retained, attached to the Python `Ctrl` instance as a `PyCapsule` (see §5.3), and freed by the capsule destructor when the instance is GC'd. Needed so fctx-using operations (discovery calls that take an fctx) can fire the callbacks later.

Branch is chosen by inspecting `$input["callbacks"]` — a dict with at least one entry triggers retention; absence / empty dict / `None` triggers the ephemeral path.

### 4.1.1 Lifetime invariant

Exactly one owner exists for each `libnvmf_context` instance:

- **Ephemeral path (no callbacks):**
  - Ownership is held by the typemap
  - `%typemap(freearg)` frees the context after `libnvmf_create_ctrl` returns

- **Callback-bearing path:**
  - Ownership is transferred to the Python `Ctrl` instance via a `PyCapsule`
  - The capsule destructor is solely responsible for calling `libnvmf_free_ctx`

These two paths are mutually exclusive. The typemap must not free the context when it is retained by the `Ctrl` instance, and the capsule destructor must never run on a context freed by the typemap.

Invariant: **a `libnvmf_context` is freed exactly once, by exactly one owner.** Implementations should enforce this invariant defensively (e.g., by nulling or transferring ownership pointers explicitly after handoff).

---

## 5. Callbacks (decoupled from any public object)

### 5.1 Surface

| Operation | Callback source |
|---|---|
| `nvme.Ctrl(ctx, cfg)` with `cfg["callbacks"]` | `decide_retry`, `on_connected`, `on_already_connected` — extracted from `"callbacks"` dict, stored on ctrl |
| `ctrl.discover(..., on_discovery_log=fn)` | Per-call kwarg; scope is the discover operation |

### 5.2 Mechanism

Four C trampolines (not SWIG directors — signatures are fixed, directors pull in C++ RTTI). One payload struct lives on the Python side as `ctrl.__cbs`; a pointer to it is passed as the `void *user_data` argument to `libnvmf_context_create`.

```c
/* nvme_py_callbacks.c — included by nvme.i */
struct libnvmf_py_cbs {
    PyObject *decide_retry;
    PyObject *on_connected;
    PyObject *on_already_connected;
    PyObject *on_discovery_log;
};

static bool _cb_decide_retry(struct libnvmf_context *fctx, int err,
                             void *user_data) {
    struct libnvmf_py_cbs *cbs = user_data;
    if (!cbs || !cbs->decide_retry) return true;   /* default: retry */
    PyGILState_STATE g = PyGILState_Ensure();
    /* fctx NOT passed to Python — kept internal */
    PyObject *r = PyObject_CallFunction(cbs->decide_retry, "i", err);
    bool ret = r && PyObject_IsTrue(r);
    Py_XDECREF(r);
    if (PyErr_Occurred()) PyErr_WriteUnraisable(cbs->decide_retry);
    PyGILState_Release(g);
    return ret;
}

static void _cb_connected(struct libnvmf_context *fctx,
                          struct libnvme_ctrl *c, void *user_data) {
    struct libnvmf_py_cbs *cbs = user_data;
    if (!cbs || !cbs->on_connected) return;
    PyGILState_STATE g = PyGILState_Ensure();
    PyObject *c_obj = SWIG_NewPointerObj(c, SWIGTYPE_p_libnvme_ctrl, 0);
    PyObject *r = PyObject_CallFunction(cbs->on_connected, "O", c_obj);
    Py_DECREF(c_obj);
    Py_XDECREF(r);
    if (PyErr_Occurred()) PyErr_WriteUnraisable(cbs->on_connected);
    PyGILState_Release(g);
}

/* _cb_already_connected, _cb_discovery_log similarly. */
```

Key points:
- `PyGILState_Ensure` / `Release` — trampolines fire on threads that do not hold the GIL (because `libnvmf_add_ctrl` runs inside `Py_BEGIN_ALLOW_THREADS`).
- Python exceptions go to `sys.unraisablehook` via `PyErr_WriteUnraisable`. Never propagated into C.
- The `fctx` argument is **dropped** before calling Python. Python callbacks receive only semantic arguments.
- Defaults baked into trampolines when a slot is NULL (matching current libnvme behavior when a NULL fn ptr is passed).

### 5.3 Plumbing — factory pattern

The `Ctrl` class does **not** use a SWIG `%extend` constructor, because `%extend` + `%pythonappend` cannot cleanly transfer auxiliary Python state (`_cbs`, `_fctx`) from C to the wrapped instance. Instead: a hand-written C helper returns a tuple; a Python-side subclass invokes it via `__new__`.

**(a) C helper** — in a small hand-written `nvme_py_ctrl.c`, exposed via `%inline`:

```c
%inline %{
/* Returns a 3-tuple: (SWIG-wrapped ctrl, cbs PyCapsule|None, fctx PyCapsule|None).
 * fctx arrives pre-built by the %typemap(in) from the user's cfg dict,
 * with callbacks already validated and attached as user_data (§4). */
static PyObject *
_libnvme_ctrl_create(struct libnvme_global_ctx *ctx,
                     struct libnvmf_context *fctx) {
    struct libnvme_ctrl *c = NULL;
    int rc;
    Py_BEGIN_ALLOW_THREADS;
    rc = libnvmf_create_ctrl(ctx, fctx, &c);
    Py_END_ALLOW_THREADS;
    if (rc) { raise_nvme(NvmeConnectError, rc); return NULL; }

    bool retain = libnvmf_context_has_py_cbs(fctx);

    PyObject *ctrl_py  = SWIG_NewPointerObj(c, SWIGTYPE_p_libnvme_ctrl,
                                              SWIG_POINTER_OWN);
    PyObject *cbs_cap  = retain
        ? PyCapsule_New(libnvmf_context_get_py_cbs(fctx),
                        "libnvmf_py_cbs", _py_cbs_destroy)
        : Py_NewRef(Py_None);
    PyObject *fctx_cap = retain
        ? PyCapsule_New(fctx, "libnvmf_context", _fctx_destroy)
        : Py_NewRef(Py_None);  /* ephemeral path: %typemap(freearg) frees fctx */

    return Py_BuildValue("(NNN)", ctrl_py, cbs_cap, fctx_cap);
}
%}
```

**(b) SWIG glue** — suppress the default constructor so the Python factory is the only path:

```swig
/* No %extend libnvme_ctrl constructor.  All construction goes through
 * the Python factory (below), which reaches C via _libnvme_ctrl_create. */
```

**(c) Python class** — emitted into the generated `nvme.py` via `%pythoncode`:

```swig
%pythoncode %{
class Ctrl(libnvme_ctrl):          # inherits methods/properties from SWIG class
    def __new__(cls, ctx, cfg):
        wrapped, cbs, fctx = _libnvme_ctrl_create(ctx, cfg)   # typemap fires on cfg
        wrapped.__class__ = cls    # re-class to Ctrl so isinstance() works
        wrapped._cbs  = cbs        # PyCapsule; destructor frees libnvmf_py_cbs
        wrapped._fctx = fctx       # PyCapsule; destructor calls libnvmf_free_ctx
        return wrapped
    def __init__(self, *_a, **_kw):
        pass                       # __new__ did the work; suppress SWIG __init__
%}
```

**Lifetime.** `_cbs` / `_fctx` are `PyCapsule` objects. When the `Ctrl` instance is GC'd, Python releases its refs; the capsule destructors free the underlying C resources in the right order (`libnvme_free_ctrl` runs via SWIG's `thisown`; the capsule destructor for `_fctx` runs after, calling `libnvmf_free_ctx`; the `_cbs` capsule destructor `Py_XDECREF`s each stored Python callable).

**`__setattr__` guard.** No longer installed via `%pythonappend` (which didn't fire through this factory path anyway). Instead, the generator emits a single line per exposed class at the bottom of each fragment:

```swig
%pythoncode %{
libnvme_ctrl.__setattr__ = _nvme_guarded_setattr
%}
```

This runs once at module import and covers both `libnvme_ctrl` and any subclass (including `Ctrl`).

### 5.4 Why not other approaches

- **Post-construction setters** (`ctrl.on_connected = fn`): `libnvmf_context_create` takes the three main callbacks only at creation time; post-hoc setters for them don't exist in the C API, and adding them just to accommodate this Python idiom is wrong-direction.
- **Exposing `FabricsContext` for callback ownership**: rejected per Δ1 — the whole point is to keep fctx internal.

---

## 6. Alias mechanism (`!python:alias=NAME`)

### 6.1 Default: no alias

If the Python attribute name matches the C member name, no alias is needed. This is the target state for ~100% of fields.

### 6.2 Bug fixes (not aliases)

The current `libnvme_ctrl_address_get` → `libnvme_ctrl_get_traddr` mapping is a naming bug. **Fix:** the Python attribute becomes `ctrl.traddr`. The `address` name is deleted. `nvme-stas` is updated to use `traddr`. No alias is introduced for this case.

### 6.3 When `!python:alias=NAME` is permitted

Only when renaming the C member would break the libnvme shared library ABI. Each alias must have a one-line justification next to it in the source:

```c
char *some_legacy_name; // !python:alias=preferred
                        //   Keep preferred Python name exposed while retaining
                        //   the C member name some_legacy_name for ABI reasons.
```

### 6.4 Alias rules

- Syntax: `!python:alias=NAME` where `NAME` matches `[A-Za-z_][A-Za-z0-9_]*`.
- The alias **overrides** the original name in the Python API. The C member name is not also exposed via SWIG.
- The underlying C accessor keeps the C member name (`libnvme_X_get_original`). SWIG only renames the Python-visible symbol via `%rename`.
- Two members in the same struct resolving to the same Python name (via alias and/or collision with another member's natural name) is a generator error, raised at emission time.
- No corresponding `%extend` entry is emitted under the original C member name — only under the alias. Avoids duplicate-attribute conflicts.

Expected alias count after v3.0 cleanup: **0**. The mechanism exists as a safety valve for future ABI constraints, not as a recurring pattern.

### 6.5 Manual bridges file

Still required for genuine C-macro bridges that are not expressible as `%rename` — e.g. bridging between a SWIG member name and a hand-written C helper function with a different name. Each entry in `nvme-manual-bridges.i` carries a justification comment. Expected entries: ≤3.

---

## 7. Migration plan (three phases, v3.0)

**Phase 1 — generator + SWIG fragment.**
- Add `--swig-out` to `generate-accessors.py`.
- Add the struct-level `!generate-python` gate and member-level `!python:none` / `!python:alias=NAME` annotations.
- Implement per-axis access routing in the SWIG fragment emitter: direct field access for `generated` (no `%rename`/bridge emitted), `%rename` of the hand-written accessor for `custom`, `%immutable` for `write=none`.
- Implement type-aware generated setters: scalar types → direct assignment; `char *` → `free(p->m); p->m = v ? strdup(v) : NULL;`.
- Implement the struct-level `!generate-lifecycle=generated|custom` annotation (absence ⇒ lifecycle = `none`; no explicit `=none` form). For `generated`, emit constructor (alloc + zero-init + apply `!default:VALUE`) and destructor (free owned `char *` members, skip `!lifecycle:none` and `const` members, free struct).
- Annotate existing structs: apply `!generate-python` to `libnvme_global_ctx`, `libnvme_host`, `libnvme_subsystem`, `libnvme_ctrl`, `libnvme_ns`, and `libnvme_fabric_options` (the sole fabrics-layer struct exposed to Python, for read-only capability introspection). Leave `libnvme_fabrics_config`, `libnvmf_context`, `libnvmf_discovery_args`, `libnvmf_uri`, `libnvme_path` as C-only.
- Emit `accessors.i` and `accessors-fabrics.i`.
- Create `nvme-manual-bridges.i` with residual bridges (target: ≤3 entries).
- Delete `generate-swig-accessors.py`, `nvme-swig-accessors.i`, `check-nvme-i-consistency.py`, and its meson test entry.
- Delete all hand-written struct/`%extend` blocks and `#define` bridge macros from `nvme.i`.
- Create `libnvme/_exc.py` with the exception hierarchy.
- Delete `connect_err` / `discover_err` globals + `%exception` blocks; replace with direct `raise_nvme()` calls.
- Install the `__setattr__` guard via generator-emitted per-class decorations (`T.__setattr__ = _nvme_guarded_setattr`) at module import — never post-process `nvme.py`, never `%pythonappend` (won't fire through the Ctrl factory).
- Fix the `address`/`traddr` naming bug: expose `ctrl.traddr` only (no alias).

**Phase 2 — dict typemap rewrite + callbacks.**
- Replace `set_fctx_from_dict` with the table-driven version. Tables generated from accessor annotations.
- Implement nested `"cfg"` sub-dict traversal via direct field reference (`&temp->cfg`) — no accessor indirection; the typemap has direct access to the private struct layout.
- Implement `"callbacks"` dict key extraction and validation in the typemap (§4).
- Add callback trampolines + `libnvmf_py_cbs` struct + ctrl `__cbs` / `__fctx` storage.
- Add the dual-lifetime paths in the ctrl typemap (ephemeral fctx vs ctrl-retained fctx).

**Phase 3 — surface polish (libnvme only).**
- Convert `connected()` / `is_registration_supported()` to properties.
- Convert `host.set_symname(x)` to `host.hostsymname = x`; delete `set_symname`.
- Rename `registration_ctlr` → `register`.

**nvme-stas update (separate, after v3.0 ships).**
- Update `staslib/ctrl.py:_get_cfg()` to nest fabrics-config keys under `"cfg"` and pass `"callbacks"` sub-dict.
- Replace `ctrl.address` → `ctrl.traddr`.
- Drop the `'nvme?'` sentinel in `staslib/ctrl.py:88` — let `device` return `None`.
- Replace `ctrl.supported_log_pages()` call sites with `ctrl.get_supported_log_pages()` and replace the surrounding `except (TypeError, IndexError)` guard with `except nvme.NvmeError`.
- Replace bare `RuntimeError` catches with `nvme.ConnectError` / `nvme.DiscoverError`.

Phases 1–3 are entirely in `nvme-cli/libnvme`. `nvme-stas` is updated separately after the v3.0 bindings are released — no per-phase cross-repo coordination. No backward-compat aliases, no deprecation warnings.

---

## 8. Before / after usage (Python)

### 8.1 Construction + connect

**Before** (`staslib/ctrl.py:221–261`, distilled):
```python
root = nvme.global_ctx()
host = nvme.host(root, hostnqn=h, hostid=i, hostsymname=s)
host.dhchap_key = sysconf.hostkey if supp else None
ctrl = nvme.ctrl(root, cfg)                       # flat dict
ctrl.discovery_ctrl = True
if dhchap_host_key and supp:
    ctrl.dhchap_host_key = dhchap_host_key
ctrl.connect(host)                                # raises RuntimeError on failure
```

**After:**
```python
root = nvme.GlobalCtx()
host = nvme.Host(root, hostnqn=h, hostid=i, hostsymname=s)
host.dhchap_key = sysconf.hostkey if supp else None

cfg = {
    "transport": "tcp",
    "subsysnqn": "...",
    "traddr": "...",
    "trsvcid": "4420",
    "cfg": {                      # nested sub-dict
        "keep_alive_tmo": 10,
        "hdr_digest": True,
    },
}
ctrl = nvme.Ctrl(root, cfg)
ctrl.discovery_ctrl = True
if dhchap_host_key and supp:
    ctrl.dhchap_host_key = dhchap_host_key
try:
    ctrl.connect(host)
except nvme.ConnectError as e:
    logging.error("connect failed (errno=%d): %s", e.errno, e.message)
```

### 8.2 Registration

**Before** (`staslib/ctrl.py:579–583`):
```python
if ctrl.is_registration_supported():
    result = ctrl.registration_ctlr(nvme.NVMF_DIM_TAS_REGISTER)
    if result is not None:
        logging.warning("Registration error: %s", result)
```

**After:**
```python
if ctrl.registration_supported:          # property
    try:
        ctrl.register(nvme.NVMF_DIM_TAS_REGISTER)
    except nvme.NvmeError as e:
        logging.warning("Registration error: %s", e)
```

### 8.3 Discovery

**Before:**
```python
supported = ctrl.supported_log_pages()    # returns None on failure
try:
    dlp_supp_opts = supported[nvme.NVME_LOG_LID_DISCOVERY] >> 16
except (TypeError, IndexError):
    dlp_supp_opts = 0
```

**After:**
```python
try:
    supported = ctrl.get_supported_log_pages()   # renamed; raises on failure
    dlp_supp_opts = supported[nvme.NVME_LOG_LID_DISCOVERY] >> 16
except nvme.NvmeError:
    dlp_supp_opts = 0
```

### 8.4 Callbacks (new capability)

**Before:** impossible — callbacks hardwired to NULL in the typemap.

**After:**
```python
def decide_retry(err):
    return err in (errno.ETIMEDOUT, errno.ECONNREFUSED)

def on_connected(ctrl):
    logging.info("connected: %s", ctrl.name)

def on_already_connected(host, subsysnqn, transport, traddr, trsvcid):
    logging.info("already connected to %s via %s", subsysnqn, traddr)

cfg = {
    "transport": "tcp",
    "subsysnqn": "...",
    "traddr": "...",
    "trsvcid": "4420",
    "callbacks": {
        "decide_retry": decide_retry,
        "on_connected": on_connected,
        "on_already_connected": on_already_connected,
    },
}
ctrl = nvme.Ctrl(root, cfg)
ctrl.connect(host)   # callbacks fire from C as events occur
```

---

## 9. Deletions — running totals

| File / block | Lines gone |
|---|---|
| `libnvme/nvme-swig-accessors.i` | 231 |
| `tools/generator/generate-swig-accessors.py` | 149 |
| `tools/check-nvme-i-consistency.py` + meson test | 553 |
| Hand-maintained `#define` bridges in `nvme.i` (L57–L92) | ~35 |
| Hand-maintained struct/`%extend` blocks in `nvme.i` | ~120 |
| `set_fctx_from_dict` + typemap, net after ~60-line replacement | ~110 |
| `__setattr__` blocks (consolidated to one generated definition) | ~45 |
| `connect_err` / `discover_err` globals + `%exception` | ~50 |
| **Total net deletions** | **~1,290 lines** |

Offsets (~40 lines added): `nvme-manual-bridges.i` header + residual entries, `libnvme/_exc.py` exception hierarchy, `nvme_py_callbacks.c` trampoline file.

---

## 10. Final shape — summary

| Dimension | Shape |
|---|---|
| **Public classes** | 5: `GlobalCtx`, `Host`, `Subsystem`, `Ctrl`, `Namespace` |
| **Hidden from Python** | `libnvmf_context`, `libnvme_fabrics_config`, `libnvmf_discovery_args`, `libnvmf_uri`, `libnvme_path`, all of `private.h` |
| **Input shape** | dict with nested `"cfg"` sub-dict; callbacks as `"callbacks"` sub-dict |
| **Output shape** | properties for state, methods for I/O, exceptions for failures |
| **Generator** | dual-pass, emits `accessors.{h,c,ld,i}` per invocation; fragments independently usable |
| **Annotations** | C-accessor dimension (existing): `!generate-accessors[:read=M,write=M]` (struct), `!access:read=M,write=M` (member, partial allowed), `!default:VALUE` (member), where `M ∈ {generated, custom, none}`. Generated setters are type-aware: scalar → direct assign; `char *` → free + strdup. Lifecycle dimension (struct-level): `!generate-lifecycle=generated|custom` (absence ⇒ lifecycle = `none`; no explicit `=none` form); member-level `!lifecycle:none` excludes from destructor. Python-exposure dimension: `!generate-python` (struct), `!python:none` (member), `!python:alias=NAME` (member). Access is member-level; lifecycle is struct-level; dimensions are independent. |
| **SWIG access routing** | per-axis: `generated` → direct field access (`p->m`), **no `%rename`/bridge emitted**; `custom` → `%rename` of hand-written accessor; `none` → no getter / `%immutable`. Public C API still uses generated accessors for ABI — Python binding bypasses them because it wraps the private struct directly. |
| **Manual bridges** | one file with per-entry justification, target ≤3 entries |
| **Callbacks** | ctrl construction: `cfg["callbacks"]` dict (validated by `%typemap(in)`); discover: per-call kwarg. Trampolines + GIL + unraisable-hook; internal fctx never surfaces |
| **`__setattr__` guard** | one generated definition, installed via class-level decoration (`T.__setattr__ = _nvme_guarded_setattr`) at module import — no post-processing of `nvme.py` |
| **Breaking changes** | v3.0 only, no aliases, no deprecation shims |

Net result: **single source of truth = annotated `private.h` + `private-fabrics.h`.** Every other artifact (C accessors, SWIG fragment, field tables for the dict typemap) is regenerated from it. Nested structs work internally. Callbacks work without exposing new public types. Exception handling is one function. Bridge files and consistency checkers cease to exist.
