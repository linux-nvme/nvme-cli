# libnvme API naming conventions

## Spec-mirroring definitions — `nvme_` / `nvmf_`

Types, structs, and enums that directly mirror the NVMe specification use the
short prefixes `nvme_` (base spec) and `nvmf_` (NVMe-oF spec). These live in
`libnvme/src/nvme/types.h` and `libnvme/src/nvme/cmds.h` and are
**data-layout definitions**, not library API.

## Public library API — `libnvme_` / `libnvmf_`

Every public symbol exported from `libnvme.so` must use one of these prefixes:

| Prefix | Scope | Examples |
|--------|-------|---------|
| `libnvme_` | Common NVMe (PCIe **and** NVMe-oF) | `libnvme_open()`, `libnvme_first_host()`, `libnvme_ctrl_identify()` |
| `libnvmf_` | NVMe-oF only (fabrics transport, discovery, connect) | `libnvmf_connect_ctrl()`, `libnvmf_get_discovery_log()` |

**Rule**: choose `libnvmf_` only when the function is meaningless outside an
NVMe-oF context. When in doubt, prefer `libnvme_`.

The split is enforced by two linker version scripts:
- `libnvme/src/libnvme.ld` — exports `libnvme_*` symbols
- `libnvme/src/libnvmf.ld` — exports `libnvmf_*` symbols

New public symbols must be added to the appropriate `.ld` file under a new
version section (see `accessor-workflow.md` for the version-section rules).

## Internal / private functions

Functions that are not exported (used only within libnvme) need no special
prefix constraint, but by convention use `libnvme_` or `libnvmf_` with a
leading underscore or by keeping them `static`.
