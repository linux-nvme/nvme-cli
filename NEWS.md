<!-- SPDX-License-Identifier: GPL-2.0-only -->
# NEWS

> This file tracks user-facing changes for each release: new
> features, behavior changes, and anything that could break an
> existing setup. Loosely modeled on systemd's NEWS file
> (https://github.com/systemd/systemd/blob/main/NEWS): one prose
> paragraph per entry, "Feature removals and incompatible changes"
> listed first in each release section since that's what someone
> upgrading most needs to see, then changes grouped by component.
> Add an entry here alongside the change that introduces it, not
> after the fact at release time -- it's much easier to describe a
> change accurately while it's fresh than to reconstruct it later
> from a commit log.
>
> Lines in this file are wrapped at ~75 columns on purpose, unlike
> our other markdown docs: this file is meant to still read cleanly
> in a plain editor or if a section is copy-pasted into an email,
> not only when viewed through a renderer.

## Changes in 3.0 (unreleased)

### Feature removals and incompatible changes

* `nvme disconnect-all` with no options no longer disconnects every
  fabric controller. It now only disconnects controllers with no
  recorded owner in the new ownership registry (see below); a
  controller owned by another orchestrator is silently skipped. To
  restore the old disconnect-everything behavior, use `--force`
  (prompts for confirmation when run interactively), or use
  `--owner NAME` to disconnect only the controllers owned by a
  specific orchestrator.

* Hostname entries in the legacy `config.json` connection file are
  now rejected with a clear error instead of sometimes silently
  resolving. Previously this worked via `nvme connect-all`/`nvme
  discover` but already failed via `nvme connect -J`; both paths now
  fail the same way. Direct CLI usage is unaffected: `nvme connect
  -a <hostname>`, `--host-traddr <hostname>`, and discovery.conf
  entries all still resolve exactly as before. Convert `config.json`
  to the new INI connection format (see below) to keep using
  hostnames in a file.

* libnvme itself no longer resolves hostnames. `libnvmf_add_ctrl()`
  and `libnvmf_connect_ctrl()` now fail immediately on a hostname
  traddr/host_traddr instead of resolving it internally -- the
  caller is responsible for resolving first. A deliberate, permitted
  3.0 API break; nvme-stas (the only external consumer using this
  path) already resolves before calling, so this is a non-issue
  there in practice.

* Transport IDs (TIDs), the identifier now shared internally by the
  registry, the exclusion list, and connection matching, only accept
  a numeric traddr/host_traddr for the tcp and rdma transports; a
  hostname is rejected at construction time rather than silently
  accepted.

* *(pending, not yet merged)* The default installation will stop
  shipping the essentially-empty `/etc/nvme/discovery.conf` stub (a
  comment-only template with no real entries). Nothing should have
  been relying on its mere presence for scripting purposes; it was
  never meant to be more than a placeholder.

### New: ownership registry and exclusion list

* A new ownership registry (`nvme registry`, backed by
  `/run/nvme/registry/`) records which orchestrator -- a daemon like
  nvme-stas or nvme-discoverd, or a manual connect -- owns each
  connected controller. This is what lets `disconnect-all` (above)
  and future orchestrator tooling avoid tearing down a connection
  another component depends on. See `libnvme/design/REGISTRY.md`.

* A new system-wide exclusion list (`nvme exclusion`, backed by
  `/etc/nvme/exclusions.conf` and `exclusions.conf.d/` drop-ins)
  lets an administrator block specific controllers -- by transport,
  address, or NQN -- from being auto-connected. It's aimed
  primarily at auto-discovered controllers, which have no config
  entry to remove in order to suppress an unwanted connection. See
  `libnvme/design/EXCLUSIONS.md`.

### nvme-cli

* `nvme connect` gained `--idempotent` and `--devid-file`.
  `--idempotent` makes connecting to an already-connected controller
  succeed instead of erroring. `--devid-file` writes the resulting
  `nvmeX` device name to the given file on success, so a caller that
  doesn't know the device name at connect time (for example, a
  systemd unit spawned before the device exists) can look it up
  afterward instead of scraping `dmesg` or polling sysfs.

* `nvme config-convert` converts the legacy `config.json` and
  `discovery.conf` files to the new INI-format `nvme-fabrics.conf`.
  By default it reads the system paths and writes to
  `/etc/nvme/nvme-fabrics.conf`; `--config` overrides the
  `config.json` path, `--output` the destination, and `--force`
  allows overwriting an existing target. On success each converted
  legacy file is renamed to `<name>.converted` so running the
  command again is a safe no-op. See `nvme-config-convert(1)`.

### libnvme

* A new INI-format connection configuration parser and writer have
  been added (`nvme-fabrics.conf` + `nvme-fabrics.conf.d/` drop-ins,
  intended to eventually replace `config.json`/`discovery.conf`).
  Not yet used by `nvme connect-all`/`nvme discover` -- that
  integration is still in progress. See `libnvme/design/CONFIG.md`
  for the format.

* Read-only Python bindings for the new config format
  (`config_read()`, `config_validate()`) are available now for early
  adopters (e.g. nvme-stas) that want to start reading the new
  format ahead of the CLI's own switch-over.

* The accessor generator that produces libnvme's getter/setter
  boilerplate (`accessors.c`/`.h`) has been rewritten in Python,
  with the struct annotations it reads now living in-source in
  `private.h` instead of a separate spec file. Relevant to
  developers extending libnvme's public structs, not to CLI end
  users.

* The library has been renamed from **libnvme** to **libnvme3**,
  and the previously separate **libnvme-mi** has been merged into
  it. The shared library SONAME is `libnvme3.so.1`. Headers install
  under `include/libnvme3/` and man pages under a versioned path,
  enabling parallel installation alongside libnvme v1 packages. The
  Python binding is now named `libnvme3`. Packages, build systems,
  and Python scripts that reference the library, its headers, or the
  Python module by name must update.

* `<nvme/nvme-cmds.h>` and `<nvme/nvme-types.h>` have each been
  split into per-spec-section sub-headers (`nvme-cmds-base.h`,
  `nvme-cmds-fabrics.h`, `nvme-cmds-mi.h`, etc.; similarly for
  nvme-types). The top-level headers still exist and include all
  sub-headers, so code that includes them is unaffected. Code that
  already included a sub-header by its old combined-file path must
  update the include path.

* `nvme_root_t` has been replaced by `struct libnvme_global_ctx *`
  throughout the public API. Code that stored or passed `nvme_root_t`
  must update to the new type.

* `libnvme_create_global_ctx()` no longer accepts logging arguments.
  Call the dedicated setter functions (`libnvme_set_logging_level()`,
  `libnvme_set_logging_file()`, etc.) on the returned context after
  construction to configure logging and other options.

* A new transport handle abstraction (`struct nvme_transport_handle`,
  `libnvme_transport_handle_*`) decouples command issuing from the
  underlying transport. A handle may wrap either a direct ioctl file
  descriptor or an MI endpoint; the choice is made at handle
  construction. This is what allows the unified passthru and identify
  APIs to work transparently over both paths.

* An explicit async passthru API has been added.
  `libnvme_submit_admin_passthru()` /
  `libnvme_submit_io_passthru()` submit a command without waiting;
  `libnvme_wait_passthru()` / `libnvme_reap_passthru()` collect the
  result later. The synchronous path is
  `libnvme_exec_admin_passthru()` / `libnvme_exec_io_passthru()`.

* `libnvmf_host_get_ids()` has been promoted from an internal helper
  to a public API. It resolves the hostnqn and hostid from all
  available sources -- DMI/device-tree, `/etc/nvme` files, the JSON
  config, and caller-supplied overrides -- and is the recommended
  way for callers to obtain host identity before connect or discover.

* The implicit hostnqn/hostid lookup inside the fabrics connect and
  discover code paths has been removed. Callers must now resolve host
  identity before connecting; use the newly public
  `libnvmf_host_get_ids()` helper or set values explicitly with
  `libnvme_global_ctx_set_hostnqn()` /
  `libnvme_global_ctx_set_hostid()`.

* `libnvmf_read_hostnqn()` and `libnvmf_read_hostid()` now take a
  `struct libnvme_global_ctx *` as their first argument. Callers
  must pass the global context object.

* `libnvme_global_ctx_set_hostnqn()` and
  `libnvme_global_ctx_set_hostid()` let callers pin the default host
  identity on the global context. Connect and discover operations
  that do not receive explicit hostnqn/hostid arguments fall back to
  these values.

* The `sizeof_args` backward-compatibility macro and the old
  struct-based command-argument shim have been removed. The macro
  returned incorrect values on 32-bit architectures; there is no
  intention to fix it.

* `libnvme_ns_get_uuid()` has been renamed to
  `libnvme_ns_copy_uuid()` to accurately reflect that it copies the
  UUID into a caller-supplied buffer rather than returning a pointer.

* The platform-specific filter helpers (`nvme_filter_*`) are no
  longer exported from libnvme. Only the `libnvme_scan_*` interfaces
  remain public. Plugins that called filter helpers directly must be
  updated to use the scan API.

* `libnvme_ctrl_match_config()` has been removed. It was exported
  but had no callers outside the library.

* `libnvmf_ctrl_get_fabrics_config()` has been removed. The
  individual field accessors generated by the new accessor machinery
  provide equivalent access without exposing the internal nested
  struct.

* `nvme_mi_ctrl_t` has been removed. MI functionality is now
  accessed through `struct nvme_transport_handle`, the same
  abstraction used for direct ioctl access; the transport is chosen
  at handle construction. `nvme_mi_admin_identify()` and
  `nvme_mi_admin_identify_partial()` are gone; use
  `libnvme_ctrl_identify()` with a transport handle opened for MI.

* Several deprecated identifiers have been removed for 3.0: the
  duplicate `NVME_SC_FEAT_IOCS_COMBINATION_REJECTED` define, the
  old notification-mask enum names, MI backward-compatibility
  `#define`s, and `nvme_cmd_get_log_telemetry_host_lsp` (renamed to
  `nvme_log_telemetry_host_lsp`). Update any code using these names.

* The environment-variable configuration knobs for libnvme have been
  removed. `LIBNVME_MI_PROBE_ENABLED`, `LIBNVME_TEST_BASE_DIR`, and
  similar variables no longer have any effect. Replace them with
  explicit setter calls on the global context:
  `libnvme_set_probe_enabled()`, `libnvme_set_test_base_dir()`,
  `libnvme_set_test_sysfs_dir()`, `libnvme_set_force_4k()`, etc.

> Open question, not yet decided: whether to also generate a
> mechanically-produced contributor list per release (roughly `git
> shortlog -sn <previous-tag>..HEAD`), the way systemd's own
> announcement emails do. Cheap to produce, credits everyone who
> touched the release.

## Older changes

Not backfilled. See the git log and GitHub release/tag history for
anything before this file existed.
