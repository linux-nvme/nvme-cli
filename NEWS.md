<!-- SPDX-License-Identifier: GPL-2.0-only -->
# NEWS

## Changes in 3.0 (unreleased)

### Feature removals and incompatible changes

* A new INI-format connection configuration parser and writer have
  been added (`nvme-fabrics.conf` + `nvme-fabrics.conf.d/` drop-ins,
  replacing `config.json`/`discovery.conf`). See 
  `libnvme/design/CONFIG.md` for the format. Existing configuration
  can be explicietly converted by 'nvme config convert' or implicitly
  by the first call of any fabric command.

* Key management has moved into a new `nvme keys` plugin.
  `gen-dhchap-key`, `check-dhchap-key`, `gen-tls-key`,
  `check-tls-key`, and `tls-key` are now `nvme keys gen-kxchap-secret`,
  `check-kxchap-secret`, `gen-tls`, `check-tls`, `insert-tls`, `import`,
  `export`, and `revoke`. The old commands still work as deprecated
  aliases, except `check-tls-key --insert`, which has no equivalent
  there. Use `nvme keys insert-tls` instead. The `DH-HMAC-CHAP`
  naming is also renamed to `KX-HMAC-CHAP` throughout, matching
  TP4201. See `nvme-keys-gen-kxchap-secret(1)` and
  `nvme-keys-check-kxchap-secret(1)`.

* NVMe Base Specification 2.4 (ECN122) renames the Reservation
  Report data structures from "Registered Controller" to
  "Registrant" throughout. `struct nvme_registered_ctrl` and
  `struct nvme_registered_ctrl_ext` are now `struct nvme_registrant`
  and `struct nvme_registrant_ext`; the `regctl`/`regctl_ds`/
  `regctl_eds` fields of `struct nvme_resv_status` are now
  `regstrnt`/`registrant_ds`/`registrant_eds`. `nvme resv-report`
  output changes to match: the `regctl`/`regctls`/`regctlext` labels
  and JSON keys are now `regstrnt`/`registrants`/`registrantext`.
  Update any code or scripts that reference the old names.

* NVMe Base Specification 2.4 (TP4150) renames the "Namespace
  Attribute Changed" asynchronous event to "Attached Namespace
  Attribute Changed", the "Changed Namespace List" log page to
  "Changed Attached Namespace List", and the "Namespace Attribute
  Notices" notice to "Attached Namespace Attribute Notices" (to
  distinguish them from the new Allocated Namespace variants added
  alongside them). `NVME_AER_NOTICE_NS_CHANGED` is now
  `NVME_AER_NOTICE_ATTACHED_NS_CHANGED`, `NVME_LOG_LID_CHANGED_NS` is
  now `NVME_LOG_LID_CHANGED_ATTACHED_NS`, and `NVME_CTRL_OAES_NA*` is
  now `NVME_CTRL_OAES_NSAN*` (matching the spec's new OAES mnemonic).
  `nvme discover --log-id=changed-ns` still works as a deprecated
  alias for the new `changed-attached-ns`.

* NVMe Base Specification 2.4 (TP4193) renames the "Create Exported
  NVM Subsystem" and "Manage Exported NVM Subsystem" admin commands
  to "Manage Exported NVM Subsystem Receive" and "...Send"
  respectively. `nvme_admin_create_export_nvms` is now
  `nvme_admin_manage_export_nvms_receive`, and
  `nvme_admin_manage_export_nvms` is now
  `nvme_admin_manage_export_nvms_send`. The opcode values (0x2a,
  0x2d) are unchanged.

* NVMe Management Interface Specification 2.2 (TP6039) adds a
  Controller Health Status Changed Flags field to the Controller
  Health Data Structure, and renames the NVM Subsystem Health Data
  Structure's Composite Controller Status field to Composite
  Controller Status Flags, to distinguish per-bit change flags from
  the status/state bits they report. In libnvme,
  `struct nvme_mi_ctrl_health_status` gains a `chscf` field (and
  `enum nvme_mi_chscf`) carved out of what was previously trailing
  reserved space, so its size is unchanged; and
  `struct nvme_mi_nvm_ss_health_status`'s `ccs` field/`enum
  nvme_mi_ccs` are renamed to `ccsf`/`enum nvme_mi_ccsf` with bit
  names getting an `F` suffix (e.g. `NVME_MI_CCS_RDY` is now
  `NVME_MI_CCSF_RDYF`) and a new `TCIDAF` bit.

* `nvme gen-dhchap-key` emits the secret it was given rather than the
  key transformed from it, so its output differs whenever `--hmac` is
  non-zero. `--nqn`/`-n` fed only that transform and is now accepted
  with a warning and ignored. See `nvme-gen-dhchap-key(1)`.

* `nvme gen-dhchap-key` rejects a `--secret` with an odd number of
  hexadecimal characters. nvme-cli 2.x padded the trailing one with a
  zero and emitted a secret that was never given: 63 characters ending
  `...bababa` produced `...ababab0a`.

* `nvme check-tls-key` used to print the TLS PSK identity as the only
  line on stdout; it now prints `Key is valid (HMAC <id>, length
  <len>)` first, the identity second, and whether that identity is
  already in the keyring third, so a script reading the identity with
  `head -1` gets the wrong line. Its `--insert`/`--keyfile` are gone;
  use `nvme keys insert-tls`. See `nvme-check-tls-key(1)`.

* `nvme check-dhchap-key` reports on the secret rather than on the key:
  `Key is valid`, `Key is loaded` and `Key is not loaded` are now
  `Secret is ...`, and the validation errors say secret where they said
  key. Exit codes are unchanged, but a script matching the old wording
  needs updating. See `nvme-check-dhchap-key(1)`.

* All `nvme *-log` commands (`smart-log`, `ana-log`, `error-log`,
  `fw-log`, `telemetry-log`, `self-test-log`, `sanitize-log`, and the
  rest of the get-log-page family, `get-log` excepted) have moved
  into a new `nvme log` plugin, dropping the redundant `-log` suffix,
  e.g. `nvme smart-log` is now `nvme log smart`. The old top-level
  commands still work as deprecated aliases.

* All `nvme id-*`/`nvm-id-*`/`list-*` Identify commands (`id-ctrl`,
  `id-ns`, `id-ns-granularity`, `id-ns-lba-format`, `list-ns`,
  `list-ctrl`, `nvm-id-ctrl`, `nvm-id-ns`, `nvm-id-ns-lba-format`,
  `primary-ctrl-caps`, `list-secondary`, `cmdset-ind-id-ns`,
  `ns-descs`, `id-nvmset`, `id-uuid`, `id-iocs`, `id-domain`, and
  `list-endgrp`) have moved into a new `nvme id` plugin, e.g.
  `nvme id-ctrl` is now `nvme id ctrl`. The old top-level commands
  still work as deprecated aliases.

* Namespace management commands (`create-ns`, `delete-ns`,
  `attach-ns`, `detach-ns`, `get-ns-id`) have moved into a new
  `nvme ns` plugin, e.g. `nvme create-ns` is now `nvme ns create`.
  The old top-level commands still work as deprecated aliases.

* `nvme ns create`, `nvme ns delete`, `nvme ns attach`, and
  `nvme ns detach` (and their deprecated `create-ns`/`delete-ns`/
  `attach-ns`/`detach-ns` aliases) no longer print a confirmation
  message on success by default; `nvme ns create` also no longer
  prints the assigned `nsid`. Both are now gated behind
  `-v`/`--verbose`. The exit code alone indicates success/failure;
  the assigned `nsid` can still be found with `nvme ns list` or
  `nvme id ctrl`. See `nvme-ns-create(1)`.

* Reservation commands (`resv-acquire`, `resv-register`,
  `resv-release`, `resv-report`) have moved into a new `nvme resv`
  plugin, e.g. `nvme resv-acquire` is now `nvme resv acquire`. The
  old top-level commands still work as deprecated aliases.

* NVMe-MI commands (`nvme-mi-recv`, `nvme-mi-send`) have moved into
  a new `nvme nvme-mi` plugin, e.g. `nvme nvme-mi-recv` is now
  `nvme nvme-mi recv`. The old top-level commands still work as
  deprecated aliases.

* I/O Management commands (`io-mgmt-recv`, `io-mgmt-send`) have
  moved into a new `nvme io-mgmt` plugin, e.g. `nvme io-mgmt-recv`
  is now `nvme io-mgmt recv`. The old top-level commands still work
  as deprecated aliases.

* Directive commands (`dir-receive`, `dir-send`) have moved into a
  new `nvme dir` plugin, e.g. `nvme dir-receive` is now
  `nvme dir receive`. The old top-level commands still work as
  deprecated aliases.

* Security Send/Receive commands (`security-send`, `security-recv`)
  have moved into a new `nvme security` plugin, e.g.
  `nvme security-send` is now `nvme security send`. The old
  top-level commands still work as deprecated aliases.

* Firmware commands (`fw-commit`, `fw-download`) have moved into a
  new `nvme fw` plugin, e.g. `nvme fw-download` is now
  `nvme fw download`. The old top-level commands still work as
  deprecated aliases.

* The RPMB command has moved into a new `nvme rpmb` plugin and, since
  RPMB is not part of the NVMe base specification, has been split
  into one subcommand per action instead of a `--cmd=<action>` flag:
  `nvme rpmb --cmd=info` is now `nvme rpmb info`, and likewise
  `program-key`, `read-counter`, `read-data`, `write-data`,
  `read-config`, and `write-config`. Unlike the other command moves
  above, the old `nvme rpmb --cmd=...` form no longer works at all;
  there is no deprecated alias. See `nvme-rpmb-info(1)` and friends.

* Deprecated commands (currently the old `nvme keys`, `nvme log`,
  `nvme id`, `nvme ns`, `nvme resv`, `nvme nvme-mi`, `nvme io-mgmt`,
  `nvme dir`, `nvme security`, and `nvme fw` aliases above) are
  enabled by default; they can be turned off at build time with
  `-Ddeprecated-cmds=disabled`.
  `nvme help` now lists them in a separate "deprecated" section
  instead of alongside current commands, and running one prints a
  warning that it will be removed in the next major version.

* `nvme disconnect-all` with no options no longer disconnects every
  fabric controller. It now only disconnects controllers with no
  recorded owner in the new ownership registry. A
  controller owned by another orchestrator is silently skipped. To
  restore the old disconnect-everything behavior.
  
* libnvme itself no longer resolves hostnames. `libnvmf_add_ctrl()`
  and `libnvmf_connect_ctrl()` now fail immediately on a hostname
  traddr/host_traddr instead of resolving it internally. The
  caller is responsible for resolving first.
  
* `--dump-config` has been removed from `nvme discover`,
  `connect-all`, and `connect`.

* In libnvme, the per-command `nvme_<cmd>()` wrapper functions and
  their `struct nvme_<cmd>_args` argument bundles have been replaced
  by an `nvme_init_<cmd>()` helper that fills a caller-owned `struct
  libnvme_passthru_cmd`, submitted separately with
  `libnvme_exec_admin_passthru()` / `libnvme_exec_io_passthru()` (or
  the async equivalents). 

* The public NBFT parsing API has moved from the `libnvme_*`
  namespace to `libnvmf_*`, and every function now takes the global
  context as its first argument (for example,
  `libnvmf_read_nbft(ctx, ...)`). Update both the prefix and the
  call signature.

* The `-Dpdc-enabled` meson build option has been removed. Whether a
  discovery controller connection is kept persistent is now decided
  at runtime, via `--persistent`/`nvme-fabrics.conf`, not at build
  time.

### New: Windows support

* nvme-cli and libnvme now build and run on Windows (MSYS2 UCRT64).
  Direct PCIe access via ioctl works; NVMe-oF fabrics, MI,
  nvme-discoverd, and `nvme top` are not yet available on this
  platform.

### New: nvme top

* `nvme top` is a new interactive, `top`-like dashboard for NVMe
  devices. It lists subsystems and lets you drill into one to see
  live namespace, path, and controller stats, including command
  retry/error counts and multipath failover/reconnect counts. 

### New: ownership registry and exclusion list

* A new ownership registry (`nvme registry`, backed by
  `/run/nvme/registry/`) records which orchestrator owns each
  connected controller. This is what lets `disconnect-all` (above)
  and future orchestrator tooling avoid tearing down a connection
  another component depends on. See `libnvme/design/REGISTRY.md`.

* A new system-wide exclusion list (`nvme exclusion`, backed by
  `/etc/nvme/exclusions.conf` and `exclusions.conf.d/` drop-ins)
  lets an administrator block specific controls from being
  auto-connected. It's aimed primarily at auto-discovered
  controllers, which have no config entry to remove
  in order to suppress an unwanted connection. See
  `libnvme/design/EXCLUSIONS.md`.

### nvme-cli

* A new global config file, `/etc/nvme/nvme-cli.conf`, sets
  machine-wide defaults for global options like `--timeout`,
  `--output-format`, `--no-retries`, and `--no-ioctl-probing`. 
  See `nvme-cli.conf(5)`.

* `nvme disconnect` now accepts the same identifying options as
  `nvme connect` (`--nqn`, `--transport`, `--traddr`,
  `--host-iface`, `--hostnqn`, `--hostid`). A new `-x`/`--exclude` also
  writes a matching entry to the exclusion list before disconnecting.
  See `nvme-disconnect(1)`.

* `nvme discover` and `nvme config-create` gained
  `--epcsd`/`--no-epcsd`, to request or refuse Explicit Persistent
  Connection Support for Discovery. See `nvme-config-create(1)`.

* `nvme utils dump-command-metadata` prints the full command and
  option tree as JSON. It is meant to  drive shell-completion
  generation.

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
  `/etc/nvme/nvme-fabrics.conf`. `--config` overrides the
  `config.json` path, `--output` the destination, and `--force`
  allows overwriting an existing target. On success each converted
  legacy file is renamed to `<name>.converted` so running the
  command again is a safe no-op. See `nvme-config-convert(1)`.

### libnvme

* The library has been renamed from **libnvme** to **libnvme3**,
  and the previously separate **libnvme-mi** has been merged into
  it. The shared library SONAME is `libnvme3.so.1`. Headers install
  under `include/libnvme3/` and man pages under a versioned path,
  enabling parallel installation alongside libnvme v1 packages. The
  Python binding is now named `libnvme3`. Packages, build systems,
  and Python scripts that reference the library, its headers, or the
  Python module by name must update.

* `nvme-fabrics.conf` entries can now record `persistent` and
  `epcsd` settings per discovery controller, matching the CLI flags
  above.

* New diagnostic accessors report per-path, per-namespace, and
  per-controller command retry/error counts, multipath failover
  count, and controller reset/reconnect counts. These are always
  read live rather than cached, and back `nvme top`.

* The Python bindings' object-oriented surface has been polished:
  `connected()` and `is_registration_supported()` are now read-only
  properties (`connected`, `registration_supported`),
  `registration_ctrl()` is renamed `registration_control()`, and
  `set_symname()` has been removed. Set `host.hostsymname`
  directly instead.

* The NBFT parser has been updated for NVMe Boot Specification
  rev. 1.3, including Security Profile Descriptors, and hardened
  against malformed or malicious NBFT ACPI tables.

* ioctl version probing is now deferred until the first command on a
  transport handle, instead of happening eagerly on open. The probe
  prefers the 64-bit ioctl and falls back to the 32-bit one only if
  it isn't supported; the result is cached per handle. The new
  `--no-ioctl-probing` global option skips probing and forces the
  32-bit ioctl.

* Controller and namespace sysfs attributes are now read lazily, on
  first access, instead of all at once when the topology tree is
  scanned. This cuts overhead when scanning large fabric setups.

* Connect and discover now share a common `struct libnvmf_context`
  internally, replacing the old discovery-only context. Relevant to
  developers extending the fabrics API, not to CLI end users.

* A new internal `shared/` static library holds code with no
  natural home in nvme-cli, libnvme, nvme-discoverd, or the Python
  bindings (INI parsing, base64, CRC32, filesystem/network helpers).

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

* `<nvme/nvme-cmds.h>` and `<nvme/nvme-types.h>` have each been
  split into per-spec-section sub-headers (`nvme-cmds-base.h`,
  `nvme-cmds-fabrics.h`, `nvme-cmds-mi.h`, similarly for
  nvme-types). The top-level headers still exist and include all
  sub-headers, so code that includes them is unaffected. Code that
  already included a sub-header by its old combined-file path must
  update the include path.

* `nvme_root_t` has been replaced by `struct libnvme_global_ctx *`
  throughout the public API. Code that stored or passed `nvme_root_t`
  must update to the new type.

* A new transport handle abstraction (`struct nvme_transport_handle`,
  `libnvme_transport_handle_*`) decouples command issuing from the
  underlying transport. A handle may wrap either a direct ioctl file
  descriptor or an MI endpoint.

* An explicit async passthru API has been added.
  `libnvme_submit_admin_passthru()` /
  `libnvme_submit_io_passthru()` submit a command without waiting;
  `libnvme_wait_passthru()` / `libnvme_reap_passthru()` collect the
  result later. The synchronous path is
  `libnvme_exec_admin_passthru()` / `libnvme_exec_io_passthru()`.

* `libnvmf_host_get_ids()` has been promoted from an internal helper
  to a public API. It resolves the hostnqn and hostid from all
  available sources and is the recommended way for callers to obtain
  host identity before connect or discover.

* The implicit hostnqn/hostid lookup inside the fabrics connect and
  discover code paths has been removed. Callers must now resolve host
  identity before connecting; use the newly public
  `libnvmf_host_get_ids()` helper or set values explicitly with
  `libnvme_global_ctx_set_hostnqn()` /
  `libnvme_global_ctx_set_hostid()`.

* The `sizeof_args` backward-compatibility macro and the old
  struct-based command-argument shim have been removed. The macro
  returned incorrect values on 32-bit architectures; there is no
  intention to fix it.

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
