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

> Open question, not yet decided: whether to also generate a
> mechanically-produced contributor list per release (roughly `git
> shortlog -sn <previous-tag>..HEAD`), the way systemd's own
> announcement emails do. Cheap to produce, credits everyone who
> touched the release.

## Older changes

Not backfilled. See the git log and GitHub release/tag history for
anything before this file existed.
