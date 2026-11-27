<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
# NVMe-oF Persistent Discovery Controllers (PDC)

A Persistent Discovery Controller (PDC) is a Discovery Controller connection
that the host keeps open after it has read the Discovery Log Page, instead of
disconnecting once the log page has been read. Keeping it open lets the target
push an Asynchronous Event Notification (AEN) to the host whenever its
Discovery Log Page data changes. The host can then react immediately, instead
of relying on someone re-running `nvme discover` or `nvme connect-all` by
hand.

This page explains the mechanism (EPCSD, the `--persistent` option, and how a
change actually reaches a running host), shows how to configure it in nvme-cli
3.0, and covers where the separate nvme-stas project fits into the same
picture.

## The problem PDC solves

Without PDC, `nvme discover`/`nvme connect-all` do three things and then quit:

1. Connect to the Discovery Controller (DC).
2. Read the Discovery Log Page and connect to the subsystems it lists.
3. Disconnect from the DC. There is nothing left listening for changes.

If the target later adds a subsystem, removes one, or changes a port, the host
has no way to find out. Someone has to re-run discovery, usually on a timer,
and the host lags behind the real topology until then.

PDC fixes this by skipping step 3 for a DC that can support it. The DC
connection stays up, the host keeps a Keep Alive running on it, and the target
can raise a Discovery Log Page Change Notification AEN on that same connection
the moment something changes. See [How to set up NVMe-oF
autoconnect](autoconnect.md) for how an AEN turns into an
actual reconnect on the host.

## One flag decides whether persistence is safe

Not every Discovery Controller can be trusted to hold a connection open and
raise AENs correctly. The NVMe Base Specification defines a flag in each
Discovery Log Page entry's EFLAGS field for this:

- **EPCSD** (Explicit Persistent Connection Support for Discovery): this
  entry's Discovery Controller supports persistent connections and will raise
  an AEN when its log page changes. Without this flag, a host has no
  spec-backed reason to expect the DC to notify it of anything, so keeping the
  connection open is a guess, not a guarantee.

Two other flags share the same field and play no part in the persistence
decision. **NCC** (No CDC Connectivity) applies only when talking to a
Centralized Discovery Controller and says whether any Direct Discovery
Controller behind it is currently reachable. **DUPRETINFO** (Duplicate
Returned Information) marks a set of ports of *this* Discovery subsystem that
return the same log page, so a host that wants redundant access to the same
information can pick one of them. nvme-cli decodes both and acts on neither.

`nvme discover` decodes all three in its `eflags:` line:

```
$ nvme discover -t tcp -a 192.168.1.116 -s 8009
Discovery Log Number of Records 2, Generation counter 6
=====Discovery Log Entry 0======
trtype:  tcp
adrfam:  ipv4
subtype: current discovery subsystem
treq:    not specified
portid:  3
trsvcid: 8009
subnqn:  nqn.1992-08.com.example:sn.xxxx:discovery
traddr:  192.168.1.116
eflags:  explicit discovery connections
sectype: none
=====Discovery Log Entry 1======
trtype:  tcp
adrfam:  ipv4
subtype: nvme subsystem
treq:    not specified
portid:  3
trsvcid: 4420
subnqn:  nqn.1992-08.com.example:sn.xxxx:subsystem.vol1
traddr:  192.168.1.116
eflags:  none
sectype: none
```

Entry 0 has `subtype: current discovery subsystem`. This is the DC describing
*itself*, and it is the entry nvme-cli reads EPCSD from when deciding whether
to keep its own connection open.

nvme-cli never reads EPCSD from an ordinary I/O subsystem entry such as entry
1. The specification leaves nothing to read there: EPCSD shall be 0 on a
subtype 2h entry, and DUPRETINFO shall be 0 on anything but a subtype 3h
entry. NCC is the only flag an I/O subsystem entry can carry.

## `--persistent[=no|auto|force]`

`nvme discover`, `nvme connect-all`, and `nvme config create --discovery` all
take the same `--persistent` option:

| Value | Meaning |
|---|---|
| (option omitted) | **auto** since nvme-cli 3.2. **no** in 3.0 and 3.1. |
| `--persistent` (bare) | **auto** -- persist this DC's connection only if its own EPCSD flag says it supports it. Otherwise disconnect, same as `no`, and log a warning. |
| `--persistent=force` | **force** -- persist regardless of what EPCSD reports, for a target whose self-reported EPCSD cannot be trusted. |
| `--persistent=no` | **no** -- never persist. Use this to opt out of the default. |

The default changed in nvme-cli 3.2. Since then, a DC stays
connected wherever the target reports EPCSD, without any option. Targets
without EPCSD are not affected. `nvme config create --discovery` and converted
`discovery.conf` lines now write `persistent = auto`. Use `--persistent=no` to
get the old behavior.

Because the value is optional, it must be attached directly to the option:
`--persistent=force`. Since nvme-cli 3.2, `--persistent force` as two separate
arguments fails: "force" is an extra argument, which is an error. In 3.0 and
3.1, it silently dropped "force" and fell back to bare `--persistent` (auto).
Always use the `=` form when you mean anything other than auto.

`nvme discover` and `nvme connect-all` also accept the short form, attached:
`-pforce`. `nvme config create` has no short form for this option, so it takes
`--persistent=force` only.

### What `auto` actually checks

nvme-cli does not know a DC's EPCSD flag until after it has already connected
and read the log page, so `auto` mode optimistically requests a Keep Alive
timeout up front, then decides per DC once the log page is back:

- If this DC's own self entry (`subtype: current discovery subsystem`) is in
  the log page it just read, its EPCSD flag decides the outcome.
- If this DC was reached as a referral from another DC and has no self entry
  of its own, nvme-cli falls back to the EPCSD flag the *referring* entry
  carried in the parent's log page.
- If neither is available, EPCSD is treated as unset, and the connection is
  torn down.

A DC that loses the `auto` bet is disconnected right after its log page is
read, with a log message naming it:

```
<subnqn>: not persisting, EPCSD=0
```

That is expected behavior, not an error: it means this particular DC doesn't
support persistent connections, so nvme-cli falls back to the pre-PDC behavior
for it.

### When the Connect fails instead

There is a second outcome, and it does not look like the one above. A
Discovery controller that genuinely does not support explicit persistent
connections shall not support Keep Alive, and the specification says:

> If the Connect command specifies a non-zero Keep Alive Timer value and the
> Discovery controller does not support Asynchronous Events, then the
> Discovery controller shall abort the Connect command with a status code of
> Connect Invalid Parameters.

So `auto`'s optimistic Keep Alive request fails the Connect outright. There is
no log page, and no `not persisting, EPCSD=0` message, because nvme-cli never
got far enough to read one. If `--persistent` turns a working `nvme discover`
into a Connect Invalid Parameters failure, that is this case: drop
`--persistent` for that target.

The `not persisting, EPCSD=0` message therefore only ever appears on a DC that
*accepts* a non-zero Keep Alive timeout and still reports EPCSD=0.

## Trying it from the command line

```bash
# Read the log page, keep the DC connected if (and only if) it says it
# supports persistence. Since 3.2 this is the default, so --persistent
# can be left out:
nvme discover -t tcp -a 192.168.1.116 -s 8009 --persistent

# Never keep the DC connected:
nvme discover -t tcp -a 192.168.1.116 -s 8009 --persistent=no

# Same, but trust this target's persistence unconditionally:
nvme discover -t tcp -a 192.168.1.116 -s 8009 --persistent=force

# connect-all takes the same option, and additionally connects every
# subsystem the log page lists:
nvme connect-all -t tcp -a 192.168.1.116 -s 8009 --persistent
```

A one-off `--persistent` on the command line only affects that single
invocation. If you want it applied automatically, at boot or every time
autoconnect re-runs discovery, record it in the configuration instead.

## Making it permanent: nvme-fabrics.conf

`persistent` is a Discovery Controller setting. It belongs in a `[Discovery
Controller]` section (one specific DC) or in `[Discovery Controller Defaults]`
(applies to every DC in that file, unless a specific DC overrides it). It may
also appear on a `controller =` line inside a `[Discovery Controller]`
section, to set it for one path of that DC. It is rejected outside a Discovery
Controller section: in an `[I/O Controller Defaults]`/`[Subsystem]` section,
or on a `controller =` line there. Persistence is a property of the Discovery
Controller connection itself, not of the subsystems it points at. See [How to
configure NVMe-oF connections](fabrics-config.md) for the
format in general.

```ini
# /etc/nvme/nvme-fabrics.conf

[Discovery Controller Defaults]
persistent = auto           # default for every DC below, unless overridden

[Discovery Controller]
controller = transport=tcp;traddr=192.168.1.116;trsvcid=8009

[Discovery Controller]
controller = transport=tcp;traddr=192.168.1.117;trsvcid=8009
persistent = force          # this one's EPCSD reporting isn't trusted

[Discovery Controller]
# Or on the controller line itself, which is equivalent here
controller = transport=tcp;traddr=192.168.1.118;trsvcid=8009;persistent=force
```

The last two entries are equivalent. A section-level `persistent` covers every
`controller =` line in that section, and a section normally has one. They
differ only if you give one Discovery Controller several addresses, which is
unusual: unlike I/O controller paths, extra Discovery Controller connections
are not combined into one entity, they are just redundant ways to read the
same log page.

Put `persistent` on a `controller =` line in an `[I/O Controller Defaults]` or
`[Subsystem]` section and the file is rejected:

```
/etc/nvme/nvme-fabrics.conf:9: persistent is only valid for a discovery controller
```

Build entries like this with `nvme config create` instead of hand-editing, the
same as any other connection:

```bash
nvme config create --discovery --persistent=auto \
  --transport tcp --traddr 192.168.1.116 --trsvcid 8009
```

`nvme connect-all` (with no arguments, reading the same file) and the
autoconnect services described below then apply `persistent` from the config
automatically. No `--persistent` on the command line is needed once it's in
the file.

## What "persistent" changes on the wire

A persistent DC gets a non-zero Keep Alive timeout (KATO), 30 seconds by
default, the same as any Discovery Controller connection that intends to stay
up. A non-persistent DC gets KATO=0, so the connection does not outlive the
`nvme discover`/`connect-all` process that made it.

`keep-alive-tmo` interacts with this in one direction only. On a persistent
DC, an explicit `keep-alive-tmo` (on the command line or in the config) is
honored and the 30-second default does not override it. On a non-persistent
DC, KATO is forced to 0 even if you set `keep-alive-tmo` explicitly, because a
non-zero Keep Alive on a connection that is about to be torn down has nothing
to keep alive. See the note on `keep-alive-tmo` in [How to configure NVMe-oF
connections](fabrics-config.md).

## How the host reacts when the discovery log page changes

Keeping the DC connected is only half of PDC. Something on the host still has
to notice the AEN and act on it. nvme-cli 3.0 ships two independent mechanisms
of its own, and a separate project, nvme-stas, provides a third. See [How to
set up NVMe-oF autoconnect](autoconnect.md) for the full
picture of the first two.

**udev/systemd autoconnect (legacy).** Since nvme-cli 3.2, it is built only
when nvme-discoverd is not built, or with `-Dnvmf-autoconnect=enabled`. The
kernel surfaces the AEN as a uevent on the persistent DC's device.
`70-nvmf-autoconnect.rules` watches for it and starts `nvmf-connect@.service`,
which runs `nvme connect-all --owner=autoconnect --quiet` with the transport,
address, service id, host address and host interface taken from the uevent, so
it re-reads that one DC's Discovery Log Page and connects whatever is new.
Anything already connected is left alone; this never disconnects an existing
controller in response to a discovery change.

**nvme-discoverd (technology preview).** Since nvme-cli 3.2, it is built by
default. You enable it with `systemctl enable nvme-discoverd.service`.
`nvme-discoverd` holds the persistent DC connections itself and reacts to the
same AEN inside its own event loop, without needing a udev round-trip. It also
does one thing the udev path does not: a DC whose EPCSD came back 0 is
disconnected right after its log page is read. Per spec, such a DC shall not
support Keep Alive or Asynchronous Events, so there is nothing to wait on.
Instead, nvme-discoverd reconnects and re-checks it on a timer,
`epcsd-poll-interval-minutes` in the `[Discovery]` section of
`nvme-discoverd.conf`, default 15 minutes. In 3.0 and 3.1, this key is in
`[Global]`. A DC with EPCSD=1 is never polled this way; it just stays
connected and waits for its AEN. Since nvme-cli 3.1, nvme-discoverd honors
`persistent = force`. A DC with this setting stays connected even if it
reports EPCSD=0. Since 3.2, nvme-discoverd connects a DC with a Keep Alive
timeout of 30 seconds, or the configured `keep-alive-tmo`. A DC with
`persistent = no` connects without a Keep Alive timeout.

**nvme-stas** is the third option. It is a separate project, not part of
nvme-cli, and is covered on its own below.

Only run one of these three against the same connections at a time. They are
not meant to be combined on the same DC.

## Where nvme-stas fits

[nvme-stas](https://github.com/linux-nvme/nvme-stas) is a separate project
from nvme-cli. It exists because nvme-cli/libnvme are stateless: they issue a
command and exit, which is enough for PDC as described above, but not enough
for two more NVMe-oF Technical Proposals that need a host to keep running
state indefinitely:

- **TP8009** (zeroconf discovery): find Discovery Controllers on the network
  via mDNS as they appear and disappear, with no configuration at all.
- **TP8010** (Centralized Discovery Controller): register with a CDC, track
  its AENs, and react to Fabric Zoning changes by connecting and disconnecting
  subsystems automatically.

nvme-stas provides these through two daemons: **stafd** discovers Discovery
Controllers and holds their connections open, and **stacd** connects the I/O
subsystems stafd finds. Both read the same libnvme INI format described above,
but nvme-stas keeps its own file, `/etc/nvme/nvme-stas.conf`, instead of the
shared `nvme-fabrics.conf`. That is deliberate: a host can run nvme-stas
alongside nvme-cli's autoconnect or nvme-discoverd, each managing its own
connections, because all of them honor the NVMe-oF ownership registry and
never disconnect a controller they didn't create.

`stafd` is the piece that implements PDC. Its decision algorithm is the same
one described above for `auto` mode: check the DC's own self entry for EPCSD,
fall back to the referring entry's EPCSD if this DC was reached through a
referral, otherwise assume it is unsupported. A DC that turns out not to
support persistence is "parked" (disconnected, but still tracked). `stafd`
reconnects it on a timer to check again: `epcsd-poll-interval-minutes` under
`[Discovery controller connection management]` in `stafd.conf`, default 15
minutes. That is the same key name and the same default nvme-discoverd uses.

`nvme-stas.conf` takes the same `persistent = no|auto|force` key, in the same
places, as `nvme-fabrics.conf`:

```ini
# /etc/nvme/nvme-stas.conf

[Discovery Controller Defaults]
keep-alive-tmo = 30
persistent     = auto

[Discovery Controller]
nqn        = nqn.2014-08.org.example:cdc.main
persistent = force
controller = transport=tcp;traddr=192.168.1.11;trsvcid=8009
```

stafd treats a DC without the key as `auto`. nvme-cli does the same since
3.2. In nvme-cli 3.0 and 3.1, the default was `no`. Keep this in mind if you
move a configuration between an older nvme-cli and nvme-stas.

nvme-discoverd before 3.1 parked any DC with EPCSD=0 and ignored
`persistent = force`. Since 3.1, nvme-discoverd and stafd both honor
`persistent = force`.

The EPCSD-aware logic landed in both libnvme/nvme-discoverd and nvme-stas in
the same week around the nvme-cli 3.0 release (late August/early September
2026), from the same author. The algorithm agrees across all three codebases
even though they don't share code.

## Verifying it's working

```bash
# Connect with persistence (the default since 3.2):
nvme discover -t tcp -a 192.168.1.116 -s 8009 --persistent -v

# Confirm the DC is still connected (it shows up as its own subsystem,
# NQN nqn.2014-08.org.nvmexpress.discovery):
nvme list-subsys

# Or check sysfs directly:
grep -l nvmexpress.discovery /sys/class/nvme/nvme*/subsysnqn
cat /sys/class/nvme/nvme*/state          # expect "live"
```

If the DC dropped instead of staying connected, check the log for the `not
persisting, EPCSD=0` message mentioned above. It means this specific target
does not advertise EPCSD support, and `auto` correctly declined to persist it.
Use `--persistent=force` only if you are sure the target actually supports
staying connected despite not reporting EPCSD. Forcing it on an incapable
target just means a connection nothing will ever wake up.

If the `nvme discover` itself failed with Connect Invalid Parameters, see
[When the Connect fails instead](#when-the-connect-fails-instead) above.

## Migrating from nvme-cli 2.x

nvme-cli 2.x also had a `--persistent`/`-p` flag on `discover`/`connect-all`,
but it had no EPCSD awareness: it unconditionally kept the DC connected, with
no `auto` mode and no way to distinguish a target that could support it from
one that couldn't. EPCSD/DUPRETINFO decoding in `nvme discover`'s output has
existed since 2023, but nvme-cli did not act on EPCSD for connection
persistence until 3.0.

Because of that, `nvme config convert` (which migrates a legacy `config.json`
into the new INI format) maps a legacy connection's `"persistent": true` to
`persistent = force`, never to `auto`. This preserves the exact old behavior
of always persisting. It avoids silently switching an existing always-on setup
to best-effort. See [Migrating from nvme-cli 2.x to
3.0](migrating-2-to-3.md).

## Current limits

In nvme-cli 3.0 and 3.1, PDC is opt-in. You decide which DCs persist, either
with `--persistent` on the command line or `persistent =` in
`nvme-fabrics.conf`.

Since nvme-cli 3.2, `auto` is the default. A DC persists without
any configuration, if the target reports EPCSD. A target without EPCSD still
gets no PDC, unless you set `persistent = force` for it. This was requested in
<https://github.com/linux-nvme/nvme-cli/issues/3112>.

nvme-cli 3.0 and 3.1 also did not send the Keep Alive timeout to a DC on `nvme
discover` and `nvme connect-all`. Because of this, the DC was never asked for
a persistent connection. This is fixed in 3.2.

## See also

- [How to set up NVMe-oF autoconnect](autoconnect.md)
- [How to configure NVMe-oF connections](fabrics-config.md)
- [How to connect to a target](connect.md)
- [Migrating from nvme-cli 2.x to 3.0](migrating-2-to-3.md)
- [nvme-stas](https://github.com/linux-nvme/nvme-stas) and its [CLI comparison
  document](https://github.com/linux-nvme/nvme-stas/blob/main/NVME-STAS-CLI_COMPARISON.md)
