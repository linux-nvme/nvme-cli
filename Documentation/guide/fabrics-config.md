<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
# How to configure NVMe-oF connections (nvme-fabrics.conf)

Since nvme-cli 3.0, the NVMe-oF connections of a host are in an INI file,
`nvme-fabrics.conf`. It tells `nvme connect-all`, the autoconnect and
nvme-discoverd which controllers to connect, and with which parameters. It
replaces `config.json` and `discovery.conf` of nvme-cli 2.x. If you come from
2.x, see [Migrating from config.json and
discovery.conf](#migrating-from-configjson-and-discoveryconf) below.

This page is a practical guide. The full format, with the precedence rules,
the validation and the host identity model, is in
[`CONFIG.md`](https://github.com/linux-nvme/nvme-cli/blob/master/libnvme/design/CONFIG.md)
and [`nvme-fabrics.conf(5)`](man:nvme-fabrics.conf). To add a new key to the format, see [How to add a
new INI configuration
parameter](ini-parameter.md).

## File location

The default file is `/etc/nvme/nvme-fabrics.conf`. Drop-in files go into the
directory `/etc/nvme/nvme-fabrics.conf.d/` and end with `.conf`. This is the
same layout that systemd uses. Both are optional. A missing file or directory
is the same as an empty one. It is not an error.

```
/etc/nvme/
    nvme-fabrics.conf       # main file: defaults by type (and connections)
    nvme-fabrics.conf.d/    # optional drop-in files, one host identity each
        prod-fabric.conf
        lab-fabric.conf
```

`--config FILE` selects another main file. `nvme connect`, `nvme connect-all`,
`nvme discover` and the `nvme config` commands accept it. The drop-in
directory is then `FILE.d/`.

## Sections

A connection is an optional `[Host]` section and one or more endpoint
sections:

- **`[Host]`:** the host identity: `hostnqn`, `hostid`, `hostsymname`, and
  credentials that all connections of the file share. Without it, the host
  uses the default identity from `/etc/nvme/hostnqn` and `/etc/nvme/hostid`.
  A file has at most one `[Host]` section.
- **`[Discovery Controller]`:** a Discovery Controller to connect to. Use one
  section for each Discovery Controller.
- **`[Subsystem]`:** an I/O subsystem to connect to, named by `nqn =`. Use one
  section for each subsystem.
- **`[Discovery Controller Defaults]`** and **`[I/O Controller Defaults]`:**
  default parameters for all connections of this type, for example
  `keep-alive-tmo`, `ctrl-loss-tmo`, `reconnect-delay`, digests and queue
  counts. A more specific setting overrides them. There is no defaults section
  for both types. Write a value that applies to both into both sections.

In an endpoint section, each `controller =` line is one path to the endpoint.
It is a list of `nvme connect` options, separated by `;`. Several
`controller =` lines give multipath: the namespaces of the subsystem are
reachable through every path. A `controller =` line can override most keys for
its path. Authentication and TLS settings are the exception. See
[Authentication and TLS credentials](#authentication-and-tls-credentials).

A simple example:

```ini
# /etc/nvme/nvme-fabrics.conf

[Discovery Controller Defaults]
keep-alive-tmo = 30

[I/O Controller Defaults]
keep-alive-tmo = 5

[Host]
hostsymname = lab-host-01
# no hostnqn or hostid: /etc/nvme/hostnqn and /etc/nvme/hostid are used

[Discovery Controller]
controller = transport=tcp;traddr=192.168.1.10;trsvcid=8009

[Subsystem]
nqn        = nqn.2024-01.com.example:data.vol1
controller = transport=tcp;traddr=192.168.1.20;trsvcid=4420

[Subsystem]
nqn           = nqn.2024-01.com.example:data.vol2
ctrl-loss-tmo = 1800                                     # for this subsystem
controller    = transport=tcp;traddr=192.168.1.21;trsvcid=4420
controller    = transport=tcp;traddr=192.168.1.22;trsvcid=4420   # second path
```

## Several host identities

A host usually has one identity. If it must use different identities on
different fabrics, give each identity its own drop-in file in
`nvme-fabrics.conf.d/`. Start the file with a `[Host]` section that sets
`hostnqn`:

```ini
# /etc/nvme/nvme-fabrics.conf.d/prod-fabric.conf

[Host]
hostnqn     = nqn.2014-08.org.nvmexpress:uuid:1111...-A
hostid      = 46ba5037-7ce5-41fa-9452-48477bf00080
hostsymname = Hydra

[Discovery Controller]
nqn        = nqn.2014-08.org.example:cdc.prod
controller = transport=tcp;traddr=10.0.0.5;trsvcid=8009
```

A `hostnqn` may appear in only one file. If the main file and a drop-in file,
or two drop-in files, use the same `hostnqn`, the validation fails.

## Precedence

The most specific value wins:

**`controller =` line > endpoint section (`[Discovery Controller]` or
`[Subsystem]`) > `[Host]` > defaults by type (`... Defaults`) > kernel
default**

`[Host]` is above the defaults by type on purpose. A value in `[Host]` wins
over the defaults sections of its own file. The defaults sections of a drop-in
file apply only to the connections of that file. They never apply to the main
file or to other drop-in files.

An empty value gives a parameter back to the kernel default. systemd drop-in
files use the same rule:

```ini
[I/O Controller Defaults]
ctrl-loss-tmo = 450

[Subsystem]
nqn           = nqn.2024-01.com.example:data.vol3
ctrl-loss-tmo =                          # reset: the kernel decides
controller    = transport=tcp;traddr=192.168.1.23;trsvcid=4420
```

## Authentication and TLS credentials

KX-HMAC-CHAP (in-band authentication) and TLS settings go into `[Host]` or an
endpoint section. They are never allowed on a `controller =` line, because
they belong to the pair of host NQN and subsystem NQN, not to a path:

```ini
[Subsystem]
nqn                = nqn.2024-01.com.example:secure.vol1
tls                = true
tls-key            = NVMeTLSkey-1:01:...
kxchap-secret      = DHHC-1:00:...
kxchap-ctrl-secret = DHHC-1:00:...              # bidirectional authentication
controller         = transport=tcp;traddr=10.0.0.9;trsvcid=4420
```

These secrets are in plain text. Make the file readable only by root with
`chmod 600`. In nvme-cli 3.2, `nvme config create` writes the file with mode
0644 again, so repeat the `chmod` after each `nvme config create`.

Since nvme-cli 3.2, `tls-key` does not have to contain the key itself. With
`tls-key-source = systemd-creds`, `tls-key` is the name of a systemd
credential, and [nvme-keysd](keysd.md) loads the key into the keyring.

### Secrets for discovered subsystems

Since nvme-cli 3.2, a controller found through discovery can get its own
KX-HMAC-CHAP secrets. `nvme connect-all` and nvme-discoverd take
`kxchap-secret` and `kxchap-ctrl-secret` from the endpoint section with the
same NQN: a `[Subsystem]` section for an I/O controller, a `[Discovery
Controller]` section for a Discovery Controller. Such a section does not need
a `controller =` line. The addresses come from discovery:

```ini
[Discovery Controller]
nqn        = nqn.2014-08.org.nvmexpress.discovery
controller = transport=tcp;traddr=10.0.0.5;trsvcid=8009

[Subsystem]
nqn                = nqn.2024-01.com.example:secure.vol1
kxchap-secret      = DHHC-1:00:...
kxchap-ctrl-secret = DHHC-1:00:...
```

The section must be in the same file as the Discovery Controller that reported
the controller. Two sections with the same NQN in one file that set different
secrets are rejected. Without such a section, `nvme connect-all` uses the
`kxchap-secret` of the Discovery Controller. nvme-discoverd uses the defaults
of the file. See [`nvme-fabrics.conf(5)`](man:nvme-fabrics.conf) for the details.

See [How to set up inband authentication](inband-auth.md)
and [How to set up TLS for NVMe over TCP](tls.md)
for how to create these values.

## Create entries with `nvme config create`

`nvme config create` creates one entry from command line options and adds it
to the file. You do not have to edit the file by hand:

```bash
nvme config create --transport=tcp --traddr=192.168.1.20 --trsvcid=4420 \
    --nqn=nqn.2024-01.com.example:data.vol1
```

If the entry exists already, the command does nothing.

- `--discovery` adds a Discovery Controller entry. `--nqn` is then optional.
  The default is the well-known discovery NQN.
- `--host-symname` or `--hostnqn` writes the entry into a new drop-in file for
  this host identity, not into the main file.

`nvme connect-all` without options connects all entries of the file. `nvme
connect` does not read the file. It uses only its command line, or the file
given with `--config`.

## Show and check the file

```bash
nvme config show            # the resolved configuration as nvme connect commands
nvme config show -o json    # the same as JSON
nvme config validate        # parse and check the file, without connecting
```

`nvme config show` does not resolve host names. It shows the addresses as they
are in the file. If an entry has no `hostnqn` or `hostid`, it shows none. It
does not show the system default that applies at connect time.

## Migrating from config.json and discovery.conf

nvme-cli 3.x converts an existing `config.json` or `discovery.conf` when a
command reads the configuration for the first time, for example `nvme
connect-all` without options. `nvme connect` and `nvme discover` with an
address on the command line do not convert. To convert explicitly:

```bash
nvme config convert         # writes /etc/nvme/nvme-fabrics.conf
nvme config status          # shows what is converted
```

The conversion keeps the original file. It creates a symlink
`<name>.converted` that points to it. Because of this, a second run does
nothing, and you can go back to the old file. `nvme config status` shows the
state of both old files and changes nothing:

```
/etc/nvme/discovery.conf: present, already converted (/etc/nvme/discovery.conf.converted exists) -- delete both once rollback is no longer a concern
```

Delete the old file and its symlink when you no longer need to go back. See
also [Migrating from nvme-cli 2.x to 3.0](migrating-2-to-3.md).
