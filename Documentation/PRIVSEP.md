<!-- SPDX-License-Identifier: GPL-2.0-only -->
# Privilege separation and the decoder sandbox

nvme-cli decodes a lot of data it should not trust: whatever a device, or a
fabrics target, returns. Much of it runs as root, because opening
`/dev/nvme*` needs root. Two features reduce what a bug in that code can
do:

- **Privilege separation** (`-Dprivsep`, Linux): when root runs nvme-cli on
  behalf of a user (sudo), nvme-cli starts a small helper which keeps root,
  drops its own privileges and sends the device commands through the helper.
- **The decoder sandbox** (`-Dsandbox`, Linux and FreeBSD): the printers
  which decode device data run in a forked child process which can do
  little more than allocate memory and write to stdout and stderr, whether
  or not nvme-cli runs privileged.

Both are technology previews and disabled by default. This document
describes the design for reviewers; the code is the source of truth.

## Threat model

The attacker controls the data a device (or a fabrics target) returns:
identify data, log pages, features. The goal is that a memory-safety bug in
the code of nvme-cli which decodes that data does not turn into root, and
not into access to other devices, files or processes either. Most of the
bugs fuzzing found were in these decoders.

The command line, `nvme-cli.conf` and `--set-options` are not untrusted in
this sense: the user who runs nvme-cli controls the command line, and
`nvme-cli.conf` belongs to root. Their parsers run in process.

Not a goal:

- Restricting which NVMe commands a user may issue. A user who may run
  `sudo nvme` may do anything to the NVMe devices; the helper passes every
  admin and I/O command through. What the user loses is root outside of
  the NVMe devices.
- setuid. A setuid nvme-cli is not supported: it keeps running as it was
  started and never trusts the environment.
- Fabrics, keys, the registry and the other commands without a device
  keep running as root for now (see "Which commands drop").

## Privilege separation

### Components

| Part | Where | Runs as |
|---|---|---|
| `nvme-privsep-helper` | `libnvme/privsep/helper.c`, installed into `libexecdir` | root |
| client and spawn API | `libnvme/src/privsep/` (`libnvme-privsep.h`) | the caller |
| wire protocol | `libnvme/src/privsep/privsep-proto.h` | both |
| decision, drop and attach | `src/privsep.c` | nvme-cli |

The helper does as little as possible: it decodes request headers, checks
them, issues the ioctl or sysfs write through the public libnvme function
of the same name and returns the raw result. It never parses data a device
returned. nvme-cli, which does, runs unprivileged.

### Lifecycle in nvme-cli

`main()` in `src/nvme.c`:

1. `plugin_lookup()` parses the global options in front of the command and
   finds the command, without running anything.
2. `nvme_privsep_init()` decides, using only that result and the
   environment:
   - no command to run (help, version), a command marked `needs_root`, or
     an MI device (`mctp:<net>,<eid>`, which talks to MCTP sockets itself):
     keep running as is;
   - otherwise, if nvme-cli runs as real and effective root and not in
     secure-execution mode, the target user is `SUDO_UID`/`SUDO_GID`, else
     `NVME_PRIVSEP_UID`/`NVME_PRIVSEP_GID` (decimal only). Without either,
     root keeps its privileges, so scripts and services are unchanged.
3. With a target: `libnvme_privsep_spawn()` starts the helper, then
   `setgroups(1, &gid)`, `setresgid()`, `setresuid()`, and a check that
   `setuid(0)` fails. The supplementary groups become the target group
   only, because looking up the user's groups would run NSS as root. If the
   helper cannot be started or the drop fails, nvme-cli exits with an error
   instead of continuing as root.
4. Only now `setlocale()` runs, `nvme-cli.conf` is read (as the target
   user, so the file has to be world-readable; it holds no secrets) and the
   command parses its options.
5. Every global context nvme-cli creates gets the helper attached
   (`nvme_privsep_attach()` → `libnvme_set_privsep()`), so `libnvme_open()`
   returns helper-backed handles transparently.

The drop happens before any configuration or option parsing, so as little
code as possible runs as root.

### Which commands drop

`struct command` has an opt-out flag, `.needs_root`. Commands drop by
default. The commands marked are the ones without a device argument
(fabrics, enumeration, keys, exclusions, configuration, registry, NBFT) and
the device commands which also touch PCI config space, the kernel log or
root-owned paths. The list doubles as the to-do list for dropping
everywhere. Should a deprecated command forward to a `needs_root` one after
the drop, `nvme_privsep_check()` refuses to run it.

### The helper channel

`libnvme_privsep_spawn()` creates an `AF_UNIX` `SOCK_STREAM` socketpair,
forks, puts the helper's end on fd 3 (`LIBNVME_PRIVSEP_FD`), closes all
other descriptors and `exec`s the helper. The helper inherits the caller's
credentials, which is why nvme-cli spawns it before dropping. The client
then sends `HELLO` and checks the protocol version. The helper reopens fds
0-2 on `/dev/null` if they were closed, so a device is never opened as
stdin or stdout.

Helper-backed transport handles have `fd = -1` and no io_uring. Each
libnvme function that has a helper path has a single
`if (hdl->type == PRIVSEP)` (or `ctx->privsep`) branch. MI keeps its own
path.

### Wire protocol

Same host, same build: host byte order, the host's errno values and
`open()` flags, no versioning beyond `HELLO` (version 1 until released).
Each request is a `struct libnvme_privsep_req` (op, handle id, payload
length) plus payload. Each response is a `struct libnvme_privsep_resp`
(status, length, result) plus payload. The helper answers in order. A
broken stream makes the channel unusable; the client does not retry.

| Op | Handle | Payload → response |
|---|---|---|
| `HELLO` | 0 | → result = version |
| `OPEN` | 0 | flags, options, name → handle id, `S_IFCHR`/`S_IFBLK` |
| `CLOSE` | h | – |
| `ADMIN`, `IO` | h | command (+ data and metadata for host-to-controller opcodes) → CQE result (+ data for reads) |
| `RESET_CTRL`, `RESET_SUBSYSTEM`, `RESCAN_NS`, `GET_NSID`, `REREAD_PARTITIONS`, `UPDATE_BLOCK_SIZE` | h | the libnvme function of the same name |
| `READ_REGS`, `WRITE_REG32`, `WRITE_REG64` | h | offset and length (reads ≤ 4 KiB) |
| `SED` | h | one of the `IOC_OPAL_*` requests `sed-linux.c` uses (nine, three of them depending on the kernel headers), with its fixed-size argument; namespaces only; the payload is wiped after use |
| `FABRICS` | 0 | connect string → kernel reply; result = failed step |
| `DELETE_CTRL` | 0 | `nvmeX` → writes `delete_controller` |

Checks in the helper: `HELLO` first; payloads ≤ 8 MiB + 4 KiB; device names
`nvmeX`, `nvmeXnY`, `ngXnY` (optionally with `/dev/`); open flags limited to
the access mode and `O_EXCL`; unknown `OPEN` options rejected; data lengths
must match the payload; buffers are page-aligned like nvme-cli's; at most
64 open handles. `LIBNVME_PRIVSEP_OPEN_NO_IOCTL_PROBING`
carries `--no-ioctl-probing`: the helper opens such handles in a context
without 64-bit ioctl probing.

## The decoder sandbox

### Why, in addition to privilege separation

- Plain root without `SUDO_UID` keeps root, and so do the `needs_root`
  commands. Their decoders run as root.
- With privilege separation, the unprivileged nvme-cli still holds the
  socket to the helper, which issues any NVMe command, including format,
  sanitize and firmware commit. A decoder that is taken over could use it.
- A decoder that crashes takes nvme-cli down with it.

In the sandbox, a decoder can't open files or use the helper socket, and a
crash only takes the child down.

### The primitive

```c
int shr_sandbox_begin(struct shr_sandbox_output *out);
void shr_sandbox_end(const void *buf, size_t len);
```

```
caller                                  child (fork: same memory)
------                                  -----
fflush(stdout, stderr)
pipe(), fork()  ───────────────────────►  close all fds but 0-2 and the pipe (on fd 3)
                                          enter seccomp / Capsicum
read 'S' ◄──────────────────────────────  write 'S'          ("I am sandboxed")
                                          begin() returns SHR_SANDBOX_CHILD
                                          run the decoder: reads the data in
                                          its copy of memory, prints itself
                                          shr_sandbox_end(result, len)
read the length and the result ◄────────  write them, _exit(0)
expect EOF, waitpid()
begin() returns SHR_SANDBOX_DONE
```

The child sees the memory of the caller as it was at the fork, so it reads
the device data without copying it. Whatever else it changes is lost; only
its output on stdout and stderr and the one result it hands to
`shr_sandbox_end()` remain. The caller treats that result as untrusted.

**Sandbox off** (the default; under valgrind; Windows; or called in the
sandbox already): `shr_sandbox_begin()` returns `SHR_SANDBOX_OFF` and the
caller runs the code itself.

Errors: a child that could not enter the sandbox reports it with a special
exit status *before* it sends the marker, and only then does
`shr_sandbox_begin()` return `SHR_SANDBOX_OFF`. Anything else (a missing
marker, a result over 64 MiB, data after the result, a crash, a non-zero
exit) is an error.

### The printers

The hook is the `nvme_print()` macro in `src/nvme-print.c`, which all
`nvme_show_*()` functions use, including the ones of the log plugin:

```c
if (nvme_print_check(ops, ops->name) && nvme_print_begin(ops, ops->name)) {
	ops->name(__VA_ARGS__);
	nvme_print_end(ops);
}
```

`nvme_print_begin()` returns false in the caller once a sandboxed child
has printed. Printers that the sandboxed printer calls itself (e.g. the
hex dump) run inline in the same child, and so do the status and error
messages they print, which do not use the macro.

Some printers stay in process (`nvme_print_sandboxed()`):

- the libnvme tree printers (`list`, `list-subsys`, `show-topology`,
  `relatives`), which read sysfs while they print and decode no device
  data;
- the ZNS zone list printers, which hand JSON objects to their caller;
- `top`, which is interactive, and `config_conn_list`;
- `show_init`/`show_finish`, and the status and error messages, unless
  a sandboxed printer prints them.

If a sandboxed printer fails, nvme-cli says so ("the decoder of the device
data crashed or misbehaved in the sandbox") and exits with an error.

### JSON output

A command prints one JSON document: `parse_args()` calls
`nvme_show_init()`, the printers add members to it (`json_r`), and
`nvme_show_finish()` prints it. In process nothing changes. A sandboxed
child, though, has only a copy of the document, and what it adds is lost.

`struct print_ops` therefore has optional capture hooks, which
`nvme_print_begin()` and `nvme_print_end()` call around a sandboxed
printer. The dispatcher hands the result over as it is; only the output
plugin knows what it contains. Plugins which write to stdout, as the
child can, leave them unset. The JSON plugin implements them:

1. `capture_begin()`, in the child: the printer call gets an object of
   its own as `json_r`; printers it calls write to the same object;
2. `capture_end()`, in the child: its members are serialized, as pairs of
   a length and the key, a length and the value;
3. `capture_add()`, in the caller: they are added to the document as raw
   text, with a serializer that re-indents them to their level. A member
   replaces one of the same key, as when the printer runs in process.

The text is not parsed again. A parse would turn 128-bit numbers, which
nvme-cli prints as bare JSON numbers, into doubles. Only the framing is
checked: the child can write anything to stdout, so a raw member in the
JSON document gives it nothing new.

### The sandbox itself

- **Descriptors:** the child keeps only fds 0-2 and the result pipe, so it
  cannot reach the privsep helper socket or any device. It closes the others
  with `close_range()`, else those listed in `/proc/self/fd` (Linux) or
  with `closefrom()` (FreeBSD); a loop up to the limit would miss those
  above a lowered limit. If it cannot close them, it fails. nvme-cli opens
  `/dev/null` on closed standard descriptors at its start, so none of them
  is the helper socket or a device.
- **Linux:** `PR_SET_NO_NEW_PRIVS` and a seccomp BPF filter. A wrong
  architecture (and x32) kills the process. Allowed: `write`, `writev`,
  memory management (`brk`, `mmap`, `munmap`, `mremap`, `madvise`),
  `fstat`, `getrandom`, `futex`, signals and `tgkill()` to the child itself
  (for `abort()`), `getpid`, `gettid`, `exit`, `exit_group`, and `ioctl()`
  only for `TCGETS`, `TCGETS2` and `TIOCGWINSZ` (terminal queries for
  `isatty()` and line wrapping). Other ioctls fail with `ENOTTY`, and every
  other system call fails with `EPERM`, so that libc degrades gracefully
  (e.g. `gettext()` without its catalog).
- **FreeBSD:** the rights of fds 0-3 are limited to write, `fstat` and the
  terminal ioctls, then `cap_enter()`.
- The sandbox must be entered while the process runs a single thread.
- libc loads some data on first use, which the child could not read. The
  caller loads the time zone (`tzset()`) before the fork, so times print
  the same in the child.
- Cost: under 1 ms per printed object (fork, seccomp, JSON splicing).

### Switches

- `-Dsandbox=enabled` turns it on by default. `NVME_SANDBOX=0` turns it off
  (e.g. for a debugger); `NVME_SANDBOX=1` turns it on in any build.

### Not covered

- Size and offset handling in the command code that fetches the data,
  before it is printed (e.g. a log read in parts).
- Vendor plugins that decode inside the command instead of through
  `nvme_show_*()`. Each needs its decoding split from the fetching.
- The printers that stay in process (see above).

## Testing

- libnvme: `libnvme/tests/privsep/` (helper protocol, handles, ioctl
  probing).
- nvme-cli: `nvme-cli - privsep` (the helper is used and opens the
  devices; `needs_root`, MI, help and version don't drop), and every mock
  CLI test runs a second time through the helper (`<name>-privsep`) and in
  the sandbox (`<name>-sandbox`). `NVME_PRIVSEP_TEST_HELPER` names a helper
  an unprivileged nvme-cli uses as well; it is ignored as root and in
  secure-execution mode.
- Sandbox: `shared - sandbox-util` (results, fallback, nesting, denied
  system calls, descriptors, terminal queries, malformed and oversized
  results, crashes), `print-sandbox-compare`, which runs the decoders of
  the print test on random device data with and without the sandbox and
  requires the same exit status, stdout and stderr, and a check in the
  print test that the sandbox is used.
