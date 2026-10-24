<!-- SPDX-License-Identifier: GPL-2.0-only -->
# Testing and CI

## Pre-built binary

For quick testing, an x86_64 static build from the current HEAD is available
[here](https://github.com/linux-nvme/nvme-cli/releases/download/nightly/nvme-cli-latest-x86_64).

## Container-Based Debugging and CI Build Reproduction

The nvme-cli project provides prebuilt CI containers that allow you to locally
reproduce GitHub Actions builds for debugging and development. These containers
mirror the environments used in the official CI workflows.

CI Containers Repository:
[linux-nvme/ci-containers](https://github.com/linux-nvme/ci-containers)

CI Build Workflow Reference:
[libnvme-build.yml](https://github.com/linux-nvme/nvme-cli/blob/master/.github/workflows/libnvme-build.yml)

### 1. Pull a CI Container

All CI containers are published as OCI/Docker images.

Example: Debian latest CI image:

```bash
docker pull ghcr.io/linux-nvme/debian:latest
```

Or with Podman:

```bash
podman pull ghcr.io/linux-nvme/debian:latest
```

### 2. Start the Container and Log In

Start an interactive shell inside the container:

```bash
docker run --rm -it \
  --name nvme-cli-debug \
  ghcr.io/linux-nvme/debian:latest \
  bash
```

Or with Podman:

```bash
podman run --rm -it \
  --name nvme-cli-debug \
  ghcr.io/linux-nvme/debian:latest \
  bash
```

You are now logged into the same environment used by CI.

### 3. Clone the nvme-cli Repository

Inside the running container:

```bash
git clone https://github.com/linux-nvme/nvme-cli.git
cd nvme-cli
```

(Optional) Check out a specific branch or pull request:

```bash
git checkout <branch-or-commit>
```

### 4. Run the CI Build Script

The GitHub Actions workflow uses `scripts/build.sh`. To reproduce the CI build locally:

```bash
./scripts/build.sh
```

Privilege separation and the decoder sandbox are disabled by default and
have their own config, which runs the tests as a user (the privsep tests
skip as root), see [PRIVSEP.md](PRIVSEP.md):

```bash
./scripts/build.sh privsep
```

Build artifacts remain inside the container unless a host volume is mounted.

### 5. Cross-Build Example

The CI supports cross compilation using a dedicated cross-build container.

#### 5.1 Pull the Cross-Build Container

```bash
docker pull ghcr.io/linux-nvme/ubuntu-cross-s390x:latest
```

Or with Podman:

```bash
podman pull ghcr.io/linux-nvme/ubuntu-cross-s390x:latest
```

#### 5.2 Start the Cross-Build Container

```bash
docker run --rm -it \
  --name nvme-cli-cross \
  ghcr.io/linux-nvme/ubuntu-cross-s390x:latest \
  bash
```

Or with Podman:

```bash
podman run --rm -it \
  --name nvme-cli-cross \
  ghcr.io/linux-nvme/ubuntu-cross-s390x:latest \
  bash
```

#### 5.3 Clone the Repository

```bash
git clone https://github.com/linux-nvme/nvme-cli.git
cd nvme-cli
```

#### 5.4 Run a Cross Build

Example: Cross-build for `s390x`:

```bash
./scripts/build.sh -b release -c gcc -t s390x cross
```

The exact supported targets depend on the toolchains installed in the container.

#### 5.5 Cross Build on a Debian Host

The cross files in `.github/cross` work on a Debian (or Ubuntu) host too.
Install the toolchain of the target, and for the targets other than i386
qemu, which runs the tests:

```bash
apt install gcc-multilib                                 # i386
apt install gcc-arm-linux-gnueabihf qemu-user-static     # armhf
apt install gcc-powerpc64le-linux-gnu qemu-user-static   # ppc64le
apt install gcc-s390x-linux-gnu qemu-user-static         # s390x
```

The optional libraries come from the target architecture, e.g. json-c:

```bash
dpkg --add-architecture i386
apt update
apt install libjson-c-dev:i386
```

`scripts/build.sh` points qemu at the libraries of the cross toolchain
(`QEMU_LD_PREFIX`), as the tests also start the binaries through
binfmt_misc.

## Test names

Every test is named `<component> - <test>` and is in exactly one
group. `meson test` prints it as `<group> - nvme-cli:<component> - <test>`:

- `<component>` is what the test covers: `nvme-cli`, `libnvme`,
  `shared`, a daemon (`nvme-discoverd`, `nvme-keysd`, ...) or a plugin
  (`micron`, `ocp`, ...).
- `<test>` is in kebab-case and names the feature, usually the command
  it covers. It does not repeat the component and has no `-test` or
  `-cli` suffix. Fuzz and e2e tests start with `fuzz-` and `e2e-`.
- A group of tests over a set of inputs uses a `/`, e.g.
  `libnvme - header/tree` or `libnvme - nbft/rhpoc`.

The group is the meson suite and says how the test runs:

| Group   | What runs                                                     |
|---------|---------------------------------------------------------------|
| `unit`  | a test program for library or internal code                   |
| `mock`  | the nvme binary or a daemon, with a mock where it needs a device |
| `e2e`   | the nvme binary against a real device (`-De2e-tests=true`)    |
| `fuzz`  | a fuzz target over its corpus (see [Fuzzing](#fuzzing))       |
| `check` | a consistency check of the tree: headers, symbols, docs, tags |

Select tests by group or by a name pattern:

```shell
meson test -C .build --suite unit --suite mock
meson test -C .build 'micron - *'
meson test -C .build 'nvme-cli - print'
```

## Memory Testing

### Valgrind

A named Valgrind test setup is registered in `meson.build`. It runs all unit
tests under `valgrind --leak-check=full` and treats any leak as a test failure.

`--show-leak-kinds=all` is set, so the log lists every leak kind with a full
stack, including blocks that are still reachable from a global at exit. Only
"definite" and "possible" leaks fail the run, which is Valgrind's default: a
still-reachable block is usually third-party global state a process holds
until it exits, so it is reported for inspection rather than gating CI. If
one of them turns out to be ours and unbounded, fix it or suppress it.

Prerequisites: Valgrind must be installed (`apt install valgrind` or equivalent).

Build and run:

```bash
meson setup .build
meson compile -C .build
meson test -C .build --setup valgrind
```

A dedicated log is written to `.build/meson-logs/testlog-valgrind.txt`.

A suppression file (`valgrind.supp`) is bundled in the repository and loaded
automatically. It covers three categories of known false positives:

- **Shell script tests**: Valgrind wraps the shell interpreter, not the C
  binary under test. Bash's internal allocations are suppressed.
- **CPython internals**: Import machinery, marshal, and tokenizer code in the
  Python interpreter generate reports that are not leaks in our code.
- **SWIG module teardown**: SWIG allocates a varlink object during module
  initialisation that CPython never releases at shutdown.

If the system provides `/usr/lib/valgrind/python3.supp` it is also loaded
automatically at configure time.

Any remaining failures after suppression are real issues in our C code.

### AddressSanitizer / UndefinedBehaviourSanitizer (ASan / UBSan)

ASan and UBSan are compiled into the binaries, so they each require a separate
build directory. They detect different classes of bugs:

- **ASan** (`address`): heap overflows, use-after-free, memory leaks.
- **UBSan** (`undefined`): signed integer overflow, misaligned pointer access,
  null dereference, out-of-bounds indexing, and other C undefined behaviour.

Build and run:

```bash
meson setup .build-asanubsan -Db_sanitize=address,undefined
meson compile -C .build-asanubsan
meson test -C .build-asanubsan --setup asanubsan
```

No wrapper binary is needed — sanitizer reports are emitted directly to stderr
when a violation is detected.

With clang, set the C++ compiler too, and let shared libraries have the
symbols of the sanitizer runtime undefined: clang links the runtime only into
executables.

```bash
CC=clang CXX=clang++ meson setup .build-asanubsan \
    -Db_sanitize=address,undefined -Db_lundef=false
```

The same known limitations apply as for Valgrind: Python tests and shell script
tests may produce false positives. Focus triage on the `nvme-cli - *` unit tests.

## Fuzzing

The parsers of untrusted input have fuzz targets in `tests/fuzz`: the
command line parser (`argconfig`), the INI parser (`ini`), `nvme-cli.conf`
(`global-config`) and `nvme-fabrics.conf` (`fabrics-conf`).

The `device` target fuzzes what nvme-cli does with the data a device
returns. It runs one of the commands which read and print something, from
the table in `tests/fuzz/fuzz-device.c`, against the device mock of
`tests/cli/libmock_nvme.c`, which answers every command from the input.
An input selects the command by its index in the table, and may pass a
fuzzed value to one option of it, so add new commands at the end of the
table: the seeds and the corpus of earlier runs keep their meaning. It needs
a dynamically linked Linux build. Its seeds named `regress-*` are inputs
which found a bug.

Every build runs them as tests of the `fuzz` suite: each target replays its
seeds in `tests/fuzz/corpus/<target>` and then a few seconds of random
mutations of them. The mutations come from a fixed seed, so a failure can be
repeated, and the input which crashed a target is written to
`fuzz-crash-<target>` in the build directory.

```bash
meson test -C .build --suite fuzz
FUZZ_SECONDS=60 FUZZ_SEED=7 meson test -C .build --suite fuzz
```

Run in a sanitizer build (see above) they also catch memory errors which
don't crash.

For longer, coverage guided runs, `scripts/fuzz/nvme-fuzz` builds the targets
for libFuzzer with clang, runs them and evaluates what they find:

```bash
scripts/fuzz/nvme-fuzz build
scripts/fuzz/nvme-fuzz run --seconds 3600
scripts/fuzz/nvme-fuzz run --targets device --jobs 8
scripts/fuzz/nvme-fuzz triage
```

`build` sets up a sanitizer build in `.build-fuzz` (`-C` selects another),
with `--buildtype=debugoptimized`, so the reports of a finding name the source
lines. It takes clang for `CC` unless `CC` names one, e.g. `clang-19`, and the
`clang++` of the same version.

`run` runs every target in turn, each with one libFuzzer job per CPU on a
shared corpus, for 600 seconds by default. A finding stops only its job, a
UBSan finding like a crash; Ctrl-C stops the run. The results are in
`.build-fuzz/fuzz` (`--results` selects another directory): `summary.txt`, and
per target the logs of the jobs in `logs/<target>/`, the inputs which found a
bug in `artifacts/<target>/` and the corpus in `corpus/<target>/`, which starts
with the seeds and grows across runs. Each run first minimizes the corpus to
the inputs which add coverage (libFuzzer's `-merge=1`): every job loads all of
it. Before that, it adds the seeds of the mock tests of the build to the
corpus of the `device` target (see `seeds` below, `--no-mock-seeds` skips it).

The `device` target runs in stages of equal time with more device data per
input in each: 16 KiB, 64 KiB, 256 KiB and 1 MiB, the default of the device
mock (`--data-limits` selects others). Most data structures fit a page, and an
input which gets little data runs fast: a megabyte of log entries prints as
tens of megabytes of text. The mock takes the limit from `FUZZ_DATA_LIMIT`.
The findings of the target are named after the limit, `data-<limit>-crash-*`,
and `check` and `triage` replay them with it. Each stage starts with the corpus
minimized again, for its limit: a stage adds tens of thousands of inputs, and
each job of the next one would load all of them. A merge runs every input once,
so the corpus of the target is merged by command, one merge per CPU, and what
they keep once more.

`triage` replays the findings of a target and groups them by the bug they hit:
the kind of finding and the first nvme-cli frame. For the `device` target, it
names the command an input runs. `triage --show` prints the stack of each
input instead, with the source lines also without `llvm-symbolizer`. Both
replay each input in a temporary directory, so the `crash-*` inputs and
other files a run leaves behind do not pile up in the current one.

`check` runs inputs once each with halting sanitizers, by default the
regression inputs of a target, and prints what went wrong. The test suite
sends the output of the targets to `/dev/null`, so this is the way to see why
a seed fails, or to show that a new regression input fails without its fix.
The regression inputs are those of the source tree `nvme-fuzz` is in, also
with the build of another tree: run the `nvme-fuzz` of the tree under test.

`coverage` shows how far the `device` target gets into each of its commands:
the edges an input of a command reaches beyond those of a command which only
identifies the controller. A command which adds few does not get past its
option parsing, or a check of the device the fuzzer may never pass. It uses
random device data, or with `--corpus` the inputs of a corpus. The commands
of plugins which check the PCI IDs of the controller run with a model of each
set of capabilities in the model tables of the plugin, or with the IDs of
`--pci`.

`sweep` tries the commands of the `device` target before a fuzz run: it runs
each a few times with each variant and random device data, and reports one
which crashes, takes long or writes files into its working directory. A new
command in the table which does any of this would make a run fail on nearly
every input. `--entries` selects commands, `--save` keeps the inputs with a
problem for `check` and `triage`.

`seeds` adds seeds to the corpus of the `device` target from the CLI mock
tests, which answer the commands with valid device data, where fuzzed data
rarely gets past the first check. It runs the `mock` test suite of the build
with `NVME_FUZZ_RECORD` set, which records the answers in the input format of
the target, and turns each run of a command of the table into a seed named
`mock-*`. `-C` selects the build, e.g. one which runs the mock tests faster
than the sanitizer build; failed tests only record less.

`scripts/build.sh fuzz` builds and runs with `nvme-fuzz` too, in `.build-ci`
and with its `--fuzz-*` options. It removes the build directory first, the
results included: pass a `--fuzz-dir` outside of `.build-ci` to grow the
corpus across runs.

`nvme-fuzz` is plain Python 3.10. Its unit tests run with the other tests, and
`meson compile -C .build lint-fuzz-tool` runs `ruff` and `mypy` on it, with
the settings of `scripts/fuzz/pyproject.toml`.

The fuzz targets are libFuzzer binaries, which also run by hand: a file
argument runs that input once, a directory is a corpus to fuzz. Then a
crashing input is written to `crash-*` in the current directory. Add an input
which found a bug to the seeds of its target, named `regress-*`: the seeds run
with the default data limit, so check that it still fails without the fix with
`nvme-fuzz check`. The targets
use the libFuzzer interface, so AFL++ can run them too (`afl-clang-fast` with
`-fsanitize=fuzzer`).
