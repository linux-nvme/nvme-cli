<!-- SPDX-License-Identifier: GPL-2.0-only -->
# Testing and CI

## Pre-built binary

For quick testing, an x86_64 static build from the current HEAD is available
[here](https://oxygen.monom.org/linux-nvme/bin/nvme-cli-latest-x86_64).

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
It needs a dynamically linked Linux build. Its seeds named `regress-*` are
inputs which found a bug.

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

For longer, coverage guided runs, build the targets for libFuzzer with clang,
in a sanitizer build as described above:

```bash
CC=clang CXX=clang++ meson setup .build-fuzz -Dfuzzing=true \
    -Db_sanitize=address,undefined -Db_lundef=false
meson compile -C .build-fuzz
```

Run a target on a copy of its seeds in the build directory, so the seeds in
the tree stay as they are. The new inputs libFuzzer finds go to the copy:

```bash
mkdir -p .build-fuzz/corpus/argconfig
cp tests/fuzz/corpus/argconfig/* .build-fuzz/corpus/argconfig/
.build-fuzz/tests/fuzz/fuzz-argconfig -close_fd_mask=3 \
    -dict=tests/fuzz/argconfig.dict .build-fuzz/corpus/argconfig
```

The config targets (`ini`, `global-config`, `fabrics-conf`) use
`tests/fuzz/config.dict`. The `device` target reads log pages, so give it
longer inputs. A device reports sizes of up to gigabytes, which nvme-cli
allocates: let ASan fail such an allocation instead of libFuzzer aborting the
run as out of memory:

```bash
mkdir -p .build-fuzz/corpus/device
cp tests/fuzz/corpus/device/* .build-fuzz/corpus/device/
ASAN_OPTIONS=allocator_may_return_null=1:max_allocation_size_mb=1024 \
    .build-fuzz/tests/fuzz/fuzz-device -close_fd_mask=3 -max_len=16384 \
    -timeout=10 .build-fuzz/corpus/device
```

`scripts/build.sh fuzz` does all of this for every target in turn, each with
one libFuzzer job per CPU on a shared corpus, for 600 seconds by default:

```bash
scripts/build.sh --fuzz-seconds 3600 fuzz
scripts/build.sh --fuzz-targets device --fuzz-jobs 8 fuzz
```

It writes the results to `.build-ci/fuzz`: `summary.txt`, and per target the
logs of the jobs in `logs/<target>/`, the inputs which found a bug in
`artifacts/<target>/` and the corpus in `corpus/<target>/`. A finding stops
only its job, a UBSan finding like a crash. The next run of `build.sh` removes
the results; pass a `--fuzz-dir` outside of `.build-ci` to keep them, and to
grow the corpus across runs. `scripts/build.sh -h` lists all options.

When run by hand, a crashing input is written to `crash-*` in the current
directory. Add an input which found a bug to the seeds of its target. The
targets use the libFuzzer interface, so AFL++ can run them too
(`afl-clang-fast` with `-fsanitize=fuzzer`).
