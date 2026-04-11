<!-- SPDX-License-Identifier: GPL-2.0-only -->
# Testing and CI

## Pre-built binary

For quick testing, an x86_64 static build from the current HEAD is available
[here](https://monom.org/linux-nvme/upload/nvme-cli-latest-x86_64).

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
