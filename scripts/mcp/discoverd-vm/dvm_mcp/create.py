# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
#
# Authors: Martin Belanger <martin.belanger@dell.com>
"""vm_create: build the test VM from a Fedora Cloud image. The image is
downloaded and checked once; the VM disk is a qcow2 overlay on it. A
cloud-init seed creates the user and installs the build dependencies.
Then nvme-cli is copied in and built, a loopback nvme-tcp target is
set up, and nvme-discoverd connects it."""

from __future__ import annotations

import hashlib
import re
import shutil
import subprocess
import urllib.request
from pathlib import Path
from typing import Any

from .scenario import NQN
from .vm import DISK, KEY, SEED, VM, VM_SRC, VMError

FEDORA = (
    'https://download.fedoraproject.org/pub/fedora/linux/releases/44/'
    'Cloud/x86_64/images/'
)
IMAGE_URL = FEDORA + 'Fedora-Cloud-Base-Generic-44-1.7.x86_64.qcow2'
CHECKSUM_URL = FEDORA + 'Fedora-Cloud-44-1.7-x86_64-CHECKSUM'

# cloud-init: the packages the build and the scenarios need
PACKAGES = (
    'meson',
    'gcc',
    'git',
    'json-c-devel',
    'systemd-devel',
    'keyutils-libs-devel',
    'openssl-devel',
    'libuuid-devel',
    'xfsprogs',
    'iproute-tc',
    'rsync',
    'python3',
)

META_DATA = 'instance-id: discoverd-vm-1\nlocal-hostname: dvm\n'

# Runs as root in the VM after the source is copied: build and install
# nvme-cli, set up a loopback target that comes back at every boot, and
# let nvme-discoverd connect it.
SETUP_SCRIPT = f"""\
set -euo pipefail
NQN={NQN}
cd {VM_SRC}
meson setup .build --prefix=/usr --sysconfdir=/etc --localstatedir=/var \\
    -Dnvme-discoverd=enabled -Ddocs=false -Dpython=disabled -Dtests=false \\
    >/dev/null
meson compile -C .build >/dev/null
meson install --quiet -C .build --skip-subprojects >/dev/null

truncate -s 2G /var/lib/nvmet-test.img
cat > /usr/local/sbin/nvmet-test-setup <<SH
#!/bin/sh
set -e
modprobe nvmet-tcp
S=/sys/kernel/config/nvmet/subsystems/$NQN
P=/sys/kernel/config/nvmet/ports/1
[ -d \\$S ] && exit 0
mkdir \\$S
echo 1 > \\$S/attr_allow_any_host
mkdir \\$S/namespaces/1
echo /var/lib/nvmet-test.img > \\$S/namespaces/1/device_path
echo 1 > \\$S/namespaces/1/buffered_io
echo 1 > \\$S/namespaces/1/enable
mkdir \\$P
echo tcp > \\$P/addr_trtype
echo ipv4 > \\$P/addr_adrfam
echo 127.0.0.1 > \\$P/addr_traddr
echo 4420 > \\$P/addr_trsvcid
ln -s \\$S \\$P/subsystems/
SH
chmod +x /usr/local/sbin/nvmet-test-setup
cat > /etc/systemd/system/nvmet-test.service <<UNIT
[Unit]
Description=Loopback nvmet target for the shutdown tests
After=network.target
Before=nvme-discoverd.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/nvmet-test-setup

[Install]
WantedBy=multi-user.target
UNIT

[ -s /etc/nvme/hostnqn ] || nvme gen-hostnqn > /etc/nvme/hostnqn
[ -s /etc/nvme/hostid ] || uuidgen > /etc/nvme/hostid
cat > /etc/nvme/nvme-fabrics.conf <<CONF
[Subsystem]
nqn        = $NQN
controller = transport=tcp;traddr=127.0.0.1;trsvcid=4420
CONF

echo nvme-tcp > /etc/modules-load.d/nvme-tcp.conf
modprobe nvme-tcp
echo 'vm.dirty_expire_centisecs = 360000' > /etc/sysctl.d/99-dirty.conf
systemctl daemon-reload
systemctl enable --now nvmet-test.service nvme-discoverd.service
for i in $(seq 1 30); do
    grep -qlx "$NQN" /sys/class/nvme/nvme*/subsysnqn 2>/dev/null && break
    sleep 1
done
grep -qlx "$NQN" /sys/class/nvme/nvme*/subsysnqn 2>/dev/null || {{
    echo "error=nvme-discoverd did not connect $NQN"
    exit 1
}}
echo connected=true
"""


def user_data(pubkey: str) -> str:
    """The cloud-init user-data: a user with sudo and the key, the
    packages, and the modules of the running kernel (nvmet-tcp, netem)."""
    pkgs = ''.join(f'  - {p}\n' for p in PACKAGES)
    return (
        '#cloud-config\n'
        'users:\n'
        '  - name: test\n'
        '    sudo: ALL=(ALL) NOPASSWD:ALL\n'
        '    shell: /bin/bash\n'
        '    ssh_authorized_keys:\n'
        f'      - {pubkey}\n'
        'ssh_pwauth: false\n'
        'package_update: false\n'
        'packages:\n'
        f'{pkgs}'
        'runcmd:\n'
        '  - dnf -y install "kernel-modules-extra-$(uname -r)"'
        ' || dnf -y install kernel-modules-extra\n'
    )


def parse_checksum(text: str, name: str) -> str:
    """The SHA-256 of @name in a Fedora CHECKSUM file."""
    m = re.search(
        rf'^SHA256 \({re.escape(name)}\) = ([0-9a-f]{{64}})$', text, re.M
    )
    if not m:
        raise VMError(f'no SHA-256 for {name} in the checksum file')
    return m.group(1)


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda: f.read(1 << 20), b''):
            h.update(block)
    return h.hexdigest()


def fetch(url: str, dest: Path) -> None:
    """Downloads @url to @dest, through a temporary file."""
    part = dest.with_name(dest.name + '.part')
    try:
        with (
            urllib.request.urlopen(url, timeout=60) as r,
            part.open('wb') as f,
        ):
            shutil.copyfileobj(r, f, 1 << 20)
    except OSError as e:
        part.unlink(missing_ok=True)
        raise VMError(f'download of {url} failed: {e}') from e
    part.rename(dest)


def seed_cmd(out: Path, files: list[Path]) -> list[str]:
    """The command which writes the cloud-init seed ISO: xorriso, or
    genisoimage."""
    names = [str(f) for f in files]
    if shutil.which('xorriso'):
        return [
            'xorriso', '-as', 'mkisofs', '-quiet', '-output', str(out),
            '-volid', 'cidata', '-joliet', '-rock', *names,
        ]  # fmt: skip
    if shutil.which('genisoimage'):
        return [
            'genisoimage', '-quiet', '-output', str(out),
            '-volid', 'cidata', '-joliet', '-rock', *names,
        ]  # fmt: skip
    raise VMError('neither xorriso nor genisoimage is installed')


def _run(cmd: list[str], what: str, timeout: float = 120) -> None:
    try:
        p = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        raise VMError(f'{what} failed: {e}') from e
    if p.returncode:
        raise VMError(f'{what} failed: {p.stderr.strip()}')


def image(vm_dir: Path, url: str, checksum_url: str) -> Path:
    """The Fedora image in @vm_dir/img, downloaded and checked if it is
    not there yet."""
    img_dir = vm_dir / 'img'
    img_dir.mkdir(parents=True, exist_ok=True)
    img = img_dir / url.rsplit('/', 1)[1]
    if img.exists():
        return img
    sums = img_dir / checksum_url.rsplit('/', 1)[1]
    fetch(checksum_url, sums)
    want = parse_checksum(sums.read_text(), img.name)
    fetch(url, img)
    got = sha256(img)
    if got != want:
        img.unlink()
        raise VMError(f'{img.name}: SHA-256 {got}, expected {want}')
    return img


def create(
    vm: VM,
    source: Path,
    url: str = IMAGE_URL,
    checksum_url: str = CHECKSUM_URL,
    disk_gb: int = 20,
) -> dict[str, Any]:
    """Builds the VM in vm.vm_dir from scratch and leaves it running,
    with nvme-discoverd connected to the loopback target."""
    d = vm.vm_dir
    if (d / DISK).exists():
        raise VMError(f'{d / DISK} exists: remove {d} to create a new VM')
    for tool in ('qemu-system-x86_64', 'qemu-img', 'ssh', 'ssh-keygen'):
        if not shutil.which(tool):
            raise VMError(f'{tool} is not installed')
    d.mkdir(parents=True, exist_ok=True)

    img = image(d, url, checksum_url)

    if not (d / KEY).exists():
        _run(
            ['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C',
             'discoverd-vm', '-f', str(d / KEY)],
            'ssh-keygen',
        )  # fmt: skip
    seed_dir = d / 'seed'
    seed_dir.mkdir(exist_ok=True)
    ud, md = seed_dir / 'user-data', seed_dir / 'meta-data'
    ud.write_text(user_data((d / f'{KEY}.pub').read_text().strip()))
    md.write_text(META_DATA)
    _run(seed_cmd(d / SEED, [ud, md]), 'the seed ISO')

    _run(
        ['qemu-img', 'create', '-q', '-f', 'qcow2', '-F', 'qcow2',
         '-b', str(img.resolve()), str(d / DISK), f'{disk_gb}G'],
        'qemu-img',
    )  # fmt: skip

    boot = vm.start()
    # the first boot installs the packages
    r = vm.run('cloud-init status --wait >/dev/null; echo $?', timeout=1800)
    if r.out.strip() not in ('0', '2'):
        raise VMError(f'cloud-init failed: {r.out.strip()} {r.err.strip()}')
    vm.sync(source)
    r = vm.run(SETUP_SCRIPT, timeout=1800)
    if r.rc:
        tail = '\n'.join((r.out + r.err).splitlines()[-20:])
        raise VMError(f'the setup in the VM failed:\n{tail}')
    return {
        'vm_dir': str(d),
        'image': img.name,
        'first_boot_s': round(boot, 1),
        'connected': 'connected=true' in r.out,
    }
