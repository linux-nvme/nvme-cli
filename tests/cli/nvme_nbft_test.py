#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (c) 2026 Flavien Solt

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


def run_case(nvme: Path, table: Path) -> None:
    with tempfile.TemporaryDirectory(prefix="nvme-nbft-test-") as raw_dir:
        test_dir = Path(raw_dir)
        table_dir = test_dir / "tables"
        table_dir.mkdir()
        shutil.copyfile(table, table_dir / "NBFT")

        sysfs_root = test_dir / "sysfs"
        (sysfs_root / "sys/class/nvme").mkdir(parents=True)
        (sysfs_root / "sys/class/nvme-subsystem").mkdir(parents=True)

        env = os.environ.copy()
        env["LC_ALL"] = "C"

        command = [
            str(nvme),
            f"--set-options=test-sysfs-dir={sysfs_root}",
            "connect-all",
            "--nbft",
            f"--nbft-path={table_dir}",
            "--hostnqn=nqn.2014-08.org.nvmexpress:uuid:"
            "3a3f9475-2f25-48d3-9025-0c2f288a4e88",
            "--hostid=3a3f9475-2f25-48d3-9025-0c2f288a4e88",
        ]
        result = subprocess.run(
            command,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if result.returncode < 0:
            raise RuntimeError(
                f"{table.name} terminated from signal {-result.returncode}"
            )


def main() -> int:
    if Path("/dev/nvme-fabrics").exists():
        return 77

    nvme = Path(sys.argv[1]).resolve()
    for value in sys.argv[2:]:
        run_case(nvme, Path(value))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
