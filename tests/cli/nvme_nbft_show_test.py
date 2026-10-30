#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


HAVE_JSON = os.environ.get("NVME_TEST_JSON", "1") == "1"


CASES = {
    "NBFT-unlinked-discovery": {
        "normal": [
            "nqn.2026-06.example:synthetic-root",
            "127.0.0.1",
            "nvme+tcp://127.0.0.1:8009/",
        ],
        "json": {
            "host_nqn": "nqn.2014-08.org.nvmexpress:uuid:11111111-1111-1111-1111-111111111111",
            "subsys_nqn": "nqn.2026-06.example:synthetic-root",
            "hfi_ip": "10.0.2.15",
            "hfi_route_metric": 500,
            "subsys_count": 1,
            "hfi_count": 1,
            "discovery_count": 1,
            "discovery_uri": "nvme+tcp://127.0.0.1:8009/",
        },
    },
    "NBFT-static-ipv4": {
        "normal": [
            "nqn.2022-12.org.nvmexpress.boot.poc:bremer.vagrant-nvmet.subsys02",
            "192.168.49.10",
            "192.168.49.50",
        ],
        "json": {
            "host_nqn": "nqn.2014-08.org.nvmexpress:uuid:a1b759e3-035d-4777-b3cc-1754b8b819b9",
            "subsys_nqn": "nqn.2022-12.org.nvmexpress.boot.poc:bremer.vagrant-nvmet.subsys02",
            "hfi_ip": "192.168.49.50",
            "hfi_route_metric": 0,
            "subsys_count": 1,
            "hfi_count": 1,
            "discovery_count": 0,
            "discovery_uri": None,
        },
    },
    "NBFT-synthetic-2hfi-3ssns-disc-sec": {
        "normal": [
            "nqn.2026-01.example:subsys-alpha",
            "nqn.2026-01.example:subsys-beta",
            "192.168.20.50",
            "nvme+tcp://192.168.10.5:8009/",
        ],
        "json": {
            "host_nqn": "nqn.2014-08.org.nvmexpress:uuid:22222222-2222-2222-2222-222222222222",
            "subsys_nqn": "nqn.2026-01.example:subsys-alpha",
            "hfi_ip": "192.168.20.50",
            "hfi_route_metric": 600,
            "subsys_count": 3,
            "hfi_count": 2,
            "discovery_count": 1,
            "discovery_uri": "nvme+tcp://192.168.10.5:8009/",
        },
    },
}


def run_command(command, env):
    return subprocess.run(
        command,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )


def assert_success(result, mode: str, table: Path) -> None:
    if result.returncode != 0:
        raise RuntimeError(
            f"nbft show {mode} failed for {table.name}: "
            f"exit={result.returncode}\nstdout={result.stdout}\nstderr={result.stderr}"
        )


def assert_json_values(output: str, expected, table: Path) -> None:
    try:
        records = json.loads(output)
    except json.JSONDecodeError as error:
        raise RuntimeError(f"invalid JSON for {table.name}: {output}") from error

    if not isinstance(records, list) or len(records) != 1:
        raise RuntimeError(f"expected one NBFT record for {table.name}: {records!r}")

    record = records[0]
    if Path(record["filename"]).name != "NBFT":
        raise RuntimeError(f"unexpected NBFT filename for {table.name}: {record!r}")

    if record["host"]["nqn"] != expected["host_nqn"]:
        raise RuntimeError(f"unexpected host NQN for {table.name}: {record['host']!r}")

    subsystems = record["subsystem"]
    if len(subsystems) != expected["subsys_count"]:
        raise RuntimeError(f"unexpected subsystem count for {table.name}: {subsystems!r}")
    if subsystems[0]["subsys_nqn"] != expected["subsys_nqn"]:
        raise RuntimeError(f"unexpected subsystem data for {table.name}: {subsystems!r}")
    if subsystems[0]["transport"] != "tcp" or subsystems[0]["trsvcid"] != "4420":
        raise RuntimeError(f"unexpected subsystem transport for {table.name}: {subsystems!r}")

    hfis = record["hfi"]
    if len(hfis) != expected["hfi_count"]:
        raise RuntimeError(f"unexpected HFI count for {table.name}: {hfis!r}")
    if hfis[-1]["ipaddr"] != expected["hfi_ip"]:
        raise RuntimeError(f"unexpected HFI data for {table.name}: {hfis!r}")
    if hfis[-1]["route_metric"] != expected["hfi_route_metric"]:
        raise RuntimeError(f"unexpected HFI route metric for {table.name}: {hfis!r}")

    discoveries = record["discovery"]
    if len(discoveries) != expected["discovery_count"]:
        raise RuntimeError(f"unexpected discovery count for {table.name}: {discoveries!r}")
    if expected["discovery_uri"] is None:
        if discoveries:
            raise RuntimeError(f"unexpected discovery data for {table.name}: {discoveries!r}")
    elif not discoveries or discoveries[0]["uri"] != expected["discovery_uri"]:
        raise RuntimeError(f"unexpected discovery data for {table.name}: {discoveries!r}")


def run_case(nvme: Path, table: Path) -> None:
    expected = CASES[table.name]

    with tempfile.TemporaryDirectory(prefix="nvme-nbft-show-test-") as raw_dir:
        test_dir = Path(raw_dir)
        table_dir = test_dir / "tables"
        table_dir.mkdir()
        shutil.copyfile(table, table_dir / "NBFT")

        sysfs_root = test_dir / "sysfs"
        (sysfs_root / "sys/class/nvme").mkdir(parents=True)
        (sysfs_root / "sys/class/nvme-subsystem").mkdir(parents=True)

        env = os.environ.copy()
        env["LC_ALL"] = "C"
        base_command = [
            str(nvme),
            f"--set-options=test-sysfs-dir={sysfs_root}",
            "nbft",
            "show",
            f"--nbft-path={table_dir}",
        ]

        normal = run_command(base_command, env)
        assert_success(normal, "normal", table)
        for value in expected["normal"]:
            if value not in normal.stdout:
                raise RuntimeError(f"missing {value!r} in normal output for {table.name}: {normal.stdout}")

        verbose = run_command([str(nvme), "-v", *base_command[1:]], env)
        assert_success(verbose, "verbose", table)
        for value in expected["normal"]:
            if value not in verbose.stdout:
                raise RuntimeError(f"missing {value!r} in verbose output for {table.name}: {verbose.stdout}")

        if HAVE_JSON:
            json_result = run_command([str(nvme), "-o", "json", *base_command[1:]], env)
            assert_success(json_result, "JSON", table)
            assert_json_values(json_result.stdout, expected["json"], table)


def main() -> int:
    nvme = Path(sys.argv[1]).resolve()
    for value in sys.argv[2:]:
        table = Path(value)
        if table.name not in CASES:
            raise RuntimeError(f"no expected values for NBFT fixture {table}")
        run_case(nvme, table)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
