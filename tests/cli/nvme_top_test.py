#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 SUSE LLC
#
# Authors: Daniel Wagner <dwagner@suse.de>
"""
Drive "nvme top" in a pseudo terminal, and its JSON output, on the sysfs
of a captured nvme-loop subsystem with two paths and of a PCIe host.

Usage: nvme_top_test.py NVME SYSFS_DATA_DIR
"""

import errno
import fcntl
import json
import os
import pty
import select
import struct
import subprocess
import sys
import tempfile
import termios
import threading
import time
import unittest
from typing import Any, Dict, List

NVME = ""
DATA = ""
LOOP = "tree-loop-duplicate.tar.xz"
PCIE = "tree-pcie.tar.xz"
FABRICS = "sys/devices/virtual/nvme-fabrics/ctl"


class NvmeTop:
    """nvme top in a pseudo terminal"""

    def __init__(self, sysfs: str) -> None:
        self.out = b""
        self.pid, self.fd = pty.fork()
        if self.pid == 0:
            os.execv(NVME, [NVME, f"--set-options=test-sysfs-dir={sysfs}",
                            "top", "--delay=1"])
        fcntl.ioctl(self.fd, termios.TIOCSWINSZ,
                    struct.pack("HHHH", 60, 200, 0, 0))

    def expect(self, text: str, timeout: float = 10) -> bool:
        """Reads the output until @text shows up or the timeout expires"""
        end = time.monotonic() + timeout
        while text.encode() not in self.out:
            left = end - time.monotonic()
            if left <= 0:
                return False
            ready, _, _ = select.select([self.fd], [], [], left)
            if not ready:
                continue
            try:
                data = os.read(self.fd, 4096)
            except OSError:
                return False
            if not data:
                return False
            self.out += data
        return True

    def send(self, keys: bytes) -> None:
        """Types @keys and forgets the output seen so far"""
        self.out = b""
        os.write(self.fd, keys)

    def wait(self, timeout: float = 10) -> int:
        """Returns the wait status, or kills nvme top after the timeout"""
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            pid, status = os.waitpid(self.pid, os.WNOHANG)
            if pid:
                os.close(self.fd)
                return status
            # drain the output, nvme top blocks on a full terminal
            if select.select([self.fd], [], [], 0.1)[0]:
                try:
                    os.read(self.fd, 4096)
                except OSError:
                    pass
        os.kill(self.pid, 9)
        _, status = os.waitpid(self.pid, 0)
        os.close(self.fd)
        return status


def extract(tarball: str, dest: str) -> None:
    # tar, as this script may run under valgrind, which makes the tarfile
    # module take half a minute
    subprocess.run(["tar", "-xJf", os.path.join(DATA, tarball), "-C", dest],
                   check=True)


class TestTop(unittest.TestCase):
    """nvme top on a loop subsystem"""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="nvme-top-test-")
        extract(LOOP, self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def check_subsystem_screen(self) -> None:
        """Enter shows the subsystem, q quits"""
        top = NvmeTop(self.tmp.name)
        self.assertTrue(top.expect("nvme-subsys0"), top.out)
        top.send(b"\r")
        self.assertTrue(top.expect("Controller Summary"), top.out)
        top.send(b"q")
        status = top.wait()
        self.assertTrue(os.WIFEXITED(status),
                        f"nvme top died: wait status {status:#x}")
        self.assertEqual(os.WEXITSTATUS(status), 0)

    def test_subsystem_screen(self) -> None:
        """A loop controller has no transport address"""
        self.check_subsystem_screen()

    def test_controller_without_state(self) -> None:
        """The state of a controller is gone while it is deleted"""
        ctl = os.path.join(self.tmp.name, FABRICS)
        for ctrl in os.listdir(ctl):
            state = os.path.join(ctl, ctrl, "state")
            if os.path.exists(state):
                os.unlink(state)
        self.check_subsystem_screen()

    def test_path_without_stat(self) -> None:
        """A path may go away while it is shown, e.g. at a failover"""
        os.unlink(os.path.join(self.tmp.name, FABRICS,
                               "nvme0/nvme0c0n1/stat"))
        self.check_subsystem_screen()


def stat_line(rd_ios: int, rd_sectors: int, rd_ticks: int,
              io_ticks: int, inflight: int = 0) -> str:
    """A block layer stat file with reads only"""
    return (f"{rd_ios} 0 {rd_sectors} {rd_ticks} 0 0 0 0 {inflight} "
            f"{io_ticks} {rd_ticks} 0 0 0 0 0 0\n")


class Feeder(threading.Thread):
    """Makes @path a FIFO which hands out @lines, one per open"""

    def __init__(self, path: str, lines: List[str]) -> None:
        super().__init__(daemon=True)
        os.unlink(path)
        os.mkfifo(path)
        self.path, self.lines = path, lines
        self.stop = time.monotonic() + 30
        self.start()

    def run(self) -> None:
        for line in self.lines:
            while time.monotonic() < self.stop:
                try:
                    fd = os.open(self.path, os.O_WRONLY | os.O_NONBLOCK)
                except OSError as e:
                    if e.errno != errno.ENXIO:  # no reader yet
                        raise
                    time.sleep(0.01)
                    continue
                os.write(fd, line.encode())
                os.close(fd)
                # let the reader close before the next open
                time.sleep(0.1)
                break


@unittest.skipUnless(os.environ.get("NVME_TEST_JSON", "1") == "1",
                     "nvme without json-c")
class TestTopJson(unittest.TestCase):
    """nvme top -o json"""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="nvme-top-test-")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def top(self) -> Dict[str, Any]:
        res = subprocess.run(
            [NVME, f"--set-options=test-sysfs-dir={self.tmp.name}",
             "top", "--delay=1", "--output-format=json"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=60, check=False)
        self.assertEqual(res.returncode, 0, res.stderr)
        doc: Dict[str, Any] = json.loads(res.stdout)
        self.assertEqual(doc["Interval"], 1)
        return doc

    def test_loop(self) -> None:
        """The rates of the two samples, and the loop controllers"""
        extract(LOOP, self.tmp.name)
        root = self.tmp.name
        head = "sys/devices/virtual/nvme-subsystem/nvme-subsys0/nvme0n1"
        feeders = [
            Feeder(os.path.join(root, head, "stat"),
                   [stat_line(100, 800, 50, 40),
                    stat_line(4100, 8800, 8050, 840, 3)]),
            Feeder(os.path.join(root, FABRICS, "nvme0/nvme0c0n1/stat"),
                   [stat_line(0, 0, 0, 0),
                    stat_line(1000, 2000, 2000, 400, 1)]),
            Feeder(os.path.join(root, FABRICS, "nvme1/nvme0c1n1/stat"),
                   [stat_line(0, 0, 0, 0),
                    stat_line(3000, 6000, 6000, 800, 2)]),
        ]
        doc = self.top()
        for f in feeders:
            f.join(5)

        sub, = doc["Subsystems"]
        self.assertEqual(sub["Name"], "nvme-subsys0")
        self.assertEqual(sub["IOPolicy"], "numa")
        ns, = sub["Namespaces"]
        self.assertEqual(ns["NSID"], 1)
        st = ns["Stats"]
        # 4000 reads over a bit more than the delay of 1 s
        self.assertTrue(3600 < st["ReadIOPS"] <= 4000, st)
        self.assertEqual(st["ReadLatencyMs"], 2.0)
        # 8000 sectors of 512 bytes, two decimals each
        self.assertAlmostEqual(st["ReadBytesPerSec"],
                               st["ReadIOPS"] * 2 * 512, delta=10)
        self.assertEqual(st["Inflights"], 3)
        self.assertEqual(st["WriteIOPS"], 0)

        paths = {p["Name"]: p for p in ns["Paths"]}
        self.assertEqual(sorted(paths), ["nvme0c0n1", "nvme0c1n1"])
        p0, p1 = paths["nvme0c0n1"], paths["nvme0c1n1"]
        self.assertEqual(p0["Controller"], "nvme0")
        self.assertEqual(p0["ANAState"], "optimized")
        # each path has an interval of its own
        self.assertTrue(900 < p0["Stats"]["ReadIOPS"] <= 1000, p0)
        self.assertTrue(2700 < p1["Stats"]["ReadIOPS"] <= 3000, p1)
        self.assertEqual(p0["Stats"]["ReadLatencyMs"], 2.0)
        self.assertEqual(p1["Stats"]["Inflights"], 2)

        # the sum of the namespaces, the highest latency
        self.assertEqual(sub["Stats"]["ReadIOPS"], st["ReadIOPS"])
        self.assertEqual(sub["Stats"]["MaxReadLatencyMs"], 2.0)

        ctrls = {c["Name"]: c for c in sub["Controllers"]}
        self.assertEqual(sorted(ctrls), ["nvme0", "nvme1"])
        c1 = ctrls["nvme1"]
        self.assertEqual(c1["Transport"], "loop")
        self.assertEqual(c1["Address"], "")
        self.assertEqual(c1["NUMANode"], -1)
        self.assertEqual(c1["Paths"], 1)
        self.assertEqual(c1["Stats"]["ReadIOPS"], p1["Stats"]["ReadIOPS"])

    def test_path_without_stat(self) -> None:
        """A path which went away has no rates"""
        extract(LOOP, self.tmp.name)
        os.unlink(os.path.join(self.tmp.name, FABRICS,
                               "nvme0/nvme0c0n1/stat"))
        sub, = self.top()["Subsystems"]
        paths = {p["Name"]: p for p in sub["Namespaces"][0]["Paths"]}
        self.assertEqual(paths["nvme0c0n1"]["Stats"]["ReadIOPS"], 0)

    def test_pcie(self) -> None:
        """A subsystem without multipath, and one with"""
        extract(PCIE, self.tmp.name)
        subs = {s["Name"]: s for s in self.top()["Subsystems"]}
        ns, = subs["nvme-subsys0"]["Namespaces"]
        self.assertEqual(ns["Controller"], "nvme0")
        self.assertNotIn("Paths", ns)
        self.assertNotIn("Paths", subs["nvme-subsys0"]["Controllers"][0])
        ns, = subs["nvme-subsys1"]["Namespaces"]
        self.assertEqual(len(ns["Paths"]), 2)
        self.assertNotIn("Controller", ns)


if __name__ == "__main__":
    NVME, DATA = sys.argv[1], sys.argv[2]
    unittest.main(argv=sys.argv[:1], verbosity=2)
