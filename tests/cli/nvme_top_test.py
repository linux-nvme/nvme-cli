#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 SUSE LLC
#
# Authors: Daniel Wagner <dwagner@suse.de>
"""
Drive "nvme top" in a pseudo terminal on the sysfs of a captured
nvme-loop subsystem with two paths.

Usage: nvme_top_test.py NVME SYSFS_TARBALL
"""

import fcntl
import os
import pty
import select
import struct
import subprocess
import sys
import tempfile
import termios
import time
import unittest

NVME = ""
TARBALL = ""


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


class TestTop(unittest.TestCase):
    """nvme top on a loop subsystem"""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="nvme-top-test-")
        # tar, as this script may run under valgrind, which makes the
        # tarfile module take half a minute
        subprocess.run(["tar", "-xJf", TARBALL, "-C", self.tmp.name],
                       check=True)

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
        ctl = os.path.join(self.tmp.name,
                           "sys/devices/virtual/nvme-fabrics/ctl")
        for ctrl in os.listdir(ctl):
            state = os.path.join(ctl, ctrl, "state")
            if os.path.exists(state):
                os.unlink(state)
        self.check_subsystem_screen()

    def test_path_without_stat(self) -> None:
        """A path may go away while it is shown, e.g. at a failover"""
        ctl = os.path.join(self.tmp.name,
                           "sys/devices/virtual/nvme-fabrics/ctl")
        os.unlink(os.path.join(ctl, "nvme0/nvme0c0n1/stat"))
        self.check_subsystem_screen()


if __name__ == "__main__":
    NVME, TARBALL = sys.argv[1], sys.argv[2]
    unittest.main(argv=sys.argv[:1], verbosity=2)
