# SPDX-License-Identifier: LGPL-2.1-or-later
# This file is part of libnvme.
"""Tests the versions the libnvme3 package reports."""

import unittest
import libnvme3


class TestVersion(unittest.TestCase):

    def test_git_version(self):
        """__git_version__ is the git version of the loaded libnvme."""
        version = libnvme3.__git_version__
        self.assertIsInstance(version, str)
        self.assertTrue(version)
        self.assertFalse(version[0] == 'v' and version[1:2].isdigit(),
                         f'{version!r} keeps the "v" of the tag')

    def test_no_attribute(self):
        """Other names are no attributes of the package."""
        with self.assertRaises(AttributeError):
            libnvme3.no_such_attribute


if __name__ == '__main__':
    unittest.main()
