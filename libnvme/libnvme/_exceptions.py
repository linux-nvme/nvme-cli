# SPDX-License-Identifier: LGPL-2.1-or-later
# This file is part of libnvme.
# Copyright (c) 2026, Dell Technologies Inc. or its subsidiaries.
# Authors: Martin Belanger <Martin.Belanger@dell.com>


class NvmeError(Exception):
    """Base class for all libnvme errors.

    Attributes:
        errno:   OS error number (negative values are stored as-is).
        message: Human-readable description from libnvme_errno_to_string().
    """
    def __init__(self, errno, message):
        self.errno = errno
        self.message = message
        super().__init__(f"[Errno {errno}] {message}")


class ConnectError(NvmeError):
    """Raised when a controller connection attempt fails."""


class DisconnectError(NvmeError):
    """Raised when a controller disconnect attempt fails."""


class DiscoverError(NvmeError):
    """Raised when a discovery log retrieval fails."""


class NotConnectedError(NvmeError):
    """Raised when an operation requires a connected controller but none exists."""
    def __init__(self, message="Not connected"):
        super().__init__(0, message)
