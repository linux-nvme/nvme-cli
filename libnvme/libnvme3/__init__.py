# SPDX-License-Identifier: LGPL-2.1-or-later
#
# This file is part of libnvme.
# Copyright (c) 2022 Dell Inc.
#
# Authors: Martin Belanger <Martin.Belanger@dell.com>

__version__ = @LIBNVME_VERSION@


def __getattr__(name):
    # The git version of the loaded libnvme, not of the build of this file
    if name == '__git_version__':
        from .nvme import _git_version
        return _git_version()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
