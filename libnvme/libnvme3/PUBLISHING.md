<!-- SPDX-License-Identifier: LGPL-2.1-or-later -->
# Publishing the libnvme PyPI package

Publishing is handled automatically by GitHub Actions workflows — no manual `twine` or `pip` commands are needed.

## What gets published

A **source distribution** (sdist) is published — not a binary wheel. The package contains the full source tree and builds libnvme and the Python bindings on the target machine at install time (via `pyproject.toml`).

## Workflows

### Test PyPI — on every push to `master`

The `libnvme-release-python.yml` workflow runs on every push to `master`. It builds a dev sdist (version derived from `git describe`, e.g. `3.0.dev123`) and publishes it to [TestPyPI](https://test.pypi.org/).

To install from TestPyPI:

```bash
pip install \
  --index-url https://test.pypi.org/simple/ \
  --extra-index-url https://pypi.org/simple/ \
  libnvme==<version>
```

### PyPI — on release tags

When a tag matching `vX.Y` or `vX.Y.Z` is pushed, the same workflow publishes the release sdist to the official [PyPI](https://pypi.org/) registry.

Publishing uses OIDC (`id-token: write`) — no API token is required.
