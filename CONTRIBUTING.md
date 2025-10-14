# Contributing to the NVM-e CLI

Here you will find instructions on how to contribute to the NVM-Express command
line interface.

Contributions and new ideas are most welcome!

**NOTE: If you do decide to implement code changes and contribute them,
please make sure you agree your contribution can be made available
under the [GPLv2-style License used for the NVMe CLI](https://github.com/linux-nvme/nvme-cli/blob/master/LICENSE).
(SPDX-License-Identifier: GPL-2.0-or-later)**

Because there are a few files licensed under GPL-2.0-only, the whole
project is tagged as GPL-2.0-only and not as GPL-2.0-or-later.

### Code Contributions

Please feel free to use the github forums to ask for comments & questions on
your code before submitting a pull request.  The NVMe CLI project uses the
common *fork and merge* workflow used by most GitHub-hosted projects.

#### Commit conventions

The project follows the Linux kernel mailing list workflow,
thus commit messages should be structured like this:
```
<feature|plugin|subject>: <commit message>

<description of the feature>

Signed-off-by: My Name/alias <email@address.foo>
```

Example:

```
doc: added commit conventions to contribution guidelines

Show new contributors the project's commit guidelines

Signed-off-by: John Doe <j.doe@address.foo>
```

### Bug Reports

Bugs for the NVM Library project are tracked in our [GitHub Issues Database](https://github.com/linux-nvme/nvme-cli/issues).
