# Plugin Tests

This directory contains hardware tests for nvme-cli vendor plugins. Each plugin
has its own subdirectory with tests that exercise plugin commands against real
hardware.

## Architecture

```
tests/plugins/
├── plugin_test.py            # Base class for all plugin tests
└── <plugin>/
    ├── meson.build           # Meson test definitions for a specific plugin
    ├── <plugin>_test.py      # plugin-specific base class
    └── *_test.py             # Individual test files
```

### Class Hierarchy

```
unittest.TestCase
└── TestNVMe (tests/nvme_test.py)
    └── TestPlugin (tests/plugins/plugin_test.py)
        └── Test<Plugin> (tests/plugins/<plugin>/<plugin>_test.py)
```

- **TestNVMe** — provides device config loading, `run_cmd()`, `exec_cmd()`,
  JSON parsing helpers, and log directory management.
- **TestPlugin** — adds `run_plugin_cmd()` and `run_plugin_cmd_check()` which
  invoke `nvme <plugin> <command> <device> <args>`. Automatically skips tests
  if the plugin is not available.
- **Test&lt;Plugin&gt;** — set the `<plugin>_name` attribute and provide a
  place for plugin-specific helpers.

## Meson Options

Plugin test suites are gated by the `plugin-tests` array option:

| Option          | Default | Choices          | Description                                   |
|-----------------|---------|------------------|-----------------------------------------------|
| `plugin-tests`  | `[]`    | `micron`, `ocp`  | List of plugin test suites to run against real hardware |

A plugin test suite is included in the build when these three conditions
are met:

1. `nvme-tests=true` (gates the entire `tests/` subtree)
2. The plugin name is listed in `plugin-tests` (e.g., `-Dplugin-tests=ocp`)
3. The plugin is listed in the `plugins` build option

## Configuration

Plugin tests reuse the same `tests/config.json` as the core tests. Ensure it
points to the correct controller and namespace for your hardware:

## Building and Running

### Configure with plugin tests enabled (comma separated list)

```bash
meson setup .build -Dnvme-tests=true -Dplugin-tests=ocp,micron
```

### Run all enabled test suites

```bash
meson test -C .build
```

### Run a specific plugin suite

```bash
meson test -C .build --suite ocp
```

### Run a single test by name

```bash
meson test -C .build "ocp - ocp_smart_add_log_test"
```

## Writing a New Test

1. Create a file in the appropriate plugin directory (e.g.,
   `tests/plugins/ocp/ocp_smart_add_log_test.py`).

2. Inherit from the plugin base class and write test methods.

3. Add the test filename to the plugin's `meson.build`.


### Key Helper Methods

| Method | Description |
|--------|-------------|
| `self.run_plugin_cmd(cmd, device=None, args="")` | Run a plugin command, return `CompletedProcess` |
| `self.run_plugin_cmd_check(cmd, device=None, args="")` | Same as above but asserts `returncode == 0` |
| `self.run_cmd(cmd)` | Run an arbitrary shell command |
| `self.exec_cmd(cmd)` | Run a shell command, return only the returncode |

## Adding a New Plugin Test Suite

To add tests for another plugin:

1. Add the plugin name to the `choices` list of the `plugin-tests` option in `meson_options.txt`

2. Add a conditional `subdir()` in `tests/plugins/meson.build`.


3. Create the directory structure:

```
tests/plugins/<plugin>/
├── meson.build
├── <plugin>_test.py
└── <plugin>_<command>_test.py
```

4. In `<plugin>_test.py`, inherit from `TestPlugin` and set `plugin_name`.

5. Copy one of the existing `meson.build` files (e.g., from `ocp/`) and
   adapt the variable names and test list.
