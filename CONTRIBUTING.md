<!-- SPDX-License-Identifier: GPL-2.0-only -->
# Contributing to nvme-cli and libnvme

Here you will find instructions on how to contribute to the NVM-Express command
line interface and the libnvme library.

Contributions and new ideas are most welcome!

This repository contains two components with different licenses:

| Component | License | SPDX identifier |
|-----------|---------|-----------------|
| nvme-cli (CLI and plugins) | GNU General Public License v2 or later | `GPL-2.0-or-later` |
| libnvme (library) | GNU Lesser General Public License v2.1 or later | `LGPL-2.1-or-later` |

When contributing, use the appropriate SPDX identifier for the component you
are modifying. New files under `libnvme/` should carry `LGPL-2.1-or-later`;
new files in the CLI or plugins should carry `GPL-2.0-or-later`.

## API naming conventions

### Spec-mirroring definitions (`nvme_` / `nvmf_`)

Types, structs, and enums that directly mirror the NVMe specifications use the
short `nvme_` (base spec) and `nvmf_` (NVMe-oF spec) prefixes. These live in
`libnvme/src/nvme/types.h` and `libnvme/src/nvme/cmds.h` and reflect the
specification naming — they are data-layout definitions, not library API.

### libnvme public API (`libnvme_` / `libnvmf_`)

This is where the naming convention is enforced. libnvme is a shared library
with a stable public ABI, so every public symbol must carry the correct prefix
so that callers can immediately tell what they are working with.

| Prefix | Scope | Examples |
|--------|-------|---------|
| `libnvme_` | Common NVMe (PCIe and NVMe-oF) | `libnvme_open()`, `libnvme_create_global_ctx()`, `libnvme_first_host()`, `libnvme_ctrl_identify()` |
| `libnvmf_` | NVMe-oF only | `libnvmf_connect_ctrl()`, `libnvmf_add_ctrl()`, `libnvmf_get_discovery_log()`, `libnvmf_trtype_str()` |

The split is enforced by two separate linker version scripts:
`libnvme/src/libnvme.ld` exports all `libnvme_*` symbols and
`libnvme/src/libnvmf.ld` exports all `libnvmf_*` symbols. Both are passed to
the linker when building `libnvme.so`.

When contributing new functions to libnvme, choose the prefix based on scope:
- Use `libnvme_` if the function applies to both PCIe and NVMe-oF controllers.
- Use `libnvmf_` if the function is specific to NVMe-oF (fabrics transport,
  discovery, connect/disconnect).

## Adding commands and plugins

You may wish to add a new command or possibly an entirely new plug-in
for some special extension outside the spec.

Every command (built-in or plugin) is a `struct command`: a name, a help
string, a callback, and optionally an alias, a `deprecated` flag, or a
`no_device` flag. A group of commands is registered together with
`plugin_add_group()`, and a named plugin additionally calls
`register_extension()` once. 

### Add a command to an existing group

The built-in (no-plugin-prefix) commands are split by feature area across
`src/nvme-cmds-*.c` (e.g. `src/nvme-cmds-io.c` for read/write/flush/...,
`src/nvme-cmds-registers.c` for register access, etc.). Pick the file that
matches your command's area, or add a new `src/nvme-cmds-<area>.c` if none
fit -- just add the one line to `src/meson.build`'s `sources` list. Each
such file ends with a block like this one from `src/nvme-cmds-discovery.c`:

```c
static struct command get_log_cmd = {
	.name = "get-log",
	.help = "Generic NVMe get log, returns log in raw format",
	.fn = get_log,
};

static struct command *commands[] = {
	&get_log_cmd,
	/* ... */
	NULL,
};

static void __shr_constructor register_group(void)
{
	plugin_add_group(&builtin, "Log Page & Identify", commands);
}
```

To add a command, write its callback function, add a `struct command`
literal for it, and add that entry to the `commands[]` array. The
callback's prototype is:

```c
int f(int argc, char **argv, struct command *command, struct plugin *plugin);
```

`argc`/`argv` are adjusted to start after the sub-command. For
`nvme foo --option=bar`, `argc` is 1 and `argv` starts at `--option`.
Use `.alias = "other-name"` for an alias, and `.deprecated = true` for a
deprecated command (deprecated built-ins live in
`src/nvme-cmds-deprecated.c`, gated by `#ifdef CONFIG_DEPRECATED_CMDS`).
Set `.no_device = true` for a command that doesn't take a positional
`<device>` argument (e.g. `nvme list` or `nvme gen-hostnqn`) -- this drops
`<device>` from its usage line and, when none of a plugin's commands need
one, from that plugin's `--help` output too.

The `title` passed to `plugin_add_group()` (`"Log Page & Identify"` above)
is the heading shown for that group's commands in `nvme help`; pass `NULL`
for no heading (that's what plugins normally do, see below).

### Add a new plugin

Create `plugins/foo/foo-nvme.c` (no header needed unless you have real
shared declarations across multiple files, see "Multi-file plugins"
below). Implement your command callbacks, then add the same three pieces
at the end of the file:

```c
static int bar(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	...
}

static struct command bar_cmd = {
	.name = "bar",
	.help = "foo bar",
	.fn = bar,
};

static struct command *commands[] = {
	&bar_cmd,
	NULL,
};

static struct plugin plugin = {
	.name = "foo",
	.desc = "Foo plugin",
	.version = NVME_VERSION,
	/* .core = true,   -- for a "core" plugin, shown in its own section of `nvme help` */
};

static void __attribute__((constructor)) register_plugin(void)
{
	plugin_add_group(&plugin, NULL, commands);
	register_extension(&plugin);
}
```

Then append `plugins/foo/foo-nvme.c` to the `all_plugins` dict in
`plugins/meson.build`.

"Core" vs. "vendor" plugin is just the `.core` flag on `struct plugin` --
it only affects which heading a plugin's listed under on `nvme help`. Both
kinds work identically otherwise.

A core plugin can also set `.group` to the title of a built-in group (see
above) it's thematically related to, e.g. `.group = "Features"` for the
`feat` plugin. When set, `nvme help` lists the plugin right after that
group's commands instead of in the flat "core NVMe/NVMeoF plugins" list.
This only affects display -- the plugin is still invoked as `nvme foo bar`,
not merged into the flat top-level command namespace.

#### Multi-file plugins

A plugin can span multiple `.c` files (see `plugins/ocp` or
`plugins/solidigm` for real examples): put the `struct plugin` definition
and any shared declarations in a small header, `#include` it from each
file, and have each file call `plugin_add_group()` with its own commands
(and its own title, if you want `nvme <plugin> help` to show sub-headings)
. only *one* file should call `register_extension()`.

### Regenerating shell completions

nvme-cli ships bash, zsh, and PowerShell tab-completion scripts under
`completions/`. They are generated from the command and option metadata the
built `nvme` binary emits, committed to the source tree, and are **not**
regenerated during a normal build. A CI check rejects any change that leaves
them out of sync with the CLI.

After adding or changing a command, plugin, or option, regenerate and commit
the completions:

```shell
$ meson compile -C .build update-completions
$ git add completions/bash-nvme-completion.sh completions/_nvme completions/nvme-completion.ps1
$ git commit -s -m "completions: regenerate for <your change>"
```

Do this on **Linux** with the default (all-plugins) build. Windows and other
reduced builds leave some plugins out, so completions generated there would be
missing commands and fail the CI check.

See [completions/README](completions/README) for how the generator works and
how to install the completions locally.

### Updating the libnvme accessor functions

libnvme exposes auto-generated getter/setter accessor functions for its
ABI-stable opaque structs. Two sets of accessors are maintained — one for
common NVMe structs and one for NVMe-oF-specific structs. The split exists so
that non-fabrics (e.g. embedded or PCIe-only) builds can exclude all fabrics
code entirely.

| Meson target | Input header | Generated files |
|---|---|---|
| `update-common-accessors` | `libnvme/src/nvme/private.h` | `libnvme/src/nvme/accessors.{h,c}`, `libnvme/src/accessors.ld` |
| `update-fabrics-accessors` | `libnvme/src/nvme/private-fabrics.h` | `libnvme/src/nvme/accessors-fabrics.{h,c}`, `libnvme/src/accessors-fabrics.ld` |

The generated `.h` and `.c` files are committed to the source tree and are
**not** regenerated during a normal build.

#### When to regenerate

Regeneration is needed whenever a `/*!generate-accessors*/` struct in
`private.h` or `private-fabrics.h` has a member added, removed, or renamed.

#### How to regenerate

To regenerate both sets at once:

```shell
$ meson compile -C .build update-accessors
```

Or regenerate only one set:

```shell
$ meson compile -C .build update-common-accessors
$ meson compile -C .build update-fabrics-accessors
```

The script atomically updates the `.h` and `.c` files when their content
changes. Commit the updated files afterward:

```shell
$ git add libnvme/src/nvme/generated/accessors.h libnvme/src/nvme/generated/accessors.c
$ git add libnvme/src/nvme/generated/accessors-fabrics.h libnvme/src/nvme/generated/accessors-fabrics.c
$ git commit -m "libnvme: regenerate accessors following <struct> changes"
```

#### Maintaining the .ld version-script files

The `.ld` files (`libnvme/src/accessors.ld` and
`libnvme/src/accessors-fabrics.ld`) are GNU linker version scripts that
control which accessor symbols are exported from the shared library and under
which ABI version label they were introduced (e.g. `LIBNVME_ACCESSORS_3`,
`LIBNVMF_ACCESSORS_3`).

These files are **not** updated automatically, because each new symbol must be
placed in the correct version section by the maintainer. Adding a symbol to an
already-published version section would break binary compatibility for
existing users of the library.

When the generator detects that the symbol list has drifted, it prints a
report like the following:

```
WARNING: accessors.ld needs manual attention.

  Symbols to ADD (new version section, e.g. LIBNVME_ACCESSORS_X_Y):
    libnvme_ctrl_get_new_field
    libnvme_ctrl_set_new_field
```

New symbols must be added to a **new** version section that chains the
previous one. For example, if the current latest section is
`LIBNVME_ACCESSORS_3`, add:

```
LIBNVME_ACCESSORS_4 {
    global:
        libnvme_ctrl_get_new_field;
        libnvme_ctrl_set_new_field;
} LIBNVME_ACCESSORS_3;
```

Then commit the updated `.ld` file together with the regenerated source files.

## Submitting changes

There are two ways to send code changes to the project. The first one
is by sending the changes to linux-nvme@lists.infradead.org. The
second one is by posting a pull request on Github. In both cases
please follow the Linux contributions guidelines as documented in
[Submitting patches](https://docs.kernel.org/process/submitting-patches.html).

That means the changes should be a clean series (no merges should be
present in a Github PR for example) and every commit should build.

See also [How to create a pull request on GitHub](https://opensource.com/article/19/7/create-pull-request-github).

### Commit conventions

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

### How to clean up your series before creating a PR

This example here assumes the changes are in a branch called
fix-something, which branched away from master in the past. In the
meantime the upstream project has changed, hence the fix-something
branch is not based on the current HEAD. Before posting the PR, the
branch should be rebased on the current HEAD and retest everything.

For example, rebasing can be done by the following steps

```shell
# Update master branch
#   upstream == https://github.com/linux-nvme/nvme-cli.git
$ git switch master
$ git fetch --all
$ git reset --hard upstream/master

# Make sure all dependencies are up to date and make a sanity build
$ meson subprojects update
$ ninja -C .build

# Go back to the fix-something branch
$ git switch fix-something

# Rebase it to the current HEAD
$ git rebase master
[fixup all merge conflicts]
[retest]

# Push your changes to Github and trigger a PR
$ git push -u origin fix-something
```

## AI-assisted development (optional)

The [nvme-cli-ai](https://github.com/linux-nvme/nvme-cli-ai) companion
repository provides optional AI workflow resources for contributors who use
AI coding assistants. It contains shared project context, coding rules,
reusable skills, and assistant configuration files for the nvme-cli and
libnvme ecosystem.

Using nvme-cli-ai is entirely optional. The nvme-cli project has no dependency
on any AI tooling.

### Setup

Clone both repositories side-by-side under the same parent directory:

    workspace/
    ├── nvme-cli/
    └── nvme-cli-ai/

### Claude Code

Claude Code searches for configuration by walking up the directory tree from
the current working directory. Because nvme-cli-ai is a sibling repository,
use the --add-dir flag to include it when starting a session:

    $ claude --add-dir ../nvme-cli-ai

Skills under .claude/skills/ (such as the /nvme-spec verifier) are discovered
automatically from the added directory. The shared CLAUDE.md project context,
however, is not loaded from an --add-dir directory by default; to load it as
well, also set CLAUDE_CODE_ADDITIONAL_DIRECTORIES_CLAUDE_MD=1:

    $ CLAUDE_CODE_ADDITIONAL_DIRECTORIES_CLAUDE_MD=1 claude --add-dir ../nvme-cli-ai

## Bug Reports

Bugs for the NVM Library project are tracked in our [GitHub Issues Database](https://github.com/linux-nvme/nvme-cli/issues).
