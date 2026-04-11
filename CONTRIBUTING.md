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

This project provides macros that help generate the code for you. If
you're interested in how that works, it is very similar to how trace
events are created by Linux kernel's 'ftrace' component.

### Add a command to the existing built-in

The first thing to do is define a new command entry in the command
list. This is declared in nvme-builtin.h. Simply append a new "ENTRY" into
the list. The ENTRY normally takes three arguments: the "name" of the
subcommand (this is what the user will type at the command line to invoke
your command), a short help description of what your command does, and the
name of the function callback that you're going to write. Additionally,
you can declare an alias name of the subcommand with a fourth argument, if
needed.

After the ENTRY is defined, you need to implement the callback. It takes
four arguments: argc, argv, the command structure associated with the
callback, and the plug-in structure that contains that command. The
prototype looks like this:

  ```c
  int f(int argc, char **argv, struct command *command, struct plugin *plugin);
  ```

The argc and argv are adjusted from the command line arguments to start
after the sub-command. So if the command line is "nvme foo --option=bar",
the argc is 1 and argv starts at "--option".

You can then define argument parsing for your sub-command's specific
options then do some command-specific action in your callback.

### Add a new plugin

The nvme-cli provides macros to make defining a new plug-in simpler. You
can certainly do all this by hand if you want, but it should be easier
to get going using the macros. To start, first create a header file
to define your plugin. This is where you will give your plugin a name,
description, and define all the sub-commands your plugin implements.

The macros must appear in a specific order within the header file. The following
is a basic example on how to start this:

File: foo-plugin.h
```c
#undef CMD_INC_FILE
#define CMD_INC_FILE plugins/foo/foo-plugin

#if !defined(FOO) || defined(CMD_HEADER_MULTI_READ)
#define FOO

#include "cmd.h"

PLUGIN(NAME("foo", "Foo plugin"),
	COMMAND_LIST(
		ENTRY("bar", "foo bar", bar)
		ENTRY("baz", "foo baz", baz)
		ENTRY("qux", "foo qux", qux)
	)
);

#endif

#include "define_cmd.h"
```

In order to have the compiler generate the plugin through the xmacro
expansion, you need to include this header in your source file, with
a pre-defining macro directive to create the commands.

To get started from the above example, we just need to define "CREATE_CMD"
and include the header:

File: foo-plugin.c
```c
#include "nvme.h"

#define CREATE_CMD
#include "foo-plugin.h"
```

After that, you just need to implement the functions you defined in each
ENTRY, then append the object file name to the meson.build "sources".

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
$ git add libnvme/src/nvme/accessors.h libnvme/src/nvme/accessors.c
$ git add libnvme/src/nvme/accessors-fabrics.h libnvme/src/nvme/accessors-fabrics.c
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

## Bug Reports

Bugs for the NVM Library project are tracked in our [GitHub Issues Database](https://github.com/linux-nvme/nvme-cli/issues).
