# nvme-cli
![Coverity Scan Build Status](https://scan.coverity.com/projects/24883/badge.svg)
![MesonBuild](https://github.com/linux-nvme/nvme-cli/actions/workflows/build.yml/badge.svg)
![GitHub](https://img.shields.io/github/license/linux-nvme/nvme-cli)

NVM-Express user space tooling for Linux.

## Build from source

nvme-cli uses meson as build system.

### nvme-cli dependencies:

 | Library | Dependency | Notes |
 |---------|------------|-------|
 | libnvme, libnvme-mi| yes | be either installed or included into the build via meson fallback feature |
 | json-c | optional | recommended, without all plugins are disabled and json-c output format is disabled |
 | libhugetlbfs | optional | adds support for hugetlbfs |


### Configuring

In case libnvme is not installed on the system, it possible to use meson's
fallback feature to resolve the dependency.

	$ meson setup --force-fallback-for=libnvme .build

If the libnvme is already installed on the system meson is using pkg-config to
find the dependency. In this case a plain setup call is enough:

	$ meson setup .build

With meson's --wrap-mode argument it's possible to control if the additional
dependencies should also resolved or not. The options are

	--wrap-mode {default,nofallback,nodownload,forcefallback,nopromote}

Note for nvme-cli the 'default' is set to nofallback.

### Building

	$ meson compile -C .build

### Installing

	# meson install -C .build

### Makefile wrapper

There is a Makefile wrapper for meson for backwards compatibility

	$ make
	# make install

Note in this case libnvme needs to be installed by hand first.

RPM build support via Makefile that uses meson

	$ make rpm

Static binary(no dependency) build support via Makefile that uses meson   
Caution : it will not support libhugetlbfs

	$ make static

If not sure how to use, find the top-level documentation with:

	$ man nvme

Or find a short summary with:

	$ nvme help

## Distro Support

Many popular distributions (Alpine, Arch, Debian, Fedora, FreeBSD, Gentoo,
Ubuntu, Nix(OS), openSUSE, ...) and the usual package name is nvme-cli.

#### OpenEmbedded/Yocto

An [nvme-cli recipe](https://layers.openembedded.org/layerindex/recipe/88631/)
is available as part of the `meta-openembeded` layer collection.

#### Buildroot

`nvme-cli` is available as [buildroot](https://buildroot.org) package. The
package is named `nvme`.

## Developers

You may wish to add a new command or possibly an entirely new plug-in
for some special extension outside the spec.

This project provides macros that help generate the code for you. If
you're interested in how that works, it is very similar to how trace
events are created by Linux kernel's 'ftrace' component.

### Add command to existing built-in

The first thing to do is define a new command entry in the command
list. This is declared in nvme-builtin.h. Simply append a new "ENTRY" into
the list. The ENTRY normally takes three arguments: the "name" of the 
subcommand (this is what the user will type at the command line to invoke
your command), a short help description of what your command does, and the
name of the function callback that you're going to write. Additionally,
You can declare an alias name of subcommand with fourth argument, if needed.

After the ENTRY is defined, you need to implement the callback. It takes
four arguments: argc, argv, the command structure associated with the
callback, and the plug-in structure that contains that command. The
prototype looks like this:

  ```c
  int f(int argc, char **argv, struct command *cmd, struct plugin *plugin);
  ```

The argc and argv are adjusted from the command line arguments to start
after the sub-command. So if the command line is "nvme foo --option=bar",
the argc is 1 and argv starts at "--option".

You can then define argument parsing for your sub-command's specific
options then do some command specific action in your callback.

### Add a new plugin

The nvme-cli provides macros to make define a new plug-in simpler. You
can certainly do all this by hand if you want, but it should be easier
to get going using the macros. To start, first create a header file
to define your plugin. This is where you will give your plugin a name,
description, and define all the sub-commands your plugin implements.

There is a very important order on how to define the plugin. The following
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
		ENTRY("qux", "foo quz", qux)
	)
);

#endif

#include "define_cmd.h"
```

In order to have the compiler generate the plugin through the xmacro
expansion, you need to include this header in your source file, with
pre-defining macro directive to create the commands.

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

## meson tips

In case meson doesn't find libnvme header files (via pkg-config) it 
will fallback using subprojects.  meson checks out libnvme in 
subprojects directory as git tree once to the commit level specified 
in the libnvme.wrap file revision parm.  After this initial checkout,
the libnvme code level will not change unless explicitly told.  That 
means if the current branch is updated via git, the subprojects/libnvme
branch will not updated accordingly.  To update it, either use the 
normal git operations or the command: 

	$ meson subprojects update

## Dependency

libnvme depends on the /sys/class/nvme-subsystem interface which was
introduced in the Linux kernel release v4.15. Hence nvme-cli 2.x is
only working on kernels >= v4.15. For older kernels nvme-cli 1.x is
recommended to be used.

## How to contribute

There are two ways to send code changes to the project. The first one
is by sending the changes to linux-nvme@lists.infradead.org. The
second one is by posting a pull request on github. In both cases
please follow the Linux contributions guidelines as documented in

https://docs.kernel.org/process/submitting-patches.html#

That means the changes should be a clean series (no merges should be
present in a github PR for example) and every commit should build.

See also https://opensource.com/article/19/7/create-pull-request-github

### How to cleanup your series before creating PR

This example here assumes, the changes are in a branch called
fix-something, which branched away from master in the past. In the
meantime the upstream project has changed, hence the fix-something
branch is not based on the current HEAD. Before posting the PR, the
branch should be rebased on the current HEAD and retest everything.

For example rebasing can be done by following steps

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

# Push your changes to github and trigger a PR
$ git push -u origin fix-something
```

## Persistent, volatile configuration

Persistent configurations can be stored in two different locations: either in
the file `/etc/nvme/discovery.conf` using the old style, or in the file
`/etc/nvme/config.json` using the new style.

On the other hand, volatile configurations, such as those obtained from
third-party tools like `nvme-stats` or `blktests'` can be stored in the
`/run/nvme` directory. When using the `nvme-cli` tool, all these configurations
are combined into a single configuration that is used as input.

The volatile configuration is particularly useful for coordinating access to the
global resources among various components. For example, when executing
`blktests` for the FC transport, the `nvme-cli` udev rules can be triggered. To
prevent interference with a test, `blktests` can create a JSON configuration
file in `/run/nvme` to inform `nvme-cli` that it should not perform any actions
triggered from the udev context. This behavior can be controlled using the
`--context` argument.

For example a `blktests` volatile configuration could look like:

```json
[
  {
    "hostnqn": "nqn.2014-08.org.nvmexpress:uuid:242d4a24-2484-4a80-8234-d0169409c5e8",
    "hostid": "242d4a24-2484-4a80-8234-d0169409c5e8",
    "subsystems": [
      {
	"application": "blktests",
        "nqn": "blktests-subsystem-1",
        "ports": [
          {
            "transport": "fc",
	    "traddr": "nn-0x10001100aa000001:pn-0x20001100aa000001",
	    "host_traddr": "nn-0x10001100aa000002:pn-0x20001100aa000002"
          }
        ]
      }
    ]
  }
]
```

Note when updating the volatile configuration during runtime, it should done in
a an atomic way. For example create a temporary file without the `.json` file
extension in `/run/nvme` and write the contents to this file. When finished use
`rename` to add the `'.json'` file name extension. This ensures nvme-cli only
sees the complete file.
