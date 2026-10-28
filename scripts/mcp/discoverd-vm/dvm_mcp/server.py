# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
#
# Authors: Martin Belanger <martin.belanger@dell.com>
"""The MCP server: JSON-RPC 2.0 over stdio, one message per line.

Built like nvme-mcp in ../nvme_mcp: no MCP library, a Tool
per function, and the tools that change the VM only with
--allow-changes."""

from __future__ import annotations

import json
import shlex
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import IO, Any

from . import __version__
from . import create as cr
from . import scenario as sc
from .vm import VM, VM_SOURCE_INFO, VM_SRC, VMError, describe

# The scenario files next to the package
SCENARIOS = Path(__file__).resolve().parent.parent / 'scenarios'

PROTOCOL_VERSIONS = ('2025-06-18', '2025-03-26', '2024-11-05')

PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602

INSTRUCTIONS = """\
Tests, in a VM, what a system shutdown does to the nvme-discoverd
connection units and the file systems mounted on them: when systemd
stops a unit, whether its ExecStop= disconnects a controller that is
still mounted. The VM is a Fedora VM with a loopback nvme-tcp target, a
namespace with XFS, and nvme-discoverd connecting it. vm_create builds
the VM from a Fedora Cloud image once (a download and package installs:
many minutes); vm_start and vm_stop start and power it off. vm_status
shows its state.
vm_sync_build copies the local nvme-cli tree to the VM and builds and
installs it there; it takes minutes. list_scenarios shows the test
scenarios; run_scenario sets one up, runs it (a reboot or a stop of the
connection unit), and compares what the VM logged with what the scenario
expects. A reboot scenario takes one to two minutes. shutdown_log shows
the shutdown lines of the previous boot."""

# What vm_status prints in the VM, one key=value per line
_STATUS_SCRIPT = f"""\
echo kernel=$(uname -r)
echo systemd=$(systemctl --version | head -1 | cut -d' ' -f2)
echo nvme=$(nvme version 2>/dev/null | head -1)
echo discoverd=$(systemctl is-active nvme-discoverd)
echo source=$(cat {VM_SOURCE_INFO} 2>/dev/null)
for c in /sys/class/nvme/nvme*; do
    [ -e "$c/subsysnqn" ] || continue
    echo ctrl=${{c##*/}} $(cat $c/transport) $(cat $c/state) \
$(cat $c/subsysnqn)
done
systemctl list-units 'nvme-discoverd-*' --all --plain --no-legend \
    | while read -r u load active sub _; do echo unit=$u $active $sub; done
findmnt -rn -o TARGET,SOURCE,FSTYPE | while read -r t s f; do
    case $s in /dev/nvme*) echo mount=$t $s $f ;; esac
done
"""


class ToolError(Exception):
    """A tool call failed: the result reports it to the agent."""


@dataclass
class Tool:
    name: str
    description: str
    schema: dict[str, Any]
    run: Callable[[dict[str, Any]], dict[str, Any]]
    read_only: bool = True

    def describe(self) -> dict[str, Any]:
        return {
            'name': self.name,
            'description': self.description,
            'inputSchema': {
                'type': 'object',
                'additionalProperties': False,
                **self.schema,
            },
            'annotations': {
                'readOnlyHint': self.read_only,
                'destructiveHint': False,
                'idempotentHint': self.read_only,
                'openWorldHint': False,
            },
        }


def parse_status(text: str) -> dict[str, Any]:
    """The output of _STATUS_SCRIPT as a dict. Repeated keys become
    lists."""
    status: dict[str, Any] = {
        'controllers': [],
        'units': [],
        'mounts': [],
    }
    lists = {'ctrl': 'controllers', 'unit': 'units', 'mount': 'mounts'}
    for line in text.splitlines():
        key, sep, value = line.partition('=')
        if not sep:
            continue
        if key in lists:
            status[lists[key]].append(value)
        else:
            status[key] = value
    return status


class Server:
    """The tools, and what they need between calls."""

    def __init__(
        self,
        vm: VM,
        source: Path,
        allow_changes: bool = False,
        scenarios: Path = SCENARIOS,
    ):
        self.vm = vm
        self.source = source
        self.scenarios = scenarios
        self.tools = {t.name: t for t in self._tools(allow_changes)}

    def _tools(self, allow_changes: bool) -> list[Tool]:
        tools = [
            Tool(
                'vm_status',
                'The state of the test VM: whether it runs and answers '
                'ssh, its kernel and systemd versions, the nvme-cli '
                'version and the local source it was built from, whether '
                'nvme-discoverd is active, the NVMe controllers, the '
                'nvme-discoverd connection units, and the mounts of NVMe '
                'devices.',
                {'properties': {}},
                self._status,
            ),
            Tool(
                'list_scenarios',
                'The test scenarios: how the file system is mounted, the '
                'action (reboot, or stop-unit at runtime), which build '
                'the VM must run (stop_unit: true for the skip-if-mounted '
                'build, false for a build without it, null for any), and '
                'the expected result.',
                {'properties': {}},
                self._list_scenarios,
            ),
            Tool(
                'shutdown_log',
                'The lines of the previous boot of the VM that tell the '
                'shutdown order: unmount, controller removal, skipped '
                'disconnect, XFS messages, and their analysis.',
                {'properties': {}},
                self._shutdown_log,
            ),
        ]
        if allow_changes:
            tools += [
                Tool(
                    'vm_create',
                    'Builds the test VM from scratch: downloads and checks '
                    'the Fedora Cloud image (once), creates the disk, an '
                    'ssh key and a cloud-init seed, boots it, installs the '
                    'build dependencies, copies and builds nvme-cli, sets '
                    'up the loopback target and lets nvme-discoverd '
                    'connect it. Fails if the VM exists. Takes many '
                    'minutes.',
                    {
                        'properties': {
                            'disk_gb': {
                                'type': 'integer',
                                'minimum': 10,
                                'default': 20,
                                'description': 'size of the VM disk',
                            }
                        }
                    },
                    self._create,
                    read_only=False,
                ),
                Tool(
                    'vm_stop',
                    'Powers the test VM off and waits for qemu to end.',
                    {'properties': {}},
                    self._stop,
                    read_only=False,
                ),
                Tool(
                    'vm_start',
                    'Starts the test VM if it does not run, and waits '
                    'until it answers ssh.',
                    {'properties': {}},
                    self._start,
                    read_only=False,
                ),
                Tool(
                    'vm_sync_build',
                    'Copies the local nvme-cli source tree to the VM, '
                    'builds and installs it there, unmounts /mnt/t and '
                    'recreates the connection units, so that they use the '
                    'new build. Takes minutes. Returns the git '
                    'describe of the source and the version installed.',
                    {'properties': {}},
                    self._sync_build,
                    read_only=False,
                ),
                Tool(
                    'run_scenario',
                    'Runs one scenario: resets the VM (unmounts, recreates '
                    'the connection units with the installed build), '
                    'creates a new XFS, mounts it as the scenario says, '
                    'writes dirty data, then reboots or stops the unit. '
                    'Returns what happened, what was expected, and pass.',
                    {
                        'properties': {
                            'name': {
                                'type': 'string',
                                'description': 'the scenario, as '
                                'list_scenarios shows it',
                            }
                        },
                        'required': ['name'],
                    },
                    self._run_scenario,
                    read_only=False,
                ),
            ]
        return tools

    # --- tools ---

    def _status(self, args: dict[str, Any]) -> dict[str, Any]:
        if not self.vm.running():
            return {'running': False}
        if not self.vm.reachable():
            return {'running': True, 'ssh': False}
        r = self.vm.run(_STATUS_SCRIPT)
        return {'running': True, 'ssh': True, **parse_status(r.out)}

    def _scenario(self, name: Any) -> sc.Scenario:
        if not isinstance(name, str):
            raise ToolError('name is required')
        try:
            scenarios = sc.load_all(self.scenarios)
        except sc.ScenarioError as e:
            raise ToolError(str(e)) from e
        if name not in scenarios:
            raise ToolError(f'no scenario {name}: one of {sorted(scenarios)}')
        return scenarios[name]

    def _list_scenarios(self, args: dict[str, Any]) -> dict[str, Any]:
        try:
            scenarios = sc.load_all(self.scenarios)
        except sc.ScenarioError as e:
            raise ToolError(str(e)) from e
        return {'scenarios': [s.describe() for s in scenarios.values()]}

    def _shutdown_log(self, args: dict[str, Any]) -> dict[str, Any]:
        lines = self.vm.run(sc.SHUTDOWN_LOG_SCRIPT).out.splitlines()
        return {'analysis': sc.parse_shutdown(lines), 'lines': lines}

    def _run_scenario(self, args: dict[str, Any]) -> dict[str, Any]:
        s = self._scenario(args.get('name'))
        if not self.vm.reachable():
            raise ToolError('the VM does not answer ssh: use vm_start')

        r = self.vm.run(sc.setup_script(s), timeout=600)
        setup = sc.parse_kv(r.out)
        if r.rc or 'error' in setup:
            tail = '\n'.join((r.out + r.err).splitlines()[-20:])
            raise ToolError(f'setup failed:\n{tail}')
        stop_unit = setup.get('stop_unit') == 'true'
        if s.stop_unit is not None and stop_unit != s.stop_unit:
            raise ToolError(
                f'{s.name} needs a build '
                f'{"with" if s.stop_unit else "without"} '
                f'the skip-if-mounted ExecStop=, but the VM runs one '
                f'{"with" if stop_unit else "without"} it: '
                'check out the right branch and use vm_sync_build'
            )

        observed: dict[str, Any]
        if s.action == 'reboot':
            self.vm.run(sc.REBOOT_SCRIPT)
            took = self.vm.wait_reboot(setup.get('boot_id', ''))
            lines = self.vm.run(sc.SHUTDOWN_LOG_SCRIPT).out.splitlines()
            observed = sc.parse_shutdown(lines)
            check = sc.parse_kv(self.vm.run(sc.CHECK_SCRIPT, 120).out)
            for key in ('mounted', 'log_recovery', 'data_intact'):
                observed[key] = check.get(key) == 'true'
            observed['reboot_s'] = round(took, 1)
        else:
            out = self.vm.run(sc.stop_unit_script(s), timeout=300).out
            lines = out.split('---')[0].strip().splitlines()
            observed = sc.parse_shutdown(lines)
            if observed['disconnect'] in ('after-unmount', 'while-mounted'):
                observed['disconnect'] = 'done'
            if 'error=' in out:
                observed['error'] = out.split('error=', 1)[1].strip()

        mismatches = sc.evaluate(s.expect, observed)
        return {
            'scenario': s.name,
            'source': self.vm.run(
                f'cat {VM_SOURCE_INFO} 2>/dev/null'
            ).out.strip(),
            'stop_unit': stop_unit,
            'dirty_kb': setup.get('dirty_kb'),
            'expected': s.expect,
            'observed': observed,
            'pass': not mismatches,
            'mismatches': mismatches,
            'log': lines,
        }

    def _create(self, args: dict[str, Any]) -> dict[str, Any]:
        disk_gb = args.get('disk_gb', 20)
        if not isinstance(disk_gb, int) or disk_gb < 10:
            raise ToolError('disk_gb must be an integer, 10 or more')
        if self.vm.running():
            raise ToolError('a VM runs already: use vm_stop first')
        out = cr.create(self.vm, self.source, disk_gb=disk_gb)
        self.vm.run(
            f'echo {shlex.quote(describe(self.source))} > {VM_SOURCE_INFO}'
        )
        return out

    def _stop(self, args: dict[str, Any]) -> dict[str, Any]:
        if not self.vm.running():
            return {'stopped': False}
        return {'stopped': True, 'took': round(self.vm.stop(), 1)}

    def _start(self, args: dict[str, Any]) -> dict[str, Any]:
        if self.vm.running():
            return {'started': False, 'up_after': round(self.vm.wait_up(), 1)}
        return {'started': True, 'up_after': round(self.vm.start(), 1)}

    def _sync_build(self, args: dict[str, Any]) -> dict[str, Any]:
        if not self.vm.reachable():
            raise ToolError('the VM does not answer ssh: use vm_start')
        source = describe(self.source)
        self.vm.sync(self.source)
        r = self.vm.run(
            f'set -e\n'
            f'echo {shlex.quote(source)} > {VM_SOURCE_INFO}\n'
            f'cd {VM_SRC}\n'
            f'meson compile -C .build >/dev/null\n'
            f'meson install --quiet -C .build --skip-subprojects'
            f' >/dev/null\n'
            f'nvme version | head -1\n',
            timeout=900,
        )
        if r.rc:
            tail = '\n'.join((r.out + r.err).splitlines()[-30:])
            raise ToolError(f'the build failed:\n{tail}')
        installed = r.out.strip()
        # transient units keep the ExecStop= of the build that made them
        r = self.vm.run(sc.RESET_SCRIPT, timeout=300)
        if r.rc:
            tail = '\n'.join((r.out + r.err).splitlines()[-20:])
            raise ToolError(f'installed, but the reset failed:\n{tail}')
        return {'source': source, 'installed': installed}

    # --- protocol ---

    def handle(self, msg: Any) -> dict[str, Any] | None:
        """The response to @msg, None for a notification."""
        if not isinstance(msg, dict) or msg.get('jsonrpc') != '2.0':
            return _error(None, INVALID_REQUEST, 'not a JSON-RPC 2.0 message')
        if 'id' not in msg:
            return None
        method, mid = msg.get('method'), msg.get('id')
        if not isinstance(method, str):
            return _error(mid, INVALID_REQUEST, 'no method')
        params = msg.get('params') or {}
        if not isinstance(params, dict):
            return _error(mid, INVALID_PARAMS, 'params must be an object')

        if method == 'initialize':
            asked = params.get('protocolVersion')
            version = (
                asked if asked in PROTOCOL_VERSIONS else PROTOCOL_VERSIONS[0]
            )
            return _result(
                mid,
                {
                    'protocolVersion': version,
                    'capabilities': {'tools': {'listChanged': False}},
                    'serverInfo': {
                        'name': 'discoverd-vm',
                        'version': __version__,
                    },
                    'instructions': INSTRUCTIONS,
                },
            )
        if method == 'ping':
            return _result(mid, {})
        if method == 'tools/list':
            return _result(
                mid, {'tools': [t.describe() for t in self.tools.values()]}
            )
        if method == 'tools/call':
            return self._call(mid, params)
        return _error(mid, METHOD_NOT_FOUND, f'unknown method {method}')

    def _call(self, mid: Any, params: dict[str, Any]) -> dict[str, Any]:
        tool = self.tools.get(params.get('name', ''))
        if tool is None:
            return _error(
                mid, INVALID_PARAMS, f'unknown tool {params.get("name")}'
            )
        args = params.get('arguments') or {}
        if not isinstance(args, dict):
            return _error(mid, INVALID_PARAMS, 'arguments must be an object')
        unknown = set(args) - set(tool.schema.get('properties', {}))
        if unknown:
            return _error(
                mid, INVALID_PARAMS, f'unknown arguments: {sorted(unknown)}'
            )
        try:
            out = tool.run(args)
        except (VMError, ToolError) as e:
            return _result(
                mid,
                {
                    'content': [{'type': 'text', 'text': str(e)}],
                    'isError': True,
                },
            )
        return _result(
            mid,
            {
                'content': [{'type': 'text', 'text': json.dumps(out)}],
                'structuredContent': out,
                'isError': False,
            },
        )

    def serve(self, rd: IO[str], wr: IO[str]) -> None:
        """Answers the messages from @rd on @wr until @rd ends."""
        for line in rd:
            if not line.strip():
                continue
            resp: dict[str, Any] | None
            try:
                msg = json.loads(line)
            except json.JSONDecodeError as e:
                resp = _error(None, PARSE_ERROR, str(e))
            else:
                resp = self.handle(msg)
            if resp is not None:
                wr.write(json.dumps(resp) + '\n')
                wr.flush()


def _result(mid: Any, result: dict[str, Any]) -> dict[str, Any]:
    return {'jsonrpc': '2.0', 'id': mid, 'result': result}


def _error(mid: Any, code: int, message: str) -> dict[str, Any]:
    return {
        'jsonrpc': '2.0',
        'id': mid,
        'error': {'code': code, 'message': message},
    }
