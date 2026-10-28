# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 SUSE LLC
#
# Authors: Daniel Wagner <dwagner@suse.de>
"""The MCP server: JSON-RPC 2.0 over stdio, one message per line."""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import IO, Any

from . import __version__, analysis
from .nvme import IOPOLICIES, MAX_INTERVAL, NvmeError, System

# The protocol versions this server speaks, newest first
PROTOCOL_VERSIONS = ('2025-06-18', '2025-03-26', '2024-11-05')

PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602

INSTRUCTIONS = """\
Watches the I/O of the NVMe subsystems of this host with nvme top. A call
samples the block layer statistics for 'interval' seconds, so it takes
that long. Rates are per second, latencies in milliseconds. The counters
(retries, failovers, errors, resets, reconnects) are totals since boot;
nvme_path_health reports how much they grew since its previous call.
The I/O policy tools measure the load which runs anyway: they start no
I/O themselves."""

_INTERVAL = {
    'type': 'integer',
    'minimum': 1,
    'maximum': MAX_INTERVAL,
    'default': 2,
    'description': 'seconds to sample the I/O statistics over',
}
_SUBSYSTEM = {
    'type': 'string',
    'pattern': '^nvme-subsys[0-9]+$',
    'description': 'only this subsystem, e.g. nvme-subsys0',
}


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


class Server:
    """The tools, and the state between their calls."""

    def __init__(
        self,
        system: System,
        allow_iopolicy: bool = False,
        sleep: Callable[[float], None] = time.sleep,
    ):
        self.system = system
        self.sleep = sleep
        self.counters = analysis.Counters()
        self.tools = {t.name: t for t in self._tools(allow_iopolicy)}

    def _tools(self, allow_iopolicy: bool) -> list[Tool]:
        tools = [
            Tool(
                'nvme_snapshot',
                'The I/O rates and counters of the NVMe subsystems, their '
                'namespaces, paths and controllers, as nvme top -o json '
                'prints them.',
                {
                    'properties': {
                        'interval': _INTERVAL,
                        'subsystem': _SUBSYSTEM,
                    }
                },
                self._snapshot,
            ),
            Tool(
                'nvme_path_health',
                'The multipath paths with their I/O share and latency, the '
                'transport and address of their controller, and flags for '
                'those which need a look: a non-optimized ANA '
                'state, a latency outlier among the sibling paths, an '
                'uneven share under the round-robin or queue-depth policy, '
                'and counters which went up since the previous call. Also '
                'namespaces without an optimized path and controllers which '
                'are not live.',
                {
                    'properties': {
                        'interval': _INTERVAL,
                        'subsystem': _SUBSYSTEM,
                        'latency_factor': {
                            'type': 'number',
                            'minimum': 1,
                            'default': analysis.Limits.latency_factor,
                            'description': 'a path is a latency outlier '
                            'at this many times the median of its siblings',
                        },
                        'imbalance': {
                            'type': 'number',
                            'minimum': 0,
                            'default': analysis.Limits.imbalance,
                            'description': 'a path is imbalanced when its '
                            'share differs from an even share by this '
                            'fraction',
                        },
                    }
                },
                self._path_health,
            ),
        ]
        if allow_iopolicy:
            tools += [
                Tool(
                    'nvme_set_iopolicy',
                    'Sets the I/O policy of a multipath subsystem.',
                    {
                        'properties': {
                            'subsystem': _SUBSYSTEM,
                            'policy': {'enum': list(IOPOLICIES)},
                        },
                        'required': ['subsystem', 'policy'],
                    },
                    self._set_iopolicy,
                    read_only=False,
                ),
                Tool(
                    'nvme_compare_iopolicies',
                    'Measures the I/O of a subsystem under each I/O policy '
                    'in turn and restores the policy it had. The workload '
                    'has to run during the whole call, which takes '
                    '(settle + interval) seconds per policy.',
                    {
                        'properties': {
                            'subsystem': _SUBSYSTEM,
                            'policies': {
                                'type': 'array',
                                'items': {'enum': list(IOPOLICIES)},
                                'minItems': 1,
                                'uniqueItems': True,
                                'default': list(IOPOLICIES),
                            },
                            'interval': {**_INTERVAL, 'default': 10},
                            'settle': {
                                'type': 'integer',
                                'minimum': 0,
                                'maximum': MAX_INTERVAL,
                                'default': 2,
                                'description': 'seconds to wait after a '
                                'policy change before measuring',
                            },
                        },
                        'required': ['subsystem'],
                    },
                    self._compare_iopolicies,
                    read_only=False,
                ),
            ]
        return tools

    # --- tools ---

    def _snapshot(self, args: dict[str, Any]) -> dict[str, Any]:
        snap = self.system.snapshot(_int(args, 'interval', 2))
        sub = args.get('subsystem')
        if sub is not None:
            snap['Subsystems'] = analysis.subsystems(snap, sub)
        return snap

    def _path_health(self, args: dict[str, Any]) -> dict[str, Any]:
        limits = analysis.Limits(
            latency_factor=float(
                args.get('latency_factor', analysis.Limits.latency_factor)
            ),
            imbalance=float(args.get('imbalance', analysis.Limits.imbalance)),
        )
        snap = self.system.snapshot(_int(args, 'interval', 2))
        return analysis.health(
            snap, self.counters, limits, args.get('subsystem')
        )

    def _set_iopolicy(self, args: dict[str, Any]) -> dict[str, Any]:
        sub, policy = _str(args, 'subsystem'), _str(args, 'policy')
        old = self.system.iopolicy(sub)
        self.system.set_iopolicy(sub, policy)
        return {'Subsystem': sub, 'Previous': old, 'IOPolicy': policy}

    def _compare_iopolicies(self, args: dict[str, Any]) -> dict[str, Any]:
        sub = _str(args, 'subsystem')
        policies = args.get('policies', list(IOPOLICIES))
        if not isinstance(policies, list) or not policies:
            raise ToolError('policies must be a list of I/O policies')
        interval = _int(args, 'interval', 10)
        settle = _int(args, 'settle', 2)
        if not 0 <= settle <= MAX_INTERVAL:
            raise ToolError(f'settle must be from 0 to {MAX_INTERVAL}')

        old = self.system.iopolicy(sub)
        results = []
        try:
            for policy in policies:
                self.system.set_iopolicy(sub, str(policy))
                self.sleep(settle)
                snap = self.system.snapshot(interval)
                results.append(analysis.policy_result(snap, sub, policy))
        finally:
            self.system.set_iopolicy(sub, old)
        return {
            'Subsystem': sub,
            'Restored': old,
            **analysis.compare(results),
        }

    # --- protocol ---

    def handle(self, msg: Any) -> dict[str, Any] | None:
        """The response to @msg, None for a notification."""
        if not isinstance(msg, dict) or msg.get('jsonrpc') != '2.0':
            return _error(None, INVALID_REQUEST, 'not a JSON-RPC 2.0 message')
        method, mid = msg.get('method'), msg.get('id')
        if 'id' not in msg:
            return None  # notifications/initialized and the like
        if not isinstance(method, str):
            return _error(mid, INVALID_REQUEST, 'no method')
        params = msg.get('params') or {}
        if not isinstance(params, dict):
            return _error(mid, INVALID_PARAMS, 'params must be an object')

        if method == 'initialize':
            return _result(mid, self._initialize(params))
        if method == 'ping':
            return _result(mid, {})
        if method == 'tools/list':
            return _result(
                mid, {'tools': [t.describe() for t in self.tools.values()]}
            )
        if method == 'tools/call':
            return self._call(mid, params)
        return _error(mid, METHOD_NOT_FOUND, f'unknown method {method}')

    def _initialize(self, params: dict[str, Any]) -> dict[str, Any]:
        asked = params.get('protocolVersion')
        version = asked if asked in PROTOCOL_VERSIONS else PROTOCOL_VERSIONS[0]
        return {
            'protocolVersion': version,
            'capabilities': {'tools': {'listChanged': False}},
            'serverInfo': {'name': 'nvme-mcp', 'version': __version__},
            'instructions': INSTRUCTIONS,
        }

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
        except (NvmeError, ToolError) as e:
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


def _int(args: dict[str, Any], key: str, default: int) -> int:
    value = args.get(key, default)
    if not isinstance(value, int) or isinstance(value, bool):
        raise ToolError(f'{key} must be an integer')
    return value


def _str(args: dict[str, Any], key: str) -> str:
    value = args.get(key)
    if not isinstance(value, str):
        raise ToolError(f'{key} is required')
    return value


def _result(mid: Any, result: dict[str, Any]) -> dict[str, Any]:
    return {'jsonrpc': '2.0', 'id': mid, 'result': result}


def _error(mid: Any, code: int, message: str) -> dict[str, Any]:
    return {
        'jsonrpc': '2.0',
        'id': mid,
        'error': {'code': code, 'message': message},
    }
