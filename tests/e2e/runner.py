#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme.
# Copyright (c) 2026 SUSE LLC
#
# Authors: Daniel Wagner <dwagner@suse.de>
"""
E2E test runner for nvme-cli.

Runs the hardware-backed tests in this package (including plugin suites)
against a real NVMe device, either as a single test module or, if none is
given, by discovering and running every e2e test. Emits TAP version 13 to
stdout so that 'meson test' can parse individual subtest results when
protocol: 'tap' is set in meson.build. --json-report additionally writes a
structured per-test summary suited for feeding into a results database.

These tests are destructive -- they create/delete namespaces and overwrite
data -- so the target device is never assumed. It must be supplied via
--controller/--ns1 (optionally layered on top of --config), or 'meson test'
passes a fixed --config file written at 'meson setup' time from
-De2e-controller=/-De2e-ns1=.

This module is imported both in-tree (as tests.e2e.runner, via meson) and
from a standalone pip install (as nvme_e2e.e2e.runner) -- see tests/README
and tests/pyproject.toml. Test discovery below is path-based rather than
name-based, driven by this file's own location, so it resolves to
'tests.e2e.<name>' or 'nvme_e2e.e2e.<name>' automatically depending on which
top-level package this module was actually loaded as.
"""

import argparse
import importlib
import io
import json
import os
import sys
import time
import traceback
import unittest

CONFIG_ENV_VAR = 'NVME_E2E_CONFIG'

# Directory this file lives in (tests/e2e in a checkout, or .../nvme_e2e/e2e
# once pip-installed) and the directory that must be on sys.path for dotted
# imports under this package to resolve (the checkout root, or site-packages).
_HERE = os.path.dirname(os.path.abspath(__file__))
_TOP_LEVEL_DIR = os.path.dirname(os.path.dirname(_HERE))


def discover_plugin_names() -> list[str]:
    """Vendor plugin test suites available under e2e/plugins/ (e.g. 'micron',
    'ocp'), regardless of which nvme-cli plugins the target binary was built
    with -- that's checked at test time, not here.
    """
    plugins_dir = os.path.join(_HERE, 'plugins')
    if not os.path.isdir(plugins_dir):
        return []
    return sorted(
        name for name in os.listdir(plugins_dir)
        if os.path.isfile(os.path.join(plugins_dir, name, '__init__.py')))


def _iter_test_cases(suite: unittest.TestSuite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from _iter_test_cases(item)
        else:
            yield item


def _plugin_name_of(test: unittest.TestCase) -> str | None:
    """Vendor plugin name a test belongs to (e.g. 'micron'), or None for a
    core (non-plugin) e2e test, based on its module path
    ('...e2e.plugins.<name>.<module>').
    """
    parts = type(test).__module__.split('.')
    if 'plugins' in parts:
        idx = parts.index('plugins')
        if idx + 1 < len(parts):
            return parts[idx + 1]
    return None


def filter_plugins(suite: unittest.TestSuite,
                   enabled_plugins: set | None) -> unittest.TestSuite:
    """Drop vendor plugin tests not in enabled_plugins.

    enabled_plugins is None (run everything discovered -- the default) or a
    set of plugin names to keep (empty set disables every vendor plugin).
    Core, non-plugin e2e tests are never filtered.
    """
    if enabled_plugins is None:
        return suite
    filtered = unittest.TestSuite()
    for test in _iter_test_cases(suite):
        name = _plugin_name_of(test)
        if name is None or name in enabled_plugins:
            filtered.addTest(test)
    return filtered


class TAPDiagnosticStream(io.TextIOBase):
    """Wrap a stream and prefix every line with '# ' for TAP diagnostics.

    This lets print()/sys.stdout.write() calls from setUp/tearDown/tests
    appear on stdout as TAP-compliant diagnostic lines instead of being
    mixed into stderr.
    """

    def __init__(self, stream: io.TextIOBase) -> None:
        super().__init__()
        self._stream = stream
        self._pending = ''

    def write(self, s: str) -> int:
        self._pending += s
        while '\n' in self._pending:
            line, self._pending = self._pending.split('\n', 1)
            self._stream.write('# {}\n'.format(line))
        self._stream.flush()
        return len(s)

    def flush(self) -> None:
        if self._pending:
            self._stream.write('# {}\n'.format(self._pending))
            self._pending = ''
        self._stream.flush()


class E2ETestResult(unittest.TestResult):
    """Render results as TAP version 13 while also collecting them as
    structured records for an optional JSON report.

    These tests are destructive, so they must only run once per process --
    this keeps TAP output and the JSON summary as two views of a single test
    run rather than requiring the suite to run twice.
    """

    def __init__(self, stdout_stream: io.TextIOBase,
                 stderr_stream: io.TextIOBase) -> None:
        super().__init__()
        self._stdout_stream = stdout_stream
        self._stderr_stream = stderr_stream
        self._test_count = 0
        self._test_start_time = None
        self.records = []

    def _description(self, test: unittest.TestCase) -> str:
        return '{} ({})'.format(test._testMethodName, type(test).__name__)

    def _duration(self):
        if self._test_start_time is None:
            return None
        return round(time.time() - self._test_start_time, 3)

    def _format_traceback(self, err) -> str:
        return ''.join(traceback.format_exception(*err))

    def _output_traceback(self, tb: str) -> None:
        self._stderr_stream.write('  ---\n')
        self._stderr_stream.write('  traceback: |\n')

        for line in tb.splitlines():
            self._stderr_stream.write(f'    {line}\n')

        self._stderr_stream.write('  ...\n')
        self._stderr_stream.flush()

    def _add_record(self, test, outcome, message=None) -> None:
        self.records.append({
            'name': test._testMethodName,
            'class': type(test).__name__,
            'outcome': outcome,
            'duration_s': self._duration(),
            'message': message,
        })

    def startTest(self, test: unittest.TestCase) -> None:
        super().startTest(test)
        self._test_start_time = time.time()

    def addSuccess(self, test: unittest.TestCase) -> None:
        super().addSuccess(test)
        self._test_count += 1
        self._stdout_stream.write('ok {} - {}\n'.format(
            self._test_count, self._description(test)))
        self._stdout_stream.flush()
        self._add_record(test, 'pass')

    def addError(self, test: unittest.TestCase, err: object) -> None:
        super().addError(test, err)
        self._test_count += 1
        self._stdout_stream.write('not ok {} - {}\n'.format(
            self._test_count, self._description(test)))
        self._stdout_stream.flush()
        tb = self._format_traceback(err)
        self._output_traceback(tb)
        self._add_record(test, 'error', tb)

    def addFailure(self, test: unittest.TestCase, err: object) -> None:
        super().addFailure(test, err)
        self._test_count += 1
        self._stdout_stream.write('not ok {} - {}\n'.format(
            self._test_count, self._description(test)))
        self._stdout_stream.flush()
        tb = self._format_traceback(err)
        self._output_traceback(tb)
        self._add_record(test, 'fail', tb)

    def addSkip(self, test: unittest.TestCase, reason: str) -> None:
        super().addSkip(test, reason)
        self._test_count += 1
        self._stdout_stream.write('ok {} - {} # SKIP {}\n'.format(
            self._test_count, self._description(test), reason))
        self._stdout_stream.flush()
        self._add_record(test, 'skip', reason)

    def addExpectedFailure(self, test: unittest.TestCase, err: object) -> None:
        super().addExpectedFailure(test, err)
        self._test_count += 1
        self._stdout_stream.write('ok {} - {} # TODO expected failure\n'.format(
            self._test_count, self._description(test)))
        self._stdout_stream.flush()
        self._add_record(test, 'expected_failure', self._format_traceback(err))

    def addUnexpectedSuccess(self, test: unittest.TestCase) -> None:
        super().addUnexpectedSuccess(test)
        self._test_count += 1
        self._stdout_stream.write('not ok {} - {} # TODO unexpected success\n'.format(
            self._test_count, self._description(test)))
        self._stdout_stream.flush()
        self._add_record(test, 'unexpected_success')


def build_config(args: argparse.Namespace) -> dict:
    """Merge --config file contents with explicit CLI overrides.

    CLI flags win over the config file so a fixed config (e.g. the one
    'meson test' passes) can still be tweaked ad hoc for a manual run.
    Refuses to guess a controller/namespace: these tests are destructive.
    """
    config = {}
    if args.config:
        with open(args.config) as f:
            config = json.load(f)

    overrides = {
        'controller': args.controller,
        'ns1': args.ns1,
        'log_dir': args.log_dir,
        'log_level': args.log_level,
        'nvme_bin': args.nvme_bin,
    }
    for key, value in overrides.items():
        if value is not None:
            config[key] = value
    if args.validate_pci_device is not None:
        config['do_validate_pci_device'] = args.validate_pci_device
    if args.collect_device_data is not None:
        config['collect_device_data'] = args.collect_device_data

    missing = [key for key in ('controller', 'ns1') if not config.get(key)]
    if missing:
        raise SystemExit(
            "error: missing required e2e configuration: {}. These tests "
            "read and write real data to an NVMe device, so nothing is "
            "assumed. Pass --controller/--ns1 (optionally with --config), "
            "or configure with -De2e-controller=... -De2e-ns1=...".format(
                ', '.join(missing)))

    return config


def load_tests(test_module_name: str | None,
               enabled_plugins: set | None = None) -> unittest.TestSuite:
    """Load either a single named test module (always run as given,
    regardless of enabled_plugins -- an explicit module name is an explicit
    request) or discover every e2e test, filtered by enabled_plugins.
    """
    loader = unittest.TestLoader()
    if test_module_name:
        if '.' not in test_module_name:
            test_module_name = f'{__package__}.{test_module_name}'
        module = importlib.import_module(test_module_name)
        return loader.loadTestsFromModule(module)

    suite = loader.discover(start_dir=_HERE, pattern='*_test.py',
                            top_level_dir=_TOP_LEVEL_DIR)
    return filter_plugins(suite, enabled_plugins)


def run_tests(test_module_name: str | None, json_report: str | None,
             enabled_plugins: set | None = None) -> bool:
    suite = load_tests(test_module_name, enabled_plugins)

    real_stdout = sys.stdout
    real_stderr = sys.stderr
    # TAP version header and plan must appear before any test output.
    real_stdout.write('TAP version 13\n')
    real_stdout.write('1..{}\n'.format(suite.countTestCases()))
    real_stdout.flush()

    # Redirect sys.stdout to a TAP diagnostic stream so that
    # print()/sys.stdout.write() calls from setUp/tearDown/tests appear on
    # stdout as '# ...' diagnostic lines rather than being sent to stderr.
    # Error tracebacks (genuine failures) still go to stderr via stderr_stream.
    sys.stdout = TAPDiagnosticStream(real_stdout)  # type: ignore[assignment]
    started_at = time.time()
    try:
        result = E2ETestResult(real_stdout, real_stderr)
        suite.run(result)
    finally:
        sys.stdout = real_stdout
    finished_at = time.time()

    if json_report:
        config = json.loads(os.environ.get(CONFIG_ENV_VAR, '{}'))
        report = {
            'controller': config.get('controller'),
            'ns1': config.get('ns1'),
            'nvme_bin': config.get('nvme_bin', 'nvme'),
            'started_at': started_at,
            'finished_at': finished_at,
            'tests': result.records,
        }
        with open(json_report, 'w') as f:
            json.dump(report, f, indent=2)

    return result.wasSuccessful()


def main() -> None:
    parser = argparse.ArgumentParser(
        prog='nvme-cli-e2e',
        description='Run nvme-cli e2e tests against a real NVMe device')
    parser.add_argument('test_module', nargs='?', default=None,
                        help='Test module to run, either bare '
                             '(e.g. nvme_id_ctrl_test) or fully dotted '
                             '(e.g. tests.e2e.nvme_id_ctrl_test). If '
                             'omitted, discover and run every e2e test.')
    parser.add_argument('--config',
                        help='Path to a JSON e2e config file')
    parser.add_argument('--controller',
                        help='Controller device, e.g. /dev/nvme0')
    parser.add_argument('--ns1',
                        help='Namespace device, e.g. /dev/nvme0n1')
    parser.add_argument('--log-dir',
                        help='Directory for test logs (default: nvmetests)')
    parser.add_argument('--log-level',
                        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                        help='Logging verbosity (default: WARNING)')
    parser.add_argument('--nvme-bin',
                        help='nvme binary to exercise (default: nvme)')
    parser.add_argument('--json-report',
                        help='Additionally write a structured per-test JSON '
                             'summary to this path (e.g. for ingestion into '
                             'a results database). TAP still goes to stdout.')
    plugin_names = discover_plugin_names()
    parser.add_argument('--plugins', default='all',
                        help="Vendor plugin test suites to include when "
                             "discovering every e2e test (ignored if a "
                             "specific test module is given). 'all' "
                             "(default) runs every one found; 'none' skips "
                             "all of them; or a comma-separated subset, "
                             "e.g. --plugins=micron. Available: {}. Tests "
                             "for a plugin the nvme binary wasn't built "
                             "with are skipped automatically at run time "
                             "regardless of this flag.".format(
                                 ', '.join(plugin_names) or '(none found)'))
    validate_group = parser.add_mutually_exclusive_group()
    validate_group.add_argument(
        '--validate-pci-device', dest='validate_pci_device',
        action='store_true', default=None,
        help='Require the target device to be a PCI NVMe device (default)')
    validate_group.add_argument(
        '--no-validate-pci-device', dest='validate_pci_device',
        action='store_false',
        help='Skip the PCI-subsystem check, e.g. for emulated devices')
    collect_group = parser.add_mutually_exclusive_group()
    collect_group.add_argument(
        '--collect-device-data', dest='collect_device_data',
        action='store_true', default=None,
        help='Opt in to recording every nvme command a test runs together '
             'with its JSON output, plus id-ctrl-derived device metadata, '
             'as device_data.json in each test\'s log directory (off by '
             'default -- intended for feeding a device-feature database)')
    collect_group.add_argument(
        '--no-collect-device-data', dest='collect_device_data',
        action='store_false',
        help='Do not record per-test device data (default)')
    args = parser.parse_args()

    plugins_arg = args.plugins.strip().lower()
    if plugins_arg == 'all':
        enabled_plugins = None
    elif plugins_arg == 'none':
        enabled_plugins = set()
    else:
        enabled_plugins = {p.strip() for p in args.plugins.split(',') if p.strip()}
        unknown = enabled_plugins - set(plugin_names)
        if unknown:
            raise SystemExit(
                "error: unknown --plugins entry: {}. Available: {}".format(
                    ', '.join(sorted(unknown)), ', '.join(plugin_names) or '(none found)'))

    os.environ[CONFIG_ENV_VAR] = json.dumps(build_config(args))

    run_tests(args.test_module, args.json_report, enabled_plugins)
    sys.exit(0)


if __name__ == '__main__':
    main()
