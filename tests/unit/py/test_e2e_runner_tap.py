#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
"""Test the e2e runner's TAP/JSON result collapsing rules.

E2ETestResult turns everything unittest reports about one test method into a
single TAP line -- the plan the runner writes up front counts test methods,
not subtests -- plus one record for the --json-report summary.  The collapsing
rules are what this covers: which outcome names the line, that no message is
dropped along the way, and that the recorded duration spans the whole method.

Nothing here touches an NVMe device or the nvme binary; the result object is
driven directly with synthetic test cases writing into StringIO.  The cases
are defined inside the test methods so that this file's own test run does not
collect the deliberately failing ones.

Usage: test_e2e_runner_tap.py <path-to-tests/e2e/runner.py>
"""
import importlib.util
import io
import sys
import time
import unittest

# Long enough to exceed the clock granularity on every supported platform.
SLEEP_S = 0.2


def load_runner(path):
    """Import runner.py by path, so no package layout has to be set up."""
    spec = importlib.util.spec_from_file_location('e2e_runner', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TapResultTest(unittest.TestCase):
    def drive(self, case_class):
        """Run @case_class through E2ETestResult; return result and streams."""
        stdout, stderr = io.StringIO(), io.StringIO()
        result = runner.E2ETestResult(stdout, stderr)
        unittest.TestLoader().loadTestsFromTestCase(case_class).run(result)
        return result, stdout.getvalue(), stderr.getvalue()

    def drive_one(self, case_class):
        """As drive(), for a case that must produce exactly one TAP line."""
        result, out, err = self.drive(case_class)
        lines = out.splitlines()
        self.assertEqual(len(lines), 1, out)
        self.assertEqual(len(result.records), 1, result.records)
        return result, result.records[0], lines[0], err

    # ------------------------------------------------------------------
    # Plain, single-outcome tests: the TAP line is the whole contract with
    # 'meson test', so it is asserted verbatim.
    # ------------------------------------------------------------------

    def test_pass_line(self):
        class Case(unittest.TestCase):
            def test_x(self):
                pass

        result, record, line, _ = self.drive_one(Case)
        self.assertEqual(line, 'ok 1 - test_x (Case)')
        self.assertEqual(record['outcome'], 'pass')
        self.assertIsNone(record['message'])
        self.assertTrue(result.wasSuccessful())

    def test_skip_line_carries_the_reason(self):
        class Case(unittest.TestCase):
            def test_x(self):
                self.skipTest('no device')

        result, record, line, _ = self.drive_one(Case)
        self.assertEqual(line, 'ok 1 - test_x (Case) # SKIP no device')
        self.assertEqual(record['outcome'], 'skip')
        self.assertEqual(record['message'], 'no device')
        self.assertTrue(result.wasSuccessful())

    def test_failure_line(self):
        class Case(unittest.TestCase):
            def test_x(self):
                self.fail('nope')

        result, record, line, _ = self.drive_one(Case)
        self.assertEqual(line, 'not ok 1 - test_x (Case)')
        self.assertEqual(record['outcome'], 'fail')
        self.assertIn('AssertionError: nope', record['message'])
        self.assertFalse(result.wasSuccessful())

    def test_error_line(self):
        class Case(unittest.TestCase):
            def test_x(self):
                raise RuntimeError('boom')

        _, record, line, err = self.drive_one(Case)
        self.assertEqual(line, 'not ok 1 - test_x (Case)')
        self.assertEqual(record['outcome'], 'error')
        self.assertIn('RuntimeError: boom', record['message'])
        self.assertIn('traceback: |', err)

    def test_expected_failure_line(self):
        class Case(unittest.TestCase):
            @unittest.expectedFailure
            def test_x(self):
                self.fail('as designed')

        _, record, line, _ = self.drive_one(Case)
        # The TAP spec dictates that an expected failure is reported as
        # 'not ok ... # TODO'.  The TODO indicates that the failure is expected,
        # so the test harness knows not to treat it as a real failure.
        self.assertEqual(line,
                         'not ok 1 - test_x (Case) # TODO expected failure')
        self.assertEqual(record['outcome'], 'expected_failure')

    def test_unexpected_success_line(self):
        class Case(unittest.TestCase):
            @unittest.expectedFailure
            def test_x(self):
                pass

        result, record, line, _ = self.drive_one(Case)
        # 'ok' on a '# TODO' test is the unexpected outcome -- the test was
        # meant to fail and passed -- which a harness reports as a failure.
        self.assertEqual(line,
                         'ok 1 - test_x (Case) # TODO unexpected success')
        self.assertEqual(record['outcome'], 'unexpected_success')
        self.assertFalse(result.wasSuccessful())

    # ------------------------------------------------------------------
    # Subtests: unittest reports each failing one separately and calls
    # neither addSuccess() nor addFailure() for the method itself.
    # ------------------------------------------------------------------

    def test_subtest_failure_is_recorded_as_a_failure(self):
        class Case(unittest.TestCase):
            def test_x(self):
                with self.subTest(i=1):
                    self.fail('nope')

        result, record, line, _ = self.drive_one(Case)
        self.assertEqual(line, 'not ok 1 - test_x (Case)')
        self.assertEqual(record['outcome'], 'fail')
        self.assertFalse(result.wasSuccessful())

    def test_subtest_error_is_recorded_as_an_error(self):
        class Case(unittest.TestCase):
            def test_x(self):
                with self.subTest(i=1):
                    raise RuntimeError('boom')

        result, record, line, _ = self.drive_one(Case)
        self.assertEqual(line, 'not ok 1 - test_x (Case)')
        # Matches where TestResult.addSubTest() filed it.
        self.assertEqual(len(result.errors), 1)
        self.assertEqual(record['outcome'], 'error')

    def test_subtest_error_outranks_subtest_failure(self):
        class Case(unittest.TestCase):
            def test_x(self):
                with self.subTest(i=1):
                    self.fail('nope')
                with self.subTest(i=2):
                    raise RuntimeError('boom')

        _, record, line, err = self.drive_one(Case)
        self.assertEqual(line, 'not ok 1 - test_x (Case)')
        self.assertEqual(record['outcome'], 'error')
        self.assertIn('AssertionError: nope', record['message'])
        self.assertIn('RuntimeError: boom', record['message'])
        self.assertEqual(err.count('# subtest:'), 2)

    def test_skipped_subtest_does_not_mask_a_later_failure(self):
        class Case(unittest.TestCase):
            def test_x(self):
                with self.subTest(i=1):
                    self.skipTest('capability missing')
                with self.subTest(i=2):
                    self.fail('nope')

        result, record, line, _ = self.drive_one(Case)
        self.assertEqual(line, 'not ok 1 - test_x (Case)')
        self.assertEqual(record['outcome'], 'fail')
        self.assertIn('capability missing', record['message'])
        self.assertIn('AssertionError: nope', record['message'])
        self.assertFalse(result.wasSuccessful())

    def test_teardown_error_outranks_a_passing_body(self):
        class Case(unittest.TestCase):
            def test_x(self):
                pass

            def tearDown(self):
                raise RuntimeError('teardown boom')

        result, record, line, _ = self.drive_one(Case)
        self.assertEqual(line, 'not ok 1 - test_x (Case)')
        self.assertEqual(record['outcome'], 'error')
        self.assertIn('RuntimeError: teardown boom', record['message'])
        self.assertFalse(result.wasSuccessful())

    def test_duration_spans_the_whole_method(self):
        class Case(unittest.TestCase):
            def test_x(self):
                with self.subTest(i=1):
                    self.fail('early')
                time.sleep(SLEEP_S)

        _, record, _, _ = self.drive_one(Case)
        self.assertGreaterEqual(record['duration_s'], SLEEP_S / 2)

    # ------------------------------------------------------------------
    # Line count: the plan is written before the run, from
    # suite.countTestCases(), so it counts test methods.
    # ------------------------------------------------------------------

    def test_one_line_per_test_method(self):
        class Case(unittest.TestCase):
            def test_a_pass(self):
                pass

            def test_b_subtests(self):
                for i in (1, 2, 3):
                    with self.subTest(i=i):
                        self.fail(f'nope {i}')

            def test_c_skip(self):
                self.skipTest('why')

        result, out, _ = self.drive(Case)
        self.assertEqual(out.splitlines(), [
            'ok 1 - test_a_pass (Case)',
            'not ok 2 - test_b_subtests (Case)',
            'ok 3 - test_c_skip (Case) # SKIP why',
        ])
        self.assertEqual([r['outcome'] for r in result.records],
                         ['pass', 'fail', 'skip'])

    def test_class_setup_error_is_reported_once(self):
        class Case(unittest.TestCase):
            @classmethod
            def setUpClass(cls):
                raise RuntimeError('no fixture')

            def test_x(self):
                pass

            def test_y(self):
                pass

        result, out, _ = self.drive(Case)
        lines = out.splitlines()
        self.assertEqual(len(lines), 1, out)
        # unittest reports this against an _ErrorHolder, which stands in for
        # the whole class and has no test method to name or time.
        self.assertTrue(lines[0].startswith('not ok 1 - setUpClass'),
                        lines[0])
        self.assertEqual(len(result.records), 1, result.records)
        self.assertEqual(result.records[0]['outcome'], 'error')
        self.assertIsNone(result.records[0]['duration_s'])
        self.assertFalse(result.wasSuccessful())


if __name__ == '__main__':
    if len(sys.argv) < 2:
        sys.exit('usage: %s <path-to-runner.py>' % sys.argv[0])
    runner = load_runner(sys.argv.pop(1))
    unittest.main()
