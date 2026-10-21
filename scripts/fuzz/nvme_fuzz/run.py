# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 SUSE Software Solutions
#
# Authors: Daniel Wagner <dwagner@suse.de>
"""nvme-fuzz run: coverage guided fuzzing with libFuzzer.

For each target the results are in the results directory: the corpus,
which grows across runs, the logs of the jobs and the inputs which found
a bug, and a summary.txt of all targets.
"""

from __future__ import annotations

import argparse
import contextlib
import os
import shutil
import signal
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from types import FrameType

from .libfuzzer import copy_new
from .targets import TARGETS, Target, parse_targets, sanitizer_env

# libFuzzer stops at the end of the run itself. Only after this more is
# it stopped, with SIGTERM, and with SIGKILL after the grace time.
DEADLINE_EXTRA = 60
GRACE_SECONDS = 60


def add_arguments(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        '--seconds',
        type=int,
        default=600,
        help='how long to run each target (%(default)s)',
    )
    p.add_argument(
        '--jobs',
        type=int,
        default=os.cpu_count() or 1,
        help='libFuzzer jobs per target (one per CPU)',
    )
    p.add_argument(
        '--targets',
        type=parse_targets,
        default=list(TARGETS.values()),
        help=f'comma-separated list ({",".join(TARGETS)})',
    )
    p.add_argument(
        '--results', type=Path, help='results directory (BUILD_DIR/fuzz)'
    )


@dataclass
class _Stop:
    """Ctrl-C or SIGTERM: stop the jobs, summarize, and run no more
    targets."""

    pgid: int | None = None
    interrupted: bool = False
    old: dict[int, object] = field(default_factory=dict)

    def __call__(self, signum: int, frame: FrameType | None) -> None:
        self.interrupted = True
        self.kill(signal.SIGTERM)

    def kill(self, sig: int) -> None:
        if self.pgid is not None:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(self.pgid, sig)

    def kill_all(self) -> None:
        """SIGKILL what is left of the process group, the jobs which
        outlive libFuzzer, and wait until it is gone."""
        if self.pgid is None:
            return
        self.kill(signal.SIGKILL)
        for _ in range(100):
            try:
                os.killpg(self.pgid, 0)
            except ProcessLookupError:
                break
            time.sleep(0.1)
        self.pgid = None

    def __enter__(self) -> _Stop:
        for sig in (signal.SIGINT, signal.SIGTERM):
            self.old[sig] = signal.signal(sig, self)
        return self

    def __exit__(self, *exc: object) -> None:
        for sig, handler in self.old.items():
            signal.signal(sig, handler)  # type: ignore[arg-type]


def _wait(proc: subprocess.Popen[bytes], stop: _Stop, deadline: float) -> int:
    """Wait for libFuzzer until @deadline, then stop it: SIGTERM to its
    process group, the jobs included, and SIGKILL to what is left after
    the grace time. A job whose timeout handler deadlocks would keep it
    waiting forever otherwise."""
    while True:
        try:
            return proc.wait(timeout=max(0.0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            pass
        if deadline - time.monotonic() <= 0:
            break
    stop.kill(signal.SIGTERM)
    try:
        return proc.wait(timeout=GRACE_SECONDS)
    except subprocess.TimeoutExpired:
        stop.kill(signal.SIGKILL)
        return proc.wait()


def _findings(artifacts: Path, since: float) -> list[Path]:
    """The inputs libFuzzer saved since @since. A slow unit is none."""
    return sorted(
        f
        for f in artifacts.iterdir()
        if f.stat().st_mtime >= since and not f.name.startswith('slow-unit-')
    )


def _run_target(
    t: Target,
    binary: Path,
    results: Path,
    seconds: int,
    jobs: int,
    stop: _Stop,
) -> tuple[list[Path], int, Path]:
    corpus = results / 'corpus' / t.name
    artifacts = results / 'artifacts' / t.name
    logs = results / 'logs' / t.name
    shutil.rmtree(logs, ignore_errors=True)
    for d in (corpus, artifacts, logs):
        d.mkdir(parents=True, exist_ok=True)
    # Add the seeds, but keep what earlier runs found
    copy_new(t.seeds, corpus)

    # The jobs are independent processes on the shared corpus. The -fork
    # mode is newer, but the libFuzzer of clang 22 crashes in it. A job
    # ends at its first finding, so queue more jobs than workers to keep
    # all of them busy: the deadline ends the run.
    cmd = [
        str(binary),
        '-close_fd_mask=3',
        f'-max_total_time={seconds}',
        f'-jobs={jobs * 100}',
        f'-workers={jobs}',
        f'-artifact_prefix={artifacts}/',
        *t.libfuzzer_options(),
        str(corpus),
    ]
    print(
        f'fuzz-{t.name}: {seconds}s, {jobs} jobs, logs in {logs}', flush=True
    )
    start = time.time()
    # Each job writes fuzz-<job>.log to the current directory
    with open(logs / 'main.log', 'wb') as log:
        proc = subprocess.Popen(
            cmd,
            cwd=logs,
            stdout=log,
            stderr=subprocess.STDOUT,
            env=sanitizer_env(dict(os.environ)),
            start_new_session=True,
        )
        stop.pgid = proc.pid
        status = _wait(proc, stop, time.monotonic() + seconds + DEADLINE_EXTRA)
        stop.kill_all()
    # What jobs which crashed left behind, e.g. the sysfs of the device
    # target
    for d in logs.glob(f'fuzz-{t.name}-??????'):
        shutil.rmtree(d, ignore_errors=True)
    return _findings(artifacts, start), status, logs


def _reports(logs: Path) -> list[str]:
    """The sanitizer summaries in the logs of the jobs."""
    res = []
    for log in sorted(logs.glob('fuzz-*.log')):
        for line in log.read_text(errors='replace').splitlines():
            if line.startswith('SUMMARY') or '==ERROR' in line:
                res.append(line)
    return res


def main(args: argparse.Namespace) -> int:
    results: Path = args.results or args.build_dir / 'fuzz'
    results.mkdir(parents=True, exist_ok=True)
    summary = results / 'summary.txt'
    summary.write_text('')
    failed: list[str] = []

    def report(line: str, *details: str) -> None:
        print(line, flush=True)
        with summary.open('a') as f:
            f.write(''.join(f'{x}\n' for x in (line, *details)))

    with _Stop() as stop:
        for t in args.targets:
            binary = t.binary(args.build_dir)
            if not binary.exists():
                print(f'fuzz-{t.name}: not built, skipped')
                continue
            found, status, logs = _run_target(
                t, binary, results, args.seconds, args.jobs, stop
            )
            if found:
                failed.append(t.name)
                report(
                    f'fuzz-{t.name}: {len(found)} findings, exit status '
                    f'{status}',
                    *_reports(logs),
                    *map(str, found),
                )
            elif stop.interrupted:
                report(f'fuzz-{t.name}: no finding until interrupted')
            # libFuzzer's own exit, or stopped at the deadline
            elif status not in (0, -signal.SIGTERM, -signal.SIGKILL):
                failed.append(t.name)
                report(f'fuzz-{t.name}: failed, exit status {status}')
            else:
                report(f'fuzz-{t.name}: no finding in {args.seconds}s')
            if stop.interrupted:
                break

    if failed:
        print(
            f'fuzz targets with findings: {", ".join(failed)}, see {summary}'
        )
        return 1
    return 130 if stop.interrupted else 0
