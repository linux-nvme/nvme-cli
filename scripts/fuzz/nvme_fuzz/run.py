# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 SUSE Software Solutions
#
# Authors: Daniel Wagner <dwagner@suse.de>
"""nvme-fuzz run: coverage guided fuzzing with libFuzzer.

For each target the results are in the results directory: the corpus,
which grows across runs, the logs of the jobs and the inputs which found
a bug, and a summary.txt of all targets. Each run starts with minimizing
the corpus, for the device target after adding the seeds of the mock
tests (see nvme-fuzz seeds).

The device target runs in stages of equal time, with more device data in
each: its findings are named data-<limit>-*, and check and triage replay
them with that limit. Ahead of each stage, its corpus is minimized for
the data limit of the stage, so that its jobs start fast.
"""

from __future__ import annotations

import argparse
import contextlib
import os
import re
import shutil
import signal
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, wait
from dataclasses import dataclass, field
from pathlib import Path
from types import FrameType

from . import device, seeds
from .libfuzzer import copy_new, is_slow_unit
from .targets import TARGETS, Target, parse_targets, sanitizer_env

# libFuzzer stops at the end of the run itself. Only after this more is
# it stopped, with SIGTERM, and with SIGKILL after the grace time.
DEADLINE_EXTRA = 60
GRACE_SECONDS = 60

# How often a job looks for the inputs the other jobs added to the shared
# corpus, in seconds. Each time it lists and stats every file of it, and
# the corpus grows by tens of thousands in a run: libFuzzer's default of
# every second costs a job a tenth of its time.
RELOAD_SECONDS = 60


def parse_sizes(spec: str) -> tuple[int, ...]:
    """The sizes in bytes of a comma-separated list, each a number with an
    optional K or M suffix."""
    sizes = []
    for item in spec.split(','):
        m = re.fullmatch(r'([1-9][0-9]*)([KM]?)', item)
        if not m:
            raise argparse.ArgumentTypeError(
                f"'{item}' is no size, e.g. 4096, 64K or 1M"
            )
        sizes.append(int(m[1]) << {'': 0, 'K': 10, 'M': 20}[m[2]])
    return tuple(sizes)


def _sizes(sizes: tuple[int, ...]) -> str:
    def size(n: int) -> str:
        for shift, unit in ((20, 'M'), (10, 'K')):
            if n >= 1 << shift and not n % (1 << shift):
                return f'{n >> shift}{unit}'
        return str(n)

    return ','.join(map(size, sizes))


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
    p.add_argument(
        '--data-limits',
        type=parse_sizes,
        help='the bytes of device data an input of the device target gets, '
        'in stages of equal time '
        f'({_sizes(TARGETS["device"].data_limits)})',
    )
    p.add_argument(
        '--no-mock-seeds',
        action='store_true',
        help='do not add the seeds of the mock tests to the corpus of the '
        'device target',
    )


@dataclass
class _Stop:
    """Ctrl-C or SIGTERM: stop the jobs, summarize, and run no more
    targets."""

    # The process groups of the libFuzzer processes which run, several
    # in a merge
    pgids: set[int] = field(default_factory=set)
    interrupted: bool = False
    old: dict[int, object] = field(default_factory=dict)

    def __call__(self, signum: int, frame: FrameType | None) -> None:
        self.interrupted = True
        for pgid in list(self.pgids):
            self.kill(pgid, signal.SIGTERM)

    @staticmethod
    def kill(pgid: int, sig: int) -> None:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(pgid, sig)

    def kill_all(self, pgid: int) -> None:
        """SIGKILL what is left of the process group @pgid, the jobs
        which outlive libFuzzer, and wait until it is gone."""
        self.kill(pgid, signal.SIGKILL)
        for _ in range(100):
            try:
                os.killpg(pgid, 0)
            except ProcessLookupError:
                break
            time.sleep(0.1)
        self.pgids.discard(pgid)

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
    stop.kill(proc.pid, signal.SIGTERM)
    try:
        return proc.wait(timeout=GRACE_SECONDS)
    except subprocess.TimeoutExpired:
        stop.kill(proc.pid, signal.SIGKILL)
        return proc.wait()


def _libfuzzer(
    cmd: list[str],
    logs: Path,
    log_name: str,
    env: dict[str, str],
    stop: _Stop,
    deadline: float | None = None,
) -> int:
    """Run libFuzzer in @logs, its output in @log_name there, until it
    ends or @deadline. Returns its exit status."""
    with open(logs / log_name, 'wb') as log:
        proc = subprocess.Popen(
            cmd,
            cwd=logs,
            stdout=log,
            stderr=subprocess.STDOUT,
            env=env,
            start_new_session=True,
        )
        stop.pgids.add(proc.pid)
        if deadline is None:
            status = proc.wait()
        else:
            status = _wait(proc, stop, deadline)
        stop.kill_all(proc.pid)
    return status


def _partitions(corpus: Path, parts: Path) -> list[Path]:
    """Split @corpus by the first byte of its inputs, the first two for
    those of the device target from index 255 on, into directories in
    @parts, of hard links to them. Returns them, the largest first."""
    sizes: dict[Path, int] = {}
    for f in corpus.iterdir():
        with f.open('rb') as fh:
            first = fh.read(2)
        if first[:1] == bytes([device.EXTENDED_INDEX]):
            first = first[:2]
        else:
            first = first[:1]
        d = parts / ('-'.join(map(str, first)) or 'empty')
        if d not in sizes:
            d.mkdir(parents=True)
            sizes[d] = 0
        try:
            os.link(f, d / f.name)
        except OSError:
            shutil.copy(f, d / f.name)
        sizes[d] += 1
    return sorted(sizes, key=lambda d: -sizes[d])


def _merge(
    t: Target,
    binary: Path,
    corpus: Path,
    logs: Path,
    stop: _Stop,
    jobs: int,
    limit: int | None,
) -> None:
    """Keep only the inputs of @corpus which add coverage, with the data
    limit @limit. The corpus grows by each input which added some when it
    was found, most of which later inputs reach as well, and each job
    loads all of it. A failed or interrupted merge keeps the corpus as it
    is.

    A merge runs every input once, which takes long for a big corpus: the
    corpus of a partitioned target is merged in parts, in parallel, and
    then what they keep once more. The first byte of an input of the
    device target selects the command: inputs of different commands
    rarely reach the same code, and the merge of what the parts keep
    keeps about what one merge of all of it does."""
    merged = corpus.with_name(f'{corpus.name}.merge')
    parts = corpus.with_name(f'{corpus.name}.parts')
    for d in (merged, parts):
        shutil.rmtree(d, ignore_errors=True)
    merged.mkdir()
    before = sum(1 for _ in corpus.iterdir())
    print(f'fuzz-{t.name}: minimizing the corpus of {before} inputs')
    # Only the coverage counts here, the jobs report the findings
    env = sanitizer_env(dict(os.environ))
    env['ASAN_OPTIONS'] += ':detect_leaks=0'
    if limit is not None:
        env['FUZZ_DATA_LIMIT'] = str(limit)

    def merge(out: Path, src: Path, log_name: str) -> bool:
        if stop.interrupted:
            return False
        out.mkdir(exist_ok=True)
        cmd = [
            str(binary),
            '-merge=1',
            '-close_fd_mask=3',
            *t.libfuzzer_options(),
            str(out),
            str(src),
        ]
        return _libfuzzer(cmd, logs, log_name, env, stop) == 0

    src = corpus
    ok = True
    if t.partitioned and jobs > 1:
        ins = _partitions(corpus, parts / 'in')
        outs = [parts / 'out' / d.name for d in ins]
        (parts / 'out').mkdir(parents=True)
        with ThreadPoolExecutor(jobs) as pool:
            futures = [
                pool.submit(merge, out, d, f'merge-{d.name}.log')
                for d, out in zip(ins, outs, strict=True)
            ]
            # Wait in steps: Ctrl-C runs its handler in this thread, and
            # an endless wait for a lock is not interrupted on every
            # system, e.g. FreeBSD
            while wait(futures, timeout=1).not_done:
                pass
        ok = all(f.result() for f in futures)
        src = parts / 'kept'
        src.mkdir()
        for out in outs if ok else []:
            for f in out.iterdir():
                os.link(f, src / f.name)
    ok = ok and merge(merged, src, 'merge.log')
    shutil.rmtree(parts, ignore_errors=True)
    after = sum(1 for _ in merged.iterdir())
    if not ok or stop.interrupted or not after:
        print(f'fuzz-{t.name}: merge failed, the corpus stays as it is')
        shutil.rmtree(merged)
        return
    shutil.rmtree(corpus)
    merged.rename(corpus)
    print(f'fuzz-{t.name}: {after} of {before} inputs add coverage')


def _findings(artifacts: Path, since: float) -> list[Path]:
    """The inputs libFuzzer saved since @since. A slow unit is none."""
    return sorted(
        f
        for f in artifacts.iterdir()
        if f.stat().st_mtime >= since and not is_slow_unit(f)
    )


def _run_target(
    t: Target,
    binary: Path,
    results: Path,
    seconds: int,
    jobs: int,
    data_limits: tuple[int, ...] | None,
    mock_seeds: Path | None,
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
    # The build of the mock tests whose answers seed the device target
    if mock_seeds and t.name == 'device':
        seeds.add_seeds(mock_seeds, corpus)

    # The jobs are independent processes on the shared corpus. The -fork
    # mode is newer, but the libFuzzer of clang 22 crashes in it. A job
    # ends at its first finding, so queue more jobs than workers to keep
    # all of them busy: the deadline ends the run.
    stages: tuple[int | None, ...] = (
        (data_limits or t.data_limits) if t.data_limits else (None,)
    )
    start = time.time()
    status = 0
    for i, limit in enumerate(stages):
        secs = max(1, seconds // len(stages) + (i < seconds % len(stages)))
        env = sanitizer_env(dict(os.environ))
        prefix = f'{artifacts}/'
        cwd = logs
        what = ''
        if limit is not None:
            env['FUZZ_DATA_LIMIT'] = str(limit)
            prefix += f'data-{limit}-'
            cwd = logs / f'data-{limit}'
            cwd.mkdir(exist_ok=True)
            what = f', {limit} bytes of device data'
        # Each stage starts with the corpus minimized for its limit, and
        # each of its jobs loads all of it
        _merge(t, binary, corpus, cwd, stop, jobs, limit)
        if stop.interrupted:
            break
        cmd = [
            str(binary),
            '-close_fd_mask=3',
            f'-max_total_time={secs}',
            f'-jobs={jobs * 100}',
            f'-workers={jobs}',
            f'-reload={RELOAD_SECONDS}',
            f'-artifact_prefix={prefix}',
            *t.libfuzzer_options(),
            str(corpus),
        ]
        print(
            f'fuzz-{t.name}: {secs}s, {jobs} jobs{what}, logs in {cwd}',
            flush=True,
        )
        # Each job writes fuzz-<job>.log to the current directory
        res = _libfuzzer(
            cmd,
            cwd,
            'main.log',
            env,
            stop,
            time.monotonic() + secs + DEADLINE_EXTRA,
        )
        # The first failure of libFuzzer itself counts
        if status in (0, -signal.SIGTERM, -signal.SIGKILL):
            status = res
        if stop.interrupted:
            break
    # What jobs which crashed left behind, e.g. the sysfs of the device
    # target
    for d in logs.rglob(f'fuzz-{t.name}-??????'):
        shutil.rmtree(d, ignore_errors=True)
    return _findings(artifacts, start), status, logs


def _reports(logs: Path) -> list[str]:
    """The sanitizer summaries in the logs of the jobs."""
    res = []
    for log in sorted(logs.rglob('fuzz-*.log')):
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
                t,
                binary,
                results,
                args.seconds,
                args.jobs,
                args.data_limits,
                None if args.no_mock_seeds else args.build_dir,
                stop,
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
