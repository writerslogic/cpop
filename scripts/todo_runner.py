#!/usr/bin/env python3
"""
todo_runner.py — parallel, model-aware, fully autonomous todo.md driver.
Unix-only (relies on os.killpg / POSIX session groups).

Parses every open task in todo.md for its Model (Haiku|Sonnet|Opus) and
its Files list, derives the set of paths the task edits, then runs up to
MAX_PARALLEL (default 3) headless Claude agents concurrently. Tasks whose
file sets overlap serialize automatically; tasks with disjoint sets
execute in parallel. Each agent receives a strict autonomous prompt: no
questions, triage-then-fix, revert on regression, always commit.

State lives in todo.md itself (Status line), so rerunning is idempotent
and a killed run leaves no orphan state beyond lockfiles which the next
launch clears.

Usage:
    scripts/todo_runner.py                     # drain every open task
    scripts/todo_runner.py --dry-run           # list what would run
    scripts/todo_runner.py --only SYS-020      # one task
    scripts/todo_runner.py --filter '^SYS-0'   # regex match
    scripts/todo_runner.py --parallel 4        # override concurrency
    scripts/todo_runner.py --max 5             # stop after 5 completions

Environment overrides:
    CLAUDE_BIN       claude CLI path        (default: claude)
    MAX_PARALLEL     concurrent workers     (default: 3)
    TASK_TIMEOUT     per-task seconds       (default: 3800)
    POLL_INTERVAL    reap poll seconds      (default: 2)
    REPO_ROOT        repo root              (default: script parent)
"""

from __future__ import annotations

import argparse
import hashlib
import logging
import os
import re
import signal
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Optional

Record = tuple[str, str, Path]

# ---------------------------------------------------------------------------
# config

REPO_ROOT = Path(os.environ.get("REPO_ROOT", Path(__file__).resolve().parent.parent))
TODO_FILE = REPO_ROOT / "todo.md"
STATE_DIR = REPO_ROOT / ".todo-runner"
LOCK_DIR = STATE_DIR / "locks"
META_DIR = STATE_DIR / "jobs"
LOG_DIR = STATE_DIR / "logs"
STATE_LOG = STATE_DIR / "state.log"

CLAUDE_BIN = os.environ.get("CLAUDE_BIN", "claude")
MAX_PARALLEL = int(os.environ.get("MAX_PARALLEL", "3"))
TASK_TIMEOUT = int(os.environ.get("TASK_TIMEOUT", "3800"))
POLL_INTERVAL = float(os.environ.get("POLL_INTERVAL", "2"))

TASK_HEADER_RE = re.compile(r"^### ((?:CRITICAL|SYS|C|H|M|L)-\d+):")
MODEL_RE = re.compile(r"\*\*Model:\*\*\s*([A-Za-z]+)")
FILES_RE = re.compile(r"\*\*Files?:\*\*\s*(.+)")
STATUS_RE = re.compile(r"\*\*Status:\*\*\s*(\S+)")

EXCLUSIVE_KEYWORDS = re.compile(
    r"\b(?:multiple|entire|widespread|project-wide|broader|many|40\+|across)\b",
    re.IGNORECASE,
)
LINE_SUFFIX_RE = re.compile(r":[\d,\-]+$")
VALID_MODELS = {"haiku", "sonnet", "opus"}

# ---------------------------------------------------------------------------
# data

@dataclass
class Task:
    id: str
    model: str
    exclusive: bool
    files: list[str]

@dataclass
class Job:
    task: Task
    proc: subprocess.Popen
    log_path: Path
    started: float
    term_sent_at: Optional[float] = None
    locks: list[str] = field(default_factory=list)  # md5 of each file (or "__exclusive__")


# ---------------------------------------------------------------------------
# progress tracking (pattern adapted from ~/.claude/scripts/audit.py)


class ProgressRenderer:
    OUTCOMES = ["fixed", "rejected", "blocked", "failed"]

    def __init__(self, total: int, concurrency: int = 1, width: int = 40):
        self.total = total
        self.concurrency = max(1, concurrency)
        self.done = 0
        self.outcomes = {o: 0 for o in self.OUTCOMES}
        self.running: list[tuple[str, str, float]] = []
        self.start = time.monotonic()
        self.completion_times: list[float] = []
        self.width = width
        self._printed_lines = 0
        self._enabled = sys.stderr.isatty()

    @staticmethod
    def _fmt_time(secs: Optional[float]) -> str:
        if secs is None:
            return "--:--"
        secs = max(0, int(secs))
        h, rem = divmod(secs, 3600)
        m, s = divmod(rem, 60)
        if h:
            return f"{h}h{m:02d}m{s:02d}s"
        return f"{m:02d}m{s:02d}s"

    def _eta_seconds(self) -> Optional[float]:
        remaining = self.total - self.done
        if remaining <= 0 and self.done > 0:
            return 0.0
        measured = len(self.completion_times)
        warmup = min(2, self.concurrency)
        if measured < warmup + 1:
            return None
        span = max(1e-6, time.monotonic() - self.completion_times[0])
        rate = (measured - 1) / span if measured > 1 else measured / span
        if rate <= 0:
            return None
        return remaining / rate

    def _lines(self) -> list[str]:
        elapsed = time.monotonic() - self.start
        eta = self._eta_seconds()
        pct = self.done / self.total if self.total else 1.0
        filled = int(self.width * pct)
        bar = "\u2588" * filled + "\u2591" * (self.width - filled)
        running_count = len(self.running)
        pending = self.total - self.done - running_count
        outcome_counts = "  ".join(f"{o}: {self.outcomes[o]}" for o in self.OUTCOMES)
        header = [
            "TODO RUNNER",
            outcome_counts,
            f"TOTAL: {self.total}  DONE: {self.done}  RUNNING: {running_count}  PENDING: {pending}",
            f"{bar} {self._fmt_time(elapsed)} / ETA {self._fmt_time(eta)}",
        ]
        for task_id, model, started in self.running:
            header.append(f"  \u25b6 {task_id:<14} {model:<7} {self._fmt_time(time.monotonic() - started)}")
        return header

    def clear(self) -> None:
        if not self._enabled or self._printed_lines == 0:
            return
        out = sys.stderr
        out.write(f"\033[{self._printed_lines}F")
        for _ in range(self._printed_lines):
            out.write("\033[2K\n")
        out.write(f"\033[{self._printed_lines}F")
        out.flush()
        self._printed_lines = 0

    def render(self) -> None:
        if not self._enabled:
            return
        lines = self._lines()
        out = sys.stderr
        if self._printed_lines:
            out.write(f"\033[{self._printed_lines}F")
            for _ in range(self._printed_lines):
                out.write("\033[2K\n")
            out.write(f"\033[{self._printed_lines}F")
        for line in lines:
            out.write(line + "\n")
        out.flush()
        self._printed_lines = len(lines)

    def on_spawn(self, task_id: str, model: str) -> None:
        self.running.append((task_id, model, time.monotonic()))
        self.render()

    def on_complete(self, task_id: str, outcome: str) -> None:
        self.done += 1
        self.completion_times.append(time.monotonic())
        if outcome in self.outcomes:
            self.outcomes[outcome] += 1
        self.running = [r for r in self.running if r[0] != task_id]
        self.render()


TRACKER: Optional[ProgressRenderer] = None


class TrackerAwareHandler(logging.StreamHandler):
    def emit(self, record: logging.LogRecord) -> None:
        if TRACKER is not None:
            TRACKER.clear()
        super().emit(record)
        if TRACKER is not None:
            TRACKER.render()


# ---------------------------------------------------------------------------
# helpers

logger = logging.getLogger("todo_runner")


def _configure_logging() -> None:
    fmt = logging.Formatter("[%(asctime)s] %(message)s", datefmt="%H:%M:%S")
    stream = TrackerAwareHandler(sys.stderr)
    stream.setFormatter(fmt)
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    fileh = logging.FileHandler(STATE_LOG)
    fileh.setFormatter(fmt)
    logger.handlers.clear()
    logger.addHandler(stream)
    logger.addHandler(fileh)
    logger.setLevel(logging.INFO)
    logger.propagate = False


def log(msg: str) -> None:
    logger.info(msg)


def all_task_statuses() -> dict[str, str]:
    """Return {task_id: first_status_word} by reading todo.md exactly once."""
    statuses: dict[str, str] = {}
    current_id: Optional[str] = None
    try:
        with TODO_FILE.open() as fh:
            for raw in fh:
                m = TASK_HEADER_RE.match(raw)
                if m:
                    current_id = m.group(1)
                    continue
                if current_id and current_id not in statuses:
                    sm = STATUS_RE.search(raw)
                    if sm:
                        statuses[current_id] = sm.group(1).lower()
    except OSError as e:
        raise RuntimeError(f"todo.md unreadable: {e}") from e
    return statuses


def md5_of(path: str) -> str:
    return hashlib.md5(path.encode()).hexdigest()


def parse_files(raw: str) -> tuple[list[str], bool]:
    """Return (files, exclusive). Prose/dir scope → exclusive."""
    exclusive = bool(EXCLUSIVE_KEYWORDS.search(raw))
    chunks = re.findall(r"`([^`]+)`", raw)
    if not chunks:
        return [], True

    out: list[str] = []
    seen: set[str] = set()
    for chunk in chunks:
        p = LINE_SUFFIX_RE.sub("", chunk.strip())
        if p.endswith("/") or "*" in p:
            exclusive = True
            continue
        if "/" not in p:
            continue
        if "." not in os.path.basename(p):
            exclusive = True
            continue
        if p not in seen:
            seen.add(p)
            out.append(p)

    if not out:
        exclusive = True
    return out, exclusive


def list_open_tasks() -> list[Task]:
    """Scan todo.md and return every task whose first Status line is 'open'."""
    tasks: list[Task] = []
    current: Optional[dict] = None

    def finalize(entry: Optional[dict]) -> None:
        if entry and entry.get("status") == "open":
            files, exclusive = parse_files(entry.get("files_raw", ""))
            tasks.append(
                Task(
                    id=entry["id"],
                    model=entry.get("model", "sonnet"),
                    exclusive=exclusive,
                    files=files,
                )
            )

    with TODO_FILE.open() as fh:
        for raw in fh:
            m = TASK_HEADER_RE.match(raw)
            if m:
                finalize(current)
                current = {"id": m.group(1)}
                continue
            if not current:
                continue
            if "model" not in current:
                mm = MODEL_RE.search(raw)
                if mm:
                    tok = mm.group(1).lower()
                    current["model"] = tok if tok in VALID_MODELS else "sonnet"
            if "files_raw" not in current:
                fm = FILES_RE.search(raw)
                if fm:
                    current["files_raw"] = fm.group(1)
            if "status" not in current:
                sm = STATUS_RE.search(raw)
                if sm:
                    current["status"] = sm.group(1).lower()
    finalize(current)
    return tasks


# ---------------------------------------------------------------------------
# lock table (file-system backed — survives crashes, cleared on launch)

def try_lock(task: Task) -> Optional[list[str]]:
    """
    Atomically acquire locks for every file in `task.files`.
    Returns the list of lock names on success, None on conflict.
    Exclusive tasks take the __exclusive__ lock and require an empty table.
    """
    exclusive_path = LOCK_DIR / "__exclusive__.lock"
    if exclusive_path.exists():
        return None

    if task.exclusive:
        # Exclusive: table must be empty.
        if any(LOCK_DIR.glob("*.lock")):
            return None
        try:
            fd = os.open(str(exclusive_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
            os.write(fd, task.id.encode())
            os.close(fd)
        except FileExistsError:
            return None
        return ["__exclusive__"]

    hashes = [md5_of(f) for f in task.files]
    lock_paths = [LOCK_DIR / f"{h}.lock" for h in hashes]

    # Two-phase acquire: scan first, then atomic create_exclusive each.
    for lp in lock_paths:
        if lp.exists():
            return None

    acquired: list[Path] = []
    try:
        for lp in lock_paths:
            fd = os.open(str(lp), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
            os.write(fd, task.id.encode())
            os.close(fd)
            acquired.append(lp)
    except FileExistsError:
        # Roll back partial acquisition.
        for lp in acquired:
            lp.unlink(missing_ok=True)
        return None
    return hashes


def release(locks: list[str]) -> None:
    for h in locks:
        (LOCK_DIR / f"{h}.lock").unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# prompt

def build_prompt(task_id: str) -> str:
    today = date.today().isoformat()
    return f"""You are resolving a SINGLE audit task in FULLY AUTONOMOUS mode. You have no human in the loop. Do not ask questions. Do not seek confirmation. Do not explain what you are about to do — just do it.

# Task
{task_id}

# Hard rules (non-negotiable)

1. **Read first.** Open `{TODO_FILE}` and find `### {task_id}:`. Read the entire task block (Description, Root cause, Fix, Files). Then read every file referenced so you know the CURRENT state.

2. **Triage before editing.** For each named site, decide ONE of:
   - **already fixed** — the fix is already in the code
   - **partially fixed** — some sites done, others not
   - **broken** — the fix is needed
   - **rejected** — the task's premise is wrong (false positive)

3. **If broken, apply the minimal fix** from the task's `Fix:` steps. Rules:
   - Do NOT touch files outside this task's scope
   - Do NOT refactor surrounding code
   - Do NOT add features, comments, or type annotations to unchanged code
   - Do NOT rename variables or restructure modules
   - Re-read each file immediately before editing (the linter rewrites on save)

4. **Verify.** Run:
   ```
   cargo test -p witnessd --lib
   ```
   If it was green before and red after, YOU broke it. Narrow the change or revert. Never commit a regression. Do NOT run `cargo test --workspace`, `cargo clippy`, or `cargo build --release` — too slow for this loop; the runner handles workspace gates.

5. **Update Status.** Change the task's `Status:** open` to one of:
   - `Status:** fixed {today} (one-sentence evidence)`
   - `Status:** rejected {today} (why it was a false positive)`
   - `Status:** blocked {today} (specific reason, what you tried)`
   Use present-tense, ≤ 120 characters.

6. **Commit.** Single-line message:
   ```
   <type>({task_id}): <what changed>
   ```
   Where `<type>` is one of: fix, refactor, docs, test, perf. Examples:
   - `fix({task_id}): propagate HKDF expand error instead of swallowing with .is_ok()`
   - `docs({task_id}): mark fixed after triage — all three sites already closed`
   - `refactor({task_id}): use Welford single-pass variance helper at named call sites`

# Autonomous decision policy

- **Ambiguity** → choose the lowest-risk interpretation. Document the choice in the commit body.
- **Stuck for >5 minutes on a single design question** → mark `blocked`, commit the status update, exit.
- **Pre-existing failing test not caused by you** → not your problem, proceed, note it in commit body.
- **The task's Fix steps contradict the current code** → follow the evidence, not the checklist.
- **Your edit would require touching files the task didn't list** → mark `blocked: scope creep`, revert, exit.
- **Any destructive git operation** (reset --hard, push --force, branch -D) → forbidden. Halt instead.

# Budget

Exactly ONE task. When you finish steps 1–6, exit. Do not start a second task.

# Completion contract

Exit 0 ONLY if:
  (a) the Status line was rewritten
  (b) a new commit exists in `git log -1`
  (c) `cargo test -p witnessd --lib` is green

Otherwise exit non-zero — the runner will reap and move on.
"""


# ---------------------------------------------------------------------------
# worker pool

def spawn(task: Task, locks: list[str]) -> Job:
    log_path = LOG_DIR / f"{task.id}.log"
    prompt = build_prompt(task.id)

    cmd = [
        CLAUDE_BIN,
        "--print",
        "--model", task.model,
        "--permission-mode", "acceptEdits",
    ]

    with log_path.open("w") as log_fh:
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=log_fh,
            stderr=subprocess.STDOUT,
            cwd=str(REPO_ROOT),
            start_new_session=True,
        )
    assert proc.stdin is not None
    proc.stdin.write(prompt.encode())
    proc.stdin.close()

    log(f"▶ spawn {task.id} pid={proc.pid} model={task.model} exclusive={int(task.exclusive)} files={len(task.files) or 'all'}")
    if TRACKER is not None:
        TRACKER.on_spawn(task.id, task.model)
    return Job(task=task, proc=proc, log_path=log_path, started=time.time(), locks=locks)


TERM_GRACE_SECS = 30


def reap(jobs: list[Job], statuses: dict[str, str]) -> tuple[list[Job], list[Record]]:
    """Return (still-running jobs, records for jobs that exited this pass)."""
    still: list[Job] = []
    records: list[Record] = []
    now = time.time()
    for job in jobs:
        rc = job.proc.poll()
        elapsed = now - job.started

        if rc is None:
            if job.term_sent_at is not None and (now - job.term_sent_at) > TERM_GRACE_SECS:
                log(f"   ☠ force-kill {job.task.id} (TERM ignored after {TERM_GRACE_SECS}s)")
                try:
                    os.killpg(os.getpgid(job.proc.pid), signal.SIGKILL)
                except ProcessLookupError:
                    pass
            elif job.term_sent_at is None and elapsed > TASK_TIMEOUT:
                log(f"   ⏱ timeout {job.task.id} after {int(elapsed)}s, sending TERM")
                try:
                    os.killpg(os.getpgid(job.proc.pid), signal.SIGTERM)
                except ProcessLookupError:
                    pass
                job.term_sent_at = now
            still.append(job)
            continue

        release(job.locks)
        status_word = statuses.get(job.task.id, "unknown")
        if rc == 0 and status_word in ProgressRenderer.OUTCOMES:
            outcome = status_word
        else:
            outcome = "failed"
        log(f"   ✓ reap {job.task.id} rc={rc} elapsed={int(elapsed)}s status={status_word} log={job.log_path}")
        if TRACKER is not None:
            TRACKER.on_complete(job.task.id, outcome)
        records.append((job.task.id, outcome, job.log_path))
    return still, records


def kill_all(jobs: list[Job]) -> None:
    for job in jobs:
        try:
            os.killpg(os.getpgid(job.proc.pid), signal.SIGTERM)
        except ProcessLookupError:
            pass
    time.sleep(1)
    for job in jobs:
        try:
            os.killpg(os.getpgid(job.proc.pid), signal.SIGKILL)
        except ProcessLookupError:
            pass
        release(job.locks)


# ---------------------------------------------------------------------------
# gates

def run_baseline_gate() -> bool:
    log("verifying baseline: cargo test -p witnessd --lib")
    rv = subprocess.run(
        ["cargo", "test", "-p", "witnessd", "--lib"],
        cwd=str(REPO_ROOT),
        capture_output=True,
    )
    (LOG_DIR / "baseline.log").write_bytes(rv.stdout + rv.stderr)
    return rv.returncode == 0


def run_final_gate() -> int:
    log("final gate: cargo clippy --workspace -- -D warnings")
    clippy = subprocess.run(
        ["cargo", "clippy", "--workspace", "--", "-D", "warnings"],
        cwd=str(REPO_ROOT),
        capture_output=True,
    )
    (LOG_DIR / "final-clippy.log").write_bytes(clippy.stdout + clippy.stderr)
    if clippy.returncode != 0:
        log(f"✗ clippy failed (see {LOG_DIR / 'final-clippy.log'})")
        return 2

    log("final gate: cargo test --workspace --lib")
    tests = subprocess.run(
        ["cargo", "test", "--workspace", "--lib"],
        cwd=str(REPO_ROOT),
        capture_output=True,
    )
    (LOG_DIR / "final-tests.log").write_bytes(tests.stdout + tests.stderr)
    if tests.returncode != 0:
        log(f"✗ workspace tests failed (see {LOG_DIR / 'final-tests.log'})")
        return 3
    log("✓ final gate green")
    return 0


# ---------------------------------------------------------------------------
# summary

def print_summary(records: list[Record], elapsed: float) -> None:
    counts = {o: 0 for o in ProgressRenderer.OUTCOMES}
    for _, outcome, _ in records:
        if outcome in counts:
            counts[outcome] += 1
    log("=" * 60)
    log(
        f"Summary ({ProgressRenderer._fmt_time(elapsed)}): "
        f"fixed={counts['fixed']}  rejected={counts['rejected']}  "
        f"blocked={counts['blocked']}  failed={counts['failed']}"
    )
    non_ok = [r for r in records if r[1] != "fixed"]
    if non_ok:
        log("Tasks needing review:")
        for tid, outcome, lp in non_ok:
            try:
                display = lp.relative_to(REPO_ROOT)
            except ValueError:
                display = lp
            log(f"  {tid:<14} {outcome:<9} → {display}")


# ---------------------------------------------------------------------------
# main

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--only")
    ap.add_argument("--filter")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--parallel", type=int, default=MAX_PARALLEL)
    ap.add_argument("--max", dest="max_tasks", type=int, default=0)
    ap.add_argument("--skip-baseline", action="store_true")
    ap.add_argument("--skip-final", action="store_true")
    args = ap.parse_args()

    parallel = args.parallel

    # Prepare state dirs; wipe stale locks from a killed prior run.
    for d in (STATE_DIR, LOCK_DIR, META_DIR, LOG_DIR):
        d.mkdir(parents=True, exist_ok=True)
    _configure_logging()
    for p in LOCK_DIR.glob("*.lock"):
        p.unlink(missing_ok=True)

    if not TODO_FILE.exists():
        logger.error("missing %s", TODO_FILE)
        return 1

    filter_re = re.compile(args.filter) if args.filter else None

    tasks = list_open_tasks()
    if args.only:
        tasks = [t for t in tasks if t.id == args.only]
    if filter_re:
        tasks = [t for t in tasks if filter_re.search(t.id)]

    log(f"init: {len(tasks)} open task(s); parallelism={parallel}")

    if args.dry_run:
        log(f"{'ID':<14} {'MODEL':<7} {'EXCL':<4} FILES")
        log("-" * 70)
        for t in tasks:
            files_str = ", ".join(t.files) if t.files else "<all>"
            log(f"{t.id:<14} {t.model:<7} {int(t.exclusive):<4} {files_str}")
        return 0

    if not tasks:
        log("nothing to do")
        return 0

    if not args.skip_baseline:
        if not run_baseline_gate():
            log("✗ baseline red; aborting")
            return 1
        log("✓ baseline green")

    global TRACKER
    total = min(len(tasks), args.max_tasks) if args.max_tasks else len(tasks)
    TRACKER = ProgressRenderer(total=total, concurrency=parallel)
    TRACKER.render()

    queue: list[Task] = list(tasks)
    jobs: list[Job] = []
    spawned_count = 0
    deadlock_passes = 0
    records: list[Record] = []
    shutdown_flag = {"requested": False}
    start_time = time.monotonic()

    def shutdown(*_args: object) -> None:
        shutdown_flag["requested"] = True

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    try:
        while (queue or jobs) and not shutdown_flag["requested"]:
            try:
                statuses = all_task_statuses()
            except RuntimeError as e:
                log(f"✗ {e}; terminating workers")
                shutdown_flag["requested"] = True
                break

            queue = [t for t in queue if statuses.get(t.id) == "open"]

            spawned = 0
            remaining: list[Task] = []
            for t in queue:
                if len(jobs) >= parallel:
                    remaining.append(t)
                    continue
                if args.max_tasks and spawned_count >= args.max_tasks:
                    remaining = []
                    break
                locks = try_lock(t)
                if locks is None:
                    remaining.append(t)
                    continue
                try:
                    jobs.append(spawn(t, locks))
                except FileNotFoundError:
                    release(locks)
                    log(f"✗ claude binary not found: {CLAUDE_BIN}; set CLAUDE_BIN env var")
                    return 1
                spawned += 1
                spawned_count += 1
            queue = remaining

            if jobs:
                time.sleep(POLL_INTERVAL)
                jobs, new_records = reap(jobs, statuses)
                records.extend(new_records)
                deadlock_passes = 0
                if TRACKER is not None:
                    TRACKER.render()
            elif queue and spawned == 0:
                deadlock_passes += 1
                if deadlock_passes == 1:
                    log(f"[schedule] waiting on lock conflicts ({len(queue)} queued, 0 running)")
                if deadlock_passes > 3:
                    log(f"✗ deadlock: {len(queue)} queued, 0 running, 0 spawnable")
                    break
                time.sleep(POLL_INTERVAL)
    finally:
        if shutdown_flag["requested"]:
            log("signal received — killing workers")
            kill_all(jobs)
        print_summary(records, time.monotonic() - start_time)

    if shutdown_flag["requested"]:
        return 130

    if args.skip_final:
        return 0

    return run_final_gate()


if __name__ == "__main__":
    sys.exit(main())
