#!/usr/bin/env bash
# todo-runner.sh — programmatically drive Claude through todo.md until drained.
#
# Design:
#   1. Parse todo.md into an ordered queue of open task IDs.
#   2. For each task, spawn a headless Claude session with a focused,
#      self-contained prompt that (a) triages, (b) fixes if broken,
#      (c) runs tests, (d) updates the task's Status line, (e) commits.
#   3. Between tasks, run a quality gate (clippy + lib tests). If the
#      gate fails, halt — a broken tree is never handed to the next task.
#   4. State lives in todo.md itself (Status: open|fixed|blocked), so the
#      script is idempotent: rerunning picks up where it left off.
#
# Usage:
#   scripts/todo-runner.sh                   # process every open task
#   scripts/todo-runner.sh --only SYS-020    # process one task
#   scripts/todo-runner.sh --dry-run         # list work, do not execute
#   scripts/todo-runner.sh --max 5           # stop after N tasks
#   scripts/todo-runner.sh --filter CRITICAL # regex-match task IDs
#
# Environment:
#   CLAUDE_BIN        path to claude CLI (default: claude)
#   CLAUDE_MODEL      model override for per-task agents (default: sonnet)
#   TASK_TIMEOUT      per-task timeout in seconds (default: 1800)
#   REPO_ROOT         repo root (default: script's parent dir)

set -euo pipefail

# ---- config ------------------------------------------------------------
REPO_ROOT="${REPO_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
TODO_FILE="$REPO_ROOT/todo.md"
LOG_DIR="$REPO_ROOT/.todo-runner"
STATE_FILE="$LOG_DIR/state.log"
CLAUDE_BIN="${CLAUDE_BIN:-claude}"
CLAUDE_MODEL="${CLAUDE_MODEL:-sonnet}"
TASK_TIMEOUT="${TASK_TIMEOUT:-1800}"

FILTER_REGEX=""
ONLY_ID=""
DRY_RUN=0
MAX_TASKS=0

# ---- arg parsing -------------------------------------------------------
while (($#)); do
    case "$1" in
        --only)     ONLY_ID="$2"; shift 2 ;;
        --dry-run)  DRY_RUN=1; shift ;;
        --filter)   FILTER_REGEX="$2"; shift 2 ;;
        --max)      MAX_TASKS="$2"; shift 2 ;;
        -h|--help)  sed -n '2,25p' "$0"; exit 0 ;;
        *)          echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

mkdir -p "$LOG_DIR"
cd "$REPO_ROOT"

# ---- helpers -----------------------------------------------------------

# Extract all (task_id, line_number) pairs where Status is "open".
# A task is "open" when the first Status line below the task header
# contains `Status:** open`. Portable POSIX awk — no gawk extensions.
list_open_tasks() {
    awk '
        /^### (CRITICAL|SYS|C|H|M|L)-[0-9]+:/ {
            line = $0
            sub(/^### /, "", line)
            sub(/:.*$/, "", line)
            current_id = line
            current_line = NR
            status_found = 0
            next
        }
        current_id && !status_found && /Status:\*\*/ {
            status_found = 1
            if ($0 ~ /Status:\*\* open/) {
                printf "%s\t%d\n", current_id, current_line
            }
            current_id = ""
        }
    ' "$TODO_FILE"
}

# Check if the given ID is still marked open (for idempotent reruns).
is_still_open() {
    local id="$1"
    list_open_tasks | awk -v id="$id" '$1 == id { found=1 } END { exit !found }'
}

# Run the project quality gate. Returns 0 iff clean.
quality_gate() {
    echo "[gate] cargo clippy --workspace -- -D warnings"
    if ! cargo clippy --workspace -- -D warnings 2>&1 | tail -20; then
        return 1
    fi
    echo "[gate] cargo test -p witnessd --lib"
    if ! cargo test -p witnessd --lib 2>&1 | tail -5; then
        return 1
    fi
    return 0
}

# Build the prompt for a single task. The prompt is self-contained so the
# spawned Claude has no conversational history to drift against.
build_prompt() {
    local id="$1"
    cat <<PROMPT
You are resolving a single audit task from \`todo.md\`. Be decisive, minimal, and evidence-driven.

# Task
$id

# Protocol

1. **Read the task.** Open \`$TODO_FILE\`, find \`### $id:\`, and read the full task block (description, files, fix steps).

2. **Triage first.** Before writing any code, verify whether the named sites are still broken. Read each referenced file/line. Common outcomes:
   - **Already fixed** — the code already implements the fix. Update the task's \`Status:\*\*\` to \`fixed YYYY-MM-DD (evidence of how it is already resolved)\` and skip to step 5.
   - **Partially fixed** — some sites are resolved, others are not. Mention which in the status update.
   - **Broken** — proceed to step 3.
   - **False positive** — the task's premise does not hold. Update status to \`rejected YYYY-MM-DD (reason)\` and skip to step 5.

3. **Apply the minimal correct fix.** Follow the "Fix" steps in the task. Do not refactor surrounding code, do not add features, do not expand scope. Re-read every file before editing (the linter may auto-fix on save).

4. **Verify.** Run \`cargo test -p witnessd --lib\`. If it was green before and red after, you broke something — narrow the change or revert. Never commit a regression.

5. **Update todo.md.** Change \`Status:\*\* open\` to a precise status line with today's date (2026-04-10) and a one-sentence evidence note.

6. **Commit.** Single-line commit message in the form: \`<type>($id): <what changed>\`. Examples: \`fix($id): ...\`, \`refactor($id): ...\`, \`docs($id): mark fixed after triage\`.

# Non-negotiables

- **Never** skip hooks, never \`--no-verify\`, never \`cargo test --no-run\` as a stand-in for running tests.
- **Never** widen scope: if the task says "fix X at line 614", do not also refactor Y at line 700.
- **Never** blindly apply the "Fix:" steps if triage shows they are obsolete or incorrect. Evidence trumps the checklist.
- **Never** leave the tree red. If you cannot finish, revert and mark status \`blocked: <reason>\`.
- If \`$id\` is ambiguous because todo.md has two entries with the same ID, address the OPEN one only.

# Budget

You have one task's worth of effort. Do not open unrelated issues or start a second task.
PROMPT
}

# Run one task through a headless Claude session.
process_task() {
    local id="$1" lineno="$2"
    local log="$LOG_DIR/${id}.log"
    echo "[$(date +%H:%M:%S)] ▶ $id (line $lineno)" | tee -a "$STATE_FILE"

    if ((DRY_RUN)); then
        echo "[$(date +%H:%M:%S)]   dry-run: would invoke claude -p" | tee -a "$STATE_FILE"
        return 0
    fi

    local prompt
    prompt=$(build_prompt "$id")

    if ! timeout --signal=TERM --kill-after=30s "$TASK_TIMEOUT" \
            "$CLAUDE_BIN" \
                --print \
                --model "$CLAUDE_MODEL" \
                --permission-mode acceptEdits \
                <<<"$prompt" \
                >"$log" 2>&1; then
        local rc=$?
        echo "[$(date +%H:%M:%S)]   ✗ $id exited rc=$rc (log: $log)" | tee -a "$STATE_FILE"
        return 1
    fi

    # Confirm the agent actually moved the task off "open".
    if is_still_open "$id"; then
        echo "[$(date +%H:%M:%S)]   ⚠ $id still marked open after agent ran; halting" | tee -a "$STATE_FILE"
        return 1
    fi

    echo "[$(date +%H:%M:%S)]   ✓ $id done" | tee -a "$STATE_FILE"
}

# ---- main loop ---------------------------------------------------------

main() {
    [[ -f "$TODO_FILE" ]] || { echo "no $TODO_FILE" >&2; exit 1; }

    # Initial gate: refuse to start on a broken tree.
    if ! ((DRY_RUN)); then
        echo "[init] verifying clean starting state"
        if ! quality_gate; then
            echo "[init] starting tree is red; fix before running the loop" >&2
            exit 1
        fi
    fi

    local -a queue=()
    while IFS=$'\t' read -r id lineno; do
        [[ -n "$id" ]] || continue
        [[ -z "$ONLY_ID"      || "$id" == "$ONLY_ID"      ]] || continue
        [[ -z "$FILTER_REGEX" || "$id" =~ $FILTER_REGEX   ]] || continue
        queue+=("$id	$lineno")
    done < <(list_open_tasks)

    local total=${#queue[@]}
    echo "[init] $total open task(s) queued"
    ((total > 0)) || { echo "[init] nothing to do"; exit 0; }

    local done=0 halted=0
    for entry in "${queue[@]}"; do
        IFS=$'\t' read -r id lineno <<<"$entry"

        # Re-check: a prior task may have closed this one as a side effect.
        if ! is_still_open "$id"; then
            echo "[$(date +%H:%M:%S)]   — $id already closed by earlier task, skipping"
            continue
        fi

        if ! process_task "$id" "$lineno"; then
            halted=1
            break
        fi

        # Gate between tasks so a regression fails fast.
        if ! ((DRY_RUN)); then
            if ! quality_gate >>"$LOG_DIR/gate.log" 2>&1; then
                echo "[$(date +%H:%M:%S)]   ⚠ quality gate failed after $id; halting" | tee -a "$STATE_FILE"
                halted=1
                break
            fi
        fi

        ((done++))
        if ((MAX_TASKS > 0 && done >= MAX_TASKS)); then
            echo "[$(date +%H:%M:%S)] reached --max $MAX_TASKS"
            break
        fi
    done

    echo "[done] processed=$done halted=$halted queued=$total"
    exit $halted
}

main "$@"
