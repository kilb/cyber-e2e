"""Regression tests for infra/sandbox_wrapper.sh (the bwrap sandbox an agent's
own process runs under). Skipped where `bwrap` isn't installed (this is a
real-sandbox test, same convention as test_exec.py's real-docker test) --
these ran for real on blk.so while fixing the two live leaks this locks in.

Each fixed here was a REAL leak found in a live benchmark trial, not a
hypothetical: (1) a prior version of this script only masked specific named
paths and left this project's own README/docs/infra/tests (and, separately,
a sibling project's trees) exposed; (2) a later version that fixed (1) still
bound the real shared `~/.claude` read-write (cross-project session
transcripts + the CLI's own credentials) and passed the launcher's full,
unfiltered environment through (an `E2E_API_KEY`-style secret, `PWD`/
`OLDPWD`) to the sandboxed process.
"""
import os
import shutil
import subprocess
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
WRAPPER = HERE.parent / "infra" / "sandbox_wrapper.sh"

pytestmark = pytest.mark.skipif(shutil.which("bwrap") is None, reason="bwrap not installed")


def _run(cwd: Path, script: str, env: dict | None = None) -> str:
    full_env = {**os.environ, **(env or {})}
    p = subprocess.run(  # noqa: S603
        [str(WRAPPER), "sh", "-c", script], cwd=cwd, env=full_env,
        capture_output=True, text=True, timeout=30, check=False,
    )
    return p.stdout + p.stderr


def test_own_work_dir_stays_readable_and_writable(tmp_path):
    (tmp_path / "marker.txt").write_text("hello")
    out = _run(tmp_path, "cat marker.txt && echo appended >> marker.txt && cat marker.txt")
    assert "hello" in out and "appended" in out


def test_real_toolchain_still_available(tmp_path):
    out = _run(tmp_path, "which gcc python3 make git")
    for tool in ("gcc", "python3", "make", "git"):
        assert tool in out, out


def test_home_is_masked_not_an_enumerated_denylist(tmp_path):
    """Regression for leak #2: must mask $HOME wholesale, not just specific
    named paths -- anything under $HOME the agent has no business reading
    (this project's own files, a sibling project's, whatever else is there)
    must be unreachable, without needing to be named here."""
    out = _run(tmp_path, 'ls -la "$HOME" 2>&1')
    # The only entries bwrap itself guarantees to re-create under a masked
    # $HOME are the ones this script explicitly re-exposes.
    assert ".claude" in out
    # Nothing else from the real $HOME should leak through as a real dirent
    # (a non-trivial, pre-existing entry would mean the mask failed).
    lines = [l for l in out.splitlines() if l and not l.startswith("total")
             and not l.rstrip().endswith(" .") and not l.rstrip().endswith(" ..")]
    names = {l.split()[-1] for l in lines}
    assert names <= {".claude", ".local", ".sandbox-claude-home"}, (
        f"unexpected entries leaked into the masked $HOME: {names}"
    )


def test_env_secrets_are_not_inherited(tmp_path):
    """Regression for leak #3: the launcher's full, unfiltered os.environ
    used to pass straight through to the sandboxed process."""
    out = _run(tmp_path, 'echo "KEY=${E2E_API_KEY:-UNSET}"; echo "PWD2=${PWD:-unset}"; echo "OLD=${OLDPWD:-UNSET}"',
              env={"E2E_API_KEY": "super-secret", "OLDPWD": "/some/harness/path"})
    assert "KEY=UNSET" in out
    assert "OLD=UNSET" in out


def test_allowlisted_model_routing_vars_survive(tmp_path):
    """The env allowlist must not be so strict it breaks the actual model
    routing a `source ~/.<model>` dotfile sets (ANTHROPIC_*/etc.)."""
    out = _run(tmp_path, 'echo "BASE=$ANTHROPIC_BASE_URL"',
              env={"ANTHROPIC_BASE_URL": "https://example-model-endpoint.test"})
    assert "BASE=https://example-model-endpoint.test" in out


def test_claude_home_is_fresh_not_the_real_shared_one(tmp_path):
    """Regression for leak #1 (re-review): the real $HOME/.claude must never
    be bound read-write into the sandbox -- it holds other projects' own
    session transcripts and the CLI's stored credentials on a shared box."""
    out = _run(tmp_path, "ls -A ~/.claude 2>&1")
    assert out.strip() == "", f"expected a fresh empty ~/.claude, got: {out!r}"
    # And the fresh dir really was created on the host, under the trial's own
    # work dir, so it's still inspectable afterward.
    assert (tmp_path / ".sandbox-claude-home").is_dir()
