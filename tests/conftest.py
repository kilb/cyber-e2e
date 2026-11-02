"""Shared pytest fixtures/paths for the cybergym-e2e harness tests."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
INFRA = ROOT / "infra"
if str(INFRA) not in sys.path:
    sys.path.insert(0, str(INFRA))

import pytest  # noqa: E402


@pytest.fixture
def toycase() -> Path:
    """The synthetic self-test case bundle (fully converted, certifiable)."""
    return ROOT / "tests" / "fixtures" / "toycase"


def make_patch(repo_dir: Path, mutate) -> bytes:
    """Produce a git-apply-able unified diff for an edit to a copy of `repo_dir`.

    `mutate(path)` receives the path to a throwaway copy and edits it in place;
    the returned bytes are the `git diff` of those edits (apply from repo root).
    Used by tests to synthesize control patches (no-op, narrow) deterministically.
    """
    import subprocess
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        work = Path(td) / "repo"
        import shutil
        shutil.copytree(repo_dir, work)
        run = lambda *a: subprocess.run(a, cwd=work, check=True,  # noqa: E731
                                        capture_output=True, text=True)
        run("git", "init", "-q")
        run("git", "config", "user.email", "x@x")
        run("git", "config", "user.name", "x")
        run("git", "add", "-A")
        run("git", "commit", "-qm", "base")
        mutate(work)
        run("git", "add", "-A")  # stage so new files appear in the diff too
        diff = subprocess.run(["git", "diff", "--cached"], cwd=work, check=True,
                              capture_output=True, text=True)
        return diff.stdout.encode()

