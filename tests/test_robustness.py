"""Scorer robustness: private TMPDIR plumbing + tolerant oracle output parsing."""
import pytest

import repo_e2e_task as scorer


def test_build_and_tests_use_private_tmpdir(tmp_path):
    tmp = tmp_path / "ptmp"
    tmp.mkdir()
    tree = tmp_path / "tree"
    tree.mkdir()
    spec = {"recipe": {
        "build": ['test -n "$TMPDIR" && touch "$TMPDIR/built"'],
        "public_tests": ['test "$TMPDIR" = "%s" && touch "$TMPDIR/ran"' % tmp],
    }}
    ok, log = scorer._build_tree(tmp_path, tree, timeout=30, spec=spec, extra_env={"TMPDIR": str(tmp)})
    assert ok, log
    assert (tmp / "built").exists()
    ok, log = scorer._run_public_tests(tmp_path, tree, timeout=30, spec=spec, extra_env={"TMPDIR": str(tmp)})
    assert ok, log
    assert (tmp / "ran").exists()


def _probe(closure, body):
    (closure / "e2e_probe.py").write_text(body, encoding="utf-8")


def test_observe_tolerates_leading_diagnostics(tmp_path):
    closure = tmp_path / "closure"
    closure.mkdir()
    tree = tmp_path / "tree"
    tree.mkdir()
    _probe(closure,
           "import sys\n"
           "sys.stderr.write('oracle warming up\\n')\n"
           "print('note: a noisy diagnostic line on stdout')\n"
           "print('{\"faulted\": true, \"detail\": {\"frame\": \"x\"}}')\n")
    body = scorer._observe(closure, tree, "poc", timeout=30)
    assert body["faulted"] is True and body["detail"]["frame"] == "x"


def test_observe_rejects_non_json_output(tmp_path):
    closure = tmp_path / "closure"
    closure.mkdir()
    tree = tmp_path / "tree"
    tree.mkdir()
    _probe(closure, "print('totally not json')\n")
    with pytest.raises(RuntimeError, match="not a JSON line"):
        scorer._observe(closure, tree, "poc", timeout=30)


def test_git_apply_immune_to_enclosing_repo(tmp_path, toycase):
    # The work tree can live inside an unrelated git repo (the server's WORK_ROOT
    # is under this project's checkout). git apply must still modify the tree's
    # files, not silently no-op against the enclosing repo.
    import shutil
    import subprocess
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    tree = tmp_path / "nested" / "deep" / "tree"
    tree.mkdir(parents=True)
    shutil.copy(toycase / "repo" / "prog.c", tree / "prog.c")
    ok, err = scorer._git_apply(tree, toycase / "fix.patch")
    assert ok, err
    assert "clamp to buffer" in (tree / "prog.c").read_text()
