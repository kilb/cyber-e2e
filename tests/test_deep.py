"""Deep-review regressions: untrusted-input safety + production-path guards."""
import shutil

import e2e_bench
import repo_e2e_task as scorer

SUBMITTED_POC = b"\x40\x00\x00\x00" + b"A" * 64


def test_patch_traversal_is_rejected_and_contained(tmp_path, toycase):
    tree = tmp_path / "tree"
    tree.mkdir()
    shutil.copy(toycase / "repo" / "prog.c", tree / "prog.c")
    evil = tmp_path / "evil.patch"
    evil.write_text(
        "diff --git a/../../escaped.txt b/../../escaped.txt\n"
        "new file mode 100644\n--- /dev/null\n+++ b/../../escaped.txt\n"
        "@@ -0,0 +1 @@\n+pwned\n", encoding="utf-8")
    ok, err = scorer._git_apply(tree, evil)
    assert not ok, "traversal patch must be rejected"
    assert not (tmp_path / "escaped.txt").exists(), "nothing may be written outside the tree"


def test_cli_agent_solver_serves_repo_without_dotgit(tmp_path, toycase):
    # A case whose repo/ carries a .git must NOT expose it to the agent: the solver
    # materializes exactly the served payload (served_source_files excludes .git).
    case = tmp_path / "case"
    shutil.copytree(toycase, case)
    (case / "repo" / ".git").mkdir()
    (case / "repo" / ".git" / "HEAD").write_text("ref: refs/heads/fixbranch\n", encoding="utf-8")

    sol_poc = tmp_path / "sol_poc.bin"
    sol_poc.write_bytes(SUBMITTED_POC)
    stub = tmp_path / "stub_agent.sh"
    stub.write_text(f"#!/bin/sh\nmkdir -p out\ncp {sol_poc} out/poc\ncp {case / 'fix.patch'} out/fix.patch\n",
                    encoding="utf-8")
    stub.chmod(0o755)

    solver = e2e_bench.cli_agent_solver(str(stub), prompt="solve it", budget=60)
    store = tmp_path / "trials.jsonl"
    work_root = tmp_path / "w"
    recs = e2e_bench.run_benchmark(
        bundles=[case], models=["stub"], n_trials=1, solver=solver,
        store=store, work_root=work_root, timeout=180)

    assert recs[0]["verdict"] == "PASS", recs[0]
    served = work_root / "case" / "stub" / "trial0" / "repo"
    assert (served / "prog.c").is_file()
    assert not (served / ".git").exists(), ".git must not be served to the agent"


def test_casecontext_cleans_up_on_build_failure(tmp_path, toycase):
    bad = tmp_path / "bad"
    shutil.copytree(toycase, bad)
    (bad / "repo" / "build.sh").write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
    root = tmp_path / "ctxroot"
    import pytest
    with pytest.raises(RuntimeError):
        scorer.CaseContext(bad, root, timeout=60)
    assert not root.exists(), "a failed context build must not leak its work dir"
