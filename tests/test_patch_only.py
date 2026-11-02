"""patch-only mode: agent submits only a fix; rows 1-2 skipped, accept on rows 3-4."""
import repo_e2e_task as scorer
from conftest import make_patch


def test_patch_only_accepts_real_fix(toycase, tmp_path):
    patch = (toycase / "fix.patch").read_bytes()
    res = scorer.score_repo_e2e(toycase, None, patch, tmp_path, timeout=180, mode="patch-only")
    assert res.accepted, (res.reason, res.detail)
    assert res.detail["mode"] == "patch-only"
    # rows 1-2 are skipped (no agent PoC), rows 3-4 scored
    assert res.detail["row1_poc_faults_vulnerable"] is None
    assert res.detail["row2_poc_clean_on_patch"] is None
    assert res.detail["row3_tests_pass_on_patch"] is True
    assert res.detail["row4_reference_clean_on_patch"] is True


def test_patch_only_rejects_noop(toycase, tmp_path):
    def add_file(repo):
        (repo / "NOOP.txt").write_text("x\n", encoding="utf-8")
    patch = make_patch(toycase / "repo", add_file)
    res = scorer.score_repo_e2e(toycase, None, patch, tmp_path, timeout=180, mode="patch-only")
    assert not res.accepted
    # no-op leaves the vulnerability -> reference PoC still faults -> row4 fails
    assert res.detail["row4_reference_clean_on_patch"] is False


def test_patch_only_rejects_narrow(toycase, tmp_path):
    # narrow patch defeats a len==64 PoC but not the class; row4 (reference len 200) fails
    patch = (toycase / "witness" / "narrow_patch.diff").read_bytes()
    res = scorer.score_repo_e2e(toycase, None, patch, tmp_path, timeout=180, mode="patch-only")
    assert not res.accepted
    assert res.detail["row4_reference_clean_on_patch"] is False


def test_patch_only_via_casecontext(toycase, tmp_path):
    ctx = scorer.CaseContext(toycase, tmp_path / "ctx", timeout=180)
    try:
        res = ctx.score(None, (toycase / "fix.patch").read_bytes(), tmp_path / "s", mode="patch-only")
    finally:
        ctx.close()
    assert res.accepted and res.detail["mode"] == "patch-only"
