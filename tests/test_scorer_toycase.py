"""End-to-end scorer checks against the synthetic toy case.

These build the vulnerable + patched trees with gcc/ASan, so they are slower than
the pure-logic tests (a few seconds each). They validate the REAL 4-row matrix in
repo_e2e_task.score_repo_e2e, and pin the behaviors the certification harness
depends on.
"""
from pathlib import Path

import repo_e2e_task as scorer
from conftest import make_patch

SUBMITTED_POC = b"\x40\x00\x00\x00" + b"A" * 64   # len=64 -> overflows (16-byte buf)


def test_real_fix_is_accepted(toycase, tmp_path):
    patch = (toycase / "fix.patch").read_bytes()
    res = scorer.score_repo_e2e(toycase, SUBMITTED_POC, patch, tmp_path, timeout=180)
    assert res.accepted, (res.reason, res.detail)
    d = res.detail
    assert d["row1_poc_faults_vulnerable"] is True
    assert d["row2_poc_clean_on_patch"] is True
    assert d["row3_tests_pass_on_patch"] is True
    assert d["row4_reference_clean_on_patch"] is True


def test_noop_patch_is_rejected_at_row2(toycase, tmp_path):
    # applies + builds but fixes nothing (adds an unreferenced file).
    def add_file(repo: Path):
        (repo / "NOOP_CONTROL.txt").write_text("noop\n", encoding="utf-8")
    patch = make_patch(toycase / "repo", add_file)
    res = scorer.score_repo_e2e(toycase, SUBMITTED_POC, patch, tmp_path, timeout=180)
    assert not res.accepted
    assert res.detail["patch_applies"] is True
    assert res.detail["patch_builds"] is True
    assert res.detail["row2_poc_clean_on_patch"] is False  # PoC still faults


def test_narrow_patch_is_rejected_at_row4(toycase, tmp_path):
    # defeats the len==64 submitted PoC but not the len==200 reference -> row4.
    patch = (toycase / "witness" / "narrow_patch.diff").read_bytes()
    res = scorer.score_repo_e2e(toycase, SUBMITTED_POC, patch, tmp_path, timeout=180)
    assert not res.accepted
    assert res.detail["row2_poc_clean_on_patch"] is True   # own PoC defeated
    assert res.detail["row4_reference_clean_on_patch"] is False  # class not fixed


def test_nonapplying_patch_is_rejected(toycase, tmp_path):
    res = scorer.score_repo_e2e(toycase, SUBMITTED_POC, b"not a patch\n", tmp_path, timeout=180)
    assert not res.accepted
    assert res.detail["patch_applies"] is False
