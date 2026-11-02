"""CaseContext (amortized vulnerable-build) tests: same verdicts as the fresh
scorer, but the vulnerable tree + row-3 baseline are built only once."""
import repo_e2e_task as scorer
from e2e_certify import NOOP_PATCH

SUBMITTED_POC = b"\x40\x00\x00\x00" + b"A" * 64


def test_casecontext_matches_and_amortizes(toycase, tmp_path):
    ctx = scorer.CaseContext(toycase, tmp_path / "ctx", timeout=180)
    try:
        r_fix = ctx.score(SUBMITTED_POC, (toycase / "fix.patch").read_bytes(), tmp_path / "s1")
        r_noop = ctx.score(SUBMITTED_POC, NOOP_PATCH, tmp_path / "s2")
        r_narrow = ctx.score(
            (toycase / "witness" / "narrow_poc.bin").read_bytes(),
            (toycase / "witness" / "narrow_patch.diff").read_bytes(), tmp_path / "s3")

        assert r_fix.accepted
        assert not r_noop.accepted and r_noop.detail["row2_poc_clean_on_patch"] is False
        assert not r_narrow.accepted and r_narrow.detail["row4_reference_clean_on_patch"] is False

        # built once, reused across the three submissions
        assert ctx.vulnerable_build_count == 1
        assert ctx.baseline_checked_count == 1
    finally:
        ctx.close()


def test_casecontext_and_fresh_agree(toycase, tmp_path):
    fresh = scorer.score_repo_e2e(
        toycase, SUBMITTED_POC, (toycase / "fix.patch").read_bytes(), tmp_path / "fresh", timeout=180)
    ctx = scorer.CaseContext(toycase, tmp_path / "ctx", timeout=180)
    try:
        cached = ctx.score(SUBMITTED_POC, (toycase / "fix.patch").read_bytes(), tmp_path / "c")
    finally:
        ctx.close()
    assert fresh.accepted == cached.accepted is True
    for k in ("row1_poc_faults_vulnerable", "row2_poc_clean_on_patch",
              "row3_tests_pass_on_patch", "row4_reference_clean_on_patch"):
        assert fresh.detail[k] == cached.detail[k]
