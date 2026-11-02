"""Certification-harness tests against the synthetic toy case."""
import shutil

import e2e_certify


def _by_name(rep):
    return {c.name: c for c in rep.controls}


def test_toycase_certifies(toycase, tmp_path):
    rep = e2e_certify.certify_case(toycase, tmp_path, timeout=180)
    assert rep.certified, [(c.name, c.passed, c.reason) for c in rep.controls]
    c = _by_name(rep)
    assert {"accepted", "noop", "narrow"} <= set(c)

    assert c["accepted"].got_accept is True
    assert c["noop"].got_accept is False
    assert c["noop"].detail["row2_poc_clean_on_patch"] is False
    # narrow defeats its own PoC (row2 clean) but not the class (row4 faults)
    assert c["narrow"].got_accept is False
    assert c["narrow"].detail["row2_poc_clean_on_patch"] is True
    assert c["narrow"].detail["row4_reference_clean_on_patch"] is False


def test_certify_fails_when_fix_is_actually_narrow(tmp_path, toycase):
    # A case whose shipped fix.patch does NOT fix the class must fail the
    # ACCEPTED control (row4 catches it) -> certified False.
    bad = tmp_path / "bad"
    shutil.copytree(toycase, bad)
    shutil.copy(bad / "witness" / "narrow_patch.diff", bad / "fix.patch")
    rep = e2e_certify.certify_case(bad, tmp_path / "work", timeout=180)
    assert not rep.certified
    assert _by_name(rep)["accepted"].passed is False
