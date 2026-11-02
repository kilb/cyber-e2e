"""Leakage/readiness audit tests, driven by the synthetic toy case.

Leak policy under test:
  * HARD leak (fails ok): an answer artifact served to the agent (oracle,
    reference PoC, fix.patch, NOTES, witness/), or served content containing a
    CASE-SPECIFIC secret (a CVE id / fix-commit hash this case declares in
    NOTES.md).
  * WARNING (reported, not fatal): a stray CVE id NOT declared by this case
    (e.g. an upstream changelog mentioning an unrelated historical CVE).
"""
import shutil

import e2e_audit


def test_toycase_is_ready(toycase):
    rep = e2e_audit.audit_case(toycase)
    assert rep.ready, rep.reasons
    assert rep.leaks == [], rep.leaks
    assert rep.ok


def test_served_set_is_repo_only(toycase):
    served = e2e_audit.served_source_files(toycase)
    assert served, "nothing served"
    rels = [p.relative_to(toycase) for p in served]
    assert all(r.parts[0] == "repo" for r in rels), rels
    served_names = {r.name for r in rels}
    for forbidden in ("e2e_probe.py", "model_poc_reference.bin", "fix.patch",
                      "NOTES.md", "narrow_patch.diff", "probe.py"):
        assert forbidden not in served_names, f"{forbidden} leaked into served set"


def test_detects_leaked_answer_file(tmp_path, toycase):
    bad = tmp_path / "bad-case"
    shutil.copytree(toycase, bad)
    shutil.copy(bad / "witness" / "e2e_probe.py", bad / "repo" / "e2e_probe.py")
    rep = e2e_audit.audit_case(bad)
    assert not rep.ok, "audit should fail when the oracle is inside repo/"
    assert any("e2e_probe" in leak for leak in rep.leaks), rep.leaks


def test_detects_case_specific_cve(tmp_path, toycase):
    bad = tmp_path / "bad-case2"
    shutil.copytree(toycase, bad)
    # This case now declares a CVE in its server-side NOTES ...
    (bad / "NOTES.md").write_text("real id: CVE-2026-109618\n", encoding="utf-8")
    # ... and that same id leaks into the served tree -> HARD leak.
    (bad / "repo" / "CHANGELOG").write_text("fixed CVE-2026-109618\n", encoding="utf-8")
    rep = e2e_audit.audit_case(bad)
    assert not rep.ok
    assert any("CVE-2026-109618" in leak for leak in rep.leaks), rep.leaks


def test_stray_cve_is_warning_not_leak(tmp_path, toycase):
    bad = tmp_path / "warn-case"
    shutil.copytree(toycase, bad)
    # A CVE the case does NOT declare (upstream changelog style) -> warning only.
    (bad / "repo" / "NEWS").write_text("2019: addressed CVE-2019-0001\n", encoding="utf-8")
    rep = e2e_audit.audit_case(bad)
    assert rep.ok, "a stray historical CVE must not hard-fail the audit"
    assert any("CVE-2019-0001" in w for w in rep.warnings), rep.warnings


def test_not_ready_without_public_tests(tmp_path, toycase):
    bad = tmp_path / "raw-case"
    shutil.copytree(toycase, bad)
    byaml = (bad / "build.yaml").read_text().replace("    - sh run_tests.sh", "")
    (bad / "build.yaml").write_text(byaml, encoding="utf-8")
    rep = e2e_audit.audit_case(bad)
    assert not rep.ready
    assert any("public_tests" in r for r in rep.reasons), rep.reasons


def test_case_fingerprint_stable_and_sensitive(tmp_path, toycase):
    import shutil
    fp1 = e2e_audit.case_fingerprint(toycase)
    copy = tmp_path / "copy"
    shutil.copytree(toycase, copy)
    assert e2e_audit.case_fingerprint(copy) == fp1          # content-addressed, path-independent
    (copy / "repo" / "prog.c").write_text("changed\n", encoding="utf-8")
    assert e2e_audit.case_fingerprint(copy) != fp1          # sensitive to served content
    # witness/fix changes do NOT affect the fingerprint (not served)
    copy2 = tmp_path / "copy2"
    shutil.copytree(toycase, copy2)
    (copy2 / "fix.patch").write_text("irrelevant\n", encoding="utf-8")
    assert e2e_audit.case_fingerprint(copy2) == fp1


def test_scan_content_false_skips_content_but_keeps_structural(tmp_path, toycase):
    # content leak (declared CVE in served file) is MISSED without a content scan ...
    bad = tmp_path / "c"
    import shutil
    shutil.copytree(toycase, bad)
    (bad / "NOTES.md").write_text("CVE-2026-109618\n", encoding="utf-8")
    (bad / "repo" / "CHANGELOG").write_text("CVE-2026-109618\n", encoding="utf-8")
    assert e2e_audit.audit_case(bad, scan_content=False).ok          # cheap gate passes
    assert not e2e_audit.audit_case(bad, scan_content=True).ok       # full gate catches it
    # ... but an answer artifact physically in repo/ is caught either way (structural)
    bad2 = tmp_path / "c2"
    shutil.copytree(toycase, bad2)
    shutil.copy(bad2 / "witness" / "e2e_probe.py", bad2 / "repo" / "e2e_probe.py")
    assert not e2e_audit.audit_case(bad2, scan_content=False).ok
