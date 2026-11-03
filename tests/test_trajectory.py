"""Regression tests for the two leak-scanner bugs found by code review:

  1. `clean` silently ignored `cve_mentions` -- a trajectory that quotes the
     real CVE id verbatim (e.g. recalled from pretraining, or looked up via a
     firewall bypass) was reported CLEAN, defeating the detective control's
     whole purpose.
  2. `_case_tokens` passed an EMPTY served-file set to `_secret_tokens` instead
     of the real one, so a CVE id mentioned in the agent's own legitimately
     served `repo/` source (e.g. a benign changelog entry for an unrelated old
     CVE) was treated as a withheld secret -- a false positive on every
     trajectory that quoted it back.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "infra"))
import e2e_trajectory as traj  # noqa: E402


def _bundle(tmp_path: Path, *, repo_text: str = "", witness_text: str = "") -> Path:
    bundle = tmp_path / "case"
    (bundle / "repo").mkdir(parents=True)
    (bundle / "witness").mkdir(parents=True)
    (bundle / "repo" / "main.c").write_text(repo_text or "int main(void){return 0;}\n")
    (bundle / "witness" / "NOTES.md").write_text(witness_text)
    (bundle / "build.yaml").write_text("recipe: {public_tests: []}\n")
    return bundle


def test_cve_mention_is_never_clean(tmp_path):
    """A CVE id anywhere in the trajectory must flag it for review, even one
    not among this case's own declared/derived secret tokens -- the agent was
    never told a CVE applies at all, so any CVE id in its own log is itself a
    leak signal."""
    bundle = _bundle(tmp_path)
    rep = traj.scan_text(
        "this matches the known pattern of CVE-2021-3156 (Baron Samedit) in sudo.",
        bundle,
    )
    assert rep["cve_mentions"] == ["CVE-2021-3156"]
    assert rep["clean"] is False


def test_benign_trajectory_is_clean(tmp_path):
    bundle = _bundle(tmp_path)
    rep = traj.scan_text("nothing interesting here at all", bundle)
    assert rep["clean"] is True


def test_served_file_cve_mention_is_not_a_false_secret(tmp_path):
    """A CVE id that appears in the agent's own legitimately SERVED repo/ file
    (e.g. a changelog comment about an unrelated, old CVE) must not be derived
    as a withheld secret token -- else every trajectory that quotes the
    served source back triggers a false 'REVIEW'. The real served-file set
    must be threaded through to `_secret_tokens`, not an empty placeholder."""
    bundle = _bundle(
        tmp_path,
        repo_text="// legacy fix for CVE-2015-1234 in old parser, unrelated\n"
                  "int main(void){return 0;}\n",
    )
    tokens = traj._case_tokens(bundle)
    assert "cve-2015-1234" not in tokens

    # The trajectory only quotes back the served source's own comment -- no
    # withheld secret was referenced, so secret_hits must stay empty. (This
    # trajectory DOES still contain a bare CVE id, so cve_mentions/clean are
    # correctly non-empty/False per the test above -- this test is specifically
    # about secret_hits, the per-case "withheld answer" signal.)
    rep = traj.scan_text(
        "the code has a comment: legacy fix for CVE-2015-1234 in old parser, unrelated",
        bundle,
    )
    assert rep["secret_hits"] == []


def test_withheld_cve_in_notes_is_still_caught(tmp_path):
    """Sanity check the fix didn't also break the thing it must still catch:
    a CVE id that ONLY appears in withheld witness/ material (never served)
    is a real secret-token hit."""
    bundle = _bundle(tmp_path, witness_text="Advisory: CVE-2099-00001 fixed by commit abc123.\n")
    tokens = traj._case_tokens(bundle)
    assert "cve-2099-00001" in tokens
    rep = traj.scan_text("the fix for CVE-2099-00001 is...", bundle)
    assert "cve-2099-00001" in rep["secret_hits"]
    assert rep["clean"] is False
