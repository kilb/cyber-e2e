"""Leaderboard report rendering tests."""
import e2e_report
import e2e_results as R

TRIALS = (
    [{"case_id": "toycase", "model": "glm-5.3-prime", "verdict": "PASS", "accepted": True}] * 2
    + [{"case_id": "toycase", "model": "glm-5.3-prime", "verdict": "FAIL", "accepted": False}] * 2
    + [{"case_id": "php-oom", "model": "glm-5.3-prime", "verdict": "FAIL", "accepted": False}] * 4
    + [{"case_id": "toycase", "model": "claude", "verdict": "PASS", "accepted": True}] * 4
)


def test_markdown_has_models_and_cases():
    agg = R.aggregate(TRIALS, ks=(1, 2))
    md = e2e_report.render_markdown(agg, title="E2E Leaderboard")
    assert "E2E Leaderboard" in md
    assert "glm-5.3-prime" in md and "claude" in md
    assert "toycase" in md and "php-oom" in md
    assert "pass@1" in md
    # claude solved toycase at 100%, glm at 50% -> claude should rank above glm
    assert md.index("claude") < md.index("glm-5.3-prime")


def test_html_is_selfcontained():
    agg = R.aggregate(TRIALS, ks=(1,))
    html = e2e_report.render_html(agg, title="E2E Leaderboard")
    assert html.lstrip().lower().startswith("<!doctype html>")
    assert "<table" in html
    assert "glm-5.3-prime" in html and "toycase" in html
    # self-contained: no external script/style URLs
    assert "http://" not in html and "https://" not in html


def test_report_shows_mode_and_cost_columns():
    trials = [{"case_id": "toy", "model": "m", "mode": "patch-only", "verdict": "PASS",
               "accepted": True, "tokens": 1200, "usd_cost": 0.12, "solve_s": 9}]
    agg = R.aggregate(trials, ks=(1,))
    md = e2e_report.render_markdown(agg)
    assert "mode" in md and "patch-only" in md and "avg $" in md and "$0.12" in md
    html = e2e_report.render_html(agg)
    assert "patch-only" in html and "avg tok" in html
