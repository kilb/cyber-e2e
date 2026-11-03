"""Render a cybergym-e2e leaderboard (markdown + self-contained HTML) from the
aggregated results. Presentation only; all numbers come from e2e_results.

CLI:  python3 e2e_report.py <store.jsonl> [--md FILE] [--html FILE] [--ks 1,5,10]
      (prints markdown to stdout if neither --md nor --html is given)
"""
from __future__ import annotations

import argparse
import html as _html
import json
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
import e2e_results as R  # noqa: E402

# Short, stable labels for the 4-row matrix + the two build gates.
_STAGE_LABEL = {
    "patch_applies": "applies",
    "patch_builds": "builds",
    "row1_poc_faults_vulnerable": "s1 reproduce",
    "row2_poc_clean_on_patch": "s2 poc-fixed",
    "row3_tests_pass_on_patch": "s3 tests",
    "row4_reference_clean_on_patch": "s4 ref-clean",
}


def _pct(x: float) -> str:
    return f"{100 * x:.1f}%"


def _frac(x) -> str:
    return "-" if x is None else _pct(x)


def _ranked_models(agg):
    return sorted(agg["by_model"], key=lambda m: (-m.macro_pass1, -m.micro_pass1, m.model))


def _ks_extra(ks):
    return [k for k in ks if k != 1]  # pass@1 already has its own column


def _sorted_cases(agg):
    return sorted(agg["by_case_model"], key=lambda c: (c.case_id, c.mode, -c.pass1, c.model))


def _patk_cell(cm, k):
    return _pct(cm.pass_at_k[k]) if k in cm.pass_at_k else "-"


def _num(x) -> str:
    if x is None:
        return "-"
    if x >= 1000:
        return f"{x/1000:.1f}k"
    return f"{x:.0f}" if x == int(x) else f"{x:.1f}"


def _usd(x) -> str:
    return "-" if x is None else f"${x:.4f}"


def _secs(x) -> str:
    return "-" if x is None else f"{x:.0f}s"


def render_markdown(agg: dict, title: str = "cybergym-e2e leaderboard") -> str:
    ks = agg["ks"]
    out = [f"# {title}", ""]
    out.append("## Leaderboard (by model x mode, ranked by macro pass@1)")
    out.append("")
    hdr = ["rank", "model", "mode", "macro pass@1", "micro pass@1", "solved/attempted",
           "valid", "errors", "avg $", "avg tok", "avg time"]
    out.append("| " + " | ".join(hdr) + " |")
    out.append("|" + "|".join(["---"] * len(hdr)) + "|")
    for i, m in enumerate(_ranked_models(agg), 1):
        c = m.cost
        out.append("| " + " | ".join([
            str(i), m.model, m.mode, _pct(m.macro_pass1), _pct(m.micro_pass1),
            f"{m.cases_solved_any}/{m.cases_attempted}", str(m.n_valid), str(m.n_error),
            _usd(c.get("usd_cost")), _num(c.get("tokens")), _secs(c.get("solve_s")),
        ]) + " |")
    out.append("")

    out.append("## Per-case results")
    out.append("")
    ks_extra = _ks_extra(ks)
    kcols = [f"pass@{k}" for k in ks_extra]
    hdr2 = ["case", "model", "mode", "n", "pass@1", "95% CI", *kcols, "errors"]
    out.append("| " + " | ".join(hdr2) + " |")
    out.append("|" + "|".join(["---"] * len(hdr2)) + "|")
    for cm in _sorted_cases(agg):
        lo, hi = cm.ci
        kvals = [_patk_cell(cm, k) for k in ks_extra]
        out.append("| " + " | ".join([
            cm.case_id, cm.model, cm.mode, str(cm.n_valid), _pct(cm.pass1),
            f"[{_pct(lo)}, {_pct(hi)}]", *kvals, str(cm.n_error),
        ]) + " |")
    out.append("")

    # Stage pass rates + where agents fail (SOTA failure diagnosis).
    out.append("## Stage pass rates & failure diagnosis")
    out.append("")
    stage_cols = [v for v in _STAGE_LABEL.values()]
    hdr3 = ["model", "mode", *stage_cols, "top failure stage"]
    out.append("| " + " | ".join(hdr3) + " |")
    out.append("|" + "|".join(["---"] * len(hdr3)) + "|")
    for m in _ranked_models(agg):
        fracs = [_frac(m.stages.get(k)) for k in _STAGE_LABEL]
        top = max(m.failures.items(), key=lambda kv: kv[1], default=(None, 0))
        top_s = f"{_STAGE_LABEL.get(top[0], top[0])} ({top[1]})" if top[0] else "-"
        out.append("| " + " | ".join([m.model, m.mode, *fracs, top_s]) + " |")
    out.append("")
    return "\n".join(out)


def render_results_json(agg: dict) -> dict:
    """Upstream-parity `results.json`: one entry per (task, model, mode) with its
    pass rate, pass@k, and cost. (Upstream requires one entry per task per mode for
    every attempted task; at max_attempts=1 that is exactly n=1 per row.)"""
    results = []
    for cm in _sorted_cases(agg):
        results.append({
            "task": cm.case_id, "model": cm.model, "mode": cm.mode,
            "n": cm.n_valid, "successes": cm.successes, "errors": cm.n_error,
            "pass1": round(cm.pass1, 6), "pass_at_k": {str(k): round(v, 6) for k, v in cm.pass_at_k.items()},
            "cost": {k: v for k, v in cm.cost.items() if v is not None},
        })
    return {"schema": "cybergym-e2e.results/v1", "results": results}


def render_submission_yaml(agg: dict, title: str = "cybergym-e2e submission") -> str:
    """Upstream-parity YAML report: per model x mode, the stage1-4 pass fractions,
    pass rates, the token breakdown / wall time / LLM-request cost, and the
    where-it-failed diagnosis."""
    models = []
    for m in _ranked_models(agg):
        models.append({
            "model": m.model, "mode": m.mode,
            "macro_pass1": round(m.macro_pass1, 6), "micro_pass1": round(m.micro_pass1, 6),
            "cases_solved": m.cases_solved_any, "cases_attempted": m.cases_attempted,
            "valid_trials": m.n_valid, "errors": m.n_error,
            "stages": {_STAGE_LABEL[k]: (None if v is None else round(v, 6))
                       for k, v in m.stages.items()},
            "failure_stages": {_STAGE_LABEL.get(k, k): n for k, n in sorted(m.failures.items())},
            "cost": {k: (round(v, 6) if isinstance(v, float) else v)
                     for k, v in m.cost.items() if v is not None},
        })
    return yaml.safe_dump({"title": title, "models": models}, sort_keys=False, allow_unicode=True)


_CSS = """
:root{--bg:#ffffff;--fg:#1a1a1a;--muted:#666;--line:#e3e3e3;--head:#f5f5f5;--accent:#2d6cdf;--good:#1a7f37;--bad:#b42318}
@media (prefers-color-scheme:dark){:root{--bg:#0f1115;--fg:#e6e6e6;--muted:#9aa0a6;--line:#2a2d34;--head:#171a21;--accent:#6ea8fe;--good:#4ac26b;--bad:#ff6b6b}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;padding:24px 16px}
main{max-width:1000px;margin:0 auto}
h1{font-size:22px;margin:0 0 4px} h2{font-size:16px;margin:28px 0 8px;color:var(--muted);font-weight:600;letter-spacing:.02em;text-transform:uppercase}
.sub{color:var(--muted);font-size:13px;margin-bottom:8px}
table{border-collapse:collapse;width:100%;font-variant-numeric:tabular-nums}
th,td{padding:7px 10px;border-bottom:1px solid var(--line);text-align:right;white-space:nowrap}
th:first-child,td:first-child,th:nth-child(2),td:nth-child(2){text-align:left}
thead th{background:var(--head);position:sticky;top:0;font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.03em}
tbody tr:hover{background:color-mix(in srgb,var(--accent) 7%,transparent)}
.rank{color:var(--muted)} .model{font-weight:600}
.bar{display:inline-block;height:8px;border-radius:4px;background:var(--accent);vertical-align:middle;margin-left:6px}
.ci{color:var(--muted);font-size:12px}
footer{color:var(--muted);font-size:12px;margin-top:28px}
"""


def render_html(agg: dict, title: str = "cybergym-e2e leaderboard") -> str:
    ks = agg["ks"]
    e = _html.escape

    def bar(x):
        return f'<span class="bar" style="width:{max(2, round(60 * x))}px"></span>'

    rows_model = []
    for i, m in enumerate(_ranked_models(agg), 1):
        c = m.cost
        rows_model.append(
            f"<tr><td class='rank'>{i}</td><td class='model'>{e(m.model)}</td>"
            f"<td>{e(m.mode)}</td>"
            f"<td>{_pct(m.macro_pass1)}{bar(m.macro_pass1)}</td>"
            f"<td>{_pct(m.micro_pass1)}</td>"
            f"<td>{m.cases_solved_any}/{m.cases_attempted}</td>"
            f"<td>{m.n_valid}</td><td>{m.n_error}</td>"
            f"<td>{_usd(c.get('usd_cost'))}</td><td>{_num(c.get('tokens'))}</td>"
            f"<td>{_secs(c.get('solve_s'))}</td></tr>")

    rows_stage = []
    for m in _ranked_models(agg):
        cells = "".join(f"<td>{_frac(m.stages.get(k))}</td>" for k in _STAGE_LABEL)
        top = max(m.failures.items(), key=lambda kv: kv[1], default=(None, 0))
        top_s = f"{_STAGE_LABEL.get(top[0], top[0])} ({top[1]})" if top[0] else "-"
        rows_stage.append(f"<tr><td class='model'>{e(m.model)}</td><td>{e(m.mode)}</td>"
                          f"{cells}<td>{e(top_s)}</td></tr>")
    stage_hdr = "".join(f"<th>{e(lbl)}</th>" for lbl in _STAGE_LABEL.values())

    ks_extra = _ks_extra(ks)
    kcols = "".join(f"<th>pass@{k}</th>" for k in ks_extra)
    rows_case = []
    for cm in _sorted_cases(agg):
        lo, hi = cm.ci
        kvals = "".join(f"<td>{_patk_cell(cm, k)}</td>" for k in ks_extra)
        rows_case.append(
            f"<tr><td>{e(cm.case_id)}</td><td class='model'>{e(cm.model)}</td>"
            f"<td>{e(cm.mode)}</td>"
            f"<td>{cm.n_valid}</td><td>{_pct(cm.pass1)}{bar(cm.pass1)}</td>"
            f"<td class='ci'>[{_pct(lo)}, {_pct(hi)}]</td>{kvals}<td>{cm.n_error}</td></tr>")

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{e(title)}</title><style>{_CSS}</style></head>
<body><main>
<h1>{e(title)}</h1>
<div class="sub">e2e = PoC reproduces · patch fixes · no regression · not a narrow escape (4 rows). patch-only = fix given the PoC (rows 3-4). pass@1 is the mean success rate (Wilson 95% CI); pass@k is the Chen et&nbsp;al. unbiased estimator. Cost columns are per-trial averages.</div>
<h2>Leaderboard (by model × mode)</h2>
<table><thead><tr><th>#</th><th>model</th><th>mode</th><th>macro pass@1</th><th>micro pass@1</th><th>solved/attempted</th><th>valid</th><th>errors</th><th>avg $</th><th>avg tok</th><th>avg time</th></tr></thead>
<tbody>{''.join(rows_model)}</tbody></table>
<h2>Per-case results</h2>
<table><thead><tr><th>case</th><th>model</th><th>mode</th><th>n</th><th>pass@1</th><th>95% CI</th>{kcols}<th>errors</th></tr></thead>
<tbody>{''.join(rows_case)}</tbody></table>
<h2>Stage pass rates &amp; failure diagnosis</h2>
<table><thead><tr><th>model</th><th>mode</th>{stage_hdr}<th>top failure</th></tr></thead>
<tbody>{''.join(rows_stage)}</tbody></table>
<footer>cybergym-e2e · generated from the trial store</footer>
</main></body></html>
"""


def main(argv: list) -> int:
    ap = argparse.ArgumentParser(description="render a cybergym-e2e leaderboard")
    ap.add_argument("store", help="path to the trials JSONL store")
    ap.add_argument("--md", default=None, help="write markdown to this file")
    ap.add_argument("--html", default=None, help="write HTML to this file")
    ap.add_argument("--results-json", default=None, help="write upstream-parity results.json")
    ap.add_argument("--submission-yaml", default=None, help="write upstream-parity YAML report")
    ap.add_argument("--ks", default="1,5,10", help="comma-separated k values for pass@k")
    ap.add_argument("--title", default="cybergym-e2e leaderboard")
    args = ap.parse_args(argv[1:])
    ks = tuple(int(x) for x in args.ks.split(",") if x.strip())
    trials = R.load_trials(args.store)
    agg = R.aggregate(trials, ks=ks)
    if args.md:
        Path(args.md).write_text(render_markdown(agg, args.title), encoding="utf-8")
        print(f"wrote {args.md}")
    if args.html:
        Path(args.html).write_text(render_html(agg, args.title), encoding="utf-8")
        print(f"wrote {args.html}")
    if args.results_json:
        Path(args.results_json).write_text(json.dumps(render_results_json(agg), indent=2), encoding="utf-8")
        print(f"wrote {args.results_json}")
    if args.submission_yaml:
        Path(args.submission_yaml).write_text(render_submission_yaml(agg, args.title), encoding="utf-8")
        print(f"wrote {args.submission_yaml}")
    if not any((args.md, args.html, args.results_json, args.submission_yaml)):
        print(render_markdown(agg, args.title))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
