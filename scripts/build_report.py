#!/usr/bin/env python3
"""
psycho-agents report builder: findings.json -> self-contained HTML dashboard.

Usage:
    python build_report.py findings.json -o audit.html
    python build_report.py findings.json -o audit.html --validate-only

The dashboard is a single file (inline CSS, zero external assets) so it can be
emailed, committed, or archived. Payloads contain HTML metacharacters by
design — everything is escaped.
"""
import argparse
import html
import json
import sys
from datetime import datetime

SEV_STYLE = {
    "P0": ("#ff4d4d", "P0 — critical"),
    "P1": ("#ff9e2c", "P1 — high"),
    "P2": ("#ffd166", "P2 — medium"),
    "P3": ("#4d9fff", "P3 — low"),
    "P4": ("#3ddc84", "P4 — hardening / passing"),
}
STATUS_STYLE = {
    "executed": "#3ddc84", "skipped": "#8a8f98", "untested": "#ffd166",
    "blocked": "#ff9e2c", "pass": "#3ddc84", "fail": "#ff4d4d",
}

def esc(s):
    return html.escape(str(s if s is not None else ""), quote=True)

def _truncate(s, n=4000):
    s = str(s or "")
    return s if len(s) <= n else s[: n - 3] + "..."

def validate(data):
    """Structural validation with actionable messages."""
    errors, warnings = [], []
    for key in ("audit_meta", "findings", "agent_log"):
        if key not in data:
            errors.append(f"missing top-level key: {key}")
    if errors:
        return errors, warnings
    meta = data["audit_meta"]
    for key in ("target", "authorization_confirmed"):
        if key not in meta:
            errors.append(f"audit_meta missing: {key}")
    if meta.get("authorization_confirmed") is not True:
        warnings.append("authorization_confirmed is not true — the consent gate is mandatory; set it only with the user's actual statement in consent_evidence")
    sev_counts = {}
    for i, f in enumerate(data["findings"]):
        fid = f.get("id", f"finding[{i}]")
        for key in ("agent", "agent_key", "title", "severity", "confidence", "invariant_violated"):
            if not f.get(key):
                errors.append(f"{fid}: missing required field '{key}'")
        if f.get("severity") not in SEV_STYLE:
            errors.append(f"{fid}: severity must be one of P0..P4, got {f.get('severity')!r}")
        if f.get("confidence") not in ("confirmed", "code-audit", "hypothesis"):
            errors.append(f"{fid}: confidence must be confirmed|code-audit|hypothesis")
        if not f.get("repro_steps"):
            warnings.append(f"{fid}: no repro_steps — a finding without reproduction is a hypothesis")
        if not f.get("evidence"):
            warnings.append(f"{fid}: no evidence recorded")
        sev_counts[f.get("severity")] = sev_counts.get(f.get("severity"), 0) + 1
    keys = [a.get("agent_key") for a in data["agent_log"]]
    expected = [f"T1-{i}" for i in range(1, 14)] + [f"T2-{i}" for i in range(1, 11)]
    missing = [k for k in expected if k not in keys]
    if missing:
        errors.append(f"agent_log missing {len(missing)} agent(s): {', '.join(missing)} — every one of the 23 must have a status (skipped is fine)")
    return errors, warnings

def _stat_card(label, value, color):
    return f'<div class="stat"><div class="stat-v" style="color:{color}">{esc(value)}</div><div class="stat-l">{esc(label)}</div></div>'

def _finding_card(f):
    sev = f.get("severity", "P4")
    color, label = SEV_STYLE.get(sev, SEV_STYLE["P4"])
    steps = "".join(f"<li>{esc(s)}</li>" for s in (f.get("repro_steps") or []))
    fix = f.get("fix") or {}
    fix_code = fix.get("code") or ""
    conf = f.get("confidence", "hypothesis")
    return f"""
<article class="finding" id="{esc(f.get('id',''))}">
  <div class="f-head">
    <span class="sev-badge" style="background:{color}22;color:{color};border:1px solid {color}55">{esc(sev)}</span>
    <span class="f-id">{esc(f.get('id',''))}</span>
    <span class="f-agent">{esc(f.get('agent',''))} <span class="tier">T{esc(f.get('tier','?'))}</span></span>
    <span class="conf conf-{esc(conf)}">{esc(conf)}</span>
  </div>
  <h3 class="f-title">{esc(f.get('title',''))}</h3>
  <div class="f-meta">
    <div><span class="k">Documented sibling</span>{esc(f.get('precedent',''))}</div>
    <div><span class="k">Mechanism</span>{esc(f.get('mechanism',''))}</div>
    <div><span class="k">Where</span><code>{esc(f.get('location',''))}</code></div>
    <div><span class="k">Invariant violated</span><strong>{esc(f.get('invariant_violated',''))}</strong></div>
  </div>
  <div class="f-body">
    <div class="f-col">
      <h4>Reproduction</h4>
      <ol class="repro">{steps}</ol>
      <h4>Payload</h4>
      <pre class="payload">{esc(_truncate(f.get('payload',''), 2000))}</pre>
    </div>
    <div class="f-col">
      <h4>Impact</h4>
      <p>{esc(f.get('impact',''))}</p>
      <h4>Evidence</h4>
      <pre class="evidence">{esc(_truncate(f.get('evidence',''), 3000))}</pre>
      <h4>Fix</h4>
      <p>{esc(fix.get('summary',''))}</p>
      {f'<pre class="fixcode">{esc(fix_code)}</pre>' if fix_code else ''}
    </div>
  </div>
</article>"""

def _invariant_matrix(rows):
    if not rows:
        return ""
    tr = []
    for r in rows:
        st = (r.get("status") or "untested").lower()
        c = STATUS_STYLE.get(st, "#8a8f98")
        agents = ", ".join(r.get("agents") or [])
        tr.append(f'<tr><td class="inv">{esc(r.get("invariant",""))}</td><td class="mono">{esc(agents)}</td>'
                  f'<td><span class="pill" style="color:{c};border-color:{c}55">{esc(st)}</span></td>'
                  f'<td class="note">{esc(r.get("notes",""))}</td></tr>')
    return f'<section id="invariants"><h2>Invariant Matrix — what the system promised vs. what it kept</h2><table class="matrix"><thead><tr><th>Invariant</th><th>Agents</th><th>Status</th><th>Notes</th></tr></thead><tbody>{"".join(tr)}</tbody></table></section>'

def _agent_log(log):
    tr = []
    for a in log:
        st = a.get("status", "untested")
        c = STATUS_STYLE.get(st, "#8a8f98")
        reason = a.get("reason") or ""
        n = a.get("findings", 0)
        tr.append(f'<tr><td>{esc(a.get("agent_key",""))}</td><td>{esc(a.get("agent",""))}</td>'
                  f'<td><span class="pill" style="color:{c};border-color:{c}55">{esc(st)}</span></td>'
                  f'<td class="mono">{n}</td><td class="note">{esc(reason)}</td></tr>')
    return f'<section id="agents"><h2>Agent Log — all 23</h2><table class="matrix"><thead><tr><th>Key</th><th>Agent</th><th>Status</th><th>Findings</th><th>Reason / notes</th></tr></thead><tbody>{"".join(tr)}</tbody></table></section>'

def build_html(data):
    meta = data.get("audit_meta", {})
    findings = data.get("findings", [])
    sev_n = {s: sum(1 for f in findings if f.get("severity") == s) for s in SEV_STYLE}
    log = data.get("agent_log", [])
    st_n = {s: sum(1 for a in log if a.get("status") == s) for s in ("executed", "skipped", "untested", "blocked")}
    inv = data.get("invariant_matrix", [])
    inv_fail = sum(1 for r in inv if (r.get("status") or "").lower() == "fail")
    inv_pass = sum(1 for r in inv if (r.get("status") or "").lower() == "pass")

    try:
        t0 = datetime.fromisoformat(meta.get("started", ""))
        t1 = datetime.fromisoformat(meta.get("completed", ""))
        dur = f"{(t1 - t0).total_seconds() / 60:.0f} min"
    except Exception:
        dur = "—"

    cards = "".join([
        _stat_card("P0 critical", sev_n.get("P0", 0), SEV_STYLE["P0"][0]),
        _stat_card("P1 high", sev_n.get("P1", 0), SEV_STYLE["P1"][0]),
        _stat_card("P2 medium", sev_n.get("P2", 0), SEV_STYLE["P2"][0]),
        _stat_card("P3 low", sev_n.get("P3", 0), SEV_STYLE["P3"][0]),
        _stat_card("P4 hardening", sev_n.get("P4", 0), SEV_STYLE["P4"][0]),
        _stat_card("agents executed", st_n.get("executed", 0), "#e6e6e6"),
        _stat_card("agents skipped", st_n.get("skipped", 0), "#8a8f98"),
        _stat_card("invariants failed", inv_fail, "#ff4d4d"),
    ])

    order = {"P0": 0, "P1": 1, "P2": 2, "P3": 3, "P4": 4}
    grouped = {}
    for f in sorted(findings, key=lambda x: (order.get(x.get("severity"), 9), x.get("id", ""))):
        grouped.setdefault(f.get("severity", "P4"), []).append(f)
    finding_sections = []
    for sev in ("P0", "P1", "P2", "P3", "P4"):
        if sev in grouped:
            color, label = SEV_STYLE[sev]
            cards_html = "".join(_finding_card(f) for f in grouped[sev])
            finding_sections.append(
                f'<section class="sev-group" data-sev="{sev}"><h2 style="color:{color}">{label} <span class="count">{len(grouped[sev])}</span></h2>{cards_html}</section>')
    findings_html = "".join(finding_sections) or '<section><h2>No findings recorded</h2><p>Either the target is remarkably solid, or the audit stopped early — check the agent log for skipped/untested statuses.</p></section>'

    auth = meta.get("authorization_confirmed")
    auth_html = (f'<span class="pill" style="color:#3ddc84;border-color:#3ddc8455">authorization confirmed</span>'
                 if auth else '<span class="pill" style="color:#ff4d4d;border-color:#ff4d4d55">AUTHORIZATION NOT CONFIRMED</span>')

    surface_map = data.get("surface_map") or []
    surfaces_html = "".join(
        f'<tr><td class="mono">{esc(s.get("surface",""))}</td><td class="mono">{esc(s.get("type",""))}</td><td class="note">{esc(s.get("flows_to",""))}</td></tr>'
        for s in surface_map)
    surfaces_tbl = (f'<section id="surfaces"><h2>Surface Map</h2><table class="matrix"><thead><tr><th>Surface</th><th>Type</th><th>Flows into</th></tr></thead><tbody>{surfaces_html}</tbody></table></section>'
                    if surfaces_html else "")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Psycho Agents Audit — {esc(meta.get('target', 'target'))}</title>
<style>
  :root {{ color-scheme: dark; }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: #0d1117; color: #e6edf3; font: 15px/1.6 -apple-system, 'Segoe UI', Roboto, 'Noto Sans', sans-serif; padding: 0 0 80px; }}
  .wrap {{ max-width: 1100px; margin: 0 auto; padding: 0 28px; }}
  header {{ border-bottom: 1px solid #21262d; padding: 34px 0 22px; margin-bottom: 26px; }}
  header h1 {{ font-size: 26px; letter-spacing: -0.5px; margin-bottom: 10px; }}
  header h1 .ghost {{ color: #8a8f98; font-weight: 400; }}
  .meta-line {{ color: #8a8f98; font-size: 13px; margin-top: 4px; }}
  .meta-line code {{ color: #e6edf3; }}
  .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 12px; margin: 22px 0 34px; }}
  .stat {{ background: #161b22; border: 1px solid #21262d; border-radius: 10px; padding: 14px 16px; }}
  .stat-v {{ font-size: 30px; font-weight: 700; line-height: 1.1; }}
  .stat-l {{ color: #8a8f98; font-size: 12px; text-transform: uppercase; letter-spacing: 0.6px; margin-top: 3px; }}
  h2 {{ font-size: 19px; margin: 34px 0 14px; letter-spacing: -0.3px; }}
  h2 .count {{ color: #8a8f98; font-weight: 400; }}
  .finding {{ background: #161b22; border: 1px solid #21262d; border-radius: 12px; padding: 20px 22px; margin-bottom: 18px; }}
  .f-head {{ display: flex; gap: 12px; align-items: center; flex-wrap: wrap; margin-bottom: 8px; font-size: 13px; }}
  .sev-badge {{ padding: 2px 10px; border-radius: 20px; font-weight: 700; font-size: 12px; }}
  .f-id {{ color: #8a8f98; font-family: ui-monospace, monospace; }}
  .f-agent {{ color: #e6edf3; font-weight: 600; }}
  .f-agent .tier {{ color: #8a8f98; font-weight: 400; font-family: ui-monospace, monospace; font-size: 11px; }}
  .conf {{ margin-left: auto; font-size: 11px; padding: 2px 8px; border-radius: 10px; border: 1px solid #30363d; color: #8a8f98; }}
  .conf-confirmed {{ color: #3ddc84; border-color: #3ddc8455; }}
  .conf-code-audit {{ color: #4d9fff; border-color: #4d9fff55; }}
  .f-title {{ font-size: 17px; margin-bottom: 12px; letter-spacing: -0.2px; }}
  .f-meta div {{ margin: 3px 0; font-size: 13.5px; color: #c9d1d9; }}
  .f-meta .k {{ display: inline-block; min-width: 150px; color: #8a8f98; font-size: 12px; }}
  .f-meta code {{ background: #21262d; padding: 1px 6px; border-radius: 5px; font-size: 12.5px; }}
  .f-body {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-top: 14px; }}
  @media (max-width: 860px) {{ .f-body {{ grid-template-columns: 1fr; }} }}
  .f-body h4 {{ font-size: 12px; text-transform: uppercase; letter-spacing: 0.7px; color: #8a8f98; margin: 12px 0 6px; }}
  .f-body h4:first-child {{ margin-top: 0; }}
  .repro {{ padding-left: 20px; }}
  .repro li {{ margin: 4px 0; font-size: 13.5px; }}
  pre {{ background: #0d1117; border: 1px solid #21262d; border-radius: 8px; padding: 10px 12px; overflow-x: auto; white-space: pre-wrap; word-break: break-all; font: 12.5px/1.5 ui-monospace, 'Cascadia Code', monospace; }}
  pre.payload {{ color: #ffa657; }}
  pre.evidence {{ color: #7ee787; }}
  pre.fixcode {{ color: #79c0ff; }}
  table.matrix {{ width: 100%; border-collapse: collapse; font-size: 13.5px; }}
  table.matrix th {{ text-align: left; color: #8a8f98; font-size: 11.5px; text-transform: uppercase; letter-spacing: 0.6px; padding: 8px 10px; border-bottom: 1px solid #30363d; }}
  table.matrix td {{ padding: 9px 10px; border-bottom: 1px solid #21262d; vertical-align: top; }}
  td.inv {{ font-weight: 600; max-width: 300px; }}
  td.mono {{ font-family: ui-monospace, monospace; font-size: 12.5px; }}
  td.note {{ color: #c9d1d9; }}
  .pill {{ display: inline-block; padding: 1px 9px; border: 1px solid #30363d; border-radius: 12px; font-size: 12px; font-weight: 600; }}
  footer {{ margin-top: 60px; color: #484f58; font-size: 12.5px; border-top: 1px solid #21262d; padding-top: 18px; }}
</style>
</head>
<body>
<div class="wrap">
<header>
  <h1>Psycho Agents Audit <span class="ghost">— extreme edge cases, documented failure classes</span></h1>
  <div class="meta-line">Target: <code>{esc(meta.get('target', '—'))}</code> · type {esc(meta.get('target_type', '—'))} · {esc(dur)} · {esc(meta.get('started', '—'))} → {esc(meta.get('completed', '—'))}</div>
  <div class="meta-line">{auth_html} · <span title="consent evidence">{esc(meta.get('consent_evidence', ''))}</span></div>
  <div class="meta-line">Surfaces: {esc(meta.get('surface_summary', '—'))}</div>
</header>
<div class="stats">{cards}</div>
{surfaces_tbl}
{findings_html}
{_invariant_matrix(inv)}
{_agent_log(log)}
<footer>Generated by psycho-agents skill · {esc(meta.get('auditor', ''))} · {esc(datetime.now().isoformat(timespec='seconds'))} · Findings are attributed to documented failure classes; invariant violations are the audit's ground truth.</footer>
</div>
</body>
</html>"""

def main():
    ap = argparse.ArgumentParser(description="psycho-agents findings.json to HTML dashboard")
    ap.add_argument("findings", help="path to findings.json")
    ap.add_argument("-o", "--out", help="output HTML path (default: alongside findings)")
    ap.add_argument("--validate-only", action="store_true")
    args = ap.parse_args()

    with open(args.findings, encoding="utf-8") as f:
        data = json.load(f)

    errors, warnings = validate(data)
    for w in warnings:
        print(f"WARNING: {w}", file=sys.stderr)
    if errors:
        for e in errors:
            print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(f"validation failed with {len(errors)} error(s) — fix findings.json first")

    print(f"validation OK: {len(data.get('findings', []))} findings, "
          f"{sum(1 for a in data.get('agent_log', []) if a.get('status') == 'executed')} agents executed, "
          f"{len(warnings)} warning(s)")

    if args.validate_only:
        return
    out = args.out or args.findings.rsplit(".", 1)[0] + ".html"
    with open(out, "w", encoding="utf-8") as f:
        f.write(build_html(data))
    print(f"wrote {out}")

if __name__ == "__main__":
    main()
