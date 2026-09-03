"""
report.py
---------
Builds a standalone, self-contained HTML report from an analysis result
dict. The report is plain HTML/CSS (no JS, no external resources) so it
can be saved, emailed, or printed without depending on the running server.
"""

import html


def esc(value):
    return html.escape(str(value)) if value is not None else ""


def _severity_color(sev):
    return {
        "critical": "#ff4d4f",
        "high": "#ffa940",
        "medium": "#ffd666",
        "low": "#95de64",
    }.get(sev, "#d9d9d9")


def _verdict_color(verdict):
    return {"HIGH": "#ff4d4f", "MEDIUM": "#faad14", "LOW": "#52c41a"}.get(verdict, "#999")


def build_html_report(result: dict) -> str:
    f = result["file"]
    pe = result["pe"]
    risk = result["risk"]
    findings = result["findings"]
    categories = result["categories"]
    sections = result.get("sections", [])
    imports = result.get("imports", {})
    iocs = result.get("iocs", {})

    findings_rows = "\n".join(
        f"""<tr>
            <td><span class="sev" style="background:{_severity_color(fnd['severity'])}">{esc(fnd['severity'].upper())}</span></td>
            <td>{esc(fnd['indicator'])}</td>
            <td>{esc(fnd['category'])}</td>
            <td>+{esc(fnd['score'])}</td>
            <td>{esc(fnd['message'])}<br><span class="muted">{esc(fnd['explanation'])}</span></td>
            <td class="muted">{esc(fnd['evidence'])}</td>
        </tr>"""
        for fnd in sorted(findings, key=lambda x: -x["score"])
    ) or "<tr><td colspan='6'>No suspicious indicators found.</td></tr>"

    category_rows = "\n".join(
        f"<tr><td>{esc(cat)}</td><td>{esc(pts)}</td></tr>"
        for cat, pts in sorted(categories.items(), key=lambda x: -x[1])
    ) or "<tr><td colspan='2'>None</td></tr>"

    section_rows = "\n".join(
        f"""<tr>
            <td>{esc(s['name'])}</td><td>{esc(s['raw_size'])}</td>
            <td>{esc(s['entropy'])}</td><td>{esc(s['permissions'])}</td>
            <td>{esc(s['status'])}</td>
        </tr>"""
        for s in sections
    ) or "<tr><td colspan='5'>Not a PE file / no sections</td></tr>"

    ioc_blocks = "\n".join(
        f"<h4>{esc(label.replace('_', ' ').title())}</h4><ul>" +
        "".join(f"<li>{esc(v)}</li>" for v in values) + "</ul>"
        for label, values in iocs.items()
    ) or "<p class='muted'>No static IOCs extracted.</p>"

    mitre_seen = {}
    for fnd in findings:
        for m in fnd.get("mitre", []):
            mitre_seen[m["technique_id"]] = m["technique_name"]
    mitre_rows = "\n".join(
        f"<tr><td>{esc(tid)}</td><td>{esc(name)}</td></tr>"
        for tid, name in sorted(mitre_seen.items())
    ) or "<tr><td colspan='2'>No techniques mapped</td></tr>"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Static Analysis Report - {esc(f['name'])}</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; background:#0d1117; color:#c9d1d9; padding:2rem; max-width:900px; margin:auto; }}
  h1,h2,h3 {{ color:#f0f6fc; }}
  .badge {{ display:inline-block; padding:2px 10px; border-radius:4px; background:#21262d; color:#8b949e; font-size:0.75rem; border:1px solid #30363d; }}
  .verdict {{ font-size:2rem; font-weight:bold; color:{_verdict_color(risk['verdict'])}; }}
  table {{ width:100%; border-collapse:collapse; margin:1rem 0; }}
  th, td {{ border:1px solid #30363d; padding:6px 10px; text-align:left; font-size:0.85rem; vertical-align:top; }}
  th {{ background:#161b22; }}
  .sev {{ padding:2px 8px; border-radius:4px; color:#111; font-weight:bold; font-size:0.7rem; }}
  .muted {{ color:#8b949e; font-size:0.8rem; }}
  .disclaimer {{ border:1px solid #30363d; background:#161b22; padding:1rem; border-radius:6px; margin-top:2rem; }}
  code {{ background:#161b22; padding:1px 4px; border-radius:3px; }}
</style>
</head>
<body>
  <span class="badge">STATIC ANALYSIS ONLY</span>
  <h1>🛡 Malware Static Analysis Report</h1>
  <p class="muted">Generated {esc(result['meta']['analyzed_at'])}</p>

  <h2>1. File Information</h2>
  <table>
    <tr><th>Name</th><td>{esc(f['name'])}</td></tr>
    <tr><th>Size</th><td>{esc(f['size'])} bytes</td></tr>
    <tr><th>SHA-256</th><td><code>{esc(f['sha256'])}</code></td></tr>
    <tr><th>Is PE</th><td>{esc(pe.get('is_pe'))}</td></tr>
  </table>

  <h2>2. Risk Assessment</h2>
  <p class="verdict">{esc(risk['verdict'])} RISK</p>
  <p>Raw score: {esc(risk['raw_score'])} &nbsp;|&nbsp; Normalized: {esc(risk['normalized_score'])}/100 &nbsp;|&nbsp; {esc(len(findings))} indicator(s)</p>
  <p class="muted">This is a heuristic classification based on detected static indicators, not a definitive malware determination.</p>

  <h2>3. PE Information</h2>
  <table>
    {"".join(f"<tr><th>{esc(k)}</th><td>{esc(v)}</td></tr>" for k, v in pe.items())}
  </table>

  <h2>4. Section Analysis</h2>
  <table>
    <tr><th>Section</th><th>Raw Size</th><th>Entropy</th><th>Permissions</th><th>Status</th></tr>
    {section_rows}
  </table>

  <h2>5. Import Analysis</h2>
  <p>Total imports: {esc(imports.get('total_imports', 0))} &nbsp;|&nbsp; Suspicious imports: {esc(imports.get('suspicious_imports', 0))}</p>

  <h2>6. Detection Category Breakdown</h2>
  <table>
    <tr><th>Category</th><th>Score Contribution</th></tr>
    {category_rows}
  </table>

  <h2>7. Findings</h2>
  <table>
    <tr><th>Severity</th><th>Indicator</th><th>Category</th><th>Score</th><th>Description</th><th>Evidence</th></tr>
    {findings_rows}
  </table>

  <h2>8. Indicators of Compromise (Static)</h2>
  {ioc_blocks}

  <h2>9. MITRE ATT&CK Mapping</h2>
  <table>
    <tr><th>Technique ID</th><th>Technique</th></tr>
    {mitre_rows}
  </table>

  <div class="disclaimer">
    <strong>Limitations and Disclaimer</strong>
    <p>This tool performs static heuristic analysis only and does not execute, detonate,
    or otherwise run the analyzed sample. A suspicious indicator is not proof that a file
    is malicious -- legitimate software can use the same APIs, strings, and packing
    techniques flagged here. Static analysis also cannot observe runtime-only or
    obfuscated behavior. Findings should be corroborated with dynamic/sandbox analysis
    and multi-engine AV scanning before any containment decision is made.</p>
  </div>
</body>
</html>"""
