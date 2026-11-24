"""
k8s-audit — security analysis of Kubernetes manifests.

Runs Trivy and Kubescape on a folder of manifests, merges their findings
and produces a report sorted by severity (Markdown, HTML, CSV, Excel).

Usage:
    python audit.py k8s/
    python audit.py k8s/ --fail-on HIGH --html reports/report.html
    python audit.py k8s/ --docker                            # no local install needed
    python audit.py data/commits --excel reports/results.xlsx  # one folder per commit
    python audit.py after/ --baseline before/                # before / after comparison
"""

import argparse
import csv
import json
import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

TRIVY_IMAGE = "aquasec/trivy:latest"
KUBESCAPE_IMAGE = "quay.io/kubescape/kubescape-cli:latest"

USE_DOCKER = False


@dataclass
class Finding:
    tool: str
    rule_id: str
    title: str
    severity: str
    file: str
    fix: str


# Running the tools

def check_tool(name: str) -> bool:
    needed = "docker" if USE_DOCKER else name
    if shutil.which(needed) is None:
        print(f"[!] {needed} not found in PATH, skipping {name}.", file=sys.stderr)
        return False
    return True


def docker_mount(target: Path) -> tuple[list[str], str]:
    """Mount the target's folder at /work and return the path as seen from the container."""
    target = target.resolve()
    folder = target if target.is_dir() else target.parent
    inside = "/work" if target.is_dir() else f"/work/{target.name}"
    return ["-v", f"{folder}:/work:ro"], inside


def run_trivy(target: Path) -> list[Finding]:
    """trivy config: detects misconfigurations (IaC, Kubernetes)."""
    if not check_tool("trivy"):
        return []
    print("[*] Trivy…" + (" (Docker)" if USE_DOCKER else ""))
    if USE_DOCKER:
        mount, inside = docker_mount(target)
        cmd = ["docker", "run", "--rm", *mount, "-v", "trivy-cache:/root/.cache/",
               TRIVY_IMAGE, "config", "--format", "json", "--quiet", inside]
    else:
        cmd = ["trivy", "config", "--format", "json", "--quiet", str(target)]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0 and not proc.stdout:
        print(f"[!] Trivy failed: {proc.stderr.strip()}", file=sys.stderr)
        return []
    return parse_trivy(json.loads(proc.stdout or "{}"))


def parse_trivy(data: dict) -> list[Finding]:
    findings = []
    for result in data.get("Results") or []:
        for m in result.get("Misconfigurations") or []:
            if m.get("Status", "FAIL") != "FAIL":
                continue
            findings.append(Finding(
                tool="Trivy",
                rule_id=m.get("ID", "?"),
                title=m.get("Title", m.get("Message", "")),
                severity=m.get("Severity", "LOW").upper(),
                file=result.get("Target", "?"),
                fix=m.get("Resolution", ""),
            ))
    return findings


def run_kubescape(target: Path) -> list[Finding]:
    """kubescape scan: security controls (NSA, MITRE, best practices)."""
    if not check_tool("kubescape"):
        return []
    print("[*] Kubescape…" + (" (Docker)" if USE_DOCKER else ""))
    with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as tmp:
        out = Path(tmp) / "kubescape.json"
        if USE_DOCKER:
            os.chmod(tmp, 0o777)
            mount, inside = docker_mount(target)
            cmd = ["docker", "run", "--rm", *mount, "-v", f"{Path(tmp).resolve()}:/out",
                   KUBESCAPE_IMAGE, "scan", inside, "--format", "json",
                   "--output", "/out/kubescape.json"]
        else:
            cmd = ["kubescape", "scan", str(target), "--format", "json",
                   "--output", str(out)]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        if not out.exists():
            print(f"[!] Kubescape failed: {proc.stderr.strip()}", file=sys.stderr)
            return []
        return parse_kubescape(json.loads(out.read_text()))


def score_to_severity(score: float) -> str:
    """Kubescape rates severity from 1 to 10 (scoreFactor)."""
    if score >= 9:
        return "CRITICAL"
    if score >= 7:
        return "HIGH"
    if score >= 4:
        return "MEDIUM"
    return "LOW"


def parse_kubescape(data: dict) -> list[Finding]:
    controls = data.get("summaryDetails", {}).get("controls", {})

    files = {}
    for res in data.get("resources") or []:
        src = res.get("source") or {}
        files[res.get("resourceID")] = src.get("relativePath") or src.get("path") or "?"

    findings = []
    for result in data.get("results") or []:
        rid = result.get("resourceID")
        for c in result.get("controls") or []:
            status = (c.get("status") or {}).get("status")
            if status != "failed":
                continue
            cid = c.get("controlID", "?")
            meta = controls.get(cid, {})
            findings.append(Finding(
                tool="Kubescape",
                rule_id=cid,
                title=c.get("name") or meta.get("name", ""),
                severity=score_to_severity(float(meta.get("scoreFactor", 0))),
                file=files.get(rid, "?"),
                fix=f"https://hub.armosec.io/docs/{cid.lower()}",
            ))
    return findings


# Merging and reporting

def deduplicate(findings: list[Finding]) -> list[Finding]:
    """The same issue can be reported several times for the same file."""
    seen, unique = set(), []
    for f in findings:
        key = (f.tool, f.rule_id, f.file)
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


def sort_key(f: Finding):
    sev = SEVERITIES.index(f.severity) if f.severity in SEVERITIES else len(SEVERITIES)
    return (sev, f.file, f.rule_id)


def count_by_severity(findings: list[Finding]) -> dict[str, int]:
    return {s: sum(1 for f in findings if f.severity == s) for s in SEVERITIES}


def write_report(findings: list[Finding], target: Path, output: Path,
                 comparison: dict | None = None) -> None:
    counts = count_by_severity(findings)
    lines = [
        "# Kubernetes Security Audit Report",
        "",
        f"- **Target:** `{target}`",
        f"- **Date:** {datetime.now():%Y-%m-%d %H:%M}",
        f"- **Findings:** {len(findings)}",
        "",
        "| Severity | Count |",
        "|---|---|",
        *[f"| {s} | {counts[s]} |" for s in SEVERITIES],
        "",
        *(comparison_markdown(comparison) if comparison else []),
        "## Details",
        "",
        "| Severity | Tool | Rule | Issue | File | Remediation |",
        "|---|---|---|---|---|---|",
    ]
    for f in findings:
        title = f.title.replace("|", "\\|")
        fix = f.fix.replace("|", "\\|").replace("\n", " ")
        lines.append(
            f"| {f.severity} | {f.tool} | `{f.rule_id}` | {title} | `{f.file}` | {fix} |"
        )
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("\n".join(lines) + "\n", encoding="utf-8")


def rel_path(file: str) -> str:
    """File path relative to the target, whatever the tool or Docker mode."""
    path = file.replace("\\", "/")
    for prefix in ("/work/", "./"):
        if path.startswith(prefix):
            path = path[len(prefix):]
    return path.strip("/")


def commit_of(file: str) -> str:
    """First folder of the path = commit ID."""
    path = rel_path(file)
    return path.split("/")[0] if "/" in path else "?"


def write_commit_summary(findings: list[Finding], target: Path, output: Path) -> None:
    """A CSV table: one row per commit, number of findings per severity."""
    commits = sorted(p.name for p in target.iterdir() if p.is_dir())
    rows = {c: {s: 0 for s in SEVERITIES} for c in commits}
    files = {c: set() for c in commits}
    for f in findings:
        c = commit_of(f.file)
        if c in rows and f.severity in SEVERITIES:
            rows[c][f.severity] += 1
            files[c].add(f.file.split("/")[-1])
    for c in commits:
        if not files[c]:
            files[c] = {p.name for p in (target / c).rglob("*.y*ml")}

    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["commit", "files", *SEVERITIES, "TOTAL"])
        for c in commits:
            counts = rows[c]
            w.writerow([c, " ".join(sorted(files[c])),
                        *[counts[s] for s in SEVERITIES], sum(counts.values())])
    print(f"Per-commit summary written to {output} ({len(commits)} commits)")


SEVERITY_COLORS = {"CRITICAL": "C0392B", "HIGH": "E67E22", "MEDIUM": "F1C40F", "LOW": "95A5A6"}


def rule_frequency(findings: list[Finding]) -> list[dict]:
    """Rules sorted by number of occurrences."""
    freq = {}
    for f in findings:
        key = (f.tool, f.rule_id)
        if key not in freq:
            freq[key] = {"tool": f.tool, "rule": f.rule_id, "title": f.title,
                         "severity": f.severity, "n": 0, "commits": set()}
        freq[key]["n"] += 1
        freq[key]["commits"].add(commit_of(f.file))
    order = lambda v: (-v["n"], SEVERITIES.index(v["severity"]) if v["severity"] in SEVERITIES else 9)
    return sorted(freq.values(), key=order)


def commit_counts(findings: list[Finding], target: Path) -> list[list]:
    """One row per commit [commit, CRITICAL, HIGH, MEDIUM, LOW, TOTAL], worst first."""
    commits = sorted(p.name for p in target.iterdir() if p.is_dir()) if target.is_dir() else []
    rows = {c: {s: 0 for s in SEVERITIES} for c in commits}
    for f in findings:
        c = commit_of(f.file)
        if c in rows and f.severity in SEVERITIES:
            rows[c][f.severity] += 1
    data = [[c, *[rows[c][s] for s in SEVERITIES], sum(rows[c].values())] for c in commits]
    data.sort(key=lambda r: (-r[-1], -r[1], -r[2]))
    return data


def write_excel(findings: list[Finding], target: Path, output: Path) -> None:
    """An Excel workbook: Summary, By commit, Rules, Details."""
    try:
        from openpyxl import Workbook
        from openpyxl.styles import Alignment, Font, PatternFill
        from openpyxl.utils import get_column_letter
    except ImportError:
        print("[!] openpyxl is missing: install it with  pip install openpyxl", file=sys.stderr)
        return

    wb = Workbook()
    bold = Font(bold=True, color="FFFFFF")
    head_fill = PatternFill("solid", fgColor="1F3A4D")

    def table(ws, headers, rows, widths):
        ws.append(headers)
        for cell in ws[1]:
            cell.font, cell.fill = bold, head_fill
            cell.alignment = Alignment(vertical="center")
        for r in rows:
            ws.append(r)
        for i, w in enumerate(widths, start=1):
            ws.column_dimensions[get_column_letter(i)].width = w
        ws.freeze_panes = "A2"
        if rows:
            ws.auto_filter.ref = ws.dimensions

    def color_severity(ws, col):
        for row in ws.iter_rows(min_row=2, min_col=col, max_col=col):
            c = row[0]
            if c.value in SEVERITY_COLORS:
                c.fill = PatternFill("solid", fgColor=SEVERITY_COLORS[c.value])
                c.font = Font(bold=True, color="000000" if c.value == "MEDIUM" else "FFFFFF")

    # 1. Summary
    ws = wb.active
    ws.title = "Summary"
    counts = count_by_severity(findings)
    by_tool = {t: sum(1 for f in findings if f.tool == t) for t in ("Trivy", "Kubescape")}
    table(ws, ["Metric", "Value"], [
        ["Target", str(target)],
        ["Date", f"{datetime.now():%Y-%m-%d %H:%M}"],
        *[[f"{s} findings", counts[s]] for s in SEVERITIES],
        ["Total findings", len(findings)],
        *[[f"Found by {t}", n] for t, n in by_tool.items()],
    ], [28, 40])

    # 2. By commit (when the target holds one folder per commit)
    data = commit_counts(findings, target)
    if data:
        table(wb.create_sheet("By commit"), ["Commit", *SEVERITIES, "TOTAL"], data,
              [44, 11, 11, 11, 11, 11])

    # 3. Most frequent rules
    ws = wb.create_sheet("Rules")
    table(ws, ["Tool", "Rule", "Issue", "Severity", "Occurrences", "Commits affected"],
          [[r["tool"], r["rule"], r["title"], r["severity"], r["n"], len(r["commits"] - {"?"})]
           for r in rule_frequency(findings)],
          [12, 14, 60, 12, 13, 17])
    color_severity(ws, 4)

    # 4. Full details
    ws = wb.create_sheet("Details")
    table(ws, ["Severity", "Tool", "Rule", "Issue", "Commit", "File", "Remediation"],
          [[f.severity, f.tool, f.rule_id, f.title, commit_of(f.file),
            f.file.split("/")[-1], f.fix] for f in findings],
          [12, 12, 14, 55, 44, 28, 70])
    color_severity(ws, 1)

    output.parent.mkdir(parents=True, exist_ok=True)
    wb.save(output)
    print(f"Excel workbook written to {output}")


# HTML report

def write_html(findings: list[Finding], target: Path, output: Path,
               comparison: dict | None = None) -> None:
    """A self-contained HTML report: summary, comparison, commits, rules, filterable details."""
    from html import escape as e

    counts = count_by_severity(findings)
    tiles = "".join(
        f'<div class="tile sev-{s.lower()}"><span>{s}</span><strong>{counts[s]}</strong></div>'
        for s in SEVERITIES)
    tiles += f'<div class="tile total"><span>TOTAL</span><strong>{len(findings)}</strong></div>'

    def badge(sev):
        return f'<span class="badge sev-{e(sev.lower())}">{e(sev)}</span>'

    def link(fix):
        return f'<a href="{e(fix)}">Documentation</a>' if fix.startswith("http") else e(fix)

    sections = []

    if comparison:
        sections.append(f"""
<section><h2>Comparison with baseline</h2>
<p class="muted">Baseline: <code>{e(str(comparison['baseline']))}</code></p>
<div class="tiles">
  <div class="tile good"><span>Fixed</span><strong>{len(comparison['fixed'])}</strong></div>
  <div class="tile bad"><span>New</span><strong>{len(comparison['new'])}</strong></div>
  <div class="tile"><span>Remaining</span><strong>{len(comparison['remaining'])}</strong></div>
</div></section>""")

    commits = commit_counts(findings, target)
    if commits:
        rows = "".join(
            f"<tr><td><code>{e(r[0])}</code></td>" +
            "".join(f'<td class="num">{n}</td>' for n in r[1:]) + "</tr>"
            for r in commits)
        sections.append(f"""
<section><h2>By commit <span class="muted">({len(commits)})</span></h2>
<div class="scroll"><table><thead><tr><th>Commit</th>{''.join(f'<th class="num">{s}</th>' for s in SEVERITIES)}<th class="num">TOTAL</th></tr></thead>
<tbody>{rows}</tbody></table></div></section>""")

    rules = rule_frequency(findings)
    if rules:
        rows = "".join(
            f"<tr><td>{badge(r['severity'])}</td><td>{e(r['tool'])}</td><td><code>{e(r['rule'])}</code></td>"
            f"<td>{e(r['title'])}</td><td class=\"num\">{r['n']}</td>"
            f"<td class=\"num\">{len(r['commits'] - {'?'})}</td></tr>"
            for r in rules[:25])
        sections.append(f"""
<section><h2>Most frequent rules</h2>
<div class="scroll"><table><thead><tr><th>Severity</th><th>Tool</th><th>Rule</th><th>Issue</th>
<th class="num">Occurrences</th><th class="num">Commits</th></tr></thead><tbody>{rows}</tbody></table></div></section>""")

    rows = "".join(
        f'<tr data-sev="{e(f.severity)}"><td>{badge(f.severity)}</td><td>{e(f.tool)}</td>'
        f"<td><code>{e(f.rule_id)}</code></td><td>{e(f.title)}</td>"
        f"<td><code>{e(rel_path(f.file))}</code></td><td>{link(f.fix)}</td></tr>"
        for f in findings)
    buttons = "".join(f'<button type="button" data-f="{s}">{s}</button>' for s in SEVERITIES)
    sections.append(f"""
<section><h2>Details</h2>
<div class="filters"><button type="button" data-f="ALL" class="on">All</button>{buttons}
<label class="sr" for="q">Search</label><input id="q" type="search" placeholder="Search a rule, a file…"></div>
<div class="scroll"><table id="detail"><thead><tr><th>Severity</th><th>Tool</th><th>Rule</th><th>Issue</th>
<th>File</th><th>Remediation</th></tr></thead><tbody>{rows}</tbody></table></div>
<p class="muted" id="shown"></p></section>""")

    page = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Kubernetes Audit</title>
<style>
:root{{--bg:#F6F7F6;--card:#FFF;--fg:#1B1E1D;--muted:#5D6461;--line:#E2E5E3;--accent:#1F6F68;
--crit:#B3261E;--high:#C2560C;--med:#9A7400;--low:#5D6461;--good:#1E7A46}}
@media (prefers-color-scheme:dark){{:root{{--bg:#131615;--card:#1B1F1E;--fg:#E5E8E6;--muted:#9AA29E;
--line:#2C3230;--accent:#5FBFB4;--crit:#F2827A;--high:#F0A060;--med:#E3C05A;--low:#A3ABA7;--good:#6CCB92}}}}
*{{box-sizing:border-box}}
body{{margin:0;background:var(--bg);color:var(--fg);font:15px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif}}
main{{max-width:1180px;margin:0 auto;padding:40px 16px;display:flex;flex-direction:column;gap:20px}}
h1{{margin:0;font-size:26px}} h2{{margin:0 0 14px;font-size:18px}}
section,header{{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:24px}}
.muted{{color:var(--muted);font-weight:400}}
code{{font:13px ui-monospace,SFMono-Regular,Menlo,monospace}}
.tiles{{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin-top:16px}}
.tile{{border:1px solid var(--line);border-radius:10px;padding:14px 16px;display:flex;flex-direction:column;gap:2px}}
.tile span{{font-size:12px;letter-spacing:.05em;color:var(--muted)}}
.tile strong{{font-size:28px;font-variant-numeric:tabular-nums}}
.sev-critical strong,.badge.sev-critical{{color:var(--crit)}} .sev-high strong,.badge.sev-high{{color:var(--high)}}
.sev-medium strong,.badge.sev-medium{{color:var(--med)}} .sev-low strong,.badge.sev-low{{color:var(--low)}}
.good strong{{color:var(--good)}} .bad strong{{color:var(--crit)}}
.badge{{font:600 12px ui-monospace,monospace;border:1px solid currentColor;border-radius:6px;padding:1px 7px}}
.scroll{{overflow-x:auto}}
table{{width:100%;border-collapse:collapse;font-size:14px}}
th,td{{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}}
th{{font-size:12px;letter-spacing:.04em;color:var(--muted);position:sticky;top:0;background:var(--card)}}
.num{{text-align:right;font-variant-numeric:tabular-nums}}
a{{color:var(--accent)}}
.filters{{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:12px}}
.filters button{{font:inherit;font-size:13px;min-height:36px;padding:0 14px;border-radius:999px;border:1px solid var(--line);background:var(--card);color:var(--fg);cursor:pointer}}
.filters button.on{{border-color:var(--accent);color:var(--accent);font-weight:600}}
.filters input{{font:inherit;flex:1 1 220px;min-height:36px;padding:0 12px;border-radius:8px;border:1px solid var(--line);background:var(--bg);color:var(--fg)}}
.sr{{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0)}}
</style></head><body><main>
<header><h1>Kubernetes Security Audit</h1>
<p class="muted">Target: <code>{e(str(target))}</code> · {datetime.now():%Y-%m-%d %H:%M} · Trivy + Kubescape</p>
<div class="tiles">{tiles}</div></header>
{''.join(sections)}
</main>
<script>
(function(){{
  var rows=[].slice.call(document.querySelectorAll('#detail tbody tr'));
  var btns=[].slice.call(document.querySelectorAll('.filters button'));
  var q=document.getElementById('q'), shown=document.getElementById('shown'), sev='ALL';
  function apply(){{
    var t=q.value.toLowerCase(), n=0;
    rows.forEach(function(r){{
      var ok=(sev==='ALL'||r.dataset.sev===sev)&&(!t||r.textContent.toLowerCase().indexOf(t)>-1);
      r.hidden=!ok; if(ok)n++;
    }});
    shown.textContent='Showing '+n+' of '+rows.length+' findings';
  }}
  btns.forEach(function(b){{b.addEventListener('click',function(){{
    sev=b.dataset.f; btns.forEach(function(x){{x.classList.toggle('on',x===b)}}); apply();
  }})}});
  q.addEventListener('input',apply); apply();
}})();
</script></body></html>"""
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(page, encoding="utf-8")
    print(f"HTML report written to {output}")


# Before / after comparison

def compare(before: list[Finding], after: list[Finding], baseline: Path) -> dict:
    """Fixed (gone), new (appeared) and remaining findings."""
    key = lambda f: (f.tool, f.rule_id, rel_path(f.file))
    b = {key(f): f for f in before}
    a = {key(f): f for f in after}
    return {
        "baseline": baseline,
        "fixed": sorted((b[k] for k in b.keys() - a.keys()), key=sort_key),
        "new": sorted((a[k] for k in a.keys() - b.keys()), key=sort_key),
        "remaining": sorted((a[k] for k in a.keys() & b.keys()), key=sort_key),
    }


def comparison_markdown(comp: dict) -> list[str]:
    lines = [
        "## Comparison with baseline",
        "",
        f"- **Baseline:** `{comp['baseline']}`",
        f"- **Fixed:** {len(comp['fixed'])}",
        f"- **New:** {len(comp['new'])}",
        f"- **Remaining:** {len(comp['remaining'])}",
        "",
    ]
    if comp["new"]:
        lines += ["### New findings", "",
                  "| Severity | Tool | Rule | Issue | File |", "|---|---|---|---|---|"]
        lines += [f"| {f.severity} | {f.tool} | `{f.rule_id}` | {f.title.replace('|', '/')} | `{rel_path(f.file)}` |"
                  for f in comp["new"]]
        lines.append("")
    return lines


def write_step_summary(findings: list[Finding], comp: dict | None) -> None:
    """In GitHub Actions: show a summary directly on the job page."""
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not path:
        return
    counts = count_by_severity(findings)
    lines = ["## Kubernetes Security Audit", "",
             "| Severity | Findings |", "|---|---|",
             *[f"| {s} | {counts[s]} |" for s in SEVERITIES],
             f"| **Total** | **{len(findings)}** |", ""]
    if comp:
        lines += comparison_markdown(comp)
    top = rule_frequency(findings)[:10]
    if top:
        lines += ["### Most frequent rules", "",
                  "| Severity | Rule | Issue | Occurrences |", "|---|---|---|---|",
                  *[f"| {r['severity']} | `{r['rule']}` | {r['title'].replace('|', '/')} | {r['n']} |" for r in top]]
    with open(path, "a", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


def print_summary(findings: list[Finding]) -> None:
    counts = count_by_severity(findings)
    print("\nSummary:")
    for s in SEVERITIES:
        print(f"  {s:<9} {counts[s]}")
    print(f"  {'TOTAL':<9} {len(findings)}")


# --------------------------------------------------------------------------

def scan(target: Path) -> list[Finding]:
    findings = deduplicate(run_trivy(target) + run_kubescape(target))
    findings.sort(key=sort_key)
    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description="Security audit of Kubernetes manifests")
    parser.add_argument("target", type=Path, help="Folder or file of manifests")
    parser.add_argument("-o", "--output", type=Path, default=Path("reports/report.md"))
    parser.add_argument("--fail-on", choices=[*SEVERITIES, "NONE"], default="CRITICAL",
                        help="Exit with code 1 if a finding of this severity or higher is found "
                             "(NONE: never fail)")
    parser.add_argument("--html", type=Path, metavar="HTML",
                        help="Also write an HTML report")
    parser.add_argument("--baseline", type=Path, metavar="DIR",
                        help="Baseline version (before) to compare the target (after) against")
    parser.add_argument("--by-commit", type=Path, metavar="CSV",
                        help="The target holds one folder per commit: write a per-commit CSV summary")
    parser.add_argument("--excel", type=Path, metavar="XLSX",
                        help="Also write an Excel workbook (Summary, By commit, Rules, Details)")
    parser.add_argument("--docker", action="store_true",
                        help="Run Trivy and Kubescape in Docker instead of local binaries")
    args = parser.parse_args()

    global USE_DOCKER
    USE_DOCKER = args.docker or (
        shutil.which("trivy") is None and shutil.which("kubescape") is None
        and shutil.which("docker") is not None
    )

    if not args.target.exists():
        print(f"[!] {args.target} does not exist.", file=sys.stderr)
        return 2

    if args.baseline and not args.baseline.exists():
        print(f"[!] {args.baseline} does not exist.", file=sys.stderr)
        return 2

    findings = scan(args.target)

    comparison = None
    if args.baseline:
        print(f"[*] Scanning baseline {args.baseline}…")
        comparison = compare(scan(args.baseline), findings, args.baseline)

    write_report(findings, args.target, args.output, comparison)
    if args.by_commit:
        write_commit_summary(findings, args.target, args.by_commit)
    if args.excel:
        write_excel(findings, args.target, args.excel)
    if args.html:
        write_html(findings, args.target, args.html, comparison)
    write_step_summary(findings, comparison)

    print_summary(findings)
    if comparison:
        print(f"\nCompared with {args.baseline}:")
        print(f"  Fixed      {len(comparison['fixed'])}")
        print(f"  New        {len(comparison['new'])}")
        print(f"  Remaining  {len(comparison['remaining'])}")
    print(f"\nReport written to {args.output}")

    if args.fail_on == "NONE":
        return 0
    threshold = SEVERITIES[: SEVERITIES.index(args.fail_on) + 1]
    if any(f.severity in threshold for f in findings):
        print(f"[x] Findings of severity {args.fail_on} or higher detected.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
