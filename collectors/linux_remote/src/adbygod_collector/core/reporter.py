#!/usr/bin/env python3
"""
AdByG0d - Report Generator
Generates beautiful HTML reports with all findings.
"""

import os
import json
from datetime import datetime
from .banner import success


class Finding:
    """Represents a single security finding."""

    def __init__(self, module, severity, title, description="", details=None,
                 remediation="", affected=None, references=None):
        self.module = module
        self.severity = severity  # CRITICAL, HIGH, MEDIUM, LOW, INFO
        self.title = title
        self.description = description
        self.details = details or {}
        self.remediation = remediation
        self.affected = affected or []
        self.references = references or []
        self.timestamp = datetime.now().isoformat()

    def to_dict(self):
        return {
            "module": self.module,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "details": self.details,
            "remediation": self.remediation,
            "affected": self.affected[:50],  # Cap for report size
            "references": self.references,
            "timestamp": self.timestamp,
        }


class Reporter:
    """Collects findings and generates reports."""

    def __init__(self, domain, output_dir="reports"):
        self.domain = domain
        self.output_dir = output_dir
        self.findings = []
        self.scan_start = datetime.now()
        self.scan_end = None
        self.modules_run = []

        os.makedirs(output_dir, exist_ok=True)

    def add_finding(self, finding):
        """Add a finding to the report."""
        self.findings.append(finding)

    def add(self, module, severity, title, description="", details=None,
            remediation="", affected=None, references=None):
        """Shorthand to create and add a finding."""
        f = Finding(module, severity, title, description, details,
                    remediation, affected, references)
        self.findings.append(f)
        return f

    def get_stats(self):
        """Get finding statistics."""
        stats = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in self.findings:
            key = f.severity.lower()
            if key in stats:
                stats[key] += 1
        stats["total"] = len(self.findings)
        stats["modules"] = len(self.modules_run)
        if self.scan_end:
            duration = self.scan_end - self.scan_start
            stats["duration"] = str(duration).split('.')[0]
        else:
            stats["duration"] = "N/A"
        return stats

    def generate_json(self):
        """Generate JSON report."""
        self.scan_end = datetime.now()
        report = {
            "tool": "AdByG0d",
            "version": "1.0.0",
            "domain": self.domain,
            "scan_start": self.scan_start.isoformat(),
            "scan_end": self.scan_end.isoformat(),
            "statistics": self.get_stats(),
            "findings": [f.to_dict() for f in self.findings],
        }

        filename = os.path.join(
            self.output_dir,
            f"adbygod_{self.domain}_{self.scan_start.strftime('%Y%m%d_%H%M%S')}.json"
        )
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2, default=str)

        success(f"JSON report saved: {filename}")
        return filename

    def generate_html(self):
        """Generate a stunning HTML report."""
        self.scan_end = datetime.now()
        stats = self.get_stats()

        # Sort findings by severity
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        sorted_findings = sorted(self.findings, key=lambda f: sev_order.get(f.severity, 5))

        findings_html = ""
        for f in sorted_findings:
            sev_class = f.severity.lower()
            affected_html = ""
            if f.affected:
                items = "".join(f"<li><code>{a}</code></li>" for a in f.affected[:20])
                if len(f.affected) > 20:
                    items += f"<li><em>... and {len(f.affected) - 20} more</em></li>"
                affected_html = f'<div class="affected"><strong>Affected Objects:</strong><ul>{items}</ul></div>'

            refs_html = ""
            if f.references:
                ref_items = "".join(f'<li><a href="{r}" target="_blank">{r}</a></li>' for r in f.references)
                refs_html = f'<div class="references"><strong>References:</strong><ul>{ref_items}</ul></div>'

            details_html = ""
            if f.details:
                detail_items = "".join(
                    f"<tr><td><strong>{k}</strong></td><td><code>{v}</code></td></tr>"
                    for k, v in f.details.items()
                )
                details_html = f'<table class="details-table">{detail_items}</table>'

            findings_html += f"""
            <div class="finding {sev_class}">
                <div class="finding-header">
                    <span class="severity-badge {sev_class}">{f.severity}</span>
                    <span class="finding-title">{f.title}</span>
                    <span class="finding-module">{f.module}</span>
                </div>
                <div class="finding-body">
                    <p>{f.description}</p>
                    {details_html}
                    {affected_html}
                    {f'<div class="remediation"><strong>Remediation:</strong> {f.remediation}</div>' if f.remediation else ''}
                    {refs_html}
                </div>
            </div>
            """

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AdByG0d Report - {self.domain}</title>
    <style>
        :root {{
            --bg-primary: #0a0a0f;
            --bg-secondary: #12121a;
            --bg-card: #1a1a2e;
            --text-primary: #e0e0e0;
            --text-secondary: #888;
            --accent: #ff6600;
            --accent-glow: rgba(255, 102, 0, 0.3);
            --critical: #ff0040;
            --high: #ff4444;
            --medium: #ffaa00;
            --low: #44ff44;
            --info: #00ccff;
            --border: #2a2a3e;
        }}

        * {{ margin: 0; padding: 0; box-sizing: border-box; }}

        body {{
            background: var(--bg-primary);
            color: var(--text-primary);
            font-family: 'Segoe UI', 'Cascadia Code', monospace;
            line-height: 1.6;
        }}

        .header {{
            background: linear-gradient(135deg, #0a0a0f 0%, #1a0a2e 50%, #0a0a0f 100%);
            border-bottom: 2px solid var(--accent);
            padding: 40px 20px;
            text-align: center;
            position: relative;
            overflow: hidden;
        }}

        .header::before {{
            content: '';
            position: absolute;
            top: 0; left: 0; right: 0; bottom: 0;
            background:
                radial-gradient(circle at 20% 50%, rgba(255,102,0,0.1) 0%, transparent 50%),
                radial-gradient(circle at 80% 50%, rgba(255,0,64,0.1) 0%, transparent 50%);
        }}

        .header h1 {{
            font-size: 3em;
            background: linear-gradient(90deg, #ff6600, #ff0040, #ff6600);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            margin-bottom: 10px;
            position: relative;
            text-shadow: 0 0 40px rgba(255,102,0,0.5);
        }}

        .header .subtitle {{
            color: var(--text-secondary);
            font-size: 1.1em;
        }}

        .header .domain {{
            color: var(--accent);
            font-size: 1.4em;
            margin-top: 10px;
            font-weight: bold;
        }}

        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }}

        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 15px;
            margin: 30px 0;
        }}

        .stat-card {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 20px;
            text-align: center;
            transition: transform 0.2s, box-shadow 0.2s;
        }}

        .stat-card:hover {{
            transform: translateY(-3px);
            box-shadow: 0 5px 20px rgba(0,0,0,0.5);
        }}

        .stat-card.critical {{ border-color: var(--critical); }}
        .stat-card.high {{ border-color: var(--high); }}
        .stat-card.medium {{ border-color: var(--medium); }}
        .stat-card.low {{ border-color: var(--low); }}
        .stat-card.info {{ border-color: var(--info); }}

        .stat-number {{
            font-size: 2.5em;
            font-weight: bold;
            display: block;
        }}

        .stat-card.critical .stat-number {{ color: var(--critical); }}
        .stat-card.high .stat-number {{ color: var(--high); }}
        .stat-card.medium .stat-number {{ color: var(--medium); }}
        .stat-card.low .stat-number {{ color: var(--low); }}
        .stat-card.info .stat-number {{ color: var(--info); }}

        .stat-label {{
            color: var(--text-secondary);
            text-transform: uppercase;
            font-size: 0.85em;
            letter-spacing: 1px;
        }}

        .section-title {{
            font-size: 1.5em;
            color: var(--accent);
            margin: 30px 0 15px;
            padding-bottom: 10px;
            border-bottom: 1px solid var(--border);
        }}

        .finding {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 8px;
            margin: 15px 0;
            overflow: hidden;
            transition: box-shadow 0.2s;
        }}

        .finding:hover {{
            box-shadow: 0 3px 15px rgba(0,0,0,0.4);
        }}

        .finding.critical {{ border-left: 4px solid var(--critical); }}
        .finding.high {{ border-left: 4px solid var(--high); }}
        .finding.medium {{ border-left: 4px solid var(--medium); }}
        .finding.low {{ border-left: 4px solid var(--low); }}
        .finding.info {{ border-left: 4px solid var(--info); }}

        .finding-header {{
            display: flex;
            align-items: center;
            gap: 15px;
            padding: 15px 20px;
            cursor: pointer;
            background: rgba(255,255,255,0.02);
        }}

        .severity-badge {{
            padding: 3px 12px;
            border-radius: 4px;
            font-size: 0.75em;
            font-weight: bold;
            text-transform: uppercase;
            letter-spacing: 1px;
            min-width: 80px;
            text-align: center;
        }}

        .severity-badge.critical {{ background: var(--critical); color: white; }}
        .severity-badge.high {{ background: var(--high); color: white; }}
        .severity-badge.medium {{ background: var(--medium); color: black; }}
        .severity-badge.low {{ background: var(--low); color: black; }}
        .severity-badge.info {{ background: var(--info); color: black; }}

        .finding-title {{ flex: 1; font-weight: 600; }}
        .finding-module {{ color: var(--text-secondary); font-size: 0.85em; }}

        .finding-body {{
            padding: 15px 20px;
            border-top: 1px solid var(--border);
        }}

        .finding-body p {{ margin-bottom: 10px; }}

        .affected ul, .references ul {{
            margin: 5px 0 10px 20px;
        }}

        .affected li, .references li {{
            margin: 3px 0;
            font-size: 0.9em;
        }}

        .remediation {{
            background: rgba(0,204,255,0.1);
            border-left: 3px solid var(--info);
            padding: 10px 15px;
            margin: 10px 0;
            border-radius: 0 4px 4px 0;
        }}

        .details-table {{
            width: 100%;
            margin: 10px 0;
            border-collapse: collapse;
        }}

        .details-table td {{
            padding: 5px 10px;
            border-bottom: 1px solid var(--border);
            font-size: 0.9em;
        }}

        .details-table td:first-child {{
            width: 200px;
            color: var(--text-secondary);
        }}

        code {{
            background: rgba(255,255,255,0.1);
            padding: 2px 6px;
            border-radius: 3px;
            font-size: 0.9em;
            color: var(--accent);
        }}

        a {{ color: var(--info); text-decoration: none; }}
        a:hover {{ text-decoration: underline; }}

        .footer {{
            text-align: center;
            padding: 30px;
            margin-top: 40px;
            border-top: 1px solid var(--border);
            color: var(--text-secondary);
        }}

        .footer .brand {{
            color: var(--accent);
            font-weight: bold;
            font-size: 1.2em;
        }}

        .meta-info {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 15px;
            margin: 20px 0;
            background: var(--bg-card);
            padding: 20px;
            border-radius: 8px;
            border: 1px solid var(--border);
        }}

        .meta-item {{
            display: flex;
            gap: 10px;
        }}

        .meta-label {{ color: var(--text-secondary); }}
        .meta-value {{ color: var(--text-primary); font-weight: 600; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>AdByG0d</h1>
        <div class="subtitle">Active Directory Penetration Testing Report</div>
        <div class="domain">{self.domain}</div>
    </div>

    <div class="container">
        <div class="meta-info">
            <div class="meta-item">
                <span class="meta-label">Target Domain:</span>
                <span class="meta-value">{self.domain}</span>
            </div>
            <div class="meta-item">
                <span class="meta-label">Scan Start:</span>
                <span class="meta-value">{self.scan_start.strftime('%Y-%m-%d %H:%M:%S')}</span>
            </div>
            <div class="meta-item">
                <span class="meta-label">Scan End:</span>
                <span class="meta-value">{self.scan_end.strftime('%Y-%m-%d %H:%M:%S') if self.scan_end else 'N/A'}</span>
            </div>
            <div class="meta-item">
                <span class="meta-label">Duration:</span>
                <span class="meta-value">{stats['duration']}</span>
            </div>
            <div class="meta-item">
                <span class="meta-label">Modules Run:</span>
                <span class="meta-value">{stats['modules']}</span>
            </div>
            <div class="meta-item">
                <span class="meta-label">Total Findings:</span>
                <span class="meta-value">{stats['total']}</span>
            </div>
        </div>

        <div class="stats-grid">
            <div class="stat-card critical">
                <span class="stat-number">{stats['critical']}</span>
                <span class="stat-label">Critical</span>
            </div>
            <div class="stat-card high">
                <span class="stat-number">{stats['high']}</span>
                <span class="stat-label">High</span>
            </div>
            <div class="stat-card medium">
                <span class="stat-number">{stats['medium']}</span>
                <span class="stat-label">Medium</span>
            </div>
            <div class="stat-card low">
                <span class="stat-number">{stats['low']}</span>
                <span class="stat-label">Low</span>
            </div>
            <div class="stat-card info">
                <span class="stat-number">{stats['info']}</span>
                <span class="stat-label">Info</span>
            </div>
        </div>

        <h2 class="section-title">Findings</h2>
        {findings_html}

        <div class="footer">
            <div class="brand">AdByG0d v1.0</div>
            <p>Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p>Developed by White0xdi3 &mdash; "Your Domain. My Rules."</p>
        </div>
    </div>
</body>
</html>"""

        filename = os.path.join(
            self.output_dir,
            f"adbygod_{self.domain}_{self.scan_start.strftime('%Y%m%d_%H%M%S')}.html"
        )
        with open(filename, 'w') as f:
            f.write(html)

        success(f"HTML report saved: {filename}")
        return filename
