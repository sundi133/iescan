"""Report generation for scan results."""

from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any

from jinja2 import Template

from iescan.core.scanner import Finding, ScanResult, Severity


# HTML report template
HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>iescan - Internal Enterprise Security Assessment Report</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
               background: #0f1117; color: #e1e4e8; line-height: 1.6; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        .header { background: linear-gradient(135deg, #1a1e2e 0%, #2d1b4e 100%);
                  padding: 40px; border-radius: 12px; margin-bottom: 30px; }
        .header h1 { font-size: 28px; color: #a78bfa; }
        .header .meta { color: #8b949e; margin-top: 10px; }
        .stats { display: grid; grid-template-columns: repeat(5, 1fr); gap: 15px;
                 margin-bottom: 30px; }
        .stat-card { padding: 20px; border-radius: 8px; text-align: center; }
        .stat-card .count { font-size: 36px; font-weight: bold; }
        .stat-card .label { font-size: 14px; color: #8b949e; }
        .critical { background: #3d1116; border: 1px solid #f85149; }
        .critical .count { color: #f85149; }
        .high { background: #341a04; border: 1px solid #db6d28; }
        .high .count { color: #db6d28; }
        .medium { background: #2d2a06; border: 1px solid #d29922; }
        .medium .count { color: #d29922; }
        .low { background: #0c2d1a; border: 1px solid #3fb950; }
        .low .count { color: #3fb950; }
        .info { background: #0d1d30; border: 1px solid #58a6ff; }
        .info .count { color: #58a6ff; }
        .findings { margin-top: 30px; }
        .finding { background: #161b22; border: 1px solid #30363d; border-radius: 8px;
                   padding: 20px; margin-bottom: 15px; }
        .finding h3 { color: #c9d1d9; margin-bottom: 10px; }
        .finding .severity-badge { display: inline-block; padding: 2px 10px;
                                    border-radius: 12px; font-size: 12px;
                                    font-weight: 600; margin-right: 8px; }
        .finding .category-badge { display: inline-block; padding: 2px 10px;
                                    border-radius: 12px; font-size: 12px;
                                    background: #1f2937; color: #a78bfa; }
        .badge-critical { background: #f85149; color: white; }
        .badge-high { background: #db6d28; color: white; }
        .badge-medium { background: #d29922; color: black; }
        .badge-low { background: #3fb950; color: black; }
        .badge-info { background: #58a6ff; color: black; }
        .finding .details { margin-top: 10px; }
        .finding .target { color: #8b949e; font-size: 14px; }
        .finding .evidence { background: #0d1117; padding: 12px; border-radius: 6px;
                             font-family: monospace; font-size: 13px; margin-top: 10px;
                             overflow-x: auto; white-space: pre-wrap; }
        .finding .remediation { background: #0c2d1a; border-left: 3px solid #3fb950;
                                padding: 12px; margin-top: 10px; border-radius: 0 6px 6px 0; }
        .module-section { margin-bottom: 40px; }
        .module-section h2 { color: #a78bfa; border-bottom: 1px solid #30363d;
                             padding-bottom: 10px; margin-bottom: 20px; }
    </style>
</head>
<body>
<div class="container">
    <div class="header">
        <h1>Internal Enterprise Security Assessment Report</h1>
        <div class="meta">
            <p>Engagement: {{ result.engagement_id }}</p>
            <p>Scan Period: {{ result.start_time }} — {{ result.end_time }}</p>
            <p>Generated: {{ generated_at }}</p>
        </div>
    </div>

    <div class="stats">
        <div class="stat-card critical">
            <div class="count">{{ result.critical_count }}</div>
            <div class="label">Critical</div>
        </div>
        <div class="stat-card high">
            <div class="count">{{ result.high_count }}</div>
            <div class="label">High</div>
        </div>
        <div class="stat-card medium">
            <div class="count">{{ result.medium_count }}</div>
            <div class="label">Medium</div>
        </div>
        <div class="stat-card low">
            <div class="count">{{ result.low_count }}</div>
            <div class="label">Low</div>
        </div>
        <div class="stat-card info">
            <div class="count">{{ result.info_count }}</div>
            <div class="label">Info</div>
        </div>
    </div>

    <div class="findings">
        {% for mr in result.module_results %}
        {% if mr.findings %}
        <div class="module-section">
            <h2>{{ mr.module_name }} — {{ mr.target }}</h2>
            {% for finding in mr.findings %}
            <div class="finding">
                <h3>
                    <span class="severity-badge badge-{{ finding.severity.value }}">
                        {{ finding.severity.value | upper }}
                    </span>
                    <span class="category-badge">{{ finding.category.value }}</span>
                    {{ finding.title }}
                </h3>
                <p class="target">Target: {{ finding.target }}</p>
                <div class="details">
                    <p>{{ finding.description }}</p>
                    {% if finding.evidence %}
                    <div class="evidence">{{ finding.evidence }}</div>
                    {% endif %}
                    {% if finding.remediation %}
                    <div class="remediation">
                        <strong>Remediation:</strong> {{ finding.remediation }}
                    </div>
                    {% endif %}
                </div>
            </div>
            {% endfor %}
        </div>
        {% endif %}
        {% endfor %}
    </div>
</div>
</body>
</html>"""


def generate_json_report(result: ScanResult, output_path: str) -> str:
    """Generate a JSON report from scan results."""
    report_data = _serialize_result(result)
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        json.dump(report_data, f, indent=2, default=str)
    return str(path)


def generate_html_report(result: ScanResult, output_path: str) -> str:
    """Generate an HTML report from scan results."""
    template = Template(HTML_TEMPLATE)
    html = template.render(
        result=result,
        generated_at=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
    )
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        f.write(html)
    return str(path)


def _serialize_result(result: ScanResult) -> dict[str, Any]:
    """Serialize a ScanResult to a dictionary."""
    return {
        "engagement_id": result.engagement_id,
        "start_time": result.start_time,
        "end_time": result.end_time,
        "summary": {
            "total_findings": result.total_findings,
            "critical": result.critical_count,
            "high": result.high_count,
            "medium": result.medium_count,
            "low": result.low_count,
            "info": result.info_count,
        },
        "module_results": [
            {
                "module": mr.module_name,
                "target": mr.target,
                "success": mr.success,
                "duration_seconds": mr.duration_seconds,
                "errors": mr.errors,
                "data": mr.data,
                "findings": [
                    {
                        "title": f.title,
                        "severity": f.severity.value,
                        "category": f.category.value,
                        "description": f.description,
                        "target": f.target,
                        "evidence": f.evidence,
                        "remediation": f.remediation,
                        "references": f.references,
                        "cvss_score": f.cvss_score,
                        "cve_ids": f.cve_ids,
                    }
                    for f in mr.findings
                ],
            }
            for mr in result.module_results
        ],
    }
