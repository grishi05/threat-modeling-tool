from datetime import datetime, timezone

from owasp_mapper import SEVERITY_ORDER


def format_analysis(threats: list) -> str:
    """Plain-text summary: numbered threats, then one recommendation per threat."""
    vulns = "\n".join(
        f"{i}. {t['title']} | {t['owasp_id'] or 'Unmapped'} | Severity: {t['severity']}"
        for i, t in enumerate(threats, 1)
    )
    recs = "\n".join(f"{i}. {t['recommendation']}" for i, t in enumerate(threats, 1))
    return f"VULNERABILITIES:\n{vulns}\n\nRECOMMENDATIONS:\n{recs}"


def generate_report(app_description: str, threats: list, risks: dict) -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    counts = {s: sum(1 for t in threats if t["severity"] == s) for s in SEVERITY_ORDER}
    summary = " · ".join(f"{s}: {counts[s]}" for s in SEVERITY_ORDER)

    threat_sections = "\n\n".join(
        f"### {i}. {t['title']}\n"
        f"- **Severity:** {t['severity']}\n"
        f"- **OWASP:** {t['owasp_id'] or 'Unmapped'} {t['owasp_name'] or ''} ({t['framework'] or 'n/a'})\n"
        f"- **Threat:** {t['description']}\n"
        f"- **Recommendation:** {t['recommendation']}"
        for i, t in enumerate(threats, 1)
    ) or "No threats identified."

    risk_lines = "\n".join(f"- **{code}**: {name}" for code, name in risks.items()) or "- No OWASP categories mapped"

    return f"""# AI Threat Modeling Report
**Generated:** {timestamp}

## Application Description
{app_description}

## Summary
{len(threats)} threats ({summary}), ordered by severity.

## Threats
{threat_sections}

## OWASP Categories Identified
{risk_lines}
"""
