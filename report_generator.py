from datetime import datetime

def generate_report(app_description: str, llm_analysis: str, risks: dict) -> str:
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    risk_lines = "\n".join([f"- **{code}**: {name}" for code, name in risks.items()]) or "- No specific OWASP risks mapped"
    
    report = f"""# AI Threat Modeling Report
**Generated:** {timestamp}

## Application Description
{app_description}

## LLM Security Analysis
{llm_analysis}

## Mapped OWASP LLM Top 10 Risks
{risk_lines}

## Recommended Mitigations
- Implement input validation and output sanitization
- Apply principle of least privilege to all LLM integrations
- Monitor for anomalous model behavior in production
- Conduct regular red team exercises against AI components
"""
    return report