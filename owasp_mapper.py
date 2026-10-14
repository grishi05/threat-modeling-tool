OWASP_LLM_TOP10_2025 = {
    "LLM01:2025": "Prompt Injection",
    "LLM02:2025": "Sensitive Information Disclosure",
    "LLM03:2025": "Supply Chain",
    "LLM04:2025": "Data and Model Poisoning",
    "LLM05:2025": "Improper Output Handling",
    "LLM06:2025": "Excessive Agency",
    "LLM07:2025": "System Prompt Leakage",
    "LLM08:2025": "Vector and Embedding Weaknesses",
    "LLM09:2025": "Misinformation",
    "LLM10:2025": "Unbounded Consumption",
}

OWASP_WEB_TOP10_2021 = {
    "A01:2021": "Broken Access Control",
    "A02:2021": "Cryptographic Failures",
    "A03:2021": "Injection",
    "A04:2021": "Insecure Design",
    "A05:2021": "Security Misconfiguration",
    "A06:2021": "Vulnerable and Outdated Components",
    "A07:2021": "Identification and Authentication Failures",
    "A08:2021": "Software and Data Integrity Failures",
    "A09:2021": "Security Logging and Monitoring Failures",
    "A10:2021": "Server-Side Request Forgery",
}

CATEGORIES = {**OWASP_LLM_TOP10_2025, **OWASP_WEB_TOP10_2021}
SEVERITY_ORDER = ["Critical", "High", "Medium", "Low"]
MAX_THREATS = 10

# JSON schema for OpenAI structured outputs: the model can only answer with
# known OWASP codes and severities, so nothing has to be parsed out of prose.
THREAT_MODEL_SCHEMA = {
    "name": "threat_model",
    "strict": True,
    "schema": {
        "type": "object",
        "properties": {
            "threats": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "title": {"type": "string"},
                        "owasp_id": {"type": "string", "enum": list(CATEGORIES)},
                        "severity": {"type": "string", "enum": SEVERITY_ORDER},
                        "description": {"type": "string"},
                        "recommendation": {"type": "string"},
                    },
                    "required": ["title", "owasp_id", "severity", "description", "recommendation"],
                    "additionalProperties": False,
                },
            }
        },
        "required": ["threats"],
        "additionalProperties": False,
    },
}


def framework_for(code: str) -> str:
    if code in OWASP_LLM_TOP10_2025:
        return "OWASP Top 10 for LLM Applications 2025"
    if code in OWASP_WEB_TOP10_2021:
        return "OWASP Top 10 2021"
    return ""


def normalize_threats(raw_threats) -> list:
    """Validate the model's threats against the OWASP catalogs and sort them
    by severity (Critical first). Anything malformed is dropped or defaulted."""
    if not isinstance(raw_threats, list):
        return []
    threats = []
    for item in raw_threats[:MAX_THREATS]:
        if not isinstance(item, dict):
            continue
        title = str(item.get("title", "")).strip()
        if not title:
            continue
        code = str(item.get("owasp_id", "")).strip().upper()
        if code not in CATEGORIES:
            code = ""
        severity = str(item.get("severity", "")).strip().capitalize()
        if severity not in SEVERITY_ORDER:
            severity = "Medium"
        threats.append({
            "title": title[:150],
            "owasp_id": code or None,
            "owasp_name": CATEGORIES.get(code),
            "framework": framework_for(code) or None,
            "severity": severity,
            "description": str(item.get("description", "")).strip(),
            "recommendation": str(item.get("recommendation", "")).strip(),
        })
    # sort() is stable, so threats of equal severity keep the model's order.
    threats.sort(key=lambda t: SEVERITY_ORDER.index(t["severity"]))
    return threats


def map_risks(threats: list) -> dict:
    """OWASP categories identified in this report, as {code: name}."""
    return {t["owasp_id"]: t["owasp_name"] for t in threats if t["owasp_id"]}
