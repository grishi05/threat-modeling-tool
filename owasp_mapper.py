OWASP_LLM_TOP10 = {
    "LLM01": "Prompt Injection",
    "LLM02": "Insecure Output Handling",
    "LLM03": "Training Data Poisoning",
    "LLM04": "Model Denial of Service",
    "LLM05": "Supply Chain Vulnerabilities",
    "LLM06": "Sensitive Information Disclosure",
    "LLM07": "Insecure Plugin Design",
    "LLM08": "Excessive Agency",
    "LLM09": "Overreliance",
    "LLM10": "Model Theft"
}

def map_risks(llm_response: str) -> dict:
    identified = {}
    for code, name in OWASP_LLM_TOP10.items():
        if name.lower() in llm_response.lower() or code.lower() in llm_response.lower():
            identified[code] = name
    return identified