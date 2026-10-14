# ThreatLens: AI threat modeling

**Live:** https://threatlens-api-a9g2gsc3b5d2dtgp.eastus-01.azurewebsites.net
(the first request after the app has been idle can take ~20 s while App Service wakes it up)

ThreatLens turns a plain-English description of an application into a threat model. Each threat
comes back with a severity, one OWASP category, a one-sentence explanation of how it would be
exploited in *this* app, and a specific fix. Risks that come from LLM or AI features are classified
against the **OWASP Top 10 for LLM Applications (2025)**, such as prompt injection, excessive agency,
and system prompt leakage. Everything else is classified against the **OWASP Top 10 (2021)**.
Every report is saved to Azure Blob Storage under a unique ID.

## How it works

```
Browser (static/index.html)
   │  POST /analyze { app_description }
   ▼
FastAPI on Azure App Service (main.py)
   ├─ Pydantic validation (1–3000 chars, else 422)
   ├─ gpt-4o-mini with Structured Outputs (JSON schema)  ──► OpenAI
   ├─ owasp_mapper.normalize_threats(): validate codes + severities, sort Critical → Low
   ├─ report_generator.generate_report(): Markdown report
   └─ upload_blob("report-<uuid>.md")  ──► Azure Blob container "threat-reports"
```

**Structured output instead of parsing prose.** The model must answer with JSON that matches
`THREAT_MODEL_SCHEMA` in `owasp_mapper.py`. `owasp_id` and `severity` are enums, so the model can
only pick real OWASP codes (`LLM01:2025` … `LLM10:2025`, `A01:2021` … `A10:2021`) and one of
Critical / High / Medium / Low. The server still validates every field (`normalize_threats`) before
using it, and sorts the threats by severity, so the report is prioritized.

**Treating input and output as untrusted.** The user's description goes in its own message, wrapped
in `<app>` tags, and the system prompt tells the model to treat it as data and ignore instructions
inside it (a mitigation for prompt injection, LLM01). The frontend escapes all model text before
rendering it (improper output handling, LLM05). Input is capped at 3,000 characters to limit
cost abuse (unbounded consumption, LLM10).

### Example response

```json
{
  "report_id": "6f1c…",
  "report_saved": true,
  "threats": [
    {
      "title": "Prompt injection through uploaded documents",
      "owasp_id": "LLM01:2025",
      "owasp_name": "Prompt Injection",
      "framework": "OWASP Top 10 for LLM Applications 2025",
      "severity": "High",
      "description": "Instructions hidden in an uploaded PDF could make the assistant ignore its rules.",
      "recommendation": "Separate retrieved content from instructions and restrict what the model's output can trigger."
    }
  ],
  "owasp_risks_identified": { "LLM01:2025": "Prompt Injection" },
  "full_analysis": "VULNERABILITIES:\n1. … | LLM01:2025 | Severity: High\n\nRECOMMENDATIONS:\n1. …"
}
```

## Run locally

```bash
python -m venv venv
venv\Scripts\activate            # macOS/Linux: source venv/bin/activate
pip install -r requirements.txt
```

Create a `.env` file (it is git-ignored):

```
OPENAI_API_KEY=sk-...
AZURE_STORAGE_CONNECTION_STRING=...   # optional locally; if missing, the report just isn't saved
```

```bash
uvicorn main:app --reload --port 8000
```

Open http://localhost:8000.

### With Docker

```bash
docker build -t threatlens .
docker run -p 8000:8000 --env-file .env threatlens
```

The image is `python:3.12-slim`. Dependencies are installed in their own layer before the code
is copied, so code changes rebuild quickly. `.dockerignore` keeps `venv/`, `.env`, and `.git/` out
of the image.

## Deployment (CI/CD)

`.github/workflows/main_threatlens-api.yml` runs on every push to `main`:

1. **build:** check out the code, set up Python 3.12, install `requirements.txt` into a virtual
   environment to catch dependency errors early, and upload the app as a build artifact.
2. **deploy:** sign in to Azure with **OpenID Connect**: GitHub issues a short-lived token for this
   repository and branch, and Microsoft Entra ID trusts it through a federated credential. No
   password or client secret is stored in GitHub; the repo only holds the client, tenant, and
   subscription IDs. Then `azure/webapps-deploy` deploys the artifact to the `threatlens-api`
   App Service (Linux, Python 3.12).

Secrets (`OPENAI_API_KEY`, `AZURE_STORAGE_CONNECTION_STRING`) are App Service application settings,
not files in the repo.

## Project layout

| File | Purpose |
| --- | --- |
| `main.py` | FastAPI app: serves the UI, `POST /analyze`, OpenAI call, Blob upload |
| `owasp_mapper.py` | OWASP LLM 2025 and Web 2021 catalogs, JSON schema, validation and severity sort |
| `report_generator.py` | Markdown report and plain-text summary |
| `static/index.html` | Single-page UI (no build step) |
| `Dockerfile` | Container image for local or portable runs |
| `.github/workflows/` | Build and deploy to Azure App Service |

## Known limitations and next steps

- No authentication or rate limiting yet. Anyone with the URL can run analyses. Next: an API key or
  Entra ID sign-in, plus per-client rate limits.
- Blob access uses a connection string. Next: a managed identity with `DefaultAzureCredential`.
- The pipeline only checks that dependencies install. Next: add tests, linting, `bandit`, and
  `pip-audit`, and build, scan, and deploy the Docker image instead of the source code.
- CORS is wide open. Since the UI is served from the same origin, it can be restricted.
