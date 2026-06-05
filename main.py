from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from openai import OpenAI
from owasp_mapper import map_risks
from report_generator import generate_report
from azure.storage.blob import BlobServiceClient
import os
from dotenv import load_dotenv
import uuid

load_dotenv(override=False)

app = FastAPI(title="AI Threat Modeling Tool")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory="static"), name="static")

api_key = os.getenv("OPENAI_API_KEY")
if not api_key:
    raise ValueError("OPENAI_API_KEY environment variable is not set")
client = OpenAI(api_key=api_key)

AZURE_CONNECTION_STRING = os.getenv("AZURE_STORAGE_CONNECTION_STRING")
CONTAINER_NAME = "threat-reports"

class AppInput(BaseModel):
    app_description: str

@app.get("/")
def serve_frontend():
    return FileResponse("static/index.html")

@app.post("/analyze")
async def analyze(input: AppInput):
    prompt = f"""You are a cybersecurity expert performing a structured threat model for the application described below.

Application: {input.app_description}

Respond using ONLY the following format. Do not add any introduction, commentary, or extra sections.

VULNERABILITIES:
1. [Threat name] | [OWASP category e.g. A01:2021] | [Severity: Critical / High / Medium / Low]
2. [Threat name] | [OWASP category] | [Severity: Critical / High / Medium / Low]
(continue for all identified threats, maximum 10)

RECOMMENDATIONS:
1. [Specific actionable fix for vulnerability 1]
2. [Specific actionable fix for vulnerability 2]
(one recommendation per vulnerability, in the same order)

Do not include descriptions, explanations, or bullet sub-points. Each line must be a single concise item."""

    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": prompt}]
    )
    llm_response = response.choices[0].message.content
    risks = map_risks(llm_response)
    report = generate_report(input.app_description, llm_response, risks)

    report_id = str(uuid.uuid4())
    filename = f"report-{report_id}.md"

    try:
        blob_service = BlobServiceClient.from_connection_string(AZURE_CONNECTION_STRING)
        container = blob_service.get_container_client(CONTAINER_NAME)
        container.upload_blob(name=filename, data=report.encode("utf-8"))
    except Exception as e:
        print(f"Azure upload failed: {e}")

    return {
        "report_id": report_id,
        "owasp_risks_identified": risks,
        "full_analysis": llm_response,
        "report_filename": filename
    }