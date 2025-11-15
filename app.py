from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from scanner import perform_full_scan
import os
from dotenv import load_dotenv

load_dotenv()
app = FastAPI()
templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")

class URLRequest(BaseModel):
    url: str

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.post("/analyze", response_class=JSONResponse)
async def analyze_url(payload: URLRequest):
    try:
        result = perform_full_scan(payload.url)
        domain = result["osint"].get("domain", "N/A")
        reasons = []

        vt_score = result["virustotal"]["data"]["attributes"]["stats"]["malicious"]
        if vt_score > 0:
            reasons.append("⚠️ Detected by VirusTotal")

        if result["google_safe"].get("matches"):
            reasons.append("⚠️ Flagged by Google Safe Browsing")

        if result["urlscan"].get("verdicts", {}).get("overall", {}).get("score", 0) > 3:
            reasons.append("⚠️ Suspicious behavior on urlscan.io")

        score = min(vt_score * 30 + len(reasons) * 20, 100)

        return {
            "domain": domain,
            "score": score,
            "reasons": reasons
        }

    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})
