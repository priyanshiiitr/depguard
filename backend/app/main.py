from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .models import AnalyzeRequest, RemediateRequest
from .analyzer import analyze_repo, AnalysisError
from .remediator import remediate_repo, RemediationError
from .eval_runner import run_eval

app = FastAPI(title="DepGuard")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

FRONTEND_DIR = Path(__file__).resolve().parent.parent.parent / "frontend"


@app.get("/")
async def root():
    return FileResponse(FRONTEND_DIR / "index.html")


@app.post("/api/analyze")
async def api_analyze(req: AnalyzeRequest):
    try:
        return await analyze_repo(req.repo_url, github_token=req.github_token)
    except AnalysisError as e:
        raise HTTPException(status_code=400, detail={"error": e.message, "trace": e.trace})
    except Exception as e:
        raise HTTPException(status_code=500, detail={"error": f"Unexpected error: {e}", "trace": []})


@app.post("/api/remediate")
async def api_remediate(req: RemediateRequest):
    try:
        return await remediate_repo(req.repo_url, github_token=req.github_token)
    except RemediationError as e:
        raise HTTPException(status_code=400, detail={"error": e.message, "trace": e.trace})
    except Exception as e:
        raise HTTPException(status_code=500, detail={"error": f"Unexpected error: {e}", "trace": []})


@app.get("/api/eval")
async def api_eval():
    return await run_eval()


app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")
