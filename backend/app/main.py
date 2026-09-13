import asyncio
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, RedirectResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles

from .models import AnalyzeRequest, RemediateRequest, ScheduleCreateRequest
from .analyzer import analyze_repo, AnalysisError
from .remediator import remediate_repo, RemediationError
from .eval_runner import run_eval
from . import oauth, scheduler


@asynccontextmanager
async def lifespan(_app: FastAPI):
    loop_task = asyncio.create_task(scheduler.run_loop())
    try:
        yield
    finally:
        loop_task.cancel()


app = FastAPI(title="DepGuard", lifespan=lifespan)

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


def _oauth_popup_response(provider: str, ok: bool, message: str) -> HTMLResponse:
    """Small self-closing page: posts the result back to the window that opened
    this popup, then closes itself. The dashboard listens for this message to
    refresh its connection badges without a full page reload."""
    import json as _json
    payload = _json.dumps({"source": "depguard-oauth", "provider": provider, "ok": ok, "message": message})
    return HTMLResponse(f"""
    <html><body style="background:#0a0d13;color:#e9ecf5;font-family:sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0">
      <div>{"Connected! You can close this window." if ok else f"Connection failed: {message}"}</div>
      <script>
        if (window.opener) {{ window.opener.postMessage({payload}, "*"); }}
        setTimeout(() => window.close(), ok ? 900 : 4000);
      </script>
    </body></html>
    """)


@app.get("/api/connections")
async def api_connections():
    return oauth.status()


@app.get("/oauth/slack/start")
async def oauth_slack_start():
    if not oauth.slack_configured():
        return _oauth_popup_response("slack", False, "Slack OAuth is not configured on this server (missing SLACK_CLIENT_ID/SECRET).")
    return RedirectResponse(oauth.slack_authorize_url())


@app.get("/oauth/slack/callback")
async def oauth_slack_callback(code: str = "", state: str = "", error: str = ""):
    if error:
        return _oauth_popup_response("slack", False, error)
    if not oauth.consume_state(state):
        return _oauth_popup_response("slack", False, "Invalid or expired OAuth state.")
    ok, message = await oauth.slack_exchange_code(code)
    return _oauth_popup_response("slack", ok, message)


@app.get("/oauth/google/start")
async def oauth_google_start():
    if not oauth.google_configured():
        return _oauth_popup_response("google", False, "Google OAuth is not configured on this server (missing GOOGLE_CLIENT_ID/SECRET).")
    return RedirectResponse(oauth.google_authorize_url())


@app.get("/oauth/google/callback")
async def oauth_google_callback(code: str = "", state: str = "", error: str = ""):
    if error:
        return _oauth_popup_response("google", False, error)
    if not oauth.consume_state(state):
        return _oauth_popup_response("google", False, "Invalid or expired OAuth state.")
    ok, message = await oauth.google_exchange_code(code)
    return _oauth_popup_response("google", ok, message)


def _schedule_or_404(job_id: str) -> dict:
    job = scheduler.get_job(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail={"error": "Schedule not found."})
    return job


@app.get("/api/schedules")
async def api_list_schedules():
    return {"jobs": scheduler.list_jobs(), "server_time": scheduler.now_iso()}


@app.post("/api/schedules")
async def api_create_schedule(req: ScheduleCreateRequest):
    try:
        job = scheduler.create_job(
            req.repo_url, req.github_token, req.schedule_type,
            interval_minutes=req.interval_minutes, daily_times=req.daily_times, notify=req.notify,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail={"error": str(e)})
    return scheduler.public_view(job)


@app.post("/api/schedules/{job_id}/run")
async def api_run_schedule(job_id: str):
    job = _schedule_or_404(job_id)
    scheduler.run_now(job)
    return scheduler.public_view(job)


@app.post("/api/schedules/{job_id}/pause")
async def api_pause_schedule(job_id: str):
    job = _schedule_or_404(job_id)
    scheduler.set_paused(job, True)
    return scheduler.public_view(job)


@app.post("/api/schedules/{job_id}/resume")
async def api_resume_schedule(job_id: str):
    job = _schedule_or_404(job_id)
    scheduler.set_paused(job, False)
    return scheduler.public_view(job)


@app.delete("/api/schedules/{job_id}")
async def api_delete_schedule(job_id: str):
    _schedule_or_404(job_id)
    scheduler.delete_job(job_id)
    return {"deleted": job_id}


@app.get("/api/schedules/{job_id}/latest")
async def api_schedule_latest(job_id: str):
    job = _schedule_or_404(job_id)
    if job["_last_result"] is None:
        raise HTTPException(status_code=404, detail={"error": "This schedule has no successful scan yet."})
    return job["_last_result"]


app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")
