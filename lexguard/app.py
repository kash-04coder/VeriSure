"""
LexGuard FastAPI application.

This replaces webapp.py's hand-rolled http.server routing. None of the
business logic changed -- auth.py, case_manager.py, documents.py,
hash_chain.py, audit.py, encryption.py, etc. are used exactly as they
were. Only the HTTP layer is new: real routing, Jinja2 templates instead
of hand-built HTML strings, and cookie-based sessions via Starlette's
SessionMiddleware instead of an in-memory SESSIONS dict.

Run with:
    uvicorn app:app --reload --port 8000
"""

import os

from fastapi import FastAPI, Request, Form, UploadFile, File, Depends
from fastapi.responses import RedirectResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from database import init_db, init_document_tables
from auth import create_default_admin, login as auth_login, get_users, delete_user, update_role, create_user
from dashboard import get_dashboard_data
from audit import get_audit_logs, log_action
from case_manager import (
    create_case, get_cases, get_case, close_case, get_case_statistics,
)
import documents
import hash_chain

init_db()
init_document_tables()
create_default_admin()

app = FastAPI(title="LexGuard")

session_secret = os.environ.get("LEXGUARD_SESSION_SECRET", "")
if len(session_secret) < 32:
    raise RuntimeError("Set LEXGUARD_SESSION_SECRET to a random value of at least 32 characters.")
app.add_middleware(
    SessionMiddleware,
    secret_key=session_secret,
    max_age=12 * 60 * 60,
    same_site="lax",
    https_only=os.environ.get("LEXGUARD_HTTPS_ONLY", "").lower() == "true",
)

app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")


# ---------- Auth helpers ----------

def get_user(request: Request):
    return request.session.get("user")


def require_login(request: Request):
    user = get_user(request)
    if not user:
        return None
    return user


def render(request, template_name, active=None, messages=None, **context):
    return templates.TemplateResponse(request, template_name, {
        "user": get_user(request),
        "active": active,
        "messages": messages or [],
        **context,
    })


# ---------- Auth routes ----------

@app.get("/", response_class=HTMLResponse)
def root(request: Request):
    return RedirectResponse("/dashboard" if get_user(request) else "/login")


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    if get_user(request):
        return RedirectResponse("/dashboard")
    return render(request, "login.html")


@app.post("/login")
def login_submit(request: Request, username: str = Form(...), password: str = Form(...)):
    role = auth_login(username, password)
    if not role:
        return render(request, "login.html", messages=[
            {"type": "error", "text": "Invalid username or password."}
        ])
    request.session["user"] = {"username": username, "role": role}
    log_action(username, "Logged in")
    return RedirectResponse("/dashboard", status_code=303)


@app.get("/logout")
def logout(request: Request):
    user = get_user(request)
    if user:
        log_action(user["username"], "Logged out")
    request.session.clear()
    return RedirectResponse("/login", status_code=303)


# ---------- Dashboard ----------

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request):
    user = require_login(request)
    if not user:
        return RedirectResponse("/login")

    data, uploads, roles, activity = get_dashboard_data()
    all_docs = documents.get_documents()
    recent_ledger = hash_chain.get_global_ledger(limit=8)

    return render(
        request, "dashboard.html", active="dashboard",
        data=data, activity=activity,
        doc_count=len(all_docs),
        chain_block_count=len(hash_chain.get_global_ledger(limit=100000)),
        recent_ledger=recent_ledger,
    )


# ---------- Documents ----------

@app.get("/documents", response_class=HTMLResponse)
def documents_list(request: Request):
    user = require_login(request)
    if not user:
        return RedirectResponse("/login")
    return render(request, "documents_list.html", active="documents",
                  documents=documents.get_documents())


@app.get("/documents/new", response_class=HTMLResponse)
def document_new_form(request: Request):
    user = require_login(request)
    if not user:
        return RedirectResponse("/login")
    return render(request, "document_new.html", active="documents",
                  doc_types=documents.DOCUMENT_TYPES)


@app.post("/documents/new")
async def document_new_submit(
    request: Request,
    case_id: str = Form(...),
    doc_type: str = Form(...),
    title: str = Form(...),
    description: str = Form(""),
    file: UploadFile = File(...),
):
    user = require_login(request)
    if not user:
        return RedirectResponse("/login")

    file_bytes = await file.read()
    client_ip = request.client.host if request.client else "Not recorded"

    doc_id, sha256, chain_hash = documents.create_document(
        case_id=case_id, doc_type=doc_type, title=title, description=description,
        file_bytes=file_bytes, filename=file.filename,
        username=user["username"], ip_address=client_ip,
    )
    return RedirectResponse(f"/documents/{doc_id}", status_code=303)


@app.get("/documents/{document_id}", response_class=HTMLResponse)
def document_detail(request: Request, document_id: int):
    user = require_login(request)
    if not user:
        return RedirectResponse("/login")

    doc = documents.get_document(document_id)
    if not doc:
        return RedirectResponse("/documents")

    versions = documents.get_versions(document_id)
    chain = hash_chain.get_chain(document_id)

    # Mark each block valid/invalid for display by recomputing.
    chain_valid, broken_at, chain_details = hash_chain.verify_chain(document_id)
    details_by_id = {d["block_id"]: d["valid"] for d in chain_details}
    for block in chain:
        block["valid"] = details_by_id.get(block["id"], True)

    return render(
        request, "document_detail.html", active="documents",
        document=doc, versions=versions, chain=chain, verify_result=None,
    )


@app.post("/documents/{document_id}/version")
async def document_add_version(
    request: Request, document_id: int,
    change_note: str = Form(...),
    file: UploadFile = File(...),
):
    user = require_login(request)
    if not user:
        return RedirectResponse("/login")

    file_bytes = await file.read()
    client_ip = request.client.host if request.client else "Not recorded"

    documents.add_version(
        document_id, file_bytes=file_bytes, filename=file.filename,
        username=user["username"], change_note=change_note, ip_address=client_ip,
    )
    return RedirectResponse(f"/documents/{document_id}", status_code=303)


@app.post("/documents/{document_id}/verify", response_class=HTMLResponse)
def document_verify(request: Request, document_id: int):
    user = require_login(request)
    if not user:
        return RedirectResponse("/login")

    doc = documents.get_document(document_id)
    versions = documents.get_versions(document_id)
    chain = hash_chain.get_chain(document_id)
    verify_result = documents.verify_document_integrity(document_id)

    details_by_id = {d["block_id"]: d["valid"] for d in verify_result["chain_details"]}
    for block in chain:
        block["valid"] = details_by_id.get(block["id"], True)

    log_action(user["username"], f"Ran integrity verification on document {document_id}")

    return render(
        request, "document_detail.html", active="documents",
        document=doc, versions=versions, chain=chain, verify_result=verify_result,
    )


# ---------- Global ledger ----------

@app.get("/ledger", response_class=HTMLResponse)
def ledger_view(request: Request):
    user = require_login(request)
    if not user:
        return RedirectResponse("/login")
    return render(request, "ledger.html", active="ledger",
                  ledger=hash_chain.get_global_ledger(limit=100))


# ---------- Cases ----------

@app.get("/cases", response_class=HTMLResponse)
def cases_list(request: Request):
    user = require_login(request)
    if not user:
        return RedirectResponse("/login")
    return render(request, "cases_list.html", active="cases", cases=get_cases())


@app.post("/cases/new")
def cases_new(
    request: Request,
    case_id: str = Form(...), case_name: str = Form(...),
    description: str = Form(""), investigator: str = Form(""),
    priority: str = Form("Medium"),
):
    user = require_login(request)
    if not user:
        return RedirectResponse("/login")
    create_case(case_id, case_name, description, investigator, priority)
    log_action(user["username"], f"Created case: {case_name}")
    return RedirectResponse("/cases", status_code=303)


@app.get("/cases/{case_id}", response_class=HTMLResponse)
def case_detail(request: Request, case_id: str):
    user = require_login(request)
    if not user:
        return RedirectResponse("/login")

    case = get_case(case_id)
    if not case:
        return RedirectResponse("/cases")

    return render(
        request, "case_detail.html", active="cases",
        case=case,
        documents=documents.get_documents(case_id=case_id),
        stats=get_case_statistics(case_id),
    )


@app.post("/cases/{case_id}/close")
def case_close(request: Request, case_id: str):
    user = require_login(request)
    if not user:
        return RedirectResponse("/login")
    if user["role"] != "Admin":
        return RedirectResponse(f"/cases/{case_id}")
    close_case(case_id)
    log_action(user["username"], f"Closed & signed case: {case_id}")
    return RedirectResponse(f"/cases/{case_id}", status_code=303)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)
