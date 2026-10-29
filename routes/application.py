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

import csv
import asyncio
import hmac
import io
import logging
import os
import secrets
import tempfile
import hashlib as _hashlib
from contextlib import asynccontextmanager
from datetime import datetime

from fastapi import FastAPI, Request, Form, UploadFile, File
from fastapi.responses import RedirectResponse, HTMLResponse, Response, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from config import HTTPS_ONLY, SESSION_SECRET
from database import init_db, init_document_tables
from auth import login as auth_login, get_users, delete_user, update_role, create_user
from audit import get_audit_logs, log_action
from case_manager import (
    create_case, get_cases, get_case, get_case_evidence,
    close_case, delete_case, update_case, get_case_statistics, build_case_summary,
)
from case_report import generate_case_report
from evidence import save_evidence
from evidence_details import get_evidence_details
from timeline import get_timeline
from verification import save_verification
from tamper import create_alert
from report_signing import verify_case_summary
from metadata import extract_image_metadata, extract_pdf_metadata, extract_file_metadata
from encryption import decrypt_file
from vault_security import vault_is_configured, setup_master_password, verify_master_password
from ip_logger import log_ip_activity
import sqlite3
import documents
import hash_chain
from fdr_portal import init_fdr_db, router as fdr_router, scan_deadlines
from security import validate_upload

if len(SESSION_SECRET) < 32:
    raise RuntimeError(
        "Set LEXGUARD_SESSION_SECRET to a random value of at least 32 characters. "
        "See .env.example and README.md."
    )

init_db()
init_document_tables()
init_fdr_db()

DB = "forensic.db"

# Role permissions, matching the original app's ROUTES table.
ROLE_RESTRICTED = {
    "/cases": ["Admin", "Investigator"],
    "/custody": ["Admin", "Investigator"],
    "/evidence/verify": ["Admin", "Analyst"],
    "/vault": ["Admin", "Analyst"],
    "/reports/verify-signature": ["Admin", "Investigator", "Analyst"],
    "/users": ["Admin"],
}

VAULT_EXEMPT_PATHS = {"/login", "/logout", "/vault/setup", "/vault/unlock"}

async def _deadline_worker():
    while True:
        try:
            await asyncio.to_thread(scan_deadlines)
        except Exception:
            logging.getLogger(__name__).exception("Scheduled FDR deadline scan failed.")
        await asyncio.sleep(60 * 60)


@asynccontextmanager
async def lifespan(_app):
    task = asyncio.create_task(_deadline_worker())
    try:
        yield
    finally:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass


app = FastAPI(title="LexGuard", lifespan=lifespan)

app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")
app.include_router(fdr_router)


@app.middleware("http")
async def vault_gate(request: Request, call_next):
    if request.method == "POST":
        body = await request.body()

        async def receive():
            return {"type": "http.request", "body": body, "more_body": False}

        request._receive = receive
        form = await request.form()
        if not check_csrf(request, form.get("csrf")):
            return HTMLResponse("Invalid or missing CSRF token.", status_code=403)
    """
    Reproduces the original app's behavior: once logged in, every page
    is gated behind the encrypted evidence vault being configured (once,
    ever) and unlocked (once per session). This mirrors the original's
    "master password protects access to everything, not just uploads"
    design, so nothing regresses.
    """
    path = request.url.path
    if (path.startswith("/static") or path.startswith("/fdr") or path == "/dashboard"
            or path.startswith("/bank/verify") or path in VAULT_EXEMPT_PATHS):
        return await call_next(request)

    user = request.session.get("user")
    if user:
        if not vault_is_configured():
            return RedirectResponse("/vault/setup")
        if not request.session.get("vault_unlocked"):
            return RedirectResponse("/vault/unlock")

    return await call_next(request)


# Registered AFTER vault_gate so it runs first and initializes request.session.
app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET,
    max_age=12 * 60 * 60,
    same_site="lax",
    https_only=HTTPS_ONLY,
)


# ---------- Auth helpers ----------

def get_user(request: Request):
    return request.session.get("user")


def csrf_token(request: Request):
    token = request.session.get("_csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        request.session["_csrf_token"] = token
    return token


def check_csrf(request: Request, submitted):
    expected = request.session.get("_csrf_token", "")
    if not expected or not hmac.compare_digest(expected, submitted or ""):
        return False
    return True


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
        "csrf_token": csrf_token(request),
        **context,
    })


def require_role(user, path):
    """Returns True if the logged-in user's role can access `path`."""
    allowed = ROLE_RESTRICTED.get(path)
    return allowed is None or user["role"] in allowed


def forbidden(request):
    return render(request, "base.html", messages=[
        {"type": "error", "text": "You do not have permission to view this page."}
    ])


# ---------- Auth routes ----------

@app.get("/", response_class=HTMLResponse)
def root(request: Request):
    return RedirectResponse("/fdr/dashboard" if get_user(request) else "/login")


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    if get_user(request):
        return RedirectResponse("/fdr/dashboard")
    return render(request, "login.html")


@app.post("/login")
def login_submit(request: Request, username: str = Form(...), password: str = Form(...),
                 csrf: str = Form(...)):
    if not check_csrf(request, csrf):
        return HTMLResponse("Invalid or missing CSRF token.", status_code=403)
    role = auth_login(username, password)
    if not role:
        return render(request, "login.html", messages=[
            {"type": "error", "text": "Invalid username or password."}
        ])
    request.session.clear()
    request.session["user"] = {"username": username, "role": role}
    request.session["_csrf_token"] = secrets.token_urlsafe(32)
    log_action(username, "Logged in")
    return RedirectResponse("/fdr/dashboard", status_code=303)


# ---------- Vault ----------

@app.get("/vault/setup", response_class=HTMLResponse)
def vault_setup_page(request: Request):
    if not get_user(request):
        return RedirectResponse("/login")
    if vault_is_configured():
        return RedirectResponse("/dashboard")
    return render(request, "vault_setup.html")


@app.post("/vault/setup")
def vault_setup_submit(request: Request, master_password: str = Form(...),
                        confirm_master_password: str = Form(...)):
    if not get_user(request):
        return RedirectResponse("/login")
    if master_password != confirm_master_password:
        return render(request, "vault_setup.html", messages=[
            {"type": "error", "text": "Passwords do not match."}
        ])
    success, message = setup_master_password(master_password)
    if success:
        request.session["vault_unlocked"] = True
        return RedirectResponse("/dashboard", status_code=303)
    return render(request, "vault_setup.html", messages=[{"type": "error", "text": message}])


@app.get("/vault/unlock", response_class=HTMLResponse)
def vault_unlock_page(request: Request):
    if not get_user(request):
        return RedirectResponse("/login")
    if not vault_is_configured():
        return RedirectResponse("/vault/setup")
    if request.session.get("vault_unlocked"):
        return RedirectResponse("/dashboard")
    return render(request, "vault_locked.html")


@app.post("/vault/unlock")
def vault_unlock_submit(request: Request, master_password: str = Form(...)):
    if not get_user(request):
        return RedirectResponse("/login")
    if verify_master_password(master_password):
        request.session["vault_unlocked"] = True
        return RedirectResponse("/dashboard", status_code=303)
    return render(request, "vault_locked.html", messages=[
        {"type": "error", "text": "Invalid master password."}
    ])


@app.post("/vault/lock")
def vault_lock(request: Request):
    request.session["vault_unlocked"] = False
    return RedirectResponse("/vault/unlock", status_code=303)


@app.get("/vault", response_class=HTMLResponse)
def vault_view(request: Request):
    user = require_login(request)
    if not user:
        return RedirectResponse("/login")
    if not require_role(user, "/vault"):
        return forbidden(request)

    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    files = [dict(r) for r in conn.execute(
        "SELECT id, title, encrypted_path FROM evidence"
    ).fetchall()]
    conn.close()
    return render(request, "vault.html", active="vault", files=files)


@app.post("/logout")
def logout(request: Request, csrf: str = Form(...)):
    if not check_csrf(request, csrf):
        return HTMLResponse("Invalid or missing CSRF token.", status_code=403)
    user = get_user(request)
    if user:
        log_action(user["username"], "Logged out")
    request.session.clear()
    return RedirectResponse("/login", status_code=303)


# ---------- Dashboard ----------

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request):
    return RedirectResponse("/fdr/dashboard" if get_user(request) else "/login")


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
        forensic_verification=documents.get_latest_forensic_verification(document_id),
    )


@app.get("/documents/{document_id}/forensics", response_class=HTMLResponse)
def document_forensics(request: Request, document_id: int):
    user = require_login(request)
    if not user:
        return RedirectResponse("/login")

    doc = documents.get_document(document_id)
    if not doc:
        return RedirectResponse("/documents")

    verification = documents.get_latest_forensic_verification(document_id)
    if not verification:
        return RedirectResponse(f"/documents/{document_id}")

    return render(
        request,
        "pending_review.html",
        active="documents",
        document=doc,
        verification=verification,
    )


@app.post("/documents/{document_id}/forensics/run")
def rerun_forensics(request: Request, document_id: int):
    user = require_login(request)
    if not user:
        return RedirectResponse("/login")

    doc = documents.get_document(document_id)
    if not doc:
        return RedirectResponse("/documents")

    documents.run_forensic_verification(
        document_id,
        doc["current_version"],
        user["username"],
    )
    log_action(user["username"], f"Ran forensic verification on document {document_id}")

    return RedirectResponse(
        f"/documents/{document_id}/forensics",
        status_code=303,
    )


@app.get("/documents/{document_id}/forensics/heatmap")
def forensic_heatmap(request: Request, document_id: int):
    user = require_login(request)
    if not user:
        return RedirectResponse("/login")

    verification = documents.get_latest_forensic_verification(document_id)
    if not verification:
        return RedirectResponse(f"/documents/{document_id}")

    path = verification.get("heatmap_path")
    if not path or not os.path.exists(path):
        return Response(content="Heatmap not available.", status_code=404)

    return FileResponse(path, media_type="image/png")


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
        forensic_verification=documents.get_latest_forensic_verification(document_id),
    )


# ---------- Evidence (search + details + timeline, unified) ----------

@app.get("/evidence", response_class=HTMLResponse)
def evidence_page(request: Request, evidence_id: int = None, search_term: str = ""):
    user = require_login(request)
    if not user:
        return RedirectResponse("/login")

    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    evidence_list = [dict(r) for r in
                      conn.execute("SELECT id, title FROM evidence ORDER BY id DESC").fetchall()]

    search_results = None
    if search_term:
        like = f"%{search_term}%"
        search_results = [dict(r) for r in conn.execute("""
            SELECT id, case_id, title, filename, uploaded_by, upload_time
            FROM evidence
            WHERE case_id LIKE ? OR title LIKE ? OR filename LIKE ?
               OR uploaded_by LIKE ? OR sha256 LIKE ?
        """, (like, like, like, like, like)).fetchall()]
        log_action(user["username"], f"Searched: {search_term}")
    conn.close()

    selected_id = evidence_id
    if selected_id is None and not search_term and evidence_list:
        selected_id = evidence_list[0]["id"]

    evidence = None
    timeline = []
    status = "Unknown"
    preview_type = preview_text = None
    alerts_count = custody_count = 0

    if selected_id:
        evidence, custody, verification, alerts, ip_logs = get_evidence_details(selected_id)
        if evidence:
            status = verification[0]["status"] if verification else "Unknown"
            alerts_count = len(alerts)
            custody_count = len(custody)

            filename = evidence["filename"]
            extension = filename.split(".")[-1].lower() if "." in filename else ""
            if extension in ("jpg", "jpeg", "png", "bmp", "gif"):
                preview_type = "image"
            elif extension in ("txt", "log", "csv"):
                try:
                    data = decrypt_file(evidence["encrypted_path"])
                    preview_text = data.decode("utf-8", errors="replace")
                    preview_type = "text"
                except (FileNotFoundError, ValueError):
                    preview_type = "error"
            elif extension == "pdf":
                preview_type = "pdf"

            raw_timeline = get_timeline(selected_id)
            css_map = {"green": "success", "red": "error", "orange": "warning"}
            timeline = [{**row, "css_class": css_map.get(row.get("color"), "info")} for row in raw_timeline]

    return render(
        request, "evidence.html", active="evidence",
        evidence_list=evidence_list, selected_id=selected_id, evidence=evidence,
        search_term=search_term, search_results=search_results,
        timeline=timeline, status=status, alerts_count=alerts_count, custody_count=custody_count,
        preview_type=preview_type, preview_text=preview_text,
    )


@app.get("/evidence/preview")
def evidence_preview(request: Request, evidence_id: int):
    if not get_user(request):
        return RedirectResponse("/login")

    conn = sqlite3.connect(DB)
    row = conn.execute(
        "SELECT filename, encrypted_path FROM evidence WHERE id=?", (evidence_id,)
    ).fetchone()
    conn.close()
    if not row:
        return Response(status_code=404)

    filename, encrypted_path = row
    try:
        data = decrypt_file(encrypted_path)
    except (FileNotFoundError, ValueError):
        return Response(status_code=404)

    extension = filename.split(".")[-1].lower() if "." in filename else ""
    content_types = {
        "jpg": "image/jpeg", "jpeg": "image/jpeg", "png": "image/png",
        "bmp": "image/bmp", "gif": "image/gif", "pdf": "application/pdf",
    }
    content_type = content_types.get(extension, "application/octet-stream")
    headers = {}
    if extension == "pdf":
        headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    return Response(content=data, media_type=content_type, headers=headers)


@app.get("/evidence/verify", response_class=HTMLResponse)
def evidence_verify_page(request: Request, message: str = None, type: str = "info"):
    user = require_login(request)
    if not user:
        return RedirectResponse("/login")
    if not require_role(user, "/evidence/verify"):
        return forbidden(request)

    conn = sqlite3.connect(DB)
    evidence_list = [{"id": r[0], "title": r[1]} for r in
                      conn.execute("SELECT id, title FROM evidence").fetchall()]
    conn.close()

    return render(request, "evidence_verify.html", active="evidence_verify",
                  evidence_list=evidence_list, message=message, message_type=type)


@app.post("/evidence/verify/run")
def evidence_verify_run(request: Request, evidence_id: int = Form(...)):
    user = require_login(request)
    if not user:
        return RedirectResponse("/login")
    if not require_role(user, "/evidence/verify"):
        return forbidden(request)

    conn = sqlite3.connect(DB)
    row = conn.execute(
        "SELECT title, encrypted_path, sha256 FROM evidence WHERE id=?", (evidence_id,)
    ).fetchone()
    conn.close()
    if not row:
        return RedirectResponse("/evidence/verify", status_code=303)

    title, encrypted_path, stored_hash = row
    client_ip = request.client.host if request.client else "Not recorded"
    try:
        data = decrypt_file(encrypted_path)
    except (FileNotFoundError, ValueError):
        return RedirectResponse(
            "/evidence/verify?message=Could+not+decrypt+evidence+for+verification&type=error",
            status_code=303,
        )

    current_hash = _hashlib.sha256(data).hexdigest()
    if current_hash == stored_hash:
        save_verification(evidence_id, user["username"], "Verified")
        log_ip_activity(evidence_id, user["username"], "Verified", client_ip)
        return RedirectResponse("/evidence/verify?message=Integrity+Verified&type=success", status_code=303)
    else:
        create_alert(evidence_id, title, user["username"], stored_hash, current_hash)
        save_verification(evidence_id, user["username"], "Tampered")
        log_action(user["username"], f"Tamper detected: {title}")
        log_ip_activity(evidence_id, user["username"], "Tampered", client_ip)
        return RedirectResponse("/evidence/verify?message=Evidence+Tampered&type=error", status_code=303)


def _decrypted_tempfile_for_evidence(filename, encrypted_path):
    data = decrypt_file(encrypted_path)
    suffix = ("." + filename.split(".")[-1]) if "." in filename else ""
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=suffix)
    tmp.write(data)
    tmp.close()
    return tmp.name


def _extract_metadata_for_evidence(evidence_id):
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    row = conn.execute("""
        SELECT id, title, filename, encrypted_path, sha256, uploaded_by, upload_time
        FROM evidence WHERE id=?
    """, (evidence_id,)).fetchone()
    conn.close()
    if not row:
        return None

    tmp_path = _decrypted_tempfile_for_evidence(row["filename"], row["encrypted_path"])
    try:
        extension = row["filename"].split(".")[-1].lower() if "." in row["filename"] else ""
        if extension in ("jpg", "jpeg", "png", "bmp", "gif"):
            metadata = extract_image_metadata(tmp_path)
        elif extension == "pdf":
            metadata = extract_pdf_metadata(tmp_path)
        else:
            metadata = extract_file_metadata(tmp_path)
            metadata["Analysis | Format-specific metadata"] = (
                "Not available for this file type. File and integrity details are shown below."
            )
    finally:
        os.remove(tmp_path)

    if "Error" not in metadata:
        stored_hash = row["sha256"]
        current_hash = metadata.get("Integrity | SHA-256")
        metadata.update({
            "Evidence record | Evidence ID": row["id"],
            "Evidence record | Title": row["title"],
            "Evidence record | Original filename": row["filename"] or "Not recorded",
            "Evidence record | Uploaded by": row["uploaded_by"] or "Not recorded",
            "Evidence record | Upload time": row["upload_time"] or "Not recorded",
            "Integrity | Stored SHA-256": stored_hash or "Not recorded",
            "Integrity | Verification": (
                "Match — file is consistent with its registered hash"
                if stored_hash and stored_hash == current_hash
                else "Mismatch — current file hash differs from the registered hash"
                if stored_hash else "No registered hash available for comparison"
            ),
        })
    return metadata


@app.get("/metadata", response_class=HTMLResponse)
def metadata_page(request: Request, evidence_id: int = None):
    user = require_login(request)
    if not user:
        return RedirectResponse("/login")

    conn = sqlite3.connect(DB)
    evidence_list = [{"id": r[0], "title": r[1]} for r in
                      conn.execute("SELECT id, title FROM evidence ORDER BY id DESC").fetchall()]
    conn.close()

    if not evidence_list:
        return render(request, "metadata.html", active="metadata", evidence_list=[])

    selected_id = evidence_id or evidence_list[0]["id"]
    metadata = _extract_metadata_for_evidence(selected_id)

    return render(request, "metadata.html", active="metadata",
                  evidence_list=evidence_list, selected_id=selected_id, metadata=metadata)


@app.get("/metadata/export")
def metadata_export(request: Request, evidence_id: int):
    if not get_user(request):
        return RedirectResponse("/login")

    metadata = _extract_metadata_for_evidence(evidence_id) or {}
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["Property", "Value"])
    for k, v in metadata.items():
        writer.writerow([k, v])

    return Response(
        content=buffer.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="evidence_{evidence_id}_metadata.csv"'},
    )


# ---------- Custody ----------

@app.get("/custody", response_class=HTMLResponse)
def custody_page(request: Request, message: str = None):
    user = require_login(request)
    if not user:
        return RedirectResponse("/login")
    if not require_role(user, "/custody"):
        return forbidden(request)

    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    evidence_list = [{"id": r[0], "title": r[1]} for r in
                      conn.execute("SELECT id, title FROM evidence").fetchall()]
    records = [dict(r) for r in conn.execute("""
        SELECT id, evidence_id, action, person, timestamp
        FROM custody ORDER BY timestamp DESC
    """).fetchall()]
    conn.close()

    return render(request, "custody.html", active="custody",
                  evidence_list=evidence_list, records=records, message=message)


@app.post("/custody/add")
def custody_add(request: Request, evidence_id: int = Form(...), action: str = Form(...)):
    user = require_login(request)
    if not user:
        return RedirectResponse("/login")
    if not require_role(user, "/custody"):
        return forbidden(request)

    conn = sqlite3.connect(DB)
    conn.execute("""
        INSERT INTO custody(evidence_id, action, person, timestamp)
        VALUES(?,?,?,?)
    """, (evidence_id, action, user["username"], datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    conn.commit()
    conn.close()

    client_ip = request.client.host if request.client else "Not recorded"
    log_ip_activity(evidence_id, user["username"], action, client_ip)
    return RedirectResponse("/custody", status_code=303)


# ---------- Reports ----------

@app.get("/reports/verify-signature", response_class=HTMLResponse)
def reports_verify_signature_page(request: Request, case_id: str = None, result: str = None):
    user = require_login(request)
    if not user:
        return RedirectResponse("/login")
    if not require_role(user, "/reports/verify-signature"):
        return forbidden(request)

    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    signed_cases = [dict(r) for r in conn.execute("""
        SELECT case_id, case_name, status, report_signature, report_signed_at
        FROM cases
        WHERE report_signature IS NOT NULL AND report_signature != ''
        ORDER BY report_signed_at DESC
    """).fetchall()]
    conn.close()

    if not signed_cases:
        return render(request, "reports_verify_signature.html",
                       active="reports_verify", signed_cases=[])

    selected = next((c for c in signed_cases if c["case_id"] == case_id), signed_cases[0])
    return render(request, "reports_verify_signature.html", active="reports_verify",
                  signed_cases=signed_cases, selected=selected, result=result)


@app.post("/reports/verify-signature/verify")
def reports_verify_signature_run(request: Request, case_id: str = Form(...)):
    user = require_login(request)
    if not user:
        return RedirectResponse("/login")
    if not require_role(user, "/reports/verify-signature"):
        return forbidden(request)

    conn = sqlite3.connect(DB)
    row = conn.execute("SELECT report_signature FROM cases WHERE case_id=?", (case_id,)).fetchone()
    conn.close()

    current_summary = build_case_summary(case_id)
    valid = verify_case_summary(current_summary, row[0] if row else None)
    result = "valid" if valid else "invalid"
    return RedirectResponse(f"/reports/verify-signature?case_id={case_id}&result={result}", status_code=303)


# ---------- Users ----------

@app.get("/users", response_class=HTMLResponse)
def users_page(request: Request, search: str = "", message: str = None):
    user = require_login(request)
    if not user:
        return RedirectResponse("/login")
    if not require_role(user, "/users"):
        return forbidden(request)

    all_users = get_users()
    counts = {"Admin": 0, "Analyst": 0, "Viewer": 0, "Investigator": 0}
    for u in all_users:
        if u[2] in counts:
            counts[u[2]] += 1

    filtered = [{"id": u[0], "username": u[1], "role": u[2]} for u in all_users
                if not search or search.lower() in u[1].lower()]

    return render(request, "users.html", active="users",
                  users=filtered, counts=counts, search=search, message=message)


@app.post("/users/create")
def users_create(request: Request, username: str = Form(...), password: str = Form(...),
                  role: str = Form("Viewer")):
    user = require_login(request)
    if not user:
        return RedirectResponse("/login")
    if not require_role(user, "/users"):
        return forbidden(request)

    success = create_user(username, password, role)
    if success:
        log_action(user["username"], f"Created User: {username}")
        return RedirectResponse("/users?message=User+Created+Successfully", status_code=303)
    return RedirectResponse("/users?message=Username+already+exists", status_code=303)


@app.post("/users/update-role")
def users_update_role(request: Request, user_id: int = Form(...), role: str = Form("Viewer")):
    user = require_login(request)
    if not user:
        return RedirectResponse("/login")
    if not require_role(user, "/users"):
        return forbidden(request)

    update_role(user_id, role)
    return RedirectResponse("/users?message=Role+Updated", status_code=303)


@app.post("/users/delete")
def users_delete(request: Request, user_id: int = Form(...)):
    user = require_login(request)
    if not user:
        return RedirectResponse("/login")
    if not require_role(user, "/users"):
        return forbidden(request)

    delete_user(user_id)
    return RedirectResponse("/users?message=User+Deleted", status_code=303)


# ---------- Activity ----------


ACTIVITY_ICONS = [
    ("Tamper", "🚨"), ("Register", "📁"), ("Verify", "✅"),
    ("Metadata", "🧬"), ("Report", "📄"), ("Login", "🔑"),
]


def _icon_for_action(action):
    for keyword, icon in ACTIVITY_ICONS:
        if keyword in action:
            return icon
    return "📌"


@app.get("/activity", response_class=HTMLResponse)
def activity_page(request: Request, user: str = "All", action: str = "All", search: str = ""):
    current_user = require_login(request)
    if not current_user:
        return RedirectResponse("/login")

    logs = get_audit_logs()
    users = ["All"] + [u[1] for u in get_users()]
    actions = ["All"] + sorted({log["action"] for log in logs})

    today_str = datetime.now().strftime("%Y-%m-%d")
    today_count = sum(1 for log in logs if log["timestamp"].startswith(today_str))
    active_users = len({log["username"] for log in logs})

    filtered = logs
    if user != "All":
        filtered = [log for log in filtered if log["username"] == user]
    if action != "All":
        filtered = [log for log in filtered if log["action"] == action]
    if search:
        filtered = [log for log in filtered if search.lower() in log["action"].lower()]

    filtered = [{**log, "icon": _icon_for_action(log["action"])} for log in filtered]

    return render(
        request, "activity.html", active="activity",
        total=len(logs), today_count=today_count, active_users=active_users,
        users=users, actions=actions, user_filter=user, action_filter=action,
        search=search, filtered=filtered,
    )


@app.get("/activity/export.csv")
def activity_export(request: Request, user: str = "All", action: str = "All", search: str = ""):
    if not get_user(request):
        return RedirectResponse("/login")

    logs = get_audit_logs()
    if user != "All":
        logs = [log for log in logs if log["username"] == user]
    if action != "All":
        logs = [log for log in logs if log["action"] == action]
    if search:
        logs = [log for log in logs if search.lower() in log["action"].lower()]

    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["username", "action", "timestamp"])
    for log in logs:
        writer.writerow([log["username"], log["action"], log["timestamp"]])

    return Response(
        content=buffer.getvalue(), media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="activity_logs.csv"'},
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
        case_evidence=get_case_evidence(case_id),
        stats=get_case_statistics(case_id),
    )


@app.post("/cases/{case_id}/evidence/add")
async def case_evidence_add(
    request: Request, case_id: str,
    title: str = Form(...),
    evidence_file: UploadFile = File(...),
):
    user = require_login(request)
    if not user:
        return RedirectResponse("/login")

    file_bytes = await evidence_file.read()
    client_ip = request.client.host if request.client else "Not recorded"
    save_evidence(case_id, title, evidence_file.filename, file_bytes, user["username"], client_ip)
    return RedirectResponse(f"/cases/{case_id}", status_code=303)


@app.post("/cases/{case_id}/update")
def case_update(
    request: Request, case_id: str,
    case_name: str = Form(...), description: str = Form(""),
    priority: str = Form("Low"), status: str = Form("Open"),
):
    user = require_login(request)
    if not user:
        return RedirectResponse("/login")

    case_row = get_case(case_id)
    if case_row:
        update_case(case_id, case_name, description, case_row[4], priority, status)
        log_action(user["username"], f"Updated case: {case_id}")
    return RedirectResponse(f"/cases/{case_id}", status_code=303)


@app.post("/cases/{case_id}/delete")
def case_delete(request: Request, case_id: str):
    user = require_login(request)
    if not user:
        return RedirectResponse("/login")
    if user["role"] != "Admin":
        return forbidden(request)

    delete_case(case_id)
    log_action(user["username"], f"Deleted case: {case_id}")
    return RedirectResponse("/cases", status_code=303)


@app.get("/cases/{case_id}/report")
def case_report_download(request: Request, case_id: str):
    user = require_login(request)
    if not user:
        return RedirectResponse("/login")
    if user["role"] != "Admin":
        return forbidden(request)

    case_row = get_case(case_id)
    if not case_row:
        return RedirectResponse("/cases", status_code=303)

    filename = f"{case_id}_Report.html"
    generate_case_report(case_id, filename)
    with open(filename, "rb") as f:
        data = f.read()
    os.remove(filename)

    log_action(user["username"], f"Downloaded signed case report: {case_id}")
    return Response(
        content=data, media_type="text/html",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
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
