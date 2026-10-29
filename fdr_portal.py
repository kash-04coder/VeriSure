"""Database-backed AICTE FDR management prototype."""

import csv
import hashlib
import hmac
import io
import json
import logging
import os
import re
import secrets
import sqlite3
import uuid
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path
from urllib.parse import quote_plus

from fastapi import APIRouter, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from security import MAX_UPLOAD_BYTES, validate_upload


DB = os.environ.get("FDR_DATABASE_PATH", "forensic.db")
USER_DB = "forensic.db"
UPLOAD_ROOT = Path(os.environ.get("FDR_UPLOAD_DIR", "uploads/fdr")).resolve()
REQUIRED_FIELDS = (
    "fdr_number", "bank", "branch", "amount", "issue_date",
    "maturity_date", "holder",
)
FIELD_LABELS = {
    "fdr_number": "FDR number",
    "bank": "Issuing bank",
    "branch": "Bank branch",
    "amount": "Deposit amount",
    "issue_date": "Issue date",
    "maturity_date": "Maturity date",
    "holder": "Holder / beneficiary",
}
VALID_ACTIONS = {"confirm", "dispute", "clarification"}
router = APIRouter()
templates = Jinja2Templates(directory="templates")
templates.env.filters["loads"] = json.loads
logger = logging.getLogger(__name__)


def connect():
    conn = sqlite3.connect(DB, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_fdr_db():
    UPLOAD_ROOT.mkdir(parents=True, exist_ok=True)
    conn = connect()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS fdr_institutions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            region TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS fdr_user_scopes (
            username TEXT NOT NULL,
            institution_id INTEGER NOT NULL REFERENCES fdr_institutions(id),
            PRIMARY KEY (username, institution_id)
        );
        CREATE TABLE IF NOT EXISTS fdr_instruments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            institution_id INTEGER NOT NULL REFERENCES fdr_institutions(id),
            fdr_number TEXT NOT NULL,
            fdr_number_norm TEXT NOT NULL,
            bank TEXT NOT NULL,
            branch TEXT NOT NULL,
            amount TEXT NOT NULL,
            issue_date TEXT NOT NULL,
            maturity_date TEXT NOT NULL,
            holder TEXT NOT NULL,
            lifecycle_status TEXT NOT NULL DEFAULT 'Under verification',
            created_by TEXT NOT NULL,
            assigned_officer TEXT NOT NULL DEFAULT '',
            replaces_id INTEGER REFERENCES fdr_instruments(id),
            duplicate_flag INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_fdr_number_norm ON fdr_instruments(fdr_number_norm);
        CREATE INDEX IF NOT EXISTS idx_fdr_maturity ON fdr_instruments(maturity_date);
        CREATE INDEX IF NOT EXISTS idx_fdr_institution ON fdr_instruments(institution_id);
        CREATE TABLE IF NOT EXISTS fdr_field_values (
            instrument_id INTEGER NOT NULL REFERENCES fdr_instruments(id),
            field_name TEXT NOT NULL,
            claimed_value TEXT NOT NULL,
            extracted_value TEXT,
            extraction_confidence TEXT NOT NULL DEFAULT 'unavailable',
            confirmed_value TEXT,
            verification_status TEXT NOT NULL DEFAULT 'Pending bank verification',
            verification_source TEXT,
            performed_by TEXT,
            performed_at TEXT,
            remarks TEXT,
            PRIMARY KEY (instrument_id, field_name)
        );
        CREATE TABLE IF NOT EXISTS fdr_field_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            instrument_id INTEGER NOT NULL REFERENCES fdr_instruments(id),
            field_name TEXT NOT NULL,
            claimed_value TEXT NOT NULL,
            confirmed_value TEXT,
            verification_status TEXT NOT NULL,
            action TEXT NOT NULL,
            actor TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS fdr_documents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            instrument_id INTEGER REFERENCES fdr_instruments(id),
            upload_id TEXT UNIQUE,
            owner TEXT NOT NULL,
            original_name TEXT NOT NULL,
            storage_path TEXT NOT NULL,
            sha256 TEXT NOT NULL,
            extraction_json TEXT NOT NULL DEFAULT '{}',
            used INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS fdr_verification_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            instrument_id INTEGER NOT NULL REFERENCES fdr_instruments(id),
            field_name TEXT NOT NULL,
            token_hash TEXT NOT NULL UNIQUE,
            created_by TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            consumed_at TEXT,
            status TEXT NOT NULL DEFAULT 'Pending'
        );
        CREATE TABLE IF NOT EXISTS fdr_verification_responses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_id INTEGER NOT NULL UNIQUE REFERENCES fdr_verification_requests(id),
            response TEXT NOT NULL,
            confirmed_value TEXT,
            remark TEXT NOT NULL,
            verification_source TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS fdr_discrepancies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            instrument_id INTEGER NOT NULL REFERENCES fdr_instruments(id),
            field_name TEXT NOT NULL,
            explanation TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'Open',
            created_at TEXT NOT NULL,
            resolved_at TEXT,
            resolved_by TEXT
        );
        CREATE TABLE IF NOT EXISTS fdr_scrutiny_remarks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            instrument_id INTEGER NOT NULL REFERENCES fdr_instruments(id),
            officer TEXT NOT NULL,
            remark TEXT NOT NULL,
            action TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS fdr_release_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            instrument_id INTEGER NOT NULL REFERENCES fdr_instruments(id),
            requested_by TEXT NOT NULL,
            reason TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'Submitted',
            rule_set_version INTEGER NOT NULL,
            eligibility_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            decision_by TEXT,
            decision_note TEXT NOT NULL DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS fdr_rule_sets (
            version INTEGER PRIMARY KEY,
            rules_json TEXT NOT NULL,
            created_by TEXT NOT NULL,
            created_at TEXT NOT NULL,
            active INTEGER NOT NULL DEFAULT 1
        );
        CREATE TABLE IF NOT EXISTS fdr_notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            instrument_id INTEGER NOT NULL REFERENCES fdr_instruments(id),
            event_key TEXT NOT NULL UNIQUE,
            message TEXT NOT NULL,
            due_date TEXT NOT NULL,
            created_at TEXT NOT NULL,
            read_at TEXT
        );
        CREATE TABLE IF NOT EXISTS fdr_settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS fdr_audit_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id TEXT NOT NULL UNIQUE,
            actor TEXT NOT NULL,
            actor_role TEXT NOT NULL,
            action TEXT NOT NULL,
            entity_type TEXT NOT NULL,
            entity_id TEXT NOT NULL,
            summary TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            previous_hash TEXT NOT NULL,
            event_hash TEXT NOT NULL
        );
    """)
    conn.execute(
        "INSERT OR IGNORE INTO fdr_settings(key, value) VALUES('demo_days_offset', '0')"
    )
    conn.execute(
        "INSERT OR IGNORE INTO fdr_settings(key, value) VALUES('reminder_days', '[90,60,30,7]')"
    )
    conn.execute(
        "INSERT OR IGNORE INTO fdr_rule_sets(version, rules_json, created_by, created_at, active) "
        "VALUES(1, ?, 'system', ?, 1)",
        (json.dumps({"require_document": True, "require_verified": True,
                     "block_discrepancy": True}), _now()),
    )
    conn.commit()
    conn.close()


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _normalize_fdr(value):
    return re.sub(r"[^A-Z0-9]", "", value.upper())


def _values_match(field_name, left, right):
    if field_name == "fdr_number":
        return _normalize_fdr(left) == _normalize_fdr(right)
    if field_name == "amount":
        try:
            return Decimal(left) == Decimal(right)
        except InvalidOperation:
            return False
    if field_name in ("issue_date", "maturity_date"):
        try:
            return date.fromisoformat(left) == date.fromisoformat(right)
        except ValueError:
            return False
    return " ".join(left.split()).casefold() == " ".join(right.split()).casefold()


def _csv_safe(value):
    text = str(value)
    if text.startswith(("=", "+", "-", "@", "\t", "\r")):
        return "'" + text
    return text


def _audit(conn, user, action, entity_type, entity_id, summary):
    previous = conn.execute(
        "SELECT event_hash FROM fdr_audit_events ORDER BY id DESC LIMIT 1"
    ).fetchone()
    previous_hash = previous["event_hash"] if previous else "0" * 64
    record = {
        "event_id": uuid.uuid4().hex,
        "actor": user["username"],
        "actor_role": user["role"],
        "action": action,
        "entity_type": entity_type,
        "entity_id": str(entity_id),
        "summary": summary,
        "timestamp": _now(),
        "previous_hash": previous_hash,
    }
    digest = hashlib.sha256(
        json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    conn.execute("""
        INSERT INTO fdr_audit_events(
            event_id, actor, actor_role, action, entity_type, entity_id,
            summary, timestamp, previous_hash, event_hash
        ) VALUES(:event_id,:actor,:actor_role,:action,:entity_type,:entity_id,
                 :summary,:timestamp,:previous_hash,:event_hash)
    """, {**record, "event_hash": digest})
    return digest


def verify_audit_chain():
    conn = connect()
    rows = conn.execute("SELECT * FROM fdr_audit_events ORDER BY id").fetchall()
    conn.close()
    expected_previous = "0" * 64
    for row in rows:
        record = {key: row[key] for key in (
            "event_id", "actor", "actor_role", "action", "entity_type",
            "entity_id", "summary", "timestamp", "previous_hash",
        )}
        digest = hashlib.sha256(
            json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        if row["previous_hash"] != expected_previous or not hmac.compare_digest(
            digest, row["event_hash"]
        ):
            return False, row["id"], len(rows)
        expected_previous = row["event_hash"]
    return True, None, len(rows)


def _role(user):
    return {
        "Admin": "Bureau Admin",
        "Competent Authority": "Bureau Admin",
        "Institution": "Institution User",
        "Scrutiny Officer": "Regional Officer",
        "Bank Verifier": "Bank Verifier",
        "Investigator": "Regional Officer",
        "Analyst": "Regional Officer",
        "Viewer": "Institution User",
    }.get(user["role"], user["role"])


def _require_user(request):
    user = request.session.get("user")
    if not user:
        return None
    with sqlite3.connect(USER_DB) as conn:
        current = conn.execute(
            "SELECT role FROM users WHERE username=?", (user["username"],)
        ).fetchone()
    if not current:
        return None
    return {"username": user["username"], "role": _role({"role": current[0]})}


def _is_admin(user):
    return user["role"] == "Bureau Admin"


def _csrf_token(request):
    token = request.session.get("_fdr_csrf")
    if not token:
        token = secrets.token_urlsafe(32)
        request.session["_fdr_csrf"] = token
    return token


def _check_csrf(request, submitted):
    expected = request.session.get("_fdr_csrf", "")
    if not expected or not hmac.compare_digest(expected, submitted or ""):
        raise HTTPException(status_code=403, detail="Invalid or missing CSRF token.")


def _render(request, template, user=None, active="", **context):
    public_link = user is None and _require_user(request) is None
    return templates.TemplateResponse(request, template, {
        "user": user or _require_user(request) or {
            "username": "Secure verifier link", "role": "Bank Verifier"
        },
        "public_link": public_link,
        "active": active,
        "csrf_token": _csrf_token(request),
        "demo_mode": True,
        **context,
    })


def _scope_ids(user):
    if _is_admin(user):
        return None
    conn = connect()
    rows = conn.execute(
        "SELECT institution_id FROM fdr_user_scopes WHERE username=?",
        (user["username"],),
    ).fetchall()
    conn.close()
    return [row["institution_id"] for row in rows]


def _visible_instrument(conn, instrument_id, user):
    row = conn.execute("""
        SELECT i.*, ins.name AS institution_name, ins.region,
               original.fdr_number AS replaces_fdr_number
        FROM fdr_instruments i
        JOIN fdr_institutions ins ON ins.id=i.institution_id
        LEFT JOIN fdr_instruments original ON original.id=i.replaces_id
        WHERE i.id=?
    """, (instrument_id,)).fetchone()
    if not row:
        return None
    if _is_admin(user):
        return row
    scope_ids = _scope_ids(user)
    if scope_ids is None or row["institution_id"] in scope_ids:
        return row
    return None


def _visible_instruments(user, search="", status=""):
    conn = connect()
    query = """
        SELECT i.*, ins.name AS institution_name, ins.region,
               (SELECT COUNT(*) FROM fdr_field_values fv
                WHERE fv.instrument_id=i.id
                AND fv.verification_status='Pending bank verification') AS pending_fields,
               (SELECT COUNT(*) FROM fdr_discrepancies d
                WHERE d.instrument_id=i.id AND d.status='Open') AS open_discrepancies
        FROM fdr_instruments i
        JOIN fdr_institutions ins ON ins.id=i.institution_id
        WHERE 1=1
    """
    params = []
    scope_ids = _scope_ids(user)
    if scope_ids is not None:
        if not scope_ids:
            conn.close()
            return []
        query += " AND i.institution_id IN (" + ",".join("?" for _ in scope_ids) + ")"
        params.extend(scope_ids)
    if search:
        like = f"%{search.strip()}%"
        query += " AND (i.fdr_number LIKE ? OR i.bank LIKE ? OR ins.name LIKE ?)"
        params.extend([like, like, like])
    if status:
        query += " AND i.lifecycle_status=?"
        params.append(status)
    query += " ORDER BY i.maturity_date, i.id DESC"
    rows = [dict(row) for row in conn.execute(query, params).fetchall()]
    conn.close()
    return rows


def _settings(conn):
    return {row["key"]: row["value"] for row in conn.execute(
        "SELECT key,value FROM fdr_settings"
    ).fetchall()}


def _effective_date(conn):
    offset = int(_settings(conn).get("demo_days_offset", "0"))
    return date.today() + timedelta(days=offset)


def _scan_maturities(conn, today):
    settings = _settings(conn)
    try:
        thresholds = sorted({int(x) for x in json.loads(settings["reminder_days"])
                             if int(x) > 0}, reverse=True)
    except (ValueError, KeyError, TypeError, json.JSONDecodeError):
        thresholds = [90, 60, 30, 7]
    rows = conn.execute("""
        SELECT id, fdr_number, maturity_date
        FROM fdr_instruments
        WHERE lifecycle_status NOT IN ('Renewed', 'Released')
    """).fetchall()
    for row in rows:
        try:
            days = (date.fromisoformat(row["maturity_date"]) - today).days
        except ValueError:
            continue
        if days < 0:
            matured = conn.execute("""
                UPDATE fdr_instruments SET lifecycle_status='Matured'
                WHERE id=? AND lifecycle_status IN ('Active','Under verification')
            """, (row["id"],))
            if matured.rowcount:
                _audit(conn, {"username": "deadline-monitor", "role": "System"},
                       "Instrument matured", "instrument", row["id"],
                       "Maturity date passed; no release or renewal was assumed.")
        if days < -15:
            escalated = conn.execute("""
                UPDATE fdr_instruments SET lifecycle_status='Escalated'
                WHERE id=? AND lifecycle_status NOT IN ('Renewed','Released','Escalated')
            """, (row["id"],))
            if escalated.rowcount:
                _audit(conn, {"username": "deadline-monitor", "role": "System"},
                       "Instrument escalated", "instrument", row["id"],
                       "Renewal or resolution remains overdue by more than 15 days.")
        reminder = next((threshold for threshold in thresholds if days == threshold), None)
        event_type = f"maturity-{reminder}" if reminder is not None else (
            "maturity-escalated" if days < -15 else
            "maturity-overdue" if days < 0 else None
        )
        if event_type:
            key = f"{row['id']}:{today.isoformat()}:{event_type}"
            inserted = conn.execute("""
                INSERT OR IGNORE INTO fdr_notifications(
                    instrument_id,event_key,message,due_date,created_at
                ) VALUES(?,?,?,?,?)
            """, (
                row["id"], key,
                f"FDR {row['fdr_number']} is " +
                (f"due in {reminder} days." if reminder is not None else
                 "escalated after more than 15 overdue days." if days < -15 else
                 "overdue."),
                row["maturity_date"], _now(),
            ))
            if inserted.rowcount:
                _audit(conn, {"username": "deadline-monitor", "role": "System"},
                       "Maturity reminder generated", "instrument", row["id"],
                       f"Prototype reminder threshold reached: {event_type}.")


def scan_deadlines():
    conn = connect()
    _scan_maturities(conn, _effective_date(conn))
    conn.commit()
    conn.close()


def _candidate_fields(text):
    candidates = {}
    labels = {
        "fdr_number": r"(?:FDR|FD)\s*(?:number|no\.?|#)\s*[:\-]\s*(.+)",
        "bank": r"(?:issuing\s+)?bank\s*[:\-]\s*(.+)",
        "branch": r"(?:bank\s+)?branch\s*[:\-]\s*(.+)",
        "amount": r"(?:deposit\s+)?amount\s*[:\-]\s*(.+)",
        "issue_date": r"(?:issue|issuance)\s+date\s*[:\-]\s*(.+)",
        "maturity_date": r"maturity\s+date\s*[:\-]\s*(.+)",
        "holder": r"(?:holder|beneficiary)\s*(?:name)?\s*[:\-]\s*(.+)",
    }
    for field, pattern in labels.items():
        match = re.search(pattern, text, re.IGNORECASE | re.MULTILINE)
        if match:
            value = match.group(1).strip()[:200]
            if field == "amount":
                amount = re.search(r"\d[\d,]*(?:\.\d{1,2})?", value)
                if amount:
                    value = amount.group(0).replace(",", "")
                else:
                    continue
            elif field in ("issue_date", "maturity_date"):
                parsed = None
                for date_format in ("%Y-%m-%d", "%d/%m/%Y", "%d-%m-%Y",
                                    "%d/%m/%y", "%d-%m-%y"):
                    try:
                        parsed = datetime.strptime(value, date_format).date()
                        break
                    except ValueError:
                        continue
                if parsed is None:
                    continue
                value = parsed.isoformat()
            candidates[field] = value
    return candidates


async def _store_upload(file, owner):
    filename = file.filename or ""
    content = await file.read(MAX_UPLOAD_BYTES + 1)
    filename = validate_upload(content, filename)
    suffix = Path(filename).suffix.lower()

    upload_id = uuid.uuid4().hex
    destination = UPLOAD_ROOT / f"{upload_id}{suffix}"
    destination.write_bytes(content)
    extraction = {"status": "unavailable", "candidates": {}, "confidence": "unavailable"}
    try:
        from forensics.ocr_extract import extract_document_content
        result = extract_document_content(str(destination))
        if result.get("error"):
            extraction["status"] = "error"
            extraction["message"] = result["error"][:300]
        else:
            extraction = {
                "status": "complete",
                "candidates": _candidate_fields(result.get("text", "")),
                "confidence": "unavailable",
            }
    except Exception as exc:
        extraction = {"status": "error", "candidates": {},
                      "confidence": "unavailable", "message": str(exc)[:300]}
    conn = connect()
    conn.execute("""
        INSERT INTO fdr_documents(
            upload_id,owner,original_name,storage_path,sha256,extraction_json,created_at
        ) VALUES(?,?,?,?,?,?,?)
    """, (upload_id, owner, filename, str(destination),
          hashlib.sha256(content).hexdigest(),
          json.dumps(extraction), _now()))
    conn.commit()
    conn.close()
    return upload_id, extraction


def _ocr_values_match(field, claimed, extracted):
    if not extracted:
        return True
    if field == "amount":
        try:
            return Decimal(str(claimed)).quantize(Decimal("0.01")) == Decimal(
                str(extracted)
            ).quantize(Decimal("0.01"))
        except (InvalidOperation, TypeError, ValueError):
            return False
    if field in ("issue_date", "maturity_date"):
        return str(claimed) == str(extracted)
    return " ".join(str(claimed).split()).casefold() == " ".join(
        str(extracted).split()
    ).casefold()


def _validate_instrument(data):
    errors = []
    for field in REQUIRED_FIELDS:
        if not str(data.get(field, "")).strip():
            errors.append(f"{FIELD_LABELS[field]} is required.")
    if data.get("fdr_number") and not _normalize_fdr(str(data["fdr_number"])):
        errors.append("FDR number must contain at least one letter or number.")
    try:
        amount = Decimal(str(data.get("amount", "")))
        if not amount.is_finite() or amount <= 0:
            errors.append("Deposit amount must be greater than zero.")
        elif amount != amount.quantize(Decimal("0.01")):
            errors.append("Deposit amount may contain no more than two decimal places.")
    except (InvalidOperation, TypeError, ValueError):
        errors.append("Deposit amount must be a valid number.")
    parsed_dates = {}
    for field in ("issue_date", "maturity_date"):
        try:
            parsed_dates[field] = date.fromisoformat(str(data.get(field, "")))
        except ValueError:
            errors.append(f"{FIELD_LABELS[field]} must use a valid YYYY-MM-DD date.")
    if len(parsed_dates) == 2 and parsed_dates["maturity_date"] < parsed_dates["issue_date"]:
        errors.append("Maturity date must be on or after the issue date.")
    return errors


def _eligibility(conn, instrument_id, rule_version=None):
    settings = conn.execute(
        "SELECT version,rules_json FROM fdr_rule_sets WHERE " +
        ("version=?" if rule_version is not None else "active=1") +
        " ORDER BY version DESC LIMIT 1",
        (rule_version,) if rule_version is not None else (),
    ).fetchone()
    version = settings["version"] if settings else 1
    rules = json.loads(settings["rules_json"]) if settings else {}
    fields = conn.execute("""
        SELECT field_name, verification_status FROM fdr_field_values WHERE instrument_id=?
    """, (instrument_id,)).fetchall()
    verified = len(fields) == len(REQUIRED_FIELDS) and all(
        field["verification_status"] == "Bank-confirmed" for field in fields
    )
    document = conn.execute(
        "SELECT 1 FROM fdr_documents WHERE instrument_id=? LIMIT 1", (instrument_id,)
    ).fetchone() is not None
    discrepancy = conn.execute(
        "SELECT 1 FROM fdr_discrepancies WHERE instrument_id=? AND status='Open' LIMIT 1",
        (instrument_id,),
    ).fetchone() is not None
    checks = [
        {"name": "Supporting document", "passed": document or not rules.get("require_document", True),
         "explanation": "A supporting document is attached." if document else
         "Attach the required supporting document."},
        {"name": "Required fields confirmed",
         "passed": verified or not rules.get("require_verified", True),
         "explanation": "All critical fields are bank-confirmed." if verified else
         "Complete independent bank confirmation for every critical field."},
        {"name": "No unresolved discrepancy",
         "passed": not discrepancy or not rules.get("block_discrepancy", True),
         "explanation": "No open discrepancy is recorded." if not discrepancy else
         "Resolve the open discrepancy before requesting release."},
    ]
    return {"rule_set_version": version, "checks": checks,
            "eligible": all(check["passed"] for check in checks)}


def _release_visible(conn, release_id, user):
    row = conn.execute("""
        SELECT r.*, i.fdr_number, i.institution_id, ins.name AS institution_name
        FROM fdr_release_requests r
        JOIN fdr_instruments i ON i.id=r.instrument_id
        JOIN fdr_institutions ins ON ins.id=i.institution_id
        WHERE r.id=?
    """, (release_id,)).fetchone()
    if not row:
        return None
    return row if _is_admin(user) or row["institution_id"] in (_scope_ids(user) or []) else None


@router.get("/fdr", include_in_schema=False)
def fdr_root():
    return RedirectResponse("/fdr/dashboard", status_code=303)


@router.get("/fdr/dashboard", response_class=HTMLResponse)
def dashboard(request: Request):
    user = _require_user(request)
    if not user:
        return RedirectResponse("/login")
    rows = _visible_instruments(user)
    conn = connect()
    today = _effective_date(conn)
    _scan_maturities(conn, today)
    conn.commit()
    scope_ids = _scope_ids(user)
    notification_sql = """
        SELECT n.*, i.fdr_number FROM fdr_notifications n
        JOIN fdr_instruments i ON i.id=n.instrument_id
    """
    notification_params = []
    if scope_ids is not None:
        if scope_ids:
            notification_sql += " WHERE i.institution_id IN (" + ",".join(
                "?" for _ in scope_ids
            ) + ")"
            notification_params.extend(scope_ids)
        else:
            notification_sql += " WHERE 0=1"
    notification_sql += " ORDER BY n.id DESC LIMIT 8"
    notifications = conn.execute(notification_sql, notification_params).fetchall()
    releases = conn.execute(
        "SELECT COUNT(*) AS count FROM fdr_release_requests WHERE status IN ('Submitted','Under scrutiny','Recommended')"
    ).fetchone()["count"]
    conn.close()
    total_amount = sum((Decimal(r["amount"]) for r in rows), Decimal("0.00"))
    expiring = 0
    overdue = 0
    for row in rows:
        try:
            days = (date.fromisoformat(row["maturity_date"]) - today).days
            expiring += 0 <= days <= 30
            overdue += days < 0 and row["lifecycle_status"] not in ("Renewed", "Released")
        except ValueError:
            continue
    kpis = {
        "total": len(rows),
        "value": f"{total_amount:,.2f}",
        "active": sum(r["lifecycle_status"] == "Active" for r in rows),
        "expiring": expiring,
        "pending": sum(r["pending_fields"] > 0 for r in rows),
        "discrepancies": sum(r["open_discrepancies"] > 0 for r in rows),
        "releases": releases if _is_admin(user) else 0,
        "overdue": overdue,
        "matured": sum(r["lifecycle_status"] == "Matured" for r in rows),
        "renewals": sum(r["lifecycle_status"] == "Renewal pending" for r in rows),
    }
    lifecycle_counts = {}
    for row in rows:
        lifecycle_counts[row["lifecycle_status"]] = lifecycle_counts.get(
            row["lifecycle_status"], 0
        ) + 1
    status_chart = [
        {"label": label, "count": count,
         "percent": round(count / len(rows) * 100) if rows else 0}
        for label, count in sorted(lifecycle_counts.items())
    ]
    maturity_months = {}
    for row in rows:
        month = row["maturity_date"][:7]
        maturity_months[month] = maturity_months.get(month, 0) + 1
    maturity_chart = [
        {"month": month, "count": count,
         "percent": round(count / max(maturity_months.values()) * 100)}
        for month, count in sorted(maturity_months.items())[:8]
    ]
    return _render(request, "fdr_dashboard.html", user, "dashboard",
                   kpis=kpis, instruments=rows[:8], notifications=notifications,
                   today=today.isoformat(), status_chart=status_chart,
                   maturity_chart=maturity_chart)


@router.get("/fdr/registry", response_class=HTMLResponse)
def registry(request: Request, q: str = "", status: str = ""):
    user = _require_user(request)
    if not user:
        return RedirectResponse("/login")
    rows = _visible_instruments(user, q, status)
    return _render(request, "fdr_registry.html", user, "registry",
                   instruments=rows, q=q, selected_status=status)


@router.get("/fdr/verification", response_class=HTMLResponse)
def verification_center(request: Request, status: str = ""):
    user = _require_user(request)
    if not user:
        return RedirectResponse("/login")
    instruments = _visible_instruments(user)
    records = []
    conn = connect()
    for instrument in instruments:
        fields = conn.execute("""
            SELECT field_name,claimed_value,confirmed_value,verification_status
            FROM fdr_field_values WHERE instrument_id=? ORDER BY field_name
        """, (instrument["id"],)).fetchall()
        for field in fields:
            if status and field["verification_status"] != status:
                continue
            if field["verification_status"] != "Bank-confirmed" or not status:
                records.append({
                    **dict(field),
                    "instrument_id": instrument["id"],
                    "fdr_number": instrument["fdr_number"],
                    "institution_name": instrument["institution_name"],
                    "bank": instrument["bank"],
                })
    conn.close()
    return _render(request, "fdr_verification.html", user, "verification",
                   records=records, selected_status=status, labels=FIELD_LABELS)


@router.get("/fdr/renewals", response_class=HTMLResponse)
def renewal_history(request: Request):
    user = _require_user(request)
    if not user:
        return RedirectResponse("/login")
    instruments = _visible_instruments(user)
    rows = []
    conn = connect()
    for item in instruments:
        if item["replaces_id"] or item["lifecycle_status"] == "Renewal pending":
            rows.append({**item, "relationship": "Replacement instrument"})
        children = conn.execute("""
            SELECT id,fdr_number,maturity_date,lifecycle_status
            FROM fdr_instruments WHERE replaces_id=? AND institution_id=?
            ORDER BY id DESC
        """, (item["id"], item["institution_id"])).fetchall()
        rows.extend({
            "id": child["id"], "fdr_number": child["fdr_number"],
            "maturity_date": child["maturity_date"],
            "lifecycle_status": child["lifecycle_status"],
            "institution_name": item["institution_name"],
            "relationship": f"Replaces {item['fdr_number']}",
        } for child in children)
    conn.close()
    return _render(request, "fdr_renewals.html", user, "renewals", instruments=rows)


@router.get("/fdr/reports", response_class=HTMLResponse)
def reports_page(request: Request):
    user = _require_user(request)
    if not user:
        return RedirectResponse("/login")
    rows = _visible_instruments(user)
    conn = connect()
    today = _effective_date(conn)
    conn.close()
    reports = [
        {"label": "Complete FDR registry", "key": "registry", "count": len(rows)},
        {"label": "Pending verifications", "key": "pending",
         "count": sum(bool(item["pending_fields"]) for item in rows)},
        {"label": "Overdue instruments", "key": "overdue",
         "count": sum(
             date.fromisoformat(item["maturity_date"]) < today
             for item in rows
         )},
        {"label": "Instruments with open discrepancies", "key": "discrepancies",
         "count": sum(bool(item["open_discrepancies"]) for item in rows)},
        {"label": "Renewal and replacement history", "key": "renewals",
         "count": sum(bool(item["replaces_id"]) for item in rows)},
    ]
    return _render(request, "fdr_reports.html", user, "reports", reports=reports)


@router.get("/fdr/new", response_class=HTMLResponse)
def new_instrument(request: Request, upload_id: str = "", error: str = ""):
    user = _require_user(request)
    if not user:
        return RedirectResponse("/login")
    if user["role"] not in ("Institution User", "Bureau Admin"):
        raise HTTPException(403, "Only institution users and bureau admins can submit FDRs.")
    conn = connect()
    if user["role"] == "Bureau Admin":
        institutions = conn.execute("SELECT * FROM fdr_institutions ORDER BY name").fetchall()
    else:
        institutions = conn.execute("""
            SELECT i.* FROM fdr_institutions i JOIN fdr_user_scopes s ON s.institution_id=i.id
            WHERE s.username=? ORDER BY i.name
        """, (user["username"],)).fetchall()
    scoped_ids = [item["id"] for item in institutions]
    replaces = []
    if scoped_ids:
        replaces = conn.execute(
            "SELECT id,fdr_number,institution_id FROM fdr_instruments WHERE institution_id IN (" +
            ",".join("?" for _ in scoped_ids) + ") ORDER BY id DESC",
            scoped_ids,
        ).fetchall()
    staged = None
    if upload_id:
        staged = conn.execute("""
            SELECT * FROM fdr_documents WHERE upload_id=? AND owner=? AND instrument_id IS NULL
              AND used=0
        """, (upload_id, user["username"])).fetchone()
    conn.close()
    extraction = json.loads(staged["extraction_json"]) if staged else {}
    return _render(request, "fdr_new.html", user, "new",
                   institutions=institutions, upload_id=upload_id if staged else "",
                   extraction=extraction, error=error, replaces=replaces)


@router.post("/fdr/intake")
async def intake_upload(request: Request, csrf: str = Form(...), document: UploadFile = File(...)):
    user = _require_user(request)
    if not user:
        return RedirectResponse("/login")
    _check_csrf(request, csrf)
    if user["role"] not in ("Institution User", "Bureau Admin"):
        raise HTTPException(403, "You cannot submit FDR documents.")
    try:
        upload_id, _ = await _store_upload(document, user["username"])
    except HTTPException as exc:
        return RedirectResponse(f"/fdr/new?error={exc.detail}", status_code=303)
    return RedirectResponse(f"/fdr/new?upload_id={upload_id}", status_code=303)


@router.post("/fdr/new")
def create_instrument(
    request: Request,
    csrf: str = Form(...),
    institution_id: int = Form(...),
    fdr_number: str = Form(...),
    bank: str = Form(...),
    branch: str = Form(...),
    amount: str = Form(...),
    issue_date: str = Form(...),
    maturity_date: str = Form(...),
    holder: str = Form(...),
    upload_id: str = Form(""),
    replaces_id: int = Form(0),
):
    user = _require_user(request)
    if not user:
        return RedirectResponse("/login")
    _check_csrf(request, csrf)
    if user["role"] not in ("Institution User", "Bureau Admin"):
        raise HTTPException(403, "You cannot submit FDRs.")
    values = locals()
    errors = _validate_instrument(values)
    conn = connect()
    institution = conn.execute(
        "SELECT id FROM fdr_institutions WHERE id=?", (institution_id,)
    ).fetchone()
    if not institution:
        errors.append("Select a valid institution.")
    if user["role"] != "Bureau Admin" and institution_id not in (_scope_ids(user) or []):
        conn.close()
        raise HTTPException(403, "You may submit FDRs only for an assigned institution.")
    staged = None
    if upload_id:
        staged = conn.execute("""
            SELECT * FROM fdr_documents WHERE upload_id=? AND owner=? AND instrument_id IS NULL
              AND used=0
        """, (upload_id, user["username"])).fetchone()
        if not staged:
            errors.append("The uploaded document is no longer available; upload it again.")
    if replaces_id:
        original = conn.execute(
            "SELECT institution_id FROM fdr_instruments WHERE id=?", (replaces_id,)
        ).fetchone()
        if not original or original["institution_id"] != institution_id:
            errors.append("A replacement must link to an existing instrument at the same institution.")
    if errors:
        conn.close()
        return RedirectResponse(
            f"/fdr/new?error={quote_plus('; '.join(errors))}" +
            (f"&upload_id={upload_id}" if staged else ""), status_code=303,
        )
    normalized = _normalize_fdr(fdr_number)
    duplicate = conn.execute(
        "SELECT 1 FROM fdr_instruments WHERE fdr_number_norm=? LIMIT 1", (normalized,)
    ).fetchone() is not None
    timestamp = _now()
    cursor = conn.execute("""
        INSERT INTO fdr_instruments(
            institution_id,fdr_number,fdr_number_norm,bank,branch,amount,issue_date,
            maturity_date,holder,lifecycle_status,created_by,replaces_id,duplicate_flag,created_at
        ) VALUES(?,?,?,?,?,?,?,?,?,'Under verification',?,?,?,?)
    """, (
        institution_id, fdr_number.strip(), normalized, bank.strip(), branch.strip(),
        format(Decimal(amount).quantize(Decimal("0.01")), "f"),
        issue_date, maturity_date, holder.strip(),
        user["username"], replaces_id or None, int(duplicate), timestamp,
    ))
    instrument_id = cursor.lastrowid
    field_values = {
        "fdr_number": fdr_number.strip(), "bank": bank.strip(), "branch": branch.strip(),
        "amount": format(Decimal(amount).quantize(Decimal("0.01")), "f"),
        "issue_date": issue_date,
        "maturity_date": maturity_date, "holder": holder.strip(),
    }
    candidates = json.loads(staged["extraction_json"]).get("candidates", {}) if staged else {}
    conn.executemany("""
        INSERT INTO fdr_field_values(
            instrument_id,field_name,claimed_value,extracted_value,extraction_confidence
        ) VALUES(?,?,?,?,?)
    """, [
        (instrument_id, field, value, candidates.get(field), "unavailable")
        for field, value in field_values.items()
    ])
    conn.executemany("""
        INSERT INTO fdr_field_history(
            instrument_id,field_name,claimed_value,verification_status,
            action,actor,created_at
        ) VALUES(?,?,?,'Pending bank verification','Claim submitted',?,?)
    """, [
        (instrument_id, field, value, user["username"], timestamp)
        for field, value in field_values.items()
    ])
    if staged:
        conn.execute(
            "UPDATE fdr_documents SET instrument_id=?,used=1 WHERE upload_id=?",
            (instrument_id, upload_id),
        )
    ocr_mismatch = False
    for field, extracted in candidates.items():
        if field in field_values and not _ocr_values_match(
            field, field_values[field], extracted
        ):
            ocr_mismatch = True
            conn.execute(
                "INSERT INTO fdr_discrepancies("
                "instrument_id,field_name,explanation,created_at"
                ") VALUES(?,?,?,?)",
                (
                    instrument_id,
                    field,
                    f"OCR candidate '{extracted}' differs from the institution-claimed "
                    f"value '{field_values[field]}'. OCR is not confirmation; review "
                    "the source document and obtain an independent response.",
                    timestamp,
                ),
            )
    if ocr_mismatch:
        conn.execute(
            "UPDATE fdr_instruments SET lifecycle_status='Discrepancy unresolved' "
            "WHERE id=?",
            (instrument_id,),
        )
    if duplicate:
        conn.execute("""
            INSERT INTO fdr_discrepancies(instrument_id,field_name,explanation,created_at)
            VALUES(?,?,?,?)
        """, (
            instrument_id, "fdr_number",
            "This normalized FDR identifier is already registered. Verify the reference and provide clarification.",
            timestamp,
        ))
    if replaces_id:
        conn.execute("""
            UPDATE fdr_instruments SET lifecycle_status='Renewal pending'
            WHERE id=? AND institution_id=?
        """, (replaces_id, institution_id))
    _audit(conn, user, "FDR submitted", "instrument", instrument_id,
           "Institution-claimed fields recorded; independent bank verification is pending.")
    conn.commit()
    conn.close()
    return RedirectResponse(f"/fdr/{instrument_id}", status_code=303)


@router.post("/fdr/{instrument_id:int}/fields/{field_name}/claim")
def update_claimed_field(request: Request, instrument_id: int, field_name: str,
                         csrf: str = Form(...), claimed_value: str = Form(...)):
    user = _require_user(request)
    if not user:
        return RedirectResponse("/login")
    _check_csrf(request, csrf)
    if user["role"] not in ("Institution User", "Bureau Admin"):
        raise HTTPException(403, "Only the submitting institution may correct claimed values.")
    if field_name not in REQUIRED_FIELDS or not claimed_value.strip():
        raise HTTPException(400, "Provide a valid critical field value.")
    conn = connect()
    instrument = _visible_instrument(conn, instrument_id, user)
    if not instrument:
        conn.close()
        raise HTTPException(404, "FDR not found.")
    row = conn.execute("""
        SELECT * FROM fdr_field_values WHERE instrument_id=? AND field_name=?
    """, (instrument_id, field_name)).fetchone()
    if not row:
        conn.close()
        raise HTTPException(404, "FDR field not found.")
    value = claimed_value.strip()[:200]
    if field_name == "amount":
        try:
            amount = Decimal(value)
            if not amount.is_finite() or amount <= 0:
                raise ValueError
            if amount != amount.quantize(Decimal("0.01")):
                raise ValueError
            value = format(amount, "f")
        except (InvalidOperation, ValueError) as exc:
            conn.close()
            raise HTTPException(400, "Deposit amount must be a positive finite number.") from exc
    if field_name in ("issue_date", "maturity_date"):
        try:
            date.fromisoformat(value)
        except ValueError as exc:
            conn.close()
            raise HTTPException(400, "Dates must use the YYYY-MM-DD format.") from exc
        other_field = "maturity_date" if field_name == "issue_date" else "issue_date"
        other = conn.execute("""
            SELECT claimed_value FROM fdr_field_values
            WHERE instrument_id=? AND field_name=?
        """, (instrument_id, other_field)).fetchone()
        issue = value if field_name == "issue_date" else other["claimed_value"]
        maturity = value if field_name == "maturity_date" else other["claimed_value"]
        if date.fromisoformat(maturity) < date.fromisoformat(issue):
            conn.close()
            raise HTTPException(400, "Maturity date must be on or after the issue date.")
    duplicate = False
    if field_name == "fdr_number":
        normalized = _normalize_fdr(value)
        if not normalized:
            conn.close()
            raise HTTPException(400, "FDR number must contain at least one letter or number.")
        duplicate = conn.execute("""
            SELECT 1 FROM fdr_instruments
            WHERE fdr_number_norm=? AND id!=? LIMIT 1
        """, (normalized, instrument_id)).fetchone() is not None
        conn.execute("""
            UPDATE fdr_instruments SET fdr_number=?,fdr_number_norm=?,duplicate_flag=?
            WHERE id=?
        """, (value, normalized, int(duplicate), instrument_id))
    else:
        column = {
            "bank": "bank", "branch": "branch", "amount": "amount",
            "issue_date": "issue_date", "maturity_date": "maturity_date",
            "holder": "holder",
        }[field_name]
        conn.execute(
            f"UPDATE fdr_instruments SET {column}=? WHERE id=?",
            (value, instrument_id),
        )
    timestamp = _now()
    conn.execute("""
        INSERT INTO fdr_field_history(
            instrument_id,field_name,claimed_value,confirmed_value,
            verification_status,action,actor,created_at
        ) VALUES(?,?,?,?,?,'Claim corrected',?,?)
    """, (instrument_id, field_name, row["claimed_value"],
          row["confirmed_value"], row["verification_status"],
          user["username"], timestamp))
    next_status = (
        "Bank-confirmed"
        if row["confirmed_value"] and _values_match(field_name, row["confirmed_value"], value)
        and row["verification_status"] in ("Bank-confirmed", "Mismatch")
        else "Pending bank verification"
    )
    conn.execute("""
        UPDATE fdr_field_values SET claimed_value=?,verification_status=?
        WHERE instrument_id=? AND field_name=?
    """, (value, next_status, instrument_id, field_name))
    if duplicate:
        conn.execute("""
            INSERT INTO fdr_discrepancies(instrument_id,field_name,explanation,created_at)
            VALUES(?,?,?,?)
        """, (
            instrument_id, "fdr_number",
            "The corrected normalized FDR identifier is already registered against another instrument.",
            timestamp,
        ))
    _audit(conn, user, "Institution claim corrected", "instrument", instrument_id,
           f"Institution corrected the claimed {FIELD_LABELS[field_name]}; bank confirmation remains separately recorded.")
    conn.commit()
    conn.close()
    return RedirectResponse(f"/fdr/{instrument_id}", status_code=303)


@router.post("/fdr/{instrument_id:int}/discrepancies/{discrepancy_id:int}/resolve")
def resolve_discrepancy(request: Request, instrument_id: int, discrepancy_id: int,
                        csrf: str = Form(...), note: str = Form(...)):
    user = _require_user(request)
    if not user:
        return RedirectResponse("/login")
    _check_csrf(request, csrf)
    if user["role"] not in ("Regional Officer", "Bureau Admin"):
        raise HTTPException(403, "Only an authorized officer can resolve discrepancies.")
    conn = connect()
    instrument = _visible_instrument(conn, instrument_id, user)
    discrepancy = conn.execute("""
        SELECT * FROM fdr_discrepancies
        WHERE id=? AND instrument_id=? AND status='Open'
    """, (discrepancy_id, instrument_id)).fetchone()
    if not instrument or not discrepancy:
        conn.close()
        raise HTTPException(404, "Open discrepancy not found.")
    field = conn.execute("""
        SELECT claimed_value,confirmed_value,verification_status
        FROM fdr_field_values WHERE instrument_id=? AND field_name=?
    """, (instrument_id, discrepancy["field_name"])).fetchone()
    if (not field or not note.strip()
            or field["verification_status"] != "Bank-confirmed"
            or field["claimed_value"] != field["confirmed_value"]):
        conn.close()
        raise HTTPException(
            409, "The claim must match an independently bank-confirmed value before resolution."
        )
    timestamp = _now()
    conn.execute("""
        UPDATE fdr_discrepancies SET status='Resolved',resolved_at=?,resolved_by=?
        WHERE id=?
    """, (timestamp, user["username"], discrepancy_id))
    remaining = conn.execute("""
        SELECT COUNT(*) AS count FROM fdr_discrepancies
        WHERE instrument_id=? AND status='Open'
    """, (instrument_id,)).fetchone()["count"]
    unverified = conn.execute("""
        SELECT COUNT(*) AS count FROM fdr_field_values
        WHERE instrument_id=? AND verification_status!='Bank-confirmed'
    """, (instrument_id,)).fetchone()["count"]
    if not remaining:
        conn.execute(
            "UPDATE fdr_instruments SET lifecycle_status=? WHERE id=?",
            ("Active" if not unverified else "Under verification", instrument_id),
        )
    _audit(conn, user, "Discrepancy resolved", "instrument", instrument_id,
           f"{FIELD_LABELS[discrepancy['field_name']]} discrepancy resolved after bank confirmation. {note.strip()[:300]}")
    conn.commit()
    conn.close()
    return RedirectResponse(f"/fdr/{instrument_id}", status_code=303)


@router.get("/fdr/{instrument_id:int}", response_class=HTMLResponse)
def instrument_detail(request: Request, instrument_id: int, link: str = ""):
    user = _require_user(request)
    if not user:
        return RedirectResponse("/login")
    conn = connect()
    instrument = _visible_instrument(conn, instrument_id, user)
    if not instrument:
        conn.close()
        raise HTTPException(404, "FDR not found.")
    fields = conn.execute(
        "SELECT * FROM fdr_field_values WHERE instrument_id=? ORDER BY field_name",
        (instrument_id,),
    ).fetchall()
    documents = conn.execute("""
        SELECT id,original_name,sha256,created_at FROM fdr_documents
        WHERE instrument_id=? ORDER BY id DESC
    """, (instrument_id,)).fetchall()
    replacements = conn.execute("""
        SELECT id,fdr_number,lifecycle_status,maturity_date
        FROM fdr_instruments WHERE replaces_id=? AND institution_id=?
        ORDER BY id DESC
    """, (instrument_id, instrument["institution_id"])).fetchall()
    discrepancies = conn.execute("""
        SELECT * FROM fdr_discrepancies WHERE instrument_id=? ORDER BY id DESC
    """, (instrument_id,)).fetchall()
    events = conn.execute("""
        SELECT * FROM fdr_audit_events WHERE entity_type='instrument' AND entity_id=?
        ORDER BY id DESC LIMIT 20
    """, (str(instrument_id),)).fetchall()
    requests = conn.execute("""
        SELECT id,field_name,created_by,created_at,expires_at,consumed_at,status
        FROM fdr_verification_requests WHERE instrument_id=? ORDER BY id DESC
    """, (instrument_id,)).fetchall()
    field_history = conn.execute("""
        SELECT * FROM fdr_field_history WHERE instrument_id=?
        ORDER BY id DESC LIMIT 50
    """, (instrument_id,)).fetchall()
    scrutiny_remarks = conn.execute("""
        SELECT * FROM fdr_scrutiny_remarks WHERE instrument_id=?
        ORDER BY id DESC LIMIT 20
    """, (instrument_id,)).fetchall()
    conn.close()
    return _render(request, "fdr_detail.html", user, "registry",
                   instrument=instrument, fields=fields, labels=FIELD_LABELS,
                   documents=documents, replacements=replacements,
                   discrepancies=discrepancies,
                   events=events, requests=requests, field_history=field_history,
                   scrutiny_remarks=scrutiny_remarks,
                   verification_url=link)


@router.post("/fdr/{instrument_id:int}/scrutiny")
def scrutiny_action(request: Request, instrument_id: int,
                     csrf: str = Form(...), action: str = Form(...),
                     remark: str = Form(...)):
    user = _require_user(request)
    if not user:
        return RedirectResponse("/login")
    _check_csrf(request, csrf)
    if user["role"] not in ("Regional Officer", "Bureau Admin"):
        raise HTTPException(403, "Only scrutiny officers can record review actions.")
    if action not in ("request_documents", "mark_verified"):
        raise HTTPException(400, "Unsupported scrutiny action.")
    if not remark.strip() or len(remark.strip()) > 1000:
        raise HTTPException(400, "A scrutiny remark of 1,000 characters or fewer is required.")
    conn = connect()
    instrument = _visible_instrument(conn, instrument_id, user)
    if not instrument:
        conn.close()
        raise HTTPException(404, "FDR not found.")
    if action == "mark_verified":
        pending = conn.execute("""
            SELECT COUNT(*) AS count FROM fdr_field_values
            WHERE instrument_id=? AND verification_status!='Bank-confirmed'
        """, (instrument_id,)).fetchone()["count"]
        open_discrepancy = conn.execute("""
            SELECT COUNT(*) AS count FROM fdr_discrepancies
            WHERE instrument_id=? AND status='Open'
        """, (instrument_id,)).fetchone()["count"]
        if pending or open_discrepancy:
            conn.close()
            raise HTTPException(
                409,
                "Every critical field must be bank-confirmed and discrepancies resolved "
                "before this FDR can be marked verified.",
            )
        next_status = "Active"
    else:
        next_status = "Under verification"
    timestamp = _now()
    conn.execute(
        "INSERT INTO fdr_scrutiny_remarks(instrument_id,officer,remark,action,created_at) "
        "VALUES(?,?,?,?,?)",
        (instrument_id, user["username"], remark.strip(), action, timestamp),
    )
    conn.execute(
        "UPDATE fdr_instruments SET lifecycle_status=? WHERE id=?",
        (next_status, instrument_id),
    )
    _audit(conn, user, "Scrutiny action recorded", "instrument", instrument_id,
           f"{action}: {remark.strip()[:300]}")
    conn.commit()
    conn.close()
    return RedirectResponse(f"/fdr/{instrument_id}", status_code=303)


@router.post("/fdr/{instrument_id:int}/verify-link", response_class=HTMLResponse)
def create_verification_link(request: Request, instrument_id: int,
                             csrf: str = Form(...), field_name: str = Form(...)):
    user = _require_user(request)
    if not user:
        return RedirectResponse("/login")
    _check_csrf(request, csrf)
    if user["role"] not in ("Bureau Admin", "Regional Officer"):
        raise HTTPException(403, "Only authorized officers can issue verification links.")
    if field_name not in REQUIRED_FIELDS:
        raise HTTPException(400, "Unknown verification field.")
    conn = connect()
    instrument = _visible_instrument(conn, instrument_id, user)
    if not instrument:
        conn.close()
        raise HTTPException(404, "FDR not found.")
    raw_token = secrets.token_urlsafe(32)
    created = datetime.now(timezone.utc)
    expires = created + timedelta(hours=24)
    digest = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    conn.execute("""
        UPDATE fdr_verification_requests SET consumed_at=?,status='Revoked'
        WHERE instrument_id=? AND field_name=? AND consumed_at IS NULL
    """, (created.isoformat(timespec="seconds"), instrument_id, field_name))
    conn.execute("""
        INSERT INTO fdr_verification_requests(
            instrument_id,field_name,token_hash,created_by,created_at,expires_at
        ) VALUES(?,?,?,?,?,?)
    """, (instrument_id, field_name, digest, user["username"],
          created.isoformat(timespec="seconds"), expires.isoformat(timespec="seconds")))
    _audit(conn, user, "Verification link created", "instrument", instrument_id,
           f"Single-use simulated bank verification link issued for {FIELD_LABELS[field_name]}; raw token not logged.")
    conn.commit()
    conn.close()
    link = str(request.url_for("bank_verify", token=raw_token))
    return instrument_detail(request, instrument_id, link=link)


@router.post("/fdr/{instrument_id:int}/documents")
async def attach_document(request: Request, instrument_id: int,
                          csrf: str = Form(...), document: UploadFile = File(...)):
    user = _require_user(request)
    if not user:
        return RedirectResponse("/login")
    _check_csrf(request, csrf)
    conn = connect()
    instrument = _visible_instrument(conn, instrument_id, user)
    if not instrument or user["role"] not in ("Institution User", "Bureau Admin"):
        conn.close()
        raise HTTPException(404, "FDR not found.")
    conn.close()
    upload_id, _ = await _store_upload(document, user["username"])
    conn = connect()
    conn.execute(
        "UPDATE fdr_documents SET instrument_id=?,used=1 WHERE upload_id=? AND owner=?",
        (instrument_id, upload_id, user["username"]),
    )
    _audit(conn, user, "Supporting document uploaded", "instrument", instrument_id,
           "A supporting document was uploaded and its SHA-256 digest recorded.")
    conn.commit()
    conn.close()
    return RedirectResponse(f"/fdr/{instrument_id}", status_code=303)


@router.get("/bank/verify/{token}", name="bank_verify", response_class=HTMLResponse)
def bank_verify(request: Request, token: str):
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    conn = connect()
    row = conn.execute("""
        SELECT r.id,r.field_name,r.expires_at,r.consumed_at,i.fdr_number,i.bank,
               fv.claimed_value
        FROM fdr_verification_requests r
        JOIN fdr_instruments i ON i.id=r.instrument_id
        JOIN fdr_field_values fv ON fv.instrument_id=i.id AND fv.field_name=r.field_name
        WHERE r.token_hash=?
    """, (digest,)).fetchone()
    conn.close()
    if not row:
        raise HTTPException(404, "This verification link is invalid or has expired.")
    expired = datetime.fromisoformat(row["expires_at"]) <= datetime.now(timezone.utc)
    if row["consumed_at"] or expired:
        return _render(request, "fdr_bank_verify.html", {"username": "Secure verifier link",
                       "role": "Bank Verifier"}, "bank",
                       verification=None, expired=expired)
    return _render(request, "fdr_bank_verify.html", {"username": "Secure verifier link",
                   "role": "Bank Verifier"}, "bank",
                   verification=row, token=token, expired=False)


@router.post("/bank/verify/{token}")
def bank_verify_submit(
    request: Request,
    token: str,
    csrf: str = Form(...),
    response: str = Form(...),
    confirmed_value: str = Form(""),
    remark: str = Form(""),
):
    _check_csrf(request, csrf)
    if response not in VALID_ACTIONS:
        raise HTTPException(400, "Choose confirm, dispute or request clarification.")
    if response == "confirm" and not confirmed_value.strip():
        raise HTTPException(400, "Enter the value confirmed by the bank.")
    if response == "confirm" and len(confirmed_value.strip()) > 200:
        raise HTTPException(400, "The confirmed value must be 200 characters or fewer.")
    if len(remark) > 1000:
        raise HTTPException(400, "The remark must be 1000 characters or fewer.")
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    bank_value = confirmed_value.strip()
    now = datetime.now(timezone.utc)
    conn = connect()
    try:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("""
            SELECT r.*,i.fdr_number FROM fdr_verification_requests r
            JOIN fdr_instruments i ON i.id=r.instrument_id
            WHERE r.token_hash=?
        """, (digest,)).fetchone()
        if not row or row["consumed_at"] or datetime.fromisoformat(row["expires_at"]) <= now:
            conn.rollback()
            raise HTTPException(410, "This verification link has expired or was already used.")
        consumed = conn.execute("""
            UPDATE fdr_verification_requests SET consumed_at=?,status=?
            WHERE id=? AND consumed_at IS NULL AND expires_at>?
        """, (now.isoformat(timespec="seconds"), response, row["id"],
              now.isoformat(timespec="seconds")))
        if consumed.rowcount != 1:
            conn.rollback()
            raise HTTPException(410, "This verification link has already been used.")
        verified_value = bank_value if response == "confirm" else None
        source = "Simulated bank response"
        conn.execute("""
            INSERT INTO fdr_verification_responses(
                request_id,response,confirmed_value,remark,verification_source,created_at
            ) VALUES(?,?,?,?,?,?)
        """, (row["id"], response, verified_value, remark.strip()[:1000], source,
              now.isoformat(timespec="seconds")))
        field_row = conn.execute(
            "SELECT claimed_value,confirmed_value,verification_status "
            "FROM fdr_field_values WHERE instrument_id=? AND field_name=?",
            (row["instrument_id"], row["field_name"]),
        ).fetchone()
        if response == "confirm" and row["field_name"] == "amount":
            try:
                bank_amount = Decimal(bank_value)
                if not bank_amount.is_finite() or bank_amount <= 0:
                    raise ValueError
                bank_value = format(bank_amount.quantize(Decimal("0.01")), "f")
                verified_value = bank_value
            except (InvalidOperation, ValueError) as exc:
                conn.rollback()
                raise HTTPException(400, "Confirmed deposit amount must be a positive number.") from exc
        if response == "confirm" and row["field_name"] in ("issue_date", "maturity_date"):
            try:
                date.fromisoformat(bank_value)
            except ValueError as exc:
                conn.rollback()
                raise HTTPException(400, "Confirmed dates must use YYYY-MM-DD.") from exc
        status = "Clarification requested" if response == "clarification" else (
            "Bank-confirmed" if _values_match(
                row["field_name"], field_row["claimed_value"], bank_value
            ) else "Mismatch"
        ) if response == "confirm" else "Mismatch"
        conn.execute("""
            INSERT INTO fdr_field_history(
                instrument_id,field_name,claimed_value,confirmed_value,
                verification_status,action,actor,created_at
            ) VALUES(?,?,?,?,?,'Bank response received','Simulated bank verifier',?)
        """, (
            row["instrument_id"], row["field_name"], field_row["claimed_value"],
            field_row["confirmed_value"], field_row["verification_status"],
            now.isoformat(timespec="seconds"),
        ))
        conn.execute("""
            UPDATE fdr_field_values SET confirmed_value=COALESCE(?,confirmed_value),
                verification_status=?,
                verification_source=?,performed_by='Simulated bank verifier',
                performed_at=?,remarks=?
            WHERE instrument_id=? AND field_name=?
        """, (verified_value, status, source, now.isoformat(timespec="seconds"),
              remark.strip()[:1000], row["instrument_id"], row["field_name"]))
        if status == "Mismatch":
            conn.execute("""
                INSERT INTO fdr_discrepancies(instrument_id,field_name,explanation,created_at)
                VALUES(?,?,?,?)
            """, (
                row["instrument_id"], row["field_name"],
                f"Bank response differs from the institution-claimed {FIELD_LABELS[row['field_name']]} value.",
                now.isoformat(timespec="seconds"),
            ))
        _audit(conn, {"username": "simulated-bank-verifier",
                      "role": "Bank Verifier"},
               "Bank verification response", "instrument", row["instrument_id"],
               f"Simulated bank response recorded for {FIELD_LABELS[row['field_name']]} ({status}); token not logged.")
        all_fields = conn.execute("""
            SELECT verification_status FROM fdr_field_values WHERE instrument_id=?
        """, (row["instrument_id"],)).fetchall()
        if all_fields and all(f["verification_status"] == "Bank-confirmed" for f in all_fields):
            conn.execute(
                "UPDATE fdr_instruments SET lifecycle_status='Active' WHERE id=?",
                (row["instrument_id"],),
            )
        elif status == "Mismatch":
            conn.execute(
                "UPDATE fdr_instruments SET lifecycle_status='Discrepancy unresolved' WHERE id=?",
                (row["instrument_id"],),
            )
        conn.commit()
    finally:
        conn.close()
    return _render(request, "fdr_bank_verify.html", {"username": "Secure verifier link",
                   "role": "Bank Verifier"}, "bank",
                   verification=None, expired=False, submitted=True)


@router.get("/fdr/maturity", response_class=HTMLResponse)
def maturity_radar(request: Request, urgency: str = ""):
    user = _require_user(request)
    if not user:
        return RedirectResponse("/login")
    rows = _visible_instruments(user)
    conn = connect()
    today = _effective_date(conn)
    _scan_maturities(conn, today)
    conn.commit()
    scopes = _scope_ids(user)
    notice_sql = """
        SELECT n.*,i.fdr_number,ins.name AS institution_name
        FROM fdr_notifications n JOIN fdr_instruments i ON i.id=n.instrument_id
        JOIN fdr_institutions ins ON ins.id=i.institution_id
    """
    notice_params = []
    if scopes is not None:
        if scopes:
            notice_sql += " WHERE i.institution_id IN (" + ",".join("?" for _ in scopes) + ")"
            notice_params.extend(scopes)
        else:
            notice_sql += " WHERE 0=1"
    notice_sql += " ORDER BY n.id DESC"
    notices = conn.execute(notice_sql, notice_params).fetchall()
    conn.close()
    due = []
    for row in rows:
        try:
            remaining = (date.fromisoformat(row["maturity_date"]) - today).days
        except ValueError:
            remaining = None
        if urgency == "overdue" and not (remaining is not None and remaining < 0):
            continue
        if urgency == "30" and not (remaining is not None and 0 <= remaining <= 30):
            continue
        due.append({**row, "days_remaining": remaining})
    due.sort(key=lambda item: (item["days_remaining"] is None,
                               item["days_remaining"] if item["days_remaining"] is not None else 0))
    return _render(request, "fdr_maturity.html", user, "maturity",
                   instruments=due, notifications=notices, today=today.isoformat(),
                   urgency=urgency)


@router.get("/fdr/releases", response_class=HTMLResponse)
def releases_page(request: Request):
    user = _require_user(request)
    if not user:
        return RedirectResponse("/login")
    conn = connect()
    scopes = _scope_ids(user)
    sql = """
        SELECT r.*,i.fdr_number,ins.name AS institution_name
        FROM fdr_release_requests r JOIN fdr_instruments i ON i.id=r.instrument_id
        JOIN fdr_institutions ins ON ins.id=i.institution_id
    """
    params = []
    if scopes is not None:
        if not scopes:
            conn.close()
            return _render(request, "fdr_releases.html", user, "releases",
                           requests=[], instruments=[])
        sql += " WHERE i.institution_id IN (" + ",".join("?" for _ in scopes) + ")"
        params.extend(scopes)
    sql += " ORDER BY r.id DESC"
    requests = conn.execute(sql, params).fetchall()
    instruments = []
    if user["role"] in ("Institution User", "Bureau Admin"):
        instrument_sql = """
            SELECT id,fdr_number FROM fdr_instruments
            WHERE lifecycle_status NOT IN ('Released','Renewal pending')
        """
        instrument_params = []
        if scopes is not None:
            instrument_sql += " AND institution_id IN (" + ",".join(
                "?" for _ in scopes
            ) + ")"
            instrument_params.extend(scopes)
        instruments = conn.execute(instrument_sql, instrument_params).fetchall()
    conn.close()
    return _render(request, "fdr_releases.html", user, "releases",
                   requests=requests, instruments=instruments)


@router.post("/fdr/releases")
def create_release(request: Request, csrf: str = Form(...),
                   instrument_id: int = Form(...), reason: str = Form(...)):
    user = _require_user(request)
    if not user:
        return RedirectResponse("/login")
    _check_csrf(request, csrf)
    if user["role"] not in ("Institution User", "Bureau Admin"):
        raise HTTPException(403, "Only assigned institutions may submit release requests.")
    if not reason.strip():
        raise HTTPException(400, "A release-request reason is required.")
    conn = connect()
    instrument = _visible_instrument(conn, instrument_id, user)
    if not instrument:
        conn.close()
        raise HTTPException(404, "FDR not found.")
    if instrument["lifecycle_status"] in ("Released", "Renewal pending"):
        conn.close()
        raise HTTPException(409, "This instrument is not eligible for a new release request.")
    open_request = conn.execute("""
        SELECT 1 FROM fdr_release_requests
        WHERE instrument_id=? AND status NOT IN ('Rejected','Released') LIMIT 1
    """, (instrument_id,)).fetchone()
    if open_request:
        conn.close()
        raise HTTPException(409, "An active release request already exists for this instrument.")
    evaluation = _eligibility(conn, instrument_id)
    timestamp = _now()
    cursor = conn.execute("""
        INSERT INTO fdr_release_requests(
            instrument_id,requested_by,reason,status,rule_set_version,
            eligibility_json,created_at,updated_at
        ) VALUES(?,?,?,'Submitted',?,?,?,?)
    """, (instrument_id, user["username"], reason.strip()[:1000],
          evaluation["rule_set_version"], json.dumps(evaluation), timestamp, timestamp))
    _audit(conn, user, "Release request submitted", "release_request", cursor.lastrowid,
           f"Eligibility evaluated against rule-set version {evaluation['rule_set_version']}.")
    conn.commit()
    conn.close()
    return RedirectResponse("/fdr/releases", status_code=303)


@router.post("/fdr/releases/{release_id}/transition")
def transition_release(request: Request, release_id: int, csrf: str = Form(...),
                       action: str = Form(...), note: str = Form("")):
    user = _require_user(request)
    if not user:
        return RedirectResponse("/login")
    _check_csrf(request, csrf)
    transitions = {
        ("Submitted", "scrutinize"): "Under scrutiny",
        ("Under scrutiny", "clarify"): "Clarification requested",
        ("Clarification requested", "resubmit"): "Submitted",
        ("Under scrutiny", "recommend"): "Recommended",
        ("Under scrutiny", "reevaluate"): "Under scrutiny",
        ("Recommended", "approve"): "Approved",
        ("Recommended", "reject"): "Rejected",
        ("Approved", "release"): "Released",
    }
    conn = connect()
    row = _release_visible(conn, release_id, user)
    if not row:
        conn.close()
        raise HTTPException(404, "Release request not found.")
    next_status = transitions.get((row["status"], action))
    if not next_status:
        conn.close()
        raise HTTPException(400, "This release status transition is not permitted.")
    if action in ("scrutinize", "clarify", "recommend") and user["role"] not in (
        "Regional Officer", "Bureau Admin"
    ):
        conn.close()
        raise HTTPException(403, "Only an authorized officer can scrutinize or recommend.")
    if action in ("approve", "reject", "release") and not _is_admin(user):
        conn.close()
        raise HTTPException(403, "Only the competent authority can approve or release.")
    if action in ("approve", "release"):
        evaluation = json.loads(row["eligibility_json"])
        if not evaluation.get("eligible"):
            conn.close()
            raise HTTPException(409, "The request does not pass its recorded eligibility rules.")
    if action in ("recommend", "approve", "release"):
        previous_evaluation = json.loads(row["eligibility_json"])
        evaluation = _eligibility(
            conn, row["instrument_id"], previous_evaluation["rule_set_version"]
        )
        conn.execute("""
            UPDATE fdr_release_requests SET eligibility_json=?,updated_at=? WHERE id=?
        """, (json.dumps(evaluation), _now(), release_id))
        if not evaluation.get("eligible"):
            conn.commit()
            conn.close()
            raise HTTPException(409, "Resolve eligibility failures and re-evaluate before proceeding.")
    if action in ("approve", "reject", "release", "clarify", "recommend") and not note.strip():
        conn.close()
        raise HTTPException(400, "Record a decision or clarification note.")
    if action == "reevaluate":
        if user["role"] not in ("Regional Officer", "Bureau Admin"):
            conn.close()
            raise HTTPException(403, "Only an authorized officer can re-evaluate eligibility.")
        evaluation = _eligibility(conn, row["instrument_id"])
        conn.execute("""
            UPDATE fdr_release_requests SET eligibility_json=?,rule_set_version=?,updated_at=?
            WHERE id=?
        """, (json.dumps(evaluation), evaluation["rule_set_version"], _now(), release_id))
    conn.execute("""
        UPDATE fdr_release_requests SET status=?,updated_at=?,decision_by=?,decision_note=?
        WHERE id=?
    """, (next_status, _now(), user["username"], note.strip()[:1000], release_id))
    if next_status == "Released":
        conn.execute(
            "UPDATE fdr_instruments SET lifecycle_status='Released' WHERE id=?",
            (row["instrument_id"],),
        )
    _audit(conn, user, f"Release {action}", "release_request", release_id,
           f"Status changed from {row['status']} to {next_status}. {note.strip()[:500]}")
    conn.commit()
    conn.close()
    return RedirectResponse("/fdr/releases", status_code=303)


@router.get("/fdr/institutions", response_class=HTMLResponse)
def institutions_page(request: Request):
    user = _require_user(request)
    if not user:
        return RedirectResponse("/login")
    if not _is_admin(user):
        raise HTTPException(403, "Bureau Admin role required.")
    conn = connect()
    institutions = conn.execute("""
        SELECT i.*,GROUP_CONCAT(s.username, ', ') AS assigned_users
        FROM fdr_institutions i LEFT JOIN fdr_user_scopes s ON s.institution_id=i.id
        GROUP BY i.id ORDER BY i.name
    """).fetchall()
    with sqlite3.connect(USER_DB) as users_conn:
        users = users_conn.execute(
            "SELECT username,role FROM users ORDER BY username"
        ).fetchall()
    conn.close()
    return _render(request, "fdr_institutions.html", user, "institutions",
                   institutions=institutions, users=users)


@router.post("/fdr/institutions")
def create_institution(request: Request, csrf: str = Form(...), name: str = Form(...),
                       region: str = Form(...), username: str = Form("")):
    user = _require_user(request)
    if not user:
        return RedirectResponse("/login")
    _check_csrf(request, csrf)
    if not _is_admin(user):
        raise HTTPException(403, "Bureau Admin role required.")
    if not name.strip() or not region.strip():
        raise HTTPException(400, "Institution name and region are required.")
    conn = connect()
    try:
        cursor = conn.execute(
            "INSERT INTO fdr_institutions(name,region,created_at) VALUES(?,?,?)",
            (name.strip(), region.strip(), _now()),
        )
    except sqlite3.IntegrityError as exc:
        conn.close()
        raise HTTPException(409, "That institution already exists.") from exc
    institution_id = cursor.lastrowid
    if username.strip():
        with sqlite3.connect(USER_DB) as users_conn:
            exists = users_conn.execute(
                "SELECT 1 FROM users WHERE username=?", (username.strip(),)
            ).fetchone()
        if not exists:
            conn.rollback()
            conn.close()
            raise HTTPException(400, "The assigned username does not exist.")
        conn.execute(
            "INSERT INTO fdr_user_scopes(username,institution_id) VALUES(?,?)",
            (username.strip(), institution_id),
        )
    _audit(conn, user, "Institution created", "institution", institution_id,
           f"Institution {name.strip()} configured for region {region.strip()}.")
    conn.commit()
    conn.close()
    return RedirectResponse("/fdr/institutions", status_code=303)


@router.post("/fdr/institutions/{institution_id:int}/assign")
def assign_user_to_institution(request: Request, institution_id: int,
                               csrf: str = Form(...), username: str = Form(...)):
    user = _require_user(request)
    if not user:
        return RedirectResponse("/login")
    _check_csrf(request, csrf)
    if not _is_admin(user):
        raise HTTPException(403, "Bureau Admin role required.")
    with sqlite3.connect(USER_DB) as users_conn:
        account = users_conn.execute(
            "SELECT role FROM users WHERE username=?", (username.strip(),)
        ).fetchone()
    allowed_roles = {"Institution User", "Viewer", "Regional Officer",
                     "Investigator", "Analyst"}
    if not account or account[0] not in allowed_roles:
        raise HTTPException(400, "Assign an existing institution or regional user account.")
    conn = connect()
    if not conn.execute(
        "SELECT 1 FROM fdr_institutions WHERE id=?", (institution_id,)
    ).fetchone():
        conn.close()
        raise HTTPException(404, "Institution not found.")
    conn.execute(
        "INSERT OR IGNORE INTO fdr_user_scopes(username,institution_id) VALUES(?,?)",
        (username.strip(), institution_id),
    )
    _audit(conn, user, "Institution access assigned", "institution", institution_id,
           f"FDR institution scope assigned to user {username.strip()}.")
    conn.commit()
    conn.close()
    return RedirectResponse("/fdr/institutions", status_code=303)


@router.get("/fdr/reports.csv")
def report_csv(request: Request, report: str = "registry"):
    user = _require_user(request)
    if not user:
        return RedirectResponse("/login")
    rows = _visible_instruments(user)
    if report == "pending":
        rows = [row for row in rows if row["pending_fields"]]
    elif report == "overdue":
        conn = connect()
        today = _effective_date(conn)
        conn.close()
        rows = [row for row in rows if date.fromisoformat(row["maturity_date"]) < today]
    elif report == "discrepancies":
        rows = [row for row in rows if row["open_discrepancies"]]
    elif report == "renewals":
        rows = [row for row in rows if row["replaces_id"]]
    elif report != "registry":
        raise HTTPException(400, "Unknown report.")
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Synthetic demo data", "Generated at", _now()])
    writer.writerow(["FDR number", "Institution", "Region", "Bank", "Amount",
                     "Maturity date", "Verification status", "Lifecycle status"])
    for row in rows:
        writer.writerow([_csv_safe(row["fdr_number"]),
                         _csv_safe(row["institution_name"]),
                         _csv_safe(row["region"]), _csv_safe(row["bank"]),
                         _csv_safe(row["amount"]), _csv_safe(row["maturity_date"]),
                         _csv_safe("Pending" if row["pending_fields"] else "Review fields"),
                         _csv_safe(row["lifecycle_status"])])
    return Response(
        output.getvalue(), media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="fdr-{report}.csv"'},
    )


@router.get("/fdr/audit", response_class=HTMLResponse)
def audit_page(request: Request):
    user = _require_user(request)
    if not user:
        return RedirectResponse("/login")
    if not _is_admin(user):
        raise HTTPException(403, "Bureau Admin role required.")
    valid, broken_at, count = verify_audit_chain()
    conn = connect()
    rows = conn.execute(
        "SELECT * FROM fdr_audit_events ORDER BY id DESC LIMIT 100"
    ).fetchall()
    conn.close()
    return _render(request, "fdr_audit.html", user, "audit",
                   valid=valid, broken_at=broken_at, count=count, events=rows)


@router.get("/fdr/settings", response_class=HTMLResponse)
def settings_page(request: Request, message: str = ""):
    user = _require_user(request)
    if not user:
        return RedirectResponse("/login")
    if not _is_admin(user):
        raise HTTPException(403, "Bureau Admin role required.")
    conn = connect()
    settings = _settings(conn)
    rule_set = conn.execute("""
        SELECT version,rules_json FROM fdr_rule_sets WHERE active=1
        ORDER BY version DESC LIMIT 1
    """).fetchone()
    rules = json.loads(rule_set["rules_json"]) if rule_set else {}
    conn.close()
    return _render(request, "fdr_settings.html", user, "settings",
                   reminder_days=",".join(map(str, json.loads(settings["reminder_days"]))),
                   demo_days_offset=int(settings["demo_days_offset"]), message=message,
                   rules=rules, rule_version=rule_set["version"] if rule_set else 1)


@router.post("/fdr/settings")
def save_settings(request: Request, csrf: str = Form(...),
                  reminder_days: str = Form(...), demo_days_offset: int = Form(0),
                  require_document: str = Form(""),
                  require_verified: str = Form(""),
                  block_discrepancy: str = Form("")):
    user = _require_user(request)
    if not user:
        return RedirectResponse("/login")
    _check_csrf(request, csrf)
    if not _is_admin(user):
        raise HTTPException(403, "Bureau Admin role required.")
    try:
        thresholds = sorted({int(value.strip()) for value in reminder_days.split(",")})
        if not thresholds or any(value < 1 or value > 3650 for value in thresholds):
            raise ValueError
    except ValueError:
        return RedirectResponse(
            "/fdr/settings?message=Enter+whole+day+thresholds+between+1+and+3650",
            status_code=303,
        )
    conn = connect()
    conn.execute("UPDATE fdr_settings SET value=? WHERE key='reminder_days'",
                 (json.dumps(thresholds),))
    conn.execute("UPDATE fdr_settings SET value=? WHERE key='demo_days_offset'",
                 (str(max(-3650, min(3650, demo_days_offset))),))
    current = conn.execute(
        "SELECT MAX(version) AS version FROM fdr_rule_sets"
    ).fetchone()["version"] or 0
    conn.execute("UPDATE fdr_rule_sets SET active=0 WHERE active=1")
    conn.execute("""
        INSERT INTO fdr_rule_sets(version,rules_json,created_by,created_at,active)
        VALUES(?,?,?,?,1)
    """, (
        current + 1,
        json.dumps({
            "require_document": require_document == "on",
            "require_verified": require_verified == "on",
            "block_discrepancy": block_discrepancy == "on",
        }, sort_keys=True),
        user["username"], _now(),
    ))
    _audit(conn, user, "Prototype settings updated", "settings", "1",
           f"Reminder thresholds and demo date offset updated.")
    conn.commit()
    conn.close()
    return RedirectResponse("/fdr/settings?message=Settings+saved", status_code=303)


@router.get("/fdr/files/{document_id}")
def download_document(request: Request, document_id: int):
    user = _require_user(request)
    if not user:
        return RedirectResponse("/login")
    conn = connect()
    row = conn.execute(
        "SELECT instrument_id,original_name,storage_path FROM fdr_documents WHERE id=?",
        (document_id,),
    ).fetchone()
    allowed = row and row["instrument_id"] and _visible_instrument(
        conn, row["instrument_id"], user
    )
    conn.close()
    if not allowed:
        raise HTTPException(404, "Document not found.")
    path = Path(row["storage_path"]).resolve()
    if UPLOAD_ROOT not in path.parents or not path.is_file():
        raise HTTPException(404, "Document not found.")
    from fastapi.responses import FileResponse
    return FileResponse(path, filename=Path(row["original_name"]).name)
