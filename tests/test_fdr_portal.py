import base64
import json
import re
import sqlite3
from datetime import date, timedelta

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from itsdangerous import TimestampSigner
from starlette.middleware.sessions import SessionMiddleware

import fdr_portal as fdr
import auth
from routes.portals import router as portals_router


SECRET = "test-only-session-secret-that-is-long-enough"


@pytest.fixture
def portal(tmp_path, monkeypatch):
    database = tmp_path / "portal.db"
    monkeypatch.setattr(fdr, "DB", str(database))
    monkeypatch.setattr(fdr, "USER_DB", str(database))
    monkeypatch.setattr(fdr, "UPLOAD_ROOT", tmp_path / "uploads")
    fdr.init_fdr_db()
    conn = fdr.connect()
    conn.execute("CREATE TABLE users(username TEXT PRIMARY KEY, role TEXT)")
    conn.execute("INSERT INTO users(username,role) VALUES('institution-user','Institution User')")
    conn.execute("INSERT INTO users(username,role) VALUES('reviewer','Bureau Admin')")
    conn.execute("INSERT INTO users(username,role) VALUES('regional','Regional Officer')")
    conn.execute("INSERT INTO users(username,role) VALUES('authority','Competent Authority')")
    conn.execute("INSERT INTO users(username,role) VALUES('system-admin','Admin')")
    conn.execute("INSERT INTO users(username,role) VALUES('bank-user','Bank Verifier')")
    institution_id = conn.execute(
        "INSERT INTO fdr_institutions(name,region,created_at) VALUES(?,?,?)",
        ("Test Institute", "Test Region", fdr._now()),
    ).lastrowid
    conn.execute(
        "INSERT INTO fdr_user_scopes(username,institution_id) VALUES(?,?)",
        ("institution-user", institution_id),
    )
    conn.execute(
        "INSERT INTO fdr_user_scopes(username,institution_id) VALUES(?,?)",
        ("regional", institution_id),
    )
    instrument_id = conn.execute("""
        INSERT INTO fdr_instruments(
            institution_id,fdr_number,fdr_number_norm,bank,branch,amount,issue_date,
            maturity_date,holder,lifecycle_status,created_by,created_at
        ) VALUES(?,?,?,?,?,?,?,?,?,'Under verification',?,?)
    """, (
        institution_id, "TEST-FDR-1", "TESTFDR1", "Test Bank", "Test Branch",
        "1000.00", date.today().isoformat(),
        (date.today() + timedelta(days=30)).isoformat(),
        "Test Institute", "institution-user", fdr._now(),
    )).lastrowid
    for field, value in {
        "fdr_number": "TEST-FDR-1",
        "bank": "Test Bank",
        "branch": "Test Branch",
        "amount": "1000.00",
        "issue_date": date.today().isoformat(),
        "maturity_date": (date.today() + timedelta(days=30)).isoformat(),
        "holder": "Test Institute",
    }.items():
        conn.execute("""
            INSERT INTO fdr_field_values(instrument_id,field_name,claimed_value)
            VALUES(?,?,?)
        """, (instrument_id, field, value))
    conn.commit()
    conn.close()
    app = FastAPI()
    app.include_router(fdr.router)
    app.include_router(portals_router)
    app.add_middleware(SessionMiddleware, secret_key=SECRET)
    return app, institution_id, instrument_id, database


def _session_cookie(client, username, role):
    session = {"user": {"username": username, "role": role}}
    payload = base64.b64encode(json.dumps(session).encode())
    client.cookies.set("session", TimestampSigner(SECRET).sign(payload).decode())


def _csrf(response):
    match = re.search(r'name="csrf" value="([^"]+)"', response.text)
    assert match, "Expected CSRF token in rendered form"
    return match.group(1)


def test_bank_verification_is_single_use_and_separates_claim(portal):
    app, _, instrument_id, database = portal
    officer = TestClient(app)
    _session_cookie(officer, "reviewer", "Bureau Admin")
    detail = officer.get(f"/fdr/{instrument_id}")
    response = officer.post(
        f"/fdr/{instrument_id}/verify-link",
        data={"csrf": _csrf(detail), "field_name": "amount"},
    )
    assert response.status_code == 200
    match = re.search(r'value="(http://testserver/bank/verify/[^"]+)"', response.text)
    assert match, "Expected one-time verifier URL"

    bank = TestClient(app)
    page = bank.get(match.group(1).replace("http://testserver", ""))
    csrf = _csrf(page)
    submitted = bank.post(
        match.group(1).replace("http://testserver", ""),
        data={"csrf": csrf, "response": "confirm",
              "confirmed_value": "1000.00", "remark": "Synthetic test"},
    )
    assert submitted.status_code == 200
    replay = bank.post(
        match.group(1).replace("http://testserver", ""),
        data={"csrf": csrf, "response": "confirm",
              "confirmed_value": "1000.00"},
    )
    assert replay.status_code == 410

    conn = sqlite3.connect(database)
    claimed, confirmed, status = conn.execute("""
        SELECT claimed_value,confirmed_value,verification_status
        FROM fdr_field_values WHERE instrument_id=? AND field_name='amount'
    """, (instrument_id,)).fetchone()
    token_hash, = conn.execute(
        "SELECT token_hash FROM fdr_verification_requests"
    ).fetchone()
    conn.close()
    assert claimed == "1000.00"
    assert confirmed == "1000.00"
    assert status == "Bank-confirmed"
    assert match.group(1).rsplit("/", 1)[1] not in token_hash
    assert len(token_hash) == 64


def test_institution_scope_hides_unassigned_fdrs(portal):
    app, _, instrument_id, database = portal
    conn = sqlite3.connect(database)
    other_institution = conn.execute(
        "INSERT INTO fdr_institutions(name,region,created_at) VALUES(?,?,?)",
        ("Private Institute", "Other Region", fdr._now()),
    ).lastrowid
    conn.execute("""
        INSERT INTO fdr_instruments(
            institution_id,fdr_number,fdr_number_norm,bank,branch,amount,issue_date,
            maturity_date,holder,lifecycle_status,created_by,created_at
        ) VALUES(?,?,?,?,?,?,?,?,?,'Active','other-user',?)
    """, (
        other_institution, "PRIVATE-FDR-9", "PRIVATEFDR9", "Private Bank",
        "Other Branch", "9000.00", date.today().isoformat(),
        (date.today() + timedelta(days=90)).isoformat(),
        "Private Institute", fdr._now(),
    ))
    conn.commit()
    conn.close()
    client = TestClient(app, follow_redirects=False)
    _session_cookie(client, "institution-user", "Institution User")
    assert client.get(f"/fdr/{instrument_id}").status_code == 200
    assert client.get(f"/fdr/{instrument_id + 100}").status_code == 404
    assert "PRIVATE-FDR-9" not in client.get("/fdr/registry").text
    assert "PRIVATE-FDR-9" not in client.get("/fdr/releases").text


def test_maturity_scan_deduplicates_and_marks_instrument_matured(portal):
    _, _, instrument_id, _ = portal
    conn = fdr.connect()
    today = date.today() - timedelta(days=1)
    conn.execute(
        "UPDATE fdr_instruments SET maturity_date=?,lifecycle_status='Active' WHERE id=?",
        (today.isoformat(), instrument_id),
    )
    fdr._scan_maturities(conn, date.today())
    fdr._scan_maturities(conn, date.today())
    conn.commit()
    count = conn.execute(
        "SELECT COUNT(*) FROM fdr_notifications WHERE instrument_id=?",
        (instrument_id,),
    ).fetchone()[0]
    status = conn.execute(
        "SELECT lifecycle_status FROM fdr_instruments WHERE id=?",
        (instrument_id,),
    ).fetchone()[0]
    conn.close()
    assert count == 1
    assert status == "Matured"


def test_audit_chain_detects_event_tampering(portal):
    _, _, instrument_id, _ = portal
    conn = fdr.connect()
    fdr._audit(
        conn, {"username": "reviewer", "role": "Bureau Admin"},
        "Review", "instrument", instrument_id, "Synthetic event",
    )
    conn.commit()
    conn.close()
    assert fdr.verify_audit_chain() == (True, None, 1)

    conn = fdr.connect()
    conn.execute("UPDATE fdr_audit_events SET summary='altered' WHERE id=1")
    conn.commit()
    conn.close()
    valid, broken_at, count = fdr.verify_audit_chain()
    assert (valid, broken_at, count) == (False, 1, 1)


def test_institution_can_submit_claimed_fields_without_bank_attestation(portal):
    app, institution_id, _, database = portal
    client = TestClient(app)
    _session_cookie(client, "institution-user", "Institution User")
    page = client.get("/fdr/new")
    response = client.post("/fdr/new", data={
        "csrf": _csrf(page),
        "institution_id": institution_id,
        "fdr_number": "NEW-TEST-002",
        "bank": "Test Bank",
        "branch": "Test Branch",
        "amount": "2500.50",
        "issue_date": date.today().isoformat(),
        "maturity_date": (date.today() + timedelta(days=180)).isoformat(),
        "holder": "Test Institute",
        "upload_id": "",
        "replaces_id": "0",
    })
    assert response.status_code == 200
    conn = sqlite3.connect(database)
    row = conn.execute("""
        SELECT i.id,fv.claimed_value,fv.confirmed_value,fv.verification_status
        FROM fdr_instruments i JOIN fdr_field_values fv ON fv.instrument_id=i.id
        WHERE i.fdr_number='NEW-TEST-002' AND fv.field_name='amount'
    """).fetchone()
    conn.close()
    assert row[1:] == ("2500.50", None, "Pending bank verification")


def test_release_request_checks_documents_and_authorized_stages(portal):
    app, _, instrument_id, database = portal
    conn = sqlite3.connect(database)
    conn.execute("""
        UPDATE fdr_field_values SET verification_status='Bank-confirmed',
            confirmed_value=claimed_value,verification_source='Simulated bank response'
        WHERE instrument_id=?
    """, (instrument_id,))
    conn.commit()
    conn.close()

    institution = TestClient(app, follow_redirects=False)
    _session_cookie(institution, "institution-user", "Institution User")
    page = institution.get(f"/fdr/{instrument_id}")
    request_response = institution.post("/fdr/releases", data={
        "csrf": _csrf(page), "instrument_id": instrument_id, "reason": "Synthetic test",
    })
    assert request_response.status_code == 303

    conn = sqlite3.connect(database)
    release_id, eligibility = conn.execute("""
        SELECT id,eligibility_json FROM fdr_release_requests WHERE instrument_id=?
    """, (instrument_id,)).fetchone()
    conn.close()
    assert json.loads(eligibility)["eligible"] is False

    officer = TestClient(app, follow_redirects=False)
    _session_cookie(officer, "regional", "Regional Officer")
    queue = officer.get("/fdr/releases")
    scrutinize = officer.post(f"/fdr/releases/{release_id}/transition", data={
        "csrf": _csrf(queue), "action": "scrutinize",
    })
    assert scrutinize.status_code == 303
    blocked = officer.post(f"/fdr/releases/{release_id}/transition", data={
        "csrf": _csrf(queue), "action": "recommend",
    })
    assert blocked.status_code == 409

    detail = institution.get(f"/fdr/{instrument_id}")
    uploaded = institution.post(
        f"/fdr/{instrument_id}/documents",
        data={"csrf": _csrf(detail)},
        files={"document": ("support.pdf", b"%PDF-1.4\n%%EOF", "application/pdf")},
    )
    assert uploaded.status_code == 303
    reevaluated = officer.post(f"/fdr/releases/{release_id}/transition", data={
        "csrf": _csrf(queue), "action": "reevaluate",
    })
    assert reevaluated.status_code == 303
    recommended = officer.post(f"/fdr/releases/{release_id}/transition", data={
        "csrf": _csrf(queue), "action": "recommend", "note": "Eligible after correction",
    })
    assert recommended.status_code == 303

    admin = TestClient(app, follow_redirects=False)
    _session_cookie(admin, "reviewer", "Bureau Admin")
    admin_queue = admin.get("/fdr/releases")
    approved = admin.post(f"/fdr/releases/{release_id}/transition", data={
        "csrf": _csrf(admin_queue), "action": "approve", "note": "Synthetic approval",
    })
    assert approved.status_code == 303
    released = admin.post(f"/fdr/releases/{release_id}/transition", data={
        "csrf": _csrf(admin_queue), "action": "release",
        "note": "Synthetic process confirmation",
    })
    assert released.status_code == 303
    conn = sqlite3.connect(database)
    state = conn.execute("""
        SELECT r.status,i.lifecycle_status FROM fdr_release_requests r
        JOIN fdr_instruments i ON i.id=r.instrument_id WHERE r.id=?
    """, (release_id,)).fetchone()
    conn.close()
    assert state == ("Released", "Released")


def test_admin_portal_pages_render_and_role_changes_take_effect(portal):
    app, _, instrument_id, database = portal
    admin = TestClient(app)
    _session_cookie(admin, "reviewer", "Bureau Admin")
    for path in (
        "/fdr/dashboard", "/fdr/registry", "/fdr/maturity",
        "/fdr/verification", "/fdr/renewals", "/fdr/releases",
        "/fdr/reports", "/fdr/institutions", "/fdr/audit", "/fdr/settings",
    ):
        response = admin.get(path)
        assert response.status_code == 200, path
        assert "AICTE FDR Guard" in response.text

    conn = sqlite3.connect(database)
    conn.execute(
        "UPDATE users SET role='Institution User' WHERE username='reviewer'"
    )
    conn.commit()
    conn.close()
    assert admin.get(f"/fdr/{instrument_id}").status_code == 404


def test_settings_create_a_new_versioned_rule_set(portal):
    app, _, _, database = portal
    admin = TestClient(app, follow_redirects=False)
    _session_cookie(admin, "reviewer", "Bureau Admin")
    page = admin.get("/fdr/settings")
    response = admin.post("/fdr/settings", data={
        "csrf": _csrf(page), "reminder_days": "90,60,30,7",
        "demo_days_offset": "10", "require_document": "on",
        "require_verified": "on",
    })
    assert response.status_code == 303
    conn = sqlite3.connect(database)
    rules = conn.execute(
        "SELECT version,rules_json,active FROM fdr_rule_sets ORDER BY version DESC LIMIT 1"
    ).fetchone()
    conn.close()
    assert rules[0] == 2
    assert json.loads(rules[1]) == {
        "block_discrepancy": False,
        "require_document": True,
        "require_verified": True,
    }
    assert rules[2] == 1


def test_legacy_default_admin_is_not_created_or_accepted():
    assert auth.create_default_admin() is None
    assert auth.login("admin", "admin123") is None


def test_ocr_candidates_are_not_given_fabricated_confidence():
    extracted = fdr._candidate_fields(
        "FDR Number: SYN-22\nAmount: INR 1,25,000.00\n"
        "Issue Date: 01/02/2026\nMaturity Date: 2027-02-01"
    )
    assert extracted == {
        "fdr_number": "SYN-22",
        "amount": "125000.00",
        "issue_date": "2026-02-01",
        "maturity_date": "2027-02-01",
    }


def test_maturity_reminders_are_scoped_deduplicated_and_escalated(portal):
    app, _, instrument_id, database = portal
    conn = fdr.connect()
    due_in_90_days = date.today() + timedelta(days=90)
    conn.execute(
        "UPDATE fdr_instruments SET maturity_date=?,lifecycle_status='Active' WHERE id=?",
        (due_in_90_days.isoformat(), instrument_id),
    )
    fdr._scan_maturities(conn, date.today())
    fdr._scan_maturities(conn, date.today())
    status = conn.execute(
        "SELECT lifecycle_status FROM fdr_instruments WHERE id=?", (instrument_id,)
    ).fetchone()[0]
    recipients = conn.execute(
        "SELECT recipient_username FROM fdr_notifications WHERE instrument_id=?",
        (instrument_id,),
    ).fetchall()
    assert status == "Expiring"
    assert {row[0] for row in recipients} == {"institution-user", "regional"}
    assert len(recipients) == 2
    for threshold in (60, 30, 7):
        conn.execute(
            "UPDATE fdr_instruments SET maturity_date=? WHERE id=?",
            ((date.today() + timedelta(days=threshold)).isoformat(), instrument_id),
        )
        fdr._scan_maturities(conn, date.today())
        event_count = conn.execute(
            "SELECT COUNT(*) FROM fdr_notifications WHERE instrument_id=? "
            "AND event_key LIKE ?",
            (instrument_id, f"%maturity-{threshold}%"),
        ).fetchone()[0]
        assert event_count == 2

    conn.execute(
        "UPDATE fdr_instruments SET maturity_date=? WHERE id=?",
        ((date.today() - timedelta(days=16)).isoformat(), instrument_id),
    )
    fdr._scan_maturities(conn, date.today())
    escalations = conn.execute(
        "SELECT recipient_username,recipient_role FROM fdr_notifications "
        "WHERE instrument_id=? AND event_key LIKE '%maturity-escalated%'",
        (instrument_id,),
    ).fetchall()
    assert conn.execute(
        "SELECT lifecycle_status FROM fdr_instruments WHERE id=?", (instrument_id,)
    ).fetchone()[0] == "Escalated"
    assert {row[0] for row in escalations} == {"authority", "reviewer", "system-admin"}
    conn.commit()
    conn.close()

    client = TestClient(app, follow_redirects=False)
    _session_cookie(client, "institution-user", "Institution User")
    page = client.get("/fdr/notifications")
    assert "overdue; officer renewal action is required" not in page.text
    assert "escalated after more than 15 overdue days" not in page.text
    assert 'aria-label="Notifications, 4 unread"' in page.text
    conn = sqlite3.connect(database)
    notification_id = conn.execute(
        "SELECT id FROM fdr_notifications WHERE recipient_username='institution-user' "
        "ORDER BY id LIMIT 1"
    ).fetchone()[0]
    conn.close()
    read = client.post(
        f"/fdr/notifications/{notification_id}/read",
        data={"csrf": _csrf(page)},
    )
    assert read.status_code == 303
    assert 'aria-label="Notifications, 3 unread"' in client.get(
        "/fdr/notifications"
    ).text
    officer = TestClient(app)
    _session_cookie(officer, "regional", "Regional Officer")
    officer_page = officer.get("/fdr/notifications")
    assert "overdue; officer renewal action is required" in officer_page.text
    assert "escalated after more than 15 overdue days" not in officer_page.text


def test_replacement_is_assigned_to_officer_and_original_is_retained(portal):
    app, institution_id, original_id, database = portal
    conn = sqlite3.connect(database)
    conn.execute("""
        UPDATE fdr_field_values SET verification_status='Bank-confirmed',
            confirmed_value=claimed_value WHERE instrument_id=?
    """, (original_id,))
    conn.commit()
    conn.close()

    institution = TestClient(app, follow_redirects=False)
    _session_cookie(institution, "institution-user", "Institution User")
    page = institution.get("/fdr/new")
    submitted = institution.post("/fdr/new", data={
        "csrf": _csrf(page), "institution_id": institution_id,
        "fdr_number": "TEST-RENEWAL-2", "bank": "Test Bank",
        "branch": "Test Branch", "amount": "1200.00",
        "issue_date": date.today().isoformat(),
        "maturity_date": (date.today() + timedelta(days=365)).isoformat(),
        "holder": "Test Institute", "replaces_id": original_id,
    })
    assert submitted.status_code == 303
    replacement_id = int(submitted.headers["location"].rsplit("/", 1)[1])
    conn = sqlite3.connect(database)
    replacement = conn.execute(
        "SELECT replaces_id,assigned_officer,lifecycle_status FROM fdr_instruments WHERE id=?",
        (replacement_id,),
    ).fetchone()
    notice = conn.execute(
        "SELECT recipient_username,message FROM fdr_notifications WHERE instrument_id=?",
        (replacement_id,),
    ).fetchone()
    conn.close()
    assert replacement == (original_id, "regional", "Under verification")
    assert notice[0] == "regional"
    assert "TEST-FDR-1" in notice[1]
    conn = sqlite3.connect(database)
    conn.execute("""
        UPDATE fdr_field_values SET verification_status='Bank-confirmed',
            confirmed_value=claimed_value WHERE instrument_id=?
    """, (replacement_id,))
    conn.commit()
    conn.close()

    officer = TestClient(app, follow_redirects=False)
    _session_cookie(officer, "regional", "Regional Officer")
    detail = officer.get(f"/fdr/{replacement_id}")
    verified = officer.post(f"/fdr/{replacement_id}/scrutiny", data={
        "csrf": _csrf(detail), "action": "mark_verified", "remark": "Renewal checked",
    })
    assert verified.status_code == 303
    conn = sqlite3.connect(database)
    states = conn.execute(
        "SELECT id,lifecycle_status FROM fdr_instruments WHERE id IN (?,?) ORDER BY id",
        (original_id, replacement_id),
    ).fetchall()
    conn.close()
    assert states == [(original_id, "Renewed"), (replacement_id, "Active")]
    assert fdr.verify_audit_chain()[0] is True


def test_release_verification_cannot_be_disabled_by_settings(portal):
    _, _, instrument_id, _ = portal
    conn = fdr.connect()
    conn.execute("""
        UPDATE fdr_rule_sets SET rules_json=? WHERE active=1
    """, (json.dumps({
        "require_document": False,
        "require_verified": False,
        "block_discrepancy": False,
    }),))
    eligibility = fdr._eligibility(conn, instrument_id)
    conn.close()
    verification_check = next(
        item for item in eligibility["checks"] if item["name"] == "Required fields confirmed"
    )
    assert verification_check["passed"] is False
    assert eligibility["eligible"] is False


def test_bank_mismatch_creates_an_open_discrepancy(portal):
    app, _, instrument_id, database = portal
    officer = TestClient(app)
    _session_cookie(officer, "reviewer", "Bureau Admin")
    detail = officer.get(f"/fdr/{instrument_id}")
    generated = officer.post(
        f"/fdr/{instrument_id}/verify-link",
        data={"csrf": _csrf(detail), "field_name": "amount"},
    )
    match = re.search(r'value="(http://testserver/bank/verify/[^\"]+)"', generated.text)
    assert match
    path = match.group(1).replace("http://testserver", "")
    bank = TestClient(app)
    page = bank.get(path)
    response = bank.post(path, data={
        "csrf": _csrf(page), "response": "confirm",
        "confirmed_value": "1200.00", "remark": "Synthetic mismatch",
    })
    assert response.status_code == 200
    conn = sqlite3.connect(database)
    status = conn.execute(
        "SELECT verification_status FROM fdr_field_values "
        "WHERE instrument_id=? AND field_name='amount'", (instrument_id,),
    ).fetchone()[0]
    discrepancy = conn.execute(
        "SELECT status FROM fdr_discrepancies WHERE instrument_id=? AND field_name='amount'",
        (instrument_id,),
    ).fetchone()[0]
    conn.close()
    assert status == "Mismatch"
    assert discrepancy == "Open"


def test_csv_and_pdf_exports_cover_scoped_report_filters(portal):
    app, _, _, _ = portal
    client = TestClient(app)
    _session_cookie(client, "institution-user", "Institution User")
    upcoming = client.get("/fdr/reports.csv?report=upcoming_30")
    missing_documents = client.get("/fdr/reports.csv?report=missing_documents")
    pdf = client.get("/fdr/reports.pdf?report=registry")
    assert upcoming.status_code == 200
    assert "TEST-FDR-1" in upcoming.text
    assert "TEST-FDR-1" in missing_documents.text
    assert pdf.status_code == 200
    assert pdf.headers["content-type"] == "application/pdf"
    assert pdf.content.startswith(b"%PDF-")


def test_users_can_open_only_their_assigned_role_portal(portal):
    app, _, _, _ = portal
    allowed = {
        "institution-user": ("Institution User", "/institution"),
        "regional": ("Regional Officer", "/officer"),
        "authority": ("Competent Authority", "/authority"),
        "system-admin": ("Admin", "/admin"),
        "bank-user": ("Bank Verifier", "/bank"),
    }
    portal_paths = ("/institution", "/officer", "/authority", "/admin", "/bank")
    for username, (role, own_portal) in allowed.items():
        client = TestClient(app)
        _session_cookie(client, username, role)
        for path in portal_paths:
            expected = 200 if path == own_portal else 403
            response = client.get(path)
            assert response.status_code == expected, (role, path)
            if role == "Institution User" and path == "/institution":
                assert 'action="/logout"' in response.text
                assert ">Log out</button>" in response.text


def test_claim_correction_requires_bank_match_before_discrepancy_resolution(portal):
    app, _, instrument_id, database = portal
    conn = sqlite3.connect(database)
    conn.execute("""
        UPDATE fdr_field_values SET confirmed_value='Verified Holder',
            verification_status='Mismatch',verification_source='Simulated bank response'
        WHERE instrument_id=? AND field_name='holder'
    """, (instrument_id,))
    conn.execute("""
        UPDATE fdr_instruments SET lifecycle_status='Discrepancy unresolved' WHERE id=?
    """, (instrument_id,))
    discrepancy_id = conn.execute("""
        INSERT INTO fdr_discrepancies(instrument_id,field_name,explanation,created_at)
        VALUES(?,'holder','Synthetic holder mismatch',?)
    """, (instrument_id, fdr._now())).lastrowid
    conn.commit()
    conn.close()

    officer = TestClient(app, follow_redirects=False)
    _session_cookie(officer, "regional", "Regional Officer")
    page = officer.get(f"/fdr/{instrument_id}")
    unresolved = officer.post(
        f"/fdr/{instrument_id}/discrepancies/{discrepancy_id}/resolve",
        data={"csrf": _csrf(page), "note": "Check the claim"},
    )
    assert unresolved.status_code == 409

    institution = TestClient(app, follow_redirects=False)
    _session_cookie(institution, "institution-user", "Institution User")
    page = institution.get(f"/fdr/{instrument_id}")
    corrected = institution.post(
        f"/fdr/{instrument_id}/fields/holder/claim",
        data={"csrf": _csrf(page), "claimed_value": "Verified Holder"},
    )
    assert corrected.status_code == 303
    page = officer.get(f"/fdr/{instrument_id}")
    resolved = officer.post(
        f"/fdr/{instrument_id}/discrepancies/{discrepancy_id}/resolve",
        data={"csrf": _csrf(page), "note": "Claim matches bank response"},
    )
    assert resolved.status_code == 303

    conn = sqlite3.connect(database)
    status = conn.execute("""
        SELECT d.status,f.verification_status,i.lifecycle_status
        FROM fdr_discrepancies d
        JOIN fdr_field_values f ON f.instrument_id=d.instrument_id
                                 AND f.field_name=d.field_name
        JOIN fdr_instruments i ON i.id=d.instrument_id
        WHERE d.id=?
    """, (discrepancy_id,)).fetchone()
    conn.close()
    assert status == ("Resolved", "Bank-confirmed", "Under verification")
