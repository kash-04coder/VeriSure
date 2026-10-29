"""Explicitly seed fictional, local-only FDR evaluation data."""

import argparse
from datetime import date, timedelta

from auth import _hash_password, create_user
from database import init_db, init_document_tables
import fdr_portal as fdr


DEMO_USERS = (
    ("demo-admin", "DemoAdmin!2026", "Bureau Admin"),
    ("demo-institution", "DemoInstitution!2026", "Institution User"),
    ("demo-officer", "DemoOfficer!2026", "Regional Officer"),
)


def _ensure_users():
    for username, password, role in DEMO_USERS:
        if not create_user(username, password, role):
            import sqlite3
            conn = sqlite3.connect("forensic.db")
            conn.execute(
                "UPDATE users SET role=?,password=? WHERE username=?",
                (role, _hash_password(password), username),
            )
            conn.commit()
            conn.close()


def _ensure_institution(conn, name, region):
    conn.execute(
        "INSERT OR IGNORE INTO fdr_institutions(name,region,created_at) VALUES(?,?,?)",
        (name, region, fdr._now()),
    )
    return conn.execute(
        "SELECT id FROM fdr_institutions WHERE name=?", (name,)
    ).fetchone()["id"]


def _add_instrument(conn, institution_id, record, actor="demo-institution"):
    existing = conn.execute("""
        SELECT id FROM fdr_instruments WHERE institution_id=? AND fdr_number=?
    """, (institution_id, record["fdr_number"])).fetchone()
    if existing:
        return existing["id"]
    cursor = conn.execute("""
        INSERT INTO fdr_instruments(
            institution_id,fdr_number,fdr_number_norm,bank,branch,amount,issue_date,
            maturity_date,holder,lifecycle_status,created_by,assigned_officer,
            replaces_id,duplicate_flag,created_at
        ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (
        institution_id, record["fdr_number"], fdr._normalize_fdr(record["fdr_number"]),
        "Prototype Cooperative Bank", "Synthetic Demo Branch",
        record["amount"], (date.today() - timedelta(days=180)).isoformat(),
        record["maturity_date"], record["holder"], record["status"], actor,
        "demo-officer", record.get("replaces_id"), int(record.get("duplicate", False)),
        fdr._now(),
    ))
    instrument_id = cursor.lastrowid
    fields = {
        "fdr_number": record["fdr_number"],
        "bank": "Prototype Cooperative Bank",
        "branch": "Synthetic Demo Branch",
        "amount": record["amount"],
        "issue_date": (date.today() - timedelta(days=180)).isoformat(),
        "maturity_date": record["maturity_date"],
        "holder": record["holder"],
    }
    confirmed = record.get("confirmed", False)
    mismatch_field = record.get("mismatch_field")
    for field, value in fields.items():
        status = "Bank-confirmed" if confirmed else "Pending bank verification"
        confirmed_value = value if confirmed else None
        if field == mismatch_field:
            status = "Mismatch"
            confirmed_value = record["confirmed_value"]
        conn.execute("""
            INSERT INTO fdr_field_values(
                instrument_id,field_name,claimed_value,confirmed_value,
                verification_status,verification_source,performed_by,performed_at
            ) VALUES(?,?,?,?,?,?,?,?)
        """, (
            instrument_id, field, value, confirmed_value, status,
            "Simulated bank response" if confirmed or field == mismatch_field else None,
            "Synthetic demo bank" if confirmed or field == mismatch_field else None,
            fdr._now() if confirmed or field == mismatch_field else None,
        ))
    if record.get("duplicate") or mismatch_field:
        field = mismatch_field or "fdr_number"
        explanation = (
            "Synthetic bank-confirmed value differs from institution claim."
            if mismatch_field else
            "Synthetic duplicate reference included to demonstrate detection."
        )
        conn.execute("""
            INSERT INTO fdr_discrepancies(instrument_id,field_name,explanation,created_at)
            VALUES(?,?,?,?)
        """, (instrument_id, field, explanation, fdr._now()))
    fdr._audit(
        conn, {"username": actor, "role": "Institution User"},
        "Synthetic FDR seeded", "instrument", instrument_id,
        "Fictional demo instrument; not real institutional or financial data.",
    )
    return instrument_id


def seed():
    init_db()
    init_document_tables()
    fdr.init_fdr_db()
    _ensure_users()
    conn = fdr.connect()
    institute = _ensure_institution(
        conn, "Synthetic Institute of Technology", "Demo Region North"
    )
    other_institute = _ensure_institution(
        conn, "Fictional Polytechnic Institute", "Demo Region South"
    )
    conn.execute(
        "INSERT OR IGNORE INTO fdr_user_scopes(username,institution_id) VALUES(?,?)",
        ("demo-institution", institute),
    )
    for institution_id in (institute, other_institute):
        conn.execute(
            "INSERT OR IGNORE INTO fdr_user_scopes(username,institution_id) VALUES(?,?)",
            ("demo-officer", institution_id),
        )

    active_id = _add_instrument(conn, institute, {
        "fdr_number": "SYN-ACT-001", "amount": "1250000.00",
        "maturity_date": (date.today() + timedelta(days=240)).isoformat(),
        "holder": "Synthetic Institute of Technology", "status": "Active",
        "confirmed": True,
    })
    _add_instrument(conn, institute, {
        "fdr_number": "SYN-EXP-007", "amount": "850000.00",
        "maturity_date": (date.today() + timedelta(days=7)).isoformat(),
        "holder": "Synthetic Institute of Technology", "status": "Under verification",
    })
    _add_instrument(conn, institute, {
        "fdr_number": "SYN-MAT-001", "amount": "410000.00",
        "maturity_date": (date.today() - timedelta(days=15)).isoformat(),
        "holder": "Synthetic Institute of Technology", "status": "Matured",
    })
    _add_instrument(conn, institute, {
        "fdr_number": "SYN-DUP-077", "amount": "300000.00",
        "maturity_date": (date.today() + timedelta(days=120)).isoformat(),
        "holder": "Synthetic Institute of Technology", "status": "Discrepancy unresolved",
        "duplicate": True,
    })
    _add_instrument(conn, other_institute, {
        "fdr_number": "SYN-DUP-077", "amount": "300000.00",
        "maturity_date": (date.today() + timedelta(days=120)).isoformat(),
        "holder": "Fictional Polytechnic Institute", "status": "Discrepancy unresolved",
        "duplicate": True,
    }, actor="demo-officer")
    _add_instrument(conn, institute, {
        "fdr_number": "SYN-MIS-012", "amount": "515000.00",
        "maturity_date": (date.today() + timedelta(days=95)).isoformat(),
        "holder": "Synthetic Institute of Technology", "status": "Discrepancy unresolved",
        "confirmed": True, "mismatch_field": "maturity_date",
        "confirmed_value": (date.today() + timedelta(days=90)).isoformat(),
    })
    replacement_id = _add_instrument(conn, institute, {
        "fdr_number": "SYN-REP-002", "amount": "1250000.00",
        "maturity_date": (date.today() + timedelta(days=605)).isoformat(),
        "holder": "Synthetic Institute of Technology", "status": "Renewal pending",
        "replaces_id": active_id,
    })
    release_instrument = _add_instrument(conn, institute, {
        "fdr_number": "SYN-REL-003", "amount": "250000.00",
        "maturity_date": (date.today() + timedelta(days=180)).isoformat(),
        "holder": "Synthetic Institute of Technology", "status": "Active",
        "confirmed": True,
    })
    release = conn.execute("""
        SELECT id FROM fdr_release_requests WHERE instrument_id=?
    """, (release_instrument,)).fetchone()
    if not release:
        evaluation = fdr._eligibility(conn, release_instrument)
        timestamp = fdr._now()
        cursor = conn.execute("""
            INSERT INTO fdr_release_requests(
                instrument_id,requested_by,reason,status,rule_set_version,
                eligibility_json,created_at,updated_at
            ) VALUES(?,?,?,'Submitted',?,?,?,?)
        """, (
            release_instrument, "demo-institution",
            "Synthetic demonstration request; add a supporting document before review.",
            evaluation["rule_set_version"],
            __import__("json").dumps(evaluation), timestamp, timestamp,
        ))
        fdr._audit(
            conn, {"username": "demo-institution", "role": "Institution User"},
            "Synthetic release request seeded", "release_request", cursor.lastrowid,
            "Synthetic request intentionally fails the supporting-document rule.",
        )
    conn.commit()
    conn.close()
    print("Synthetic FDR demo data is ready.")
    print("No real institution, bank, FDR or financial data was created.")
    print(f"Replacement instrument ID: {replacement_id} (linked to original ID {active_id})")
    for role, username, password in DEMO_USERS:
        print(f"{role}: {username} / {password}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--allow-demo-seed", action="store_true",
        help="Explicitly allow creation/reset of local-only demo accounts and records.",
    )
    arguments = parser.parse_args()
    if not arguments.allow_demo_seed:
        parser.error("Pass --allow-demo-seed only in a local evaluation environment.")
    import os
    if os.environ.get("LEXGUARD_ENVIRONMENT", "").lower() in {"production", "prod"}:
        parser.error("Demo seeding is disabled when LEXGUARD_ENVIRONMENT is production.")
    seed()
