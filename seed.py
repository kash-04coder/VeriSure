"""Seed a repeatable, fictional Verisure portal dataset."""

import sqlite3
from datetime import date, timedelta

from auth import _hash_password
from database import init_db, init_document_tables
from fdr_portal import init_fdr_db
from portal_schema import init_portal_schema, PORTAL_STATUSES


DATABASE = "forensic.db"
DEMO_USERS = (
    ("demo-institution", "DemoInstitution!2026", "Institution"),
    ("demo-officer", "DemoOfficer!2026", "Scrutiny Officer"),
    ("demo-authority", "DemoAuthority!2026", "Competent Authority"),
    ("demo-bank", "DemoBank!2026", "Bank Verifier"),
    ("demo-admin", "DemoAdmin!2026", "Admin"),
)


def seed():
    init_db()
    init_document_tables()
    init_fdr_db()
    init_portal_schema(DATABASE)
    conn = sqlite3.connect(DATABASE)
    now = date.today().isoformat()
    for username, password, role in DEMO_USERS:
        conn.execute(
            "INSERT INTO users(username,password,role) VALUES(?,?,?) "
            "ON CONFLICT(username) DO UPDATE SET role=excluded.role",
            (username, _hash_password(password), role),
        )
    conn.execute(
        "INSERT OR IGNORE INTO institutions(name,region,registration_number,created_at) "
        "VALUES(?,?,?,?)",
        ("Synthetic Institute of Technology", "Demo Region North", "SIH-DEMO-001", now),
    )
    conn.execute(
        "INSERT OR IGNORE INTO institutions(name,region,registration_number,created_at) "
        "VALUES(?,?,?,?)",
        ("Fictional Polytechnic Institute", "Demo Region South", "SIH-DEMO-002", now),
    )
    institution_id = conn.execute(
        "SELECT id FROM institutions WHERE registration_number='SIH-DEMO-001'"
    ).fetchone()[0]
    legacy_institution = conn.execute(
        "INSERT INTO fdr_institutions(name,region,created_at) VALUES(?,?,?) "
        "ON CONFLICT(name) DO UPDATE SET region=excluded.region RETURNING id",
        ("Synthetic Institute of Technology", "Demo Region North", now),
    ).fetchone()[0]
    conn.execute(
        "INSERT OR IGNORE INTO fdr_user_scopes(username,institution_id) VALUES(?,?)",
        ("demo-institution", legacy_institution),
    )
    for index, status in enumerate(PORTAL_STATUSES, 1):
        fdr_number = f"VER-DEMO-{index:03d}"
        maturity = date.today() + timedelta(days=(index - 5) * 30)
        issue_date = (date.today() - timedelta(days=180)).isoformat()
        amount = f"{100000 + index * 25000}.00"
        conn.execute(
            "INSERT OR IGNORE INTO fdrs("
            "institution_id,fdr_number,bank_name,branch,amount,issue_date,maturity_date,"
            "status,submitted_by,bank_verified,discrepancy_flag,discrepancy_details,created_at"
            ") VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                institution_id, fdr_number, "Prototype Cooperative Bank",
                "Synthetic Demo Branch", amount, issue_date,
                maturity.isoformat(), status, "demo-institution",
                int(status in {"Verified", "Active", "Renewed", "Released"}),
                int(status in {"Under Scrutiny", "Escalated"}),
                "Synthetic review required." if status in {"Under Scrutiny", "Escalated"} else "",
                now,
            ),
        )
        conn.execute(
            "INSERT OR IGNORE INTO bank_records("
            "fdr_number,bank_name,amount,issue_date,maturity_date,verification_status,updated_at"
            ") VALUES(?,?,?,?,?,?,?)",
            (
                fdr_number, "Prototype Cooperative Bank",
                amount, issue_date,
                maturity.isoformat(), "confirmed", now,
            ),
        )
        legacy_status = {
            "Submitted": "Under verification",
            "Under Scrutiny": "Under verification",
            "Verified": "Active",
            "Expiring": "Active",
            "Renewed": "Renewal pending",
            "Release Requested": "Under verification",
            "Rejected": "Discrepancy unresolved",
            "Escalated": "Discrepancy unresolved",
        }.get(status, status)
        legacy = conn.execute(
            "INSERT OR IGNORE INTO fdr_instruments("
            "institution_id,fdr_number,fdr_number_norm,bank,branch,amount,issue_date,"
            "maturity_date,holder,lifecycle_status,created_by,created_at"
            ") VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                legacy_institution, fdr_number, fdr_number.casefold(),
                "Prototype Cooperative Bank", "Synthetic Demo Branch", amount,
                issue_date, maturity.isoformat(), "Synthetic Institute of Technology",
                legacy_status, "demo-institution", now,
            ),
        )
        legacy_id = conn.execute(
            "SELECT id FROM fdr_instruments WHERE fdr_number_norm=?",
            (fdr_number.casefold(),),
        ).fetchone()[0]
        for field, value in {
            "fdr_number": fdr_number,
            "bank": "Prototype Cooperative Bank",
            "branch": "Synthetic Demo Branch",
            "amount": amount,
            "issue_date": issue_date,
            "maturity_date": maturity.isoformat(),
            "holder": "Synthetic Institute of Technology",
        }.items():
            conn.execute(
                "INSERT OR IGNORE INTO fdr_field_values("
                "instrument_id,field_name,claimed_value,verification_status"
                ") VALUES(?,?,?,'Pending bank verification')",
                (legacy_id, field, value),
            )
    conn.commit()
    conn.close()
    print("Seeded fictional Verisure users and FDR records.")
    for username, password, role in DEMO_USERS:
        print(f"{role}: {username} / {password}")


if __name__ == "__main__":
    seed()
