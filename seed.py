"""Seed a repeatable, fictional Verisure portal dataset."""

import sqlite3
from datetime import date, timedelta

from auth import _hash_password
from database import init_db, init_document_tables
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
    init_portal_schema(DATABASE)
    conn = sqlite3.connect(DATABASE)
    now = date.today().isoformat()
    for username, password, role in DEMO_USERS:
        conn.execute(
            "INSERT INTO users(username,password,role) VALUES(?,?,?) "
            "ON CONFLICT(username) DO UPDATE SET password=excluded.password, role=excluded.role",
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
    statuses = list(PORTAL_STATUSES)
    for index, status in enumerate(statuses, 1):
        fdr_number = f"VER-DEMO-{index:03d}"
        maturity = date.today() + timedelta(days=(index - 5) * 30)
        conn.execute(
            "INSERT OR IGNORE INTO fdrs("
            "institution_id,fdr_number,bank_name,branch,amount,issue_date,maturity_date,"
            "status,submitted_by,bank_verified,discrepancy_flag,discrepancy_details,created_at"
            ") VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                institution_id, fdr_number, "Prototype Cooperative Bank",
                "Synthetic Demo Branch", f"{100000 + index * 25000}.00",
                (date.today() - timedelta(days=180)).isoformat(),
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
                f"{100000 + index * 25000}.00",
                (date.today() - timedelta(days=180)).isoformat(),
                maturity.isoformat(), "confirmed", now,
            ),
        )
    conn.commit()
    conn.close()
    print("Seeded fictional Verisure users and FDR records.")
    for username, password, role in DEMO_USERS:
        print(f"{role}: {username} / {password}")


if __name__ == "__main__":
    seed()
