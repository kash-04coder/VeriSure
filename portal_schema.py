"""Additive schema for the Verisure SIH 2026 portal."""

import sqlite3
from config import DATABASE_PATH


PORTAL_STATUSES = (
    "Submitted", "Under Scrutiny", "Verified", "Active", "Expiring",
    "Matured", "Renewed", "Release Requested", "Released", "Rejected",
    "Escalated",
)


def init_portal_schema(database=DATABASE_PATH):
    conn = sqlite3.connect(database, timeout=15)
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS institutions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            region TEXT NOT NULL,
            registration_number TEXT UNIQUE,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS fdrs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            institution_id INTEGER NOT NULL REFERENCES institutions(id),
            fdr_number TEXT NOT NULL UNIQUE,
            bank_name TEXT NOT NULL,
            branch TEXT NOT NULL,
            amount TEXT NOT NULL,
            issue_date TEXT NOT NULL,
            maturity_date TEXT NOT NULL,
            status TEXT NOT NULL,
            submitted_by TEXT NOT NULL,
            bank_verified INTEGER NOT NULL DEFAULT 0,
            discrepancy_flag INTEGER NOT NULL DEFAULT 0,
            discrepancy_details TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS fdr_documents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fdr_id INTEGER NOT NULL REFERENCES fdrs(id),
            document_type TEXT NOT NULL,
            filename TEXT NOT NULL,
            storage_path TEXT NOT NULL,
            sha256 TEXT NOT NULL,
            uploaded_by TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS fdr_renewals (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            original_fdr_id INTEGER NOT NULL REFERENCES fdrs(id),
            replacement_fdr_id INTEGER NOT NULL REFERENCES fdrs(id),
            submitted_by TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'Under Scrutiny',
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS release_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fdr_id INTEGER NOT NULL REFERENCES fdrs(id),
            requested_by TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'Release Requested',
            reason TEXT NOT NULL,
            officer_remarks TEXT NOT NULL DEFAULT '',
            authority_remarks TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            fdr_id INTEGER REFERENCES fdrs(id),
            message TEXT NOT NULL,
            due_at TEXT NOT NULL,
            read_at TEXT
        );
        CREATE TABLE IF NOT EXISTS scrutiny_remarks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fdr_id INTEGER NOT NULL REFERENCES fdrs(id),
            officer TEXT NOT NULL,
            remark TEXT NOT NULL,
            action TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS bank_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fdr_number TEXT NOT NULL UNIQUE,
            bank_name TEXT NOT NULL,
            amount TEXT NOT NULL,
            issue_date TEXT NOT NULL,
            maturity_date TEXT NOT NULL,
            verification_status TEXT NOT NULL DEFAULT 'confirmed',
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
    """)
    conn.execute(
        "INSERT OR IGNORE INTO settings(key,value) VALUES('reminder_days','90,60,30,7')"
    )
    conn.commit()
    conn.close()
