import sqlite3
from config import DATABASE_PATH

def init_db():
    conn = sqlite3.connect(
        DATABASE_PATH,
        timeout=10
    )
    c = conn.cursor()

    c.execute("""
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        role TEXT
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS custody(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        evidence_id INTEGER,
        action TEXT,
        person TEXT,
        timestamp TEXT
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS evidence(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT,
    title TEXT,
    filename TEXT,
    filepath TEXT,
    encrypted_path TEXT,
    sha256 TEXT,
    uploaded_by TEXT,
    upload_time TEXT)
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS audit_logs(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        action TEXT,
        timestamp TEXT
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS verification_logs(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        evidence_id INTEGER,
        verified_by TEXT,
        verification_time TEXT,
        status TEXT
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS tamper_alerts(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        evidence_id INTEGER,
        evidence_title TEXT,
        detected_by TEXT,
        detection_time TEXT,
        original_hash TEXT,
        current_hash TEXT,
        severity TEXT,
        status TEXT
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS cases(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        case_id TEXT UNIQUE,
        case_name TEXT,
        description TEXT,
        investigator TEXT,
        priority TEXT,
        status TEXT,
        created_at TEXT,
        report_signature TEXT,
        report_signed_at TEXT
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS evidence_ip_logs(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        evidence_id INTEGER,
        username TEXT,
        action TEXT,
        ip_address TEXT,
        timestamp TEXT
    )
    """)

    
    c.execute("""
    CREATE TABLE IF NOT EXISTS vault_security(
        id INTEGER PRIMARY KEY CHECK(id = 1),
        salt BLOB NOT NULL,
        password_hash BLOB NOT NULL,
        iterations INTEGER NOT NULL,
        created_at TEXT NOT NULL
    )
    """)

    conn.commit()
    conn.close()


def init_document_tables():
    """
    Schema for the legal document management + hash-chain integrity system.

    Kept as a separate init function (called alongside init_db()) so the
    original evidence/case schema above is untouched -- this is purely
    additive.
    """
    conn = sqlite3.connect(DATABASE_PATH, timeout=10)
    c = conn.cursor()

    # A "document" is the logical legal record (an FIR, a charge sheet, a
    # witness statement, a court filing, etc). It never stores a file
    # itself -- every actual file lives in document_versions, so the
    # original is never overwritten.
    c.execute("""
    CREATE TABLE IF NOT EXISTS documents(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        case_id TEXT,
        doc_type TEXT,
        title TEXT,
        description TEXT,
        created_by TEXT,
        created_at TEXT,
        current_version INTEGER DEFAULT 1,
        status TEXT DEFAULT 'Active'
    )
    """)

    # Every upload/edit creates a new, immutable version row rather than
    # overwriting the previous one.
    c.execute("""
    CREATE TABLE IF NOT EXISTS document_versions(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        document_id INTEGER,
        version_number INTEGER,
        filename TEXT,
        filepath TEXT,
        encrypted_path TEXT,
        sha256 TEXT,
        uploaded_by TEXT,
        upload_time TEXT,
        change_note TEXT,
        chain_hash TEXT,
        signature TEXT
    )
    """)

    # The hash-chain ledger. Each row is a block: it commits to the
    # document's state at that point in time AND to the previous block's
    # hash, so altering or deleting any past entry breaks every block
    # after it -- this is what makes tampering detectable, not just the
    # per-file SHA-256 check.
    c.execute("""
    CREATE TABLE IF NOT EXISTS hash_chain(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        document_id INTEGER,
        version_number INTEGER,
        action TEXT,
        actor TEXT,
        timestamp TEXT,
        content_hash TEXT,
        previous_hash TEXT,
        chain_hash TEXT
    )
    """)

    # Document-level permissions (RBAC starting point -- per-document
    # grants layered on top of the existing role system).
    c.execute("""
    CREATE TABLE IF NOT EXISTS document_permissions(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        document_id INTEGER,
        username TEXT,
        permission TEXT,
        granted_by TEXT,
        granted_at TEXT
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS forensic_verifications(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        document_id INTEGER NOT NULL,
        version_number INTEGER NOT NULL,
        status TEXT NOT NULL,
        risk_level TEXT,
        risk_score INTEGER DEFAULT 0,
        ai_score INTEGER DEFAULT 0,
        tamper_score INTEGER DEFAULT 0,
        metadata_score INTEGER DEFAULT 0,
        ocr_text TEXT,
        entities_json TEXT,
        findings_json TEXT,
        narrative TEXT,
        heatmap_path TEXT,
        created_at TEXT NOT NULL,
        verified_by TEXT
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS forensic_findings(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        verification_id INTEGER NOT NULL,
        category TEXT NOT NULL,
        severity TEXT,
        finding TEXT,
        evidence TEXT,
        created_at TEXT NOT NULL
    )
    """)

    conn.commit()
    conn.close()