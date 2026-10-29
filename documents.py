"""
Legal document management with immutable version control.

This generalizes evidence.py's pattern (hash -> encrypt -> store) from
"evidence files" to any legal/investigation document: FIRs, charge
sheets, witness statements, court filings, forensic reports, legal
notices, judgments, etc.

Key difference from evidence.py: uploading a new copy of a document
never overwrites anything. It creates a new row in document_versions
and bumps documents.current_version. Every version stays retrievable,
and every version is a block in that document's hash chain (see
hash_chain.py) -- so you can prove not just that today's copy is
authentic, but that its entire history is.
"""
import json

from verification_gate import verify_encrypted_version
import os
import sqlite3
from datetime import datetime

from encryption import encrypt_file
from security import validate_upload
from audit import log_action
from ip_logger import log_ip_activity
from evidence import calculate_hash
import hash_chain

DB = "forensic.db"
UPLOAD_FOLDER = "uploads"

DOCUMENT_TYPES = [
    "FDR",
    "Deposit Receipt",
    "Bank Letter",
    "Renewal Letter",
    "Release Request",
    "Other",
]

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
def run_forensic_verification(document_id, version_number, username):
    """
    Run forensic verification on one immutable document version.
    """

    version = get_version(
        document_id,
        version_number,
    )

    if not version:
        return None

    result = verify_encrypted_version(
        version["encrypted_path"],
        version["filename"],
    )

    metadata_score = (
        result
        .get("metadata", {})
        .get("content", {})
        .get("risk_score", 0)
    )

    ai_score = (
        result
        .get("ai_detection", {})
        .get("score", 0)
    )

    tamper_score = (
        result
        .get("tamper_detection", {})
        .get("score", 0)
    )

    ocr_text = result.get(
        "ocr",
        {}
    ).get(
        "text",
        "",
    )

    entities = result.get(
        "ocr",
        {}
    ).get(
        "entities",
        {},
    )

    narrative = result.get(
        "narrative",
        {},
    ).get(
        "text",
        "",
    )

    conn = sqlite3.connect(DB)

    cursor = conn.execute("""
        INSERT INTO forensic_verifications(
            document_id,
            version_number,
            status,
            risk_level,
            risk_score,
            ai_score,
            tamper_score,
            metadata_score,
            ocr_text,
            entities_json,
            findings_json,
            narrative,
            heatmap_path,
            created_at,
            verified_by
        )
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (
        document_id,
        version_number,
        result.get("status"),
        result.get("risk_level"),
        result.get("risk_score", 0),
        ai_score,
        tamper_score,
        metadata_score,
        ocr_text,
        json.dumps(entities, default=str),
        json.dumps(result, default=str),
        narrative,
        result.get(
            "tamper_detection",
            {}
        ).get(
            "heatmap"
        ),
        datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        ),
        username,
    ))

    verification_id = cursor.lastrowid

    conn.commit()
    conn.close()

    return {
        **result,
        "verification_id": verification_id,
    }


def get_latest_forensic_verification(document_id):
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row

    row = conn.execute("""
        SELECT *
        FROM forensic_verifications
        WHERE document_id=?
        ORDER BY id DESC
        LIMIT 1
    """, (document_id,)).fetchone()

    conn.close()

    return dict(row) if row else None

def create_document(case_id, doc_type, title, description, file_bytes, filename,
                     username, ip_address="Not recorded"):
    """
    Register a new document and store its first version (version 1).
    Returns (document_id, sha256, chain_hash).
    """
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("""
        INSERT INTO documents(
            case_id, doc_type, title, description,
            created_by, created_at, current_version, status
        )
        VALUES(?,?,?,?,?,?,?,?)
    """, (
        case_id, doc_type, title, description,
        username, datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        1, "Active"
    ))
    document_id = c.lastrowid
    conn.commit()
    conn.close()

    sha256, chain_hash = _store_version(
        document_id, version_number=1, file_bytes=file_bytes, filename=filename,
        username=username, change_note="Initial upload", ip_address=ip_address,
        action="Document Created"
    )

    log_action(username, f"Created document: {title} ({doc_type})")

    try:
        run_forensic_verification(document_id, 1, username)
    except Exception as exc:
        log_action(
            username,
            f"Forensic verification failed for document {document_id}: {exc}",
        )

    return document_id, sha256, chain_hash


def add_version(document_id, file_bytes, filename, username, change_note,
                 ip_address="Not recorded"):
    """
    Add a new immutable version to an existing document. The previous
    version is never deleted or overwritten.
    """
    conn = sqlite3.connect(DB)
    row = conn.execute("""
        SELECT current_version, title FROM documents WHERE id=?
    """, (document_id,)).fetchone()
    conn.close()

    if not row:
        return None, None, None

    next_version = row[0] + 1
    title = row[1]

    sha256, chain_hash = _store_version(
        document_id, version_number=next_version, file_bytes=file_bytes,
        filename=filename, username=username, change_note=change_note,
        ip_address=ip_address, action="New Version Uploaded"
    )

    conn = sqlite3.connect(DB)
    conn.execute("""
        UPDATE documents SET current_version=? WHERE id=?
    """, (next_version, document_id))
    conn.commit()
    conn.close()

    log_action(username, f"New version ({next_version}) of document: {title}")

    try:
        run_forensic_verification(document_id, next_version, username)
    except Exception as exc:
        log_action(
            username,
            f"Forensic verification failed for document {document_id} v{next_version}: {exc}",
        )

    return next_version, sha256, chain_hash


def _store_version(document_id, version_number, file_bytes, filename, username,
                    change_note, ip_address, action):
    safe_filename = validate_upload(file_bytes, filename)
    file_path = os.path.join(
        UPLOAD_FOLDER, f"doc{document_id}_v{version_number}_{safe_filename}"
    )
    with open(file_path, "wb") as f:
        f.write(file_bytes)

    sha256 = calculate_hash(file_path)
    encrypted_path = encrypt_file(file_path)
    os.remove(file_path)

    conn = sqlite3.connect(DB)
    conn.execute("""
        INSERT INTO document_versions(
            document_id, version_number, filename, filepath, encrypted_path,
            sha256, uploaded_by, upload_time, change_note, chain_hash
        )
        VALUES(?,?,?,?,?,?,?,?,?,?)
    """, (
        document_id, version_number, filename, file_path, encrypted_path,
        sha256, username, datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        change_note, None
    ))
    conn.commit()
    conn.close()

    chain_hash = hash_chain.add_block(
        document_id=document_id,
        version_number=version_number,
        action=action,
        actor=username,
        content_hash=sha256,
    )

    conn = sqlite3.connect(DB)
    conn.execute("""
        UPDATE document_versions
        SET chain_hash=?
        WHERE document_id=? AND version_number=?
    """, (chain_hash, document_id, version_number))
    conn.commit()
    conn.close()

    log_ip_activity(document_id, username, action, ip_address)

    return sha256, chain_hash


def get_documents(case_id=None):
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    if case_id:
        rows = conn.execute("""
            SELECT * FROM documents WHERE case_id=? ORDER BY created_at DESC
        """, (case_id,)).fetchall()
    else:
        rows = conn.execute("""
            SELECT * FROM documents ORDER BY created_at DESC
        """).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_document(document_id):
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT * FROM documents WHERE id=?", (document_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def get_versions(document_id):
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("""
        SELECT * FROM document_versions
        WHERE document_id=?
        ORDER BY version_number ASC
    """, (document_id,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_version(document_id, version_number):
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    row = conn.execute("""
        SELECT * FROM document_versions
        WHERE document_id=? AND version_number=?
    """, (document_id, version_number)).fetchone()
    conn.close()
    return dict(row) if row else None


def verify_document_integrity(document_id):
    """
    Two-layer verification:
      1. Re-hash every stored version's encrypted file and compare to the
         SHA-256 recorded at upload time (catches file-level tampering).
      2. Walk the hash chain and recompute every block (catches
         history/ledger tampering -- e.g. someone editing the database
         directly to rewrite what happened).
    """
    from encryption import decrypt_file

    versions = get_versions(document_id)
    file_level = []
    for v in versions:
        try:
            data = decrypt_file(v["encrypted_path"])
            import hashlib
            current_hash = hashlib.sha256(data).hexdigest()
            file_level.append({
                "version_number": v["version_number"],
                "valid": current_hash == v["sha256"],
            })
        except (FileNotFoundError, ValueError):
            file_level.append({
                "version_number": v["version_number"],
                "valid": False,
            })

    chain_valid, broken_at, chain_details = hash_chain.verify_chain(document_id)

    return {
        "file_level": file_level,
        "chain_valid": chain_valid,
        "chain_broken_at": broken_at,
        "chain_details": chain_details,
        "overall_valid": chain_valid and all(f["valid"] for f in file_level),
    }
