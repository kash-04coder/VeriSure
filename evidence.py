import hashlib
import sqlite3
import os
from datetime import datetime
from encryption import encrypt_file
from audit import log_action
from ip_logger import log_ip_activity
from security import validate_upload
from config import DATABASE_PATH, UPLOAD_PATH

UPLOAD_FOLDER = UPLOAD_PATH

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def calculate_hash(file_path):
    sha256 = hashlib.sha256()
    with open(file_path,"rb") as f:
        while chunk := f.read(4096):
            sha256.update(chunk)
    return sha256.hexdigest()


def save_evidence(case_id, title, filename, file_bytes, username, ip_address="Not recorded"):
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    safe_filename = validate_upload(file_bytes, filename)
    file_path = os.path.join(UPLOAD_FOLDER, safe_filename)
    print("Saving to:", file_path)
    with open(file_path, "wb") as f:
        f.write(file_bytes)
    file_hash = calculate_hash(file_path)
    encrypted_path = encrypt_file(file_path)
    # save to database...
    conn = sqlite3.connect(DATABASE_PATH)
    c = conn.cursor()
    c.execute("""
    INSERT INTO evidence(
    case_id,
    title,
    filename,
    filepath,
    encrypted_path,
    sha256,
    uploaded_by,
    upload_time
    )
    VALUES(?,?,?,?,?,?,?,?)
    """,
    (
        case_id,
        title,
        filename,
        file_path,
        encrypted_path,
        file_hash,
        username,
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))

    evidence_id = c.lastrowid

    c.execute("""
    INSERT INTO custody(
    evidence_id,
    action,
    person,
    timestamp
    )
    VALUES(?,?,?,?)
    """,
    (
        evidence_id,
        "Evidence Registered",
        username,
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))
    os.remove(file_path)

    conn.commit()
    conn.close()

    log_ip_activity(
        evidence_id,
        username,
        "Evidence Registered",
        ip_address
    )

    log_action(
        username,
        f"Encrypted Evidence: {title}"
    )

    return file_hash